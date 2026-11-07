"""Tests for ASCII/UTF-16 string extraction and xref matching."""
import unittest
from pathlib import Path

from reversesuite import loader, strings


def frozen(name: str) -> bytes:
    return (Path("fixtures/frozen") / name).read_bytes()


class ScannerTests(unittest.TestCase):
    def test_ascii_min_length(self):
        blob = b"abc\x00abcd\x00"
        self.assertEqual(strings.scan_ascii(blob, 0x1000), [(0x1004, "abcd")])

    def test_ascii_trailing_blanks_trimmed(self):
        self.assertEqual(strings.scan_ascii(b"CV: \x00", 0), [])
        self.assertEqual(strings.scan_ascii(b"CV: \x00", 0, min_length=3), [(0, "CV:")])
        self.assertEqual(strings.scan_ascii(b"name  \x00", 0), [(0, "name")])

    def test_ascii_run_cut_by_nonprintable(self):
        self.assertEqual(strings.scan_ascii(b"hello\x01world", 0), [(0, "hello"), (6, "world")])

    def test_ascii_custom_min_length(self):
        self.assertEqual(strings.scan_ascii(b"abc\x00", 0, min_length=3), [(0, "abc")])

    def test_utf16_basic(self):
        blob = "hello".encode("utf-16le") + b"\x00\x00"
        self.assertEqual(strings.scan_utf16le(blob, 0x2000), [(0x2000, "hello")])

    def test_utf16_rejects_odd_offset(self):
        blob = b"\x00" + "hello".encode("utf-16le")
        self.assertEqual(strings.scan_utf16le(blob, 0), [])

    def test_utf16_min_length(self):
        self.assertEqual(strings.scan_utf16le("abc".encode("utf-16le"), 0), [])

    def test_min_length_validated(self):
        with self.assertRaises(ValueError):
            strings.scan_ascii(b"abcd", 0, min_length=0)


class ExtractTests(unittest.TestCase):
    def test_b_exec_ascii_matches_known_strings(self):
        data = frozen("b.exe")
        found = strings.extract(data)
        ascii_strings = [s for s in found if s.encoding == "ascii"]
        self.assertEqual(len(ascii_strings), 96)
        self.assertEqual([s for s in found if s.encoding == "utf16le"], [])
        by_addr = {s.address: s for s in found}
        self.assertEqual(by_addr[0x5000].value, "libgcc_s_dw2-1.dll")
        self.assertEqual(by_addr[0x5000].section, ".rdata")

    def test_only_non_executable_sections(self):
        data = frozen("b.exe")
        exec_sections = {s.name for s in loader.sections(data) if s.characteristics & 0x20000000}
        for item in strings.extract(data):
            self.assertNotIn(item.section, exec_sections)

    def test_a_exec_utf16_roundtrip(self):
        data = frozen("a.exe")
        found = [s for s in strings.extract(data) if s.encoding == "utf16le"]
        self.assertGreater(len(found), 100)
        text_rva = strings._text_rva(data)
        bounds = []
        for sec in loader.sections(data):
            base = 0x1000 + (sec.virtual_address - text_rva)
            bounds.append((base, base + sec.raw_size, sec.raw_ptr))
        for item in found:
            base, _end, raw_ptr = next(b for b in bounds if b[0] <= item.address < b[1])
            off = raw_ptr + (item.address - base)
            want = item.value.encode("utf-16le")
            self.assertEqual(data[off:off + len(want)], want)

    def test_deterministic(self):
        data = frozen("b.exe")
        self.assertEqual([s.value for s in strings.extract(data)], [s.value for s in strings.extract(data)])


class XrefTests(unittest.TestCase):
    def test_known_xrefs(self):
        data = frozen("b.exe")
        found = strings.extract(data)
        refs = strings.find_xrefs(loader.text_bytes(data), found)
        self.assertEqual(len(refs), 20)
        self.assertEqual(refs[0x5000], (0x167B, 0x1690))

    def test_extract_with_xrefs_attaches(self):
        data = frozen("b.exe")
        found = strings.extract_with_xrefs(data)
        by_addr = {s.address: s for s in found}
        self.assertIn(0x167B, by_addr[0x5000].xrefs)

    def test_xref_skipped_when_text_too_large(self):
        data = frozen("b.exe")
        found = strings.extract(data)
        text = loader.text_bytes(data)
        self.assertEqual(strings.xref_skip_reason(len(text), 100), "text_too_large_for_xref")
        self.assertIsNone(strings.xref_skip_reason(len(text), len(text)))
        self.assertEqual(strings.find_xrefs(text, found, max_bytes=100), {})
        self.assertGreater(len(strings.find_xrefs(text, found)), 0)

    def test_extract_with_xrefs_respects_limit(self):
        data = frozen("b.exe")
        limited = strings.extract_with_xrefs(data, max_bytes=1)
        self.assertEqual(len(limited), 96)
        self.assertTrue(all(not s.xrefs for s in limited))

    def test_parallel_matches_serial(self):
        data = frozen("a.exe")
        found = strings.extract(data)
        text = loader.text_bytes(data)[:200000]
        serial = strings.find_xrefs(text, found, workers=1, window=8192)
        parallel = strings.find_xrefs(text, found, workers=3, window=8192)
        self.assertEqual(serial, parallel)
        self.assertGreater(len(serial), 0)

    def test_xrefs_empty_without_strings(self):
        self.assertEqual(strings.find_xrefs(b"\x90", []), {})


if __name__ == "__main__":
    unittest.main()