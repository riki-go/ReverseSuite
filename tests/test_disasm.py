"""Tests for the streaming disassembly writer."""
import gzip
import json
import tempfile
import unittest
from pathlib import Path

from reversesuite import disasm, loader


def sample_text(limit: int = 256 * 1024) -> bytes:
    data = Path("fixtures/frozen/a.exe").read_bytes()
    return loader.text_bytes(data)[:limit]


class StreamingTests(unittest.TestCase):
    def test_stream_matches_buffer(self):
        blob = sample_text()
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "insn.jsonl"
            summary = disasm.write_stream(blob, out)
            streamed = out.read_text(encoding="utf-8").splitlines()
        buffered = [disasm.format_line(i).decode("utf-8").rstrip("\n")
                    for i in disasm.iter_instructions(blob)]
        self.assertEqual(streamed, buffered)
        self.assertEqual(summary["instructions"], len(buffered))

    def test_gzip_roundtrip(self):
        blob = sample_text(64 * 1024)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "insn.jsonl.gz"
            summary = disasm.write_stream(blob, out, use_gzip=True)
            with gzip.open(out, "rt", encoding="utf-8") as fh:
                lines = fh.read().splitlines()
        self.assertTrue(lines)
        for line in lines[:5]:
            obj = json.loads(line)
            self.assertIn("a", obj)
            self.assertIn("m", obj)
            self.assertIn("o", obj)
        self.assertEqual(summary["instructions"], len(lines))
        self.assertIn("gzip_over_raw_pct", summary)

    def test_slim_format(self):
        blob = sample_text(32 * 1024)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "slim.jsonl"
            disasm.write_stream(blob, out, slim=True)
            first = json.loads(out.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(set(first.keys()), {"a", "m"})

    def test_deterministic_output(self):
        blob = sample_text(64 * 1024)
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "a.jsonl"
            b = Path(tmp) / "b.jsonl"
            disasm.write_stream(blob, a)
            disasm.write_stream(blob, b)
            self.assertEqual(a.read_bytes(), b.read_bytes())


if __name__ == "__main__":
    unittest.main()
