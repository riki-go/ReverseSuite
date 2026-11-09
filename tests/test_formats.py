"""M8 Phase 1: format loaders, container handling and the multi-format pipeline."""
from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from reversesuite import analysis, disasm, functions, loader, rules, schema  # noqa: E402
from reversesuite.formats import (FORMAT_APK, FORMAT_DEX, FORMAT_ELF, FORMAT_IPA, FORMAT_MACHO,  # noqa: E402
                                  FORMAT_PE, FORMAT_UNKNOWN, container, detect, load)

MULTI = ROOT / "fixtures" / "multi"


def fixture(name: str) -> bytes:
    path = MULTI / name
    if not path.is_file():
        raise unittest.SkipTest("run fixtures/gen_multi.py first: %s missing" % name)
    return path.read_bytes()


class RegistryTests(unittest.TestCase):
    def test_registry_exposes_one_loader_per_format(self):
        from reversesuite.formats import BinaryLoader, loader_for
        for name in (FORMAT_PE, FORMAT_ELF, FORMAT_MACHO, FORMAT_DEX):
            with self.subTest(format=name):
                loader_obj = loader_for(name)
                self.assertIsInstance(loader_obj, BinaryLoader)
                self.assertEqual(loader_obj.format, name)

    def test_unregistered_format_raises(self):
        from reversesuite.formats import FormatError, loader_for
        with self.assertRaises(FormatError):
            loader_for("java-class")


class DetectionTests(unittest.TestCase):
    def test_detects_every_supported_format(self):
        cases = {
            "arm64_demo.so": FORMAT_ELF,
            "ios_demo": FORMAT_MACHO,
            "classes.dex": FORMAT_DEX,
            "demo.apk": FORMAT_APK,
            "demo.ipa": FORMAT_IPA,
        }
        for name, expected in cases.items():
            with self.subTest(name=name):
                self.assertEqual(detect(fixture(name), name), expected)

    def test_pe_is_still_detected(self):
        data = (ROOT / "fixtures" / "frozen" / "a.exe").read_bytes()
        self.assertEqual(detect(data, "a.exe"), FORMAT_PE)

    def test_unknown_input_is_not_guessed_from_extension(self):
        self.assertEqual(detect(b"not a binary at all", "fake.apk"), FORMAT_UNKNOWN)
        self.assertEqual(detect(b"", "empty.bin"), FORMAT_UNKNOWN)

    def test_container_kind_uses_member_names(self):
        self.assertEqual(container.detect_kind(fixture("demo.apk"), "wrong.zip"), "apk")
        self.assertEqual(container.detect_kind(fixture("demo.ipa"), "wrong.zip"), "ipa")


class ElfLoaderTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture("arm64_demo.so")
        self.image = load(self.data, "arm64_demo.so")

    def test_arch_and_kind(self):
        self.assertEqual(self.image.format, FORMAT_ELF)
        self.assertEqual(self.image.arch, "arm64")
        self.assertEqual(self.image.bits, 64)

    def test_sections_and_symbols(self):
        names = [s.name for s in self.image.sections]
        self.assertIn(".text", names)
        self.assertIn(".rodata", names)
        symbols = [name for _addr, name in self.image.symbols]
        self.assertIn("demo_start", symbols)
        self.assertIn("demo_helper", symbols)

    def test_code_is_normalised_to_base_address(self):
        self.assertEqual(len(self.image.code), 0x40)
        self.assertEqual(self.image.code_va, 0x1000)
        self.assertEqual(self.image.entry, 0x1000)


class MachOLoaderTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture("ios_demo")
        self.image = load(self.data, "ios_demo")

    def test_arch_and_entry(self):
        self.assertEqual(self.image.format, FORMAT_MACHO)
        self.assertEqual(self.image.arch, "arm64")
        self.assertEqual(self.image.entry, 0x1000)

    def test_text_section_and_symbols(self):
        names = [s.name for s in self.image.sections]
        self.assertIn("__TEXT,__text", names)
        self.assertIn("__TEXT,__cstring", names)
        symbols = {name for _addr, name in self.image.symbols}
        self.assertIn("_main", symbols)
        self.assertIn("_helper", symbols)


class DexLoaderTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture("classes.dex")
        image = load(self.data, "classes.dex")
        self.assertEqual(image.arch, "dalvik")
        self.assertFalse(image.has_code())

    def test_inventory(self):
        from reversesuite.formats import dex
        inventory = dex.parse(self.data)
        self.assertEqual(inventory.version, "035")
        self.assertEqual(inventory.classes, ["com.demo.App"])
        self.assertEqual(inventory.methods, ["com.demo.App.run"])
        self.assertIn("hello from dex", [value for _o, value in inventory.strings])


class ContainerTests(unittest.TestCase):
    def test_apk_members(self):
        parts = container.read_apk(fixture("demo.apk"))
        self.assertTrue(parts.has_manifest)
        self.assertEqual([name for name, _b in parts.dex], ["classes.dex"])
        self.assertEqual(len(parts.libs), 2)
        self.assertEqual({abi for abi, _n, _b in parts.libs}, {"arm64-v8a", "x86_64"})

    def test_ipa_members(self):
        parts = container.read_ipa(fixture("demo.ipa"))
        self.assertEqual(parts.app_dir, "Payload/Demo.app")
        self.assertEqual(parts.binary_name, "Payload/Demo.app/Demo")
        self.assertTrue(parts.has_info_plist)
        self.assertTrue(parts.binary.startswith(b"\xcf\xfa\xed\xfe"))


class Arm64AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.data = fixture("ios_demo")
        self.image = load(self.data, "ios_demo")

    def test_engine_is_arm64(self):
        engine = disasm.make_engine("arm64")
        instructions = list(engine.disasm(self.image.code[:16], 0x1000))
        self.assertEqual(instructions[0].mnemonic, "stp")
        self.assertEqual(instructions[-1].mnemonic, "ret")

    def test_function_discovery_finds_prologues(self):
        found = functions.discover(self.image.code, base=self.image.code_va,
                                   exports=self.image.exports, entry=self.image.entry,
                                   arch="arm64")
        starts = sorted(fn.start for fn in found)
        self.assertEqual(starts, [0x1000, 0x1020])

    def test_unknown_arch_is_rejected(self):
        with self.assertRaises(ValueError):
            disasm.make_engine("mips")


class PipelineTests(unittest.TestCase):
    def test_every_format_produces_findings(self):
        cases = {
            "arm64_demo.so": ("elf", {"signature", "section", "string", "function"}),
            "ios_demo": ("macho", {"signature", "section", "string", "function"}),
            "classes.dex": ("dex", {"signature", "class", "method", "string"}),
            "demo.apk": ("apk", {"package", "member", "class", "section"}),
            "demo.ipa": ("ipa", {"package", "member", "function"}),
        }
        for name, (kind, required) in cases.items():
            with self.subTest(name=name):
                result = analysis.analyze_bytes(fixture(name), name)
                self.assertEqual(result.target_kind, kind)
                self.assertIn(result.status, ("ok", "degraded"))
                kinds = {item.kind for item in result.findings}
                self.assertTrue(required.issubset(kinds), "%s missing %s" % (name, required - kinds))
                for finding in result.findings:
                    self.assertTrue(rules.is_registered(finding.rule))

    def test_strings_carry_section_evidence(self):
        result = analysis.analyze_bytes(fixture("ios_demo"), "ios_demo")
        values = {item.value for item in result.findings if item.kind == "string"}
        self.assertIn("IOS_TOKEN", values)
        string_findings = [item for item in result.findings if item.kind == "string"]
        self.assertTrue(all(item.evidence[0].space == "va" for item in string_findings))

    def test_pe_path_is_unchanged(self):
        data = (ROOT / "fixtures" / "frozen" / "a.exe").read_bytes()
        direct = loader.parse(data)
        routed = analysis.analyze_bytes(data, "a.exe")
        self.assertEqual(direct.target_kind, routed.target_kind)
        self.assertEqual(len(direct.findings), len(routed.findings))

    def test_unknown_input_fails_cleanly(self):
        result = analysis.analyze_bytes(b"garbage-bytes-here", "x.bin")
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.diagnostics[0].code, "format.unknown")

    def test_truncated_macho_reports_error_not_traceback(self):
        data = fixture("ios_demo")[:40]
        result = analysis.analyze_bytes(data, "broken")
        self.assertEqual(result.status, "failed")
        self.assertTrue(result.diagnostics)


if __name__ == "__main__":
    unittest.main()
