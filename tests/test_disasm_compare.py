"""AC-2: normalisation and capstone-vs-objdump agreement."""
import subprocess
import unittest
from pathlib import Path

from reversesuite import disasm, disasm_compare, loader, strings

FIXTURES = Path("fixtures/frozen")
OBJDUMP = Path("tools/mingw64/bin/objdump.exe")


class NormalisationTests(unittest.TestCase):
    def test_operand_basics(self):
        self.assertEqual(disasm_compare.normalize_operands("QWORD PTR [rsp + 0x8]"), "[rsp+0x8]")
        self.assertEqual(disasm_compare.normalize_operands("[rsp + 8]"), "[rsp+0x8]")
        self.assertEqual(disasm_compare.normalize_operands("[rax*8+0x0]"), "[rax*0x8]")

    def test_sign_extended_displacement(self):
        self.assertEqual(disasm_compare.normalize_operands("[rip+0xffffffffffffb5a8]"), "[rip-0x4a58]")
        self.assertEqual(disasm_compare.normalize_operands("[rip - 0x4a58]"), "[rip-0x4a58]")

    def test_sign_extended_immediate(self):
        self.assertEqual(disasm_compare.normalize_operands("0xffffffff"), "-0x1")
        self.assertEqual(disasm_compare.normalize_operands("-1"), "-0x1")

    def test_objdump_comment_and_symbols(self):
        self.assertEqual(disasm_compare.normalize_operands("0x439a]        # 0x53e0"), "0x439a]")

    def test_rex_prefix_is_dropped(self):
        self.assertEqual(disasm_compare.normalize_mnemonic("rex"), "")
        self.assertEqual(disasm_compare.normalize_mnemonic("rex.w"), "")


class ParseTests(unittest.TestCase):
    def test_rebase_and_prefix_shift(self):
        sample = "\n".join([
            "   140001005:\trex push rbx",
            "   140001007:\tcall   1400033c0 <fflush>",
            "   14000100c:\tmov    rax,QWORD PTR [rip+0x439a]        # 0x53e0",
        ])
        parsed = disasm_compare.parse_objdump(sample, 0x140000000, 0x1000, 0x1000, 0x2000)
        self.assertEqual(parsed[0x1005].mnemonic, "push")
        self.assertEqual(parsed[0x1005].operands, "rbx")
        self.assertEqual(parsed[0x1007].key()[2], "0x33c0")
        self.assertEqual(disasm_compare.normalize_operands(parsed[0x100C].operands), "rax,[rip+0x439a]")


class AgreementTests(unittest.TestCase):
    def test_b_exec_agrees_with_objdump_over_99_percent(self):
        path = FIXTURES / "b.exe"
        data = path.read_bytes()
        text = loader.text_bytes(data)
        image_base = strings._image_base(data)
        text_rva = strings._text_rva(data)
        out = subprocess.run([str(OBJDUMP), "-d", "-M", "intel", "--no-show-raw-insn", str(path)],
                             capture_output=True, text=True, errors="replace").stdout
        base = disasm.BASE_ADDRESS
        reference = disasm_compare.parse_objdump(out, image_base, text_rva, base, base + len(text), base)
        result = disasm_compare.compare_at_addresses(reference, text, base)
        self.assertGreater(len(reference), 2000)
        self.assertGreaterEqual(result.accuracy, 0.99, result.summary())
        self.assertLessEqual(len(result.missing), 5)


if __name__ == "__main__":
    unittest.main()