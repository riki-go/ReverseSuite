"""AC-6 packed detection and AC-8 CLI exit-code mapping."""
import unittest
from pathlib import Path

from reversesuite import cli, loader

FIXTURES = Path("fixtures/frozen")


class PackedTests(unittest.TestCase):
    def test_packed_binary_reports_upx(self):
        data = (FIXTURES / "b_packed.exe").read_bytes()
        result = loader.parse(data)
        packers = [f for f in result.findings if f.kind == "packer"]
        self.assertEqual(len(packers), 1)
        self.assertEqual(packers[0].value, "upx")
        self.assertEqual(packers[0].rule, "pe.packer.upx")

    def test_unpacked_binary_reports_no_packer(self):
        result = loader.parse((FIXTURES / "b.exe").read_bytes())
        self.assertEqual([f for f in result.findings if f.kind == "packer"], [])


class ExitCodeTests(unittest.TestCase):
    def run_cli(self, argv):
        import io
        from contextlib import redirect_stdout, redirect_stderr
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_ok_is_0(self):
        code, _, _ = self.run_cli(["analyze", str(FIXTURES / "b.exe")])
        self.assertEqual(code, 0)

    def test_missing_file_is_usage_error(self):
        code, _, err = self.run_cli(["analyze", str(FIXTURES / "does-not-exist.exe")])
        self.assertEqual(code, 4)
        self.assertIn("cannot read input", err)

    def test_corrupt_input_is_failed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.exe"
            path.write_bytes(b"MZ" + b"\x00" * 64)
            code, _, _ = self.run_cli(["analyze", str(path)])
        self.assertEqual(code, 3)

    def test_missing_subcommand_is_usage_error(self):
        code, _, _ = self.run_cli([])
        self.assertEqual(code, 4)

    def test_degraded_is_2(self):
        import tempfile
        data = bytearray((FIXTURES / "b.exe").read_bytes())
        data = data[:-2000]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "truncated.exe"
            path.write_bytes(bytes(data))
            code, _, _ = self.run_cli(["analyze", str(path)])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()