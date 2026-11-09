"""End-to-end CLI tests: analyze runs loader + functions + strings."""
import io
import json
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from reversesuite import cli


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_analyze_b_runs_all_passes(self):
        code, out, err = run(["analyze", "fixtures/frozen/b.exe"])
        self.assertEqual(code, 0, err)
        self.assertIn("functions 88", out)
        self.assertIn("strings  96 (ascii=96 utf16le=0) xref=20", out)
        self.assertIn("diagnostics 0", out)
        self.assertIn("edges    145  indirect_calls 17", out)

    def test_analyze_json_is_canonical(self):
        code, out, err = run(["analyze", "fixtures/frozen/b.exe", "--json"])
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        self.assertIn("schema_version", doc)
        self.assertEqual(doc["status"], "ok")
        self.assertGreaterEqual(len(doc["findings"]), 180)
        rules = {f["rule"] for f in doc["findings"]}
        self.assertIn("pe.function.discover", rules)
        self.assertIn("pe.string.ascii", rules)

    @unittest.skipUnless(Path("fixtures/out/d.exe").exists(), "fixtures/out/d.exe not generated")
    def test_analyze_large_file_skips_heavy_passes(self):
        code, out, err = run(["analyze", "fixtures/out/d.exe"])
        self.assertEqual(code, 0, err)
        self.assertIn("skip=text_too_large_for_xref", out.replace("skipped=", "skip="))
        self.assertIn("text_too_large_for_functions", out)
        self.assertIn("functions 0", out)

    def test_strings_subcommand_json(self):
        code, out, err = run(["strings", "fixtures/frozen/b.exe", "--json", "--no-xref"])
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        self.assertEqual(doc["count"], 96)
        self.assertEqual(doc["with_xref"], 0)

    def test_calls_subcommand(self):
        code, out, err = run(["calls", "fixtures/frozen/b.exe"])
        self.assertEqual(code, 0, err)
        self.assertIn("nodes 88 edges 145 (direct=71, import=56, indirect_resolved=16, tail=2) indirect 17 imports 56", out)

    def test_calls_json(self):
        code, out, err = run(["calls", "fixtures/frozen/b.exe", "--json"])
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        self.assertEqual(len(doc["nodes"]), 88)
        self.assertEqual(len(doc["edges"]), 145)
        self.assertEqual(doc["indirect_calls"], 17)

    def test_diff_same_file_is_empty(self):
        code, out, err = run(["diff", "fixtures/frozen/b.exe", "fixtures/frozen/b.exe"])
        self.assertEqual(code, 0, err)
        self.assertIn("nodes  +0 -0 ~0(moved) ~0(similar)", out)
        self.assertIn("edges  +0 -0 =145", out)

    def test_diff_json_output(self):
        code, out, err = run(["diff", "fixtures/frozen/b.exe", "fixtures/frozen/b.exe", "--json"])
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        self.assertEqual(doc["summary"]["edges"]["unchanged"], 145)
        self.assertEqual(doc["summary"]["nodes"]["added"], 0)

    def test_report_to_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out_path = str((Path(tmp) / "report.md"))
            code, out, err = run(["report", "fixtures/frozen/b.exe", "fixtures/frozen/b.exe",
                                  "--out", out_path])
            self.assertEqual(code, 0, err)
            payload = json.loads(out)
            self.assertEqual(payload["format"], "md")
            body = Path(out_path).read_text(encoding="utf-8")
            self.assertIn("No changes detected", body)

    def test_report_html_on_stdout(self):
        code, out, err = run(["report", "fixtures/frozen/b.exe", "fixtures/frozen/b.exe",
                              "--format", "html"])
        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith("<!DOCTYPE html>"))

    def test_missing_subcommand_is_usage_error(self):
        code, out, err = run([])
        self.assertEqual(code, 4)


if __name__ == "__main__":
    unittest.main()