"""End-to-end CLI tests: analyze runs loader + functions + strings."""
import io
import json
import unittest
from contextlib import redirect_stdout, redirect_stderr

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
        self.assertIn("edges    127  indirect_calls 35", out)

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
        self.assertIn("nodes 88 edges 127 (direct=125, tail=2) indirect 35", out)

    def test_calls_json(self):
        code, out, err = run(["calls", "fixtures/frozen/b.exe", "--json"])
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        self.assertEqual(len(doc["nodes"]), 88)
        self.assertEqual(len(doc["edges"]), 127)
        self.assertEqual(doc["indirect_calls"], 35)

    def test_missing_subcommand_is_usage_error(self):
        code, out, err = run([])
        self.assertEqual(code, 4)


if __name__ == "__main__":
    unittest.main()