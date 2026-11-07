"""Report rendering tests: markdown/html output, escaping, determinism."""
import unittest
from pathlib import Path

from reversesuite import callgraph, diff, report


def graphs():
    b = (Path("fixtures/frozen") / "b.exe").read_bytes()
    a = (Path("fixtures/frozen") / "a.exe").read_bytes()
    return callgraph.build(b).as_dict(), callgraph.build(a).as_dict()


class ReportTests(unittest.TestCase):
    def test_self_diff_markdown(self):
        b, _ = graphs()
        result = diff.diff_graphs(b, b)
        text = report.render_markdown(result, "b.exe", "b.exe")
        self.assertIn("# ReverseSuite diff report", text)
        self.assertIn("**No changes detected.**", text)
        self.assertIn("| edges unchanged | %d |" % len(b["edges"]), text)

    def test_html_escapes_untrusted_labels(self):
        b, _ = graphs()
        result = diff.diff_graphs(b, b)
        text = report.render_html(result, "<script>alert(1)</script>", "b.exe")
        self.assertNotIn("<script>alert(1)</script>", text)
        self.assertIn("&lt;script&gt;", text)

    def test_html_is_standalone(self):
        b, _ = graphs()
        result = diff.diff_graphs(b, b)
        text = report.render_html(result)
        self.assertTrue(text.startswith("<!DOCTYPE html>"))
        self.assertIn("<style>", text)
        self.assertNotIn("<script", text)

    def test_deterministic_output(self):
        b, a = graphs()
        result = diff.diff_graphs(b, a, ignore_thunks=True)
        first = report.render_html(result, "b", "a")
        second = report.render_html(diff.diff_graphs(b, a, ignore_thunks=True), "b", "a")
        self.assertEqual(first, second)

    def test_large_diff_is_truncated(self):
        b, a = graphs()
        text = report.render_markdown(diff.diff_graphs(b, a), "b.exe", "a.exe")
        self.assertIn("... and ", text)
        self.assertLess(len(text), 40000)

    def test_unknown_format_rejected(self):
        b, _ = graphs()
        with self.assertRaises(ValueError):
            report.render(diff.diff_graphs(b, b), fmt="pdf")


if __name__ == "__main__":
    unittest.main()