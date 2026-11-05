"""Tests for canonical schema and rule registry (stdlib unittest)."""
import json
import unittest

from reversesuite.schema import AnalysisResult, Diagnostic, Evidence, Finding
from reversesuite import rules


def sample() -> AnalysisResult:
    ev = [Evidence(offset=1024, space="file", rule="pe.section.parse")]
    return AnalysisResult(
        target_sha256="a" * 64,
        target_kind="pe",
        target_size=668672,
        status="ok",
        findings=[
            Finding(kind="section", value=".text", confidence_permille=1000, level="L0",
                    rule="pe.section.parse", evidence=ev),
            Finding(kind="string", value="hello", confidence_permille=500, level="L4",
                    rule="pe.strings.scan", evidence=[Evidence(offset=2048, rule="pe.strings.scan")]),
        ],
        diagnostics=[Diagnostic(code="pe.sectab.truncated", message="section table truncated", severity="error")],
    )


class SchemaTests(unittest.TestCase):
    def test_finding_id_is_deterministic(self):
        a = Finding(kind="string", value="hi", confidence_permille=100, level="L4",
                    rule="pe.strings.scan", evidence=[Evidence(offset=10, rule="pe.strings.scan")])
        b = Finding(kind="string", value="hi", confidence_permille=999, level="L4",
                    rule="pe.strings.scan", evidence=[Evidence(offset=10, rule="pe.strings.scan")])
        self.assertEqual(a.id, b.id)
        c = Finding(kind="string", value="ho", confidence_permille=100, level="L4",
                    rule="pe.strings.scan", evidence=[Evidence(offset=10, rule="pe.strings.scan")])
        self.assertNotEqual(a.id, c.id)

    def test_canonical_json_is_stable(self):
        r1 = sample()
        r2 = sample()
        self.assertEqual(r1.to_canonical_json(), r2.to_canonical_json())
        self.assertEqual(r1.canonical_hash(), r2.canonical_hash())

    def test_no_float_confidence(self):
        payload = json.loads(sample().to_canonical_json())
        for f in payload["findings"]:
            self.assertIsInstance(f["confidence_permille"], int)
            self.assertGreaterEqual(f["confidence_permille"], 0)
            self.assertLessEqual(f["confidence_permille"], 1000)

    def test_unregistered_rule_rejected(self):
        with self.assertRaises(ValueError):
            Finding(kind="x", value="y", confidence_permille=1, level="L0", rule="nope.rule")

    def test_bad_permille_rejected(self):
        with self.assertRaises(ValueError):
            Finding(kind="x", value="y", confidence_permille=1001, level="L0", rule="pe.section.parse")

    def test_arity_sorted_in_output(self):
        payload = json.loads(sample().to_canonical_json())
        kinds = [f["kind"] for f in payload["findings"]]
        self.assertEqual(kinds, sorted(kinds))

    def test_registry_has_loader_rules(self):
        for rid in ("pe.header.parse", "pe.coff.parse", "pe.opt.parse", "pe.section.parse"):
            self.assertTrue(rules.is_registered(rid))


if __name__ == "__main__":
    unittest.main()
