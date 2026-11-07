"""AC-14: rule registry enforcement over analysis findings."""
import unittest
from pathlib import Path

from reversesuite import functions, loader, rules, schema, strings


def frozen(name: str) -> bytes:
    return (Path("fixtures/frozen") / name).read_bytes()


class EnforcementTests(unittest.TestCase):
    def setUp(self):
        rules.enable("pe.string.ascii")
        rules.enable("pe.string.utf16le")
        rules.enable("pe.function.discover")

    def test_new_rules_registered_and_enabled(self):
        for rule_id in ("pe.function.discover", "pe.string.ascii", "pe.string.utf16le", "pe.string.xref"):
            self.assertTrue(rules.is_registered(rule_id), rule_id)
            self.assertTrue(rules.is_enabled(rule_id), rule_id)

    def test_function_findings_cite_registered_rule(self):
        data = frozen("b.exe")
        found = functions.discover(loader.text_bytes(data), entry=functions.entry_point(data))
        items = functions.to_findings(found)
        self.assertEqual(len(items), len(found))
        for item in items:
            self.assertEqual(item.rule, functions.RULE_FUNCTION)
            self.assertTrue(rules.is_registered(item.rule))
            self.assertTrue(item.value.startswith("0x"))
            self.assertEqual(item.evidence[0].space, "va")

    def test_string_findings_carry_encoding_and_rule(self):
        data = frozen("b.exe")
        items = strings.to_findings(strings.extract(data))
        self.assertEqual(len(items), 96)
        self.assertTrue(all(i.rule == strings.RULE_ASCII for i in items))
        self.assertTrue(all(i.encoding == "ascii" for i in items))

    def test_utf16_findings_use_utf16_rule(self):
        data = frozen("a.exe")
        items = strings.to_findings([s for s in strings.extract(data) if s.encoding == "utf16le"])
        self.assertGreater(len(items), 100)
        self.assertTrue(all(i.rule == strings.RULE_UTF16 for i in items))

    def test_disabled_rule_is_filtered_out(self):
        data = frozen("b.exe")
        items = strings.to_findings(strings.extract(data))
        self.assertEqual(len(schema.enforce_rules(items)), 96)
        rules.disable("pe.string.ascii")
        try:
            self.assertEqual(schema.enforce_rules(items), [])
            self.assertFalse(rules.is_enabled("pe.string.ascii"))
            self.assertNotIn("pe.string.ascii", {r.id for r in rules.enabled_rules()})
        finally:
            rules.enable("pe.string.ascii")

    def test_xrefs_become_evidence(self):
        data = frozen("b.exe")
        items = strings.to_findings(strings.extract_with_xrefs(data))
        with_refs = [i for i in items if len(i.evidence) > 1]
        self.assertEqual(len(with_refs), 20)
        self.assertTrue(all(e.rule == strings.RULE_XREF for i in with_refs for e in i.evidence[1:]))
        self.assertTrue(all(e.xref == i.evidence[0].offset for i in with_refs for e in i.evidence[1:]))

    def test_unknown_rule_cannot_be_constructed(self):
        with self.assertRaises(ValueError):
            schema.Finding(kind="x", value="y", confidence_permille=1, level="L0", rule="not.a.rule")


if __name__ == "__main__":
    unittest.main()