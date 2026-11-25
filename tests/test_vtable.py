"""M6.3: vtable inventory with RTTI class names."""
import unittest
from pathlib import Path

from reversesuite import callgraph

FIXTURE = Path("fixtures/frozen/vtable_demo.exe")


class VtableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = FIXTURE.read_bytes()
        cls.graph = callgraph.build(cls.data, use_valueflow=True)

    def test_named_vtables_are_found(self):
        names = {name for _addr, name, _slots in self.graph.vtables if name}
        self.assertIn("Base", names)
        self.assertIn("Derived", names)

    def test_class_tables_have_the_expected_slots(self):
        slots = {name: len(s) for _addr, name, s in self.graph.vtables if name}
        self.assertEqual(slots["Base"], 4)
        self.assertEqual(slots["Derived"], 4)

    def test_slots_point_at_discovered_functions(self):
        nodes = set(self.graph.nodes)
        for _addr, name, entries in self.graph.vtables:
            if not name:
                continue
            for target in entries:
                self.assertIn(target, nodes)

    def test_findings_carry_rule_and_name(self):
        findings = [f for f in callgraph.to_findings(self.graph) if f.kind == "vtable"]
        self.assertTrue(findings)
        self.assertTrue(all(f.rule == "pe.callgraph.vtable" for f in findings))
        self.assertTrue(any(f.value.startswith("Derived:") for f in findings))

    def test_inventory_is_opt_in(self):
        plain = callgraph.build(self.data)
        self.assertEqual(plain.vtables, ())


if __name__ == "__main__":
    unittest.main()
