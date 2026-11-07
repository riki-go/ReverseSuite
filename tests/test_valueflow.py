"""M6.1 intra-procedural value-set tests."""
import unittest
from pathlib import Path

from reversesuite import callgraph, valueflow

FIXTURES = Path("fixtures/frozen")


class ValueflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (FIXTURES / "b.exe").read_bytes()
        cls.graph = callgraph.build(cls.data)

    def test_global_to_function_pointer_chain(self):
        edge = next(e for e in self.graph.edges if e.site == 0x138B)
        self.assertEqual(edge.kind, callgraph.KIND_INDIRECT_RESOLVED)
        self.assertEqual(edge.callee, 0x1970)
        self.assertEqual(edge.via, 0x1378)

    def test_only_one_site_resolved_by_valueflow(self):
        self.assertEqual(self.graph.valueflow_resolved, 1)
        resolved = [e for e in self.graph.edges if e.kind == callgraph.KIND_INDIRECT_RESOLVED]
        self.assertEqual(len(resolved), 17)

    def test_every_resolved_target_is_a_node(self):
        nodes = set(self.graph.nodes)
        for edge in self.graph.edges:
            if edge.kind == callgraph.KIND_INDIRECT_RESOLVED and edge.callee is not None:
                self.assertIn(edge.callee, nodes)

    def test_unresolved_calls_stay_counted(self):
        self.assertEqual(self.graph.indirect_calls, 16)

    def test_direct_and_import_totals_unchanged(self):
        kinds = {}
        for edge in self.graph.edges:
            kinds[edge.kind] = kinds.get(edge.kind, 0) + 1
        self.assertEqual(kinds["direct"], 71)
        self.assertEqual(kinds["import"], 56)
        self.assertEqual(kinds["tail"], 2)

    def test_deterministic(self):
        again = callgraph.build(self.data)
        self.assertEqual(self.graph.as_dict(), again.as_dict())

    def test_image_view_maps_sections(self):
        view = valueflow.ImageView(self.data)
        self.assertIsNotNone(view.offset(0x1000))
        self.assertIsNone(view.offset(0x0))


if __name__ == "__main__":
    unittest.main()