"""Call graph tests: direct/tail/thunk edges and provenance."""
import unittest
from pathlib import Path

from reversesuite import callgraph, functions, loader, rules, schema


def frozen(name):
    return (Path("fixtures/frozen") / name).read_bytes()


class CallGraphTests(unittest.TestCase):
    def setUp(self):
        rules.enable(callgraph.RULE_EDGE)
        self.data = frozen("b.exe")
        self.graph = callgraph.build(self.data)

    def test_rule_registered(self):
        self.assertTrue(rules.is_registered(callgraph.RULE_EDGE))

    def test_nodes_match_discovery(self):
        found = functions.discover(loader.text_bytes(self.data), entry=functions.entry_point(self.data))
        self.assertEqual(self.graph.nodes, tuple(sorted(f.start for f in found)))

    def test_direct_edges_and_sites(self):
        direct = [e for e in self.graph.edges if e.kind == callgraph.KIND_DIRECT]
        self.assertEqual(len(direct), 71)
        self.assertEqual(len({e.site for e in direct}), len(direct))
        self.assertTrue(all(e.caller < e.site for e in direct))

    def test_known_edge_present(self):
        sites = {e.site for e in self.graph.edges}
        self.assertIn(0x104C, sites)
        edge = next(e for e in self.graph.edges if e.site == 0x104C)
        self.assertEqual(edge.kind, callgraph.KIND_DIRECT)
        self.assertEqual(edge.callee, 0x108E)

    def test_iat_call_resolves_to_import_name(self):
        edge = next(e for e in self.graph.edges if e.site == 0x1024)
        self.assertEqual(edge.kind, callgraph.KIND_IMPORT)
        self.assertIsNone(edge.callee)
        self.assertTrue(edge.name.endswith("!fflush"), edge.name)
        self.assertEqual(self.graph.import_calls, 56)
        self.assertEqual(self.graph.resolved_indirect, 16)

    def test_tail_calls_target_nodes(self):
        tails = [e for e in self.graph.edges if e.kind == callgraph.KIND_TAIL]
        self.assertEqual(len(tails), 2)
        self.assertTrue(all(e.callee in self.graph.nodes for e in tails))

    def test_unresolved_indirect_calls_never_become_edges(self):
        self.assertEqual(self.graph.indirect_calls, 17)
        self.assertTrue(all(e.kind != callgraph.KIND_INDIRECT for e in self.graph.edges))

    def test_indirect_call_resolved_through_iat_load(self):
        edge = next(e for e in self.graph.edges if e.site == 0x10EF)
        self.assertEqual(edge.kind, callgraph.KIND_INDIRECT_RESOLVED)
        self.assertTrue(edge.name.endswith("!Sleep"), edge.name)
        self.assertEqual(edge.via, 0x10E8)
        self.assertEqual(self.graph.resolved_indirect,
                         len([e for e in self.graph.edges if e.kind == callgraph.KIND_INDIRECT_RESOLVED]))

    def test_deterministic(self):
        again = callgraph.build(self.data)
        self.assertEqual(self.graph.as_dict(), again.as_dict())

    def test_findings_cite_rule_with_site_evidence(self):
        items = callgraph.to_findings(self.graph)
        self.assertEqual(len(items), len(self.graph.edges))
        self.assertTrue(all(i.rule == callgraph.RULE_EDGE for i in items))
        sites = {i.evidence[0].offset for i in items}
        self.assertIn(0x104C, sites)

    def test_disabled_rule_filters_edges(self):
        items = callgraph.to_findings(self.graph)
        rules.disable(callgraph.RULE_EDGE)
        try:
            self.assertEqual(schema.enforce_rules(items), [])
        finally:
            rules.enable(callgraph.RULE_EDGE)

    def test_large_text_is_skipped(self):
        graph = callgraph.build(frozen("b.exe"), max_bytes=1)
        self.assertEqual(graph.skipped, functions.FUNCTION_SKIP_TEXT_TOO_LARGE)
        self.assertEqual(graph.edges, ())


if __name__ == "__main__":
    unittest.main()