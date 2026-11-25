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
        total_resolved = len([e for e in self.graph.edges
                              if e.kind == callgraph.KIND_INDIRECT_RESOLVED])
        self.assertEqual(self.graph.resolved_indirect + self.graph.valueflow_resolved, total_resolved)

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


class InterprocTests(unittest.TestCase):
    """M6.2: stack spills, register copies and IAT loads resolve register calls."""

    def _seq(self, code_bytes, address=0x1000):
        import capstone
        engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        engine.detail = True
        return list(engine.disasm(code_bytes, address))

    def test_stack_spill_is_followed(self):
        from reversesuite import callgraph_interproc as ci
        # lea rax,[rip+0x10] -> 0x1017; mov [rbp-8],rax; call [rbp-8]
        code = bytes.fromhex("488d0510000000" "488945f8" "ff55f8")
        calls = ci.resolve_function(self._seq(code), {0x1017}, view=None)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].target, 0x1017)
        self.assertTrue(calls[0].via.startswith("slot:"))

    def test_register_copy_is_followed(self):
        from reversesuite import callgraph_interproc as ci
        # lea rbx,[rip+0x10] -> 0x1017; mov rax,rbx; call rax
        code = bytes.fromhex("488d1d10000000" "4889d8" "ffd0")
        calls = ci.resolve_function(self._seq(code), {0x1017}, view=None)
        self.assertEqual([c.target for c in calls], [0x1017])

    def test_iat_slot_resolves_to_import(self):
        from reversesuite import callgraph_interproc as ci
        # mov rax,[rip+0x10]; call rax with the slot mapped to an import
        code = bytes.fromhex("488b0510000000" "ffd0")
        iat = {0x1017: "KERNEL32.dll!ExitProcess"}
        calls = ci.resolve_function(self._seq(code), set(), view=None, iat=iat)
        self.assertEqual(calls[0].name, "KERNEL32.dll!ExitProcess")
        self.assertIsNone(calls[0].target)

    def test_unknown_register_stays_unresolved(self):
        from reversesuite import callgraph_interproc as ci
        self.assertEqual(ci.resolve_function(self._seq(bytes.fromhex("ffd0")), set(), view=None), [])

if __name__ == "__main__":
    unittest.main()