"""Diff engine tests: node matching and multiset edge diffing."""
import copy
import json
import unittest
from pathlib import Path

from reversesuite import callgraph, diff


def graph() -> dict:
    data = (Path("fixtures/frozen") / "b.exe").read_bytes()
    return callgraph.build(data).as_dict()


def shifted(doc: dict, delta: int = 0x1000) -> dict:
    out = copy.deepcopy(doc)
    out["nodes"] = [a + delta for a in out["nodes"]]
    for item in out["node_info"]:
        item["start"] += delta
    for edge in out["edges"]:
        edge["caller"] += delta
        edge["site"] += delta
        if edge["callee"] is not None:
            edge["callee"] += delta
    return out


class SelfDiffTests(unittest.TestCase):
    def test_identical_graphs_have_no_changes(self):
        doc = graph()
        result = diff.diff_graphs(doc, doc)
        self.assertEqual(result.summary(), {"nodes": {"added": 0, "removed": 0, "moved": 0, "similar": 0},
                                            "edges": {"added": 0, "removed": 0, "unchanged": len(doc["edges"])}})

    def test_duplicate_edges_are_counted_not_collapsed(self):
        doc = graph()
        result = diff.diff_graphs(doc, doc)
        keys = {(e["caller"], e["callee"], e["kind"]) for e in doc["edges"]}
        self.assertLess(len(keys), len(doc["edges"]))
        self.assertEqual(result.unchanged_edges, len(doc["edges"]))


class MoveDiffTests(unittest.TestCase):
    def test_shifted_graph_matches_by_body_hash(self):
        base = graph()
        moved = shifted(base)
        result = diff.diff_graphs(base, moved)
        self.assertEqual(result.summary()["nodes"]["moved"], len(base["nodes"]))
        self.assertEqual(result.summary()["nodes"]["added"], 0)
        self.assertEqual(result.summary()["nodes"]["removed"], 0)
        self.assertEqual(result.unchanged_edges, len(base["edges"]))
        self.assertEqual(result.added_edges, [])
        self.assertEqual(result.removed_edges, [])

    def test_removed_node_reports_its_edges(self):
        base = graph()
        victim = next(e["caller"] for e in base["edges"])
        trimmed = copy.deepcopy(base)
        trimmed["nodes"] = [a for a in trimmed["nodes"] if a != victim]
        trimmed["node_info"] = [n for n in trimmed["node_info"] if n["start"] != victim]
        out_edges = [e for e in trimmed["edges"] if e["caller"] == victim]
        trimmed["edges"] = [e for e in trimmed["edges"] if e["caller"] != victim]
        result = diff.diff_graphs(base, trimmed)
        self.assertEqual(result.summary()["nodes"]["removed"], 1)
        self.assertEqual(len(result.removed_edges), len(out_edges))

    def test_added_node_reported(self):
        base = graph()
        extra = copy.deepcopy(base)
        extra["nodes"].append(0x99999)
        extra["node_info"].append({"start": 0x99999, "size": 8, "sha256": "00" * 32})
        result = diff.diff_graphs(base, extra)
        self.assertEqual(result.summary()["nodes"]["added"], 1)
        self.assertEqual(result.added_nodes[0].address, 0x99999)

    def test_ignore_thunks_drops_thunk_edges(self):
        base = graph()
        doc = copy.deepcopy(base)
        doc["edges"].append({"caller": base["nodes"][0], "callee": base["nodes"][1],
                             "kind": callgraph.KIND_THUNK, "site": 0x90000})
        kept = diff.diff_graphs(base, base)
        ignored = diff.diff_graphs(base, base, ignore_thunks=True)
        self.assertEqual(kept.unchanged_edges, len(base["edges"]))
        self.assertEqual(ignored.unchanged_edges, len(base["edges"]))
        changed = diff.diff_graphs(doc, base, ignore_thunks=True)
        self.assertEqual(changed.added_edges, [])


if __name__ == "__main__":
    unittest.main()