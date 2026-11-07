"""Graph diff (M2 slice 2): match nodes, then diff edges.

Matching order:
1. same address and same body hash  -> "exact"
2. same body hash, unique on both sides -> "moved" (re-linked / re-based code)
3. same size and same in/out degree shape -> "similar" (best effort, reported apart)
Anything unmatched is removed (only in v1) or added (only in v2).

Edges are compared in the matched node space, so a function that moved still
counts as unchanged when its callees moved with it.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import callgraph

MATCH_EXACT = "exact"
MATCH_MOVED = "moved"
MATCH_SIMILAR = "similar"


@dataclass(frozen=True)
class NodeChange:
    address: int
    counterpart: Optional[int]
    size: int
    sha256: str

    def as_dict(self) -> dict:
        return {"address": self.address, "counterpart": self.counterpart,
                "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True)
class EdgeChange:
    caller: int
    callee: Optional[int]
    kind: str
    site: int

    def as_dict(self) -> dict:
        return {"caller": self.caller, "callee": self.callee, "kind": self.kind, "site": self.site}


@dataclass
class DiffResult:
    added_nodes: List[NodeChange] = field(default_factory=list)
    removed_nodes: List[NodeChange] = field(default_factory=list)
    moved_nodes: List[Tuple[NodeChange, int]] = field(default_factory=list)
    similar_nodes: List[Tuple[NodeChange, int]] = field(default_factory=list)
    added_edges: List[EdgeChange] = field(default_factory=list)
    removed_edges: List[EdgeChange] = field(default_factory=list)
    unchanged_edges: int = 0
    mapping: Dict[int, int] = field(default_factory=dict)

    def summary(self) -> dict:
        return {
            "nodes": {"added": len(self.added_nodes), "removed": len(self.removed_nodes),
                      "moved": len(self.moved_nodes), "similar": len(self.similar_nodes),
                    },
            "edges": {"added": len(self.added_edges), "removed": len(self.removed_edges),
                      "unchanged": self.unchanged_edges},
        }

    def as_dict(self) -> dict:
        return {
            "summary": self.summary(),
            "added_nodes": [n.as_dict() for n in self.added_nodes],
            "removed_nodes": [n.as_dict() for n in self.removed_nodes],
            "moved_nodes": [{"from": n.as_dict(), "to": to} for n, to in self.moved_nodes],
            "similar_nodes": [{"from": n.as_dict(), "to": to} for n, to in self.similar_nodes],
            "added_edges": [e.as_dict() for e in self.added_edges],
            "removed_edges": [e.as_dict() for e in self.removed_edges],
            "unchanged_edges": self.unchanged_edges,
        }


def _doc(data: dict) -> Tuple[List[dict], List[dict]]:
    nodes = list(data.get("node_info") or [])
    if not nodes:
        nodes = [{"start": a, "size": 0, "sha256": ""} for a in data.get("nodes", [])]
    return nodes, list(data.get("edges", []))


def diff_graphs(v1: dict, v2: dict, ignore_thunks: bool = False) -> DiffResult:
    nodes1, edges1 = _doc(v1)
    nodes2, edges2 = _doc(v2)
    if ignore_thunks:
        edges1 = [e for e in edges1 if e.get("kind") != callgraph.KIND_THUNK]
        edges2 = [e for e in edges2 if e.get("kind") != callgraph.KIND_THUNK]

    by_addr1 = {n["start"]: n for n in nodes1}
    by_addr2 = {n["start"]: n for n in nodes2}
    mapping: Dict[int, int] = {}
    used2: set = set()

    for addr, n1 in by_addr1.items():
        n2 = by_addr2.get(addr)
        if n2 is not None and (not n1.get("sha256") or n1.get("sha256") == n2.get("sha256")):
            mapping[addr] = addr
            used2.add(addr)

    def index_by_hash(nodes):
        idx: Dict[str, List[int]] = {}
        for n in nodes:
            if n.get("sha256"):
                idx.setdefault(n["sha256"], []).append(n["start"])
        return idx

    hash1 = index_by_hash(nodes1)
    hash2 = index_by_hash(nodes2)
    for key, addrs1 in hash1.items():
        cand1 = sorted(a for a in addrs1 if a not in mapping)
        cand2 = sorted(a for a in hash2.get(key, []) if a not in used2)
        if not cand1 or len(cand1) != len(cand2):
            continue
        for a1, a2 in zip(cand1, cand2):
            if a1 == a2:
                mapping[a1] = a2
            else:
                mapping[a1] = a2
            used2.add(a2)

    # similar: same size and same edge shape, unique candidates
    def shape(edges):
        degree: Dict[int, int] = {}
        for e in edges:
            degree[e["caller"]] = degree.get(e["caller"], 0) + 1
            degree[e["callee"]] = degree.get(e["callee"], 0) + 1
        return degree

    degree1, degree2 = shape(edges1), shape(edges2)
    for addr, n1 in by_addr1.items():
        if addr in mapping:
            continue
        size = n1.get("size")
        deg = degree1.get(addr, 0)
        cand = [a for a in by_addr2
                if a not in used2
                and by_addr2[a].get("size") == size
                and degree2.get(a, 0) == deg
                and size]
        if len(cand) == 1:
            mapping[addr] = cand[0]
            used2.add(cand[0])

    reverse = {v: k for k, v in mapping.items()}
    result = DiffResult(mapping=mapping)
    for addr, n1 in by_addr1.items():
        change = NodeChange(address=n1["start"], counterpart=None,
                             size=n1.get("size", 0), sha256=n1.get("sha256", ""))
        if addr not in mapping:
            result.removed_nodes.append(change)
        elif mapping[addr] != addr:
            if n1.get("sha256") and by_addr2[mapping[addr]].get("sha256") == n1["sha256"]:
                result.moved_nodes.append((change, mapping[addr]))
            else:
                result.similar_nodes.append((change, mapping[addr]))
    for addr, n2 in by_addr2.items():
        if addr not in reverse:
            result.added_nodes.append(NodeChange(addr, None, n2.get("size", 0), n2.get("sha256", "")))

    def key1(e) -> Tuple[int, Optional[int], str, Optional[str]]:
        """Edges are compared in v1 address space; v2 edges are mapped back."""
        return (e["caller"], e.get("callee"), e.get("kind", ""), e.get("name"))

    def key2(e) -> Tuple[int, Optional[int], str, Optional[str]]:
        caller = reverse.get(e["caller"], e["caller"])
        callee = e.get("callee")
        callee = reverse.get(callee, callee) if callee is not None else None
        return (caller, callee, e.get("kind", ""), e.get("name"))

    counts1 = Counter(key1(e) for e in edges1)
    counts2 = Counter(key2(e) for e in edges2)
    common = counts1 & counts2
    result.unchanged_edges = sum(common.values())
    remaining1 = counts1 - common
    remaining2 = counts2 - common
    for e in edges1:
        key = key1(e)
        if remaining1[key] > 0:
            remaining1[key] -= 1
            result.removed_edges.append(EdgeChange(e["caller"], e.get("callee"), e.get("kind", ""), e.get("site", 0)))
    for e in edges2:
        key = key2(e)
        if remaining2[key] > 0:
            remaining2[key] -= 1
            result.added_edges.append(EdgeChange(e["caller"], e.get("callee"), e.get("kind", ""), e.get("site", 0)))
    result.removed_edges.sort(key=lambda e: (e.caller, e.site))
    result.added_edges.sort(key=lambda e: (e.caller, e.site))
    return result