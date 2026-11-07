"""Call graph (M2 slice 1): direct call, tail-call and thunk-resolved edges.

Scope: direct `call rel32`, indirect calls (counted, no target), `jmp` that lands
on a known function start (tail call) and calls routed through a short jmp thunk.
Each edge records the call site so provenance survives into findings.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import capstone

from . import disasm, functions, loader, schema

RULE_EDGE = "pe.callgraph.edge"

KIND_DIRECT = "direct"
KIND_TAIL = "tail"
KIND_THUNK = "thunk"
KIND_INDIRECT = "indirect"

MAX_GRAPH_TEXT_BYTES = functions.MAX_FUNCTION_TEXT_BYTES


@dataclass(frozen=True)
class CallEdge:
    caller: int
    callee: Optional[int]
    site: int
    kind: str

    def as_dict(self) -> dict:
        return {"caller": self.caller, "callee": self.callee, "site": self.site, "kind": self.kind}


@dataclass
class CallGraph:
    nodes: Tuple[int, ...] = ()
    edges: Tuple[CallEdge, ...] = ()
    indirect_calls: int = 0
    unresolved_calls: int = 0
    tail_calls: int = 0
    thunk_calls: int = 0
    skipped: Optional[str] = None

    def out_degree(self) -> Dict[int, int]:
        counts: Dict[int, int] = {}
        for edge in self.edges:
            counts[edge.caller] = counts.get(edge.caller, 0) + 1
        return counts

    def as_dict(self) -> dict:
        return {
            "nodes": list(self.nodes),
            "edges": [e.as_dict() for e in self.edges],
            "indirect_calls": self.indirect_calls,
            "unresolved_calls": self.unresolved_calls,
            "tail_calls": self.tail_calls,
            "thunk_calls": self.thunk_calls,
            "skipped": self.skipped,
        }


def _thunks(text: bytes, funcs: Sequence[functions.Function], base: int) -> Dict[int, int]:
    """start -> final target for single-jmp thunk bodies."""
    engine = disasm.make_engine()
    out: Dict[int, int] = {}
    for fn in funcs:
        if fn.size > functions.THUNK_MAX_BYTES:
            continue
        off = fn.start - base
        if off < 0 or off >= len(text):
            continue
        insn = next(iter(engine.disasm(text[off:off + functions.THUNK_MAX_BYTES], fn.start)), None)
        if insn is None or insn.mnemonic != "jmp" or not insn.op_str.startswith("0x"):
            continue
        if insn.size != fn.size:
            continue
        try:
            target = int(insn.op_str, 16)
        except ValueError:
            continue
        if target != fn.start:
            out[fn.start] = target
    return out


def build(data: bytes, funcs: Optional[Sequence[functions.Function]] = None,
          base: int = disasm.BASE_ADDRESS,
          max_bytes: Optional[int] = MAX_GRAPH_TEXT_BYTES) -> CallGraph:
    text = loader.text_bytes(data)
    if functions.skip_reason(len(text), max_bytes):
        return CallGraph(skipped=functions.FUNCTION_SKIP_TEXT_TOO_LARGE)
    if funcs is None:
        funcs = functions.discover(text, exports=loader.export_addresses(data),
                                   entry=functions.entry_point(data), base=base)
    funcs = sorted(funcs, key=lambda f: f.start)
    nodes = tuple(f.start for f in funcs)
    node_set = set(nodes)
    spans = [(f.start, f.start + max(f.size, 1)) for f in funcs]
    starts = [s for s, _ in spans]
    thunks = _thunks(text, funcs, base)
    limit = base + len(text)

    def caller_of(addr: int) -> Optional[int]:
        """Nearest function start at or before addr (sizes from CFG can under-cover)."""
        idx = bisect.bisect_right(starts, addr) - 1
        return starts[idx] if idx >= 0 else None

    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    engine.detail = False
    edges: List[CallEdge] = []
    indirect = 0
    unresolved = 0
    tails = 0
    thunked = 0
    for insn in disasm.iter_instructions(text, base, engine):
        if insn.mnemonic not in ("call", "jmp"):
            continue
        caller = caller_of(insn.address)
        if caller is None:
            continue
        if insn.mnemonic == "call":
            if not insn.op_str.startswith("0x"):
                indirect += 1
                continue
            try:
                target = int(insn.op_str, 16)
            except ValueError:
                indirect += 1
                continue
            if target in thunks:
                edges.append(CallEdge(caller, thunks[target], insn.address, KIND_THUNK))
                thunked += 1
            elif target in node_set:
                edges.append(CallEdge(caller, target, insn.address, KIND_DIRECT))
            elif base <= target < limit:
                edges.append(CallEdge(caller, target, insn.address, KIND_DIRECT))
                unresolved += 1
            else:
                unresolved += 1
        else:
            if not insn.op_str.startswith("0x"):
                continue
            try:
                target = int(insn.op_str, 16)
            except ValueError:
                continue
            if target == caller or target not in node_set:
                continue
            edges.append(CallEdge(caller, target, insn.address, KIND_TAIL))
            tails += 1
    edges.sort(key=lambda e: (e.caller, e.site, e.callee or 0))
    return CallGraph(nodes=nodes, edges=tuple(edges), indirect_calls=indirect,
                     unresolved_calls=unresolved, tail_calls=tails, thunk_calls=thunked)


def to_findings(graph: CallGraph):
    """AC-14: one finding per resolved edge."""
    out = []
    for edge in graph.edges:
        out.append(schema.Finding(
            kind="edge",
            value="0x%x->0x%x" % (edge.caller, edge.callee or 0),
            confidence_permille=1000 if edge.kind == KIND_DIRECT else 900,
            level=edge.kind,
            rule=RULE_EDGE,
            evidence=[schema.Evidence(offset=edge.site, space="va", xref=edge.callee, rule=RULE_EDGE)],
        ))
    return out