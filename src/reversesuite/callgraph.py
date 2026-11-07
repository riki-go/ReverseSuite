"""Call graph (M2 slice 1): direct call, tail-call and thunk-resolved edges.

Scope: direct `call rel32`, indirect calls (counted, no target), `jmp` that lands
on a known function start (tail call) and calls routed through a short jmp thunk.
Each edge records the call site so provenance survives into findings.
"""
from __future__ import annotations

import bisect
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import capstone

from . import disasm, functions, loader, schema

RULE_EDGE = "pe.callgraph.edge"

KIND_DIRECT = "direct"
KIND_TAIL = "tail"
KIND_THUNK = "thunk"
KIND_INDIRECT = "indirect"
KIND_IMPORT = "import"
KIND_INDIRECT_RESOLVED = "indirect_resolved"

MAX_GRAPH_TEXT_BYTES = functions.MAX_FUNCTION_TEXT_BYTES


@dataclass(frozen=True)
class NodeInfo:
    start: int
    size: int
    sha256: str

    def as_dict(self) -> dict:
        return {"start": self.start, "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True)
class CallEdge:
    caller: int
    callee: Optional[int]
    site: int
    kind: str
    name: Optional[str] = None
    via: Optional[int] = None

    def as_dict(self) -> dict:
        return {"caller": self.caller, "callee": self.callee, "site": self.site,
                "kind": self.kind, "name": self.name, "via": self.via}


@dataclass
class CallGraph:
    nodes: Tuple[int, ...] = ()
    edges: Tuple[CallEdge, ...] = ()
    node_info: Tuple[NodeInfo, ...] = ()
    indirect_calls: int = 0
    import_calls: int = 0
    resolved_indirect: int = 0
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
            "node_info": [n.as_dict() for n in self.node_info],
            "edges": [e.as_dict() for e in self.edges],
            "indirect_calls": self.indirect_calls,
            "import_calls": self.import_calls,
            "resolved_indirect": self.resolved_indirect,
            "unresolved_calls": self.unresolved_calls,
            "tail_calls": self.tail_calls,
            "thunk_calls": self.thunk_calls,
            "skipped": self.skipped,
        }


def _mem_target(insn: capstone.CsInsn, op) -> Optional[int]:
    """Resolve a memory operand that holds an absolute address."""
    if op.type != capstone.x86.X86_OP_MEM:
        return None
    if op.mem.base == capstone.x86.X86_REG_RIP:
        return insn.address + insn.size + op.mem.disp
    if op.mem.base == 0 and op.mem.index == 0:
        return op.mem.disp & 0xFFFFFFFFFFFFFFFF
    return None


def _thunks(text: bytes, funcs: Sequence[functions.Function], base: int,
            iat: Dict[int, str]) -> Dict[int, Tuple[str, Optional[int], Optional[str]]]:
    """start -> ("import", None, name) or ("thunk", target, None) for one-jmp bodies."""
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    engine.detail = True
    out: Dict[int, Tuple[str, Optional[int], Optional[str]]] = {}
    for fn in funcs:
        if fn.size > functions.THUNK_MAX_BYTES:
            continue
        off = fn.start - base
        if off < 0 or off >= len(text):
            continue
        insn = next(iter(engine.disasm(text[off:off + functions.THUNK_MAX_BYTES], fn.start)), None)
        if insn is None or insn.mnemonic != "jmp" or insn.size != fn.size:
            continue
        if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
            target = insn.operands[0].imm
            if target != fn.start:
                out[fn.start] = ("thunk", target, None)
            continue
        slot = _mem_target(insn, insn.operands[0]) if insn.operands else None
        if slot is not None and slot in iat:
            out[fn.start] = ("import", None, iat[slot])
    return out

PROVENANCE_WINDOW = 2
PROVENANCE_REGS = {capstone.x86.X86_REG_RAX: "rax", capstone.x86.X86_REG_RBX: "rbx",
                   capstone.x86.X86_REG_RCX: "rcx", capstone.x86.X86_REG_RDX: "rdx",
                   capstone.x86.X86_REG_RSI: "rsi", capstone.x86.X86_REG_RDI: "rdi",
                   capstone.x86.X86_REG_R8: "r8", capstone.x86.X86_REG_R9: "r9",
                   capstone.x86.X86_REG_R10: "r10", capstone.x86.X86_REG_R11: "r11"}


def _register_name(operand) -> Optional[str]:
    if operand.type != capstone.x86.X86_OP_REG:
        return None
    return PROVENANCE_REGS.get(operand.reg)


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
    infos = []
    for fn in funcs:
        off = fn.start - base
        body = text[off:off + fn.size] if 0 <= off < len(text) else b""
        infos.append(NodeInfo(fn.start, fn.size, hashlib.sha256(body).hexdigest()))
    spans = [(f.start, f.start + max(f.size, 1)) for f in funcs]
    starts = [s for s, _ in spans]
    iat: Dict[int, str] = {}
    for entry in loader.imports(data):
        label = entry.module + "!" + entry.name
        iat.setdefault(entry.iat_address, label)
    thunks = _thunks(text, funcs, base, iat)
    limit = base + len(text)

    def caller_of(addr: int) -> Optional[int]:
        """Nearest function start at or before addr (sizes from CFG can under-cover)."""
        idx = bisect.bisect_right(starts, addr) - 1
        return starts[idx] if idx >= 0 else None

    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    engine.detail = True
    edges: List[CallEdge] = []
    indirect = 0
    imports_hit = 0
    unresolved = 0
    tails = 0
    thunked = 0
    resolved_indirect = 0
    provenance: dict = {}
    step = 0
    for insn in disasm.iter_instructions(text, base, engine):
        step += 1
        # Track simple register provenance inside a short straight-line window.
        if insn.mnemonic in ("lea", "mov") and len(insn.operands) == 2:
            dst = _register_name(insn.operands[0])
            if dst:
                value = None
                if insn.mnemonic == "lea":
                    value = _mem_target(insn, insn.operands[1])
                    if value is not None:
                        value = ("func", value, None)
                else:
                    slot = _mem_target(insn, insn.operands[1])
                    if slot is not None and slot in iat:
                        value = ("import", None, iat[slot])
                if value is None:
                    provenance.pop(dst, None)
                else:
                    provenance[dst] = (value, step, insn.address)
        elif insn.mnemonic in ("xor", "add", "sub", "and", "or", "pop", "movzx", "movsx") and insn.operands:
            dst = _register_name(insn.operands[0])
            if dst:
                provenance.pop(dst, None)
        if insn.mnemonic not in ("call", "jmp") or not insn.operands:
            continue
        caller = caller_of(insn.address)
        if caller is None:
            continue
        op = insn.operands[0]
        if op.type == capstone.x86.X86_OP_IMM:
            target: Optional[int] = op.imm
        else:
            target = _mem_target(insn, op)
        if insn.mnemonic == "call":
            if target is None:
                reg = _register_name(op)
                entry = provenance.get(reg) if reg else None
                if entry is not None and (step - entry[1]) <= PROVENANCE_WINDOW:
                    kind, final, label = entry[0]
                    via = entry[2]
                    if kind == "import":
                        edges.append(CallEdge(caller, None, insn.address, KIND_INDIRECT_RESOLVED, label, via))
                        resolved_indirect += 1
                        continue
                    if kind == "func" and final in node_set:
                        edges.append(CallEdge(caller, final, insn.address, KIND_INDIRECT_RESOLVED, None, via))
                        resolved_indirect += 1
                        continue
                indirect += 1
                continue
            if target in iat:
                edges.append(CallEdge(caller, None, insn.address, KIND_IMPORT, iat[target]))
                imports_hit += 1
                continue
            if target in thunks:
                kind, final, label = thunks[target]
                if kind == "import":
                    edges.append(CallEdge(caller, None, insn.address, KIND_IMPORT, label))
                    imports_hit += 1
                else:
                    edges.append(CallEdge(caller, final, insn.address, KIND_THUNK))
                    thunked += 1
                continue
            if target in node_set:
                edges.append(CallEdge(caller, target, insn.address, KIND_DIRECT))
            elif base <= target < limit:
                edges.append(CallEdge(caller, target, insn.address, KIND_DIRECT))
                unresolved += 1
            else:
                edges.append(CallEdge(caller, None, insn.address, KIND_IMPORT, "external@0x%x" % target))
                unresolved += 1
        else:
            if target is None or target == caller or target not in node_set:
                continue
            edges.append(CallEdge(caller, target, insn.address, KIND_TAIL))
            tails += 1
    edges.sort(key=lambda e: (e.caller, e.site, e.callee or 0))
    return CallGraph(nodes=nodes, edges=tuple(edges), node_info=tuple(infos),
                     indirect_calls=indirect, import_calls=imports_hit,
                     resolved_indirect=resolved_indirect,
                     unresolved_calls=unresolved, tail_calls=tails, thunk_calls=thunked)


def to_findings(graph: CallGraph):
    """AC-14: one finding per resolved edge."""
    out = []
    for edge in graph.edges:
        out.append(schema.Finding(
            kind="edge",
            value=("0x%x->%s" % (edge.caller, edge.name)) if edge.callee is None else (
                "0x%x->0x%x" % (edge.caller, edge.callee)),
            confidence_permille=1000 if edge.kind == KIND_DIRECT else 900,
            level=edge.kind,
            rule=RULE_EDGE,
            evidence=[schema.Evidence(offset=edge.site, space="va", xref=edge.callee, rule=RULE_EDGE)],
        ))
    return out