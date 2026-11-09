"""Dalvik (DEX) method-level call graph - static, stdlib only.

Decodes every code_item, keeps the invoke-kind opcodes (0x6e-0x72 and the
/range forms 0x74-0x7d) and turns them into caller -> callee edges keyed by
method_id. Framework/library callees are labelled so the UI can hide them.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Set, Tuple

from . import dex as dex_mod

MAX_METHODS = 300000
MAX_INSN_UNITS = 4 * 1024 * 1024

INVOKE_KINDS = {
    0x6E: "virtual", 0x6F: "super", 0x70: "direct", 0x71: "static", 0x72: "interface",
    0x74: "virtual", 0x75: "super", 0x76: "direct", 0x77: "static", 0x78: "interface",
    0xFA: "polymorphic", 0xFB: "polymorphic", 0xFC: "custom", 0xFD: "custom",
}
RANGE_OPS = {0x74, 0x75, 0x76, 0x77, 0x78, 0x7B, 0xFB, 0xFD}

FRAMEWORK_PREFIXES = (
    "java.", "javax.", "jdk.", "sun.", "android.", "androidx.", "dalvik.",
    "kotlin.", "kotlinx.", "org.jetbrains.", "com.android.", "org.apache.",
    "org.json.", "org.w3c.", "org.xml.", "libcore.",
)

# Instruction width in 16-bit code units, indexed by opcode (0x00-0xff).
# Payloads (0x0100/0x0200/0x0300 in the *high* byte of a nop) are handled separately.
WIDTHS: Tuple[int, ...] = (
    # 0x00-0x0f
    1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1,
    # 0x10-0x1f
    1, 1, 1, 2, 3, 2, 2, 3, 5, 2, 2, 3, 2, 1, 1, 2,
    # 0x20-0x2f
    2, 1, 2, 2, 3, 3, 3, 1, 1, 2, 3, 3, 3, 2, 2, 2,
    # 0x30-0x3f
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1,
    # 0x40-0x4f
    1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    # 0x50-0x5f
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    # 0x60-0x6f
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3,
    # 0x70-0x7f
    3, 3, 3, 1, 3, 3, 3, 3, 3, 1, 1, 1, 1, 1, 1, 1,
    # 0x80-0x8f
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    # 0x90-0x9f
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    # 0xa0-0xaf
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    # 0xb0-0xbf
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    # 0xc0-0xcf
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    # 0xd0-0xdf
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    # 0xe0-0xef
    2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    # 0xf0-0xff
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4, 4, 3, 3, 2, 2,
)


@dataclass
class DexNode:
    id: int
    label: str
    class_name: str
    framework: bool

    def as_dict(self) -> dict:
        return {"id": self.id, "label": self.label, "class": self.class_name,
                "framework": self.framework}


@dataclass
class DexEdge:
    caller: int
    callee: int
    kind: str

    def as_dict(self) -> dict:
        return {"caller": self.caller, "callee": self.callee, "kind": self.kind}


@dataclass
class DexGraph:
    nodes: List[DexNode] = field(default_factory=list)
    edges: List[DexEdge] = field(default_factory=list)
    methods_scanned: int = 0
    methods_with_code: int = 0
    hidden_nodes: int = 0
    decode_errors: int = 0

    def as_dict(self) -> dict:
        return {
            "nodes": [n.as_dict() for n in self.nodes],
            "edges": [e.as_dict() for e in self.edges],
            "stats": {
                "methods": len(self.nodes),
                "edges": len(self.edges),
                "scanned": self.methods_scanned,
                "with_code": self.methods_with_code,
                "hidden_framework": self.hidden_nodes,
                "decode_errors": self.decode_errors,
            },
        }


def is_framework(class_name: str) -> bool:
    return class_name.startswith(FRAMEWORK_PREFIXES)


def _code_insns(data: bytes, code_off: int) -> Optional[bytes]:
    """Return the raw instruction stream of a code_item (or None)."""
    if code_off <= 0 or code_off + 16 > len(data):
        return None
    _regs, _ins, _outs, tries, _dbg, insns_size = struct.unpack_from("<HHHHII", data, code_off)
    if insns_size == 0 or insns_size > MAX_INSN_UNITS:
        return None
    start = code_off + 16
    end = start + insns_size * 2
    if end > len(data):
        return None
    return data[start:end]


def iter_invokes(insns: bytes, base_pc: int = 0) -> Iterator[Tuple[int, int, str, int]]:
    """Yield (pc, opcode, kind, method_index) for every invoke instruction."""
    units = struct.unpack_from("<%dH" % (len(insns) // 2), insns)
    total = len(units)
    pc = 0
    while pc < total:
        unit = units[pc]
        opcode = unit & 0xFF
        if opcode == 0x00 and unit != 0x0000:
            # payload pseudo-instruction: 0x0100 packed-switch, 0x0200 sparse-switch,
            # 0x0300 fill-array-data - all carry their size in the second unit.
            kind = unit >> 8
            if kind in (0x01, 0x02):
                size = units[pc + 1] if pc + 1 < total else 0
                pc += size * 2 + 4
            elif kind == 0x03:
                width = units[pc + 1] if pc + 1 < total else 0
                count = units[pc + 2] if pc + 2 < total else 0
                length = (width * count + 1) // 2
                pc += length + 4
            else:
                pc += 1
            continue
        if opcode in INVOKE_KINDS and pc + 1 < total:
            method_idx = units[pc + 1]
            yield (base_pc + pc, opcode, INVOKE_KINDS[opcode], method_idx)
        width = WIDTHS[opcode] if opcode < len(WIDTHS) else 1
        pc += max(width, 1)


def build(data: bytes, include_framework: bool = False,
          max_edges: int = 200000) -> DexGraph:
    """Build the method-level call graph for a .dex image."""
    inventory = dex_mod.parse(data)
    graph = DexGraph()

    names: List[str] = list(inventory.method_names)
    signatures: List[str] = list(inventory.method_signatures)

    def node_for(method_idx: int) -> Optional[DexNode]:
        if method_idx >= len(names):
            return None
        label = names[method_idx]
        class_name = label.rsplit(".", 1)[0] if "." in label else label
        return DexNode(method_idx, label, class_name, is_framework(class_name))

    known: Dict[int, DexNode] = {}
    edges: Set[Tuple[int, int, str]] = set()

    for method_idx, code_off in sorted(inventory.code_offsets.items()):
        if method_idx >= len(names):
            continue
        graph.methods_scanned += 1
        caller = node_for(method_idx)
        if caller is None:
            continue
        insns = _code_insns(data, code_off)
        if insns is None:
            continue
        graph.methods_with_code += 1
        if caller.framework and not include_framework:
            continue
        for _pc, _op, kind, callee_idx in iter_invokes(insns):
            callee = node_for(callee_idx)
            if callee is None:
                continue
            if callee.framework and not include_framework:
                graph.hidden_nodes += 1
                continue
            key = (method_idx, callee_idx, kind)
            if key in edges:
                continue
            if len(edges) >= max_edges:
                break
            edges.add(key)
            known.setdefault(method_idx, caller)
            known.setdefault(callee_idx, callee)

    node_ids = sorted({e[0] for e in edges} | {e[1] for e in edges})
    graph.nodes = [known[i] for i in node_ids if i in known]
    graph.edges = [DexEdge(c, t, k) for (c, t, k) in sorted(edges)]
    return graph


def summarise(graph: DexGraph) -> str:
    stats = graph.as_dict()["stats"]
    return "dex graph: %d nodes / %d edges (scanned %d methods, %d with code)" % (
        stats["methods"], stats["edges"], stats["scanned"], stats["with_code"])
