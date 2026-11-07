"""Heuristic function discovery (AC-15 slice 1).

Sources, in confidence order:
- export table entries (L0, exact)
- direct call targets (L4, strong heuristic)
- frame prologues push rbp; mov rbp, rsp (L4, weak heuristic)

Function sizes are derived from the next discovered start (or end of .text).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

import capstone

from . import disasm

CONF_CALL = 900
CONF_PROLOGUE = 600
CONF_EXPORT = 1000


@dataclass(frozen=True)
class Function:
    start: int
    size: int
    sources: tuple
    confidence_permille: int
    level: str

    def as_dict(self) -> dict:
        return {"start": self.start, "size": self.size, "sources": list(self.sources),
                "confidence_permille": self.confidence_permille, "level": self.level}


def _is_prologue(md: capstone.Cs, blob: bytes, offset: int) -> bool:
    window = blob[offset:offset + 16]
    insns = list(md.disasm(window, 0))[:3]
    if len(insns) < 2:
        return False
    first, second = insns[0], insns[1]
    if first.mnemonic == "push" and first.op_str == "rbp" and second.mnemonic == "mov" and second.op_str.replace(" ", "") == "rbp,rsp":
        return True
    return False


def discover(blob: bytes, base: int = disasm.BASE_ADDRESS,
             exports: Optional[List[int]] = None,
             md: Optional[capstone.Cs] = None) -> List[Function]:
    engine = md or disasm.make_engine()
    found: Dict[int, dict] = {}

    for addr in exports or []:
        found.setdefault(addr, {"sources": set(), "confidence": 0, "level": "L4"})
        entry = found[addr]
        entry["sources"].add("export")
        entry["confidence"] = CONF_EXPORT
        entry["level"] = "L0"

    for insn in disasm.iter_instructions(blob, base, engine):
        if insn.mnemonic == "call" and insn.op_str.startswith("0x"):
            try:
                target = int(insn.op_str, 16)
            except ValueError:
                continue
            if base <= target < base + len(blob):
                entry = found.setdefault(target, {"sources": set(), "confidence": 0, "level": "L4"})
                entry["sources"].add("call_target")
                entry["confidence"] = max(entry["confidence"], CONF_CALL)

    # prologue scan at every instruction boundary already visited
    for insn in disasm.iter_instructions(blob, base, engine):
        if insn.mnemonic == "push" and insn.op_str == "rbp":
            offset = insn.address - base
            if _is_prologue(engine, blob, offset):
                entry = found.setdefault(insn.address, {"sources": set(), "confidence": 0, "level": "L4"})
                entry["sources"].add("prologue")
                entry["confidence"] = max(entry["confidence"], CONF_PROLOGUE)

    starts = sorted(found)
    functions: List[Function] = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else base + len(blob)
        entry = found[start]
        functions.append(Function(
            start=start,
            size=max(0, end - start),
            sources=tuple(sorted(entry["sources"])),
            confidence_permille=entry["confidence"],
            level=entry["level"],
        ))
    return functions
