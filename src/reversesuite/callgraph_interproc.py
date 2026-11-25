"""M6.2 - inter-procedural value-set pass.

The intra-procedural pass (M6.1) only follows a register inside a short window.
Real -O0 code spills pointers to the stack, reloads them later and passes them to
other functions. This pass models those moves:

  * registers <- constants (immediate, `lea` of a function, pointer read from .rdata)
  * stack slots [rbp-x] / [rsp+x] <- register value, and the reverse load
  * register <- register copies

and then resolves `call reg` / `call [rbp-x]` sites the earlier passes left open.
It never guesses: a slot is only trusted while it holds one provable constant.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import capstone

from . import valueflow

ARG_ALIASES = {
    "rcx": 0, "ecx": 0, "cx": 0, "cl": 0,
    "rdx": 1, "edx": 1, "dx": 1, "dl": 1,
    "r8": 2, "r8d": 2, "r8w": 2, "r8b": 2,
    "r9": 3, "r9d": 3, "r9w": 3, "r9b": 3,
}
MAX_FUNCTION_INSNS = 60000


@dataclass
class ResolvedCall:
    site: int
    target: Optional[int]
    via: str
    name: Optional[str] = None


def _reg(insn: capstone.CsInsn, operand) -> Optional[str]:
    if operand.type == capstone.x86.X86_OP_REG:
        return insn.reg_name(operand.reg)
    return None


def _slot(insn: capstone.CsInsn, operand) -> Optional[Tuple[str, int]]:
    """Stack slot key ("rbp"/"rsp", displacement) or None."""
    if operand.type != capstone.x86.X86_OP_MEM:
        return None
    mem = operand.mem
    if mem.index != 0:
        return None
    name = insn.reg_name(mem.base) if mem.base else ""
    if name in ("rbp", "ebp", "rsp", "esp"):
        return ("rbp" if name.endswith("bp") else "rsp", mem.disp)
    return None


def _static_target(insn: capstone.CsInsn, operand, node_set, view, iat=None):
    """Return ("func", addr) or ("import", name) for a constant operand."""
    """Resolve lea/mov source to a function address when it is a constant."""
    if insn.mnemonic == "lea":
        if operand.type != capstone.x86.X86_OP_MEM:
            return None
        mem = operand.mem
        if mem.index != 0:
            return None
        if mem.base == 0:
            return ("func", mem.disp) if mem.disp in node_set else None
        if mem.base == capstone.x86.X86_REG_RIP:
            target = insn.address + insn.size + mem.disp
            return ("func", target) if target in node_set else None
        return None
    if insn.mnemonic == "mov":
        if operand.type == capstone.x86.X86_OP_IMM:
            return ("func", operand.imm) if operand.imm in node_set else None
        if operand.type == capstone.x86.X86_OP_MEM:
            mem = operand.mem
            slot = None
            if mem.index == 0 and mem.base == capstone.x86.X86_REG_RIP:
                slot = insn.address + insn.size + mem.disp
            elif mem.index == 0 and mem.base == 0:
                slot = mem.disp
            if slot is None:
                return None
            if iat and slot in iat:
                return ("import", iat[slot])
            if view is None:
                return None
            try:
                pointer = view.read_qword(slot)
            except Exception:
                return None
            if pointer in node_set:
                return ("func", pointer)
            if iat and pointer in iat:
                return ("import", iat[pointer])
    return None


def resolve_function(seq: Sequence[capstone.CsInsn], node_set, view, iat=None) -> List[ResolvedCall]:
    regs: Dict[str, Tuple[str, object]] = {}
    slots: Dict[Tuple[str, int], Tuple[str, object]] = {}
    out: List[ResolvedCall] = []
    for insn in seq:
        mn = insn.mnemonic
        ops = insn.operands
        if mn in ("mov", "lea") and len(ops) == 2:
            dst, src = ops[0], ops[1]
            dst_reg = _reg(insn, dst)
            dst_slot = _slot(insn, dst)
            value = _static_target(insn, src, node_set, view, iat)
            if value is None:
                src_reg = _reg(insn, src)
                src_slot = _slot(insn, src)
                if src_reg is not None and src_reg in regs:
                    value = regs[src_reg]
                elif src_slot is not None and src_slot in slots:
                    value = slots[src_slot]
            if dst_reg is not None:
                if value is None:
                    regs.pop(dst_reg, None)
                else:
                    regs[dst_reg] = value
            elif dst_slot is not None:
                if value is None:
                    slots.pop(dst_slot, None)
                else:
                    slots[dst_slot] = value
            continue
        if mn in ("push", "pop", "xor", "add", "sub", "and", "or", "imul", "shl", "shr", "movzx", "movsx", "call") and ops:
            dst_reg = _reg(insn, ops[0])
            if dst_reg is not None and mn != "call":
                regs.pop(dst_reg, None)
        if mn != "call" or not ops:
            continue
        op = ops[0]
        if op.type == capstone.x86.X86_OP_IMM:
            continue
        target = None
        via = None
        op_reg = _reg(insn, op)
        if op_reg is not None:
            target = regs.get(op_reg)
            via = "reg:" + op_reg
        else:
            slot = _slot(insn, op)
            if slot is not None:
                target = slots.get(slot)
                via = "slot:%s%+d" % slot
        if target is None:
            continue
        kind, value = target
        if kind == "func" and value in node_set:
            out.append(ResolvedCall(insn.address, value, via))  # type: ignore[arg-type]
        elif kind == "import":
            out.append(ResolvedCall(insn.address, None, via, name=str(value)))
    return out


def resolve(sequences: Dict[int, Sequence[capstone.CsInsn]], node_set, view, base: int,
            limit: int, iat=None) -> List[ResolvedCall]:
    found: List[ResolvedCall] = []
    for _start, seq in sequences.items():
        if not seq or len(seq) > MAX_FUNCTION_INSNS:
            continue
        found.extend(resolve_function(seq, node_set, view, iat))
    return found
