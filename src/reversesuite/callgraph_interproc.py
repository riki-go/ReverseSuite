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


def find_vtables(view, node_set, limit: int = 4000):
    """Address -> tuple of code pointers for read-only arrays that look like vtables."""
    tables = {}
    if view is None:
        return tables
    spans = getattr(view, "spans", [])
    count = 0
    for start, end, raw_ptr in spans:
        address = start
        while address + 16 <= end and count < limit:
            try:
                first = view.read_qword(address)
                second = view.read_qword(address + 8)
            except Exception:
                address += 8
                continue
            first_norm = _norm(view, first)
            if first_norm in node_set:
                slots = []
                cursor = address
                while cursor + 8 <= end and len(slots) < 64:
                    try:
                        value = _norm(view, view.read_qword(cursor))
                    except Exception:
                        break
                    if value not in node_set:
                        break
                    slots.append(value)
                    cursor += 8
                if len(slots) >= 2:
                    tables[address] = tuple(slots)
                    count += 1
                    address = cursor
                    continue
            address += 8
    return tables


def _norm(view, value):
    """Map an image VA read from .rdata into the normalised address space."""
    if view is None or value is None:
        return None
    try:
        return view.to_norm(value)
    except Exception:
        return None


def _read_byte(view, address: int) -> int:
    """Single byte from the image, via the section mapping."""
    offset = view.offset(address)
    if offset is None:
        raise ValueError("address not mapped")
    return view.data[offset]


def _read_cstr(view, address: int, limit: int = 96) -> str:
    """Best-effort C string at a normalised address."""
    out = bytearray()
    for i in range(limit):
        try:
            byte = _read_byte(view, address + i)
        except Exception:
            break
        if byte == 0:
            break
        out.append(byte)
    return out.decode("utf-8", "replace")


def _demangle(name: str) -> str:
    """Very small Itanium-mangled name reader: '7Derived' -> 'Derived'."""
    out = []
    i = 0
    while i < len(name):
        if name[i].isdigit():
            j = i
            while j < len(name) and name[j].isdigit():
                j += 1
            length = int(name[i:j])
            out.append(name[j:j + length])
            i = j + length
        else:
            i += 1
    return "".join(out)


def vtable_names(view, vtables: Dict[int, Tuple[int, ...]]) -> Dict[int, str]:
    """Map vtable address -> class name via the RTTI typeinfo pointer at [-1]."""
    names: Dict[int, str] = {}
    for address in vtables:
        try:
            typeinfo = _norm(view, view.read_qword(address - 8))
            if not typeinfo:
                continue
            name_ptr = _norm(view, view.read_qword(typeinfo + 8))
            if not name_ptr:
                continue
            raw = _read_cstr(view, name_ptr)
            cleaned = _demangle(raw)
            if cleaned:
                names[address] = cleaned
        except Exception:
            continue
    return names


def _vtable_of(target: int, vtables):
    for base, slots in vtables.items():
        if target == base or (base <= target < base + 8 * len(slots) and (target - base) % 8 == 0):
            return base
    return None


def _static_target(insn: capstone.CsInsn, operand, node_set, view, iat=None, vtables=None):
    """Return ("func", addr) or ("import", name) for a constant operand."""
    """Resolve lea/mov source to a function address when it is a constant."""
    if insn.mnemonic == "lea":
        if operand.type != capstone.x86.X86_OP_MEM:
            return None
        mem = operand.mem
        if mem.index != 0:
            return None
        if mem.base == 0:
            if mem.disp in node_set:
                return ("func", mem.disp)
            if vtables and mem.disp in vtables:
                return ("vtable", mem.disp)
            return None
        if mem.base == capstone.x86.X86_REG_RIP:
            target = insn.address + insn.size + mem.disp
            if target in node_set:
                return ("func", target)
            if vtables and target in vtables:
                return ("vtable", target)
            return None
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
                raw = view.read_qword(slot)
            except Exception:
                return None
            pointer = _norm(view, raw)
            if pointer is not None and pointer in node_set:
                return ("func", pointer)
            if iat and raw in iat:
                return ("import", iat[raw])
    return None


def resolve_function(seq: Sequence[capstone.CsInsn], node_set, view, iat=None,
                     vtables=None) -> List[ResolvedCall]:
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
            value = _static_target(insn, src, node_set, view, iat, vtables)
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
            if op.type == capstone.x86.X86_OP_MEM and vtables:
                mem = op.mem
                base_reg = insn.reg_name(mem.base) if mem.base else None
                holder = regs.get(base_reg) if base_reg else None
                if holder and holder[0] == "vtable" and mem.index == 0 and mem.disp >= 0:
                    slots_of = vtables.get(holder[1])
                    index = mem.disp // 8
                    if slots_of and index < len(slots_of):
                        target = ("func", slots_of[index])
                        via = "vtable:0x%x+%d" % (holder[1], mem.disp)
            if target is None:
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
            limit: int, iat=None, vtables=None) -> List[ResolvedCall]:
    found: List[ResolvedCall] = []
    for _start, seq in sequences.items():
        if not seq or len(seq) > MAX_FUNCTION_INSNS:
            continue
        found.extend(resolve_function(seq, node_set, view, iat, vtables))
    return found
