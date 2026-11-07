"""Intra-procedural value-set analysis (M6.1).

Goal: resolve `call reg` when the register was loaded from a stack slot or a global
slot inside the same function. Scope is deliberately small:

- one function at a time, CFG-lite (leaders = function start, jump targets, the
  instruction after a conditional jump)
- abstract values are (address, via) pairs capped at MAX_SET entries; exceeding the
  cap degrades to Unknown instead of guessing
- only `mov imm`, `lea rip-relative`, `mov reg,[rip+slot]` when the slot holds a
  pointer into .text, `mov reg,[rbp/rsp +/- disp]`, stores to those slots and
  `xor reg,reg` are tracked; every other write clears the register
- a call site resolves only when the value-set has exactly one target that is a
  known function start; everything else stays unresolved
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

import capstone

from . import disasm, loader

MAX_SET = 4
MAX_PASSES = 8
MAX_BLOCKS = 4000
VOLATILE = {capstone.x86.X86_REG_RAX, capstone.x86.X86_REG_RCX, capstone.x86.X86_REG_RDX,
            capstone.x86.X86_REG_R8, capstone.x86.X86_REG_R9, capstone.x86.X86_REG_R10,
            capstone.x86.X86_REG_R11}
REGS = {capstone.x86.X86_REG_RAX: "rax", capstone.x86.X86_REG_RBX: "rbx",
        capstone.x86.X86_REG_RCX: "rcx", capstone.x86.X86_REG_RDX: "rdx",
        capstone.x86.X86_REG_RSI: "rsi", capstone.x86.X86_REG_RDI: "rdi",
        capstone.x86.X86_REG_RBP: "rbp", capstone.x86.X86_REG_RSP: "rsp",
        capstone.x86.X86_REG_R8: "r8", capstone.x86.X86_REG_R9: "r9",
        capstone.x86.X86_REG_R10: "r10", capstone.x86.X86_REG_R11: "r11",
        capstone.x86.X86_REG_R12: "r12", capstone.x86.X86_REG_R13: "r13",
        capstone.x86.X86_REG_R14: "r14", capstone.x86.X86_REG_R15: "r15"}


class ImageView:
    """Maps the normalised VA space back to file bytes for any section."""

    def __init__(self, data: bytes, base: int = disasm.BASE_ADDRESS) -> None:
        self.data = data
        self.base = base
        sections = loader.sections(data)
        text_rva = next((s.virtual_address for s in sections if s.name == ".text"), 0)
        self.text_rva = text_rva
        self.image_base = _image_base(data)
        self.size = len(data)
        self.spans = []
        for section in sections:
            if not section.raw_size:
                continue
            start = base + (section.virtual_address - text_rva)
            self.spans.append((start, start + section.raw_size, section.raw_ptr))

    def to_norm(self, value: int) -> Optional[int]:
        """Map a VA from the file (image_base + rva) into the normalised space."""
        if self.image_base and self.image_base <= value < self.image_base + 0x40000000:
            norm = self.base + (value - self.image_base - self.text_rva)
            return norm if self.offset(norm) is not None else None
        return None

    def offset(self, address: int) -> Optional[int]:
        for start, end, raw_ptr in self.spans:
            if start <= address < end:
                return raw_ptr + (address - start)
        return None

    def read_qword(self, address: int) -> Optional[int]:
        off = self.offset(address)
        if off is None or off + 8 > len(self.data):
            return None
        return int.from_bytes(self.data[off:off + 8], "little")


def _image_base(data: bytes) -> int:
    import struct
    e = struct.unpack_from("<I", data, 0x3C)[0]
    magic = struct.unpack_from("<H", data, e + 24)[0]
    field = e + 24 + (28 if magic == 0x10B else 24)
    return struct.unpack_from("<I", data, field)[0] if magic == 0x10B else struct.unpack_from("<Q", data, field)[0]


@dataclass(frozen=True)
class Val:
    value: int
    via: int


State = Dict[str, Tuple[Val, ...]]


@dataclass
class ResolvedCall:
    site: int
    target: int
    via: int


def _reg_name(operand) -> Optional[str]:
    if operand.type != capstone.x86.X86_OP_REG:
        return None
    return REGS.get(operand.reg)


def _reg_name_from_mem(insn, operand) -> Optional[str]:
    if operand.type != capstone.x86.X86_OP_MEM:
        return None
    return REGS.get(operand.mem.base)


def _slot_key(insn, operand) -> Optional[str]:
    """Stack slot key for [rbp/rsp +/- disp]; None for anything else."""
    if operand.type != capstone.x86.X86_OP_MEM:
        return None
    base = operand.mem.base
    if base not in (capstone.x86.X86_REG_RBP, capstone.x86.X86_REG_RSP):
        return None
    if operand.mem.index != 0:
        return None
    return "slot:%s:%d" % ("rbp" if base == capstone.x86.X86_REG_RBP else "rsp", operand.mem.disp)


def _merge(a: Optional[State], b: State) -> State:
    if a is None:
        return dict(b)
    out: State = dict(a)
    for key, values in b.items():
        current = out.get(key, ())
        seen = {v.value: v for v in current}
        for value in values:
            seen.setdefault(value.value, value)
        merged = tuple(seen.values())
        out[key] = merged if len(merged) <= MAX_SET else ()
    return out


def _same(a: State, b: State) -> bool:
    if set(a) != set(b):
        return False
    return all(set(a[k]) == set(b[k]) for k in a)


def _rip_target(insn, operand) -> Optional[int]:
    if operand.type != capstone.x86.X86_OP_MEM:
        return None
    if operand.mem.base != capstone.x86.X86_REG_RIP or operand.mem.index != 0:
        return None
    return insn.address + insn.size + operand.mem.disp


def _block_leaders(insns: Sequence[capstone.CsInsn]) -> Set[int]:
    leaders = {insns[0].address} if insns else set()
    addrs = {i.address for i in insns}
    for insn in insns:
        if insn.mnemonic in ("jmp", "jcc", "call", "ret"):
            pass
        target = None
        if insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
            target = insn.operands[0].imm
        if insn.mnemonic.startswith("j") and target in addrs:
            leaders.add(target)
            nxt = insn.address + insn.size
            if nxt in addrs:
                leaders.add(nxt)
    return leaders


def analyze_function(insns: Sequence[capstone.CsInsn], view: "ImageView", base: int,
                     node_starts: Set[int]) -> List[ResolvedCall]:
    if not insns or len(insns) > 20000:
        return []
    leaders = _block_leaders(insns)
    blocks: List[List[capstone.CsInsn]] = []
    current: List[capstone.CsInsn] = []
    for insn in insns:
        if insn.address in leaders and current:
            blocks.append(current)
            current = []
        current.append(insn)
    if current:
        blocks.append(current)
    if len(blocks) > MAX_BLOCKS:
        return []

    # Seed every block: some code is only reachable through branches we do not model
    # (jump tables, indirect jumps), and losing it would lose real call sites.
    entry: Dict[int, State] = {block[0].address: {} for block in blocks}
    results: Set[Tuple[int, int, int]] = set()

    def load_pointer(address: Optional[int]) -> Optional[int]:
        """Read a qword; return it in normalised space when it points into the image."""
        if address is None:
            return None
        value = view.read_qword(address)
        if value is None or value == 0:
            return None
        return view.to_norm(value)

    def transfer(block: List[capstone.CsInsn], state: State) -> Tuple[State, List[ResolvedCall]]:
        out = dict(state)
        found: List[ResolvedCall] = []
        for insn in block:
            ops = insn.operands
            if insn.mnemonic == "call":
                target: Optional[int] = None
                via = insn.address
                if ops:
                    op = ops[0]
                    values: Tuple[Val, ...] = ()
                    if op.type == capstone.x86.X86_OP_REG:
                        name = _reg_name(op)
                        values = out.get("reg:" + name, ()) if name else ()
                    else:
                        slot = _rip_target(insn, op)
                        if slot is not None:
                            direct = load_pointer(slot)
                            if direct is not None:
                                target, via = direct, insn.address
                        else:
                            key = _slot_key(insn, op)
                            if key:
                                values = out.get(key, ())
                    if target is None and len({v.value for v in values}) == 1:
                        candidate = next(iter(values))
                        if candidate.value in node_starts:
                            target, via = candidate.value, candidate.via
                if target is not None:
                    found.append(ResolvedCall(insn.address, target, via))
                for reg in VOLATILE:
                    out.pop("reg:" + REGS[reg], None)
                continue
            if not ops:
                continue
            dst, src = ops[0], (ops[1] if len(ops) > 1 else None)
            dst_reg = _reg_name(dst)
            dst_slot = _slot_key(insn, dst)
            new_value: Optional[Val] = None
            if insn.mnemonic == "lea" and dst_reg and src is not None:
                addr = _rip_target(insn, src)
                if addr is not None:
                    new_value = Val(addr, insn.address)
            elif insn.mnemonic == "mov" and dst_reg and src is not None:
                if src.type == capstone.x86.X86_OP_IMM:
                    new_value = Val(src.imm, insn.address)
                elif src.type == capstone.x86.X86_OP_REG:
                    name = _reg_name(src)
                    if name:
                        values = out.get("reg:" + name, ())
                        if len(values) == 1:
                            new_value = values[0]
                elif src.type == capstone.x86.X86_OP_MEM:
                    key = _slot_key(insn, src)
                    if key:
                        values = out.get(key, ())
                        if len(values) == 1:
                            new_value = values[0]
                    else:
                        slot = _rip_target(insn, src)
                        if slot is not None:
                            pointer = load_pointer(slot)
                            if pointer is not None:
                                new_value = Val(pointer, insn.address)
                        else:
                            base_name = _reg_name_from_mem(insn, src)
                            if base_name:
                                values = out.get("reg:" + base_name, ())
                                if len(values) == 1 and src.mem.index == 0:
                                    base_addr = values[0].value
                                    pointer = load_pointer(base_addr)
                                    if pointer is not None:
                                        new_value = Val(pointer, insn.address)
            elif insn.mnemonic == "xor" and dst_reg and src is not None and _reg_name(src) == dst_reg:
                new_value = Val(0, insn.address)

            if dst_slot and insn.mnemonic == "mov" and src is not None:
                values = ()
                if src.type == capstone.x86.X86_OP_REG:
                    name = _reg_name(src)
                    if name:
                        values = out.get("reg:" + name, ())
                out[dst_slot] = values
                continue

            if dst_reg:
                if new_value is not None:
                    out["reg:" + dst_reg] = (new_value,)
                else:
                    out.pop("reg:" + dst_reg, None)
        return out, found
    for _ in range(MAX_PASSES):
        changed = False
        for index, block in enumerate(blocks):
            start = block[0].address
            state = entry.get(start, {})
            out_state, found = transfer(block, state)
            for call in found:
                results.add((call.site, call.target, call.via))
            last = block[-1]
            nxt = last.address + last.size
            targets: List[int] = []
            if last.mnemonic.startswith("j") and last.operands and last.operands[0].type == capstone.x86.X86_OP_IMM:
                targets.append(last.operands[0].imm)
                if last.mnemonic != "jmp":
                    targets.append(nxt)
            else:
                targets.append(nxt)
            for target in targets:
                if not any(b[0].address == target for b in blocks):
                    continue
                merged = _merge(entry.get(target), out_state)
                if target not in entry or not _same(entry[target], merged):
                    entry[target] = merged
                    changed = True
        if not changed:
            break

    return [ResolvedCall(site, target, via) for site, target, via in sorted(results)]