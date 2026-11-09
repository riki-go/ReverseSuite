"""Function discovery: recursive descent with thunk collapsing (AC-15).

Pipeline:
1. seeds = exports + entry point + direct call targets
2. decode each seed until a terminator (ret / unconditional jmp / int3 / ud2)
3. collapse thunks (body <= 16 bytes starting with jmp) into their targets
4. drop seeds that fall inside an already accepted function
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set

import capstone

from . import disasm, rules, schema

CONF_EXPORT = 1000
CONF_ENTRY = 950
CONF_CALL = 900

TERMINATORS = {"ret", "retf", "jmp", "int3", "ud2", "hlt"}
ARM_TERMINATORS = {"ret", "retaa", "retab", "br", "b", "udf", "brk"}
ARCH_TERMINATORS = {"x86": TERMINATORS, "x64": TERMINATORS, "arm": ARM_TERMINATORS,
                    "arm64": ARM_TERMINATORS}
BRANCH_MNEMONICS = {"x86": ("call",), "x64": ("call",), "arm": ("bl", "blx"), "arm64": ("bl",)}
TAIL_MNEMONICS = {"x86": ("jmp",), "x64": ("jmp",), "arm": ("b",), "arm64": ("b",)}
MAX_INSNS_PER_FUNCTION = 20000
THUNK_MAX_BYTES = 16
MAX_FUNCTION_TEXT_BYTES = 32 * 1024 * 1024
FUNCTION_SKIP_TEXT_TOO_LARGE = "text_too_large_for_functions"


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


def skip_reason(text_bytes: int, max_bytes: Optional[int] = MAX_FUNCTION_TEXT_BYTES) -> Optional[str]:
    """Diagnostic code when discovery is skipped, else None."""
    if max_bytes is not None and text_bytes > max_bytes:
        return FUNCTION_SKIP_TEXT_TOO_LARGE
    return None


def _build_index(engine: capstone.Cs, blob: bytes, base: int):
    """address -> (size, mnemonic, op_str) for every decoded instruction."""
    index = {}
    for insn in disasm.iter_instructions(blob, base, engine):
        index[insn.address] = (insn.size, insn.mnemonic, insn.op_str)
    return index


def _scan_from(engine: capstone.Cs, blob: bytes, base: int, start: int, terminators=frozenset(TERMINATORS)):
    """Decode from an address that the linear index may have missed."""
    off = start - base
    if off < 0 or off >= len(blob):
        return [], False
    seq = []
    addr = start
    for insn in engine.disasm(blob[off:], addr):
        seq.append((insn.address, insn.size, insn.mnemonic, insn.op_str))
        if insn.mnemonic in terminators:
            return seq, True
        if len(seq) >= MAX_INSNS_PER_FUNCTION:
            return seq, False
    return seq, bool(seq and seq[-1][2] in terminators)

def _decode_body(index: dict, base: int, start: int, limit: int, terminators=frozenset(TERMINATORS)):
    """Walk the index from start until a terminator. Returns (end, terminated, count)."""
    addr = start
    count = 0
    while addr in index and count < MAX_INSNS_PER_FUNCTION:
        size, mnemonic, _op = index[addr]
        addr += size
        count += 1
        if mnemonic in terminators:
            return (addr, True, count)
    return (addr, False, count)

RULE_FUNCTION = "pe.function.discover"


def to_findings(funcs: Iterable["Function"], rule: str = RULE_FUNCTION):
    """AC-14: convert discovered functions into schema findings."""
    out = []
    for fn in funcs:
        out.append(schema.Finding(
            kind="function",
            value=f"0x{fn.start:x}",
            confidence_permille=fn.confidence_permille,
            level=fn.level,
            rule=rule,
            evidence=[schema.Evidence(offset=fn.start, space="va", xref=None, rule=rule)],
        ))
    return out


def _prologue_at(index: dict, addr: int, size: int, mnemonic: str, op_str: str, arch: str) -> bool:
    """Architecture-specific function prologue heuristic."""
    compact = op_str.replace(" ", "")
    if arch in ("x86", "x64"):
        if mnemonic != "push" or compact != "rbp":
            return False
        nxt = index.get(addr + size)
        if nxt is None:
            return False
        _ns, nmn, nop = nxt
        flat = nop.replace(" ", "")
        return bool((nmn == "mov" and flat in ("rbp,rsp", "ebp,esp"))
                    or nmn == "push"
                    or (nmn == "sub" and flat.startswith("rsp,")))
    if arch == "arm64":
        # stp x29, x30, [sp, #-N]!  /  stp w29, w30, [sp, #-N]!
        return mnemonic == "stp" and compact.startswith(("x29,x30,[sp", "w29,w30,[sp"))
    if arch == "arm":
        return mnemonic == "push" and compact.startswith(("{r4", "{r7", "{fp", "{lr"))
    return False


def discover(blob: bytes, base: int = disasm.BASE_ADDRESS,
             exports: Optional[List[int]] = None,
             entry: Optional[int] = None,
             md: Optional[capstone.Cs] = None,
             max_bytes: Optional[int] = MAX_FUNCTION_TEXT_BYTES,
             arch: str = "x64") -> List[Function]:
    if skip_reason(len(blob), max_bytes):
        return []
    arch = disasm.ARCH_ALIASES.get(arch, arch)
    terminators = ARCH_TERMINATORS.get(arch, TERMINATORS)
    branches = BRANCH_MNEMONICS.get(arch, ("call",))
    tails = TAIL_MNEMONICS.get(arch, ("jmp",))
    engine = md or disasm.make_engine(arch)
    index = _build_index(engine, blob, base)
    limit = base + len(blob)

    seeds: Dict[int, Set[str]] = {}
    for addr in exports or []:
        seeds.setdefault(addr, set()).add("export")
    if entry is not None and base <= entry < limit:
        seeds.setdefault(entry, set()).add("entry")

    for addr, (size, mnemonic, op_str) in index.items():
        if mnemonic in branches and op_str.startswith("0x"):
            try:
                target = int(op_str, 16)
            except ValueError:
                continue
            if base <= target < limit:
                seeds.setdefault(target, set()).add("call_target")
        elif _prologue_at(index, addr, size, mnemonic, op_str, arch):
            seeds.setdefault(addr, set()).add("prologue")

    bodies: Dict[int, tuple] = {}
    for start in sorted(seeds):
        if start in index:
            end, terminated, count = _decode_body(index, base, start, limit, terminators)
        else:
            seq, terminated = _scan_from(engine, blob, base, start, terminators)
            count = len(seq)
            for item in seq:
                index.setdefault(item[0], (item[1], item[2], item[3]))
            end = seq[-1][0] + seq[-1][1] if seq else start
        if not terminated:
            continue
        first = index.get(start)
        if first is not None and first[1] in tails and (end - start) <= THUNK_MAX_BYTES and first[2].startswith("0x"):
            try:
                target = int(first[2], 16)
            except ValueError:
                target = -1
            if base <= target < limit:
                seeds.setdefault(start, set()).add("thunk")
                seeds.setdefault(target, set()).add("thunk_target")
        bodies[start] = (end, terminated, count)

    STRONG = {"export", "entry", "prologue", "thunk"}
    accepted: Dict[int, tuple] = {}
    previous = None
    for start in sorted(bodies):
        end, terminated, count = bodies[start]
        if previous is not None and start < accepted[previous][0]:
            if seeds.get(start, set()) & STRONG:
                prev_end, prev_term, prev_count = accepted[previous]
                accepted[previous] = (start, prev_term, prev_count)
            else:
                continue
        accepted[start] = (end, terminated, count)
        previous = start

    # Gap pass: unclaimed short jmp blocks that target an accepted function.
    spans = sorted((start, end) for start, (end, _t, _c) in accepted.items())
    covered = lambda a: any(s <= a < e for s, e in spans)
    for addr, (size, mnemonic, op_str) in sorted(index.items()):
        if mnemonic != "jmp" or not op_str.startswith("0x") or size > THUNK_MAX_BYTES:
            continue
        if addr in accepted or covered(addr):
            continue
        try:
            target = int(op_str, 16)
        except ValueError:
            continue
        if target in accepted:
            accepted[addr] = (addr + size, True, 1)
            seeds.setdefault(addr, set()).add("thunk")
            spans = sorted((a, b) for a, (b, _t, _c) in accepted.items())

    functions: List[Function] = []
    for start in sorted(accepted):
        end, terminated, count = accepted[start]
        srcs = sorted(seeds.get(start, set()))
        if "export" in srcs:
            conf, level = CONF_EXPORT, "L0"
        elif "entry" in srcs:
            conf, level = CONF_ENTRY, "L0"
        else:
            conf, level = CONF_CALL, "L4"
        functions.append(Function(start=start, size=max(0, end - start),
                                   sources=tuple(srcs), confidence_permille=conf, level=level))
    return functions

def entry_point(data: bytes) -> Optional[int]:
    """Entry point mapped into the disassembly address space (or None if outside .text)."""
    import struct
    from . import loader
    e = struct.unpack_from("<I", data, 0x3C)[0]
    magic = struct.unpack_from("<H", data, e + 24)[0]
    ep_rva = struct.unpack_from("<I", data, e + 24 + 16)[0]
    n = struct.unpack_from("<H", data, e + 6)[0]
    o = struct.unpack_from("<H", data, e + 20)[0]
    table = e + 4 + 20 + o
    for i in range(n):
        off = table + i * 40
        if data[off:off + 8].rstrip(b"\x00") == b".text":
            vsize, vaddr = struct.unpack_from("<II", data, off + 8)
            rsize = struct.unpack_from("<I", data, off + 16)[0]
            if vaddr <= ep_rva < vaddr + max(vsize, rsize):
                return disasm.BASE_ADDRESS + (ep_rva - vaddr)
    return None
