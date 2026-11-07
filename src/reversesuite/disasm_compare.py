"""Compare capstone disassembly against objdump for AC-2.

Both sides are reduced to (address, mnemonic, normalised operands) and compared at
instruction-address level. Normalisation is deliberate and narrow: lowercase, drop
x86 size qualifiers, strip whitespace, canonicalise hex (`0x28`, no leading zeros)
and drop segment prefixes that objdump prints but capstone does not.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from . import disasm

SIZE_PREFIX = re.compile(r"\b(byte|word|dword|qword|tbyte|xmmword|ymmword|oword|zmmword) ptr\b")
HEX = re.compile(r"0x([0-9a-fA-F]+)")
SEGMENT = re.compile(r"\b(ds|es|ss|cs|fs|gs):")
SYMBOL_SUFFIX = re.compile(r"\s*<[^>]*>\s*$")
IMAGE_CONST = re.compile(r"0x([0-9a-fA-F]+)")


DECIMAL = re.compile(r"(?<![\w.])(\d+)(?![\w.])")
COMMENT = re.compile(r"#.*$")


def normalize_operands(text: str) -> str:
    """Canonical operand text so objdump and capstone become comparable."""
    out = text.lower().strip()
    out = COMMENT.sub("", out)
    out = SIZE_PREFIX.sub("", out)
    out = SEGMENT.sub("", out)
    def fix_hex(match):
        digits = match.group(1)
        value = int(digits, 16)
        # objdump keeps sign-extended values at the operand width; capstone prints
        # them signed. Convert by literal width so both sides agree.
        if len(digits) == 16 and value >= 0x8000000000000000:
            value -= 1 << 64
        elif len(digits) == 8 and value >= 0x80000000:
            value -= 1 << 32
        return ("-0x%x" % -value) if value < 0 else ("0x%x" % value)

    out = HEX.sub(fix_hex, out)
    out = DECIMAL.sub(lambda m: "0x%x" % int(m.group(1)), out)
    out = out.replace(", ", ",").replace(" ", "")
    out = out.replace("+-", "-").replace("*0x1", "").replace("+0x0]", "]")
    return out


REX_PREFIX = re.compile(r"^rex[.a-z]*\s+")
REX_ONLY = re.compile(r"^rex[.a-z]*$")


def normalize_mnemonic(mnemonic: str) -> str:
    """objdump prints redundant REX prefixes ("rex push rbx"); capstone does not."""
    out = REX_PREFIX.sub("", mnemonic.lower().strip())
    if re.fullmatch(r"rex[.a-z]*", out):
        return ""
    return out


@dataclass
class Instruction:
    address: int
    mnemonic: str
    operands: str

    def key(self) -> Tuple[int, str, str]:
        return (self.address, normalize_mnemonic(self.mnemonic), normalize_operands(self.operands))


@dataclass
class CompareResult:
    total_reference: int = 0
    total_candidate: int = 0
    matched: int = 0
    missing: List[int] = field(default_factory=list)
    extra: List[int] = field(default_factory=list)
    mismatched: List[Tuple[int, str, str]] = field(default_factory=list)

    @property
    def accuracy(self) -> float:
        return self.matched / self.total_reference if self.total_reference else 0.0

    @property
    def precision(self) -> float:
        return self.matched / self.total_candidate if self.total_candidate else 0.0

    def summary(self) -> dict:
        return {
            "reference": self.total_reference,
            "candidate": self.total_candidate,
            "matched": self.matched,
            "accuracy": round(self.accuracy, 6),
            "precision": round(self.precision, 6),
            "missing": len(self.missing),
            "extra": len(self.extra),
            "mismatched": len(self.mismatched),
            "missing_sample": [hex(a) for a in self.missing[:5]],
            "extra_sample": [hex(a) for a in self.extra[:5]],
            "mismatch_sample": [{"addr": hex(a), "objdump": r, "capstone": c}
                                for a, r, c in self.mismatched[:5]],
        }


OBJDUMP_LINE = re.compile(r"^\s*([0-9a-f]+):\s+([a-z][a-z0-9.]*)\s*(.*)$")


def parse_objdump(output: str, image_base: int, text_rva: int, low: int, high: int,
                  candidate_base: int = disasm.BASE_ADDRESS) -> Dict[int, Instruction]:
    """Parse `objdump -d -M intel --no-show-raw-insn` into the candidate address space.

    objdump prints virtual addresses (image_base + rva); the disassembler works in a
    normalised space where .text starts at candidate_base, so each address is shifted
    by (candidate_base - image_base - text_rva).
    """
    delta = candidate_base - image_base - text_rva
    image_end = image_base + 0x40000000

    def rebase(operands: str) -> str:
        """objdump prints branch targets as image VAs; map them to candidate space."""
        bare = operands.strip()
        if re.fullmatch(r"[0-9a-f]{7,16}", bare):
            value = int(bare, 16)
            if image_base <= value < image_end:
                return "0x%x" % (value + delta)
            return bare

        def fix(match):
            value = int(match.group(1), 16)
            if image_base <= value < image_end:
                return "0x%x" % (value + delta)
            return match.group(0)
        return IMAGE_CONST.sub(fix, operands)

    out: Dict[int, Instruction] = {}
    for line in output.splitlines():
        match = OBJDUMP_LINE.match(line)
        if not match:
            continue
        address = int(match.group(1), 16) + delta
        if not (low <= address < high):
            continue
        operands = SYMBOL_SUFFIX.sub("", (match.group(3) or "").strip())
        mnemonic = match.group(2)
        if REX_ONLY.match(mnemonic):
            parts = operands.split(None, 1)
            if parts:
                mnemonic, operands = parts[0], (parts[1] if len(parts) > 1 else "")
        out[address] = Instruction(address, mnemonic, rebase(operands))
    return out


def parse_capstone(blob: bytes, base: int) -> Dict[int, Instruction]:
    out: Dict[int, Instruction] = {}
    for insn in disasm.iter_instructions(blob, base):
        out[insn.address] = Instruction(insn.address, insn.mnemonic, insn.op_str)
    return out


def decode_at(blob: bytes, base: int, address: int, md=None) -> Optional[Instruction]:
    """Decode exactly one instruction at `address` (no sweep alignment issues)."""
    import capstone
    engine = md or capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    offset = address - base
    if offset < 0 or offset >= len(blob):
        return None
    insn = next(iter(engine.disasm(blob[offset:offset + 16], address, 1)), None)
    if insn is None:
        return None
    return Instruction(insn.address, insn.mnemonic, insn.op_str)


def compare_at_addresses(reference: Dict[int, Instruction], blob: bytes,
                         base: int = disasm.BASE_ADDRESS) -> CompareResult:
    """Compare by decoding capstone at each reference address (AC-2 metric)."""
    import capstone
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    result = CompareResult(total_reference=len(reference))
    for address, ref in reference.items():
        cand = decode_at(blob, base, address, engine)
        if cand is None:
            result.missing.append(address)
            continue
        result.total_candidate += 1
        if ref.key() == cand.key():
            result.matched += 1
        else:
            result.mismatched.append((address,
                                      ref.mnemonic + " " + ref.operands,
                                      cand.mnemonic + " " + cand.operands))
    result.missing.sort()
    result.mismatched.sort(key=lambda item: item[0])
    return result


def compare(reference: Dict[int, Instruction], candidate: Dict[int, Instruction]) -> CompareResult:
    result = CompareResult(total_reference=len(reference), total_candidate=len(candidate))
    for address, ref in reference.items():
        cand = candidate.get(address)
        if cand is None:
            result.missing.append(address)
            continue
        if ref.key() == cand.key():
            result.matched += 1
        else:
            result.mismatched.append((address,
                                      ref.mnemonic + " " + ref.operands,
                                      cand.mnemonic + " " + cand.operands))
    for address in candidate:
        if address not in reference:
            result.extra.append(address)
    result.missing.sort()
    result.extra.sort()
    result.mismatched.sort(key=lambda item: item[0])
    return result