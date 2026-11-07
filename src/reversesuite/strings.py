"""String extraction (M1b): ASCII and UTF-16LE runs with addresses and xrefs.

Address space follows the disassembler: the image is normalised so that .text
maps to BASE_ADDRESS (0x1000), i.e. addr = 0x1000 + (rva - text_rva).

Scope (M1b): printable ASCII / UTF-16LE runs of at least MIN_LENGTH characters,
restricted to sections without IMAGE_SCN_MEM_EXECUTE. Xrefs are direct
rip-relative and immediate references found by static decoding of .text.
"""
from __future__ import annotations

import bisect
import re
import struct
from dataclasses import dataclass, field
from concurrent.futures import ProcessPoolExecutor
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import capstone

from . import disasm, loader

MIN_LENGTH = 4
ASCII_PRINTABLE = frozenset(list(range(0x20, 0x7F)) + [0x09])
IMAGE_SCN_MEM_EXECUTE = 0x20000000
MAX_STRINGS = 200000
XREF_TAIL = 15
XREF_WORKERS_DEFAULT = 6


@dataclass(frozen=True)
class ExtractedString:
    address: int
    value: str
    encoding: str
    section: str
    length: int
    xrefs: Tuple[int, ...] = ()


def _image_base(data: bytes) -> int:
    e = struct.unpack_from("<I", data, 0x3C)[0]
    magic = struct.unpack_from("<H", data, e + 24)[0]
    field = e + 24 + (28 if magic == 0x10B else 24)
    return struct.unpack_from("<I", data, field)[0] if magic == 0x10B else struct.unpack_from("<Q", data, field)[0]


def data_sections(data: bytes) -> List[loader.Section]:
    """Sections that hold data (executable bit clear) with raw bytes present."""
    out = [s for s in loader.sections(data)
           if s.raw_size and not (s.characteristics & IMAGE_SCN_MEM_EXECUTE)]
    return out


def _text_rva(data: bytes) -> int:
    for s in loader.sections(data):
        if s.name == ".text":
            return s.virtual_address
    raise ValueError("no .text section")


ASCII_RE = re.compile(rb"[\x20-\x7e\x09]{%d,}" % MIN_LENGTH)
UTF16_RE = re.compile(rb"(?:[\x20-\x7e\x09]\x00){%d,}" % MIN_LENGTH)


def _run_length(blob: bytes, start: int) -> int:
    i = start
    while i < len(blob) and blob[i] in ASCII_PRINTABLE:
        i += 1
    return i - start


def scan_ascii(blob: bytes, base: int, min_length: int = MIN_LENGTH) -> List[Tuple[int, str]]:
    """Maximal printable runs of at least min_length characters, trailing blanks trimmed."""
    out: List[Tuple[int, str]] = []
    if min_length < 1:
        raise ValueError("min_length must be >= 1")
    pattern = ASCII_RE if min_length == MIN_LENGTH else re.compile(rb"[\x20-\x7e\x09]{%d,}" % min_length)
    for m in pattern.finditer(blob):
        start = m.start()
        if start and blob[start - 1] in ASCII_PRINTABLE:
            continue
        value = m.group().decode("latin-1").rstrip(" \t")
        if len(value) >= min_length:
            out.append((base + start, value))
    return out


def scan_utf16le(blob: bytes, base: int, min_length: int = MIN_LENGTH) -> List[Tuple[int, str]]:
    """ASCII-only UTF-16LE runs, even offset relative to the section, maximal."""
    out: List[Tuple[int, str]] = []
    if min_length < 1:
        raise ValueError("min_length must be >= 1")
    pattern = UTF16_RE if min_length == MIN_LENGTH else re.compile(rb"(?:[\x20-\x7e\x09]\x00){%d,}" % min_length)
    for m in pattern.finditer(blob):
        start = m.start()
        if start % 2:
            continue
        if start >= 2 and blob[start - 2] in ASCII_PRINTABLE and blob[start - 1] == 0:
            continue
        value = m.group().decode("utf-16le").rstrip(" \t")
        if len(value) >= min_length:
            out.append((base + start, value))
    return out

def extract(data: bytes, min_length: int = MIN_LENGTH) -> List[ExtractedString]:
    if min_length < 1:
        raise ValueError("min_length must be >= 1")
    text_rva = _text_rva(data)
    result: List[ExtractedString] = []
    for sec in data_sections(data):
        blob = data[sec.raw_ptr:sec.raw_ptr + sec.raw_size]
        if not blob:
            continue
        sec_base = disasm.BASE_ADDRESS + (sec.virtual_address - text_rva)
        used: List[Tuple[int, int]] = []
        for addr, value in scan_ascii(blob, sec_base, min_length):
            result.append(ExtractedString(addr, value, "ascii", sec.name, len(value)))
            used.append((addr, addr + len(value)))
        for addr, value in scan_utf16le(blob, sec_base, min_length):
            span = (addr, addr + len(value) * 2)
            if any(span[0] < u[1] and u[0] < span[1] for u in used):
                continue
            result.append(ExtractedString(addr, value, "utf16le", sec.name, len(value)))
        if len(result) >= MAX_STRINGS:
            break
    result.sort(key=lambda s: (s.address, s.encoding))
    return result


def _ref_targets(insn: capstone.CsInsn) -> List[int]:
    targets: List[int] = []
    for op in insn.operands:
        if op.type == capstone.x86.X86_OP_MEM:
            if op.mem.base == capstone.x86.X86_REG_RIP:
                targets.append(insn.address + insn.size + op.mem.disp)
            elif op.mem.base == 0 and op.mem.index == 0:
                targets.append(op.mem.disp & 0xFFFFFFFFFFFFFFFF)
        elif op.type == capstone.x86.X86_OP_IMM and getattr(op, "imm", 0):
            targets.append(op.imm)
    return targets


def _scan_window(payload) -> Dict[int, List[int]]:
    """Worker: find string references inside one window of .text."""
    blob, base, spans = payload
    starts = [sp[0] for sp in spans]
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    engine.detail = True
    hits: Dict[int, List[int]] = {}
    for insn in engine.disasm(blob, base):
        for target in _ref_targets(insn):
            idx = bisect.bisect_right(starts, target) - 1
            if idx < 0:
                continue
            lo, hi, key = spans[idx]
            if lo <= target < hi:
                bucket = hits.get(key)
                if bucket is None:
                    hits[key] = [insn.address]
                elif insn.address not in bucket:
                    bucket.append(insn.address)
    return hits


def _xref_windows(text: bytes, base: int, spans, window: int = disasm.WINDOW) -> Iterable[tuple]:
    """Fixed-size windows with a 15-byte tail so boundary instructions still decode."""
    for start in range(0, len(text), window):
        piece = text[start:start + window + XREF_TAIL]
        yield piece, base + start, spans


def find_xrefs(text: bytes, strings: Sequence[ExtractedString],
               base: int = disasm.BASE_ADDRESS, workers: int = 1,
               window: int = disasm.WINDOW) -> Dict[int, Tuple[int, ...]]:
    """Map string address -> sorted code addresses that reference it."""
    if not strings:
        return {}
    spans = sorted((s.address, s.address + s.length * (2 if s.encoding == "utf16le" else 1), s.address)
                   for s in strings)
    starts = [s.address for s in strings]
    hits: Dict[int, List[int]] = {}
    if workers and workers > 1 and len(text) > window:
        with ProcessPoolExecutor(max_workers=workers) as ex:
            for part in ex.map(_scan_window, _xref_windows(text, base, spans, window)):
                for key, sites in part.items():
                    bucket = hits.setdefault(key, [])
                    bucket.extend(sites)
    else:
        for part in _xref_windows(text, base, spans, window):
            for key, sites in _scan_window(part).items():
                bucket = hits.setdefault(key, [])
                bucket.extend(sites)
    del starts
    return {k: tuple(sorted(set(v))) for k, v in hits.items()}

def extract_with_xrefs(data: bytes, min_length: int = MIN_LENGTH, workers: int = 1) -> List[ExtractedString]:
    strings = extract(data, min_length)
    xrefs = find_xrefs(loader.text_bytes(data), strings, workers=workers)
    if not xrefs:
        return strings
    return [ExtractedString(s.address, s.value, s.encoding, s.section, s.length, xrefs.get(s.address, ()))
            for s in strings]