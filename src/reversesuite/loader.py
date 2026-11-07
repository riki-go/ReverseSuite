"""PE loader (static, stdlib only). Produces findings/diagnostics per PLAN.

Caps come from PLAN section 14.4 and are part of config_hash.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .schema import AnalysisResult, Diagnostic, Evidence, Finding

MAX_SECTIONS = 96
MAX_IMPORT_DLLS = 4096
MAX_IMPORT_ENTRIES = 65535
MAX_EXPORTS = 65535
MAX_RAW_SECTION = 512 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024 * 1024

PE32_MAGIC = 0x10B
PE32P_MAGIC = 0x20B
OPT_SIZE_EXPECTED = {PE32_MAGIC: 224, PE32P_MAGIC: 240}


class LoadError(Exception):
    def __init__(self, code: str, message: str, offset: int = 0) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.offset = offset


@dataclass
class Section:
    index: int
    name: str
    virtual_address: int
    virtual_size: int
    raw_ptr: int
    raw_size: int
    characteristics: int


def _u16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def _u32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _need(b: bytes, off: int, size: int, code: str, what: str) -> None:
    if off < 0 or off + size > len(b):
        raise LoadError(code, f"{what} exceeds file size", off)


def parse(data: bytes) -> AnalysisResult:
    findings: List[Finding] = []
    diags: List[Diagnostic] = []
    status = "ok"

    if len(data) > MAX_FILE:
        return _failed(data, "pe.file.cap_exceeded", "file larger than cap")

    try:
        _need(data, 0x3C, 4, "pe.header.truncated", "e_lfanew field")
        e_lfanew = _u32(data, 0x3C)
        if e_lfanew + 4 > len(data):
            raise LoadError("pe.lfanew.out_of_range", "e_lfanew points past end of file", 0x3C)
        if e_lfanew + 24 > len(data):
            raise LoadError("pe.coff.truncated", "COFF/optional header truncated", e_lfanew)

        machine = _u16(data, e_lfanew + 4)
        nsec = _u16(data, e_lfanew + 6)
        opt_size = _u16(data, e_lfanew + 20)

        if nsec > MAX_SECTIONS:
            raise LoadError("pe.sectab.cap_exceeded", f"section count {nsec} exceeds cap {MAX_SECTIONS}", e_lfanew + 6)

        _need(data, e_lfanew + 24, 2, "pe.opt.truncated", "optional header magic")
        magic = _u16(data, e_lfanew + 24)
        if magic not in (PE32_MAGIC, PE32P_MAGIC):
            raise LoadError("pe.opt.truncated", f"unknown optional header magic 0x{magic:x}", e_lfanew + 24)
        if opt_size != OPT_SIZE_EXPECTED[magic]:
            raise LoadError("pe.opt.size_mismatch", f"SizeOfOptionalHeader {opt_size} != expected {OPT_SIZE_EXPECTED[magic]}", e_lfanew + 20)

        section_table = e_lfanew + 4 + 20 + opt_size
        table_end = section_table + nsec * 40
        if table_end > len(data):
            raise LoadError("pe.sectab.truncated", "section table extends past end of file", section_table)

        sections: List[Section] = []
        for i in range(nsec):
            off = section_table + i * 40
            name = data[off:off + 8].rstrip(b"\x00").decode("latin-1")
            vsize = _u32(data, off + 8)
            vaddr = _u32(data, off + 12)
            raw_size = _u32(data, off + 16)
            raw_ptr = _u32(data, off + 20)
            chars = _u32(data, off + 36)
            if raw_size > MAX_RAW_SECTION:
                raise LoadError("pe.section.cap_exceeded", f"section {name} raw size exceeds cap", off + 16)
            if raw_ptr + raw_size > len(data):
                status = "degraded"
                diags.append(Diagnostic("pe.section.truncated", f"section {name} raw data truncated", "warn",
                                        {"section": name, "raw_ptr": raw_ptr, "raw_size": raw_size, "file_size": len(data)}))
            sections.append(Section(i + 1, name, vaddr, vsize, raw_ptr, raw_size, chars))
            findings.append(Finding(
                kind="section", value=name, confidence_permille=1000, level="L0",
                rule="pe.section.parse",
                evidence=[Evidence(offset=off, space="file", rule="pe.section.parse")],
            ))

        findings.append(Finding(
            kind="signature", value=f"machine=0x{machine:04x};magic=0x{magic:03x}",
            confidence_permille=1000, level="L0", rule="pe.coff.parse",
            evidence=[Evidence(offset=e_lfanew + 4, space="file", rule="pe.coff.parse")],
        ))

        dlls, entries = _parse_imports(data, sections)
        if dlls:
            findings.append(Finding(
                kind="import", value=f"dlls={len(dlls)};entries={entries}",
                confidence_permille=1000, level="L0", rule="pe.import.parse",
                evidence=[Evidence(offset=sections[0].raw_ptr if sections else 0, space="file", rule="pe.import.parse")],
            ))

        exports = _parse_exports(data, sections)
        if exports:
            findings.append(Finding(
                kind="export", value=f"count={exports}", confidence_permille=1000, level="L0",
                rule="pe.export.parse",
                evidence=[Evidence(offset=0, space="file", rule="pe.export.parse")],
            ))

    except LoadError as exc:
        return _failed(data, exc.code, exc.message, exc.offset)

    return AnalysisResult(
        target_sha256=_sha(data), target_kind="pe", target_size=len(data),
        status=status, findings=findings, diagnostics=diags,
    )


def _failed(data: bytes, code: str, message: str, offset: int = 0) -> AnalysisResult:
    return AnalysisResult(
        target_sha256=_sha(data), target_kind="pe", target_size=len(data),
        status="failed",
        findings=[],
        diagnostics=[Diagnostic(code, message, "error", {"offset": offset})],
    )


def _sha(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _rva_to_off(sections: List[Section], rva: int) -> Optional[int]:
    for s in sections:
        span = max(s.virtual_size, s.raw_size)
        if s.virtual_address <= rva < s.virtual_address + span:
            return s.raw_ptr + (rva - s.virtual_address)
    return None


def _data_dir(data: bytes, e_lfanew: int, index: int) -> Tuple[int, int]:
    magic = _u16(data, e_lfanew + 24)
    base = e_lfanew + 24 + (96 if magic == PE32_MAGIC else 112)
    off = base + index * 8
    if off + 8 > len(data):
        return (0, 0)
    return (_u32(data, off), _u32(data, off + 4))


def _parse_imports(data: bytes, sections: List[Section]) -> Tuple[List[str], int]:
    try:
        e_lfanew = _u32(data, 0x3C)
        rva, size = _data_dir(data, e_lfanew, 1)
    except Exception:
        return ([], 0)
    if not rva or not size:
        return ([], 0)
    off = _rva_to_off(sections, rva)
    if off is None:
        return ([], 0)
    dlls: List[str] = []
    entries = 0
    cur = off
    while cur + 20 <= len(data) and len(dlls) < MAX_IMPORT_DLLS:
        name_rva = _u32(data, cur + 12)
        if name_rva == 0:
            break
        name_off = _rva_to_off(sections, name_rva)
        if name_off is None or name_off >= len(data):
            break
        end = data.find(b"\x00", name_off, min(name_off + 256, len(data)))
        if end < 0:
            break
        dlls.append(data[name_off:end].decode("latin-1"))
        thunk_rva = _u32(data, cur)
        thunk_off = _rva_to_off(sections, thunk_rva) if thunk_rva else None
        if thunk_off is not None:
            width = 8 if _u16(data, _u32(data, 0x3C) + 24) == PE32P_MAGIC else 4
            step = 0
            while thunk_off + width <= len(data) and step < MAX_IMPORT_ENTRIES:
                val = struct.unpack_from("<Q" if width == 8 else "<I", data, thunk_off)[0]
                if val == 0:
                    break
                entries += 1
                thunk_off += width
                step += 1
        cur += 20
    return (dlls, entries)


@dataclass
class ImportEntry:
    iat_address: int
    module: str
    name: str
    ordinal: bool = False

    def as_dict(self) -> dict:
        return {"iat_address": self.iat_address, "module": self.module,
                "name": self.name, "ordinal": self.ordinal}


def imports(data: bytes) -> List[ImportEntry]:
    """Import directory -> IAT slot address (normalised space) + module/name."""
    try:
        sections = sections_of(data)
        e_lfanew = _u32(data, 0x3C)
        rva, size = _data_dir(data, e_lfanew, 1)
        magic = _u16(data, e_lfanew + 24)
    except Exception:
        return []
    if not rva or not size:
        return []
    off = _rva_to_off(sections, rva)
    if off is None:
        return []
    width = 8 if magic == PE32P_MAGIC else 4
    text_rva = next((s.virtual_address for s in sections if s.name == ".text"), 0)
    norm = lambda value: 0x1000 + (value - text_rva)  # noqa: E731
    out: List[ImportEntry] = []
    cur = off
    while cur + 20 <= len(data) and len(out) < MAX_IMPORT_ENTRIES:
        name_rva = _u32(data, cur + 12)
        if name_rva == 0:
            break
        name_off = _rva_to_off(sections, name_rva)
        if name_off is None or name_off >= len(data):
            break
        end = data.find(b"\x00", name_off, min(name_off + 256, len(data)))
        if end < 0:
            break
        module = data[name_off:end].decode("latin-1")
        lookup_rva = _u32(data, cur) or _u32(data, cur + 16)
        lookup_off = _rva_to_off(sections, lookup_rva) if lookup_rva else None
        iat_rva = _u32(data, cur + 16)
        if lookup_off is not None and iat_rva:
            idx = 0
            while lookup_off + width <= len(data) and idx < MAX_IMPORT_ENTRIES:
                value = struct.unpack_from("<Q" if width == 8 else "<I", data, lookup_off)[0]
                if value == 0:
                    break
                slot = norm(iat_rva + idx * width)
                if value & (1 << (63 if width == 8 else 31)):
                    out.append(ImportEntry(slot, module, "#%d" % (value & 0xFFFF), True))
                else:
                    hint_off = _rva_to_off(sections, value & 0x7FFFFFFF)
                    if hint_off is None or hint_off + 2 >= len(data):
                        idx += 1
                        continue
                    stop = data.find(b"\x00", hint_off + 2, min(hint_off + 258, len(data)))
                    if stop < 0:
                        idx += 1
                        continue
                    out.append(ImportEntry(slot, module,
                                           data[hint_off + 2:stop].decode("latin-1")))
                idx += 1
                lookup_off += width
        cur += 20
    return out


def sections_of(data: bytes) -> List[Section]:
    return sections(data)


def _parse_exports(data: bytes, sections: List[Section]) -> int:
    try:
        e_lfanew = _u32(data, 0x3C)
        rva, size = _data_dir(data, e_lfanew, 0)
    except Exception:
        return 0
    if not rva or not size:
        return 0
    off = _rva_to_off(sections, rva)
    if off is None or off + 24 > len(data):
        return 0
    count = _u32(data, off + 20)
    return count if count <= MAX_EXPORTS else MAX_EXPORTS
def sections(data: bytes) -> List[Section]:
    """Section headers only (no full parse); raises LoadError on a malformed table."""
    _need(data, 0x3C, 4, "pe.header.truncated", "e_lfanew field")
    e = _u32(data, 0x3C)
    _need(data, e, 24, "pe.coff.truncated", "COFF header")
    nsec = _u16(data, e + 6)
    opt_size = _u16(data, e + 20)
    if nsec > MAX_SECTIONS:
        raise LoadError("pe.sectab.cap_exceeded", f"section count {nsec} exceeds cap {MAX_SECTIONS}", e + 6)
    table = e + 4 + 20 + opt_size
    if table + nsec * 40 > len(data):
        raise LoadError("pe.sectab.truncated", "section table extends past end of file", table)
    out: List[Section] = []
    for i in range(nsec):
        off = table + i * 40
        name = data[off:off + 8].rstrip(b"\x00").decode("latin-1")
        vsize = _u32(data, off + 8)
        vaddr = _u32(data, off + 12)
        raw_size = _u32(data, off + 16)
        raw_ptr = _u32(data, off + 20)
        chars = _u32(data, off + 36)
        out.append(Section(i + 1, name, vaddr, vsize, raw_ptr, raw_size, chars))
    return out


def text_bytes(data: bytes) -> bytes:
    """Return the raw bytes of the .text section."""
    e = struct.unpack_from("<I", data, 0x3C)[0]
    n = struct.unpack_from("<H", data, e + 6)[0]
    o = struct.unpack_from("<H", data, e + 20)[0]
    table = e + 4 + 20 + o
    for i in range(n):
        off = table + i * 40
        if data[off:off + 8].rstrip(b"\x00") == b".text":
            rs, rp = struct.unpack_from("<II", data, off + 16)
            return data[rp:rp + rs]
    raise ValueError("no .text section")

def export_addresses(data: bytes) -> list[int]:
    """Map export RVAs into the disassembly address space (0x1000 + offset in .text)."""
    e = struct.unpack_from("<I", data, 0x3C)[0]
    n = struct.unpack_from("<H", data, e + 6)[0]
    o = struct.unpack_from("<H", data, e + 20)[0]
    magic = struct.unpack_from("<H", data, e + 24)[0]
    dir_base = e + 24 + (96 if magic == 0x10B else 112)
    exp_rva, exp_size = struct.unpack_from("<II", data, dir_base)
    if not exp_rva or not exp_size:
        return []
    table = e + 4 + 20 + o
    text_vaddr = None
    text_size = 0
    exp_off = None
    for i in range(n):
        off = table + i * 40
        name = data[off:off + 8].rstrip(b"\x00")
        vsize, vaddr = struct.unpack_from("<II", data, off + 8)
        rsize, roff = struct.unpack_from("<II", data, off + 16)
        if name == b".text":
            text_vaddr, text_size = vaddr, rsize
        if vaddr <= exp_rva < vaddr + max(vsize, rsize):
            exp_off = roff + (exp_rva - vaddr)
    if text_vaddr is None or exp_off is None or exp_off + 40 > len(data):
        return []
    count = struct.unpack_from("<I", data, exp_off + 24)[0]
    funcs_rva = struct.unpack_from("<I", data, exp_off + 28)[0]
    if not funcs_rva:
        return []
    funcs_off = exp_off + (funcs_rva - exp_rva)
    out = []
    for k in range(min(count, 65535)):
        pos = funcs_off + 4 * k
        if pos + 4 > len(data):
            break
        rva = struct.unpack_from("<I", data, pos)[0]
        if not rva or rva < text_vaddr:
            continue
        offset = rva - text_vaddr
        if offset < text_size:
            out.append(0x1000 + offset)
    return out
