"""Mach-O loader (stdlib only): thin 32/64-bit and fat/universal binaries.

Targets iOS app binaries shipped inside `.ipa` (`Payload/<App>.app/<App>`).
"""
from __future__ import annotations

import struct
from typing import List, Optional, Tuple

from .base import BinaryImage, BinaryLoader, FormatError, SectionInfo, build_image, pick_code_section

MH_MAGIC = 0xFEEDFACE
MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF

LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_MAIN = 0x80000028
LC_UNIXTHREAD = 0x5

CPU_TYPE_X86 = 7
CPU_TYPE_X86_64 = 0x01000007
CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = 0x0100000C

MAX_LOAD_COMMANDS = 8192
MAX_SECTIONS = 512
MAX_SYMBOLS = 200000


def is_macho(data: bytes) -> bool:
    if len(data) < 8:
        return False
    magic_le = struct.unpack_from("<I", data, 0)[0]
    magic_be = struct.unpack_from(">I", data, 0)[0]
    return magic_le in (MH_MAGIC, MH_MAGIC_64) or magic_be in (FAT_MAGIC, FAT_MAGIC_64)


def _arch(cputype: int) -> str:
    return {CPU_TYPE_X86_64: "x64", CPU_TYPE_ARM64: "arm64", CPU_TYPE_ARM: "arm", CPU_TYPE_X86: "x86"}.get(
        cputype, "unknown")


def _cstr(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("latin-1", "replace")


def slice_offsets(data: bytes) -> List[Tuple[int, int, int]]:
    """Fat binaries -> [(cputype, offset, size)]; thin -> [(cputype, 0, len)]."""
    if len(data) < 8:
        return []
    magic_be = struct.unpack_from(">I", data, 0)[0]
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        count = struct.unpack_from(">I", data, 4)[0]
        if count > 64:
            raise FormatError("macho.fat.cap_exceeded", f"fat arch count {count} exceeds cap 64")
        step = 32 if magic_be == FAT_MAGIC_64 else 20
        out = []
        for i in range(count):
            off = 8 + i * step
            if off + step > len(data):
                break
            if magic_be == FAT_MAGIC_64:
                cputype, _sub, offset, size, _align, _res = struct.unpack_from(">IIQQII", data, off)
            else:
                cputype, _sub, offset, size, _align = struct.unpack_from(">IIIII", data, off)
            if offset + size <= len(data):
                out.append((cputype, offset, size))
        return out
    magic_le = struct.unpack_from("<I", data, 0)[0]
    if magic_le in (MH_MAGIC, MH_MAGIC_64):
        cputype = struct.unpack_from("<I", data, 4)[0]
        return [(cputype, 0, len(data))]
    return []


def load(data: bytes, slice_index: Optional[int] = None) -> BinaryImage:
    slices = slice_offsets(data)
    if not slices:
        raise FormatError("macho.header.truncated", "not a Mach-O image")
    if slice_index is not None:
        slices = [slices[slice_index]]
    else:
        # Prefer arm64 (iOS device builds), then x64, then whatever is first.
        order = {CPU_TYPE_ARM64: 0, CPU_TYPE_X86_64: 1, CPU_TYPE_ARM: 2, CPU_TYPE_X86: 3}
        slices = sorted(slices, key=lambda item: order.get(item[0], 9))
    cputype, offset, size = slices[0]
    blob = data[offset:offset + size]
    return _load_thin(blob, cputype)


def _load_thin(blob: bytes, cputype: int) -> BinaryImage:
    if len(blob) < 28:
        raise FormatError("macho.header.truncated", "Mach-O header truncated")
    magic = struct.unpack_from("<I", blob, 0)[0]
    is64 = magic == MH_MAGIC_64
    if magic not in (MH_MAGIC, MH_MAGIC_64):
        raise FormatError("macho.header.magic", "unexpected Mach-O magic 0x%x" % magic)
    header_size = 32 if is64 else 28
    if len(blob) < header_size:
        raise FormatError("macho.header.truncated", "Mach-O header truncated")
    (_m, _ct, _cs, filetype, ncmds, sizeofcmds, _flags) = struct.unpack_from("<IIIIIII", blob, 0)
    if ncmds > MAX_LOAD_COMMANDS:
        raise FormatError("macho.lc.cap_exceeded", f"load command count {ncmds} exceeds cap")

    sections: List[SectionInfo] = []
    segments: List[Tuple[str, int, int, int, int]] = []
    symtab: Optional[Tuple[int, int, int, int]] = None
    entry_off: Optional[int] = None
    cryptid = 0
    encrypted_range = (0, 0)
    text_vmaddr: Optional[int] = None

    cur = header_size
    index = 0
    for _ in range(ncmds):
        if cur + 8 > len(blob):
            raise FormatError("macho.lc.truncated", "load command truncated", cur)
        cmd, cmdsize = struct.unpack_from("<II", blob, cur)
        if cmdsize < 8 or cur + cmdsize > len(blob):
            raise FormatError("macho.lc.truncated", "load command size out of range", cur)
        if cmd in (LC_SEGMENT, LC_SEGMENT_64):
            if cmd == LC_SEGMENT_64:
                if cur + 72 > len(blob):
                    raise FormatError("macho.segment.truncated", "segment command truncated", cur)
                segname = _cstr(blob[cur + 8:cur + 24])
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", blob, cur + 24)
                nsects = struct.unpack_from("<I", blob, cur + 64)[0]
                sect_base = cur + 72
                sect_size = 80
            else:
                if cur + 56 > len(blob):
                    raise FormatError("macho.segment.truncated", "segment command truncated", cur)
                segname = _cstr(blob[cur + 8:cur + 24])
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<IIII", blob, cur + 24)
                nsects = struct.unpack_from("<I", blob, cur + 48)[0]
                sect_base = cur + 56
                sect_size = 68
            segments.append((segname, vmaddr, vmsize, fileoff, filesize))
            if segname == "__TEXT" and text_vmaddr is None:
                text_vmaddr = vmaddr
            if nsects > MAX_SECTIONS:
                raise FormatError("macho.section.cap_exceeded", f"section count {nsects} exceeds cap")
            for k in range(nsects):
                off = sect_base + k * sect_size
                if off + sect_size > len(blob):
                    break
                sectname = _cstr(blob[off:off + 16])
                seg_of_sect = _cstr(blob[off + 16:off + 32])
                if is64:
                    addr, ssize, foff, _align, _reloff, _nreloc, flags = struct.unpack_from("<QQIIIII", blob, off + 32)
                else:
                    addr, ssize, foff, _align, _reloff, _nreloc, flags = struct.unpack_from("<IIIIIII", blob, off + 32)
                if ssize == 0 or foff + ssize > len(blob):
                    continue
                executable = bool(flags & 0x80000000) or sectname in ("__text", "__stubs", "__stub_helper")
                sections.append(SectionInfo(index, f"{seg_of_sect},{sectname}", addr, ssize, foff, ssize, executable))
                index += 1
        elif cmd == LC_SYMTAB:
            if cur + 24 <= len(blob):
                symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", blob, cur + 8)
                symtab = (symoff, nsyms, stroff, strsize)
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            if cur + 20 <= len(blob):
                _cryptoff, _cryptsize, cryptid = struct.unpack_from("<III", blob, cur + 8)
                encrypted_range = (_cryptoff, _cryptsize)
        elif cmd == LC_MAIN:
            if cur + 16 <= len(blob):
                entry_off = struct.unpack_from("<Q", blob, cur + 8)[0]
        cur += cmdsize

    # __TEXT,__text is the analysis target; fall back to any executable section.
    code_sec = None
    for sec in sections:
        if sec.name == "__TEXT,__text" and sec.raw_size:
            code_sec = sec
            break
    if code_sec is None:
        code_sec = pick_code_section(sections, ("__TEXT,__text",))
    if code_sec is None:
        raise FormatError("macho.text.missing", "no executable section found")

    code = blob[code_sec.raw_ptr:code_sec.raw_ptr + code_sec.raw_size]

    entry = None
    if entry_off is not None and text_vmaddr is not None:
        entry = text_vmaddr + entry_off

    symbols: List[Tuple[int, str]] = []
    if symtab:
        symoff, nsyms, stroff, strsize = symtab
        if symoff + nsyms * (16 if is64 else 12) <= len(blob) and stroff + strsize <= len(blob):
            strtab = blob[stroff:stroff + strsize]
            for k in range(min(nsyms, MAX_SYMBOLS)):
                pos = symoff + k * (16 if is64 else 12)
                if is64:
                    n_strx, n_type, n_sect, _desc, n_value = struct.unpack_from("<IBBHQ", blob, pos)
                else:
                    n_strx, n_value, n_type, n_sect, _desc = struct.unpack_from("<IIBBH", blob, pos)
                if n_value and (n_type & 0x0E) in (0x0E, 0x02):
                    name = _cstr(strtab[n_strx:]) if n_strx < len(strtab) else ""
                    if name:
                        symbols.append((n_value, name))
    symbols.sort(key=lambda item: (item[0], item[1]))

    has_bitcode = any("__LLVM" in sec.name or "bitcode" in sec.name.lower() for sec in sections)
    meta = {
        "filetype": filetype,
        "encrypted": bool(cryptid),
        "cryptid": cryptid,
        "crypt_range": list(encrypted_range),
        "bitcode": has_bitcode,
        "segments": [seg[0] for seg in segments],
        "cputype": "0x%08x" % cputype,
        "fat_slices": len(slice_offsets(blob)) if len(blob) >= 8 else 1,
        "uuid": "",
    }
    diagnostics = []
    if cryptid:
        diagnostics.append(("macho.encrypted",
                            "binary is FairPlay-encrypted (cryptid=%d); static analysis sees ciphertext"
                            % cryptid))
    if has_bitcode:
        diagnostics.append(("macho.bitcode", "binary embeds LLVM bitcode sections"))
    return build_image(
        format="macho", arch=_arch(cputype), bits=64 if is64 else 32, sections=sections,
        entry=entry, code=code, code_va=code_sec.va,
        exports=[addr for addr, _n in symbols], imports=[n for _a, n in symbols if n.startswith("_")],
        symbols=symbols, metadata=meta, diagnostics=diagnostics, target_kind="macho",
    )


class MachOLoader(BinaryLoader):
    """Mach-O loader implementing the BinaryLoader contract."""

    format = "macho"
    target_kind = "macho"

    def parse(self, data: bytes) -> BinaryImage:
        return load(data)
