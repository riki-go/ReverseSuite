"""ELF loader (stdlib only): ELF32/ELF64, x86, x86-64, ARM, AArch64.

Covers Android native libraries (`lib/arm64-v8a/*.so`) and Linux binaries.
"""
from __future__ import annotations

import struct
from typing import List, Tuple

from .base import BinaryImage, BinaryLoader, FormatError, SectionInfo, build_image, pick_code_section

SHT_SYMTAB = 2
SHT_DYNSYM = 11
SHF_EXECINSTR = 0x4

EM_386 = 3
EM_ARM = 40
EM_X86_64 = 62
EM_AARCH64 = 183

MAX_SECTIONS = 4096
MAX_SYMBOLS = 200000


def _arch(machine: int) -> str:
    return {EM_X86_64: "x64", EM_AARCH64: "arm64", EM_ARM: "arm", EM_386: "x86"}.get(machine, "unknown")


def _cstr(blob: bytes, off: int) -> str:
    if off < 0 or off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    if end < 0:
        end = len(blob)
    return blob[off:end].decode("latin-1", "replace")


def load(data: bytes) -> BinaryImage:
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise FormatError("elf.header.truncated", "not an ELF file")
    ei_class = data[4]
    ei_data = data[5]
    if ei_data != 1:
        raise FormatError("elf.header.big_endian", "big-endian ELF is not supported")
    is64 = ei_class == 2
    if is64:
        if len(data) < 64:
            raise FormatError("elf.header.truncated", "ELF64 header truncated")
        (e_type, e_machine, _ver, e_entry, _phoff, e_shoff, _flags, _ehsize,
         _phentsize, _phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    else:
        (e_type, e_machine, _ver, e_entry, _phoff, e_shoff, _flags, _ehsize,
         _phentsize, _phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHIIIIIHHHHHH", data, 16)

    if e_shnum > MAX_SECTIONS:
        raise FormatError("elf.section.cap_exceeded", f"section count {e_shnum} exceeds cap {MAX_SECTIONS}")
    if not e_shoff or e_shoff + e_shnum * e_shentsize > len(data):
        raise FormatError("elf.section.truncated", "section table extends past end of file")

    raw = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        if is64:
            (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
             sh_link, _info, _align, sh_entsize) = struct.unpack_from("<IIQQQQIIQQ", data, off)
        else:
            (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
             sh_link, _info, _align, sh_entsize) = struct.unpack_from("<IIIIIIIIII", data, off)
        raw.append((sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_entsize))

    shstr = b""
    if 0 <= e_shstrndx < len(raw):
        _n, _t, _f, _a, sh_offset, sh_size, _l, _e = raw[e_shstrndx]
        shstr = data[sh_offset:sh_offset + sh_size]

    sections: List[SectionInfo] = []
    names: List[str] = []
    for i, (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, _link, _ent) in enumerate(raw):
        name = _cstr(shstr, sh_name)
        names.append(name)
        if sh_type == 8 or sh_size == 0 or sh_offset + sh_size > len(data):
            continue  # SHT_NOBITS / empty / truncated
        sections.append(SectionInfo(i, name or ("section%d" % i), sh_addr, sh_size,
                                    sh_offset, sh_size, bool(sh_flags & SHF_EXECINSTR)))

    code_sec = pick_code_section(sections, (".text",))
    if code_sec is None:
        raise FormatError("elf.text.missing", "no executable section found")
    code = data[code_sec.raw_ptr:code_sec.raw_ptr + code_sec.raw_size]

    symbols: List[Tuple[int, str]] = []
    for i, (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, link, ent) in enumerate(raw):
        if sh_type not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if not ent or not sh_offset or sh_offset + sh_size > len(data):
            continue
        if not (0 <= link < len(raw)):
            continue
        _ln, _lt, _lf, _la, str_off, str_size, _ll, _le = raw[link]
        strtab = data[str_off:str_off + str_size]
        count = min(sh_size // ent, MAX_SYMBOLS)
        for k in range(count):
            pos = sh_offset + k * ent
            if is64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", data, pos)
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from("<IIIBBH", data, pos)
            if st_value and st_shndx != 0:
                label = _cstr(strtab, st_name)
                if label:
                    symbols.append((st_value, label))
    symbols.sort(key=lambda item: (item[0], item[1]))

    exports: List[int] = list(dict.fromkeys(addr for addr, name in symbols if name and not name.startswith("_")))
    imports = [name for _a, name in symbols if name.endswith("@") or name.startswith("__imp_")]
    meta = {
        "elf_type": {1: "rel", 2: "exec", 3: "dyn", 4: "core"}.get(e_type, str(e_type)),
        "machine": "0x%x" % e_machine,
        "section_names": [n for n in names if n][:64],
    }
    return build_image(
        format="elf", arch=_arch(e_machine), bits=64 if is64 else 32, sections=sections,
        entry=e_entry or None, code=code, code_va=code_sec.va or 0x1000,
        exports=exports, imports=imports, symbols=symbols, metadata=meta,
        target_kind="elf",
    )


class ELFLloader(BinaryLoader):
    """ELF loader implementing the BinaryLoader contract."""

    format = "elf"
    target_kind = "elf"

    def parse(self, data: bytes) -> BinaryImage:
        return load(data)
