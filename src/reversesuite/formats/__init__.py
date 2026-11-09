"""Format detection and loading (M8 Phase 1).

`detect` looks at magic bytes only - never at the file extension alone - and
`load` returns a :class:`BinaryImage` for single-image formats.
ZIP containers (.apk/.ipa) are handed to :mod:`reversesuite.formats.container`.
"""
from __future__ import annotations

import struct
from typing import Optional

from .base import (ARCH_INFO, BASE_ADDRESS, FORMAT_APK, FORMAT_DEX, FORMAT_ELF, FORMAT_IPA,
                   FORMAT_MACHO, FORMAT_PE, FORMAT_UNKNOWN, BinaryImage, BinaryLoader,
                   FormatError, SectionInfo, build_image, pick_code_section)

__all__ = [
    "ARCH_INFO", "BASE_ADDRESS", "BinaryImage", "BinaryLoader", "FormatError", "SectionInfo",
    "build_image",
    "pick_code_section", "detect", "detect_container", "load", "load_slice_count", "loader_for",
    "FORMAT_PE", "FORMAT_ELF", "FORMAT_MACHO", "FORMAT_DEX", "FORMAT_APK", "FORMAT_IPA",
    "FORMAT_UNKNOWN",
]

MACHO_MAGICS_BE = (0xCAFEBABE, 0xCAFEBABF)


def detect(data: bytes, filename: str = "") -> str:
    """Magic-byte format detection. Extension is only a hint for ZIP containers."""
    if len(data) < 8:
        return FORMAT_UNKNOWN
    if data[:2] == b"MZ":
        try:
            e = struct.unpack_from("<I", data, 0x3C)[0]
            if e + 4 <= len(data) and data[e:e + 4] == b"PE\x00\x00":
                return FORMAT_PE
        except struct.error:
            return FORMAT_UNKNOWN
    if data[:4] == b"\x7fELF":
        return FORMAT_ELF
    if data[:4] == b"dex\n":
        return FORMAT_DEX
    magic_le = struct.unpack_from("<I", data, 0)[0]
    magic_be = struct.unpack_from(">I", data, 0)[0]
    if magic_le in (0xFEEDFACE, 0xFEEDFACF) or magic_be in MACHO_MAGICS_BE:
        return FORMAT_MACHO
    if data[:2] == b"PK":
        from . import container
        try:
            kind = container.detect_kind(data, filename)
        except Exception:
            return FORMAT_UNKNOWN
        if kind == "apk":
            return FORMAT_APK
        if kind == "ipa":
            return FORMAT_IPA
    return FORMAT_UNKNOWN


def detect_container(data: bytes, filename: str = "") -> str:
    from . import container
    if not container.is_zip(data):
        return ""
    return container.detect_kind(data, filename)


def load_slice_count(data: bytes) -> int:
    from . import macho
    try:
        return len(macho.slice_offsets(data)) or 1
    except FormatError:
        return 1


def loader_for(fmt: str) -> "BinaryLoader":
    """Return the registered loader for a format name (M8 Phase 1 registry)."""
    from . import dex as dex_mod, elf as elf_mod, macho as macho_mod, pe as pe_mod
    registry = {
        FORMAT_PE: pe_mod.PELoader(),
        FORMAT_ELF: elf_mod.ELFLloader(),
        FORMAT_MACHO: macho_mod.MachOLoader(),
        FORMAT_DEX: dex_mod.DEXLoader(),
    }
    try:
        return registry[fmt]
    except KeyError:
        raise FormatError("format.unsupported", f"no loader registered for: {fmt or 'unknown'}")


def load(data: bytes, filename: str = "", fmt: Optional[str] = None) -> BinaryImage:
    fmt = fmt or detect(data, filename)
    if fmt == FORMAT_PE:
        from . import pe
        return pe.load(data)
    if fmt == FORMAT_ELF:
        from . import elf
        return elf.load(data)
    if fmt == FORMAT_MACHO:
        from . import macho
        return macho.load(data)
    if fmt == FORMAT_DEX:
        from . import dex
        return dex.load(data)
    raise FormatError("format.unsupported", f"cannot load format: {fmt or 'unknown'}")
