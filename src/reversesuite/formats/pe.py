"""PE adapter: wraps the existing stdlib loader so PE keeps byte-identical behaviour."""
from __future__ import annotations

import struct

from .base import BinaryImage, BinaryLoader, SectionInfo, build_image
from .. import loader

MACHINE_X86 = 0x14C
MACHINE_X64 = 0x8664
MACHINE_ARM = 0x1C0
MACHINE_ARM64 = 0xAA64

PE32_MAGIC = 0x10B
PE32P_MAGIC = 0x20B


def _arch(machine: int) -> str:
    if machine == MACHINE_X64:
        return "x64"
    if machine == MACHINE_ARM64:
        return "arm64"
    if machine == MACHINE_ARM:
        return "arm"
    return "x86"


def load(data: bytes) -> BinaryImage:
    e = struct.unpack_from("<I", data, 0x3C)[0]
    machine = struct.unpack_from("<H", data, e + 4)[0]
    magic = struct.unpack_from("<H", data, e + 24)[0]
    bits = 64 if magic == PE32P_MAGIC else 32
    entry_rva = struct.unpack_from("<I", data, e + 24 + 16)[0]
    image_base = (struct.unpack_from("<Q", data, e + 24 + 24)[0] if magic == PE32P_MAGIC
                  else struct.unpack_from("<I", data, e + 24 + 28)[0])

    raw = loader.sections(data)
    sections = [
        SectionInfo(s.index, s.name, s.virtual_address, s.virtual_size, s.raw_ptr,
                    s.raw_size, bool(s.characteristics & 0x20000000))
        for s in raw
    ]
    text = next((s for s in raw if s.name == ".text"), None)
    if text is None:
        raise loader.LoadError("pe.text.missing", "no .text section", 0)
    code = data[text.raw_ptr:text.raw_ptr + text.raw_size]

    entry = text.virtual_address + (entry_rva - text.virtual_address) if entry_rva else None
    exports = loader.export_addresses(data)
    imports = [f"{item.module}!{item.name}" for item in loader.imports(data)]
    symbols = [(s.virtual_address, s.name) for s in raw if s.raw_size]

    meta = {
        "machine": "0x%04x" % machine,
        "image_base": image_base,
        "subsystem": struct.unpack_from("<H", data, e + 24 + 68)[0] if magic == PE32P_MAGIC
        else struct.unpack_from("<H", data, e + 24 + 68)[0],
    }
    return build_image(
        format="pe", arch=_arch(machine), bits=bits, sections=sections,
        entry=entry, code=code, code_va=text.virtual_address,
        exports=exports, imports=imports, symbols=symbols, metadata=meta,
        target_kind="pe",
    )


class PELoader(BinaryLoader):
    """PE loader implementing the BinaryLoader contract."""

    format = "pe"
    target_kind = "pe"

    def parse(self, data: bytes) -> BinaryImage:
        return load(data)
