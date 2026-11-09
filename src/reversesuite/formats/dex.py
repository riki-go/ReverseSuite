"""DEX loader (stdlib only): classes, methods, fields and string table.

Dalvik bytecode is intentionally not disassembled in this release (M8 Phase 3):
the goal is static inventory - what classes/methods/strings the app ships.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .base import BinaryImage, BinaryLoader, FormatError, SectionInfo, build_image

MAX_ITEMS = 300000
NO_INDEX = 0xFFFFFFFF


@dataclass
class DexInventory:
    version: str
    strings: List[Tuple[int, str]] = field(default_factory=list)
    classes: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    # method_idx -> "com.foo.Bar.method" (index aligned with method_ids)
    method_names: List[str] = field(default_factory=list)
    # method_idx -> full descriptor including prototype
    method_signatures: List[str] = field(default_factory=list)
    # method_idx -> code_item file offset (0 when abstract/native)
    code_offsets: Dict[int, int] = field(default_factory=dict)
    # class name -> declared method indices in class_data order
    class_methods: Dict[str, List[int]] = field(default_factory=dict)
    fields: List[str] = field(default_factory=list)
    superclasses: Dict[str, str] = field(default_factory=dict)
    source_files: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"version": self.version, "strings": len(self.strings), "classes": len(self.classes),
                "methods": len(self.methods), "fields": len(self.fields)}


def is_dex(data: bytes) -> bool:
    return len(data) >= 8 and data[:4] == b"dex\n" and data[7] == 0


def _uleb128(data: bytes, off: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if off >= len(data):
            return result, off
        byte = data[off]
        off += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, off
        shift += 7
        if shift > 35:
            return result, off


def _mutf8(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def _descriptor(value: str) -> str:
    """'Lcom/foo/Bar;' -> 'com.foo.Bar'; keep primitive descriptors as-is."""
    if value.startswith("L") and value.endswith(";"):
        return value[1:-1].replace("/", ".")
    return value


def parse(data: bytes) -> DexInventory:
    if not is_dex(data):
        raise FormatError("dex.header.magic", "not a DEX file")
    if len(data) < 112:
        raise FormatError("dex.header.truncated", "DEX header truncated")
    version = data[4:7].decode("ascii", "replace")
    (file_size, header_size, endian_tag) = struct.unpack_from("<III", data, 32)
    if endian_tag != 0x12345678:
        raise FormatError("dex.header.endian", "unsupported endian tag 0x%x" % endian_tag)
    if file_size and file_size > len(data):
        raise FormatError("dex.header.size_mismatch",
                          f"declared file_size {file_size} exceeds actual {len(data)}")
    (string_ids_size, string_ids_off) = struct.unpack_from("<II", data, 56)
    (type_ids_size, type_ids_off) = struct.unpack_from("<II", data, 64)
    (field_ids_size, field_ids_off) = struct.unpack_from("<II", data, 80)
    (method_ids_size, method_ids_off) = struct.unpack_from("<II", data, 88)
    (class_defs_size, class_defs_off) = struct.unpack_from("<II", data, 96)

    inv = DexInventory(version=version)

    def need(off: int, size: int, code: str) -> None:
        if off < 0 or off + size > len(data):
            raise FormatError(code, "table extends past end of file", off)

    if string_ids_size and string_ids_off:
        need(string_ids_off, string_ids_size * 4, "dex.strings.truncated")
        for i in range(min(string_ids_size, MAX_ITEMS)):
            data_off = struct.unpack_from("<I", data, string_ids_off + i * 4)[0]
            if data_off >= len(data):
                continue
            _len, pos = _uleb128(data, data_off)
            end = data.find(b"\x00", pos)
            if end < 0:
                end = len(data)
            inv.strings.append((data_off, _mutf8(data[pos:end])))

    def type_name(index: int) -> str:
        if not type_ids_size or index >= type_ids_size or index == NO_INDEX:
            return ""
        pos = type_ids_off + index * 4
        if pos + 4 > len(data):
            return ""
        str_idx = struct.unpack_from("<I", data, pos)[0]
        if str_idx >= len(inv.strings):
            return ""
        return inv.strings[str_idx][1]

    if field_ids_size and field_ids_off:
        need(field_ids_off, field_ids_size * 8, "dex.fields.truncated")
        for i in range(min(field_ids_size, MAX_ITEMS)):
            cls_idx, type_idx, name_idx = struct.unpack_from("<HHI", data, field_ids_off + i * 8)
            owner = _descriptor(type_name(cls_idx))
            name = inv.strings[name_idx][1] if name_idx < len(inv.strings) else ""
            if owner and name:
                inv.fields.append(f"{owner}.{name}:{type_name(type_idx)}")

    if method_ids_size and method_ids_off:
        need(method_ids_off, method_ids_size * 8, "dex.methods.truncated")
        for i in range(min(method_ids_size, MAX_ITEMS)):
            cls_idx, proto_idx, name_idx = struct.unpack_from("<HHI", data, method_ids_off + i * 8)
            owner = _descriptor(type_name(cls_idx))
            name = inv.strings[name_idx][1] if name_idx < len(inv.strings) else ""
            signature = f"{owner}.{name}"
            proto_return = _proto_return(data, inv, proto_idx)
            if owner and name:
                inv.method_names.append(signature)
                inv.method_signatures.append(f"{owner}.{name}:{proto_return}")
                if not name.startswith("<"):
                    inv.methods.append(signature)

    if class_defs_size and class_defs_off:
        need(class_defs_off, class_defs_size * 32, "dex.classes.truncated")
        for i in range(min(class_defs_size, MAX_ITEMS)):
            (class_idx, _flags, super_idx, _ifaces, source_idx,
             _ann, _cdata, _static) = struct.unpack_from("<IIIIIIII", data, class_defs_off + i * 32)
            name = _descriptor(type_name(class_idx))
            if not name:
                continue
            inv.classes.append(name)
            sup = _descriptor(type_name(super_idx))
            if sup:
                inv.superclasses[name] = sup
            if source_idx < len(inv.strings):
                inv.source_files.append(inv.strings[source_idx][1])

    inv.classes.sort()
    inv.methods.sort()
    inv.fields.sort()
    _read_class_data(data, inv, class_defs_off, class_defs_size, method_ids_size)
    return inv


def _uleb(data: bytes, off: int) -> Tuple[int, int]:
    return _uleb128(data, off)


def _read_class_data(data: bytes, inv: "DexInventory", class_defs_off: int,
                     class_defs_size: int, method_ids_size: int) -> None:
    """Walk class_def -> class_data_item -> encoded methods -> code_item offsets."""
    for i in range(min(class_defs_size, MAX_ITEMS)):
        pos = class_defs_off + i * 32
        if pos + 32 > len(data):
            break
        class_idx, _flags, _super, _ifaces, _src, _ann, class_data_off, _static = struct.unpack_from(
            "<IIIIIIII", data, pos)
        if not class_data_off or class_data_off >= len(data):
            continue
        class_name = _descriptor(_type_name_at(data, inv, class_idx))
        cursor = class_data_off
        counts = []
        for _ in range(4):  # static fields, instance fields, direct methods, virtual methods
            value, cursor = _uleb(data, cursor)
            counts.append(value)
        static_fields, instance_fields, direct_methods, virtual_methods = counts
        # skip field definitions (idx_diff, access_flags)
        for _ in range(static_fields + instance_fields):
            _v, cursor = _uleb(data, cursor)
            _v, cursor = _uleb(data, cursor)
        order: List[int] = []
        for method_count in (direct_methods, virtual_methods):
            method_idx = 0
            for _ in range(method_count):
                diff, cursor = _uleb(data, cursor)
                _flags, cursor = _uleb(data, cursor)
                code_off, cursor = _uleb(data, cursor)
                method_idx += diff
                if method_idx >= method_ids_size:
                    continue
                order.append(method_idx)
                if code_off:
                    inv.code_offsets[method_idx] = code_off
        if class_name:
            inv.class_methods[class_name] = order


def _type_name_at(data: bytes, inv: "DexInventory", type_index: int) -> str:
    off = struct.unpack_from("<II", data, 64)[1]  # type_ids_size, type_ids_off
    pos = off + type_index * 4
    if pos + 4 > len(data):
        return ""
    str_idx = struct.unpack_from("<I", data, pos)[0]
    return inv.strings[str_idx][1] if str_idx < len(inv.strings) else ""


def _proto_return(data: bytes, inv: "DexInventory", proto_idx: int) -> str:
    proto_ids_off = struct.unpack_from("<II", data, 72)[1]
    pos = proto_ids_off + proto_idx * 12
    if pos + 12 > len(data):
        return "?"
    _shorty, return_type, _params = struct.unpack_from("<III", data, pos)
    return _descriptor(_type_name_at(data, inv, return_type))


def load(data: bytes) -> BinaryImage:
    inv = parse(data)
    sections = [SectionInfo(1, "dex", 0x1000, len(data), 0, len(data), False)]
    meta = {"dex_version": inv.version, "classes": len(inv.classes),
            "methods": len(inv.methods), "fields": len(inv.fields),
            "strings": len(inv.strings), "declared": True}
    return build_image(
        format="dex", arch="dalvik", bits=0, sections=sections, entry=None,
        code=b"", code_va=0x1000,
        exports=[], imports=[], symbols=[(0, name) for name in inv.classes[:200000]],
        metadata=meta, target_kind="dex",
    )


class DEXLoader(BinaryLoader):
    """DEX loader implementing the BinaryLoader contract."""

    format = "dex"
    target_kind = "dex"

    def parse(self, data: bytes) -> BinaryImage:
        return load(data)
