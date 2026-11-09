"""Binary AndroidManifest.xml (AXML) decoder - stdlib only.

Parses the compiled resource XML shipped inside every .apk: string pool,
start/end elements and their attributes, enough to report package identity,
SDK levels, permissions and exported components.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103

UTF8_FLAG = 0x100
NO_INDEX = 0xFFFFFFFF

TYPE_REFERENCE = 0x01
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

ANDROID_NS = "http://schemas.android.com/apk/res/android"

MAX_CHUNKS = 200000
MAX_STRINGS = 200000


class AxmlError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class Component:
    tag: str
    name: str
    exported: Optional[bool] = None
    permission: str = ""

    def as_dict(self) -> dict:
        return {"tag": self.tag, "name": self.name, "exported": self.exported,
                "permission": self.permission}


@dataclass
class Manifest:
    package: str = ""
    version_name: str = ""
    version_code: int = 0
    min_sdk: int = 0
    target_sdk: int = 0
    permissions: List[str] = field(default_factory=list)
    features: List[str] = field(default_factory=list)
    components: List[Component] = field(default_factory=list)
    debuggable: bool = False
    allow_backup: Optional[bool] = None
    uses_cleartext: Optional[bool] = None
    main_activity: str = ""

    def as_dict(self) -> dict:
        return {
            "package": self.package, "version_name": self.version_name,
            "version_code": self.version_code, "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk, "permissions": list(self.permissions),
            "components": [c.as_dict() for c in self.components],
            "debuggable": self.debuggable, "allow_backup": self.allow_backup,
            "uses_cleartext": self.uses_cleartext, "main_activity": self.main_activity,
        }

    def exported_components(self) -> List[Component]:
        return [c for c in self.components if c.exported]


def is_axml(data: bytes) -> bool:
    if len(data) < 8:
        return False
    chunk_type, header_size, _size = struct.unpack_from("<HHI", data, 0)
    return chunk_type == RES_XML_TYPE and header_size >= 8


def _read_string_pool(data: bytes, offset: int, header_size: int, size: int) -> List[str]:
    if offset + 28 > len(data):
        raise AxmlError("axml.pool.truncated", "string pool header truncated")
    (string_count, style_count, flags, strings_start,
     _styles_start) = struct.unpack_from("<IIIII", data, offset + 8)
    if string_count > MAX_STRINGS:
        raise AxmlError("axml.pool.cap_exceeded", f"string count {string_count} exceeds cap")
    offsets_start = offset + header_size
    if offsets_start + string_count * 4 > len(data):
        raise AxmlError("axml.pool.truncated", "string offsets extend past end of chunk")
    base = offset + strings_start
    utf8 = bool(flags & UTF8_FLAG)
    out: List[str] = []
    for i in range(string_count):
        pos = struct.unpack_from("<I", data, offsets_start + i * 4)[0]
        cursor = base + pos
        if cursor >= len(data):
            out.append("")
            continue
        try:
            if utf8:
                char_len, cursor = _varint8(data, cursor)
                byte_len, cursor = _varint8(data, cursor)
                raw = data[cursor:cursor + byte_len]
                out.append(raw.decode("utf-8", "replace"))
            else:
                char_len, cursor = _varint16(data, cursor)
                raw = data[cursor:cursor + char_len * 2]
                out.append(raw.decode("utf-16le", "replace"))
        except Exception:  # noqa: BLE001 - a damaged pool must not kill the analysis
            out.append("")
    return out


def _varint8(data: bytes, offset: int) -> Tuple[int, int]:
    value = data[offset]
    if value & 0x80:
        return ((value & 0x7F) << 8) | data[offset + 1], offset + 2
    return value, offset + 1


def _varint16(data: bytes, offset: int) -> Tuple[int, int]:
    value = struct.unpack_from("<H", data, offset)[0]
    if value & 0x8000:
        low = struct.unpack_from("<H", data, offset + 2)[0]
        return ((value & 0x7FFF) << 16) | low, offset + 4
    return value, offset + 2


def _typed_value(data: bytes, offset: int, size: int, strings: List[str]) -> object:
    if offset + 8 > len(data):
        return None
    _vsize, _res0, dtype, value = struct.unpack_from("<HBBI", data, offset)
    if dtype == TYPE_STRING:
        return strings[value] if value < len(strings) else ""
    if dtype in (TYPE_INT_DEC, TYPE_INT_HEX):
        return value
    if dtype == TYPE_INT_BOOLEAN:
        return bool(value)
    if dtype == TYPE_REFERENCE:
        return "@0x%08x" % value
    return value


def parse(data: bytes, max_components: int = 2000) -> Manifest:
    if not is_axml(data):
        raise AxmlError("axml.header.magic", "not a binary AndroidManifest.xml")
    _type, header_size, total = struct.unpack_from("<HHI", data, 0)
    if total > len(data):
        raise AxmlError("axml.header.truncated", "declared size exceeds the file size")

    strings: List[str] = []
    manifest = Manifest()
    stack: List[Tuple[str, Dict[str, object]]] = []
    depth = 0
    inside_manifest = False
    current_component: Optional[Component] = None
    pending_action = False
    cursor = header_size
    chunks = 0

    while cursor + 8 <= len(data) and cursor + 8 <= total:
        chunks += 1
        if chunks > MAX_CHUNKS:
            raise AxmlError("axml.chunk.cap_exceeded", "chunk count exceeds cap")
        ctype, chdr, csize = struct.unpack_from("<HHI", data, cursor)
        if csize < 8 or cursor + csize > len(data):
            break
        if ctype == RES_STRING_POOL_TYPE and not strings:
            strings = _read_string_pool(data, cursor, chdr, csize)
        elif ctype == RES_XML_START_ELEMENT_TYPE:
            name, attrs = _parse_start_element(data, cursor, chdr, strings)
            tag = name.lower()
            if tag == "manifest":
                inside_manifest = True
                manifest.package = str(attrs.get("package", manifest.package) or "")
                manifest.version_name = str(attrs.get("versionName", "") or "")
                code = attrs.get("versionCode", 0)
                manifest.version_code = int(code) if isinstance(code, int) else 0
            elif tag == "uses-sdk" and inside_manifest:
                manifest.min_sdk = _as_int(attrs.get("minSdkVersion"))
                manifest.target_sdk = _as_int(attrs.get("targetSdkVersion"))
            elif tag == "uses-permission" and inside_manifest:
                perm = str(attrs.get("name", "") or "")
                if perm:
                    manifest.permissions.append(perm)
            elif tag in ("uses-feature",) and inside_manifest:
                feature = str(attrs.get("name", "") or "")
                if feature:
                    manifest.features.append(feature)
            elif tag == "application" and inside_manifest:
                manifest.debuggable = bool(attrs.get("debuggable", False))
                if "allowBackup" in attrs:
                    manifest.allow_backup = bool(attrs["allowBackup"])
                if "usesCleartextTraffic" in attrs:
                    manifest.uses_cleartext = bool(attrs["usesCleartextTraffic"])
            elif tag == "action" and current_component is not None:
                if str(attrs.get("name", "")) == "android.intent.action.MAIN":
                    pending_action = True
            elif tag == "category" and current_component is not None:
                if str(attrs.get("name", "")) == "android.intent.category.LAUNCHER" and pending_action:
                    manifest.main_activity = current_component.name
                    pending_action = False
            elif tag in ("activity", "service", "receiver", "provider", "activity-alias"):
                component = Component(
                    tag=tag,
                    name=str(attrs.get("name", "") or ""),
                    exported=bool(attrs["exported"]) if "exported" in attrs else None,
                    permission=str(attrs.get("permission", "") or ""),
                )
                if component.name and len(manifest.components) < max_components:
                    manifest.components.append(component)
                if tag in ("activity", "activity-alias"):
                    current_component = component
            stack.append((tag, attrs))
            depth += 1
        elif ctype == RES_XML_END_ELEMENT_TYPE:
            if len(data) >= cursor + 24:
                name_idx = struct.unpack_from("<I", data, cursor + 20)[0]
                tag = strings[name_idx].lower() if name_idx < len(strings) else ""
                if tag in ("activity", "service", "receiver", "provider", "activity-alias"):
                    current_component = None
                    pending_action = False
                if tag == "manifest":
                    inside_manifest = False
            if stack:
                stack.pop()
            depth = max(0, depth - 1)
        cursor += csize

    if not manifest.package and not strings:
        raise AxmlError("axml.manifest.empty", "no package and no string pool found")
    manifest.permissions = list(dict.fromkeys(manifest.permissions))
    manifest.features = list(dict.fromkeys(manifest.features))
    return manifest


def _as_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return 0
    return 0


def _has_main_action(attrs: Dict[str, object]) -> bool:
    return False


def _parse_start_element(data: bytes, offset: int, header_size: int,
                         strings: List[str]) -> Tuple[str, Dict[str, object]]:
    body = offset + header_size  # attrExt starts after header + lineNumber + comment
    if body + 20 > len(data):
        return "", {}
    _ns, name_idx = struct.unpack_from("<II", data, body)
    (attr_start, attr_size, attr_count) = struct.unpack_from("<HHH", data, body + 8)
    name = strings[name_idx] if name_idx < len(strings) else ""
    attrs: Dict[str, object] = {}
    base = body + attr_start
    for i in range(attr_count):
        pos = base + i * attr_size
        if attr_size < 20 or pos + 20 > len(data):
            break
        _ans, aname, raw = struct.unpack_from("<III", data, pos)
        key = strings[aname] if aname < len(strings) else ""
        if not key:
            continue
        if raw != NO_INDEX and raw < len(strings):
            attrs[key] = strings[raw]
        else:
            attrs[key] = _typed_value(data, pos + 12, attr_size - 12, strings)
    return name, attrs
