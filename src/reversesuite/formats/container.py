"""ZIP container handling for .apk and .ipa (stdlib zipfile)."""
from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

MAX_MEMBERS = 20000
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024


class ContainerError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def is_zip(data: bytes) -> bool:
    return len(data) >= 4 and data[:2] == b"PK" and data[2:4] in (b"\x03\x04", b"\x05\x06", b"\x07\x08")


@dataclass
class ApkParts:
    dex: List[Tuple[str, bytes]] = field(default_factory=list)
    libs: List[Tuple[str, str, bytes]] = field(default_factory=list)  # (abi, name, bytes)
    has_manifest: bool = False
    manifest: bytes = b""
    resources: int = 0
    skipped: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"dex": [name for name, _b in self.dex],
                "libs": [f"{abi}/{name}" for abi, name, _b in self.libs],
                "has_manifest": self.has_manifest, "resources": self.resources,
                "skipped": self.skipped[:20]}


@dataclass
class IpaParts:
    app_dir: str = ""
    binary_name: str = ""
    binary: bytes = b""
    frameworks: List[str] = field(default_factory=list)
    has_info_plist: bool = False
    skipped: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"app_dir": self.app_dir, "binary_name": self.binary_name,
                "binary_bytes": len(self.binary), "frameworks": self.frameworks[:20],
                "has_info_plist": self.has_info_plist, "skipped": self.skipped[:20]}


def _open(data: bytes) -> zipfile.ZipFile:
    try:
        return zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise ContainerError("zip.invalid", f"invalid zip container: {exc}") from exc


def names(data: bytes) -> List[str]:
    with _open(data) as archive:
        return [info.filename for info in archive.infolist()]


def detect_kind(data: bytes, filename: str = "") -> str:
    """Return 'apk', 'ipa' or 'zip' using member names first, extension second."""
    try:
        members = names(data)
    except ContainerError:
        return "unknown"
    lowered = [m.lower() for m in members]
    if any(m.startswith("payload/") and ".app/" in m for m in lowered):
        return "ipa"
    if "androidmanifest.xml" in lowered or any(m.startswith("classes") and m.endswith(".dex") for m in lowered):
        return "apk"
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if suffix in ("apk", "ipa"):
        return suffix
    return "zip"


def _read(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> Optional[bytes]:
    if info.file_size > MAX_MEMBER_BYTES:
        return None
    with archive.open(info) as handle:
        return handle.read(MAX_MEMBER_BYTES + 1)[:MAX_MEMBER_BYTES]


def read_apk(data: bytes) -> ApkParts:
    parts = ApkParts()
    total = 0
    with _open(data) as archive:
        infos = [i for i in archive.infolist() if not i.is_dir()][:MAX_MEMBERS]
        for info in infos:
            name = info.filename
            lower = name.lower()
            payload = None
            if lower.startswith("classes") and lower.endswith(".dex"):
                payload = _read(archive, info)
                if payload:
                    parts.dex.append((name, payload))
            elif lower.startswith("lib/") and lower.endswith(".so"):
                segments = name.split("/")
                if len(segments) >= 3:
                    payload = _read(archive, info)
                    if payload:
                        parts.libs.append((segments[1], segments[-1], payload))
            elif lower == "androidmanifest.xml":
                parts.has_manifest = True
                payload = _read(archive, info)
                if payload:
                    parts.manifest = payload
            elif lower.startswith("res/"):
                parts.resources += 1
            if payload:
                total += len(payload)
                if total > MAX_TOTAL_BYTES:
                    parts.skipped.append("total_size_cap")
                    break
    parts.dex.sort(key=lambda item: item[0])
    parts.libs.sort(key=lambda item: (item[0], item[1]))
    return parts


def read_ipa(data: bytes) -> IpaParts:
    parts = IpaParts()
    entries: List[Tuple[zipfile.ZipInfo, str]] = []
    with _open(data) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = info.filename
            lower = name.lower()
            if "payload/" not in lower or ".app/" not in lower:
                continue
            if "/frameworks/" in lower:
                if lower.endswith(".framework/"):
                    parts.frameworks.append(name)
                continue
            if lower.endswith(".app/info.plist"):
                parts.has_info_plist = True
                continue
            entries.append((info, name))
        if not entries:
            return parts
        # App binary = Payload/<App>.app/<App> (depth 2 under Payload)
        app_dirs: Dict[str, str] = {}
        for _info, name in entries:
            parts_of = name.split("/")
            if len(parts_of) >= 3 and parts_of[0].lower() == "payload":
                app_dirs[parts_of[0] + "/" + parts_of[1]] = parts_of[1]
        chosen = None
        for info, name in entries:
            segments = name.split("/")
            if len(segments) != 3:
                continue
            bundle = segments[1]
            stem = bundle[:-4] if bundle.lower().endswith(".app") else bundle
            if segments[2].lower() == stem.lower():
                chosen = (info, name)
                break
        if chosen is None:
            # Fall back to the biggest non-nested file: usually the main binary.
            chosen = max(entries, key=lambda item: item[0].file_size)
        info, name = chosen
        payload = _read(archive, info)
        if payload:
            parts.binary = payload
            parts.binary_name = name
            parts.app_dir = "/".join(name.split("/")[:2])
        if not app_dirs:
            parts.skipped.append("no_payload_app")
    return parts


def member_bytes(data: bytes, target: str) -> Optional[bytes]:
    with _open(data) as archive:
        for info in archive.infolist():
            if info.filename == target and not info.is_dir():
                return _read(archive, info)
    return None
