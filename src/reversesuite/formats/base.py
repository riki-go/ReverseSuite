"""Format-independent binary image model (M8 Phase 1).

Every loader normalises addresses into the analysis address space used by
disasm/functions/strings: the primary code section starts at 0x1000, so
`addr = 0x1000 + (raw_va - code_va)`. PE keeps its historical convention,
which is exactly this rule with `code_va = .text` virtual address.

The model is deliberately small and stdlib-only: no external parser is required
at runtime, so the desktop sidecar stays self-contained.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

BASE_ADDRESS = 0x1000

FORMAT_PE = "pe"
FORMAT_MACHO = "macho"
FORMAT_ELF = "elf"
FORMAT_DEX = "dex"
FORMAT_APK = "apk"
FORMAT_IPA = "ipa"
FORMAT_UNKNOWN = "unknown"

# arch -> (capstone arch name, bits)
ARCH_INFO = {
    "x86": ("x86", 32),
    "x64": ("x86", 64),
    "arm": ("arm", 32),
    "arm64": ("arm64", 64),
    "dalvik": ("", 0),
    "unknown": ("", 0),
}


class FormatError(Exception):
    """Raised when a file claims a format but cannot be parsed."""

    def __init__(self, code: str, message: str, offset: int = 0) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.offset = offset


@dataclass(frozen=True)
class SectionInfo:
    index: int
    name: str
    va: int          # normalised analysis address
    vsize: int
    raw_ptr: int
    raw_size: int
    executable: bool = False

    def contains(self, addr: int) -> bool:
        return self.va <= addr < self.va + max(self.vsize, self.raw_size)


@dataclass
class BinaryImage:
    format: str
    arch: str
    bits: int
    entry: Optional[int]
    code: bytes
    code_va: int
    sections: List[SectionInfo] = field(default_factory=list)
    exports: List[int] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    symbols: List[Tuple[int, str]] = field(default_factory=list)
    metadata: Dict[str, object] = field(default_factory=dict)
    diagnostics: List[Tuple[str, str]] = field(default_factory=list)
    target_kind: str = ""

    @property
    def kind(self) -> str:
        return self.target_kind or self.format

    def has_code(self) -> bool:
        return bool(self.code) and self.arch in ("x86", "x64", "arm", "arm64")

    def section_at(self, addr: int) -> Optional[SectionInfo]:
        for sec in self.sections:
            if sec.contains(addr):
                return sec
        return None

    def as_summary(self) -> dict:
        return {
            "format": self.format,
            "arch": self.arch,
            "bits": self.bits,
            "entry": self.entry,
            "code_bytes": len(self.code),
            "sections": len(self.sections),
            "exports": len(self.exports),
            "imports": len(self.imports),
            "metadata": self.metadata,
        }


def build_image(format: str, arch: str, bits: int, sections: List[SectionInfo],
                entry: Optional[int], code: bytes, code_va: int,
                exports: Optional[List[int]] = None, imports: Optional[List[str]] = None,
                symbols: Optional[List[Tuple[int, str]]] = None,
                metadata: Optional[Dict[str, object]] = None,
                diagnostics: Optional[List[Tuple[str, str]]] = None,
                target_kind: str = "") -> BinaryImage:
    """Normalise raw sections into the 0x1000-based analysis address space."""
    shift = code_va - BASE_ADDRESS if code else 0
    norm_sections = [
        SectionInfo(s.index, s.name, s.va - shift, s.vsize, s.raw_ptr, s.raw_size, s.executable)
        for s in sections
    ]
    norm_entry = None
    if entry is not None and code:
        norm_entry = entry - shift
        if not (BASE_ADDRESS <= norm_entry < BASE_ADDRESS + len(code)):
            norm_entry = None
    norm_exports = []
    for addr in exports or []:
        value = addr - shift if code else addr
        if code and not (BASE_ADDRESS <= value < BASE_ADDRESS + len(code)):
            continue
        norm_exports.append(value)
    norm_symbols = []
    for addr, name in symbols or []:
        value = addr - shift if code else addr
        if code and not (BASE_ADDRESS <= value < BASE_ADDRESS + len(code)):
            continue
        norm_symbols.append((value, name))
    return BinaryImage(
        format=format, arch=arch, bits=bits, entry=norm_entry,
        code=code, code_va=BASE_ADDRESS,
        sections=norm_sections, exports=norm_exports, imports=list(imports or []),
        symbols=norm_symbols, metadata=dict(metadata or {}),
        diagnostics=list(diagnostics or []), target_kind=target_kind,
    )


def pick_code_section(sections: List[SectionInfo], preferred: Tuple[str, ...],
                      exclude_prefix: str = "") -> Optional[SectionInfo]:
    """Preferred name first, else the largest executable section."""
    for name in preferred:
        for sec in sections:
            if sec.name == name and sec.raw_size:
                return sec
    best = None
    for sec in sections:
        if not sec.executable or not sec.raw_size:
            continue
        if exclude_prefix and sec.name.startswith(exclude_prefix):
            continue
        if best is None or sec.raw_size > best.raw_size:
            best = sec
    return best


class BinaryLoader(ABC):
    """Abstract loader contract (M8 Phase 1).

    Concrete loaders parse one container format and return a normalised
    :class:`BinaryImage`. They never execute the input and never write to disk.
    """

    format = FORMAT_UNKNOWN
    target_kind = FORMAT_UNKNOWN

    @abstractmethod
    def parse(self, data: bytes) -> "BinaryImage":
        """Parse `data` into a BinaryImage; raise FormatError on bad input."""

    def load(self, data: bytes) -> "BinaryImage":
        return self.parse(data)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<%s format=%s>" % (self.__class__.__name__, self.format)
