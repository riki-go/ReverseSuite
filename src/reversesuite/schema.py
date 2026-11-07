"""Canonical result schema (see PLAN section 4).

Rules encoded here:
- confidence is an integer permille (0..1000), never a float
- finding ids are deterministic: sha256(kind + value + primary evidence)
- arrays are sorted with explicit keys before hashing
- canonical JSON uses json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)
- volatile data (time, host) never enters the hashed document
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from . import rules
from .version import SCHEMA_VERSION

OFFSET_SPACES = ("file", "rva", "va")
SEVERITIES = ("info", "warn", "error")
STATUSES = ("ok", "degraded", "failed")


@dataclass(frozen=True)
class Evidence:
    offset: int
    space: str = "file"
    xref: Optional[int] = None
    rule: str = ""

    def __post_init__(self) -> None:
        if self.space not in OFFSET_SPACES:
            raise ValueError(f"bad offset space: {self.space}")
        if self.offset < 0:
            raise ValueError("offset must be >= 0")

    def canonical(self) -> Dict[str, Any]:
        return {"offset": self.offset, "space": self.space, "xref": self.xref, "rule": self.rule}


@dataclass(frozen=True)
class Finding:
    kind: str
    value: str
    confidence_permille: int
    level: str
    rule: str
    calibrated: bool = False
    encoding: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not 0 <= self.confidence_permille <= 1000:
            raise ValueError("confidence_permille must be within 0..1000")
        if not self.rule:
            raise ValueError("every finding must cite a rule id")
        if not rules.is_registered(self.rule):
            raise ValueError(f"unregistered rule: {self.rule}")

    @property
    def id(self) -> str:
        primary = self.evidence[0].canonical() if self.evidence else None
        payload = json.dumps(
            {"kind": self.kind, "value": self.value, "evidence": primary},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def canonical(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "id": self.id,
            "kind": self.kind,
            "value": self.value,
            "confidence_permille": self.confidence_permille,
            "calibrated": self.calibrated,
            "level": self.level,
            "rule": self.rule,
            "evidence": [e.canonical() for e in sorted(
                self.evidence, key=lambda e: (e.space, e.offset, e.rule)
            )],
        }
        if self.encoding:
            out["encoding"] = self.encoding
        return out


@dataclass(frozen=True)
class Diagnostic:
    code: str
    message: str
    severity: str = "error"
    params: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"bad severity: {self.severity}")

    def canonical(self) -> Dict[str, Any]:
        return {"code": self.code, "message": self.message, "severity": self.severity, "params": self.params}


def enforce_rules(findings: List[Finding]) -> List[Finding]:
    """AC-14: every finding cites a registered rule; disabled rules disappear."""
    kept: List[Finding] = []
    for item in findings:
        if not rules.is_registered(item.rule):
            raise ValueError(f"unregistered rule: {item.rule}")
        if not rules.is_enabled(item.rule):
            continue
        kept.append(item)
    return kept


@dataclass
class AnalysisResult:
    target_sha256: str
    target_kind: str
    target_size: int
    status: str
    findings: List[Finding] = field(default_factory=list)
    diagnostics: List[Diagnostic] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.status not in STATUSES:
            raise ValueError(f"bad status: {self.status}")

    def canonical(self) -> Dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "target": {
                "sha256": self.target_sha256,
                "kind": self.target_kind,
                "size": self.target_size,
            },
            "status": self.status,
            "findings": [f.canonical() for f in sorted(
                self.findings, key=lambda f: (f.kind, f.level, f.value, f.id)
            )],
            "diagnostics": [d.canonical() for d in sorted(
                self.diagnostics, key=lambda d: (d.code, d.message)
            )],
        }

    def to_canonical_json(self) -> str:
        return json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def canonical_hash(self) -> str:
        return hashlib.sha256(self.to_canonical_json().encode("utf-8")).hexdigest()
