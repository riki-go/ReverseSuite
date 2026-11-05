"""Rule registry: every finding must cite a registered rule id."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable


@dataclass(frozen=True)
class Rule:
    id: str
    description: str
    version: int = 1


_RULES: Dict[str, Rule] = {}


def register(rule: Rule) -> Rule:
    if rule.id in _RULES:
        raise ValueError(f"rule already registered: {rule.id}")
    _RULES[rule.id] = rule
    return rule


def get(rule_id: str) -> Rule:
    return _RULES[rule_id]


def all_rules() -> Iterable[Rule]:
    return tuple(_RULES.values())


def is_registered(rule_id: str) -> bool:
    return rule_id in _RULES


# --- built-in rules (M1a: loader/schema level) ---
register(Rule("pe.header.parse", "parse DOS header and e_lfanew"))
register(Rule("pe.coff.parse", "parse COFF file header"))
register(Rule("pe.opt.parse", "parse optional header"))
register(Rule("pe.section.parse", "parse section table entries"))
register(Rule("pe.import.parse", "parse import directory"))
register(Rule("pe.export.parse", "parse export directory"))
register(Rule("pe.strings.scan", "extract printable strings"))
register(Rule("pe.packer.upx", "detect UPX packing signature"))
register(Rule("pe.corrupt.diagnose", "report structural damage"))
