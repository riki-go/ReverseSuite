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
_DISABLED: set = set()


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


def disable(rule_id: str) -> None:
    if rule_id not in _RULES:
        raise KeyError(f"unknown rule: {rule_id}")
    _DISABLED.add(rule_id)


def enable(rule_id: str) -> None:
    _DISABLED.discard(rule_id)


def is_enabled(rule_id: str) -> bool:
    return rule_id in _RULES and rule_id not in _DISABLED


def enabled_rules() -> Iterable[Rule]:
    return tuple(r for r in _RULES.values() if r.id not in _DISABLED)


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

# --- M1b: analysis layers ---
register(Rule("pe.function.discover", "function bounds from CFG-lite recursive descent"))
register(Rule("pe.string.ascii", "printable ASCII string"))
register(Rule("pe.string.utf16le", "UTF-16LE string"))
register(Rule("pe.string.xref", "code reference to a string"))
register(Rule("pe.callgraph.edge", "resolved caller -> callee edge"))

# --- M8: multi-format loaders (PE / Mach-O / ELF / DEX / packages) ---
register(Rule("elf.header.parse", "parse ELF header"))
register(Rule("elf.section.parse", "parse ELF section table"))
register(Rule("elf.symbol.parse", "read ELF symbol tables"))
register(Rule("elf.function.discover", "function bounds from ARM/x86 prologues and branch targets"))
register(Rule("macho.header.parse", "parse Mach-O header and load commands"))
register(Rule("macho.section.parse", "parse Mach-O segments and sections"))
register(Rule("macho.symbol.parse", "read Mach-O LC_SYMTAB symbols"))
register(Rule("macho.function.discover", "function bounds from ARM64 prologues and bl targets"))
register(Rule("dex.header.parse", "parse DEX header"))
register(Rule("dex.string.table", "read DEX string ids"))
register(Rule("dex.class.parse", "read DEX class definitions"))
register(Rule("dex.method.parse", "read DEX method ids"))
register(Rule("package.container.parse", "parse ZIP-based app containers (.apk/.ipa)"))
register(Rule("package.member.parse", "read a member file inside an app container"))
register(Rule("apk.manifest.parse", "decode binary AndroidManifest.xml (AXML)"))
register(Rule("apk.permission", "declared Android permission"))
register(Rule("apk.component", "declared Android component with its exported state"))
register(Rule("apk.sdk", "declared min/target SDK levels"))
register(Rule("string.ascii", "printable ASCII string (format independent)"))
register(Rule("string.utf16le", "UTF-16LE string (format independent)"))
register(Rule("format.unknown", "report an unrecognised input format"))
