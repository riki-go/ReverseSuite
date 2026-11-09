"""Multi-format static analysis pipeline (M8).

`analyze_bytes` is the single entry point used by the CLI and the HTTP API:

- PE keeps the original, byte-identical path through reversesuite.loader
- Mach-O / ELF / DEX go through the reversesuite.formats loaders
- .apk / .ipa are unpacked in memory and their members are analysed recursively

Nothing is executed; every input is treated as untrusted bytes.
"""
from __future__ import annotations

import hashlib
from typing import List, Optional, Sequence, Tuple

from . import functions as functions_mod
from . import loader, rules, schema, strings as strings_mod
from .formats import (FORMAT_APK, FORMAT_DEX, FORMAT_ELF, FORMAT_IPA, FORMAT_MACHO, FORMAT_PE,
                      FORMAT_UNKNOWN, BinaryImage, FormatError, detect, load)
from .formats import axml as axml_mod
from .formats import container as container_mod
from .formats import dex as dex_mod

MAX_MEMBER_ANALYSIS_BYTES = 64 * 1024 * 1024
MAX_DEX_STRINGS = 5000
MAX_SYMBOL_FINDINGS = 2000
MAX_MEMBER_FINDINGS = 20000

FUNCTION_RULE = {
    FORMAT_ELF: "elf.function.discover",
    FORMAT_MACHO: "macho.function.discover",
    FORMAT_PE: "pe.function.discover",
}


def analyze_bytes(data: bytes, filename: str = "", min_string_length: int = 4,
                  do_functions: bool = True, include_members: bool = True) -> schema.AnalysisResult:
    """Analyse one file of any supported format."""
    fmt = detect(data, filename)
    if fmt == FORMAT_PE:
        return loader.parse(data)
    if fmt in (FORMAT_APK, FORMAT_IPA):
        return _analyze_container(data, filename, fmt, min_string_length, do_functions,
                                  include_members)
    if fmt == FORMAT_UNKNOWN:
        return _unknown(data, filename)
    try:
        image = load(data, filename, fmt)
    except (FormatError, loader.LoadError) as exc:
        return _failed(data, fmt, getattr(exc, "code", "format.parse_error"),
                       getattr(exc, "message", str(exc)), getattr(exc, "offset", 0))
    if fmt == FORMAT_DEX:
        return _analyze_dex(data, image)
    return _analyze_image(data, image, min_string_length, do_functions)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unknown(data: bytes, filename: str) -> schema.AnalysisResult:
    return schema.AnalysisResult(
        target_sha256=_sha(data), target_kind="unknown", target_size=len(data), status="failed",
        findings=[],
        diagnostics=[schema.Diagnostic(
            "format.unknown",
            "input is not a recognised PE, Mach-O, ELF, DEX, APK or IPA file",
            "error", {"filename": filename, "head": data[:8].hex()})],
    )


def _failed(data: bytes, fmt: str, code: str, message: str, offset: int = 0) -> schema.AnalysisResult:
    return schema.AnalysisResult(
        target_sha256=_sha(data), target_kind=fmt, target_size=len(data), status="failed",
        findings=[],
        diagnostics=[schema.Diagnostic(code, message, "error", {"offset": offset})],
    )


def _analyze_image(data: bytes, image: BinaryImage, min_string_length: int,
                   do_functions: bool) -> schema.AnalysisResult:
    findings: List[schema.Finding] = []
    diags: List[schema.Diagnostic] = []
    status = "ok"

    header_rule = "%s.header.parse" % image.format
    findings.append(schema.Finding(
        kind="signature",
        value="format=%s;arch=%s;bits=%d" % (image.format, image.arch, image.bits),
        confidence_permille=1000, level="L0", rule=header_rule,
        evidence=[schema.Evidence(offset=0, space="file", rule=header_rule)],
    ))
    if image.entry is not None:
        findings.append(schema.Finding(
            kind="entry", value="0x%x" % image.entry, confidence_permille=1000, level="L0",
            rule="%s.header.parse" % image.format,
            evidence=[schema.Evidence(offset=image.entry, space="va", rule="%s.header.parse" % image.format)],
        ))

    section_rule = "%s.section.parse" % image.format
    for sec in image.sections:
        findings.append(schema.Finding(
            kind="section", value=sec.name, confidence_permille=1000, level="L0",
            rule=section_rule,
            evidence=[schema.Evidence(offset=sec.raw_ptr, space="file", rule=section_rule)],
        ))

    if image.imports:
        findings.append(schema.Finding(
            kind="import", value="count=%d" % len(image.imports), confidence_permille=1000,
            level="L0", rule="%s.symbol.parse" % image.format,
            evidence=[schema.Evidence(offset=0, space="file", rule="%s.symbol.parse" % image.format)],
        ))
    symbols = [(addr, name) for addr, name in image.symbols if addr][:MAX_SYMBOL_FINDINGS]
    for addr, name in symbols:
        findings.append(schema.Finding(
            kind="symbol", value=name, confidence_permille=900, level="L1",
            rule="%s.symbol.parse" % image.format,
            evidence=[schema.Evidence(offset=addr, space="va", rule="%s.symbol.parse" % image.format)],
        ))

    for code, message in image.diagnostics:
        status = "degraded"
        diags.append(schema.Diagnostic(code, message, "warn", {}))

    extracted = strings_mod.extract_from_image(image, data, min_string_length)
    findings.extend(strings_mod.to_findings(
        extracted[:MAX_MEMBER_FINDINGS], rule_ascii="string.ascii", rule_utf16="string.utf16le",
        rule_xref="string.ascii"))

    if do_functions and image.has_code():
        funcs = functions_mod.discover(
            image.code, base=image.code_va, exports=image.exports, entry=image.entry,
            max_bytes=functions_mod.MAX_FUNCTION_TEXT_BYTES, arch=image.arch)
        findings.extend(functions_mod.to_findings(funcs, rule=FUNCTION_RULE[image.format]))
        if not funcs:
            diags.append(schema.Diagnostic(
                "function.discovery.empty",
                "no functions matched the %s prologue/branch heuristics" % image.arch,
                "warn", {"code_bytes": len(image.code)}))

    return schema.AnalysisResult(
        target_sha256=_sha(data), target_kind=image.kind, target_size=len(data),
        status=status, findings=schema.enforce_rules(findings), diagnostics=diags,
    )


def _analyze_dex(data: bytes, image: BinaryImage) -> schema.AnalysisResult:
    inventory = dex_mod.parse(data)
    findings: List[schema.Finding] = []
    header_rule = "dex.header.parse"
    findings.append(schema.Finding(
        kind="signature",
        value="format=dex;version=%s;classes=%d;methods=%d" % (
            inventory.version, len(inventory.classes), len(inventory.methods)),
        confidence_permille=1000, level="L0", rule=header_rule,
        evidence=[schema.Evidence(offset=0, space="file", rule=header_rule)],
    ))
    for name in inventory.classes[:MAX_MEMBER_FINDINGS]:
        findings.append(schema.Finding(
            kind="class", value=name, confidence_permille=1000, level="L0",
            rule="dex.class.parse",
            evidence=[schema.Evidence(offset=0, space="file", rule="dex.class.parse")],
        ))
    for name in inventory.methods[:MAX_MEMBER_FINDINGS]:
        findings.append(schema.Finding(
            kind="method", value=name, confidence_permille=950, level="L0",
            rule="dex.method.parse",
            evidence=[schema.Evidence(offset=0, space="file", rule="dex.method.parse")],
        ))
    for offset, value in inventory.strings:
        if len(value) < strings_mod.MIN_LENGTH:
            continue
        findings.append(schema.Finding(
            kind="string", value=value, confidence_permille=1000, level="dex",
            rule="dex.string.table", encoding="mutf8",
            evidence=[schema.Evidence(offset=offset, space="file", rule="dex.string.table")],
        ))
        if len(findings) >= MAX_MEMBER_FINDINGS:
            break
    diags = [schema.Diagnostic("dex.bytecode.not_analyzed",
                               "Dalvik bytecode is inventoried (classes/methods/strings) but not disassembled",
                               "info", {"methods": len(inventory.methods)})]
    return schema.AnalysisResult(
        target_sha256=_sha(data), target_kind="dex", target_size=len(data), status="ok",
        findings=schema.enforce_rules(findings), diagnostics=diags,
    )


def _manifest_findings(manifest: "axml_mod.Manifest") -> List[schema.Finding]:
    """Turn a decoded AndroidManifest into schema findings (M8 follow-up)."""
    out: List[schema.Finding] = []
    rule = "apk.manifest.parse"

    def add(kind: str, value: str, rule_id: str, level: str = "L0", conf: int = 1000) -> None:
        out.append(schema.Finding(kind=kind, value=value, confidence_permille=conf, level=level,
                                  rule=rule_id,
                                  evidence=[schema.Evidence(offset=0, space="file", rule=rule_id)]))

    if manifest.package:
        add("package_name", manifest.package, rule)
    if manifest.version_name or manifest.version_code:
        add("package_version", "versionName=%s;versionCode=%d" % (manifest.version_name,
                                                                  manifest.version_code), rule)
    if manifest.min_sdk or manifest.target_sdk:
        add("min_sdk", "min=%d;target=%d" % (manifest.min_sdk, manifest.target_sdk), "apk.sdk")
    flags = []
    if manifest.debuggable:
        flags.append("debuggable=true")
    if manifest.allow_backup is not None:
        flags.append("allowBackup=%s" % str(manifest.allow_backup).lower())
    if manifest.uses_cleartext is not None:
        flags.append("usesCleartextTraffic=%s" % str(manifest.uses_cleartext).lower())
    if flags:
        add("manifest_flag", ";".join(flags), rule)
    for perm in manifest.permissions:
        add("permission", perm, "apk.permission")
    for component in manifest.components:
        state = "exported" if component.exported else ("internal" if component.exported is False else "unset")
        add("component", "%s:%s" % (component.tag, component.name), "apk.component",
            level="L1" if component.exported else "L0")
        add("component_flag", "%s:%s:%s" % (component.tag, component.name, state), "apk.component",
            conf=900)
    if manifest.main_activity:
        add("main_activity", manifest.main_activity, rule)
    return out


def _analyze_container(data: bytes, filename: str, fmt: str, min_string_length: int,
                       do_functions: bool, include_members: bool) -> schema.AnalysisResult:
    try:
        parts = container_mod.read_apk(data) if fmt == FORMAT_APK else container_mod.read_ipa(data)
    except container_mod.ContainerError as exc:
        return _failed(data, fmt, exc.code, exc.message)

    findings: List[schema.Finding] = []
    diags: List[schema.Diagnostic] = []
    status = "ok"
    package_rule = "package.container.parse"

    manifest_findings: List[schema.Finding] = []
    if fmt == FORMAT_APK and parts.manifest:
        try:
            manifest = axml_mod.parse(parts.manifest)
        except axml_mod.AxmlError as exc:
            diags.append(schema.Diagnostic("apk.manifest.unparsed", str(exc), "warn",
                                           {"code": exc.code}))
            manifest = None
        if manifest is not None:
            manifest_findings = _manifest_findings(manifest)
    if fmt == FORMAT_APK:
        members = [("dex", name, payload) for name, payload in parts.dex]
        members += [("so", "%s/%s" % (abi, name), payload) for abi, name, payload in parts.libs]
        meta = parts.as_dict()
        summary = "format=apk;package=%s;version=%s;dex=%d;libs=%d;manifest=%s" % (
            (manifest.package if fmt == FORMAT_APK and parts.manifest and "manifest" in dir() and manifest else ""),
            (manifest.version_name if fmt == FORMAT_APK and parts.manifest and "manifest" in dir() and manifest else ""),
            len(parts.dex), len(parts.libs), parts.has_manifest)
        if not parts.dex:
            diags.append(schema.Diagnostic("apk.dex.missing", "no classes*.dex in the archive",
                                           "warn", {}))
            status = "degraded"
    else:
        members = []
        if parts.binary:
            members.append(("macho", parts.binary_name, parts.binary))
        for framework in parts.frameworks:
            payload = container_mod.member_bytes(data, framework.rstrip("/") + "/" + framework.split("/")[-1].replace(".framework", ""))
            if payload:
                members.append(("macho", framework, payload))
        meta = parts.as_dict()
        summary = "format=ipa;app=%s;binary=%s;frameworks=%d" % (
            parts.app_dir, parts.binary_name, len(parts.frameworks))
        if not parts.binary:
            diags.append(schema.Diagnostic("ipa.binary.missing", "no Mach-O binary under Payload/*.app",
                                           "warn", {}))
            status = "degraded"

    findings.append(schema.Finding(
        kind="package", value=summary, confidence_permille=1000, level="L0", rule=package_rule,
        evidence=[schema.Evidence(offset=0, space="file", rule=package_rule)]))
    findings.append(schema.Finding(
        kind="package_meta", value=str(sorted(meta.items()))[:512], confidence_permille=1000,
        level="L0", rule=package_rule,
        evidence=[schema.Evidence(offset=0, space="file", rule=package_rule)]))
    findings.extend(manifest_findings)

    if not include_members:
        return schema.AnalysisResult(
            target_sha256=_sha(data), target_kind=fmt, target_size=len(data), status=status,
            findings=schema.enforce_rules(findings), diagnostics=diags)

    for kind, name, payload in members:
        if len(payload) > MAX_MEMBER_ANALYSIS_BYTES:
            diags.append(schema.Diagnostic("package.member.too_large",
                                           "member skipped: larger than the analysis cap",
                                           "info", {"member": name, "bytes": len(payload)}))
            if status == "ok":
                status = "degraded"
            continue
        result = analyze_bytes(payload, filename=name, min_string_length=min_string_length,
                              do_functions=do_functions, include_members=False)
        findings.append(schema.Finding(
            kind="member", value="%s:%s" % (kind, name),
            confidence_permille=1000, level="L0", rule="package.member.parse",
            evidence=[schema.Evidence(offset=0, space="file", rule="package.member.parse")]))
        if result.status == "failed":
            diags.append(schema.Diagnostic("package.member.failed",
                                           "member could not be parsed: %s" % name,
                                           "warn", {"member": name,
                                                    "code": result.diagnostics[0].code if result.diagnostics else ""}))
            status = "degraded"
            continue
        for finding in result.findings:
            findings.append(finding)
        for diag in result.diagnostics:
            diags.append(schema.Diagnostic(diag.code, "[%s] %s" % (name, diag.message),
                                           diag.severity, diag.params))
        if result.status != "ok" and status == "ok":
            status = result.status

    return schema.AnalysisResult(
        target_sha256=_sha(data), target_kind=fmt, target_size=len(data), status=status,
        findings=schema.enforce_rules(findings), diagnostics=diags)
