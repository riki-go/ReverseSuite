"""CLI: analyze a PE file and print canonical JSON (stdout only)."""
from __future__ import annotations

import argparse
import sys

import json
import os

import hashlib
import shutil

from . import functions as functions_mod
from . import strings as strings_mod
from . import cache as cache_mod, disasm, loader, schema

EXIT_OK, EXIT_DEGRADED, EXIT_FAILED, EXIT_USAGE, EXIT_INTERNAL = 0, 2, 3, 4, 5


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="reversesuite", add_help=True)
    sub = parser.add_subparsers(dest="cmd")
    analyze = sub.add_parser("analyze", help="analyze one PE file")
    analyze.add_argument("path")
    analyze.add_argument("--json", action="store_true", help="emit canonical JSON on stdout")
    analyze.add_argument("--workers", type=int, default=6, help="worker processes for the xref pass")
    analyze.add_argument("--no-xref", action="store_true", help="skip string xref resolution")
    analyze.add_argument("--min-string-length", type=int, default=strings_mod.MIN_LENGTH)
    analyze.add_argument("--disasm-out", default="", help="also stream disassembly to this JSONL path")
    dis = sub.add_parser("disasm", help="stream disassembly to JSONL")
    dis.add_argument("path")
    dis.add_argument("--out", required=True)
    dis.add_argument("--gzip", action="store_true")
    dis.add_argument("--slim", action="store_true", help="write only address+mnemonic")
    dis.add_argument("--limit-bytes", type=int, default=0, help="disassemble only the first N bytes of .text")
    dis.add_argument("--workers", type=int, default=1, help="parallel worker processes")
    dis.add_argument("--cache-dir", default="", help="enable artifact cache in this directory")
    st = sub.add_parser("strings", help="extract ASCII/UTF-16LE strings with addresses")
    st.add_argument("path")
    st.add_argument("--json", action="store_true", help="emit JSON array on stdout")
    st.add_argument("--min-length", type=int, default=strings_mod.MIN_LENGTH)
    st.add_argument("--workers", type=int, default=6, help="worker processes for the xref pass")
    st.add_argument("--no-xref", action="store_true", help="skip string xref resolution")
    fn = sub.add_parser("functions", help="discover function starts heuristically")
    fn.add_argument("path")
    fn.add_argument("--json", action="store_true", help="emit JSON array on stdout")
    fn.add_argument("--limit-bytes", type=int, default=0)
    fn.add_argument("--max-functions", type=int, default=200000)
    args = parser.parse_args(argv)

    if args.cmd == "strings":
        try:
            with open(args.path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            print(f"cannot read input: {exc}", file=sys.stderr)
            return EXIT_USAGE
        try:
            items = strings_mod.extract(data, args.min_length)
            text = loader.text_bytes(data)
        except Exception as exc:
            print(f"cannot scan strings: {exc}", file=sys.stderr)
            return EXIT_FAILED
        reason = None if args.no_xref else strings_mod.xref_skip_reason(len(text))
        if not args.no_xref and reason is None:
            xrefs = strings_mod.find_xrefs(text, items, workers=args.workers)
            items = [strings_mod.ExtractedString(s.address, s.value, s.encoding, s.section, s.length,
                                                 xrefs.get(s.address, ())) for s in items]
        payload = {
            "count": len(items),
            "ascii": sum(1 for s in items if s.encoding == "ascii"),
            "utf16le": sum(1 for s in items if s.encoding == "utf16le"),
            "with_xref": sum(1 for s in items if s.xrefs),
            "xref_skipped": reason,
            "strings": [{"address": s.address, "encoding": s.encoding, "section": s.section,
                         "length": s.length, "value": s.value, "xrefs": list(s.xrefs)} for s in items],
        }
        if args.json:
            sys.stdout.write(json.dumps(payload) + chr(10))
        else:
            print("strings: %d (ascii=%d utf16le=%d) xref=%d%s" % (
                payload["count"], payload["ascii"], payload["utf16le"], payload["with_xref"],
                " skipped=" + reason if reason else ""))
            for item in items[:10]:
                print("  0x%x %-7s %-8s %r" % (item.address, item.encoding, item.section, item.value[:40]))
        return EXIT_OK
    if args.cmd == "functions":
        try:
            with open(args.path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            print(f"cannot read input: {exc}", file=sys.stderr)
            return EXIT_USAGE
        try:
            text = loader.text_bytes(data)
            exports = loader.export_addresses(data)
        except Exception as exc:
            print(f"cannot locate sections: {exc}", file=sys.stderr)
            return EXIT_FAILED
        if args.limit_bytes:
            text = text[: args.limit_bytes]
        found = functions_mod.discover(text, exports=exports)
        found = found[: args.max_functions]
        payload = {"count": len(found), "functions": [f.as_dict() for f in found]}
        if args.json:
            sys.stdout.write(json.dumps(payload) + chr(10))
        else:
            print(f"functions: {len(found)}")
            for item in found[:10]:
                srcs = ",".join(item.sources)
                print("  0x%x size=%d sources=%s conf=%d" % (item.start, item.size, srcs, item.confidence_permille))
        return EXIT_OK

    if args.cmd == "disasm":
        if not args.path or not args.out:
            print("disasm requires path and --out", file=sys.stderr)
            return EXIT_USAGE
        try:
            with open(args.path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            print(f"cannot read input: {exc}", file=sys.stderr)
            return EXIT_USAGE
        try:
            text = loader.text_bytes(data)
        except Exception as exc:
            print(f"cannot locate .text: {exc}", file=sys.stderr)
            return EXIT_FAILED
        if args.limit_bytes:
            text = text[: args.limit_bytes]
        if args.limit_bytes:
            key_bytes = text
        else:
            key_bytes = text
        file_sha = hashlib.sha256(data).hexdigest()
        cache = cache_mod.Cache(__import__("pathlib").Path(args.cache_dir)) if args.cache_dir else None
        key = cache_mod.make_key(file_sha, mode="disasm", slim=args.slim, gzip=args.gzip,
                                 limit=args.limit_bytes) if cache else ""
        if cache is not None:
            hit = cache.get(key)
            if hit is not None:
                shutil.copyfile(hit, args.out)
                sys.stdout.write(json.dumps({"cached": True, "out": args.out,
                                             "file_bytes": os.path.getsize(args.out)}) + chr(10))
                return EXIT_OK
        try:
            summary = disasm.write_stream(text, __import__("pathlib").Path(args.out), args.gzip, args.slim, workers=args.workers)
        except Exception as exc:
            print(f"internal error: {exc.__class__.__name__}", file=sys.stderr)
            return EXIT_INTERNAL
        summary["cached"] = False
        if cache is not None:
            cache.put(key, __import__("pathlib").Path(args.out), {"mode": "disasm", "slim": args.slim})
        sys.stdout.write(json.dumps(summary) + chr(10))
        return EXIT_OK

    if args.cmd != "analyze":
        parser.print_help(sys.stderr)
        return EXIT_USAGE

    try:
        with open(args.path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print(f"cannot read input: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        result = loader.parse(data)
    except Exception as exc:  # never leak tracebacks to the user
        print(f"internal error: {exc.__class__.__name__}", file=sys.stderr)
        return EXIT_INTERNAL

    extra: dict = {"functions": 0, "strings": 0, "ascii": 0, "utf16le": 0, "with_xref": 0,
                   "xref_skipped": None}
    if result.status != "failed":
        try:
            text = loader.text_bytes(data)
            exports = loader.export_addresses(data)
            fn_reason = functions_mod.skip_reason(len(text))
            if fn_reason is None:
                found = functions_mod.discover(text, exports=exports, entry=functions_mod.entry_point(data))
            else:
                found = []
                result.diagnostics.append(schema.Diagnostic(
                    functions_mod.FUNCTION_SKIP_TEXT_TOO_LARGE, "function discovery skipped", "info",
                    {"text_bytes": len(text), "cap": functions_mod.MAX_FUNCTION_TEXT_BYTES}))
            items = strings_mod.extract(data, args.min_string_length)
            reason = strings_mod.xref_skip_reason(len(text)) or ("disabled" if args.no_xref else None)
            if reason is None:
                xrefs = strings_mod.find_xrefs(text, items, workers=args.workers)
                items = [strings_mod.ExtractedString(s.address, s.value, s.encoding, s.section, s.length,
                                                     xrefs.get(s.address, ())) for s in items]
            else:
                result.diagnostics.append(schema.Diagnostic(
                    strings_mod.XREF_SKIP_TEXT_TOO_LARGE, "xref pass skipped", "info",
                    {"text_bytes": len(text), "cap": strings_mod.MAX_XREF_TEXT_BYTES,
                     "reason": reason}))
            result.findings.extend(schema.enforce_rules(
                functions_mod.to_findings(found) + strings_mod.to_findings(items)))
            extra = {"functions": len(found), "strings": len(items),
                     "ascii": sum(1 for s in items if s.encoding == "ascii"),
                     "utf16le": sum(1 for s in items if s.encoding == "utf16le"),
                     "with_xref": sum(1 for s in items if s.xrefs),
                     "xref_skipped": reason}
        except Exception as exc:
            result.status = "degraded"
            result.diagnostics.append(schema.Diagnostic(
                "analysis.partial", f"functions/strings pass failed: {exc.__class__.__name__}", "warn", {}))
        if args.disasm_out:
            try:
                summary = disasm.write_stream(text, __import__("pathlib").Path(args.disasm_out),
                                              False, False, workers=args.workers)
                extra["disasm"] = summary
            except Exception as exc:
                result.diagnostics.append(schema.Diagnostic(
                    "analysis.disasm_failed", f"disassembly failed: {exc.__class__.__name__}", "warn", {}))

    if args.json:
        sys.stdout.write(result.to_canonical_json())
        sys.stdout.write(chr(10))
    else:
        print("target  %s  %d bytes" % (result.target_sha256[:16], result.target_size))
        print("status  %s" % result.status)
        print("findings %d  diagnostics %d" % (len(result.findings), len(result.diagnostics)))
        print("functions %d" % extra["functions"])
        print("strings  %d (ascii=%d utf16le=%d) xref=%d%s" % (
            extra["strings"], extra["ascii"], extra["utf16le"], extra["with_xref"],
            " skipped=" + extra["xref_skipped"] if extra["xref_skipped"] else ""))
        for diag in result.diagnostics:
            print("diag    %s: %s" % (diag.code, diag.message))

    return {"ok": EXIT_OK, "degraded": EXIT_DEGRADED, "failed": EXIT_FAILED}[result.status]


if __name__ == "__main__":
    raise SystemExit(main())
