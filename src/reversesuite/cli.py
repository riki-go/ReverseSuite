"""CLI: analyze a PE file and print canonical JSON (stdout only)."""
from __future__ import annotations

import argparse
import sys

import json
import os

import hashlib
import shutil

from . import functions as functions_mod
from . import callgraph as callgraph_mod
from . import diff as diff_mod
from . import report as report_mod
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
    rp = sub.add_parser("report", help="render a diff report as Markdown or HTML")
    rp.add_argument("left")
    rp.add_argument("right")
    rp.add_argument("--format", choices=("md", "html"), default="md")
    rp.add_argument("--out", default="", help="write to this path instead of stdout")
    rp.add_argument("--ignore-thunks", action="store_true")
    df = sub.add_parser("diff", help="diff two call graphs (JSON docs or PE files)")
    df.add_argument("left")
    df.add_argument("right")
    df.add_argument("--json", action="store_true", help="emit JSON on stdout")
    df.add_argument("--ignore-thunks", action="store_true", help="drop thunk edges before diffing")
    cg = sub.add_parser("calls", help="build the call graph (direct/tail/thunk edges)")
    cg.add_argument("path")
    cg.add_argument("--json", action="store_true", help="emit JSON on stdout")
    fn = sub.add_parser("functions", help="discover function starts heuristically")
    fn.add_argument("path")
    fn.add_argument("--json", action="store_true", help="emit JSON array on stdout")
    fn.add_argument("--limit-bytes", type=int, default=0)
    fn.add_argument("--max-functions", type=int, default=200000)
    args = parser.parse_args(argv)

    if args.cmd == "report":
        def load_doc(path):
            if path.lower().endswith(".json"):
                with open(path, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            with open(path, "rb") as fh:
                return callgraph_mod.build(fh.read()).as_dict()

        try:
            left = load_doc(args.left)
            right = load_doc(args.right)
        except Exception as exc:
            print(f"cannot load inputs: {exc}", file=sys.stderr)
            return EXIT_USAGE
        result = diff_mod.diff_graphs(left, right, ignore_thunks=args.ignore_thunks)
        document = report_mod.render(result, args.left, args.right, args.format)
        if args.out:
            try:
                with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(document)
            except OSError as exc:
                print(f"cannot write report: {exc}", file=sys.stderr)
                return EXIT_USAGE
            sys.stdout.write(json.dumps({"out": args.out, "format": args.format,
                                         "bytes": len(document.encode("utf-8"))}) + chr(10))
        else:
            sys.stdout.write(document)
        return EXIT_OK
    if args.cmd == "diff":
        def load_doc(path):
            if path.lower().endswith(".json"):
                with open(path, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            with open(path, "rb") as fh:
                return callgraph_mod.build(fh.read()).as_dict()

        try:
            left = load_doc(args.left)
            right = load_doc(args.right)
        except Exception as exc:
            print(f"cannot load inputs: {exc}", file=sys.stderr)
            return EXIT_USAGE
        result = diff_mod.diff_graphs(left, right, ignore_thunks=args.ignore_thunks)
        if args.json:
            sys.stdout.write(json.dumps(result.as_dict()) + chr(10))
        else:
            s = result.summary()
            print("nodes  +%d -%d ~%d(moved) ~%d(similar)" % (
                s["nodes"]["added"], s["nodes"]["removed"], s["nodes"]["moved"], s["nodes"]["similar"]))
            print("edges  +%d -%d =%d" % (s["edges"]["added"], s["edges"]["removed"], s["edges"]["unchanged"]))
            for node in result.added_nodes[:5]:
                print("  + node 0x%x size=%d" % (node.address, node.size))
            for node in result.removed_nodes[:5]:
                print("  - node 0x%x size=%d" % (node.address, node.size))
            for node, to in result.moved_nodes[:5]:
                print("  ~ node 0x%x -> 0x%x" % (node.address, to))
            for edge in result.added_edges[:5]:
                print("  + edge 0x%x -> 0x%x %s" % (edge.caller, edge.callee or 0, edge.kind))
            for edge in result.removed_edges[:5]:
                print("  - edge 0x%x -> 0x%x %s" % (edge.caller, edge.callee or 0, edge.kind))
        return EXIT_OK
    if args.cmd == "calls":
        try:
            with open(args.path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            print(f"cannot read input: {exc}", file=sys.stderr)
            return EXIT_USAGE
        try:
            graph = callgraph_mod.build(data)
        except Exception as exc:
            print(f"cannot build call graph: {exc}", file=sys.stderr)
            return EXIT_FAILED
        if graph.skipped:
            print(f"call graph skipped: {graph.skipped}", file=sys.stderr)
            return EXIT_DEGRADED
        if args.json:
            sys.stdout.write(json.dumps(graph.as_dict()) + chr(10))
        else:
            kinds = {}
            for edge in graph.edges:
                kinds[edge.kind] = kinds.get(edge.kind, 0) + 1
            print("nodes %d edges %d (%s) indirect %d imports %d unresolved %d" % (
                len(graph.nodes), len(graph.edges),
                ", ".join("%s=%d" % (k, v) for k, v in sorted(kinds.items())) or "none",
                graph.indirect_calls, graph.import_calls, graph.unresolved_calls))
            for edge in graph.edges[:10]:
                target = ("0x%x" % edge.callee) if edge.callee is not None else (edge.name or "?")
                print("  0x%x -> %s  %s @0x%x" % (edge.caller, target, edge.kind, edge.site))
        return EXIT_OK
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

    extra: dict = {"functions": 0, "strings": 0, "ascii": 0, "utf16le": 0, "with_xref": 0, "edges": 0, "indirect_calls": 0,
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
            graph = callgraph_mod.build(data, funcs=found) if found else callgraph_mod.CallGraph()
            result.findings.extend(schema.enforce_rules(
                functions_mod.to_findings(found) + strings_mod.to_findings(items) + callgraph_mod.to_findings(graph)))
            extra = {"functions": len(found), "strings": len(items),
                     "ascii": sum(1 for s in items if s.encoding == "ascii"),
                     "utf16le": sum(1 for s in items if s.encoding == "utf16le"),
                     "with_xref": sum(1 for s in items if s.xrefs),
                     "edges": len(graph.edges),
                     "indirect_calls": graph.indirect_calls,
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
        print("edges    %d  indirect_calls %d" % (extra["edges"], extra["indirect_calls"]))
        print("strings  %d (ascii=%d utf16le=%d) xref=%d%s" % (
            extra["strings"], extra["ascii"], extra["utf16le"], extra["with_xref"],
            " skipped=" + extra["xref_skipped"] if extra["xref_skipped"] else ""))
        for diag in result.diagnostics:
            print("diag    %s: %s" % (diag.code, diag.message))

    return {"ok": EXIT_OK, "degraded": EXIT_DEGRADED, "failed": EXIT_FAILED}[result.status]


if __name__ == "__main__":
    raise SystemExit(main())
