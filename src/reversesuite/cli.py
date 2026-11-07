"""CLI: analyze a PE file and print canonical JSON (stdout only)."""
from __future__ import annotations

import argparse
import sys

import json
import os

import hashlib
import shutil

from . import functions as functions_mod
from . import cache as cache_mod, disasm, loader

EXIT_OK, EXIT_DEGRADED, EXIT_FAILED, EXIT_USAGE, EXIT_INTERNAL = 0, 2, 3, 4, 5


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="reversesuite", add_help=True)
    sub = parser.add_subparsers(dest="cmd")
    analyze = sub.add_parser("analyze", help="analyze one PE file")
    analyze.add_argument("path")
    analyze.add_argument("--json", action="store_true", help="emit canonical JSON on stdout")
    dis = sub.add_parser("disasm", help="stream disassembly to JSONL")
    dis.add_argument("path")
    dis.add_argument("--out", required=True)
    dis.add_argument("--gzip", action="store_true")
    dis.add_argument("--slim", action="store_true", help="write only address+mnemonic")
    dis.add_argument("--limit-bytes", type=int, default=0, help="disassemble only the first N bytes of .text")
    dis.add_argument("--workers", type=int, default=1, help="parallel worker processes")
    dis.add_argument("--cache-dir", default="", help="enable artifact cache in this directory")
    fn = sub.add_parser("functions", help="discover function starts heuristically")
    fn.add_argument("path")
    fn.add_argument("--json", action="store_true", help="emit JSON array on stdout")
    fn.add_argument("--limit-bytes", type=int, default=0)
    fn.add_argument("--max-functions", type=int, default=200000)
    args = parser.parse_args(argv)

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

    if args.json:
        sys.stdout.write(result.to_canonical_json())
        sys.stdout.write(chr(10))

    return {"ok": EXIT_OK, "degraded": EXIT_DEGRADED, "failed": EXIT_FAILED}[result.status]


if __name__ == "__main__":
    raise SystemExit(main())
