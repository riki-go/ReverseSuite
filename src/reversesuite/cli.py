"""CLI: analyze a PE file and print canonical JSON (stdout only)."""
from __future__ import annotations

import argparse
import sys

import json

from . import disasm, loader

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
    args = parser.parse_args(argv)

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
        try:
            summary = disasm.write_stream(text, __import__("pathlib").Path(args.out), args.gzip, args.slim, workers=args.workers)
        except Exception as exc:
            print(f"internal error: {exc.__class__.__name__}", file=sys.stderr)
            return EXIT_INTERNAL
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
