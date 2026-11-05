"""CLI: analyze a PE file and print canonical JSON (stdout only)."""
from __future__ import annotations

import argparse
import sys

from . import loader

EXIT_OK, EXIT_DEGRADED, EXIT_FAILED, EXIT_USAGE, EXIT_INTERNAL = 0, 2, 3, 4, 5


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="reversesuite", add_help=True)
    sub = parser.add_subparsers(dest="cmd")
    analyze = sub.add_parser("analyze", help="analyze one PE file")
    analyze.add_argument("path")
    analyze.add_argument("--json", action="store_true", help="emit canonical JSON on stdout")
    args = parser.parse_args(argv)

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
