"""Generate synthetic C code split across translation units."""
from __future__ import annotations

import argparse
from pathlib import Path


def write_part(path: Path, start: int, count: int) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as f:
        f.write("#include <stdio.h>\n")
        for i in range(start, start + count):
            f.write(f"__declspec(noinline) int fn_{i}(int x) {{ return (x * {i + 1}) ^ {i}; }}\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--parts", type=int, default=10)
    ap.add_argument("--total", type=int, default=2023000)
    ap.add_argument("--outdir", default="src")
    ap.add_argument("--prefix", default="big_part")
    args = ap.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    per = args.total // args.parts
    files = []
    for p in range(args.parts):
        start = p * per
        good = per if p < args.parts - 1 else args.total - start
        name = f"{args.prefix}_{p + 1:02d}.c"
        write_part(outdir / name, start, good)
        files.append(name)

    main_c = outdir / "big_main.c"
    with main_c.open("w", encoding="utf-8", newline="\n") as f:
        f.write("#include <stdio.h>\n")
        f.write("int main(void) { printf(\"%d\\n\", 0); return 0; }\n")

    all_c = outdir / f"{args.prefix}_all.c"
    with all_c.open("w", encoding="utf-8", newline="\n") as f:
        for name in files:
            f.write(f'#include "{name}"\n')
        f.write('#include "big_main.c"\n')

    total_bytes = sum((outdir / n).stat().st_size for n in files)
    print(f"parts={len(files)} per={per} total_funcs={args.total} bytes={total_bytes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
