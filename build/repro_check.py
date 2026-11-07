"""AC-4: prove the pinned gcc recipe is byte-reproducible.

Builds fixtures/src/prog.c twice in two different temporary directories with the
locked flags and compares sha256. MSVC is intentionally out of scope (PLAN records
that /Brepro still differs); our frozen PE32 fixtures keep their original build.
"""
import argparse
import hashlib
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
GCC = ROOT / "tools" / "mingw64" / "bin" / "gcc.exe"
SRC = ROOT / "fixtures" / "src" / "prog.c"
FLAGS = ["-O2", "-s", "-Wl,--no-insert-timestamp", "-ffile-prefix-map=__ROOT__=."]


def build(workdir: pathlib.Path, src: pathlib.Path, flags) -> tuple:
    out = workdir / "prog.exe"
    mapped = [f.replace("__ROOT__", str(ROOT)) for f in flags]
    result = subprocess.run([str(GCC), *mapped, "-o", str(out), str(src)],
                            capture_output=True, text=True, cwd=str(workdir))
    if result.returncode != 0:
        return None, result.stderr.strip()[:400]
    return hashlib.sha256(out.read_bytes()).hexdigest(), ""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--src", default=str(SRC))
    args = parser.parse_args(argv)
    src = pathlib.Path(args.src)
    hashes = []
    for _ in range(2):
        with tempfile.TemporaryDirectory() as tmp:
            digest, error = build(pathlib.Path(tmp), src, FLAGS)
            if digest is None:
                print("build failed:", error, file=sys.stderr)
                return 2
            hashes.append(digest)
    same = hashes[0] == hashes[1]
    print("sha256[0]=%s" % hashes[0])
    print("sha256[1]=%s" % hashes[1])
    print("reproducible:", same)
    return 0 if same else 1


if __name__ == "__main__":
    raise SystemExit(main())