"""AC-2: capstone vs objdump over .text, normalised instruction comparison."""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from reversesuite import disasm_compare, loader, strings  # noqa: E402

OBJDUMP = ROOT / "tools" / "mingw64" / "bin" / "objdump.exe"


def binutils_version() -> str:
    try:
        out = subprocess.run([str(OBJDUMP), "--version"], capture_output=True, text=True).stdout
        return out.splitlines()[0] if out else "unknown"
    except Exception:
        return "unknown"


def measure(path: pathlib.Path) -> dict:
    data = path.read_bytes()
    text = loader.text_bytes(data)
    base = disasm_compare.disasm.BASE_ADDRESS
    image_base = strings._image_base(data)
    text_rva = strings._text_rva(data)
    out = subprocess.run([str(OBJDUMP), "-d", "-M", "intel", "--no-show-raw-insn", str(path)],
                         capture_output=True, text=True, errors="replace").stdout
    low = base
    high = base + len(text)
    reference = disasm_compare.parse_objdump(out, image_base, text_rva, low, high, base)
    candidate = disasm_compare.parse_capstone(text, base)
    sweep = disasm_compare.compare(reference, candidate)
    result = disasm_compare.compare_at_addresses(reference, text, base)
    summary = result.summary()
    summary["sweep"] = sweep.summary()
    summary.update({"file": path.name, "text_bytes": len(text),
                    "image_base": hex(image_base), "text_rva": hex(text_rva)})
    return summary


def main() -> int:
    print("binutils:", binutils_version())
    rows = []
    for name in ("a.exe", "b.exe", "b_unstripped.exe"):
        path = ROOT / "fixtures" / "frozen" / name
        row = measure(path)
        rows.append(row)
        print(json.dumps(row, indent=1))
    out_path = ROOT / "spikes" / "AC2-results.json"
    out_path.write_text(json.dumps({"binutils": binutils_version(), "results": rows}, indent=1),
                        encoding="utf-8")
    print("wrote", out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())