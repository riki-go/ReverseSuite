"""AC-7a runner: disassemble .text with capstone, stream JSONL (+gzip), measure wall/RSS."""
from __future__ import annotations

import ctypes
import gzip
import json
import struct
import sys
import time
from pathlib import Path

import capstone


class PMC(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("PageFaultCount", ctypes.c_ulong),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def peak_rss_mb() -> float:
    c = PMC()
    c.cb = ctypes.sizeof(c)
    fn = ctypes.windll.kernel32.K32GetProcessMemoryInfo
    fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(PMC), ctypes.c_ulong]
    fn.restype = ctypes.c_int
    if not fn(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(c), c.cb):
        raise OSError(ctypes.get_last_error(), "K32GetProcessMemoryInfo failed")
    return c.PeakWorkingSetSize / (1024 * 1024)


def text_range(data: bytes) -> tuple[int, int]:
    e = struct.unpack_from("<I", data, 0x3C)[0]
    n = struct.unpack_from("<H", data, e + 6)[0]
    o = struct.unpack_from("<H", data, e + 20)[0]
    t = e + 4 + 20 + o
    for i in range(n):
        off = t + i * 40
        if data[off:off + 8].rstrip(b"\x00") == b".text":
            rs, rp = struct.unpack_from("<II", data, off + 16)
            return rp, rs
    raise SystemExit("no .text")


def main() -> int:
    path = Path(sys.argv[1])
    outdir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("fixtures/out/ac7a")
    outdir.mkdir(parents=True, exist_ok=True)
    data = path.read_bytes()
    rp, rs = text_range(data)
    blob = data[rp:rp + rs]

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False

    raw_path = outdir / "insn.jsonl"
    gz_path = outdir / "insn.jsonl.gz"

    t0 = time.perf_counter()
    count = 0
    raw_bytes = 0
    with open(raw_path, "wb", buffering=1024 * 1024) as raw, gzip.open(gz_path, "wb", compresslevel=6) as gz:
        for insn in md.disasm(blob, 0x1000):
            line = ('{"a":%d,"m":"%s","o":"%s"}\n' % (insn.address, insn.mnemonic, insn.op_str)).encode("utf-8")
            raw.write(line)
            gz.write(line)
            raw_bytes += len(line)
            count += 1
    wall = time.perf_counter() - t0
    peak = peak_rss_mb()

    result = {
        "file": str(path),
        "text_bytes": len(blob),
        "instructions": count,
        "wall_s": round(wall, 3),
        "peak_rss_mb": round(peak, 1),
        "jsonl_raw_bytes": raw_bytes,
        "jsonl_gzip_bytes": gz_path.stat().st_size,
        "raw_ratio_over_code": round(raw_bytes / len(blob), 3),
        "gzip_over_raw_pct": round(100.0 * gz_path.stat().st_size / raw_bytes, 2),
        "instr_per_s": round(count / wall, 0) if wall else 0,
    }
    print(json.dumps(result, indent=1))
    (outdir / "ac7a-result.json").write_text(json.dumps(result, indent=2) + chr(10), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
