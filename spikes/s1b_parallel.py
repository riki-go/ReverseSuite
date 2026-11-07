"""S1b/AC-7a parallel: disassemble .text across worker processes."""
from __future__ import annotations

import ctypes
import json
import struct
import sys
import time
from concurrent.futures import ProcessPoolExecutor
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
    fn(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(c), c.cb)
    return c.PeakWorkingSetSize / (1024 * 1024)


def text_range(path: str) -> tuple[int, int]:
    with open(path, "rb") as fh:
        head = fh.read(4096)
        e = struct.unpack_from("<I", head, 0x3C)[0]
        fh.seek(e + 6)
        n = struct.unpack("<H", fh.read(2))[0]
        fh.seek(e + 20)
        o = struct.unpack("<H", fh.read(2))[0]
        t = e + 4 + 20 + o
        for i in range(n):
            fh.seek(t + i * 40)
            sec = fh.read(40)
            if sec[:8].rstrip(b"\x00") == b".text":
                rs, rp = struct.unpack_from("<II", sec, 16)
                return rp, rs
    raise SystemExit("no .text")


def work(args):
    path, offset, size, base = args
    with open(path, "rb") as fh:
        fh.seek(offset)
        blob = fh.read(size)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False
    count = 0
    t0 = time.perf_counter()
    SUB = 2 * 1024 * 1024
    for start in range(0, len(blob), SUB):
        piece = blob[start:start + SUB]
        pbase = base + start
        pend = pbase + len(piece)
        for insn in md.disasm(piece, pbase):
            if insn.address + insn.size > pend:
                break
            count += 1
    return count, time.perf_counter() - t0, peak_rss_mb()


def main() -> int:
    path = sys.argv[1]
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    rp, rs = text_range(path)
    per = rs // workers
    jobs = []
    for i in range(workers):
        off = rp + i * per
        size = per if i < workers - 1 else rs - i * per
        jobs.append((path, off, size, 0x1000 + i * per))

    t0 = time.perf_counter()
    with ProcessPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(work, jobs))
    wall = time.perf_counter() - t0

    total = sum(r[0] for r in results)
    result = {
        "file": path,
        "workers": workers,
        "text_bytes": rs,
        "instructions": total,
        "wall_s": round(wall, 3),
        "instr_per_s": round(total / wall, 0) if wall else 0,
        "worker_peak_rss_mb": [round(r[2], 1) for r in results],
        "sum_worker_rss_mb": round(sum(r[2] for r in results), 1),
        "worker_wall_s": [round(r[1], 3) for r in results],
    }
    print(json.dumps(result, indent=1))
    Path(sys.argv[3] if len(sys.argv) > 3 else "fixtures/out/ac7a_parallel.json").write_text(
        json.dumps(result, indent=2) + chr(10), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
