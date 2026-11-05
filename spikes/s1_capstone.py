"""S1 spike: capstone throughput, bytes/instruction, JSONL size, stream-vs-buffer RSS.

Read-only measurement. Does not modify fixtures. Deterministic inputs only.
"""
from __future__ import annotations

import ctypes
import json
import statistics
import struct
import subprocess
import sys
import time
from pathlib import Path

import capstone

HERE = Path(__file__).resolve().parent
TARGET = HERE.parent / "fixtures" / "frozen" / "a.exe"
SLICE = 10 * 1024 * 1024


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
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
    counters = PROCESS_MEMORY_COUNTERS()
    counters.cb = ctypes.sizeof(counters)
    fn = ctypes.windll.kernel32.K32GetProcessMemoryInfo
    fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), ctypes.c_ulong]
    fn.restype = ctypes.c_int
    ok = fn(ctypes.windll.kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb)
    if not ok:
        raise OSError(ctypes.get_last_error(), "K32GetProcessMemoryInfo failed")
    return counters.PeakWorkingSetSize / (1024 * 1024)

def text_section(data: bytes) -> tuple[int, int, int]:
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    table = e_lfanew + 4 + 20 + opt_size
    for i in range(nsec):
        off = table + i * 40
        name = data[off:off + 8].rstrip(b"\x00")
        if name == b".text":
            raw_size, raw_ptr = struct.unpack_from("<II", data, off + 16)
            return raw_ptr, raw_size, nsec
    raise SystemExit("no .text section")


def disasm_count(md, blob: bytes, base: int) -> int:
    n = 0
    for _ in md.disasm(blob, base):
        n += 1
    return n


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else "measure"
    data = TARGET.read_bytes()
    raw_ptr, raw_size, _ = text_section(data)
    blob = data[raw_ptr: raw_ptr + raw_size]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False

    if mode == "mem-stream":
        base_peak = peak_rss_mb()
        sink = 0
        for insn in md.disasm(blob[:SLICE], 0x1000):
            line = '{"a":%d,"m":"%s"}\n' % (insn.address, insn.mnemonic)
            sink += len(line)
        print(json.dumps({"mode": "stream", "peak_mb": peak_rss_mb(), "baseline_mb": base_peak, "sink": sink}))
        return 0

    if mode == "mem-buffer":
        base_peak = peak_rss_mb()
        rows = []
        for insn in md.disasm(blob[:SLICE], 0x1000):
            rows.append((insn.address, insn.mnemonic, insn.op_str))
        print(json.dumps({"mode": "buffer", "peak_mb": peak_rss_mb(), "baseline_mb": base_peak, "rows": len(rows)}))
        return 0

    # full .text instruction count + B
    t0 = time.perf_counter()
    total_instr = disasm_count(md, blob, 0x1000)
    full_s = time.perf_counter() - t0
    bytes_per_instr = len(blob) / total_instr if total_instr else 0.0

    # throughput on a 10MB slice, 3 runs
    piece = blob[:SLICE]
    times = []
    counts = []
    for _ in range(3):
        t0 = time.perf_counter()
        n = disasm_count(md, piece, 0x1000)
        dt = time.perf_counter() - t0
        times.append(dt)
        counts.append(n)
    med_s = statistics.median(times)
    med_n = statistics.median(counts)
    throughput = med_n / med_s if med_s else 0.0

    # JSONL size per 1MB of code
    one_mb = blob[: 1024 * 1024]
    bytes_out = 0
    lines = 0
    for insn in md.disasm(one_mb, 0x1000):
        bytes_out += len('{"a":%d,"m":"%s","o":"%s"}\n' % (insn.address, insn.mnemonic, insn.op_str))
        lines += 1
    jsonl_per_mb = bytes_out / (len(one_mb) / (1024 * 1024)) if one_mb else 0.0

    def child(m: str) -> dict:
        out = subprocess.run([sys.executable, str(Path(__file__)), m], capture_output=True, text=True)
        try:
            return json.loads(out.stdout.strip().splitlines()[-1])
        except Exception:
            return {"mode": m, "error": out.stderr[-200:]}

    mem_stream = child("mem-stream")
    mem_buffer = child("mem-buffer")

    size_bytes = min(100 * 1024 * 1024, throughput * 45.0 * bytes_per_instr)
    size_mb = int(size_bytes / (1024 * 1024) // 5 * 5)

    result = {
        "target": "frozen/a.exe",
        "text_bytes": len(blob),
        "instructions_full_text": total_instr,
        "full_text_seconds": round(full_s, 3),
        "bytes_per_instr": bytes_per_instr,
        "throughput_instr_per_s_median3": throughput,
        "runs_seconds": [round(t, 3) for t in times],
        "runs_counts": counts,
        "jsonl_bytes_per_code_mb": jsonl_per_mb,
        "jsonl_over_input_ratio": jsonl_per_mb / (1024 * 1024),
        "mem_stream": mem_stream,
        "mem_buffer": mem_buffer,
        "computed_fixture_size_mb": size_mb,
        "python": sys.version.split()[0],
        "capstone_dist": "5.0.9",
        "capstone_module_version": capstone.__version__,
        "capstone_core_version": list(capstone.cs_version()),
    }
    print(json.dumps(result, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
