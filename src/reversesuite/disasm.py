"""Streaming disassembly to JSONL (optionally gzip), bounded memory.

Design notes (M1b):
- never materialise the whole instruction list
- capstone is called per 2 MB window (capstone 5.0.9 raises CS_ERR_MEM on larger buffers)
- the last instruction of a window that crosses the boundary is dropped to avoid misalignment
- output is deterministic: same input -> same bytes
"""
from __future__ import annotations

import gzip
from concurrent.futures import ProcessPoolExecutor
import json
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional, TextIO

import capstone

WINDOW = 2 * 1024 * 1024
BASE_ADDRESS = 0x1000


def make_engine() -> capstone.Cs:
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False
    return md


def iter_instructions(blob: bytes, base: int = BASE_ADDRESS, md: Optional[capstone.Cs] = None) -> Iterator[capstone.CsInsn]:
    engine = md or make_engine()
    for start in range(0, len(blob), WINDOW):
        piece = blob[start:start + WINDOW]
        pbase = base + start
        pend = pbase + len(piece)
        for insn in engine.disasm(piece, pbase):
            if insn.address + insn.size > pend:
                break
            yield insn


def format_line(insn: capstone.CsInsn, slim: bool = False) -> bytes:
    if slim:
        return ('{"a":%d,"m":"%s"}\n' % (insn.address, insn.mnemonic)).encode("utf-8")
    return ('{"a":%d,"m":"%s","o":"%s"}\n' % (insn.address, insn.mnemonic, insn.op_str)).encode("utf-8")


@contextmanager
def open_writer(path: Path, use_gzip: bool = False):
    path.parent.mkdir(parents=True, exist_ok=True)
    if use_gzip:
        handle = gzip.open(path, "wb", compresslevel=6)
    else:
        handle = open(path, "wb", buffering=1024 * 1024)
    try:
        yield handle
    finally:
        handle.close()


def _window_lines(payload):
    """Worker: decode one fixed window and return serialized JSONL bytes."""
    blob, base, slim = payload
    engine = make_engine()
    out = bytearray()
    end = base + len(blob)
    for insn in engine.disasm(blob, base):
        if insn.address + insn.size > end:
            break
        out += format_line(insn, slim)
    return bytes(out)


def _windows(blob: bytes):
    for start in range(0, len(blob), WINDOW):
        yield blob[start:start + WINDOW], BASE_ADDRESS + start


def write_stream_parallel(blob: bytes, out_path: Path, use_gzip: bool = False, slim: bool = False,
                          workers: int = 2) -> dict:
    tasks = [(piece, base, slim) for piece, base in _windows(blob)]
    started = time.perf_counter()
    count = 0
    written = 0
    with ProcessPoolExecutor(max_workers=workers) as ex:
        chunks = ex.map(_window_lines, tasks)
        with open_writer(out_path, use_gzip) as fh:
            for chunk in chunks:
                fh.write(chunk)
                written += len(chunk)
                count += chunk.count(b"\n")
    wall = time.perf_counter() - started
    result = {
        "out": str(out_path),
        "gzip": use_gzip,
        "slim": slim,
        "workers": workers,
        "instructions": count,
        "jsonl_raw_bytes": written,
        "file_bytes": out_path.stat().st_size if out_path.exists() else 0,
        "wall_s": round(wall, 3),
        "instr_per_s": round(count / wall, 0) if wall else 0,
    }
    if use_gzip and written:
        result["gzip_over_raw_pct"] = round(100.0 * result["file_bytes"] / written, 2)
    return result

def write_stream(blob: bytes, out_path: Path, use_gzip: bool = False, slim: bool = False,
                 md: Optional[capstone.Cs] = None, workers: int = 1) -> dict:
    if workers and workers > 1:
        return write_stream_parallel(blob, out_path, use_gzip, slim, workers)
    engine = md or make_engine()
    count = 0
    written = 0
    started = time.perf_counter()
    with open_writer(out_path, use_gzip) as fh:
        for insn in iter_instructions(blob, BASE_ADDRESS, engine):
            line = format_line(insn, slim)
            fh.write(line)
            written += len(line)
            count += 1
    wall = time.perf_counter() - started
    result = {
        "out": str(out_path),
        "gzip": use_gzip,
        "slim": slim,
        "instructions": count,
        "jsonl_raw_bytes": written,
        "file_bytes": out_path.stat().st_size if out_path.exists() else 0,
        "wall_s": round(wall, 3),
        "instr_per_s": round(count / wall, 0) if wall else 0,
    }
    if use_gzip and written:
        result["gzip_over_raw_pct"] = round(100.0 * result["file_bytes"] / written, 2)
    return result
