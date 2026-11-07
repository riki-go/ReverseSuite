"""Extract function ground truth from a PDB using dbghelp (ctypes, stdlib only)."""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import struct
import sys
from pathlib import Path

dbghelp = ctypes.WinDLL("dbghelp", use_last_error=True)
dbghelp.SymSetOptions.argtypes = [ctypes.c_ulong]
dbghelp.SymInitializeW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_int]
dbghelp.SymInitializeW.restype = ctypes.c_int
dbghelp.SymLoadModuleExW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_wchar_p,
                                     ctypes.c_wchar_p, ctypes.c_ulonglong, ctypes.c_ulong,
                                     ctypes.c_void_p, ctypes.c_ulong]
dbghelp.SymLoadModuleExW.restype = ctypes.c_ulonglong
PROTO = ctypes.WINFUNCTYPE(wt.BOOL, ctypes.c_void_p, wt.ULONG, ctypes.c_void_p)
dbghelp.SymEnumSymbolsW.argtypes = [ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_wchar_p,
                                    PROTO, ctypes.c_void_p]
dbghelp.SymEnumSymbolsW.restype = ctypes.c_int
dbghelp.SymCleanup.argtypes = [ctypes.c_void_p]

SYMOPT_UNDNAME = 0x00000002
SYMOPT_DEFERRED_LOADS = 0x00000004
SymTagFunction = 5


class SYMBOL_INFOW(ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct", wt.ULONG),
        ("TypeIndex", wt.ULONG),
        ("Reserved", ctypes.c_ulonglong),
        ("Index", wt.ULONG),
        ("Size", wt.ULONG),
        ("ModBase", ctypes.c_ulonglong),
        ("Flags", wt.ULONG),
        ("Value", ctypes.c_ulonglong),
        ("Address", ctypes.c_ulonglong),
        ("Register", wt.DWORD),
        ("Scope", wt.DWORD),
        ("Tag", wt.DWORD),
        ("NameLen", wt.DWORD),
        ("MaxNameLen", wt.DWORD),
        ("Name", ctypes.c_wchar * 1),
    ]


def image_base(data: bytes) -> int:
    e = struct.unpack_from("<I", data, 0x3C)[0]
    return struct.unpack_from("<Q", data, e + 24 + 24)[0]


def text_vaddr(data: bytes) -> int:
    e = struct.unpack_from("<I", data, 0x3C)[0]
    n = struct.unpack_from("<H", data, e + 6)[0]
    o = struct.unpack_from("<H", data, e + 20)[0]
    table = e + 4 + 20 + o
    for i in range(n):
        off = table + i * 40
        if data[off:off + 8].rstrip(b"\x00") == b".text":
            return struct.unpack_from("<I", data, off + 12)[0]
    raise SystemExit("no .text")


def symbols(exe: Path) -> list:
    proc = ctypes.windll.kernel32.GetCurrentProcess()
    dbghelp.SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS)
    if not dbghelp.SymInitializeW(proc, str(exe.parent), False):
        raise SystemExit("SymInitialize failed: %s" % ctypes.get_last_error())
    data = exe.read_bytes()
    base = image_base(data)
    mod = dbghelp.SymLoadModuleExW(proc, None, str(exe), None, base, 0, None, 0)
    if not mod:
        raise SystemExit("SymLoadModuleEx failed: %s" % ctypes.get_last_error())

    found = []

    def cb(info_ptr, size, ctx):
        info = ctypes.cast(info_ptr, ctypes.POINTER(SYMBOL_INFOW)).contents
        if info.Tag == SymTagFunction:
            name = ctypes.wstring_at(ctypes.addressof(info) + SYMBOL_INFOW.Name.offset, info.NameLen)
            found.append((int(info.Address), name))
        return True

    if not dbghelp.SymEnumSymbolsW(proc, base, None, PROTO(cb), None):
        raise SystemExit("SymEnumSymbols failed: %s" % ctypes.get_last_error())
    dbghelp.SymCleanup(proc)
    return found


def main() -> int:
    exe = Path(sys.argv[1])
    data = exe.read_bytes()
    base = image_base(data)
    tv = text_vaddr(data)
    syms = symbols(exe)
    out = []
    for addr, name in syms:
        rva = addr - base
        if rva < tv:
            continue
        out.append({"addr": 0x1000 + (rva - tv), "name": name})
    result = {"exe": str(exe), "symbols": len(syms), "in_text": len(out), "sample": out[:8]}
    print(json.dumps(result, indent=1))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(json.dumps(out, indent=1) + chr(10), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
