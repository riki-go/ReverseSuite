"""Ground-truth functions from a COFF symbol table (b_unstripped.exe)."""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path


def parse(path: Path) -> list:
    data = path.read_bytes()
    e = struct.unpack_from("<I", data, 0x3C)[0]
    sym_ptr = struct.unpack_from("<I", data, e + 12)[0]
    sym_count = struct.unpack_from("<I", data, e + 16)[0]
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    opt_size = struct.unpack_from("<H", data, e + 20)[0]
    table = e + 4 + 20 + opt_size
    text_section = None
    for i in range(nsec):
        off = table + i * 40
        if data[off:off + 8].rstrip(b"\x00") == b".text":
            text_section = i + 1
    out = []
    if not sym_ptr:
        return out
    strtab_off = sym_ptr + sym_count * 18
    for k in range(sym_count):
        off = sym_ptr + k * 18
        if off + 18 > len(data):
            break
        name_bytes = data[off:off + 8]
        value, section, typ, storage, aux = struct.unpack_from("<IhHBB", data, off + 8)
        if section != text_section:
            continue
        if not (typ & 0x20):
            continue
        if name_bytes[:4] == b"\x00\x00\x00\x00":
            long_off = struct.unpack_from("<I", name_bytes, 4)[0]
            end = data.find(b"\x00", strtab_off + long_off)
            if end < 0:
                continue
            name = data[strtab_off + long_off:end].decode("latin-1")
        else:
            name = name_bytes.rstrip(b"\x00").decode("latin-1")
        if not name:
            continue
        out.append({"addr": 0x1000 + value, "name": name})
    return out


def main() -> int:
    path = Path(sys.argv[1])
    syms = parse(path)
    print(json.dumps({"file": str(path), "functions": len(syms), "sample": syms[:8]}, indent=1))
    if len(sys.argv) > 2:
        Path(sys.argv[2]).write_text(json.dumps(syms, indent=1) + chr(10), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
