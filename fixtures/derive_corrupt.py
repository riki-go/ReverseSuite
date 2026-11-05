"""derive_corrupt.py - deterministic corrupt-PE fixture generator (stdlib only).

Pure function of the frozen bytes: no timestamps, no randomness, no absolute paths in results.
Does not import or read any analyzer code (independent oracle).
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE / 'frozen' / 'a.exe'

CASES = [
    ('t1', 'truncate at 0x20 (middle of DOS header)', 'failed', 3,
     'DOS header cannot be parsed, so e_lfanew is unavailable'),
    ('t2', 'truncate at e_lfanew+0x10 (middle of COFF header)', 'failed', 3,
     'COFF header incomplete; section count and optional-header size unreadable'),
    ('t3', 'truncate in the middle of section entry #3', 'failed', 3,
     'section table is truncated; section metadata incomplete'),
    ('t4', 'truncate in the middle of .text raw data', 'degraded', 2,
     'headers and section table are intact; only part of .text bytes are missing'),
    ('t5', 'drop the last byte of the file', 'degraded', 2,
     'headers intact; one byte missing from the tail region'),
    ('f1', 'NumberOfSections = 0xFFFF', 'failed', 3,
     'section count exceeds any sane limit; also hits the T2 cap'),
    ('f2', 'SizeOfOptionalHeader = 0x0010', 'failed', 3,
     'optional header too small to hold required fields; section table offset invalid'),
    ('f3', 'e_lfanew points past end of file', 'failed', 3,
     'COFF/optional headers lie outside the file'),
]


def header_info(data: bytes) -> dict:
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    machine = struct.unpack_from('<H', data, e_lfanew + 4)[0]
    nsec = struct.unpack_from('<H', data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]
    magic = struct.unpack_from('<H', data, e_lfanew + 24)[0]
    sec_table = e_lfanew + 4 + 20 + opt_size
    sections = []
    for i in range(min(nsec, 96)):
        off = sec_table + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].rstrip(b'\x00').decode('latin-1')
        raw_size, raw_ptr = struct.unpack_from('<II', data, off + 16)
        sections.append({'index': i + 1, 'name': name, 'raw_ptr': raw_ptr, 'raw_size': raw_size,
                         'raw_end': raw_ptr + raw_size})
    text = next((s for s in sections if s['name'] == '.text'), None)
    return {
        'e_lfanew': e_lfanew,
        'machine': machine,
        'machine_hex': hex(machine),
        'magic': magic,
        'magic_hex': hex(magic),
        'pe_kind': 'PE32+' if magic == 0x20B else ('PE32' if magic == 0x10B else 'unknown'),
        'num_sections': nsec,
        'size_of_optional_header': opt_size,
        'section_table_offset': sec_table,
        'section_table_end': sec_table + nsec * 40,
        'sections': sections,
        'text': text,
        'max_raw_end': max((s['raw_end'] for s in sections), default=0),
        'file_size': len(data),
    }


def build(data: bytes, info: dict) -> list:
    out = []
    for cid, desc, status, exit_code, rationale in CASES:
        b = bytearray(data)
        if cid == 't1':
            b = b[:0x20]
            detail = {'kind': 'truncate', 'cut_at': 0x20, 'bytes_after': 0x20}
        elif cid == 't2':
            cut = info['e_lfanew'] + 0x10
            b = b[:cut]
            detail = {'kind': 'truncate', 'cut_at': cut, 'bytes_after': cut}
        elif cid == 't3':
            cut = info['section_table_offset'] + 2 * 40 + 20
            b = b[:cut]
            detail = {'kind': 'truncate', 'cut_at': cut, 'bytes_after': cut,
                      'formula': 'section_table_offset + 2*40 + 20'}
        elif cid == 't4':
            t = info['text']
            cut = t['raw_ptr'] + t['raw_size'] // 2
            b = b[:cut]
            detail = {'kind': 'truncate', 'cut_at': cut, 'bytes_after': cut,
                      'formula': '.text.raw_ptr + .text.raw_size/2'}
        elif cid == 't5':
            b = b[:-1]
            detail = {'kind': 'truncate', 'cut_at': len(b), 'bytes_after': len(b),
                      'formula': 'file_size - 1',
                      'last_raw_end': info['max_raw_end'], 'file_size': info['file_size'],
                      'overlay_bytes': info['file_size'] - info['max_raw_end']}
        elif cid == 'f1':
            struct.pack_into('<H', b, info['e_lfanew'] + 6, 0xFFFF)
            detail = {'kind': 'patch', 'offset': info['e_lfanew'] + 6, 'length': 2, 'new_hex': 'ffff'}
        elif cid == 'f2':
            struct.pack_into('<H', b, info['e_lfanew'] + 20, 0x0010)
            detail = {'kind': 'patch', 'offset': info['e_lfanew'] + 20, 'length': 2, 'new_hex': '1000'}
        elif cid == 'f3':
            struct.pack_into('<I', b, 0x3C, len(data) + 0x1000)
            detail = {'kind': 'patch', 'offset': 0x3C, 'length': 4, 'new_value': 'file_size + 0x1000'}
        else:
            raise SystemExit('unknown case: ' + cid)
        out.append({
            'id': cid,
            'description': desc,
            'mutation': detail,
            'expected_status': status,
            'expected_exit_code': exit_code,
            'rationale': rationale,
            'bytes': bytes(b),
        })
    return out


def main() -> int:
    out_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else (HERE / 'out' / 'corrupt')
    manifest_path = Path(sys.argv[2]) if len(sys.argv) > 2 else (HERE / 'corrupt-manifest.json')
    data = SRC.read_bytes()
    info = header_info(data)
    out_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for item in build(data, info):
        payload = item.pop('bytes')
        path = out_dir / (item['id'] + '.bin')
        path.write_bytes(payload)
        item['file'] = item['id'] + '.bin'
        item['bytes_out'] = len(payload)
        item['sha256'] = hashlib.sha256(payload).hexdigest().upper()
        records.append(item)
    manifest = {
        'schema_version': '1.0.0',
        'source': {'file': 'frozen/a.exe', 'sha256': hashlib.sha256(data).hexdigest().upper(), 'bytes': len(data)},
        'header': info,
        'cases': records,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + chr(10), encoding='utf-8')
    print(json.dumps({'cases': len(records)}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
