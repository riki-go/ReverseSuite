"""Generate small synthetic fixtures for the M8 multi-format loaders.

Each builder writes a structurally valid file (verified with LIEF when it is
installed), so loader tests do not depend on shipping third-party samples.
"""
from __future__ import annotations

import hashlib
import pathlib
import struct
import zlib

HERE = pathlib.Path(__file__).resolve().parent
OUT = HERE / "multi"

ARM64_TEXT = b"".join(struct.pack("<I", word) for word in (
    0xA9BF7BFD,  # stp x29, x30, [sp, #-16]!
    0x910003FD,  # mov x29, sp
    0x94000006,  # bl 0x1020
    0xD65F03C0,  # ret
    0xD503201F, 0xD503201F, 0xD503201F, 0xD503201F,
    0xA9BF7BFD,  # stp x29, x30, [sp, #-16]!
    0x910003FD,  # mov x29, sp
    0x52800000,  # mov w0, #0
    0xD65F03C0,  # ret
))
ARM64_TEXT = ARM64_TEXT + b"\x1f\x20\x03\xd5" * ((0x40 - len(ARM64_TEXT)) // 4)

RODATA = b"arm64 demo library\x00https://example.com/ios\x00DEMO_TOKEN\x00"


def build_elf_arm64() -> bytes:
    text_off, text_addr, text_size = 0x1000, 0x1000, 0x40
    ro_off, ro_addr = 0x2000, 0x2000
    dynstr_off = 0x2100
    dynsym_off = 0x2200
    shstr_off = 0x3000
    shoff = 0x4000

    dynstr = b"\x00demo_start\x00demo_helper\x00"
    nsyms = 3
    dynsym = b"\x00" * 24
    for name_off, value in ((1, text_addr), (12, text_addr + 0x20)):
        dynsym += struct.pack("<IBBHQQ", name_off, 0x12, 0, 1, value, 0x20)

    shstr = b"\x00.text\x00.rodata\x00.dynstr\x00.dynsym\x00.shstrtab\x00"
    names = {".text": 1, ".rodata": 7, ".dynstr": 15, ".dynsym": 23, ".shstrtab": 31}

    def shdr(name, sh_type, flags, addr, off, size, link=0, info=0, align=1, entsize=0):
        return struct.pack("<IIQQQQIIQQ", name, sh_type, flags, addr, off, size,
                           link, info, align, entsize)

    sections = [
        b"\x00" * 64,
        shdr(names[".text"], 1, 6, text_addr, text_off, text_size, align=4),
        shdr(names[".rodata"], 1, 2, ro_addr, ro_off, len(RODATA), align=1),
        shdr(names[".dynstr"], 3, 2, dynstr_off, dynstr_off, len(dynstr), align=1),
        shdr(names[".dynsym"], 11, 2, dynsym_off, dynsym_off, len(dynsym), link=3, info=1,
             align=8, entsize=24),
        shdr(names[".shstrtab"], 3, 0, 0, shstr_off, len(shstr), align=1),
    ]

    ident = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\x00" * 8
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, 0x3000, 0x3000, 0x1000)
    ehdr = ident + struct.pack(
        "<HHIQQQIHHHHHH", 3, 183, 1, text_addr, 64, shoff, 0, 64, 56, 1, 64,
        len(sections), 5)

    total = shoff + len(sections) * 64
    buf = bytearray(total)
    buf[0:64] = ehdr
    buf[64:64 + len(phdr)] = phdr
    buf[text_off:text_off + len(ARM64_TEXT)] = ARM64_TEXT
    buf[ro_off:ro_off + len(RODATA)] = RODATA
    buf[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    buf[dynsym_off:dynsym_off + len(dynsym)] = dynsym
    buf[shstr_off:shstr_off + len(shstr)] = shstr
    for i, section in enumerate(sections):
        buf[shoff + i * 64:shoff + (i + 1) * 64] = section
    return bytes(buf)


def build_macho_arm64() -> bytes:
    text_off, text_addr = 0x1000, 0x100001000
    cstring_off, cstring_addr = 0x1100, 0x100001100
    link_off = 0x4000
    strtab = b"\x00_main\x00_helper\x00"
    symtab = struct.pack("<IBBHQ", 1, 0x0F, 1, 0, text_addr)
    symtab += struct.pack("<IBBHQ", 7, 0x0F, 1, 0, text_addr + 0x20)

    def segment(name, vmaddr, vmsize, fileoff, filesize, sections=()):
        body = struct.pack("<16sQQQQIIII", name.encode(), vmaddr, vmsize, fileoff, filesize,
                           5, 5, len(sections), 0)
        for sectname, segname, addr, size, offset, flags in sections:
            body += struct.pack("<16s16sQQIIIIIIII", sectname.encode(), segname.encode(),
                                addr, size, offset, 4, 0, 0, flags, 0, 0, 0)
        return struct.pack("<II", 0x19, 8 + len(body)) + body

    pagezero = segment("__PAGEZERO", 0, 0x100000000, 0, 0)
    text_seg = segment("__TEXT", 0x100000000, 0x4000, 0, 0x4000, sections=(
        ("__text", "__TEXT", text_addr, 0x40, text_off, 0x80000400),
        ("__cstring", "__TEXT", cstring_addr, 0x40, cstring_off, 0),
    ))
    linkedit = segment("__LINKEDIT", 0x100004000, 0x1000, link_off, 0x1000)
    symtab_cmd = struct.pack("<IIIIII", 0x2, 24, link_off, 2, link_off + 0x40, len(strtab))
    main_cmd = struct.pack("<IIQQ", 0x80000028, 24, text_off, 0)

    cmds = pagezero + text_seg + linkedit + symtab_cmd + main_cmd
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 5, len(cmds), 0, 0)
    total = link_off + 0x1000
    buf = bytearray(total)
    buf[0:len(header)] = header
    buf[len(header):len(header) + len(cmds)] = cmds
    buf[text_off:text_off + len(ARM64_TEXT)] = ARM64_TEXT
    cstrings = b"Hello from iOS\x00https://example.com/ios\x00IOS_TOKEN\x00"
    buf[cstring_off:cstring_off + len(cstrings)] = cstrings
    buf[link_off:link_off + len(symtab)] = symtab
    buf[link_off + 0x40:link_off + 0x40 + len(strtab)] = strtab
    return bytes(buf)


def _uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def build_dex() -> bytes:
    strings = ["Lcom/demo/App;", "Ljava/lang/Object;", "run", "V", "hello from dex", "App.java"]
    types = [0, 1, 3]              # App, Object, void
    proto = (3, 2, 0)              # shorty "V", return type "V", no params
    method = (0, 0, 2)            # class App, proto 0, name "run"
    class_def = (0, 0x1, 1, 5)    # class, public, super, source file

    header_size = 0x70
    string_ids_size = len(strings)
    string_ids_off = header_size
    type_ids_off = string_ids_off + 4 * string_ids_size
    proto_ids_off = type_ids_off + 4 * len(types)
    method_ids_off = proto_ids_off + 12
    class_defs_off = method_ids_off + 8
    data_off = class_defs_off + 32

    data = bytearray()
    string_offsets = []
    for value in strings:
        raw = value.encode("utf-8")
        string_offsets.append(data_off + len(data))
        data += _uleb(len(value)) + raw + b"\x00"

    total = data_off + len(data)
    buf = bytearray(total)
    buf[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", buf, 32, total)      # file_size
    struct.pack_into("<I", buf, 36, header_size)
    struct.pack_into("<I", buf, 40, 0x12345678)
    struct.pack_into("<II", buf, 56, string_ids_size, string_ids_off)
    struct.pack_into("<II", buf, 64, len(types), type_ids_off)
    struct.pack_into("<II", buf, 72, 1, proto_ids_off)
    struct.pack_into("<II", buf, 80, 0, 0)
    struct.pack_into("<II", buf, 88, 1, method_ids_off)
    struct.pack_into("<II", buf, 96, 1, class_defs_off)
    struct.pack_into("<II", buf, 104, len(data), data_off)
    for i, off in enumerate(string_offsets):
        struct.pack_into("<I", buf, string_ids_off + i * 4, off)
    for i, type_idx in enumerate(types):
        struct.pack_into("<I", buf, type_ids_off + i * 4, type_idx)
    struct.pack_into("<III", buf, proto_ids_off, *proto)
    struct.pack_into("<HHI", buf, method_ids_off, *method)
    struct.pack_into("<IIII", buf, class_defs_off, class_def[0], class_def[1], class_def[2],
                     class_def[3])
    buf[data_off:total] = data
    buf[12:32] = hashlib.sha1(bytes(buf[32:total])).digest()
    struct.pack_into("<I", buf, 8, zlib.adler32(bytes(buf[12:total])) & 0xFFFFFFFF)
    return bytes(buf)


def build_zip(files) -> bytes:
    import io
    import zipfile
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in files:
            archive.writestr(name, payload)
    return buffer.getvalue()


def build_apk(elf: bytes, dex: bytes) -> bytes:
    return build_zip([
        ("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 60),
        ("classes.dex", dex),
        ("res/layout/main.xml", b"<layout/>"),
        ("lib/arm64-v8a/libdemo.so", elf),
        ("lib/x86_64/libdemo.so", elf),
    ])


def build_ipa(macho: bytes) -> bytes:
    framework = macho[:0x1000]
    return build_zip([
        ("Payload/Demo.app/Demo", macho),
        ("Payload/Demo.app/Info.plist", b"<?xml version=\"1.0\"?><plist><dict/></plist>"),
        ("Payload/Demo.app/Frameworks/Kit.framework/Kit", framework),
        ("Payload/Demo.app/embedded.mobileprovision", b"\x00" * 32),
    ])


def validate(path: pathlib.Path) -> str:
    try:
        import lief
    except ImportError:
        return "lief-missing"
    try:
        if path.suffix in (".so", ".elf"):
            binary = lief.ELF.parse(str(path))
            return "ELF arch=%s sections=%d" % (binary.header.machine_type, len(binary.sections))
        if path.name == "ios_demo":
            binary = lief.MachO.parse(str(path))
            return "MachO slices=%d" % len(binary)
        if path.suffix == ".dex":
            if hasattr(lief, "DEX"):
                binary = lief.DEX.parse(str(path))
                return "DEX strings=%d" % len(binary.strings)
            return "lief-DEX-missing"
    except Exception as exc:  # noqa: BLE001 - validation is advisory
        return "FAILED: %s" % exc
    return "skipped"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    elf = build_elf_arm64()
    macho = build_macho_arm64()
    dex = build_dex()
    files = {
        "arm64_demo.so": elf,
        "ios_demo": macho,
        "classes.dex": dex,
        "demo.apk": build_apk(elf, dex),
        "demo.ipa": build_ipa(macho),
    }
    for name, payload in files.items():
        path = OUT / name
        path.write_bytes(payload)
        print("%-16s %8d bytes  %s" % (name, len(payload), validate(path)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
