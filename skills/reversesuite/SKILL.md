---
name: reversesuite
description: Static multi-format analysis with ReverseSuite - Windows PE, iOS Mach-O (.ipa), Android (.apk/.dex/.so), strings, functions, call graphs, diffs and reports.
---

# ReverseSuite

## Overview

สแตติกวิเคราะห์ไบแนรี (ไม่รันไฟล์เป้าหมาย) รองรับ 4 ตระกูลไฟล์:

- **Windows PE** - `.exe` / `.dll` / `.sys` (x86/x64/ARM64): import, export, section, strings + xref, function discovery, call graph, diff, report
- **iOS Mach-O** - `.ipa` (แตก ZIP อัตโนมัติ) หรือ Mach-O เดี่ยว: arm64 prologue discovery, `bl` call targets, `__cstring` strings, FairPlay `cryptid` detection
- **Android** - `.apk` (แตก ZIP): ถอด binary `AndroidManifest.xml` (package, version, min/target SDK, permissions, components + exported, debuggable/allowBackup) + `classes*.dex` inventory + method-level call graph (invoke edges, framework hidden) + `lib/<abi>/*.so` ผ่าน ELF loader
- **Android/Linux ELF** - `.so` (arm64, x86_64, x86, arm): sections, dynsym, ARM64/UDF prologues

## When to use

- ตรวจไฟล์ `.exe`/`.dll`/`.so`/`.dylib`/`.dex` หรือแพ็กเกจ `.apk`/`.ipa`: โครงสร้าง, ฟังก์ชัน, สตริง, การเรียกใช้
- เทียบสองบิลด์ (เก่า/ใหม่) ว่าเพิ่ม/ลบ/ย้ายอะไร แล้วออกรายงาน
- ให้เครื่องมืออื่นเรียกผ่าน HTTP loopback (API + token)

ไม่ใช้เมื่อ: ต้องการรัน/ดีบักไบแนรี (static only), ไฟล์ `.text` ใหญ่เกิน 32 MB สำหรับ function/xref, หรือต้องการ disassemble Dalvik bytecode ทุก opcode (เวอร์ชันนี้สร้างกราฟจาก stream ของ `invoke` เท่านั้น)

## Usage

```powershell
$py = "projects\reversesuite\.venv\Scripts\python.exe"
$env:PYTHONPATH = "projects\reversesuite\src"

# Windows PE
& $py -m reversesuite.cli analyze fixtures\frozen\b.exe
& $py -m reversesuite.cli calls fixtures\frozen\b.exe --json

# iOS: อ่าน .ipa ทั้งแพ็กเกจ (Mach-O + __cstring + ARM64 functions)
& $py -m reversesuite.cli analyze MyApp.ipa
& $py -m reversesuite.cli analyze MyApp.ipa --no-members      # เฉพาะสรุปแพ็กเกจ

# Android: .apk (classes.dex + lib/arm64-v8a/*.so)
& $py -m reversesuite.cli analyze app-release.apk        # manifest + dex + .so
& $py -m reversesuite.cli analyze app-release.apk --json # ดู permission/component findings
& $py -m reversesuite.cli analyze classes.dex --json          # มี dex_graph
& $py -m reversesuite.cli analyze classes.dex --all-methods   # เก็บ java.*/android.* ด้วย
& $py -m reversesuite.cli analyze lib/arm64-v8a/libnative.so

# diff + report (PE)
& $py -m reversesuite.cli diff fixtures\frozen\b.exe fixtures\frozen\a.exe --ignore-thunks
& $py -m reversesuite.cli report b.exe a.exe --format html --out out.html

# local API/UI: stderr พิมพ์ "PORT=<n> TOKEN=<token>" บรรทัดแรก
& $py -m reversesuite.cli serve --port 0
```

DEX call graph ใน JSON (`analyze ... --json`):

```json
{"dex_graph": {"nodes": [{"id": 0, "label": "com.demo.App.run", "class": "com.demo.App", "framework": false}],
               "edges": [{"caller": 0, "callee": 1, "kind": "virtual"}],
               "stats": {"methods": 2, "edges": 1, "scanned": 2, "with_code": 2,
                         "hidden_framework": 1, "decode_errors": 0}}}
```

เรียกจาก API: `POST /analyze`, `/diff`, `/report` พร้อม header `Authorization: Bearer <token>`; รับ `path`, URL หรือ `upload_id` (`POST /upload`)
- `{"dex_all_methods": true}` เก็บ `java.*`/`android.*` ในกราฟ DEX
- `api.serve(upload_parent=...)` ย้ายโฟลเดอร์ upload/download ไปที่อื่น (จำเป็นเมื่อ antivirus บล็อกการอ่าน PE ใน `%TEMP%`)
- URL input: โฟลเดอร์ temp ถูกลบใน `finally` ทุกครั้ง (แก้ใน 0.5.1)
UI รับไฟล์ `.apk`/`.ipa`/`.so`/`.dex` เพิ่มจาก `.exe`/`.dll` แล้ว (ตรวจ magic bytes ไม่ใช่แค่นามสกุล)

## Verification

```powershell
& $py -m unittest discover -s tests -t tests
# expected: OK (192 tests, 2 skipped เมื่อไม่มี objdump/gcc ที่ pin ไว้)
& $py skills\validate_skills.py
# expected: ผ่านทุก skill (name/description/หัวข้อครบ)
& $py fixtures\gen_multi.py
# regenerates fixtures/multi/{arm64_demo.so,ios_demo,classes.dex,demo.apk,demo.ipa}
```

## Limits

- static only: ไม่รัน target; indirect call ที่ต้องใช้ dataflow ลึกยังไม่ resolve (M6.2/M6.3 deferred)
- เพดาน 32 MB ของ `.text` สำหรับ function discovery/xref (ไฟล์ใหญ่ขึ้นไปจะได้ diagnostic)
- Dalvik bytecode: อ่าน classes/methods/strings + สร้าง call graph จาก `invoke-*`; opcode อื่นไม่ถูก disassemble และ dynamic dispatch ยังชี้ที่ declared method
- FairPlay-encrypted iOS binaries (`cryptid != 0`) ให้ผลเป็น ciphertext; ต้องถอดรหัสก่อน
- URL: จำกัด 256 MB, timeout 30 s, บล็อก private/link-local (ยกเว้น loopback)
- rate limit 60 req/min ต่อ client
- runtime ไม่พึ่ง lief/androguard (stdlib only) เพื่อคุมขนาดตัวติดตั้ง; lief ใช้เฉพาะตอนสร้าง fixture/ตรวจสอบ
