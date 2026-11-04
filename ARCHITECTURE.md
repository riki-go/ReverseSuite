# ReverseSuite — Architecture v0.1

เครื่องมือ reverse engineering แบบ standalone (ไม่ต้องใช้ AI agent) + GUI

## 1. เป้าหมาย
- แกะได้: เว็บไซต์/JS bundle, binary (PE/ELF/Mach-O), .NET, Android APK, Electron (asar)
- GUI สวย ใช้งานจริง (desktop app)
- ฟื้นชื่อ symbol ที่โดน strip ให้ "ใกล้เคียงที่สุด" พร้อมระดับความมั่นใจ
- ทำงาน offline, deterministic, ไม่พึ่ง cloud/LLM

## 2. Stack
- Core engine: Python 3.12 (LIEF, pefile, capstone, pyelftools, dnfile, jadx, acorn/esprima ผ่าน Node worker)
- Service: FastAPI + WebSocket (local only, 127.0.0.1)
- GUI: Tauri 2 (Rust shell) + React + TypeScript + Monaco Editor + Cytoscape (xref graph)
- DB: SQLite (analysis cache, symbol DB, projects) + content-addressed artifact store
- Report: Markdown/HTML -> PDF (WeasyPrint)
- Packaging: single installer (MSI), auto-update optional

## 3. โครงสร้างโปรเจกต์
/reversesuite
  /core            # analysis engines + orchestrator
    /loaders       # pe.py elf.py macho.py dotnet.py apk.py jsbundle.py
    /disasm        # capstone wrappers, ilspy, jadx bridges
    /symbols       # symbol recovery pipeline (หัวใจ)
    /diff          # version matching
    /web           # crawler, sourcemap, api-extract
  /server          # FastAPI routes + ws events + job queue
  /ui              # Tauri + React app
  /plugins         # engine plugins (ghidra_headless, ida_bridge optional)
  /tests           # golden cases + fixtures
  /docs

## 4. Pipeline หลัก
1. Ingest: ตรวจชนิดไฟล์, hash, unpack (asar/zip/apk), ตรวจ packer/protector
2. Static triage: sections, imports/exports, strings, entropy, compiler signature
3. Disassembly: capstone (raw) หรือ engine plugin (ghidra headless)
4. CFG + call graph: basic blocks, xrefs, vtable/RTTI
5. Symbol recovery (ดูข้อ 5)
6. Type/struct recovery: heuristic จาก access pattern + RTTI
7. Evidence store: ทุกข้อสรุปมีที่มา (offset, xref, rule id)
8. Export: .map, Ghidra script, IDA .idc, r2 project, Markdown report

## 5. Symbol Recovery Pipeline (ข้อ 5 ของผู้ใช้)
สำคัญ: ชื่อเดิม "กู้คืนไม่ได้" ถ้า metadata ถูกตัด — ทำได้คือ "อนุมาน" พร้อม confidence
L0 Exact: PDB/DWARF/COFF/Go pclntab/.NET metadata/JS sourcemap -> ชื่อจริง 100%
L1 Downloadable: Microsoft symbol server, debuginfod, NuGet snupkg
L2 Library match: FLIRT/FID signatures, r2 sigs, Ghidra FID, Lumina -> ชื่อฟังก์ชัน library จริง
L3 Demangle: C++/Rust/MSVC decorated names -> ชื่อ readable
L4 Heuristic naming: import usage, string refs, call patterns, error messages
   (เช่น "RegOpenKeyEx + path string" -> suggest open_registry_key)
L5 Optional ML model (offline, plugin): decompiler-name-prediction — ต้องโหลดโมเดลเอง ไม่บังคับ
UI: แสดงชื่อเป็น "suggested_name (L4, 62%)" ผู้ใช้แก้/ยืนยันได้ -> symbol DB ถาวรต่อโปรเจกต์

## 6. GUI (หน้าจอ)
- Project hub: รายการ target, ประวัติ scan, diff timeline
- Analyzer: tree (sections/classes/functions) | center (disasm/decompile) | right (xref, strings, evidence)
- Symbol Workbench: ตารางชื่อที่อนุมาน + confidence + ยืนยัน/แก้ + bulk accept
- Diff view: 2 versions side-by-side, function matching, changed bytes/functions
- Web Analyzer: รายการ endpoint, secrets scan, sourcemap recovery, dependency graph
- Report builder: เลือกส่วน -> export PDF/MD
- Thai UI + English toggle

## 7. จุดที่ "ดีกว่า" เครื่องมือเดิม
- Standalone GUI ไทย (REA เป็น agent/CLI)
- เก็บ evidence ทุกข้อสรุป (audit ได้)
- Symbol DB ต่อโปรเจกต์ + export ไป Ghidra/IDA ได้
- Version diff ในตัว (ฟีเจอร์ที่คนใช้จริงต้องการที่สุด)
- Web/Electron analyzer รวมในที่เดียวกับ binary analyzer
- ไม่กิน token/ไม่ต้องต่อเน็ต

## 8. Roadmap
M1 (2 สัปดาห์): PE loader + capstone + strings/imports + GUI shell + symbol L0/L3
M2 (2 สัปดาห์): symbol L2 (library sigs) + workbench + export
M3 (2 สัปดาห์): .NET + APK + JS bundle analyzer
M4 (2 สัปดาห์): diff engine + report + packaging MSI

## 9. ความเสี่ยง
- ชื่อเดิมกู้ไม่ได้ถ้าไม่มี metadata (ต้องสื่อสารกับผู้ใช้ให้ชัด)
- packed/protected binaries ต้องใช้ dynamic analysis (แยกเฟส)
- กฎหมาย: วิเคราะห์ได้ แต่ห้ามนำโค้ด/asset ผู้อื่นไปใช้ต่อโดยไม่ได้รับอนุญาต
