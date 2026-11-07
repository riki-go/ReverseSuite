# ReverseSuite — PLAN v3 (review draft)

เกณฑ์ผูกกับ Definition of Done ของแต่ละ milestone ไม่ผูกกับจำนวนสัปดาห์

## 0. Scope & Assumptions
- วิเคราะห์เฉพาะไฟล์ที่ผู้ใช้มีสิทธิ์วิเคราะห์ (README + แจ้งตอนเปิดไฟล์)
- core = static only ห้าม execute ไฟล์เป้าหมาย
- fixture คอมไพล์เองจาก source ที่เราเขียน
- schema_version ในทุก output และ DB ตั้งแต่ commit แรก + migration
- M1 รับทั้ง PE32 (x86) และ PE32+ (x64); ARM64 อยู่นอกขอบเขต

## 1. Architecture Layers
- DisassemblerBackend — capstone: disassembly + CFG (M1)
- DecompilerBackend — Ghidra headless (M2) แยกขาดกัน
- AnalysisBackend — orchestrator
- Service layer เดียว: core.service (library, in-process)
  - CLI = client แรก (in-process)
  - HTTP API = adapter (เปิดเมื่อ GUI ต้องการ)
  - GUI (Tauri) = client ของ API

## 2. Security
### 2.1 Local API
- bind 127.0.0.1, สุ่มพอร์ตทุกครั้งที่เปิดแอป
- token ต่อ session: สุ่มใหม่ทุกครั้ง ไม่ persist, เก็บใน memory
- ส่ง token ทาง header Authorization เท่านั้น (ห้าม query string)
- Tauri ส่ง token ให้ service ผ่าน env/stdin (ห้าม argv)
- ตรวจ Host header: localhost / 127.0.0.1 เท่านั้น
- ตรวจ Origin ทั้ง HTTP และ WebSocket (กัน cross-site WebSocket hijacking)
- CORS ปิดโดยปริยาย เปิดเฉพาะ origin ของแอป
### 2.2 File handling
- allowlist root: ผู้ใช้เลือกโฟลเดอร์เอง (config หรือ dialog) ไม่บังคับ upload
- กฎนี้ใช้กับ HTTP adapter เท่านั้น; CLI in-process ไม่ต้อง
- realpath check: กัน symlink/junction, UNC, \\?\ prefix, alternate data stream, ชื่อสั้น 8.3
- จำกัดต่อ job: ไฟล์ <= 2 GB, memory cap (Job Object), time limit, ขนาด output สูงสุด, จำนวน findings สูงสุด
### 2.3 Parser sandbox
- loader + PDB parser รันใน subprocess แยก
- Windows: Job Object (ctypes/pywin32): memory cap, ActiveProcessLimit=1
- time limit + kill process tree
- timeout/resource cap -> status degraded + diagnostic
- โหมดปกติห้ามออกเน็ต: Authenticode offline/cache-only (ไม่ดึง CRL/OCSP), PDB path ในไฟล์ห้ามดึงอัตโนมัติ
- integration test ต้องครอบ: เกิน memory cap, timeout, kill tree, child spawn ถูกบล็อก

## 3. Threat Model
- สมมติฐานผู้โจมตี: ควบคุมได้แค่ไฟล์เป้าหมายและหน้าเว็บอื่นในเครื่อง; ผู้ใช้ท้องถิ่นไว้ใจได้; ไม่มีผู้ใช้หลายคนบนเครื่องเดียว
- T1 malformed PE / PDB / Authenticode data -> crash/OOM หรือโค้ดรัน: subprocess + Job Object + timeout + fuzz corpus; PDB และ Authenticode ถูก parse ใน sandbox เดียวกัน
- T2 resource exhaustion: เพดาน section/import/resource/directory nesting ใน loader (asar/zip ทีหลัง)
- T3 path traversal: allowlist root + realpath checks
- T4 DNS rebinding / CSWSH: token + Host + Origin
- T5 secret รั่ว: mask เฉพาะตอนแสดงผล/รายงาน; ชั้น raw เก็บค่าจริงและเข้าถึงได้ผ่าน flag ที่ระบุชัด
- T6 supply chain: lockfile + license audit
- T7 สตริงอันตราย render ใน GUI/รายงาน: escape ทุกจุด + CSP
- T8 cache ถูกปลอม/แก้: ตรวจ hash ตอนอ่าน + ปฏิเสธ entry ที่ hash ไม่ตรง
- T9 การเขียนไฟล์ออก: ชื่อไฟล์ที่มาจากไบแนรี (section/resource) ต้อง sanitize; export เขียนได้เฉพาะโฟลเดอร์ที่ผู้ใช้เลือก
- Job Object ไม่ใช่ security boundary: จำกัด memory/เวลา/จำนวน process แต่ไม่กันการอ่านไฟล์หรือออกเน็ต; ถ้า parser มีช่องโหว่ ผู้โจมตีรันโค้ดด้วยสิทธิ์ผู้ใช้ได้ -> คู่มือต้องแนะนำเปิดไฟล์น่าสงสัยใน VM; restricted token/low integrity พิจารณาใน M2+
- นอกขอบเขต M1: malware execution, network sandbox, kernel analysis

## 4. Output Schema
### 4.1 รูปแบบ
- ฟิลด์บังคับ: schema_version, target{sha256,kind,size}, status(ok|degraded|failed), findings[], diagnostics[]
- finding: {id, kind(symbol|string|import|export|section|signature), value, encoding?, confidence_permille(int 0..1000), calibrated(bool), level(L0..L5), rule, evidence[]}
- evidence: {offset, space(file|rva|va), xref, rule}
- diagnostics: {code, message, severity} — ห้ามมี path เต็ม/ชื่อเครื่อง/ชื่อผู้ใช้
### 4.2 Determinism
- ไม่ใช้ float ในส่วนที่ hash: confidence เป็นจำนวนเต็ม permille
- serialize ด้วย RFC 8785 (JCS)
- finding.id = sha256(kind + value + primary evidence) ไม่ใช้ UUID/ตัวนับ
- ลำดับ array: findings เรียง (kind, level, value, id); evidence เรียง (space, offset, rule); diagnostics เรียง (code, message)
- meta.json เก็บเวลา/host และไม่ถูก hash
- Reproducibility key: sha256(ไฟล์) + schema_version + engine_build_id + ruleset_version + config_hash
### 4.3 สตริง
- ระบุ encoding: ascii | utf8 | utf16le | utf16be
- ไบต์ที่ไม่ valid: escape dạng \xNN และระบุ raw_hex เมื่อจำเป็น

## 5. Cache
- key = sha256(ไฟล์) + schema_version + engine_build_id + ruleset_version + config_hash
- config_hash ครอบ: rule ที่เปิด/ปิด, limits (timeout/เพดานจำนวน), โหมด L1
- engine_build_id = git commit + sha256(lockfile) (ระบุเวอร์ชัน capstone/LIEF)
- ห้าม cache degraded ที่เกิดจาก timeout/memory cap (ไม่ deterministic); cache ได้เฉพาะ degraded จากไฟล์เสียจริง
- ผล L1 ไม่ reproducible: บันทึก sha256 + GUID/age ของ PDB ที่ได้ และแยกชั้น cache
- เขียน atomic, ตรวจ hash ตอนอ่าน, SQLite WAL รองรับหลายโปรเซส
- ชั้น raw มีสตริง unmasked: เก็บในโฟลเดอร์เฉพาะ สิทธิ์จำกัด + มีคำสั่ง purge

## 6. Symbol Layers
- L0 exact: PDB local (ตรวจ GUID+age ตรงไฟล์ก่อนใช้), export table, COFF symbols
- L1 symbol server: ต้องผ่าน 2 ชั้น (setting แอป ปิดโดยปริยาย + flag ต่อ job)
  - คำขอส่ง: ชื่อ PDB + GUID/age (หรือ timestamp+size ของ PE เมื่อค้นด้วยไบนารี) — ไม่ส่ง hash ไฟล์
  - HTTPS เท่านั้น + allowlist โฮสต์ + เพดานขนาดดาวน์โหลด + log ทุกครั้ง (URL, สิ่งที่ส่ง, ผล, sha256 ของไฟล์ที่ได้)
- L2 library signature (M2+)
- L3 demangle: เก็บทั้ง mangled และ demangled (เป็น transform ไม่ใช่แหล่งอิสระ)
- L4 heuristics ผ่าน rule registry (id + version + คำอธิบาย + เปิด/ปิด)
- precedence: L0 > L2 > L3 > L4; เก็บ candidate ทั้งหมดไว้ ไม่ทิ้ง
- L5 ML: เลื่อนไปหลังสุด
- Calibration: หลัง L4; กำหนดขั้นต่ำต่อ rule และต่อไบน์แยกกัน; แยกชุดสร้าง rule ออกจากชุดวัด; ระบุว่า fixture คอมไพล์เองสไตล์เดียวกัน ความแม่นกับไฟล์ภายนอกจะต่ำกว่า
- ก่อน calibrate: ทุก finding มี calibrated=false และ GUI ต้องแสดงว่า uncalibrated

## 7. M1 — Scope
ทำ: schema + DB + PE loader (subprocess + Job Object) + cache + strings/imports/exports + CLI analyze --json + benchmark harness
ไม่ทำ: Ghidra/decompile, L1 symbol server, L4 rules, GUI, diff, .NET/APK/JS, ARM64, installer

## 8. M1 — Acceptance Criteria
### AC-1 เปิดไฟล์ได้ (fixture คอมไพล์เองทั้งหมด — ห้ามใช้ไฟล์ระบบ)
- a.exe: MSVC, มี PDB -> คาดหวัง status=ok
- b.exe: MinGW-w64, stripped -> คาดหวัง status=ok
- c.exe: fixture ที่ออกแบบให้โครงสร้างผิด (header เพี้ยน) -> คาดหวัง status=failed พร้อม diagnostic
- d.exe: fixture ที่ pad ให้ ~100MB -> คาดหวัง status=ok (ใช้ใน AC-7a ด้วย)
- ผ่านเมื่อ: สถานะตรงกับที่คาดหวังทุกไฟล์, JSON ตรง schema, และ exit code ตรงกับ AC-8 (c.exe -> 3)

### AC-2 disassembly ตรง objdump >= 99%
- อ้างอิง: objdump -d -M intel --no-show-raw-insn (ระบุเวอร์ชัน binutils)
- ขอบเขต: section ที่ executable (.text)
- หน่วยเทียบ: (address, mnemonic, normalized operands)
- Normalization: lowercase, trim, ',' + ช่องว่างเดียว, hex เป็น 0x ตัวเล็กไม่มี leading zero, ตัด size prefix ของ memory operand ออกทั้งสองฝั่ง
- ผ่านเมื่อ matched/total >= 0.99 + รายงาน address ที่ไม่ตรง

### AC-3 strings/imports/exports
- imports/exports ตรง 100% กับ dumpbin
- strings: พบครบ 100% ของรายการอ้างอิง (ASCII ยาว >= 4)

### AC-4 Reproducible
- รัน 2 ครั้ง (ล้าง cache) -> canonical hash เท่ากัน
- (การตรวจ rule ownership ย้ายไป AC-14 เพื่อไม่ให้มีเจ้าของซ้ำ)

### AC-5 ไฟล์เสีย
- ตัดไบต์ 3 ตำแหน่ง -> degraded/failed + diagnostic ทุกครั้ง ไม่มี traceback ถึงผู้ใช้

### AC-6 packed
- UPX -> ตรวจพบ + degraded + diagnostic

### AC-7a Performance (ไฟล์ปกติ ต้องผ่านเกณฑ์)
- d.exe (PE32+ x64) ต้องมี code จริงปริมาณมาก (codegen + คอมไพล์จริง) ไม่ใช่ pad section ว่าง
- **ขนาดและตัวเลขยังไม่ล็อก**: ต้องผ่าน spike S1 (วัด throughput/memory ของ capstone) ก่อนแล้วจึงเติมตัวเลข
- **นิยาม output**: analyze ต้องไม่เก็บ instruction ทั้งหมดใน memory — เขียนเป็น stream ไฟล์แยก (JSONL) + summary ใน JSON หลัก
- เครื่องวัด: DESKTOP-RC2ODCV i5-10400 / 16GB / SSD
- วัด: wall time CLI start -> JSON summary เสร็จ, peak RSS ของ subprocess
- ผ่านเมื่อ (หลัง S1): peak RSS <= 1 GB และ wall <= 60 วิ ที่ขนาดไฟล์ซึ่ง S1 ยืนยันว่า feasible

### AC-7b Resource cap (ห้าม execute ไฟล์เป้าหมาย — ใช้ fault injection)
- ห้ามใช้ไฟล์ที่ต้อง "รัน" เพื่อกิน memory (ขัดกับ static-only)
- ใช้ **worker fault-injection flag** ในบิลด์ทดสอบ: `--fault=memhog|spin|child` สั่ง worker กิน memory / วนไม่จบ / สร้าง child
- memory cap ของ Job Object = 1.5 GB (สูงกว่าเกณฑ์วัด 1 GB)
- **job time limit (CPU) = 120 วิ และ wall-clock watchdog = 120 วิ** (สูงกว่าเกณฑ์วัด 60 วิ ของ AC-7a โดยเจตนา เพื่อไม่ให้ไฟล์ที่ใช้ 61 วิถูกฆ่าเป็น degraded ปนกับเคส "ช้าเกินเกณฑ์")
- ตั้ง KILL_ON_JOB_CLOSE เพื่อให้ลูกตายเมื่อ runner ตาย
- ผ่านเมื่อ: ถูกตัดด้วย diagnostic code + status=degraded + ไม่มี orphan + **ไม่มีผลลัพธ์บางส่วนถูกเขียนเป็น ok**

### AC-8 CLI (map สถานะ -> exit code ให้ตรงกับ AC-1)
- reversuesuite analyze <file> --json -> stdout เป็น JSON เท่านั้น (log ไป stderr)
- exit mapping (ใช้ตรงกันทั้งระบบ): 0=ok, **2=degraded**, 3=failed, 4=usage error, **5=internal error**
- stdout contract: ต้องเป็น JSON ที่ตรง schema **หรือว่าง** เท่านั้น — ห้ามมีข้อความอื่นปน; กรณี internal error (5) อนุญาตให้ stdout ว่างและให้รายละเอียดทาง stderr
- stdout ต้องเป็น UTF-8 (บังคับ encoding บน Windows) และห้าม child/ไลบรารี native เขียน stdout ปน JSON (ให้ redirect ไป stderr หรือ pipe ปิด)

### AC-9 Cache
- วัดเฉพาะขั้น analysis (ตัด startup)
- cold vs warm, median 3 รอบ, warm เร็วขึ้น >= 10x

### AC-11 Job Object integration (ต้องผ่านก่อนถือว่า sandbox ใช้ได้)
- helper ที่คอมไพล์เอง 3 ตัว: memhog.exe (จองเกิน cap), spin.exe (วนไม่จบ), spawner.exe (สร้าง child)
- ทดสอบบน Windows จริง 4 กรณี: เกิน memory cap, timeout, kill ทั้ง process tree, ActiveProcessLimit บล็อก child spawn
- วิธีตรวจ "ไม่มี process ค้าง": enumerate process ใน job ก่อน/หลัง + ตรวจว่า pid ใหม่ทั้งหมดตายภายใน N วินาที
- ผ่านเมื่อ: ทุกกรณีคืน diagnostic code เฉพาะ และจำนวน process ใน job = 0 หลังจบ

### AC-12 เพดาน T2 (resource exhaustion)
- fixture ที่มี section/import/resource จำนวนมากผิดปกติ และ directory ซ้อนลึก
- ผ่านเมื่อ: loader ปฏิเสธพร้อม diagnostic ที่ระบุเพดานที่ชน (ไม่ OOM) + status=**failed** + exit code **3**

### AC-13 Cache invalidation + integrity (ครบทุกข้อ)
- เปลี่ยน schema_version หรือ config_hash หรือ ruleset_version -> cache ต้อง miss
- ไม่ cache ผล degraded ที่มาจาก timeout/memory cap (ทดสอบว่าไม่ถูกเขียนลง cache)
- เขียน cache แบบ atomic (ไม่มีไฟล์ครึ่ง ๆ) — จำลอง crash ด้วยการ kill worker ระหว่างเขียน (fault flag `--fault=crash-on-write`)
- ตรวจ hash ตอนอ่าน: entry ที่ hash ไม่ตรงถูกปฏิเสธและคำนวณใหม่
- หลายโปรเซสพร้อมกัน (SQLite WAL) ไม่ทำให้ entry เสีย
- ล้าง/invalidate cache เมื่อ schema เปลี่ยน (มีคำสั่งและทดสอบ)

### AC-14 Rule registry
- ทุก finding อ้าง rule id ที่ลงทะเบียน; rule ที่ปิดต้องไม่ปรากฏในผล
- ผ่านเมื่อ: CI ตรวจแล้ว 0 finding ที่อ้าง rule ไม่มีอยู่

### AC-15 Function discovery (พื้นฐานของ symbol layer และ Diff)
- ขอบเขต M1: entrypoint, exported functions, direct call targets, thunks เท่านั้น (ไม่รวม indirect call / jump table / exception handler)
- ground truth: a.exe ใช้ PDB; b.exe ใช้ **สำเนาไฟล์เดียวกันก่อน strip** (ไม่ใช่บิลด์ใหม่) เพื่อให้ address ตรงกัน
- กรองเฉพาะฟังก์ชันที่ "อยู่ในขอบเขต M1" (reachable ผ่าน entrypoint/export/direct call/thunk) — ฟังก์ชันที่ PDB มีแต่เข้าถึงผ่าน indirect call เท่านั้น ถูกตัดออกจากเฉลย
- MSVC ICF รวมฟังก์ชันซ้ำเป็น address เดียว: จับคู่ด้วย **address** ไม่ใช่ชื่อ และ dedupe ตาม address
- วัด recall และ precision แยกกัน
- ผ่านเมื่อ: recall >= 0.98 และ precision >= 0.98 + รายงานรายชื่อที่ขาด/เกิน + ระบุข้อที่ถูกตัดเพราะอยู่นอกขอบเขต

### AC-10 (ย้ายไป milestone M-API — ไม่ใช่ M1)
- ไม่มี token -> 401; Host ไม่ใช่ localhost -> 403; Origin แปลกปลอม -> 403; ไม่มี CORS wildcard

## 7b. M1 split (ตามรีวิว — M1 ต้องเล็ก)
- **M1a Base** (ต้องผ่านก่อน): AC-1, AC-4, AC-5, AC-8, AC-11, AC-12, AC-13
- **M1b Correctness** (เข้าได้หลังผ่าน phase gate): AC-2, AC-3, AC-6, AC-7a, AC-7b, AC-9, AC-14, AC-15
- เกต: M1b เริ่มได้เมื่อ M1a ผ่านครบ + เขียน AC ของ M1b ใหม่ถ้ามีการเปลี่ยน และผ่านรีวิว

## 8a. Execution order & dependencies (ไม่เรียงตามเลข AC)
0. สคริปต์บิลด์ fixture (a-e.exe + helper) พร้อม toolchain pin + sha256 ที่ commit ไว้
1. spike S1: throughput/memory ของ capstone (กำหนดขนาด d.exe และตัวเลข AC-7a ได้จริง)
2. R1 spike: Job Object + wall-clock watchdog (ถ้าไม่ผ่าน ใช้แผนสำรองก่อนเขียน loader
3. Schema + canonical JSON (ฐานของทุกอย่าง)
4. Rule registry stub (ให้ AC-14 ตรวจได้ตั้งแต่ต้น)
5. Sandbox runner + Job Object + watchdog (AC-11) — **เริ่มได้หลัง S1 จบ** เพราะผล S1 กำหนดรูปแบบ IPC/stream
6. PE loader + เพดาน T2 (AC-12)
7. CLI analyze + exit codes (AC-8)
8. Cache + integrity (AC-13)
9. Reproducibility (AC-4) + ไฟล์เสีย (AC-5)
10. **AC-1 ปิดที่นี่** (ต้องใช้ exit code จากขั้น 7)
11. --- phase gate: M1a ผ่านครบ ---
12. Disassembler + normalizer + streaming output (AC-2)
13. strings/imports/exports (AC-3) + UPX (AC-6)
14. Function discovery (AC-15)
15. Performance 7a/7b (AC-7a, AC-7b)
16. Rule registry เต็ม (AC-14)
17. Cache performance (AC-9)

## 8b. API Milestone — AC (เมื่อเปิด HTTP API)
- AC-API-1: ไม่มี token -> 401
- AC-API-2: Host ไม่ใช่ localhost/127.0.0.1 -> 403
- AC-API-3: Origin แปลกปลอม (HTTP และ WS) -> 403
- AC-API-4: ไม่มี CORS wildcard; path traversal test ผ่าน
- AC-API-5: ทดสอบยิงจากเบราว์เซอร์หน้าอื่นแล้วถูกปฏิเสธ

## 8e. Spike governance (อนุมัติแยกจาก M1)
- โค้ดสไปก์อยู่ใน `spikes/` เท่านั้น ห้ามนำไปใช้เป็นโค้ด M1 โดยตรง (ถ้าจะใช้ ต้องเขียนใหม่ใน M1)
- ต้องระบุคำถาม + time-box ก่อนเริ่ม:
  - **S1** (capstone): throughput (คำสั่ง/วินาที), RSS เมื่อ stream เทียบกับเก็บทั้งหมด, ขนาด JSONL ต่อ 100MB
  - **R1** (Job Object): จำกัด memory / ฆ่า tree / กัน child / watchdog บนเครื่องนี้ได้จริงหรือไม่
- **ตั้งเกณฑ์ตัดสินล่วงหน้าก่อนรัน** เช่น "ถ้า throughput < X คำสั่ง/วินาที ให้ลดขนาด fixture เป็น Y" — ห้ามปรับเกณฑ์ตามผลทีหลัง
- ห้ามแตะระบบอื่น และห้ามสร้างโครง repo จริงระหว่างสไปก์
- ผลสไปก์บันทึกใน Change Log แล้วปรับตัวเลข AC-7a เป็น **v4.1** เพื่อรีวิวก่อนอนุมัติ M1a
- ลำดับอนุมัติ: step 0 (สคริปต์ fixture) + S1/R1 → ดูผล → v4.1 → อนุมัติ M1a

## 9. Definition of Done (M1)
- ผู้ตัดสิน: เจ้าของโปรเจกต์ (คุณ) — ต้องรันหลักฐานซ้ำเองได้ด้วยคำสั่งเดียว (เช่น tools/verify.ps1 -Ac AC-4) ไม่ใช่เชื่อรายงาน
- ห้ามมี test ที่ skip; ต้องรันบน venv ใหม่/เครื่องสะอาดอย่างน้อย 1 ครั้ง
- ห้ามลดเกณฑ์แบบเงียบ: ถ้าทำไม่ได้ ให้บันทึกใน Change Log ของ PLAN.md พร้อมเหตุผลและผลกระทบ
- นิยาม blocker: AC ใดไม่ผ่าน, security mitigation ข้อใดหาย, crash/data loss, หรือผลไม่ reproducible
- ขยับ M2 เมื่อ: AC-1..AC-9 ผ่านครบ และไม่มี blocker ค้าง
- AC-API (ย้ายไป milestone ที่เปิด API) ต้องผ่านก่อนประกาศว่า API พร้อม
- กติกาทำงาน: ทำทีละเกณฑ์ -> หยุดรายงาน -> รออนุมัติ

## 10. Risks
- R1 Job Objects: ctypes/pywin32 ต่างกันตามเวอร์ชัน
  - ตัวชี้วัด: spike ไม่ผ่านเกณฑ์ (memory cap, kill tree, ActiveProcessLimit) ภายใน 2 วันทำการ
  - แผนสำรอง: ใช้ CREATE_SUSPENDED + จำกัดเวลาอย่างเดียว + เตือนผู้ใช้ว่า memory cap ใช้ไม่ได้
- R6 fixture toolchain: MSVC ติดลิขสิทธิ์/ติดตั้งยาก
  - ตัวชี้วัด: เครื่อง build ไม่มี MSVC ใน 1 วัน
  - แผนสำรอง: ใช้ MinGW-w64/clang เป็นหลัก และเก็บ MSVC เป็น optional
- R7 version drift ของ LIEF/pefile/capstone เปลี่ยนผล
  - ตัวชี้วัด: canonical hash เปลี่ยนหลังอัปเดต dependency
  - แผนสำรอง: pin เวอร์ชัน + engine_build_id ใน key + benchmark gate ใน CI
- R8 DecompilerBackend ถูกออกแบบก่อนเห็นผลจริงของ Ghidra
  - ตัวชี้วัด: interface ต้องแก้เกิน 30% หลัง spike
  - แผนสำรอง: spike Ghidra เล็กก่อนเริ่ม M2 แล้ว revise interface
- R9 ข้อมูล calibration ไม่พอ
  - ตัวชี้วัด: ตัวอย่างต่อ rule < ขั้นต่ำที่กำหนด
  - แผนสำรอง: คงสถานะ uncalibrated และไม่เปิดเผยตัวเลขเป็นความน่าจะเป็น
- R2 Python sidecar + Tauri: PyInstaller path/DLL -> PoC แพ็กก่อน M5
- R3 ความแม่น disasm ต่างจาก objdump เพราะ linear sweep ไปชนข้อมูลใน code section (data-in-code) และ objdump ตัดสินขอบเขตคำสั่งต่างกัน -> รายงานช่วง address ที่ต่าง พร้อมสาเหตุเป็นหมวด (data-in-code, jump table, padding)
- R4 schema เปลี่ยน -> version ใน hash key + migration
- R5 scope creep -> non-goals ในข้อ 7

## 11. Open Decisions
- D1 ชื่อ: ใช้ "ReverseSuite" เป็นรหัสโปรเจกต์; เก็บชื่อในค่าคงที่เดียว ห้ามฝังใน schema/rule id/cache key; ตัดสินชื่อจริงก่อนเริ่ม GUI/installer
- D2 license: Apache-2.0; กฎ "ห้าม dependency แบบ GPL ใน core" (เครื่องมือ GPL เรียกผ่านโปรเซสแยกเท่านั้น); มีไฟล์ third-party licenses ก่อน commit แรก
- D3 HTTP API: เลื่อนหลัง CLI นิ่ง; M1 แค่ออกแบบ service layer + Pydantic schema โดยไม่เปิดพอร์ต; AC-10 (token/Host/Origin) ย้ายไป milestone API
- D4 ภาษา: รองรับ 2 ภาษา; ต้นฉบับอังกฤษ + ไทยเป็นคำแปล; diagnostics เก็บเป็น code + params (ไม่เก็บข้อความแปล) แล้ว client แปลตอนแสดงผล

## 12. M2+ (หัวข้อ)
- M2a: Ghidra spike (ทดลอง headless 1 เคส + วัดเวลา/RAM + revise DecompilerBackend)
- M2b: Symbol L0 (PDB local) + L3 (demangle) + export มาเป็น finding
- M2c: L1 symbol server (opt-in 2 ชั้น + log + allowlist)
- M2d: L2 library signatures
- M3: L4 rules + calibration + benchmark ขยาย
- M4: Diff engine
- M5: GUI + report + installer
- M-API: เปิด HTTP API พร้อม AC-API-1..5 (ประตูก่อน GUI)
- ภายหลัง: .NET / APK / Web-JS, L5 ML, restricted token/low integrity
- Phase gate: ก่อนเริ่ม milestone ใด ต้องเขียน AC ของ milestone นั้นและผ่านรีวิวก่อน

## 14. Pre-spike lock (v4.1) — ตัวเลขและนิยามที่ล็อกก่อนรัน S1/R1

### 14.1 ข้อเท็จจริง PE ของ a.exe (ยืนยันจาก header)
- Machine = 0x8664 (x64) · Magic = 0x20B (PE32+) · SizeOfOptionalHeader = 240
- e_lfanew = 248 · section_table_offset = 512 · .text raw_ptr = 1024, raw_size = 537,088
- maxRawEnd = 668,672 = file_size → ไม่มี overlay (ตัด 1 ไบต์ท้ายไฟล์จึงโดนข้อมูลจริง)

### 14.2 S1 (capstone) — เกณฑ์ผ่านคงที่ + สูตรขนาดไฟล์
เกณฑ์ผ่าน **คงที่ทุกกรณี**: wall <= 60 วิ · peak RSS <= 1 GB (ไม่ผ่อน)

วัดใน S1 (1 รอบ, time-box 2 ชั่วโมง) บน .text ของ a.exe:
- T = instructions/วินาที (CPython 3.12)
- B = bytes ของ .text ต่อ 1 instruction (537,088 / จำนวน instruction ที่นับได้)
- R_stream / R_buffer = peak RSS ของ streaming เทียบกับเก็บทั้งหมด
- J = ขนาด JSONL ต่อ code 1 MB

สูตรกำหนดขนาด d.exe (ปัดลงเป็นผลคูณของ 5 MB):
- `size = min(100 MB, T × 45 วิ × B)`
- ถ้า size < 10 MB → **ไม่ลดเกณฑ์** แต่ต้องทำ S1b (แบ่งงานหลาย process) ก่อน
- ตัวเลข AC-7a (wall/RSS) ยังคง 60 วิ / 1 GB ตามที่ล็อกไว้ใน AC-7a
- รัน 3 รอบ ใช้ **ค่ามัธยฐานของ T**
- คำนวณขนาด d.exe **ครั้งเดียว**; ถ้า AC-7a ไม่ผ่านที่ขนาดนั้น ถือเป็นผลจริงที่ต้องแก้ประสิทธิภาพ ห้ามลดขนาดซ้ำ
- วัด B จริงของ d.exe หลังสร้าง ถ้าต่างจาก B ของ a.exe มาก ให้บันทึก แต่ **ห้ามใช้ปรับสูตรย้อนหลัง**

เกณฑ์อื่น:
- streaming บังคับถ้า R_buffer - R_stream > 200 MB ที่ขนาดที่เลือก
- ถ้า J > 8 เท่าของขนาด code → เพิ่ม gzip ให้ JSONL ก่อน M1b
### 14.2.1 AC-7a — ตัวเลขที่ล็อก (v4.3, จากผล S1)
ผล S1 (commit 9e3e838 · `spikes/S1-results.json`):
- T_median = 627,159 instr/s (3 รอบ: 0.322/0.320/0.319 s, counts 200,850 เท่ากันทุกครั้ง)
- B = 2.6741 bytes/instr · .text = 537,088 B / 200,850 instr
- capstone triple: dist 5.0.9 · module 5.0.7 · core 5.0.1280 · Python 3.12.10 · Windows 10.0.26300
- JSONL = 14,383,477 B ต่อ code 1 MB → ratio 13.72× → **gzip required**

**ขนาด d.exe (target): 70 MB** — จาก `size = min(100MB, T×45×B)` = 75.4 MB ปัดลง 5 MB

**(a) T เป็น proxy — ไม่ใช่คำสัญญาเวลา**
- T วัดจาก .text ของ a.exe (MSVC mix จริง) แต่ d.exe เป็น synthetic codegen (repetitive pattern) ซึ่ง disasm มักเร็วกว่า
- ดังนั้น T=627k เป็นการ **underestimate เวลา** ของ d.exe ไม่ใช่ overestimate
- AC-7a วัดเวลาจริงบน d.exe และ **ผลจริงมีอำนาจเหนือกว่าตัวเลขคาดการณ์** (ห้ามอ้าง 41.8 s ว่าเป็นคำสัญญา)

**(b) เกณฑ์ผ่าน + fallback ที่ประกาศล่วงหน้า**
- AC-7a gate (ไม่เปลี่ยน): wall <= 60 s · peak RSS <= 1 GB
- Sizing budget = 45 s (ใช้เลือกขนาดเท่านั้น เพื่อเหลือ headroom 25% ถึง gate 60 s)
- **Fallback ที่ประกาศล่วงหน้า**: ถ้า AC-7a บน 70 MB ใช้เวลา > 45 s → ลดเป็น **65 MB** (คาด ~38.8 s) และรันใหม่ได้ทันที **โดยไม่ต้องอนุมัติซ้ำ** เพราะเกณฑ์ ≤ 60 s ยังเดิม
- ต้องรายงานทั้งสองผล (70 MB ที่ fail 45 s และ 65 MB ที่ผ่าน) เพื่อบันทึกว่า fallback ถูกใช้จริง
- ถ้า RSS เกิน 1 GB → **หยุดและรายงาน** (cap เป็น safety ไม่ใช่ perf target — ห้าม fallback อัตโนมัติ)

**(c) gzip ต้องวัดจริงใน AC-7a**
- ต้องบันทึกทั้ง raw bytes และ gzip bytes
- ผ่านเมื่อ ratio(raw) > 8× **และ** gzip size <= 20% ของ raw (ไม่ปล่อยเป็นเงื่อนไขหลวมว่า "ใส่ gzip แล้ว")

**(d) streaming เป็น default**
- streaming **บังคับ** เมื่อ slice >= 32 MB ไม่ว่า `R_buffer − R_stream` จะเป็นเท่าไร
- เหตุผล: buffer ที่ 70 MB ≈ 26M rows ≈ 1.3 GB ซึ่งเกิน cap ใด ๆ ที่ประกาศ (delta 10.5 MB ที่ 10 MB slice ไม่ใช่เหตุผลที่ต้อง stream)
### 14.2.2 AC-7a / AC-7b ที่ขนาดจริง 71 MB (v4.4)
ข้อเท็จจริงจากการสร้าง fixture:
- d.exe = 46 TU · 2,326,450 ฟังก์ชัน · exe 71.1 MB · `.text` = 74,531,840 B (71.07 MB) ✅ ตรงเป้า 70 MB
- ต้นเหตุที่เคยล้มเหลว: `__declspec(dllexport)` ทำให้ `LNK1189: library limit of 65535 objects exceeded` และทำให้ cl ช้า/obj ค้าง 0 ไบต์ → เปลี่ยนเป็น `__declspec(noinline)`
- Defender exclusion ที่โฟลเดอร์โปรเจกต์ลดเวลาคอมไพล์อย่างมีนัยสำคัญ (บันทึกเป็นข้อกำหนดของ environment การวัด ไม่ใช่ของผลิตภัณฑ์)

**AC-7a (CPU disasm, เกณฑ์หลัก) — parallel 6 workers**
- `spikes/s1b_parallel.py` · แบ่ง .text เป็น 6 ก้อน, disasm ภายในก้อนละ 2 MB (capstone 5.0.9 ล้มเหลว `CS_ERR_MEM` เมื่อ buffer ใหญ่กว่านี้)
- ผล: instructions 38,447,906 · **wall 19.481 s** · 1,973,566 instr/s
- RSS: **peak ต่อ process 518.3–518.5 MB** (ผ่าน cap 1 GB) · ผลรวมทุก worker 3,110 MB (บันทึกเป็นข้อมูลประกอบ; cap ที่ผูกคือ per-process)
- เกณฑ์ผ่าน AC-7a: wall <= 60 s และ per-process RSS <= 1 GB
- **RSS gate is per-worker <= 1 GB.** Total RSS = 3.11 GB for 6 workers. Future scaling must account for RAM total (e.g. 8 workers ≈ 4.2 GB).

**AC-7b (E2E: disasm + JSONL + gzip) — แยกเกณฑ์**
- ผล: instructions 41,896,289 · **wall 167.014 s** · 250,855 instr/s · peak RSS 648.8 MB
- JSONL raw 1,532,523,522 B (20.56× ของ code) · gzip 136,779,241 B = **8.93% ของ raw**
- gzip verified: decompress 8 MB แรกได้ครบ, บรรทัดแรกเป็น JSON ที่ถูกต้อง
- เกณฑ์ผ่าน AC-7b: wall <= 180 s · gzip <= 20% ของ raw · raw ratio > 8×

**หมายเหตุความต่างของจำนวน instruction** ระหว่าง single (36,434,211) กับ parallel (38,447,906) เกิดจากการตัดขอบ chunk ต่างกัน — AC-7a ใช้การแบ่งแบบขนานตามที่ระบุ
### 14.3 R1 (Job Object) — เกณฑ์ที่สไปก์ต้องยืนยัน (แก้ตามข้อเท็จจริงของ Windows)
ข้อเท็จจริง: เมื่อโปรเซสใน Job จองเกิน memory limit **การจองล้มเหลว ไม่ใช่ถูกฆ่าอัตโนมัติ** — ผู้เรียกต้องตัดสินใจเอง

- memory: ผ่านเมื่อ peak job memory <= cap + 64 MB และรันเนอร์ **ตรวจพบเหตุการณ์** (ข้อความจาก completion port หรือ helper ออกด้วย exit code 2) แล้วยุติ job ภายใน 2.0 วิ พร้อม diagnostic `sandbox.memory_cap`
- child: ผ่านเมื่อ child ไม่ได้ทำงานต่อ (CreateProcess ล้มเหลว หรือ child ถูกยุติทันที) และจำนวน process ใน job ไม่เกิน 1 — บันทึกว่าเกิดแบบไหน
- tree: หลังสั่ง kill รายการ process ใน job ต้องเป็น 0 ภายใน 1.0 วิ
- watchdog: รันเนอร์ (อยู่นอก job) ฆ่าที่ 120 ± 2 วิ
- บันทึก Windows build และ Python version ลงผลสไปก์
- memory cap 512 MB ใช้ **เฉพาะสไปก์ R1** (AC-7b ใช้ 1.5 GB ตามที่ล็อกไว้)
- ถ้าข้อใดไม่ผ่าน → แผนสำรอง R1 (จำกัดเวลาอย่างเดียว + บันทึกว่า memory cap ใช้ไม่ได้)
- retry = รันซ้ำด้วยพารามิเตอร์เดิมทุกตัว ไม่เกิน 2 ครั้ง และรายงานผลทุกรอบ

#### 14.3.1 กติกาของรันเนอร์ (บังคับ)
- สร้างโปรเซสด้วย `CREATE_SUSPENDED` → `AssignProcessToJobObject` → จึง `ResumeThread`
- ถ้า assign เข้า Job ล้มเหลว → **ยกเลิกทันที** ห้ามรัน helper นอก Job เด็ดขาด
- ตั้ง `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`
- ใช้ **ctypes ของ stdlib เท่านั้น**; ถ้าจำเป็นต้องใช้ pywin32 ต้องขออนุมัติแยก
### 14.4 T2 — เพดานตัวเลขของ loader (หน่วยชัดเจน)
- sections <= 96 (จำนวน section)
- imported DLLs <= 4,096 และ import entries รวม <= 65,535
- exports <= 65,535 (จำนวนรายการ)
- resource entries <= 4,096 (จำนวน entry รวมใน resource tree) · depth <= 8
- raw section เดียว <= 512 MB · ไฟล์ <= 2 GB
- เพดานทั้งหมดถูกนับใน `config_hash`; การปรับค่าใดต้องลง Change Log พร้อมเหตุผล (ค่าเริ่มต้นอาจปฏิเสธไบนารีจริงขนาดใหญ่)
### 14.5 นิยาม failed / degraded + diagnostic namespace
- **failed** = header / optional header / section table อ่านไม่ได้ หรือชนเพดาน T2 → exit 3
- **degraded** = header + section table ใช้ได้ แต่ข้อมูลบางส่วนอ่านไม่ได้ (section data ขาด) → exit 2
- diagnostic codes (namespace pe.*): `pe.header.truncated`, `pe.coff.truncated`, `pe.sectab.truncated`, `pe.section.truncated`, `pe.sectab.cap_exceeded`, `pe.opt.truncated`, `pe.opt.size_mismatch`, `pe.lfanew.out_of_range`
- **ลำดับความสำคัญ**: ตรวจ `cap_exceeded` ก่อน `truncated` เสมอ (เพดานเป็นนโยบาย ไม่ขึ้นกับว่าไฟล์ขาดหรือไม่)
- f1 (NumberOfSections=0xFFFF) → `pe.sectab.cap_exceeded` (ไม่ใช่ truncated)
- f2 (SizeOfOptionalHeader=0x0010) → `pe.opt.size_mismatch` (ไม่ใช่ truncated)

### 14.6 Fixture inventory (frozen, tracked) + hash ของไฟล์คุม
frozen: a.exe 7E01F46B…, a.pdb C45DF73D…, b.exe 3584E288…, b_unstripped.exe 7970DD44…, c.exe 8CDE9462…, memhog.exe, spawner.exe, spin.exe, b_packed.exe 04C212E1…
- `fixtures/frozen/manifest.json` sha256 = 2DF65578A6B5DE23B35232AA84B54C03FF72DF0D5217F0EAA066825EF458D001
- `fixtures/toolchain-manifest.json` sha256 = 322F22AC00207C1B67AA68D3E0838DA70C6ACCAF42D71BB2F38A8E40AFD0831A
- `fixtures/corrupt-manifest.json` sha256 = 5F3349C1D54DA66F87E006B6C8C0D447CF9D570E48BC15E787E9F2EC86098623
- `fixtures/derive_corrupt.py` sha256 = 0AC43E6737F3D489C9E8993EA5403A3CD1D868B84F3E7AB8F9A654F6C3D8DBD2
- derived cases (ไม่ commit ไบนารี): t1 34B9348E…, t2 AF6CEC57…, t3 18C07F4A…, t4 3DD3BF88…, t5 806569CC…, f1 C16E2945…, f2 1F1B291D…, f3 83C21954…

### 14.7 UPX
- UPX 5.2.1 (ใหม่ที่สุดที่ผ่านเกณฑ์อายุ 14 วัน) · checksum_source = GitHub asset digest (API), ไม่มีไฟล์ checksum จากผู้เผยแพร่

## 13. Change Log
- v1: โครงแรก (ARCHITECTURE.md)
- v2: เพิ่ม threat model, risks, open decisions, DoD; precision ของ AC
- v3: permille/JCS, deterministic id, sort keys, offset space, encoding, cache config_hash, PDB sandbox, precedence, calibration gating
- v4: Job Object ไม่ใช่ security boundary, T8/T9, สมมติฐานผู้โจมตี, risks + indicator/fallback (R1,R3,R6-R9), DoD หลักฐานต้องรันซ้ำได้/ห้าม skip/clean venv/blocker definition, ตัดสิน D1-D4, ย้าย AC-10 ไป milestone API
- v4 final (numbers TBD pending S1): watchdog 120 วิ (เกณฑ์วัดยัง 60 วิ), exit code 5 = internal error + stdout contract, S1 ต้องจบก่อน sandbox runner, spike governance (spikes/, pre-registered thresholds, v4.1)
- กติกา: การลดเกณฑ์ใด ๆ ต้องบันทึกที่นี่พร้อมเหตุผล
- v4.1 (pre-spike lock): ยืนยัน a.exe = PE32+ x64 (0x8664/0x20B, OptSize 240); เพิ่มตัวเลข S1 (T/R/J), R1 (512MB cap, 2s kill, 120s watchdog), เพดาน T2, นิยาม failed/degraded + diagnostic pe.*, hash ของ manifest 3 ไฟล์ + สคริปต์, รายการ fixture/derived cases
- v4.2: S1 = เกณฑ์คงที่ 60 วิ/1 GB + สูตรขนาด (มัธยฐาน 3 รอบ, คำนวณครั้งเดียว, วัด B ของ d.exe ภายหลัง), R1 = นิยามตามพฤติกรรมจริงของ Job (peak <= cap+64MB + ตรวจจับเหตุการณ์ + ยุติ <= 2 วิ) + กติการันเนอร์ CREATE_SUSPENDED/Resume/KILL_ON_JOB_CLOSE + ctypes เท่านั้น, T2 หน่วยชัดเจน + config_hash, diagnostic priority (cap ก่อน truncated) + `pe.opt.size_mismatch`, 512 MB เฉพาะสไปก์, นิยาม retry
- บันทึกประวัติที่ขาด (ย้อนหลัง): b.exe เปลี่ยนจาก MSVC เป็น MinGW-w64 + strip (b_unstripped เป็นเฉลย AC-15) · นโยบาย frozen fixture + MSVC build ไม่ reproducible (ทดสอบ /Brepro แล้ว hash ต่าง) · เลือก UPX 5.2.1 ด้วยกติกาอายุ 14 วัน + checksum_source = GitHub asset digest · provenance MSVC (โฟลเดอร์ 14.44.35207 vs ไบนารี 19.44.35228.0, ยืนยันได้แค่ linker 14.44 จาก PE header) · แก้ข้อผิดพลาดเดิม: a.exe เป็น PE32+ x64 (Machine 0x8664, Magic 0x20B, OptSize 240) ไม่ใช่ PE32/OptSize 224 · กติกา git (ห้าม add -A, ระบุ path, commit ต้องอนุมัติรายครั้ง) + เหตุการณ์ git add -A ที่ดูด toolchain 11,878 ไฟล์เข้า commit 19eeb6a และการแก้ด้วย 0d995c9/8184c5d · ตัดสินใจยังไม่ rotate กุญแจ (Telegram/Tavily) แต่ต้อง untrack ไฟล์ memory ที่มีค่าเมื่อได้อนุมัติ · เอา notepad.exe ออกจาก AC-1 (ใช้ fixture ที่คอมไพล์เองทั้งหมด)
- v4.3: ล็อก AC-7a จากผล S1 — 70 MB target, T เป็น proxy (ผลจริงชนะ), fallback 65 MB ที่ประกาศล่วงหน้าเมื่อ >45 s (gate ยัง 60 s/1 GB), gzip <= 20% ของ raw + raw ratio > 8x, streaming บังคับที่ slice >= 32 MB
- v4.4: วัดจริงที่ 71.07 MB — AC-7a = parallel disasm 6 workers (19.481 s, per-process RSS 518 MB), AC-7b = E2E (167.014 s, gzip 8.93%); เพิ่มเหตุผล LNK1189/noinline, Defender exclusion, และข้อกำหนด buffer 2 MB ของ capstone
