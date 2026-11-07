---
name: reversesuite
description: Static PE analysis with the ReverseSuite CLI/API - analyze binaries, extract strings and call graphs, diff two builds, render reports, or serve the local UI.
---

# ReverseSuite

## Overview

สแตติกวิเคราะห์ PE (ไม่รันไฟล์เป้าหมาย) — loader/functions/strings/call graph/diff/report และ local API+UI

## When to use

- ต้องดูโครงสร้างไฟล์ `.exe`/`.dll`: ฟังก์ชัน, สตริง, การเรียกใช้, import
- ต้องเทียบสองบิลด์ (เก่า/ใหม่) ว่าเพิ่ม/ลบ/ย้ายอะไร แล้วออกรายงาน
- ต้องให้เครื่องมืออื่นเรียกผ่าน HTTP loopback (API + token)

ไม่ใช้เมื่อ: ต้องการรัน/ดีบักไบแนรี (เครื่องมือนี้ static only) หรือไฟล์ `.text` ใหญ่เกิน 32 MB สำหรับ function/xref

## Usage

```powershell
$py = "projects\reversesuite\.venv\Scripts\python.exe"
$env:PYTHONPATH = "projects\reversesuite\src"

# วิเคราะห์ไฟล์เดียว (path หรือ URL)
& $py -m reversesuite.cli analyze fixtures\frozen\b.exe

# call graph (เพิ่ม --valueflow ถ้าต้องการทดลอง M6.1)
& $py -m reversesuite.cli calls fixtures\frozen\b.exe --json

# diff + report
& $py -m reversesuite.cli diff fixtures\frozen\b.exe fixtures\frozen\a.exe --ignore-thunks
& $py -m reversesuite.cli report b.exe a.exe --format html --out out.html

# local API/UI (token ออกทาง stderr)
& $py -m reversesuite.cli serve --port 0
```

เรียกจาก API: `POST /analyze`, `/diff`, `/report` พร้อม header `Authorization: Bearer <token>`; รับ `path`, URL หรือ `upload_id` (`POST /upload`)

## Verification

```powershell
& $py -m unittest discover -s tests
# expected: OK (152 tests)
```

## Limits

- static only: ไม่รัน target; indirect call ที่ต้องใช้ dataflow ลึกยังไม่ resolve (M6.2/M6.3 deferred)
- เพดาน 32 MB ของ `.text` สำหรับ function discovery/xref (ไฟล์ใหญ่ขึ้นไปจะได้ diagnostic)
- URL: จำกัด 256 MB, timeout 30 s, บล็อก private/link-local (ยกเว้น loopback)
- rate limit 60 req/min ต่อ client
