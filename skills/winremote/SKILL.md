---
name: winremote
description: Control this Windows desktop from an agent: snapshot, click, type, shortcuts, OCR and read-only process/port queries via a local MCP server.
---

# winremote (desktop control MCP)

## Overview

`winremote-mcp` เป็น MCP server ที่รันบนเครื่องนี้ เปิด HTTP ที่ `127.0.0.1:8095/mcp` ให้เอเจนต์
จับภาพหน้าจอ คลิก/พิมพ์/กดคีย์ ลากสกรอลล์ สลับหน้าต่าง อ่านข้อความด้วย OCR
และ query ข้อมูลระบบแบบอ่านอย่างเดียว (process, service, task, port, event log)

มี **30 tools**: `Snapshot`, `AnnotatedSnapshot`, `Click`, `Type`, `Scroll`, `Move`, `Shortcut`,
`Wait`, `FocusWindow`, `MinimizeAll`, `GetClipboard`, `ListProcesses`, `GetSystemInfo`,
`ReconnectSession`, `Notification`, `Scrape`, `FileList`, `FileSearch`, `RegRead`, `ServiceList`,
`TaskList`, `Ping`, `PortCheck`, `NetConnections`, `EventLog`, `OCR`, `ScreenRecord`,
`CancelTask`, `GetTaskStatus`, `GetRunningTasks`

## When to use

- ผู้ใช้ขอให้ "ดูหน้าจอ" / "ช่วยคลิก" / "พิมพ์ให้" / "เปิดโปรแกรมนี้บนเดสก์ท็อป"
- ต้องตรวจสอบ UI ของแอปที่รันอยู่ (อ่านค่าด้วย `OCR` หรือ `Snapshot`)
- ต้องดู process/service/port/event log แบบเร็ว (`ListProcesses`, `NetConnections`, `EventLog`)

ไม่ใช้เมื่อ: ต้องทำงานกับไฟล์ใน repo (ใช้ shell/exec ตรง ๆ เร็วกว่า), ต้องรันแบบ headless
(session 0 จะจับภาพไม่ได้), หรือผู้ใช้ไม่ได้ขอให้แตะเดสก์ท็อป

## Usage

### เริ่ม/ตรวจ server

```powershell
# task ที่รัน server (สถานะปกติ = Running)
schtasks /query /tn "OpenClaw-WinRemoteMCP" /fo list

# ถ้ายังไม่รัน
schtasks /run /tn "OpenClaw-WinRemoteMCP"

# ตรวจว่าฟังพอร์ตจริง
netstat -ano | findstr :8095
```

- endpoint: `http://127.0.0.1:8095/mcp` (MCP streamable HTTP)
- log: `D:\OpenClaw\workspace\.winremote.log`
- ตัว task รันผ่าน `cmd.exe` แบบ interactive → **จะมีหน้าต่าง cmd ดำ ๆ ค้างไว้ 1 หน้าต่าง** (ปิด = server ดับ)

### ลำดับการสั่งที่ปลอดภัย

1. `Snapshot` (หรือ `AnnotatedSnapshot` เพื่อได้พิกัดของ element) → ดูว่าจอเป็นอย่างไร
2. `FocusWindow` ระบุหน้าต่างเป้าหมาย ก่อนพิมพ์/คลิก
3. `Click` / `Type` / `Shortcut` ตามที่ผู้ใช้ขอ
4. `OCR` เมื่อต้องอ่านข้อความบนจอ (ไม่ต้องเดาจากภาพ)
5. `Wait` หลังคำสั่งที่ทำให้จอเปลี่ยน แล้ว `Snapshot` ซ้ำเพื่อยืนยันผล

### ตัวอย่าง

```text
# เปิด Start แล้วพิมพ์ชื่อแอป
Shortcut(keys="win")            → Type(text="notepad") → Wait(ms=800)
# อ่านข้อความจากหน้าต่างที่เพิ่งเปิด
FocusWindow(title="Untitled - Notepad") → OCR()
```

### ตรวจระบบแบบอ่านอย่างเดียว

`ListProcesses()` · `NetConnections()` · `ServiceList()` · `TaskList()` · `EventLog(...)` · `PortCheck(port=8095)`

## Verification

```powershell
netstat -ano | findstr :8095      # ต้องเห็น LISTENING
Get-Content D:\OpenClaw\workspace\.winremote.log -Tail 3   # ต้องมี POST /mcp 200
```

และเรียก `Snapshot` หนึ่งครั้ง — ต้องได้ภาพหน้าจอปัจจุบันกลับมา (ไม่ error)

## Limits

- **ต้องมี interactive desktop** — ถ้าเอเจนต์รันใน session 0 (service) จะจับภาพ/คลิกไม่ได้
- หน้าต่าง cmd ของ server ต้องเปิดค้างไว้; ปิดแล้วต้อง `schtasks /run` ใหม่
- **ไม่มี authentication** และ bind แค่ loopback — ห้าม expose พอร์ต 8095 ออกเครือข่าย
- `Type` พิมพ์ได้ทุกอย่างรวมถึงความลับ → **ห้ามพิมพ์รหัสผ่าน/token ลงใน UI** เว้นแต่ผู้ใช้สั่งชัดเจน
- คลิก/ปิดหน้าต่าง/ลบไฟล์ผ่าน UI เป็นการกระทำที่ย้อนยาก → ต้องมีคำสั่งจากผู้ใช้ก่อนเสมอ
- ความละเอียดภาพขึ้นกับสเกลหน้าจอ; `AnnotatedSnapshot` ช่วยเรื่องพิกัดแต่กินแบนด์วิดท์มากกว่า
