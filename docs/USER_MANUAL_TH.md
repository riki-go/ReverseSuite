# คู่มือการใช้งาน ReverseSuite v0.2.1 (ฉบับภาษาไทย)

ReverseSuite คือเครื่องมือวิเคราะห์ไฟล์โปรแกรม (Static PE Analysis) ที่สแกนหา **ฟังก์ชัน (Functions)**, **ข้อความ (Strings)**, **กราฟการเรียกใช้ฟังก์ชัน (Call Graph)** และ**เปรียบเทียบไฟล์ (Diff)** ได้อย่างรวดเร็วและปลอดภัย — ไม่รันไฟล์เป้าหมายเลย (static only)

---

## 🛠️ ส่วนที่ 1: การติดตั้ง (Installation)

1. **ถอนตัวเก่า (ถ้ามี)** — Settings → Apps → Installed apps → ค้นหา `ReverseSuite` → Uninstall
2. **ติดตั้งตัวใหม่** — เปิดโฟลเดอร์ `src-tauri\target\release\bundle\msi\` แล้วดับเบิ้ลคลิก `ReverseSuite_0.2.1_x64_en-US.msi`
3. **เปิดโปรแกรม** — กด Start → พิมพ์ `ReverseSuite` → เปิดแอป

> ถ้า Windows SmartScreen เตือน ให้กด **More info** → **Run anyway** (ไฟล์ยังไม่ได้ซื้อ certificate จาก CA)

---

## 🖥️ ส่วนที่ 2: ภาพรวมหน้าจอ (UI Overview)

หน้าจอแบ่งเป็น 4 ส่วน

| ส่วน | หน้าที่ |
| --- | --- |
| **Status Bar** (มุมซ้ายบน) | 🟢 `connected` = หลังบ้านทำงานปกติ · 🔴 `checking...` / `token required` = หลังบ้านมีปัญหา (ดูหัวข้อ 7) |
| **Analyze** | วิเคราะห์ไฟล์เดี่ยว |
| **Diff & Report** | เปรียบเทียบ 2 ไฟล์ + สร้างรายงาน |
| **Graph** | แสดงกราฟความเชื่อมโยงของฟังก์ชัน |

---

## 🔍 ส่วนที่ 3: Analyze (วิเคราะห์ไฟล์)

### วิธีนำไฟล์เข้า (3 วิธี)

1. **พิมพ์ Absolute Path** เช่น `D:\OpenClaw\workspace\projects\reversesuite\fixtures\frozen\b.exe`
2. **พิมพ์ URL** ที่ขึ้นต้นด้วย `http://` หรือ `https://` — ระบบจะดาวน์โหลดลง Temp แล้วลบทิ้งเมื่อวิเคราะห์เสร็จ
3. **ลากไฟล์มาวาง (Drag & Drop)** จาก Explorer ลงในช่อง หรือกด **browse…** เพื่อเลือกไฟล์

### อ่านผลลัพธ์

- `status` — สถานะ (`ok` = สำเร็จ)
- `size` — ขนาดไฟล์ (ไบต์)
- `findings` — จำนวนข้อมูลที่ตรวจพบทั้งหมด
- `functions` — จำนวนฟังก์ชันที่ตรวจพบ
- `edges` — จำนวนเส้นเชื่อมการเรียกใช้ (แยก `imports` และ `indirect`)
- `diagnostics` — ข้อผิดพลาด/คำเตือน (ถ้ามี)

> ไฟล์ที่มี `.text` ใหญ่กว่า 32 MB ระบบจะข้าม function discovery และ xref พร้อมแจ้ง diagnostic (`text_too_large_for_functions` / `text_too_large_for_xref`) — string extraction ยังทำงานปกติ

---

## ⚖️ ส่วนที่ 4: Diff & Report (เปรียบเทียบไฟล์)

### วิธีใช้งาน

1. **Left binary path** — ไฟล์เวอร์ชันที่ 1 (พิมพ์ path, URL หรือกด browse)
2. **Right binary path** — ไฟล์เวอร์ชันที่ 2
3. **ignore thunks** — แนะนำให้ติ๊กเมื่อเทียบไฟล์ที่คอมไพล์ด้วย MSVC (Visual Studio) เพราะจะซ่อน thunk ของ linker ที่ทำให้ผลรก
4. กด **run diff**

### อ่านผลลัพธ์

- `nodes +X -Y ~Z` — ฟังก์ชันที่เพิ่ม (+) / ลบ (-) / ย้ายตำแหน่ง (~)
- `edges +X -Y =Z` — เส้นเชื่อมที่เพิ่ม / ลบ / เหมือนเดิม

### ดาวน์โหลดรายงาน

กด **download report** → ได้ไฟล์ HTML (หรือ Markdown ถ้าเรียกผ่าน API) เก็บไว้ได้ทันที

---

## 🕸️ ส่วนที่ 5: Graph (กราฟแสดงผล)

| ปุ่ม | การทำงาน |
| --- | --- |
| `view call graph` | กราฟการเรียกใช้ของไฟล์ที่ Analyze ล่าสุด |
| `view diff graph` | กราฟความต่างหลัง Diff (เขียว = เพิ่ม, แดง = ลบ) |
| `export svg` | ดาวน์โหลดเป็น `.svg` (เวกเตอร์ ขยายไม่แตก) |
| `export png` | ดาวน์โหลดเป็น `.png` |
| `clear` | ล้างกราฟบนหน้าจอ |

### การโต้ตอบ

- **ลาก (Drag)** — คลิกที่ Node (วงกลม) แล้วลากเพื่อจัดตำแหน่ง
- **ซูม (Zoom)** — หมุน Scroll Wheel
- **แพน (Pan)** — คลิกพื้นที่ว่างแล้วลาก

กราฟใช้ force-directed layout (ผลักกัน + ดึงตามเส้นเชื่อม) จึงไม่ทับกันเป็นลูกบอล; กราฟใหญ่จะจำกัดที่ 400 node แรกและแจ้งในสถานะ

---

## 🛡️ ส่วนที่ 6: ความปลอดภัย (Security Limits)

- **จำกัดการโหลด URL (SSRF guard)** — บล็อกเป้าหมายที่เป็น private / link-local / reserved address เช่น `10.x.x.x`, `192.168.x.x`, `169.254.x.x`; อนุญาต loopback (`127.0.0.1`) เพื่อใช้กับไฟล์ทดสอบในเครื่อง (ถ้าต้องการอนุญาต private ทั้งหมด ต้องเปิด `--allow-private-urls` ที่ CLI)
- **เพดานไฟล์จาก URL** — ไม่เกิน **256 MB**, timeout 30 วินาที และต้องเป็นไฟล์ PE จริง (ตรวจ magic `MZ`)
- **ลบไฟล์ชั่วคราว** — ไฟล์ที่ดาวน์โหลด/อัปโหลดจะถูกลบเมื่อจบโปรแกรม (`atexit`) และมีอายุ (TTL) 15 นาที; ถ้าโปรเซสถูก kill แบบ force ไฟล์อาจค้างใน `%TEMP%` (ลบเองได้)
- **Rate limit** — 60 คำขอ/นาที ต่อ client (เกินได้ `429 rate_limited`)
- **Token** — ส่งผ่าน header `Authorization: Bearer …` เท่านั้น (ไม่ผ่าน URL)

---

## 🚑 ส่วนที่ 7: แก้ไขปัญหาเบื้องต้น (Troubleshooting)

### เปิดแอปแล้วขึ้น `checking...` ตลอด (ไม่ขึ้น connected)
- สาเหตุ: กระบวนการหลังบ้าน (Python sidecar) ไม่ทำงาน
- วิธีแก้: ปิดแอปแล้วเปิดใหม่ 1 ครั้ง; ถ้ายังไม่หาย เปิดดู log ที่ `%LOCALAPPDATA%\ReverseSuite\desktop.log` แล้วส่งให้ผู้พัฒนา

### กด Analyze/Diff แล้วขึ้น `path rejected: it must be inside the allowed root folder`
- สาเหตุ: ใช้เวอร์ชันเก่า (≤ 0.2.0) ที่ยังล็อกสิทธิ์การอ่านไฟล์ หรือรัน backend ด้วย `--root`
- วิธีแก้: อัปเดตเป็น **0.2.1** ขึ้นไป (เวอร์ชันนี้รับ absolute path ทุกไดรฟ์และ URL)

### กราฟดูแน่น/อ่านไม่ออก
- สาเหตุ: จำนวน node หนาแน่น
- วิธีแก้: ซูมเข้าจุดที่สนใจ หรือกด **export svg** แล้วเปิดในโปรแกรมจัดการภาพ

### `429 rate_limited`
- สาเหตุ: เรียก API เกิน 60 ครั้งใน 1 นาที
- วิธีแก้: รอประมาณ 1 นาที หรือเพิ่ม `--rate-limit` ตอนเริ่ม backend

---

คู่มือฉบับนี้จัดทำสำหรับ **ReverseSuite v0.2.1** — สงวนลิขสิทธิ์การใช้งานส่วนบุคคล (MIT License)
