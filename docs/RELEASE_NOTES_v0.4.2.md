# ReverseSuite v0.4.2 - Release Notes

Released: 2026-11-09

## Fixes

- **Readable error messages.** The UI no longer prints raw API payloads such as
  `error: bad request: {"error":"path_not_found"}`. Failures are translated into
  plain language, for example:
  - empty Diff inputs -> `กรุณาใส่ไฟล์ที่ต้องการ Diff ทั้งสองช่อง (ซ้าย = เวอร์ชันเก่า, ขวา = เวอร์ชันใหม่)`
  - empty Analyze input -> `กรุณาใส่ path ของไฟล์ที่ต้องการวิเคราะห์ (หรือลากไฟล์มาวาง)`
  - missing file -> `ไม่พบไฟล์ที่ระบุ — ตรวจสอบ path ให้ถูกต้อง แล้วลองใหม่`
  - rejected path -> `ไม่ได้รับอนุญาตให้เข้าถึง path นี้ — ใช้ path แบบเต็ม (absolute path) หรือเปิด backend ด้วย --root`
  - rate limit -> `เรียกถี่เกินไป — รอสักครู่แล้วลองใหม่`
  - expired upload -> `ไฟล์ที่อัปโหลดหมดอายุแล้ว — กรุณาเลือกไฟล์ใหม่`
  - bad token -> `token ไม่ถูกต้องหรือหมดอายุ — เปิดแอปใหม่ หรือคัดลอกจาก session.json`
- The UI validates empty Analyze/Diff inputs before calling the API, so the common
  mistakes never produce an HTTP round-trip.

## Compatibility

- Backend behaviour and the JSON API are unchanged; only the browser-side message
  mapping and the input guards are new.

## Verification

- Unit tests: 185/185 passing
- GUI check on the installed build: pressing `run diff` with empty fields shows the Thai
  guidance message instead of a raw error payload
