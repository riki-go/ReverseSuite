# ReverseSuite Skills

โฟลเดอร์นี้เก็บ **AI Skills** ของโปรเจกต์ ReverseSuite — ชุดคำอธิบายวิธีทำงานที่ทั้งมนุษย์และ AI ใช้ร่วมกันได้ (รูปแบบ AgentSkills: โฟลเดอร์ละหนึ่งสกิล มี `SKILL.md` เป็นจุดเข้า)

## Index

| Skill | What it does | Path |
| --- | --- | --- |
| `reversesuite` | ใช้งาน ReverseSuite CLI/API: analyze, calls, diff, report, serve; ข้อจำกัดและวิธีตรวจผล | [`reversesuite/SKILL.md`](reversesuite/SKILL.md) |

> เพิ่มสกิลใหม่แล้วอัปเดตตารางนี้ทุกครั้ง — ตารางนี้คือสัญญาระหว่างคนกับ AI

## กฎการเพิ่มสกิลใหม่ (บังคับ)

1. **หนึ่งโฟลเดอร์ต่อหนึ่งสกิล** ชื่อโฟลเดอร์เป็น lowercase + hyphen (`my-skill`)
2. ต้องมีไฟล์ **`SKILL.md`** และต้องเริ่มด้วย **YAML frontmatter** เสมอ:

   ```yaml
   ---
   name: my-skill
   description: One sentence (<= 160 chars) saying what it does and when to use it.
   ---
   ```

3. `name` ต้องตรงกับชื่อโฟลเดอร์ และไม่ซ้ำกับสกิลที่มีอยู่
4. เนื้อหาต้องมีอย่างน้อย: **Overview**, **When to use**, **Usage**, **Verification**
5. คำสั่งที่อ้างในสกิลต้องรันได้จริงใน repo นี้ (หรือระบุ dependency ให้ชัด)
6. **ห้ามใส่ความลับ** (token, key, path ส่วนตัว) ลงในสกิล — ใช้ชื่อ env var แทน
7. ถ้าสกิลมีไฟล์ประกอบ ให้เก็บใน `scripts/` หรือ `references/` ภายในโฟลเดอร์ของสกิลเท่านั้น
8. ก่อน merge: รันตามที่เขียนใน *Verification* แล้วแนบผลจริง (คำสั่ง + output) ใน PR/commit message

## เริ่มสกิลใหม่

```powershell
cd projects\reversesuite\skills
New-Item -ItemType Directory my-skill | Out-Null
Copy-Item _TEMPLATE_SKILL.md my-skill\SKILL.md -Force
```

จากนั้นเติมเนื้อหาให้ครบทุกหัวข้อ และเพิ่มแถวในตาราง Index ด้านบน

## สถานะ

- สกิลที่ ship อยู่: `reversesuite`
- สกิลที่เลิกใช้: ลบโฟลเดอร์ + ลบแถวใน Index (อย่าทิ้งไฟล์ค้าง)
