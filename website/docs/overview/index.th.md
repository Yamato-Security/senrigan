# Senrigan คืออะไร?

## ล่าภัยคุกคามบน AWS ได้ในไม่กี่นาที — ไม่ต้องใช้ SIEM ไม่ต้องมีโครงสร้างพื้นฐานบนคลาวด์
> เพียงนำล็อก CloudTrail ของคุณใส่เข้าไป แล้วรับการล่าภัยคุกคามที่พร้อมใช้งานกว่า 100 รายการ แดชบอร์ด BI และการวิเคราะห์ที่ช่วยด้วย AI
> — ทั้งหมดนี้ทำงานบนแล็ปท็อปของคุณด้วยคำสั่งเดียว `make up`

[![License](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](https://github.com/Yamato-Security/senrigan/blob/main/LICENSE)
[![CI](https://github.com/Yamato-Security/senrigan/actions/workflows/ci.yml/badge.svg)](https://github.com/Yamato-Security/senrigan/actions/workflows/ci.yml)
[![Docker](https://img.shields.io/badge/docker-compose-blue)](https://github.com/Yamato-Security/senrigan/blob/main/docker/docker-compose.yml)
[![DEFCON](https://img.shields.io/badge/DEFCON-2026-red)](https://defcon.org/html/defcon-34/dc-34-demolabs.html#content_66521)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://github.com/Yamato-Security/senrigan/blob/main/ingester/Cargo.toml)
[![Python](https://img.shields.io/badge/python-3.14%2B-blue.svg)](https://github.com/Yamato-Security/senrigan/blob/main/agent/requirements.txt)

## คุณสมบัติหลัก
## 🔍 การล่าภัยคุกคามในตัวกว่า 100 รายการ + AI Chat

<img src="../assets/img-agent.png" width="800" alt="AI Chat UI">

## 📊 แผนภูมิแดชบอร์ดสำเร็จรูปกว่า 80 รายการ

<img src="../assets/img-dashboard.png" width="800" alt="Superset Dashboard">

## 🦅️ การแสดงผลลัพธ์ของ Suzaku

<img src="../assets/img-suzaku-summary.png" width="800" alt="Suzaku results visualization">

## 📄 รายงานการล่าภัยคุกคามแบบ HTML

<img src="../assets/img-html.png" width="800" alt="HTML Threat Hunting Report">

## 🗺 กราฟทรัพยากร AWS Config

<img src="../assets/img-config.png" width="800" alt="AWS Config Resource Graph">

## ออกแบบมาสำหรับ
- 🔍 วิศวกรด้านความปลอดภัย — ผู้ที่กำลังสืบสวนการบุกรุกบัญชี AWS การยกระดับสิทธิ์ หรือการลักลอบนำข้อมูลออก
- 🛡 ทีมความปลอดภัยบนคลาวด์ — ผู้ที่ดำเนินการตรวจสอบสถานะความปลอดภัยบนคลาวด์เป็นระยะโดยไม่ต้องมี SIEM โดยเฉพาะ
- 🧑‍💻 นักพัฒนาและ SRE — ผู้ที่ต้องการตรวจสอบประวัติ CloudTrail ของบัญชีตนเองอย่างรวดเร็วระหว่างหรือหลังเกิดเหตุการณ์

---
