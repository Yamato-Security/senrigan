# เริ่มต้นใช้งาน

## ข้อกำหนดเบื้องต้น

| ข้อกำหนด                           | รายละเอียด                                            |
|---------------------------------------|----------------------------------------------------|
| **Docker**                            | Docker Desktop หรือ Docker Engine + Compose v2       |
| **make**                              | GNU Make (ติดตั้งมาแล้วบน macOS)                  |
| **ทรัพยากร**                         | RAM ขั้นต่ำ 16 GB, แนะนำให้ใช้ SSD                 |
| **CloudTrail logs**                   | ไฟล์ `.json` หรือ `.json.gz` ที่ส่งออกจาก AWS      |
| *(ทางเลือก)* **AWS Config snapshots** | ไฟล์ `.json` หรือ `.json.gz` สำหรับกราฟทรัพยากร AWS |
| *(ทางเลือก)* **OpenAI API key**       | จำเป็นสำหรับการสร้างคิวรีด้วย AI                   |
| *(ทางเลือก)* **MaxMind GeoLite2**     | ไฟล์ `.mmdb` สำหรับการเสริมข้อมูล GeoIP                 |

---

## เริ่มต้นอย่างรวดเร็ว

**ขั้นตอนที่ 1.** ดาวน์โหลด CloudTrail logs จาก S3

```bash
aws s3 cp s3://<your-bucket-prefix> <local-output-dir>/ --recursive --include "*.json.gz"
```

**ขั้นตอนที่ 2.** โคลน repository และวางข้อมูลของคุณให้เรียบร้อย

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded CloudTrail logs here
cp -r <local-output-dir>/ docker/logs/
```

ไดเรกทอรีทางเลือกสองรายการด้านล่างจะถูกตรวจพบโดยอัตโนมัติ วางไฟล์ **ก่อน** ขั้นตอนถัดไป — ไม่ต้องรันคำสั่งเพิ่มเติม

| ไดเรกทอรี | เนื้อหา | สิ่งที่เพิ่มเข้ามา |
|---|---|---|
| `docker/data/geoip/` | [GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | แปลง source IP เป็นประเทศ เมือง และ ASN |
| `docker/data/config-snapshots/` | ไฟล์ `.json` ของ AWS Config snapshot | สร้างกราฟทรัพยากร AWS Config |

**ขั้นตอนที่ 3.** นำเข้า logs และเริ่มบริการ

```bash
make ingest
make up
```

**ขั้นตอนที่ 4.** 🪽 เปิดเบราว์เซอร์ของคุณแล้วเริ่มล่าภัยคุกคามได้เลย!🪽

- http://localhost:8501 — คิวรีที่มีมาให้ในตัวและ AI Chat
- http://localhost:8088 — Dashboard (`admin` / `admin`)
- http://localhost:8502 — กราฟทรัพยากร AWS Config

---

## คำสั่งที่ใช้บ่อย

การรัน `make` โดยไม่ใส่อาร์กิวเมนต์จะแสดงรายการนี้ และ `make help-all` จะแสดง target ทั้งหมด

| คำสั่ง | การทำงาน |
|---|---|
| `make ingest` | โหลด CloudTrail logs จาก `docker/logs/` เข้า DuckDB |
| `make up` | เริ่ม UI แดชบอร์ด และกราฟทรัพยากร |
| `make down` | หยุดทั้งหมด |
| `make logs` | ติดตาม logs ของบริการ (ใช้ `SERVICE=agent` สำหรับบริการเดียว) |
| `make reset` | ลบฐานข้อมูลแล้วเริ่มใหม่ |

---

## พร็อกซีองค์กร / ใบรับรอง CA แบบกำหนดเอง

หากคุณอยู่หลังพร็อกซีองค์กรที่มีการตรวจสอบ TLS โปรดดูคำแนะนำในการตั้งค่าที่ [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate)
