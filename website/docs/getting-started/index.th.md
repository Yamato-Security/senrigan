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

**ขั้นตอนที่ 2.** โคลน repository, นำเข้า logs, และเริ่มบริการทั้งหมด

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded logs into the Docker logs directory
cp -r <local-output-dir>/ docker/logs/

# Ingest CloudTrail logs into DuckDB
make ingest

# Start all services (agent + dashboard)
make up
```

**ขั้นตอนที่ 3.** 🪽 เปิดเบราว์เซอร์ของคุณแล้วเริ่มล่าภัยคุกคามได้เลย!🪽

- http://localhost:8501 — คิวรีที่มีมาให้ในตัวและ AI Chat
- http://localhost:8088 — Dashboard (`admin` / `admin`)
- http://localhost:8502 — กราฟทรัพยากร AWS Config

**(ทางเลือก)** การเสริมข้อมูล GeoIP
วางไฟล์ [GeoLite2 `.mmdb` files](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) ไว้ใน `docker/data/geoip/` จากนั้น:

```bash
make ingest-geoip
```

**(ทางเลือก)** การนำเข้า AWS Config snapshot สำหรับการแสดงผลกราฟทรัพยากร
วางไฟล์ AWS Config snapshot ไว้ใน `docker/logs/config/` จากนั้น:
```bash
make ingest-config
```
---

## พร็อกซีองค์กร / ใบรับรอง CA แบบกำหนดเอง

หากคุณอยู่หลังพร็อกซีองค์กรที่มีการตรวจสอบ TLS โปรดดูคำแนะนำในการตั้งค่าที่ [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate)
