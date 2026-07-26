# البدء

## المتطلبات الأساسية

| المتطلب                           | التفاصيل                                            |
|---------------------------------------|----------------------------------------------------|
| **Docker**                            | Docker Desktop أو Docker Engine + Compose v2       |
| **make**                              | GNU Make (مثبّت مسبقًا على macOS)                  |
| **الموارد**                         | 16 GB RAM كحد أدنى، يُوصى باستخدام SSD                 |
| **سجلات CloudTrail**                   | ملفات `.json` أو `.json.gz` مُصدَّرة من AWS      |
| *(اختياري)* **لقطات AWS Config** | ملفات `.json` أو `.json.gz` لرسم بياني لموارد AWS |
| *(اختياري)* **مفتاح OpenAI API**       | مطلوب لتوليد الاستعلامات بالذكاء الاصطناعي                   |
| *(اختياري)* **MaxMind GeoLite2**     | ملفات `.mmdb` لإثراء GeoIP                 |

---

## البدء السريع

**الخطوة 1.** قم بتنزيل سجلات CloudTrail من S3.

```bash
aws s3 cp s3://<your-bucket-prefix> <local-output-dir>/ --recursive --include "*.json.gz"
```

**الخطوة 2.** انسخ المستودع، واستورد السجلات، وابدأ جميع الخدمات.

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

**الخطوة 3.** 🪽 افتح متصفحك وابدأ التصيّد!🪽

- http://localhost:8501 — الاستعلامات المدمجة ودردشة الذكاء الاصطناعي
- http://localhost:8088 — لوحة المعلومات (`admin` / `admin`)
- http://localhost:8502 — رسم بياني لموارد AWS Config

**(اختياري)** إثراء GeoIP.
ضع [ملفات GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) في `docker/data/geoip/`، ثم:

```bash
make ingest-geoip
```

**(اختياري)** استيراد لقطات AWS Config لتصوّر رسم بياني للموارد.
ضع ملفات لقطات AWS Config في `docker/data/config-snapshots/`، ثم:
```bash
make ingest-config
```
---

## وكيل الشركة / شهادة CA مخصصة

إذا كنت خلف وكيل شركة يفحص TLS، فراجع [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) للحصول على تعليمات الإعداد.
