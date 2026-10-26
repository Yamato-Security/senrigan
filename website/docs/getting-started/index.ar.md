# البدء

## المتطلبات الأساسية

| المتطلب                           | التفاصيل                                            |
|---------------------------------------|----------------------------------------------------|
| **Docker**                            | Docker Desktop أو Docker Engine + Compose v2       |
| **make**                              | GNU Make (مثبّت مسبقًا على macOS)                  |
| **الموارد**                         | 16 GB RAM كحد أدنى، يُوصى باستخدام SSD                 |
| **سجلات CloudTrail**                   | ملفات `.json` أو `.json.gz` مُصدَّرة من AWS      |
| *(اختياري)* **VPC Flow Logs** | ملفات `.log.gz` نصية عادية مُسلَّمة إلى S3 |
| *(اختياري)* **لقطات AWS Config** | ملفات `.json` أو `.json.gz` لرسم بياني لموارد AWS |
| *(اختياري)* **مفتاح OpenAI API**       | مطلوب لتوليد الاستعلامات بالذكاء الاصطناعي                   |
| *(اختياري)* **MaxMind GeoLite2**     | ملفات `.mmdb` لإثراء GeoIP                 |

---

## البدء السريع

**الخطوة 1.** قم بتنزيل البادئة `AWSLogs/` كاملةً من S3 — سجلات CloudTrail و VPC Flow Logs إن وُجدت. يتم تخطي ملفات الخدمات الأخرى أثناء الاستيعاب.

```bash
aws s3 sync s3://<your-bucket>/AWSLogs/ <local-output-dir>/AWSLogs/
```

**الخطوة 2.** انسخ المستودع وضع بياناتك في مكانها.

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded AWSLogs/ tree here
cp -r <local-output-dir>/ docker/logs/
```

يتم اكتشاف المجلدين الاختياريين أدناه تلقائيًا. املأهما **قبل** الخطوة التالية — لا يوجد أمر إضافي لتشغيله.

| المجلد | المحتوى | ما يضيفه |
|---|---|---|
| `docker/data/geoip/` | [GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | يحوّل عناوين IP المصدر إلى الدولة والمدينة و ASN |
| `docker/data/config-snapshots/` | ملفات `.json` للقطات AWS Config | ينشئ رسم موارد AWS Config البياني |

**الخطوة 3.** استورد السجلات وابدأ الخدمات.

```bash
make ingest
make up
```

**الخطوة 4.** 🪽 افتح متصفحك وابدأ التصيّد!🪽

- http://localhost:8501 — الاستعلامات المدمجة ودردشة الذكاء الاصطناعي
- http://localhost:8088 — لوحة المعلومات (`admin` / `admin`)
- http://localhost:8502 — رسم بياني لموارد AWS Config

---

## الأوامر اليومية

تشغيل `make` بدون وسائط يطبع هذه القائمة، و`make help-all` يعرض جميع الأهداف.

| الأمر | الوظيفة |
|---|---|
| `make ingest` | تحميل سجلات CloudTrail و VPC Flow Logs من `docker/logs/` إلى DuckDB |
| `make up` | بدء الواجهة ولوحة المعلومات ورسم الموارد البياني |
| `make down` | إيقاف كل شيء |
| `make logs` | متابعة سجلات الخدمات (`SERVICE=agent` لخدمة واحدة) |
| `make reset` | حذف قاعدة البيانات والبدء من جديد |

---

## وكيل الشركة / شهادة CA مخصصة

إذا كنت خلف وكيل شركة يفحص TLS، فراجع [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) للحصول على تعليمات الإعداد.
