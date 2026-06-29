# शुरुआत करना

## पूर्वापेक्षाएँ

| आवश्यकता                              | विवरण                                              |
|---------------------------------------|----------------------------------------------------|
| **Docker**                            | Docker Desktop या Docker Engine + Compose v2       |
| **make**                              | GNU Make (macOS पर पहले से इंस्टॉल)                  |
| **संसाधन**                            | न्यूनतम 16 GB RAM, SSD अनुशंसित                 |
| **CloudTrail logs**                   | AWS से एक्सपोर्ट की गई `.json` या `.json.gz` फ़ाइलें      |
| *(वैकल्पिक)* **AWS Config snapshots** | AWS संसाधन ग्राफ़ के लिए `.json` या `.json.gz` फ़ाइलें |
| *(वैकल्पिक)* **OpenAI API key**       | AI क्वेरी जनरेशन के लिए आवश्यक                   |
| *(वैकल्पिक)* **MaxMind GeoLite2**     | GeoIP संवर्धन के लिए `.mmdb` फ़ाइलें                 |

---

## त्वरित शुरुआत

**चरण 1.** S3 से CloudTrail logs डाउनलोड करें।

```bash
aws s3 cp s3://<your-bucket-prefix> <local-output-dir>/ --recursive --include "*.json.gz"
```

**चरण 2.** रिपॉज़िटरी क्लोन करें, logs इनजेस्ट करें, और सभी सेवाएँ शुरू करें।

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

**चरण 3.** 🪽 अपना ब्राउज़र खोलें और हंटिंग शुरू करें!🪽

- http://localhost:8501 — अंतर्निहित क्वेरीज़ और AI Chat
- http://localhost:8088 — Dashboard (`admin` / `admin`)
- http://localhost:8502 — AWS Config संसाधन ग्राफ़

**(वैकल्पिक)** GeoIP संवर्धन।
[GeoLite2 `.mmdb` फ़ाइलें](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) को `docker/data/geoip/` में रखें, फिर:

```bash
make ingest-geoip
```

**(वैकल्पिक)** संसाधन ग्राफ़ विज़ुअलाइज़ेशन के लिए AWS Config snapshot इनजेशन।
AWS Config snapshot फ़ाइलों को `docker/logs/config/` में रखें, फिर:
```bash
make ingest-config
```
---

## कॉर्पोरेट प्रॉक्सी / कस्टम CA प्रमाणपत्र

यदि आप TLS-निरीक्षण करने वाली कॉर्पोरेट प्रॉक्सी के पीछे हैं, तो सेटअप निर्देशों के लिए [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) देखें।
