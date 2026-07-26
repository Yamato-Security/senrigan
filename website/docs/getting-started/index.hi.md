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

**चरण 2.** रिपॉज़िटरी क्लोन करें और अपना डेटा रखें।

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded CloudTrail logs here
cp -r <local-output-dir>/ docker/logs/
```

नीचे दी गई दोनों वैकल्पिक डायरेक्टरीज़ स्वतः पहचानी जाती हैं। इन्हें अगले चरण से **पहले** भरें — कोई अतिरिक्त कमांड चलाने की ज़रूरत नहीं है।

| डायरेक्टरी | सामग्री | क्या जुड़ता है |
|---|---|---|
| `docker/data/geoip/` | [GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | source IP को देश, शहर और ASN में हल करता है |
| `docker/data/config-snapshots/` | AWS Config snapshot `.json` फ़ाइलें | AWS Config संसाधन ग्राफ़ बनाता है |

**चरण 3.** logs इनजेस्ट करें और सेवाएँ शुरू करें।

```bash
make ingest
make up
```

**चरण 4.** 🪽 अपना ब्राउज़र खोलें और हंटिंग शुरू करें!🪽

- http://localhost:8501 — अंतर्निहित क्वेरीज़ और AI Chat
- http://localhost:8088 — Dashboard (`admin` / `admin`)
- http://localhost:8502 — AWS Config संसाधन ग्राफ़

---

## रोज़मर्रा के कमांड

बिना आर्ग्युमेंट के `make` चलाने पर यही सूची दिखती है। `make help-all` सभी targets दिखाता है।

| कमांड | क्या करता है |
|---|---|
| `make ingest` | `docker/logs/` से CloudTrail logs को DuckDB में लोड करें |
| `make up` | UI, dashboard और संसाधन ग्राफ़ शुरू करें |
| `make down` | सब कुछ बंद करें |
| `make logs` | सेवा logs देखें (केवल एक के लिए `SERVICE=agent`) |
| `make reset` | डेटाबेस हटाकर फिर से शुरू करें |

---

## कॉर्पोरेट प्रॉक्सी / कस्टम CA प्रमाणपत्र

यदि आप TLS-निरीक्षण करने वाली कॉर्पोरेट प्रॉक्सी के पीछे हैं, तो सेटअप निर्देशों के लिए [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) देखें।
