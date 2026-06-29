# စတင်အသုံးပြုခြင်း

## ကြိုတင်လိုအပ်ချက်များ

| လိုအပ်ချက်                           | အသေးစိတ်အချက်အလက်                                            |
|---------------------------------------|----------------------------------------------------|
| **Docker**                            | Docker Desktop သို့မဟုတ် Docker Engine + Compose v2       |
| **make**                              | GNU Make (macOS တွင် ကြိုတင်ထည့်သွင်းပြီးသား)                  |
| **အရင်းအမြစ်များ**                         | အနည်းဆုံး RAM 16 GB၊ SSD ကို အကြံပြုသည်                 |
| **CloudTrail logs**                   | AWS မှ ထုတ်ယူထားသော `.json` သို့မဟုတ် `.json.gz` ဖိုင်များ      |
| *(ရွေးချယ်နိုင်)* **AWS Config snapshots** | AWS resource graph အတွက် `.json` သို့မဟုတ် `.json.gz` ဖိုင်များ |
| *(ရွေးချယ်နိုင်)* **OpenAI API key**       | AI query generation အတွက် လိုအပ်သည်                   |
| *(ရွေးချယ်နိုင်)* **MaxMind GeoLite2**     | GeoIP enrichment အတွက် `.mmdb` ဖိုင်များ                 |

---

## အမြန်စတင်ခြင်း

**အဆင့် 1.** S3 မှ CloudTrail logs များကို ဒေါင်းလုဒ်လုပ်ပါ။

```bash
aws s3 cp s3://<your-bucket-prefix> <local-output-dir>/ --recursive --include "*.json.gz"
```

**အဆင့် 2.** repository ကို clone လုပ်ပါ၊ logs များကို ingest လုပ်ပါ၊ ပြီးနောက် ဝန်ဆောင်မှုအားလုံးကို စတင်ပါ။

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

**အဆင့် 3.** 🪽 သင့်ဘရောက်ဆာကို ဖွင့်ပြီး hunting စတင်ပါ!🪽

- http://localhost:8501 — Built-in queries နှင့် AI Chat
- http://localhost:8088 — Dashboard (`admin` / `admin`)
- http://localhost:8502 — AWS Config resource graph

**(ရွေးချယ်နိုင်)** GeoIP enrichment။
[GeoLite2 `.mmdb` ဖိုင်များ](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) ကို `docker/data/geoip/` တွင် ထားရှိပါ၊ ပြီးနောက်:

```bash
make ingest-geoip
```

**(ရွေးချယ်နိုင်)** resource graph မြင်ကွင်းဖော်ပြခြင်းအတွက် AWS Config snapshot ingestion။
AWS Config snapshot ဖိုင်များကို `docker/logs/config/` တွင် ထားရှိပါ၊ ပြီးနောက်:
```bash
make ingest-config
```
---

## ကုမ္ပဏီ Proxy / စိတ်ကြိုက် CA Certificate

သင်သည် TLS-inspecting ကုမ္ပဏီ proxy တစ်ခု၏ နောက်ကွယ်တွင် ရှိနေပါက၊ တပ်ဆင်ခြင်းညွှန်ကြားချက်များအတွက် [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) ကို ကြည့်ပါ။
