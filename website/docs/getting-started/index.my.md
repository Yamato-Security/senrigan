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

**အဆင့် 2.** repository ကို clone လုပ်ပြီး သင့်ဒေတာများကို နေရာချပါ။

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded CloudTrail logs here
cp -r <local-output-dir>/ docker/logs/
```

အောက်ပါ ရွေးချယ်နိုင်သော directory နှစ်ခုကို အလိုအလျောက် ရှာဖွေတွေ့ရှိပါသည်။ နောက်အဆင့်မတိုင်မီ ထည့်သွင်းထားပါ — အပိုအမိန့် လုပ်ဆောင်ရန် မလိုအပ်ပါ။

| Directory | အကြောင်းအရာ | ထပ်တိုးလာသည့်အရာ |
|---|---|---|
| `docker/data/geoip/` | [GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | source IP များကို နိုင်ငံ၊ မြို့နှင့် ASN အဖြစ် ဖြေရှင်းပေးသည် |
| `docker/data/config-snapshots/` | AWS Config snapshot `.json` ဖိုင်များ | AWS Config resource graph ကို တည်ဆောက်သည် |

**အဆင့် 3.** logs များကို ingest လုပ်ပြီး ဝန်ဆောင်မှုများကို စတင်ပါ။

```bash
make ingest
make up
```

**အဆင့် 4.** 🪽 သင့်ဘရောက်ဆာကို ဖွင့်ပြီး hunting စတင်ပါ!🪽

- http://localhost:8501 — Built-in queries နှင့် AI Chat
- http://localhost:8088 — Dashboard (`admin` / `admin`)
- http://localhost:8502 — AWS Config resource graph

---

## နေ့စဉ်သုံး command များ

`make` ကို argument မပါဘဲ လုပ်ဆောင်ပါက ဤစာရင်းကို ပြသပါသည်။ target အားလုံးကို `make help-all` ဖြင့် ကြည့်ရှုနိုင်ပါသည်။

| Command | လုပ်ဆောင်ချက် |
|---|---|
| `make ingest` | `docker/logs/` မှ CloudTrail logs များကို DuckDB သို့ ထည့်သွင်းသည် |
| `make up` | UI၊ dashboard နှင့် resource graph ကို စတင်သည် |
| `make down` | အားလုံးကို ရပ်တန့်သည် |
| `make logs` | ဝန်ဆောင်မှု logs များကို စောင့်ကြည့်သည် (တစ်ခုတည်းအတွက် `SERVICE=agent`) |
| `make reset` | ဒေတာဘေ့စ်ကို ဖျက်ပြီး အစမှ ပြန်စသည် |

---

## ကုမ္ပဏီ Proxy / စိတ်ကြိုက် CA Certificate

သင်သည် TLS-inspecting ကုမ္ပဏီ proxy တစ်ခု၏ နောက်ကွယ်တွင် ရှိနေပါက၊ တပ်ဆင်ခြင်းညွှန်ကြားချက်များအတွက် [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) ကို ကြည့်ပါ။
