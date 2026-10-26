# VPC Flow Logs ကိုးကားချက်

Senrigan သည် CloudTrail နှင့် တူညီသော S3 မိတ္တူမှ Amazon VPC Flow Logs ကို ထည့်သွင်းပြီး 🌊 **VPC Flow** agent စာမျက်နှာနှင့် **VPC Flow Logs Threat Hunting** dashboard တွင် hunting လုပ်နိုင်စေသည်။

## စတင်ပြင်ဆင်ခြင်း

`AWSLogs/` prefix တစ်ခုလုံးကို ကူးယူပါ။ ဖိုင်တစ်ခုစီကို AWS object အမည်ဖြင့် ခွဲခြားပြီး digest၊ AWS Config၊ ELB logs နှင့် အခြားဖိုင်များကို ကျော်သွားကာ ingest အကျဉ်းချုပ်တွင် ရေတွက်ပြသည်။

```bash
aws s3 sync s3://<your-bucket>/AWSLogs/ docker/logs/AWSLogs/
make ingest
make up
```

## ထည့်သွင်းသည့်အရာများ

- Plain-text flow logs (`.log.gz`)၊ default သို့မဟုတ် custom format၊ S3 ၏ default၊ hourly သို့မဟုတ် Hive-compatible layout။ AWS က သတ်မှတ်ထားသော field အားလုံးနှင့် နောက်မှ ထပ်တိုးမည့် field များကိုပါ ထိန်းသိမ်းသည်။
- Parquet flow logs ကို မပံ့ပိုးပါ — ကျော်သွားပြီး ရေတွက်သည်။
- `docker/data/geoip/` တွင် GeoLite2 ရှိပါက address တိုင်းသည် နိုင်ငံ၊ မြို့နှင့် ASN ရရှိသည်။ `ingester enrich` ဖြင့် နောက်မှလည်း ဖြည့်နိုင်သည်။

## Flow အထောက်အထားကို ဖတ်နည်း

- Row တစ်ခုသည် interface တစ်ခုတွင် aggregation window တစ်ခုအတွင်း မြင်တွေ့ရသော flow တစ်ခုဖြစ်သည် — connection မဟုတ်ပါ။ VPC အတွင်း traffic ကို နှစ်ကြိမ် မြင်ရသည်။
- `ACCEPT` ဆိုသည်မှာ security group သို့မဟုတ် NACL က packet များကို ခွင့်ပြုခဲ့ခြင်းဖြစ်ပြီး session တည်ဆောက်ပြီးကြောင်း မဆိုလိုပါ။
- Record တွင် `flow-direction` ပါမှသာ local နှင့် remote endpoint များ သေချာသည် (`direction_source = 'record'`)။
- Block Public Access မှ ငြင်းပယ်ထားသော record များတွင် bytes မရှိပါ၊ `traffic_path = 2` သည် internet gateway *သို့မဟုတ်* gateway endpoint ကို ဆိုလိုသည်။
- Amazon DNS resolver၊ instance metadata၊ Time Sync နှင့် DHCP သို့ traffic ကို ဘယ်တော့မှ log မလုပ်ပါ။

## 🎯 Built-in hunts 18 ခု — 🌊 VPC Flow စာမျက်နှာ

Hunt တိုင်းသည် API key မလိုဘဲ run နိုင်ပြီး လိုအပ်သော field များကို ကြေညာထားသည်။ ရွေးထားသော data တွင် ထို field မပါပါက ရလဒ်အလွတ်အစား coverage မလုံလောက်ကြောင်း ပြသည်။

| # | Hunt | အမျိုးအစား | ပြင်းထန်မှု |
|---|---|---|---|
| 1 | 🧭 Flow Log Sources and Field Coverage | 🧭 Coverage | P4 |
| 2 | 🧭 SKIPDATA Gaps by Interface | 🧭 Coverage | P3 |
| 3 | 🔍 Vertical Port Scans | 🔍 Recon | P3 |
| 4 | 🔍 Horizontal Sweeps | 🔍 Recon | P3 |
| 5 | 🚪 Internet Access to Admin / DB Ports | 🚪 Exposure | P1 |
| 6 | 🚪 Rejected, Then Accepted | 🚪 Exposure | P2 |
| 7 | 📤 Egress Spike vs Host Baseline | 📤 Egress | P1 |
| 8 | 📤 Unusual Destination Ports | 📤 Egress | P2 |
| 9 | 📤 DNS to Non-Amazon Resolvers | 📤 Egress | P3 |
| 10 | 📤 Outbound SMTP | 📤 Egress | P3 |
| 11 | ⏱️ Periodic Observations to External Peers | ⏱️ Periodicity | P2 |
| 12 | ↔️ New Internal Admin-Port Pairs | ↔️ Lateral Movement | P1 |
| 13 | ↔️ Internal Inbound, Then External Egress | ↔️ Lateral Movement | P2 |
| 14 | 🧪 Unusual IP Protocols | 🧪 Protocols | P3 |
| 15 | 🧪 UDP Fan-Out to External Hosts | 🧪 Protocols | P3 |
| 16 | 🧪 ICMP and ICMPv6 Peers | 🧪 Protocols | P4 |
| 17 | 🌍 Accepted Inbound by Country | 🌍 GeoIP | P4 |
| 18 | 🛡️ BPA and Encryption-Control Rejections | 🛡️ Posture | P3 |

## 📊 Chart 50 ခုပါ dashboard — VPC Flow Logs Threat Hunting

Coverage tab မှ စတင်ပါ — အခြား tab များက မည်သည့် subscription၊ field နှင့် အချိန်ကာလကို မြင်နိုင်သည်ကို ပြသည်။

| # | Chart | Tab |
|---|---|---|
| 1 | Flow Log Sources | 🧭 Coverage |
| 2 | Capture Scope from CloudTrail | 🧭 Coverage |
| 3 | NODATA / SKIPDATA Windows | 🧭 Coverage |
| 4 | Records by Direction Source | 🧭 Coverage |
| 5 | Field Availability by Source | 🧭 Coverage |
| 6 | Flow Records | 🚦 Overview |
| 7 | Bytes Observed | 🚦 Overview |
| 8 | REJECT Ratio | 🚦 Overview |
| 9 | Distinct External Peers | 🚦 Overview |
| 10 | Interfaces Observed | 🚦 Overview |
| 11 | SKIPDATA Windows | 🚦 Overview |
| 12 | Flow Records by Action | 🚦 Overview |
| 13 | Bytes by Direction | 🚦 Overview |
| 14 | Top Rejected External Sources | 🔍 Inbound / Recon |
| 15 | Vertical Scan Candidates | 🔍 Inbound / Recon |
| 16 | Horizontal Scan Candidates | 🔍 Inbound / Recon |
| 17 | Internet to Admin / DB Ports — Accepted | 🔍 Inbound / Recon |
| 18 | SYN-Only Records from External Sources | 🔍 Inbound / Recon |
| 19 | REJECT then ACCEPT — Same Peer, Target and Port | 🔍 Inbound / Recon |
| 20 | Top External Destinations by Bytes | 📤 Egress |
| 21 | Egress Volume vs Host Baseline | 📤 Egress |
| 22 | Egress Bytes by Traffic Path | 📤 Egress |
| 23 | Unusual Destination Ports | 📤 Egress |
| 24 | DNS to Non-Amazon Resolvers | 📤 Egress |
| 25 | Outbound SMTP | 📤 Egress |
| 26 | Long-Running and Low-and-Slow Flows | 📤 Egress |
| 27 | Periodic Flow-Log Observations | ⏱️ Periodicity |
| 28 | Internal Admin-Port Traffic | ↔️ Lateral Movement |
| 29 | First-Seen Internal Pairs | ↔️ Lateral Movement |
| 30 | Internal Fan-Out by Source | ↔️ Lateral Movement |
| 31 | Internal Inbound Followed by External Egress | ↔️ Lateral Movement |
| 32 | ICMP / ICMPv6 Peers | 🧪 Protocols & IPv6 |
| 33 | UDP Fan-Out to External Hosts | 🧪 Protocols & IPv6 |
| 34 | Unusual IP Protocols | 🧪 Protocols & IPv6 |
| 35 | IPv6 Flows | 🧪 Protocols & IPv6 |
| 36 | Inbound Countries | 🌍 GeoIP |
| 37 | Outbound Countries | 🌍 GeoIP |
| 38 | External ASNs | 🌍 GeoIP |
| 39 | Inbound Accepted — Origin Map | 🌍 GeoIP |
| 40 | Inbound Rejected — Origin Map | 🌍 GeoIP |
| 41 | Outbound Bytes — Destination Map | 🌍 GeoIP |
| 42 | Inbound Records by Country and Action | 🌍 GeoIP |
| 43 | Inbound Accepted Ports by Country | 🌍 GeoIP |
| 44 | Top Outbound ASNs by Bytes | 🌍 GeoIP |
| 45 | Rare Outbound Countries | 🌍 GeoIP |
| 46 | REJECT Reasons (BPA / Encryption Controls) | 🛡️ Posture |
| 47 | Encryption Status | 🛡️ Posture |
| 48 | Egress to AWS Services by Path | 🛡️ Posture |
| 49 | Middlebox Interfaces | 🛡️ Posture |
| 50 | Egress Heatmap (UTC Hour × Weekday) | 🛡️ Posture |
