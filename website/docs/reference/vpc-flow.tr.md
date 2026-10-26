# VPC Flow Logs Başvurusu

Senrigan, Amazon VPC Flow Logs'u CloudTrail ile aynı S3 kopyasından yükler ve 🌊 **VPC Flow** ajan sayfasında ve **VPC Flow Logs Threat Hunting** panosunda avlanmaya açar.

## Kurulum

`AWSLogs/` önekinin tamamını kopyalayın. Her dosya AWS nesne adına göre yönlendirilir; özet dosyaları, AWS Config, ELB günlükleri ve diğer dosyalar atlanır ve içe aktarma özetinde sayılır.

```bash
aws s3 sync s3://<your-bucket>/AWSLogs/ docker/logs/AWSLogs/
make ingest
make up
```

## Neler içe aktarılır

- Düz metin akış günlükleri (`.log.gz`); varsayılan veya özel biçim, S3'ün varsayılan, saatlik ya da Hive uyumlu düzeninde. AWS'nin belgelediği tüm alanlar ve sonradan eklenecek alanlar korunur.
- Parquet akış günlükleri desteklenmez: atlanır ve sayılır.
- `docker/data/geoip/` içinde GeoLite2 varsa her adres ülke, şehir ve ASN alır; `ingester enrich` bunları sonradan da ekler.

## Akış kanıtını okumak

- Bir satır, tek bir arayüzde tek bir toplama penceresinde gözlemlenen tek bir akıştır — asla bir bağlantı değildir. VPC içi trafik iki kez gözlemlenir.
- `ACCEPT`, bir güvenlik grubunun veya NACL'nin paketlere izin verdiği anlamına gelir; oturumun kurulduğu anlamına gelmez.
- Yerel ve uzak uç noktalar yalnızca kayıt `flow-direction` içerdiğinde kesindir (`direction_source = 'record'`).
- Block Public Access tarafından reddedilen kayıtlarda bayt bilgisi yoktur ve `traffic_path = 2` internet ağ geçidi *veya* ağ geçidi uç noktası demektir.
- Amazon DNS çözümleyicisine, örnek meta verilerine, Time Sync'e ve DHCP'ye giden trafik asla kaydedilmez.

## 🎯 18 yerleşik av — 🌊 VPC Flow sayfası

Her av API anahtarı olmadan çalışır ve ihtiyaç duyduğu alanları bildirir: seçilen veriler bunlardan birini kaydetmiyorsa sayfa boş sonuç yerine yetersiz kapsama bildirir.

| # | Av | Kategori | Önem |
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

## 📊 50 grafiklik pano — VPC Flow Logs Threat Hunting

Coverage sekmesiyle başlayın: diğer sekmelerin hangi abonelikleri, alanları ve zaman aralıklarını görebildiğini gösterir.

| # | Grafik | Sekme |
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
