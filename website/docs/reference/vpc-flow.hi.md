# VPC Flow Logs संदर्भ

Senrigan, CloudTrail वाली उसी S3 कॉपी से Amazon VPC Flow Logs लोड करता है और 🌊 **VPC Flow** एजेंट पेज तथा **VPC Flow Logs Threat Hunting** डैशबोर्ड पर उनमें हंटिंग की सुविधा देता है।

## सेटअप

पूरा `AWSLogs/` prefix कॉपी करें। हर फ़ाइल उसके AWS object नाम से पहचानी जाती है; digest, AWS Config, ELB logs और अन्य फ़ाइलें छोड़ दी जाती हैं और ingest सारांश में गिनी जाती हैं।

```bash
aws s3 sync s3://<your-bucket>/AWSLogs/ docker/logs/AWSLogs/
make ingest
make up
```

## क्या ingest होता है

- Plain-text flow logs (`.log.gz`), default या custom format में, S3 के default, hourly या Hive-compatible layout में। AWS के सभी documented fields रखे जाते हैं, बाद में जुड़ने वाले fields भी।
- Parquet flow logs समर्थित नहीं हैं: उन्हें छोड़ दिया जाता है और गिना जाता है।
- `docker/data/geoip/` में GeoLite2 होने पर हर address को देश, शहर और ASN मिलता है; `ingester enrich` इन्हें बाद में भी जोड़ सकता है।

## Flow evidence कैसे पढ़ें

- एक row एक interface पर एक aggregation window में देखा गया एक flow है — कभी भी connection नहीं। VPC के अंदर का traffic दो बार दिखता है।
- `ACCEPT` का अर्थ है कि security group या NACL ने packets को अनुमति दी, यह नहीं कि session बना।
- Local और remote endpoints तभी निश्चित हैं जब record में `flow-direction` हो (`direction_source = 'record'`)।
- Block Public Access द्वारा rejected records में bytes नहीं होते, और `traffic_path = 2` का अर्थ है internet gateway *या* gateway endpoint।
- Amazon DNS resolver, instance metadata, Time Sync और DHCP का traffic कभी log नहीं होता।

## 🎯 18 built-in hunts — 🌊 VPC Flow पेज

हर hunt बिना API key के चलता है और ज़रूरी fields घोषित करता है: चुने गए data में कोई field log न हो, तो पेज खाली परिणाम के बजाय insufficient coverage बताता है।

| # | Hunt | श्रेणी | गंभीरता |
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

## 📊 50 charts वाला डैशबोर्ड — VPC Flow Logs Threat Hunting

Coverage tab से शुरू करें: यह बताता है कि बाकी tabs कौन-सी subscriptions, fields और time windows देख सकते हैं।

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
