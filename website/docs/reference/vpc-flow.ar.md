# مرجع VPC Flow Logs

يحمّل Senrigan سجلات Amazon VPC Flow Logs من نسخة S3 نفسها التي يُحمَّل منها CloudTrail، ويتيح البحث عن التهديدات فيها عبر صفحة الوكيل 🌊 **VPC Flow** ولوحة **VPC Flow Logs Threat Hunting**.

## الإعداد

انسخ البادئة `AWSLogs/` كاملةً. يُوجَّه كل ملف حسب اسم كائن AWS الخاص به، وتُتخطى ملفات الملخصات وAWS Config وسجلات ELB وغيرها وتُحتسب في ملخص الاستيعاب.

```bash
aws s3 sync s3://<your-bucket>/AWSLogs/ docker/logs/AWSLogs/
make ingest
make up
```

## ما الذي يُستوعَب

- سجلات التدفق النصية (`.log.gz`) بالتنسيق الافتراضي أو المخصص، وبتخطيط S3 الافتراضي أو بالساعة أو المتوافق مع Hive. تُحفظ كل الحقول التي توثقها AWS، بما فيها الحقول التي تُضاف لاحقًا.
- سجلات التدفق بتنسيق Parquet غير مدعومة: تُتخطى وتُحتسب.
- مع وجود GeoLite2 في `docker/data/geoip/` يحصل كل عنوان على الدولة والمدينة وASN، ويمكن لـ `ingester enrich` إضافتها لاحقًا.

## قراءة أدلة التدفق

- الصف هو تدفق واحد رُصد على واجهة واحدة خلال نافذة تجميع واحدة، وليس اتصالًا أبدًا. تُرصد الحركة داخل الـ VPC مرتين.
- تعني `ACCEPT` أن مجموعة الأمان أو NACL سمحت بالحزم، لا أن جلسة قد أُنشئت.
- لا يكون الطرفان المحلي والبعيد مؤكدين إلا إذا تضمّن السجل `flow-direction` (`direction_source = 'record'`).
- السجلات المرفوضة بواسطة Block Public Access لا تحمل عدد البايتات، و`traffic_path = 2` تعني بوابة الإنترنت *أو* نقطة نهاية البوابة.
- لا تُسجَّل أبدًا الحركة إلى محلّل DNS الخاص بـ Amazon وبيانات تعريف المثيل وTime Sync وDHCP.

## 🎯 18 عملية بحث مدمجة — صفحة 🌊 VPC Flow

تعمل كل عملية بحث دون مفتاح API وتعلن الحقول التي تحتاجها: إذا لم تسجّل البيانات المحددة أحدها، تُبلغ الصفحة عن تغطية غير كافية بدلًا من نتيجة فارغة.

| # | عملية البحث | الفئة | الخطورة |
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

## 📊 لوحة من 50 مخططًا — VPC Flow Logs Threat Hunting

ابدأ بتبويب Coverage: فهو يبيّن الاشتراكات والحقول والفترات الزمنية التي تستطيع التبويبات الأخرى رؤيتها.

| # | المخطط | التبويب |
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
