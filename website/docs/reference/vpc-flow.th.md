# ข้อมูลอ้างอิง VPC Flow Logs

Senrigan โหลด Amazon VPC Flow Logs จากสำเนา S3 ชุดเดียวกับ CloudTrail และให้ล่าภัยคุกคามได้บนหน้าเอเจนต์ 🌊 **VPC Flow** และแดชบอร์ด **VPC Flow Logs Threat Hunting**

## การตั้งค่า

คัดลอก prefix `AWSLogs/` ทั้งหมด แต่ละไฟล์จะถูกแยกตามชื่อออบเจ็กต์ของ AWS ส่วนไฟล์ digest, AWS Config, ELB logs และไฟล์อื่นจะถูกข้ามและนับรวมในสรุปการ ingest

```bash
aws s3 sync s3://<your-bucket>/AWSLogs/ docker/logs/AWSLogs/
make ingest
make up
```

## สิ่งที่ถูก ingest

- Flow logs แบบข้อความธรรมดา (`.log.gz`) ทั้งรูปแบบเริ่มต้นและกำหนดเอง ในโครงสร้าง S3 แบบเริ่มต้น รายชั่วโมง หรือแบบ Hive เก็บทุกฟิลด์ที่ AWS กำหนด รวมถึงฟิลด์ที่เพิ่มในภายหลัง
- ไม่รองรับ flow logs แบบ Parquet: จะถูกข้ามและนับจำนวน
- หากมี GeoLite2 ใน `docker/data/geoip/` ทุกที่อยู่จะได้ประเทศ เมือง และ ASN และ `ingester enrich` เติมให้ภายหลังได้

## วิธีอ่านหลักฐานจาก flow

- หนึ่งแถวคือหนึ่ง flow ที่สังเกตได้บนหนึ่งอินเทอร์เฟซในหนึ่งช่วงรวบรวม ไม่ใช่การเชื่อมต่อ ทราฟฟิกภายใน VPC จะถูกสังเกตสองครั้ง
- `ACCEPT` หมายถึง security group หรือ NACL อนุญาตแพ็กเก็ต ไม่ได้หมายความว่าเกิดเซสชันแล้ว
- ฝั่ง local และ remote จะแน่นอนก็ต่อเมื่อเรคคอร์ดมี `flow-direction` (`direction_source = 'record'`)
- เรคคอร์ดที่ถูก Block Public Access ปฏิเสธไม่มีจำนวนไบต์ และ `traffic_path = 2` หมายถึง internet gateway *หรือ* gateway endpoint
- ทราฟฟิกไปยัง Amazon DNS resolver, instance metadata, Time Sync และ DHCP จะไม่ถูกบันทึก

## 🎯 ฮันต์ในตัว 18 รายการ — หน้า 🌊 VPC Flow

ทุกฮันต์รันได้โดยไม่ต้องใช้ API key และประกาศฟิลด์ที่ต้องใช้ หากข้อมูลที่เลือกไม่มีฟิลด์นั้น หน้าจะแจ้งว่าความครอบคลุมไม่เพียงพอแทนการแสดงผลว่าง

| # | ฮันต์ | หมวดหมู่ | ความรุนแรง |
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

## 📊 แดชบอร์ด 50 แผนภูมิ — VPC Flow Logs Threat Hunting

เริ่มจากแท็บ Coverage ซึ่งแสดงว่าแท็บอื่นเห็น subscription ฟิลด์ และช่วงเวลาใดได้บ้าง

| # | แผนภูมิ | แท็บ |
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
