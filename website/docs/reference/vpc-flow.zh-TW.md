# VPC Flow Logs 參考

Senrigan 從與 CloudTrail 相同的 S3 副本載入 Amazon VPC Flow Logs，並在 🌊 **VPC Flow** 代理頁面與 **VPC Flow Logs Threat Hunting** 儀表板上進行狩獵。

## 設定

請複製整個 `AWSLogs/` 前綴。每個檔案依其 AWS 物件名稱分流；摘要檔、AWS Config、ELB 日誌與其他檔案會被略過，並計入匯入摘要。

```bash
aws s3 sync s3://<your-bucket>/AWSLogs/ docker/logs/AWSLogs/
make ingest
make up
```

## 匯入的內容

- 純文字流量日誌（`.log.gz`），預設或自訂格式，支援 S3 的預設、每小時與 Hive 相容配置。保留 AWS 定義的所有欄位，AWS 日後新增的欄位也會保留。
- 不支援 Parquet 流量日誌：會被略過並計數。
- 若 `docker/data/geoip/` 中有 GeoLite2，每個位址都會取得國家、城市與 ASN；也可之後以 `ingester enrich` 補上。

## 解讀流量證據

- 一列是在一個介面、一個彙總時間窗內觀察到的一個流量——不是連線。VPC 內部流量會被觀察到兩次。
- `ACCEPT` 表示安全群組或 NACL 允許了封包，並不代表工作階段已建立。
- 只有在記錄帶有 `flow-direction` 時（`direction_source = 'record'`），本地與遠端端點才是確定的。
- 被 Block Public Access 拒絕的記錄沒有位元組數，而 `traffic_path = 2` 表示網際網路閘道*或*閘道端點。
- 前往 Amazon DNS 解析器、執行個體中繼資料、Time Sync 與 DHCP 的流量永遠不會被記錄。

## 🎯 18 個內建狩獵 — 🌊 VPC Flow 頁面

每個狩獵都不需 API 金鑰即可執行，並宣告所需欄位：若所選資料未記錄該欄位，頁面會顯示涵蓋範圍不足，而非空結果。

| # | 狩獵 | 類別 | 嚴重度 |
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

## 📊 50 張圖表的儀表板 — VPC Flow Logs Threat Hunting

請從 Coverage 分頁開始：它顯示其他分頁能看到哪些訂閱、欄位與時間範圍。

| # | 圖表 | 分頁 |
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
