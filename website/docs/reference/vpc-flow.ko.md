# VPC Flow Logs 레퍼런스

Senrigan은 CloudTrail과 같은 S3 사본에서 Amazon VPC Flow Logs를 수집하고, 🌊 **VPC Flow** 에이전트 페이지와 **VPC Flow Logs Threat Hunting** 대시보드에서 헌팅할 수 있게 합니다.

## 설정

`AWSLogs/` 접두사 전체를 복사하세요. 각 파일은 AWS 객체 이름으로 분류되며, 다이제스트, AWS Config, ELB 로그 등 다른 파일은 건너뛰고 수집 요약에 개수가 표시됩니다.

```bash
aws s3 sync s3://<your-bucket>/AWSLogs/ docker/logs/AWSLogs/
make ingest
make up
```

## 수집 대상

- 일반 텍스트 플로 로그(`.log.gz`) — 기본 또는 사용자 지정 형식, S3의 기본·시간별·Hive 호환 레이아웃을 지원합니다. AWS가 정의한 모든 필드를 보존하며, 이후 추가되는 필드도 유지됩니다.
- Parquet 플로 로그는 지원하지 않습니다. 건너뛰고 개수만 표시합니다.
- `docker/data/geoip/`에 GeoLite2가 있으면 모든 주소에 국가, 도시, ASN이 붙습니다. 나중에 `ingester enrich`로 채울 수도 있습니다.

## 플로 증거 읽는 법

- 한 행은 하나의 인터페이스에서 하나의 집계 구간 동안 관찰된 하나의 플로이며, 연결이 아닙니다. VPC 내부 트래픽은 두 번 관찰됩니다.
- `ACCEPT`는 보안 그룹이나 NACL이 패킷을 허용했다는 뜻이지, 세션이 성립했다는 뜻이 아닙니다.
- 로컬과 원격 엔드포인트는 레코드에 `flow-direction`이 있을 때(`direction_source = 'record'`)만 확정됩니다.
- Block Public Access로 거부된 레코드에는 바이트 수가 없으며, `traffic_path = 2`는 인터넷 게이트웨이 *또는* 게이트웨이 엔드포인트를 뜻합니다.
- Amazon DNS 리졸버, 인스턴스 메타데이터, Time Sync, DHCP로 가는 트래픽은 기록되지 않습니다.

## 🎯 기본 제공 헌트 18개 — 🌊 VPC Flow 페이지

모든 헌트는 API 키 없이 실행되며 필요한 필드를 선언합니다. 선택한 데이터에 그 필드가 없으면 빈 결과 대신 커버리지 부족을 알립니다.

| # | 헌트 | 카테고리 | 심각도 |
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

## 📊 차트 50개 대시보드 — VPC Flow Logs Threat Hunting

Coverage 탭부터 보세요. 다른 탭이 어떤 구독, 필드, 시간 범위를 볼 수 있는지 알려 줍니다.

| # | 차트 | 탭 |
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
