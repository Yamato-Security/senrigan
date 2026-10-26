# Requirements Document — Amazon VPC Flow Logs Support

## Senrigan — VPC Flow Logs Ingestion, Dashboard and Hunting

| Field | Details |
|-------|---------|
| Document Version | 0.2 (Draft) |
| Date | 2026-10-26 |
| Status | Phases 0–4 implemented (2026-10-27). Phase 1.5 measured on synthetic data only — the realistic-data gate was deferred by decision; Phase 5 not started |
| Related | [PRD.md](PRD.md), [ARCHITECTURE.md](ARCHITECTURE.md), [TDD_GUIDE.md](TDD_GUIDE.md), [PRD_VPC_FLOW_LOGS_REVIEW.md](PRD_VPC_FLOW_LOGS_REVIEW.md) |

---

## 1. Executive Summary

Senrigan hunts over CloudTrail, which records *who called which AWS API*. It cannot see what
happened on the network afterwards: a scan against an exposed instance, a reverse shell, a
large outbound transfer, or lateral movement between subnets. Amazon VPC Flow Logs record
that layer — as **aggregated per-interface observations**, not as connections.

This document plans VPC Flow Logs support end to end:

- **Ingest** — `make ingest` loads a verbatim S3 copy of `AWSLogs/` in one pass. CloudTrail and
  Flow Logs are told apart per file; everything else in the copy is skipped and counted.
- **Store** — new `vpc_flow_*` tables in the existing `threat_hunting.db`, written only by
  `ingester`, so the one-writer invariant is unchanged. Evidence is never silently rewritten:
  AWS `-` and malformed values stay distinguishable, and file-level provenance is kept.
- **Enrich** — GeoIP per distinct address in an `ip_geo` lookup table, so every address column
  can be enriched without guessing which endpoint is remote.
- **Visualise** — a new Superset bundle with network-centric threat hunting tabs, coverage first.
- **Hunt** — a new agent chat page with built-in SQL hunts, each declaring the fields it needs.

### 1.1 Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Flow Logs live in the same `docker/logs/` tree as CloudTrail and are routed by path/name | `aws s3 sync s3://<bucket>/AWSLogs/ docker/logs/AWSLogs/` must be all a user does |
| D2 | The existing `ingester ingest` subcommand classifies and dispatches; no `flow-ingest` subcommand | One command for both `make ingest` and direct CLI use |
| D3 | Everything copied is ingested — no default date window, no default row reduction | Keeps the default simple; date-bounded runs stay under `make help-all` |
| D4 | Only the plain-text format (`.log.gz`) is supported; Parquet is out of scope — skipped and counted | Text is the S3 default. Parquet would need either a new crate or an exception to the Appender-only write rule, for no hunting capability text lacks |
| D5 | GeoIP is stored once per distinct address in `ip_geo`, not as columns on the flow table | Geo becomes available for `srcaddr`, `dstaddr`, `pkt_*addr` and `remote_addr` alike, so a wrong remote/local guess can never attach geo to the wrong endpoint; memory and back-fill cost scale with distinct addresses, not rows (review F-01, F-09) |
| D6 | A remote endpoint is definitive only when the record carries `flow-direction`; otherwise it is labelled heuristic or left NULL | Without direction, address class does not identify the ENI-local side (review F-01) |
| D7 | A row is an *observation*: counts are "flow records", never "connections" | Records aggregate a 5-tuple over a window per interface; one flow can appear on several interfaces (review F-02, F-03) |

---

## 2. VPC Flow Logs Specification (as it affects the implementation)

Sources: [Flow log records](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html),
[Flow log files](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3-path.html),
[Limitations](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-limitations.html),
[Record examples](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html).

### 2.1 S3 delivery

| Item | Value |
|------|-------|
| Default prefix | `AWSLogs/{account}/vpcflowlogs/{region}/{yyyy}/{mm}/{dd}/` |
| Hourly partitions | `…/{yyyy}/{mm}/{dd}/{HH}/` |
| Hive-compatible prefix | `AWSLogs/aws-account-id={account}/aws-service=vpcflowlogs/aws-region={region}/year={yyyy}/month={mm}/day={dd}/[hour={HH}/]` |
| File name | `{account}_vpcflowlogs_{region}_{flow-log-id}_{YYYYMMDD}T{HHmm}Z_{hash}.log.gz` |
| Delivery | Files every 5 minutes; several files per window are possible |
| Formats | Plain text (default; space-delimited, gzip) or Parquet (gzip) |
| Header | Text files start with a header line naming the fields in record order |
| Format stability | A subscription's format cannot change after creation, so the field set is fixed per `flow-log-id` |
| Missing value | `-` (field not applicable or not computable) |
| `log-status` | `OK`, `NODATA` (no traffic in the window), `SKIPDATA` (records dropped) |
| Aggregation | 10 min max by default, 1 min optional; always ≤ 1 min on Nitro |

### 2.2 Fields by version

The default format is exactly the version-2 fields, in this order. A custom format may select
any subset in any order — which is why the parser must be driven by the header line.

| Ver | Fields |
|-----|--------|
| 2 | `version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status` |
| 3 | `vpc-id subnet-id instance-id tcp-flags type pkt-srcaddr pkt-dstaddr` |
| 4 | `region az-id sublocation-type sublocation-id` |
| 5 | `pkt-src-aws-service pkt-dst-aws-service flow-direction traffic-path` |
| 7 | `ecs-cluster-arn ecs-cluster-name ecs-container-instance-arn ecs-container-instance-id ecs-container-id ecs-second-container-id ecs-service-name ecs-task-definition-arn ecs-task-arn ecs-task-id` |
| 8 | `reject-reason` (`BPA` / `EC`) |
| 9 | `resource-id` (regional NAT gateway) |
| 10 | `encryption-status` (`0`–`3`) |
| 11 | `instance-tag instance-tag-2 interface-tag interface-tag-2 asg-tag asg-tag-2 interface-type next-hop-interface-id next-hop-subnet-id next-hop-az-id next-hop-vpc-id next-hop-interface-type` |

Selected value domains used by hunts:

- `tcp-flags` — bitmask, OR-ed over the window: FIN 1, SYN 2, RST 4, SYN-ACK 18. A short
  connection can show 3 (SYN+FIN) or 19 (SYN-ACK+FIN) on one row.
- `traffic-path` (egress only; not supported for ingress) — 1 same VPC or Outpost local gateway,
  **2 Internet Gateway *or* gateway endpoint (ambiguous)**, 3 VGW, 4 intra-region peering,
  5 inter-region peering, 6 Local/Wavelength Zone, **7 gateway endpoint**, **8 Internet Gateway**.
- `pkt-*-aws-service` — `AMAZON`, `S3`, `EC2`, `ROUTE53_RESOLVER`, … when the packet address is
  public and belongs to an AWS range.
- ICMP records carry `0` in `srcport` and `dstport` (AWS record examples); type and code are not
  available.

### 2.3 Limits every hunt must respect

| Limit | Consequence |
|-------|-------------|
| Flow metadata only — no payload | Content-based detection is impossible |
| One row = one 5-tuple × one interface × one aggregation window | Row counts are observation counts, not connection counts; timestamps are window bounds with up to ~60 s skew |
| Intra-VPC traffic is observed on both the sending and receiving ENI; NAT GW / TGW / ELB add their own interfaces | Byte and record totals double-count unless observations are de-duplicated (§4.3) |
| No DNS names | Domain-level hunting needs Route 53 Resolver query logs (out of scope) |
| Not logged: Amazon DNS, IMDS (169.254.169.254), Time Sync (169.254.169.123), DHCP, ARP, Windows license activation, default VPC router reserved IP, mirrored source traffic | The CloudTrail-side SSRF/IMDS hunts cannot be replaced; any observed port-53 flow is, by construction, to a non-Amazon resolver |
| `srcaddr`/`dstaddr` show the interface's primary private IP for middlebox, secondary-IP and NAT traffic | The original peer is only in `pkt-srcaddr`/`pkt-dstaddr` (v3+) |
| `ACCEPT` ≠ established connection | A SYN-only scan is `ACCEPT`; use `tcp-flags` |
| BPA records carry no `bytes` and no `SKIPDATA` | Byte metrics must exclude BPA rows rather than read them as zero |
| Metadata fields (instance, ECS, tags, next-hop) are best effort | Treat as hints; tag values may be wrong in a subscription's first hour |
| Capture scope (VPC / subnet / ENI, `ALL` / `ACCEPT` / `REJECT`) is not in the records | "No finding" must be qualified by coverage (§4.2) |

---

## 3. Ingestion Design

### 3.1 File classification (`ingester/src/log_kind.rs`, new)

A pure function `classify(path) -> LogKind` decides per file. A whole-bucket copy contains more
than CloudTrail, and today the extras are not skipped — they fail to parse and are counted as
errors.

| Path / name | `LogKind` | Handling |
|-------------|-----------|----------|
| `…/CloudTrail/…/*_CloudTrail_*.json.gz` | `CloudTrail` | Existing pipeline, unchanged |
| `…/vpcflowlogs/…/*_vpcflowlogs_*.log.gz` | `VpcFlowText` | Flow pipeline |
| `aws-service=vpcflowlogs/…/*.log.gz` | `VpcFlowText` | Flow pipeline |
| `…/vpcflowlogs/…/*.parquet` | `Skipped(VpcFlowParquet)` | Counted; out of scope (D4). The summary names the count so a Parquet-only copy is not mistaken for an empty one |
| `…/CloudTrail-Digest/…` | `Skipped(CloudTrailDigest)` | Counted (today: parse error) |
| `…/CloudTrail-Insight/…` | `Skipped(CloudTrailInsight)` | Counted |
| `…/Config/…` | `Skipped(Config)` | Counted (today: parse error) |
| `…/elasticloadbalancing/…/*.log.gz` | `Skipped(Other)` | Same extension as Flow Logs — must not be mistaken for them |
| `.json` / `.json.gz` with no service hint | `CloudTrail` | Backward compatibility with hand-made test files |
| anything else | `Skipped(Other)` | Counted |

AWS names every delivered object `{account}_{service}_{region}_…`, so the service token in the
file name is the primary signal; a service directory segment anywhere in the path (plain or
`aws-service=`) is the fallback for renamed files, so Organization trails
(`AWSLogs/<org-id>/<account>/…`) classify the same way as single-account ones. A CloudTrail file
name wins over a directory that happens to be called `Config`. Classification is by path only;
content validation happens in the parser (§3.3), so a named flow-log file that turns out not to
be one is a *failed file*, never a silent skip.

### 3.2 Pipeline (`ingester/src/ingest.rs`)

```
walk (once) → date filter → path filter → classify
   ├─ CloudTrail    → existing parse/insert pipeline              (unchanged)
   ├─ VpcFlowText   → flow_ingest::run on the same connection, after CloudTrail
   │                    per chunk: BEGIN → rows + file metadata + parse issues + dedup marks → COMMIT
   │                  then: ip_geo post-pass (§5)
   └─ Skipped(kind) → counted per kind
```

- One process, one READ_WRITE connection, run sequentially — the one-writer invariant holds.
- The flow pipeline mirrors the CloudTrail one: rayon-parallel parse in chunks, a bounded
  channel, a single writer thread using `duckdb::Appender` (`appender_with_columns`, so the
  physical column order never matters). Chunks are capped at 8 MiB of *compressed* input rather
  than a file count, because flow log objects range from kilobytes to many megabytes and a fixed
  file count has no memory bound (measured in §8 Phase 1.5).
- **Atomicity (review F-08).** A chunk's flow rows, its `vpc_flow_files` rows, its parse issues
  and its `ingested_files` marks are written inside one transaction. A failure rolls the whole
  chunk back, so a retry cannot append the same evidence twice. The CloudTrail pipeline has the
  same latent failure mode today; fixing it is tracked separately and not in this scope.
- Deduplication reuses `ingested_files` (`file_path`, `sha256`); a re-sync ingests only new files.
- `IngestStats` reports, per kind: input files, ingested files, failed files, valid rows,
  rows with field issues, rejected rows, and skipped files. The CLI summary prints, e.g.:

```
CloudTrail: 1,234 files / 98,765 records
VPC Flow:   8,640 files / 45,210,000 records (field issues 12 rows, rejected 3 rows, failed 1 file)
Skipped:    CloudTrail-Digest 288, Config 30, Parquet 0, other 2
Warning:    2 flow files exceed 1% rejected rows — see vpc_flow_files
```

### 3.3 Parser (`ingester/src/flow_parser.rs`, new)

**Header acceptance (review F-04).** The first line is a header when every token matches
`^[a-z0-9]+(-[a-z0-9]+)*$`, no token repeats, and at least three tokens are known field names.
Unknown tokens are accepted and their values go to `extra`. A line that is not a header is
accepted as data only if it has exactly 14 tokens and parses as the version-2 default format
(CloudWatch Logs exports). Anything else fails the file.

**Values (review F-05).**

| Input | Stored as | Recorded |
|-------|-----------|----------|
| `-` | `NULL` | nothing — this is AWS's own "not applicable" |
| valid value | typed value | nothing |
| malformed value in a typed field (e.g. `abc` in `bytes`) | `NULL`, row kept, `has_parse_issue = TRUE` | one `vpc_flow_parse_issues` row: file, line, field, raw value |
| token count ≠ header length | row rejected | one `vpc_flow_parse_issues` row with the raw line |

Issue rows store raw text for at most the first 100 issues per file, so a corrupt file cannot
balloon the database; the per-file counts in `vpc_flow_files` are always complete. A file with
more than 1% rejected rows raises a summary warning; the run never aborts because of one file,
matching the CloudTrail pipeline's per-file error behaviour.

**Endpoint derivation (review F-01).** See §4.1.

### 3.4 Filters

- `date_filter.rs` additionally recognises `year=YYYY/month=MM/day=DD` (Hive prefixes) and the
  `_YYYYMMDDTHHmmZ_` timestamp in AWS object names. The latter also applies to CloudTrail object
  names, so a flat copy without `yyyy/mm/dd` directories is now date-filtered instead of always
  included.
- `--from` / `--to` / `--include` / `--exclude` apply to every `LogKind`.

### 3.5 Makefile

- `make ingest` proceeds when *either* CloudTrail JSON or Flow Logs are present; today it exits
  when no `*.json` / `*.json.gz` exists, which would block a Flow-Logs-only copy.
- Detection lines join the existing GeoIP / Config ones, e.g.
  `✓ VPC Flow Logs found in docker/logs/ — ingesting alongside CloudTrail`.
- The "no logs" hint changes from `aws s3 cp … --include "*.json.gz"` to
  `aws s3 sync s3://<bucket>/AWSLogs/ docker/logs/AWSLogs/`.
- The command still takes no flags (D3).

---

## 4. Data Model

All tables are created by `ingester/src/flow_db.rs` (new) with `CREATE TABLE IF NOT EXISTS`;
later additions use `ALTER TABLE ADD COLUMN IF NOT EXISTS`. Views are created by the ingester
with `CREATE OR REPLACE VIEW`, so readers stay read-only.

### 4.1 `vpc_flow_logs` — one row per observation

Field names map hyphen → underscore; three are renamed because the AWS name is a SQL keyword or
ambiguous. Original address fields are always kept as first-class columns.

| Group | Columns | Type |
|-------|---------|------|
| Time | `start_time`, `end_time` (main time column: `start_time`); `duration_secs` | `TIMESTAMP`; `INTEGER` |
| v2 | `version`, `srcport`, `dstport`, `protocol` | `INTEGER` |
| v2 | `packets`, `bytes`, `start_unix` (`start`), `end_unix` (`end`) | `BIGINT` |
| v2 | `account_id`, `interface_id`, `srcaddr`, `dstaddr`, `action`, `log_status` | `VARCHAR` |
| v3 | `tcp_flags` | `INTEGER` |
| v3 | `vpc_id`, `subnet_id`, `instance_id`, `traffic_type` (`type`), `pkt_srcaddr`, `pkt_dstaddr` | `VARCHAR` |
| v4 | `region`, `az_id`, `sublocation_type`, `sublocation_id` | `VARCHAR` |
| v5 | `traffic_path` | `INTEGER` |
| v5 | `pkt_src_aws_service`, `pkt_dst_aws_service`, `flow_direction` | `VARCHAR` |
| v7 | `ecs_cluster_arn` … `ecs_task_id` (10 columns) | `VARCHAR` |
| v8–v10 | `reject_reason`, `resource_id` / `encryption_status` | `VARCHAR` / `INTEGER` |
| v11 | `instance_tag`, `instance_tag_2`, `interface_tag`, `interface_tag_2`, `asg_tag`, `asg_tag_2`, `interface_type`, `next_hop_interface_id`, `next_hop_subnet_id`, `next_hop_az_id`, `next_hop_vpc_id`, `next_hop_interface_type` | `VARCHAR` |
| Derived | `protocol_name` (`TCP`/`UDP`/`ICMP`/`ICMPv6`/number), `ip_version` (`4`/`6`) | `VARCHAR` / `INTEGER` |
| Endpoints | `local_addr`, `remote_addr`, `direction_source` | `VARCHAR` |
| Provenance | `flow_log_id` (from the file name), `source_file`, `line_no`, `has_parse_issue` | `VARCHAR` / `INTEGER` / `BOOLEAN` |
| Overflow | `extra` — unknown header fields, JSON stored as `VARCHAR` | `VARCHAR` |

**Endpoint derivation.** `direction_source` records how `local_addr` / `remote_addr` were set:

| Condition | `local_addr` | `remote_addr` | `direction_source` |
|-----------|--------------|---------------|--------------------|
| `flow_direction = ingress` | `pkt_dstaddr`, else `dstaddr` | `pkt_srcaddr`, else `srcaddr` | `record` |
| `flow_direction = egress` | `pkt_srcaddr`, else `srcaddr` | `pkt_dstaddr`, else `dstaddr` | `record` |
| no direction; IPv4; exactly one endpoint private/special | the private one | the other | `heuristic` |
| no direction; anything else (both private, both public, IPv6, …) | `NULL` | `NULL` | `unknown` |
| `NODATA` / `SKIPDATA` | `NULL` | `NULL` | `unknown` |

`inventory` (local side identified from ENI addresses in AWS Config data) is reserved for
Phase 5. Direction-dependent KPIs and charts filter `direction_source = 'record'` by default and
show heuristic rows only with an explicit label. Middlebox interfaces (`interface_type` set, or
`resource_id` set) are kept, but charts label them so a NAT gateway is not read as a victim host.

### 4.2 `vpc_flow_files` and `vpc_flow_sources` — coverage (review F-03)

`vpc_flow_files`, one row per ingested file, written in the same transaction as its rows:
`file_path`, `flow_log_id`, `account_id`, `region` (from the path), `header` (the field list as
written), `header_known` / `header_unknown` field lists, `rows_total`, `rows_valid`,
`rows_with_issues`, `rows_rejected`, `nodata_rows`, `skipdata_rows`, `min_start_time`,
`max_end_time`.

`vpc_flow_sources` is a view grouping `vpc_flow_files` by `flow_log_id`: account, region, field
set, first/last observation, file count, issue counts and `NODATA` / `SKIPDATA` counts. Interfaces
seen per source are counted from `vpc_flow_logs` directly — a distinct count does not sum across
files. Since a subscription's format cannot change, a `flow_log_id` with more than one
distinct header is itself flagged.

`vpc_flow_log_configs` is a view over `cloudtrail_events` (`CreateFlowLogs`, `DeleteFlowLogs`),
extracting resource IDs, traffic type (`ALL`/`ACCEPT`/`REJECT`), log format and the returned
`flowLogId` with `json_extract_string`. When the trail covers the subscription's creation, this
supplies the capture scope the records lack; otherwise the scope is shown as "unknown".

Both UIs distinguish **"no findings"** from **"insufficient coverage"**: a hunt whose required
fields are absent from every source, or whose time window has no observations for the selected
source, reports coverage rather than an empty result.

### 4.3 Duplicate observations

Original observations are never deleted. `vpc_flow_unique` is a view adding a fingerprint
(`pkt_srcaddr`/`srcaddr`, `pkt_dstaddr`/`dstaddr`, ports, protocol, `start_unix` bucketed to
the aggregation window) and an `observation_count`, for charts that report traffic volume rather
than per-interface observations. Which charts use it is decided after the performance gate (§9).

### 4.4 `ip_geo` — one row per distinct address (D5)

`ip`, `country_code`, `country_name`, `city`, `latitude`, `longitude`, `asn`, `org`. Private and
special-purpose addresses carry the existing markers (`PRIVATE`, `LOOPBACK`, `LINK-LOCAL`,
`SPECIAL`) in `country_code`, so they are looked up once and never again.

`vpc_flow_logs_geo` is a view joining `vpc_flow_logs.remote_addr` to `ip_geo` as
`remote_geo_*`; it is the dataset for the GeoIP tab. Any other address column can be joined the
same way in hunt SQL.

### 4.5 `vpc_flow_parse_issues`

`file_path`, `line_no`, `kind` (`field` / `row`), `field`, `raw_value`, `raw_line` — bounded as in §3.3.

---

## 5. GeoIP Enrichment

**Population.** After the flow chunks commit, a post-pass streams
`SELECT DISTINCT addr FROM (srcaddr ∪ dstaddr ∪ pkt_srcaddr ∪ pkt_dstaddr) ANTI JOIN ip_geo`
from DuckDB, looks each address up with `GeoipEnricher::lookup` from `ingester/src/geoip.rs`,
and appends the results to `ip_geo` in batches with `duckdb::Appender`. DuckDB performs the
distinct (spilling if needed) and Rust holds only one batch, so memory is bounded however many
distinct peers the logs contain (review F-09). The benchmark in §9 records distinct-address
cardinality and peak RSS.

**Back-fill.** `ingester enrich` runs the same post-pass for flow addresses — inherently
idempotent, and no `UPDATE` of the flow table is ever needed. The CloudTrail `geo_*` columns and
their `UPDATE`-per-IP back-fill are unchanged.

**AWS peers.** Rows whose `pkt_*_aws_service` is set talk to an AWS range. Charts show them as
their own category with their own baseline rather than excluding them as benign or letting
Amazon's ASN dominate external rankings.

**Agent results (review F-06).** `agent/geo.py` today detects IP columns with the name pattern
`(^ip$|_ip$|ip_address)` and looks geo up only in `cloudtrail_events`. Two changes:

- `DatasetProfile.ip_columns` lists the address columns explicitly; the flow profile lists
  `srcaddr`, `dstaddr`, `pkt_srcaddr`, `pkt_dstaddr`, `local_addr`, `remote_addr`. The name
  pattern remains as a fallback for LLM-chosen aliases.
- `DatasetProfile.geo_lookup` selects the lookup source; the flow profile uses `ip_geo`.
- The CloudTrail page keeps its current behaviour, guarded by a regression test.

---

## 6. Dashboard — `dashboard/assets/vpc_flow_default/`

New Superset bundle with datasets `vpc_flow_logs`, `vpc_flow_logs_geo` and `vpc_flow_sources` on
the existing `CloudTrail DuckDB` connection, a `rebuild_vpc_flow_zip.py` built on
`zip_builder.build_zip`, and registration in `dashboard/init/bootstrap.sh`. `superset-init` must
not fail when the tables do not exist (CloudTrail-only installs). Every YAML edit ends with
`/rebuild-dashboard`.

**Native filters on every tab:** flow log source, account, region, VPC, subnet, interface,
instance, address / CIDR, ASN, port, protocol, time window.

Wording rule for every chart: counts are "flow records", byte charts exclude BPA rows, and
descriptions call findings *triage signals* — high volume, unusual ports, geography, hosting
ASNs and regular timing do not by themselves establish exfiltration, C2, mining or attacker
ownership.

| Tab | Charts | Signal |
|-----|--------|--------|
| **Coverage** (first tab) | Sources table (`vpc_flow_sources`): field set, first/last seen, files, issue counts. Capture scope from `vpc_flow_log_configs` or "unknown". `NODATA` / `SKIPDATA` over time. Field availability matrix per source. Rows by `direction_source` | Whether the other tabs can be trusted for the selected scope |
| **Overview** | KPIs: flow records, bytes (non-BPA), REJECT ratio, distinct external peers, distinct ENIs. Records over time by `action`; bytes over time by `flow_direction` | Baseline and sudden change |
| **Inbound / Recon** | Top rejected external sources. Vertical scan: one source → many `dstport` in a window. Horizontal scan: one source → many destinations on one port. Internet → admin/DB ports accepted (22, 3389, 5985/5986, 3306, 5432, 1433, 6379, 9200, 27017, 2375, 10250). SYN-only records (`tcp_flags = 2`). REJECT → ACCEPT transitions for the same peer, target and port | Reconnaissance, exposed services, possible initial access |
| **Egress** | Top external destinations by bytes. Per-instance egress outliers against the instance's own baseline. Egress by path: **8 IGW**, **7 gateway endpoint**, **2 IGW-or-endpoint (ambiguous)** shown separately. Unusual destination ports (4444, 6667, 9001/9030, 3333/5555/7777/14444). Any port-53 flow (Amazon DNS is never logged, so these are custom resolvers — legitimate ones become the baseline). Outbound 25/SMTP. Long-running / low-and-slow: the same 5-tuple across many consecutive windows, bytes/s and packets/s | Possible exfiltration, C2, mining, spam relay |
| **Periodicity** | See §6.1 | Possible beaconing |
| **Lateral Movement** | Internal ↔ internal on 445, 3389, 22, 5985/5986 (`direction_source = 'record'` only, or `unknown` rows shown as unattributed pairs). First-seen internal (src, dst, port) pairs after a minimum history. ENI fan-out. Internal inbound volume followed by external outbound from the same host (staging) | Post-compromise movement |
| **Protocols & IPv6** | ICMP / ICMPv6 volume and peers (ports are 0 — no type/code). UDP fan-out. Unusual IP protocol numbers. IPv6 peers and volume, with no IPv4 private/public assumption | Tunnelling, covert channels, blind spots of IPv4-only views |
| **GeoIP** | KPIs: inbound countries, outbound countries, external ASNs. Three world maps: inbound accepted, inbound rejected, outbound bytes. Country × action. Country × destination port (inbound accepted). Top outbound ASN/org by bytes, hosting providers highlighted. Rare and first-seen outbound countries | Geographic anomalies, hosting infrastructure |
| **Posture** | `reject_reason` (BPA / EC). `encryption_status` distribution. Volume per `pkt_dst_aws_service`, S3 by path 7 vs 8 (value 2 excluded as ambiguous). Middlebox traffic by `interface_type` / `resource_id`. Off-hours egress heatmap | Encryption coverage, misconfiguration |
| **Cross-source** (Phase 5) | See §8 Phase 5 | API activity tied to network behaviour |

### 6.1 Periodicity (revised — review F-02)

A record is an aggregated observation whose timestamps are window bounds, so the signal is
**periodic flow-log observations**, never "periodic connections", and `COUNT(*)` is never
presented as a connection count. For each (`local_addr`, `remote_addr`, `dstport`, `protocol`)
with `direction_source = 'record'`:

- bucket observations by `start_time` and `end_time` at the source's aggregation granularity;
- compute observed buckets, active-bucket ratio, candidate period (median gap between active
  buckets), jitter (MAD of gaps / period) and stability of bytes and packets per bucket;
- require a minimum observation span (24 h) and a minimum number of active buckets (20);
- drop candidate periods at or below the aggregation window (1 min, or 10 min where non-Nitro
  traffic is present), since they reproduce the logging cadence rather than the traffic;
- lower the score when `SKIPDATA` or a coverage gap overlaps the interval.

Thresholds are starting values to be tuned against Phase 0 fixtures (§8) and the benchmark data.

---

## 7. Agent — 🌊 VPC Flow page

- A chat page (`chat_enabled=True`) with its own `DatasetProfile` in `agent/profiles.py`: table
  `vpc_flow_logs`, time column `start_time`, `ip_columns` and `geo_lookup` per §5.
- A dedicated system prompt stating the §2.3 limits — observations not connections, `ACCEPT` is
  not "connected", window-bound timestamps, `traffic_path = 2` is ambiguous, `direction_source`
  semantics, BPA rows lack bytes — so generated SQL and analysis do not overstate the evidence.
- The LLM sees a deliberate column subset (v2 core, `vpc_id`, `subnet_id`, `instance_id`,
  `tcp_flags`, `pkt_*addr`, `flow_direction`, `traffic_path`, `pkt_*_aws_service`,
  `local_addr`, `remote_addr`, `direction_source`, `protocol_name`, `ip_version`,
  `start_time`/`end_time`), plus `ip_geo` for joins. ECS, tag and next-hop columns stay
  available to hunt SQL only.
- `agent/vpc_flow_hunts.yaml` holds built-in hunts mirroring the dashboard tabs, each with an
  `sql` field so it runs without an API key, and a contract:

| Key | Meaning |
|-----|---------|
| `requires` | Columns that must be populated; the page shows "not available for this data" instead of an empty result when every selected source lacks one |
| `optional` | Columns that improve the result when present |
| `protocols`, `ip_versions` | Scope the hunt is valid for |
| `min_span` | Minimum observation period |
| `limitations` | Shown with the result and carried into the exported report |

- Exported reports carry the coverage and data-quality warnings that were shown on screen.
- The four-page wording across the agent and docs becomes five pages.

---

## 8. Implementation Plan

TDD throughout ([TDD_GUIDE.md](TDD_GUIDE.md)): test list first, one failing test, minimum code,
refactor. Each phase ends with its suite and `make check` green.

### Phase 0 — Fixtures

`ingester/tests/testdata_awslogs/`, a miniature `AWSLogs/` tree:

- **Routing:** CloudTrail `.json.gz`, CloudTrail-Digest, Config, ELB `.log.gz`, Parquet
  placeholder, Hive-prefixed Flow Logs, Organization-trail layout.
- **Formats:** v2 default; v5 custom with a reordered header; an unknown future header field;
  custom formats missing `bytes`, `tcp-flags` or `flow-direction`; headerless 14-token rows.
- **Traffic:** IPv6, ICMP, ICMPv6, UDP; both endpoints private, both public, direction missing;
  NAT gateway, Transit Gateway and secondary-IP cases where interface and packet addresses
  differ (from the AWS record examples); the same flow seen on two ENIs and under two
  `flow_log_id`s; BPA records without bytes; `NODATA` / `SKIPDATA`.
- **Periodicity:** a 5-minute beacon over 24 h (positive), the same with 1-min and 10-min
  aggregation cadence only (near-miss negatives), a beacon interrupted by `SKIPDATA`.
- **Corruption:** malformed numeric values, short rows, extra-token rows, corrupt gzip,
  header-only file, empty file.

### Phase 1 — Ingester

| Step | Module | Tests |
|------|--------|-------|
| 1 | `log_kind.rs` | One case per row of §3.1 |
| 2 | `flow_parser.rs` | Header acceptance incl. unknown fields → `extra`, duplicate-token rejection, headerless fallback, reordered header |
| 3 | `flow_parser.rs` | `-` vs malformed values, row rejection, bounded issue capture |
| 4 | `flow_parser.rs` | Endpoint derivation: every row of the §4.1 table, plus NAT / TGW / IPv6 fixtures |
| 5 | `flow_db.rs` | Tables and views created idempotently; Appender round-trip; `ADD COLUMN IF NOT EXISTS` |
| 6 | `flow_ingest.rs` | Chunk transaction: a failing dedup mark rolls back rows, file metadata and issues; the retry inserts exactly once |
| 7 | `flow_ingest.rs` | `vpc_flow_files` counts match the fixtures; `vpc_flow_sources` flags a `flow_log_id` with two headers |
| 8 | `ip_geo` post-pass | Distinct addresses from all four columns; idempotent; markers for private/special; batch-bounded |
| 9 | `ingest.rs` | Mixed tree → per-kind counts; CloudTrail results unchanged; Digest/Config no longer errors |
| 10 | `date_filter.rs` | Hive prefixes, Flow Logs file-name timestamps |
| 11 | `enrich.rs` | Flow back-fill via the post-pass; CloudTrail path unchanged |
| 12 | `main.rs` + `tests/cli_test.rs` | Summary lines and warnings, mixed tree end to end |
| 13 | `Makefile` + `tests/test_makefile_ingest.py` | Flow-only copy proceeds, detection line, new hint |

### Phase 1.5 — Performance gate

Before any Phase 2 chart SQL is finalised, measure a realistic data set (target: at least one
week of an internet-facing VPC) and record, with agreed thresholds:

- ingestion records per second and peak RSS;
- database bytes per million records;
- distinct-address cardinality and `ip_geo` post-pass time;
- p50 / p95 latency of the scan, lateral-movement and periodicity queries;
- no-change re-ingestion time.

The results decide whether `vpc_flow_unique` and the periodicity tab need pre-aggregated tables.

**Synthetic measurement (2026-10-26).** Not a substitute for the realistic run above: one week of
5-minute objects (2,016 files, 402 MB gzip), 10M records, ~500k distinct external peers, uniform
random traffic. Release build, Apple Silicon laptop, GeoLite2 test database.

| Metric | Result |
|--------|--------|
| Ingest throughput | ~165k records/s (60.6 s wall) |
| Peak RSS | 2.6 GB with 8 MiB chunks (4.2 GB with the first, file-count chunking; 1.8 GB at 1 MiB chunks but 3× slower) — of which ~1.5 GB is DuckDB itself |
| Database size | ~56 MB per million records |
| `ip_geo` post-pass | 504k distinct addresses in 1.3 s |
| No-change re-ingest | 3.6 s (files are parsed before the SHA comparison, as in the CloudTrail pipeline) |
| Query latency p50 / max of 5 | vertical scan 0.15 / 0.18 s · lateral movement 0.03 / 0.04 s · periodicity 0.95 / 0.98 s · `vpc_flow_unique` count 0.35 / 0.39 s · geo by country 0.15 / 0.15 s |

Follow-ups surfaced by the measurement: records are held as one `FieldValue` per known field
(~2.3 KB each); storing only the header's fields would roughly halve chunk memory. Comparing the
SHA before parsing would make no-change re-ingests read-only.

### Phase 2 — Dashboard

Datasets, registration (tolerant of missing tables), chart YAMLs per §6, rebuild script,
`dashboard/tests` coverage matching the existing bundles, then `/rebuild-dashboard`.

### Phase 3 — Agent

Profile with `ip_columns` / `geo_lookup`, prompt, column subset, `vpc_flow_hunts.yaml` with the
§7 contract. Every hunt has a positive control and a near-miss negative control executed against
a fixture DB. `geo.py` change with a CloudTrail regression test; navigation test updated.

### Phase 4 — Documentation

`AGENTS.md` (architecture, schema, CLI, repository tree), `ingester/AGENTS.md`,
`agent/AGENTS.md`, `website/docs/` in every locale (`/add-locale-doc`), `tests/test_doc_counts.py`
entries for the new hunts and bundle, then `make test-repo`.

### Phase 5 — Optional

- `direction_source = 'inventory'`: local side from ENI addresses in AWS Config data.
- Cross-source correlation:
  - IPs present in both `cloudtrail_events.source_ip_address` and `vpc_flow_logs.remote_addr`.
  - New accepted inbound flows after `AuthorizeSecurityGroupIngress` — this event names a
    security group, not an instance, so the join needs the security-group → ENI relationship,
    preferably time-aware from AWS Config.
  - Outbound flows shortly after `RunInstances` — instance and ENI IDs must first be extracted
    from the event's `response_elements` (`instancesSet` / `networkInterfaceSet`).
- CloudWatch Logs / Firehose exports; Config snapshots picked up from the same `AWSLogs/` tree;
  flow volume overlaid on the `config_viz` ENI graph.

---

## 9. Risks

| # | Item | Notes |
|---|------|-------|
| R1 | Volume | Flow Logs typically exceed CloudTrail by orders of magnitude and D3 keeps the default unbounded. Mitigated by the Phase 1.5 gate |
| R2 | Superset query latency | Scan, periodicity and de-duplicated charts over large tables may need pre-aggregated tables; decided at the gate |
| R3 | Misclassification | A `.log.gz` that is not a flow log must fail header acceptance; covered by the ELB fixture |
| R4 | Over-interpretation | Mitigated by the wording rule (§6), `direction_source` filtering, hunt `limitations` and the agent prompt |

---

## 10. Review Disposition

Response to [PRD_VPC_FLOW_LOGS_REVIEW.md](PRD_VPC_FLOW_LOGS_REVIEW.md).

| Finding | Disposition | Where |
|---------|-------------|-------|
| F-01 `remote_addr` without direction | Accepted. `local_addr` / `remote_addr` / `direction_source`; geo decoupled from the guess | D5, D6, §4.1, §5 |
| F-02 Beaconing semantics | Accepted. Renamed and redefined over observations | D7, §6.1 |
| F-03 Coverage and duplicates | Accepted. File/source metadata, CloudTrail-derived capture config, de-duplication view, coverage-vs-no-findings | §4.2, §4.3 |
| F-04 Header sniff vs `extra` | Accepted | §3.3 |
| F-05 Malformed vs `-` | Accepted, with a bounded raw-value store | §3.3, §4.5 |
| F-06 Agent IP column detection | Accepted. Verified: the current pattern matches none of the flow address names | §5 |
| F-07 `traffic_path = 2` | Accepted. Verified against the AWS field reference | §2.2, §6 |
| F-08 Transaction boundary | Accepted for the flow pipeline; CloudTrail's equivalent is out of scope | §3.2 |
| F-09 Unbounded geo cache | Accepted. Replaced by the `ip_geo` post-pass rather than an LRU | D5, §5 |
| §4.1 ICMP "type/code carried in the port fields" | Not adopted. AWS record examples show ICMP with `srcport`/`dstport` = `0`; ICMP views use protocol, peers and volume only | §2.2, §6 |
| §4 other DFIR additions | Accepted: UDP / unusual protocols, long-running flows, REJECT→ACCEPT, staging, first-seen pairs, IPv6, middlebox attribution, pivots, AWS-service baselines, interpretation safeguards | §6, §7 |
| §5 Fixtures, performance gate, hunt contract | Accepted | §8, §7 |
| §5 Phase 5 correlation corrections | Accepted | §8 Phase 5 |
