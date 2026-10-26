# Review — Amazon VPC Flow Logs Implementation Plan

| Field | Details |
|-------|---------|
| Reviewed document | [PRD_VPC_FLOW_LOGS.md](PRD_VPC_FLOW_LOGS.md) version 0.1 |
| Review date | 2026-10-26 |
| Review scope | DFIR coverage, AWS semantics, ingestion integrity, and Senrigan integration |
| Recommendation | Conditional approval — revise the blocking findings before Phase 0 |

## 1. Summary

The proposal has a sound overall direction: it preserves the single-writer invariant, routes a
mixed `AWSLogs/` tree through one command, retains `NODATA` and `SKIPDATA`, supports custom field
order, and gives network evidence dedicated dashboard and agent surfaces.

Implementation should not start from the draft unchanged. Three issues can materially
misrepresent evidence:

1. A single `remote_addr` cannot be determined reliably for version 2–4 records without flow
   direction or independent ENI address inventory.
2. VPC Flow Log records are aggregated observations, not connection events, so the proposed
   beaconing calculation cannot call row counts "connections" or treat record timestamps as
   precise connection arrival times.
3. The model lacks capture-scope, field-coverage, and duplicate-observation metadata, making it
   impossible to distinguish "no finding" from "not observed" reliably.

The header-sniff rules also contradict forward-compatible parsing, malformed numeric values lose
forensic provenance, and the current agent GeoIP column detector will not recognize any of the
proposed Flow Log address names.

## 2. Blocking Findings

### F-01 — `remote_addr` is not reliable when `flow_direction` is absent

**Severity:** Critical  
**PRD references:** §1.1 D5, §5.1, Phase 1 Step 3

The proposed fallback selects the non-private endpoint, or `srcaddr` when both endpoints have the
same address class. That does not identify the ENI-local endpoint for:

- private-to-private lateral traffic;
- two public endpoints or public-addressed EC2 traffic;
- IPv6 traffic;
- shared VPCs and overlapping address spaces;
- NAT gateways, load balancers, Transit Gateway, and other middleboxes; or
- records where interface-level and packet-level addresses differ.

This can label the victim as the remote peer, reverse ingress and egress interpretation, and
attach GeoIP data to the wrong endpoint. AWS documents cases where `srcaddr` or `dstaddr` contains
an interface primary address and the original address is available only in `pkt-srcaddr` or
`pkt-dstaddr`.

**Required change:**

- Derive a definitive remote endpoint only when `flow_direction` is present or independent ENI
  inventory identifies the local endpoint.
- Otherwise leave `remote_addr` null, or mark it explicitly as a heuristic.
- Add `local_addr`, `remote_addr`, and `direction_source` with values such as `record`,
  `inventory`, `heuristic`, and `unknown`.
- Preserve `srcaddr`, `dstaddr`, `pkt_srcaddr`, and `pkt_dstaddr` as first-class investigation
  fields in every case.
- Do not use heuristic rows in direction-dependent KPIs unless the UI displays their confidence.

### F-02 — Beaconing is defined in terms the source data cannot support

**Severity:** Critical  
**PRD reference:** §6, Beaconing tab

A Flow Log row is an aggregation over an interval for a flow key; it is not one connection. Its
timestamp is not a precise connection-arrival timestamp, and TCP flags can be OR-ed across the
aggregation window. Consequently, `COUNT(*)` cannot be presented as a connection count, and a low
coefficient of variation can merely reproduce the one-minute or ten-minute aggregation cadence.

**Required change:**

- Rename the signal to periodic flow-log observations rather than periodic connections.
- Calculate observed buckets, active-bucket ratio, candidate period, jitter, and stability of
  bytes or packets.
- Require a minimum observation duration and minimum number of populated buckets.
- Exclude periods at or below the source aggregation granularity, or lower their confidence.
- Lower confidence when `SKIPDATA` or collection gaps overlap the evaluated interval.
- Use both `start_time` and `end_time`, and document timestamp uncertainty in the agent prompt and
  hunt description.

### F-03 — Collection coverage and duplicate observations are not modeled

**Severity:** Critical  
**PRD references:** §4 provenance, §6 Overview and Posture / Ops

`flow_log_id` identifies the subscription but does not describe whether it captures a VPC,
subnet, or ENI; whether it selects `ALL`, `ACCEPT`, or `REJECT`; which fields are present; or when
the subscription was active. The same traffic can also be observed by multiple subscriptions or
interfaces.

Without that context, global REJECT ratios, distinct-flow counts, gap statements, and negative
findings can combine incompatible populations or double-count observations.

**Required change:**

- Add a `vpc_flow_log_sources` table keyed by source or subscription identity.
- Record at least `flow_log_id`, account, region, first/last observation, observed field set,
  file count, bad-row count, `NODATA` count, and `SKIPDATA` count.
- Make KPIs filterable by source, account, region, and interface.
- Retain original observations. If deduplicated analytics are needed, add a derived fingerprint
  and `observation_count` rather than deleting evidence.
- Distinguish "no findings" from "insufficient coverage" in both UIs.
- Treat CloudTrail `CreateFlowLogs` / `DeleteFlowLogs` or AWS Config integration as the eventual
  source of authoritative capture configuration.

## 3. High-Priority Findings

### F-04 — Header sniffing contradicts unknown-field preservation

**Severity:** High  
**PRD references:** §3.1 rule 2, §3.3

The classifier requires every header token to be known, while the parser promises to preserve
unknown future AWS fields in `extra`. The classifier would reject the file before the parser could
apply that behavior.

**Required change:** Accept unknown tokens when the line is structurally a header, contains a
reasonable known-field signature, and has no duplicate field names. Reject a named Flow Log file
only when it cannot be recognized as a valid header or supported headerless default record.

### F-05 — Invalid numeric values are silently indistinguishable from AWS `-`

**Severity:** High  
**PRD reference:** §3.3

Mapping both AWS's explicit unavailable marker and malformed numeric text to null hides corruption,
parser defects, and source anomalies. It also prevents later reprocessing of the original value.

**Required change:**

- Map only `-` to an ordinary null.
- Count malformed fields and rows separately.
- Preserve malformed source rows in `raw_record`, `parse_warnings`, or a quarantine table.
- Include bad-file, bad-row, and bad-field counts in the CLI summary.
- Define a warning or failure threshold for materially corrupted input.

### F-06 — The agent will not detect the proposed address columns for GeoIP enrichment

**Severity:** High  
**PRD reference:** §5.4

The current `agent/geo.py` name matcher recognizes names such as `ip`, `*_ip`, and `ip_address`.
It does not recognize `remote_addr`, `srcaddr`, `dstaddr`, `pkt_srcaddr`, or `pkt_dstaddr`.
Changing only the lookup table therefore leaves Flow Log results unenriched.

**Required change:** Add explicit per-profile IP-column metadata, preferably
`DatasetProfile.ip_columns`, instead of continuing to broaden a global name regular expression.
Test every Flow Log address field and retain the CloudTrail regression test.

### F-07 — `traffic_path = 2` is not definitive Internet Gateway traffic

**Severity:** High  
**PRD references:** §2.2, §6 Egress / Exfiltration

Value 2 represents an Internet Gateway or a gateway endpoint and is therefore ambiguous. Values 7
and 8 distinguish gateway endpoint and Internet Gateway respectively.

**Required change:** Report the categories as:

- `8`: Internet Gateway;
- `7`: gateway endpoint;
- `2`: legacy or ambiguous Internet Gateway / gateway endpoint; and
- other or null: according to the documented value domain.

Do not count value 2 as definitive IGW traffic or use it to classify S3 path choice.

### F-08 — Flow rows and dedup marks need one transaction boundary

**Severity:** High  
**PRD references:** §3.2, Phase 1 Step 5

If rows are appended successfully but the corresponding `ingested_files` mark fails, a retry can
append the same evidence again. The much larger Flow Log volume amplifies this existing failure
mode.

**Required change:** Insert a file or chunk's flow rows and its dedup marks in the same transaction.
Add tests proving rollback when marking fails and proving that the subsequent retry does not
duplicate rows.

### F-09 — An unbounded per-run GeoIP cache is a memory risk

**Severity:** High  
**PRD references:** §5.2, §9 R1

Internet-facing Flow Logs can contain millions of distinct remote addresses. A per-run
`HashMap<IpAddr, GeoInfo>` therefore has no useful upper memory bound.

**Required change:** Use a bounded LRU cache, a chunk-scoped cache, or a temporary DuckDB lookup
table. Include distinct-peer cardinality and peak RSS in the volume benchmark.

## 4. DFIR Coverage Assessment

The proposed recon, egress, lateral movement, GeoIP, and logging-health views cover important
first-line triage. The following additions are recommended for representative DFIR coverage.

### 4.1 Network behavior

- ICMP and ICMPv6 analysis, including type/code semantics carried in the port fields.
- UDP fan-out, unusual IP protocol numbers, and traffic with zero or inapplicable ports.
- Long-running and low-and-slow flows using duration, bytes per second, and packets per second.
- Bidirectional request/response correlation with an explicit confidence score.
- REJECT-to-ACCEPT transitions for the same peer, target, and port without claiming that ACCEPT
  proves an established session.
- Internal staging followed by external transfer.
- Rare and first-seen peer pairs with minimum history and population requirements.

### 4.2 Attribution and pivots

- IPv6-specific views that do not depend on IPv4 private/public assumptions.
- NAT and middlebox attribution using `resource_id`, `interface_type`, and `next_hop_*`.
- Investigator pivots by IP, CIDR, ASN, port, ENI, instance, account, region, and time window.
- Separate baselines for AWS service destinations rather than excluding them as benign.
- Source-account and source-region context in all triage results.

### 4.3 Interpretation safeguards

- Treat high byte volume, unusual ports, geography, hosting ASNs, and regular timing as triage
  signals rather than determinations of exfiltration, C2, mining, or attacker ownership.
- Never equate `ACCEPT` with an established connection.
- Label `bytes` and packet counts unavailable for BPA records where applicable.
- Display field availability before running a hunt that depends on optional custom-format fields.
- Carry data-quality and coverage warnings into exported reports.

## 5. Required Plan Changes

### Phase 0 — Fixtures

Add fixtures for:

- IPv6, ICMP, ICMPv6, and UDP;
- both endpoints private, both endpoints public, and missing `flow-direction`;
- NAT, load balancer, or Transit Gateway cases where interface and packet addresses differ;
- an unknown future header field;
- malformed numeric values, short rows, extra-token rows, corrupt gzip, header-only, and empty
  files;
- the same flow observed under multiple `flow_log_id` values;
- one-minute and ten-minute periodic observations;
- custom formats missing `bytes`, `tcp-flags`, or `flow-direction`; and
- BPA records without byte counts.

### Phase 1 — Ingester

Add the following deliverables:

- source and field-coverage metadata;
- parse diagnostics and malformed-row preservation;
- confidence-aware endpoint derivation;
- transactional row insertion and dedup marking;
- a bounded GeoIP cache; and
- separate counts for input files, valid rows, malformed rows, diagnostic records, skipped files,
  and failed files.

### Performance gate before Phase 2

Measure a realistic data set and define acceptable thresholds for:

- ingestion records per second;
- peak resident memory;
- database bytes per million records;
- p50 and p95 latency for scan, lateral-movement, and periodicity queries;
- no-change re-ingestion time; and
- enrichment time by distinct-address cardinality.

### Phases 2 and 3 — Dashboard and Agent

Each reviewed hunt should declare:

- required and optional columns;
- behavior when a required field is absent;
- supported protocols and IP versions;
- minimum observation period;
- known limitations and confidence interpretation;
- a synthetic positive control; and
- a near-miss negative control.

Add profile-level IP-column metadata and display source coverage before presenting global KPIs.

### Phase 5 — Cross-source correlation

Keep this phase optional, but revise two proposed correlations:

- `AuthorizeSecurityGroupIngress` does not directly identify an instance. Correlation needs the
  security-group-to-ENI relationship, preferably time-aware AWS Config data.
- `RunInstances` correlation must extract instance and ENI identities from CloudTrail response
  data before joining to Flow Logs.

## 6. Acceptance Conditions

The plan is ready for implementation when all of the following are reflected in the PRD:

1. Directionless records cannot silently create a definitive `remote_addr`.
2. Beaconing is defined over aggregated observations, not connection counts.
3. Source coverage, field coverage, and duplicate observations are represented explicitly.
4. Unknown header fields are accepted consistently with the `extra` design.
5. Malformed values remain distinguishable from AWS `-` values.
6. Flow row insertion and dedup marking are atomic.
7. Agent GeoIP detection explicitly supports Flow Log address columns.
8. `traffic_path = 2` is treated as ambiguous.
9. Phase 0 includes protocol, IPv6, direction, corruption, optional-field, and duplicate-source
   fixtures.
10. A measurable performance gate precedes dashboard query finalization.

## 7. References

- [AWS — Flow log records](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html)
- [AWS — Flow log files](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3-path.html)
- [AWS — Flow log limitations](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-limitations.html)
- [AWS — Flow log record examples](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-records-examples.html)

