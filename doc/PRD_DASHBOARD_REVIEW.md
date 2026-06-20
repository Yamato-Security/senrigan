# Requirements Document — CloudTrail Threat Hunting Dashboard (DFIR Review & Redesign)

## Senrigan — Apache Superset Dashboard

| Field | Details |
|-------|---------|
| Document Version | 0.1 (Draft) |
| Date | 2026-06-20 |
| Status | Under Review |
| Scope | `dashboard/assets/cloudtrail_default/` (Superset import bundle) |
| Reviewer perspective | DFIR / Threat Hunting analyst |

---

## 1. Purpose

This document reviews the pre-built **CloudTrail Threat Hunting** Superset dashboard from a
DFIR and threat-hunting standpoint and defines requirements for its next iteration. It covers:

- **Improvements** to existing charts and dashboard behavior
- **Charts to add** (new high-value DFIR hunts)
- **Charts to remove or merge** (low-signal / redundant)
- **Layout changes** (grid, sizing, visualization types)
- **Ordering changes** (tab order and intra-tab chart order)

The goal is to optimize the dashboard for the **triage → scoping → deep-dive** investigation
workflow, so that an analyst opening the dashboard during an incident reaches a verdict faster.

---

## 2. Current State

### 2.1 Inventory

| Property | Value |
|----------|-------|
| Tabs | 9 |
| Charts placed | 74 (75 chart definitions on disk) |
| Native filters | 28 (`+Include` / `NOT` pairs across 14 columns + time range) |
| Dataset | single `cloudtrail_events` (DuckDB, READ_ONLY) |

### 2.2 Tab structure (current order)

| # | Tab | Charts | Theme |
|---|-----|:------:|-------|
| 1 | 🔑 Identity & Access | 11 | Login, IAM privilege change, secrets, AssumeRole |
| 2 | 🎯 Threat Detection | 9 | Audit/defense tampering, errors, throttling, baseline |
| 3 | 📊 API Activity | 5 | Top API, access-denied, region, source IP, user agent |
| 4 | 🌐 Network | 5 | SG, NACL/route, VPC infra, peering/TGW, Route53 |
| 5 | 🖥️ Computing | 13 | EC2 / ECS / SSM / EBS / Lambda / CloudFormation |
| 6 | 🪣 S3 & RDS | 11 | Exfil, bulk delete, anti-forensics, KMS, backup |
| 7 | 🌍 GeoIP Intelligence | 6 | Country / ASN / city / world map |
| 8 | 🕒 Temporal Analysis | 7 | First/last seen, dormant, velocity spikes |
| 9 | 🚨 High-Risk API Monitor | 7 | 42-API watchlist volume & actors |

### 2.3 Visualization mix

| viz_type | Count | Note |
|----------|:-----:|------|
| `table` | 59 | **79% of all charts** — dominant |
| `echarts_timeseries_bar` | 7 | Trend charts |
| `dist_bar` | 4 | |
| `bar` | 4 | |
| `world_map` | 1 | GeoIP |

---

## 3. Review Findings

### 3.1 Strengths (preserve)

- **Strong filter spine.** 28 native filters with `+Include` / `NOT` pairs across every key
  column (ARN, source IP, event name/source, region, account, error code, country, ASN, etc.)
  plus a time-range filter. This is the single most valuable DFIR feature and must be kept.
- **DFIR-aligned coverage.** Defense-evasion / audit tampering, anti-forensics (versioning &
  logging disabled, backup vault & KMS deletion, RDS deleted without snapshot), persistence
  (key pair, instance profile, login profile), and exfil (S3 bulk download, snapshot sharing)
  are all represented — a genuinely broad hunt surface.
- **High-Risk API watchlist.** The 42-API watchlist powering the HRM tab encodes real attacker
  TTPs and is a good "what changed in volume" signal.
- **Temporal first/last-seen hunts.** New-IP / new-principal / new-API detection is exactly the
  novelty-based hunting DFIR needs.

### 3.2 Gaps & issues (prioritized)

| ID | Severity | Finding |
|----|:--------:|---------|
| F-1 | **High** | **No triage landing tab / no KPI summary cards.** There is no `big_number` chart anywhere. An analyst has no at-a-glance "where do I start" view (total events, distinct principals, root usage count, MFA-less logins, error rate, defense-evasion hits, distinct source countries, time span of data). |
| F-2 | **High** | **Over-reliance on tables (59/74).** Tables are good for evidence pivot but poor for anomaly *spotting*. Many "trend"/"timeline"/"heatmap" intents are rendered as tables. Trend-shaped data should be timeseries/heatmap so spikes are visible pre-attention. |
| F-3 | **High** | **`login_heatmap` is a `table`, not a heatmap.** The chart named for hour-of-day login pattern detection cannot show that pattern in its current form. |
| F-4 | **Medium** | **Tab order does not match stated DFIR triage priority.** The README states categories are "ordered by DFIR triage priority — detection-tool tampering first." The dashboard leads with Identity & Access; Threat Detection (defense evasion) is Tab 2. Triage should lead with defense-evasion. |
| F-5 | **Medium** | **Stale / inconsistent metadata.** `dashboard.yaml` header and `description` say "5-tab layout" while 9 tabs exist; tab tooltips embed `Tab 6/7/8/9` numbers that no longer match positions. |
| F-6 | **Medium** | **Filter UX overload.** 28 filters (every column duplicated as `+Include` and `NOT`) is powerful but overwhelming and slow to scan. Consider collapsing to single multi-select filters (exclusion via filter logic) and grouping into "Who / Where / What / When" sections. |
| F-7 | **Medium** | **HRM tab overlaps other tabs.** `Top Source IPs` and `By Region` duplicate the API Activity tab; `Security Service Modifications` and `Credential Retrieval` duplicate Threat/Identity. The tab is partly a re-cut of existing data. |
| F-8 | **Medium** | **No severity encoding.** Charts carry `[CRITICAL]`/`[HIGH]` only in YAML comments — invisible in the UI. No conditional formatting highlights critical rows; all tables look equally urgent. |
| F-9 | **Medium** | **MITRE ATT&CK mapping not surfaced.** Technique IDs live in comments only. Analysts cannot pivot or report by technique from the UI. |
| F-10 | **Low** | **`row_limit: 20` on 31 charts.** During an active incident the top-20 cut can hide the long tail (e.g., 21st noisiest principal). Triage charts especially should allow a higher/explicit limit. |
| F-11 | **Low** | **GeoIP empty-state.** GeoIP charts render blank when enrichment is absent, with no guidance that `make ingest-geoip` is required. |
| F-12 | **Low** | **Missing cross-chart drill / cross-filter.** Clicking a principal/IP in one chart does not filter the rest of the dashboard, forcing manual filter entry. |

---

## 4. Requirements

### R1 — Improvements (existing charts & dashboard behavior)

| Req | Description | Addresses |
|-----|-------------|:---------:|
| R1-1 | Add an **Overview / Triage** tab of `big_number` KPI cards (see R2-1). Make it the first tab. | F-1, F-4 |
| R1-2 | Convert intent-mismatched tables to appropriate viz types: `login_heatmap` → `heatmap` (hour-of-day × day-of-week); error/throttling/velocity tables → timeseries where a trend is the signal. | F-2, F-3 |
| R1-3 | Apply **conditional formatting** to critical tables (red text/background on rows matching CRITICAL conditions, e.g. `StopLogging`, root usage, `DeleteTrail`). Adopt a consistent severity color scheme dashboard-wide. | F-8 |
| R1-4 | Surface **MITRE ATT&CK technique IDs** in each chart's visible subtitle/description (not only comments). | F-9 |
| R1-5 | Rationalize native filters: collapse `+Include`/`NOT` pairs into single multi-select filters and group into **Who / Where / What / When** divider sections in the filter panel. | F-6 |
| R1-6 | Enable Superset **cross-filtering** (`DASHBOARD_CROSS_FILTERS`) so clicking a principal/IP/region scopes the whole dashboard. | F-12 |
| R1-7 | Raise `row_limit` on triage/top-N charts (e.g. 50–100) or add a server-pagination table; keep 20 only on intentionally short evidence tables. | F-10 |
| R1-8 | Add a Markdown empty-state note to the GeoIP tab pointing to `make ingest-geoip`. | F-11 |
| R1-9 | Fix stale metadata: update `dashboard.yaml` header/description to "9-tab" (or the new count), and remove hard-coded `Tab N` strings from tooltips. | F-5 |

### R2 — Charts to Add

> Each new chart should reuse the single `cloudtrail_events` dataset and the existing column set
> (no schema change required unless noted).

| Req | Chart | Tab | viz_type | Key columns / logic | MITRE | Priority |
|-----|-------|-----|----------|---------------------|-------|:--------:|
| R2-1 | **Triage KPI cards** (8–10 `big_number`): total events, distinct principals, distinct source IPs, root-account events, MFA-less console logins, access-denied count, defense-evasion hits, distinct countries, data time span | Overview | `big_number_total` | counts/distinct over filtered range | — | High |
| R2-2 | **Impossible Travel** — same principal, geographically distant source IPs within a short window | GeoIP | `table` | `user_identity_arn` × `geo_country_code`/`geo_city` time-windowed | TA0001 | High |
| R2-3 | **Access Key Used from New IP** — first-seen `source_ip_address` per access-key/principal | Identity | `table` | first-seen join on principal × IP | T1078 | High |
| R2-4 | **Failed→Success Auth Sequence** — `ConsoleLogin` failures followed by success per principal/IP (password spray / brute force) | Identity | `table` | `event_name=ConsoleLogin`, `error_message` patterns | T1110 | High |
| R2-5 | **CloudTrail Logging Gap** — time buckets with zero events (possible logging stopped / blind spot) | Threat Detection | `echarts_timeseries_bar` | event count per fine-grained bucket, highlight zeros | T1562.008 | High |
| R2-6 | **Cross-Account AssumeRole / External Account** — `recipient_account_id` ≠ `user_identity_account_id` | Identity | `table` | account-id mismatch | T1199 | Medium |
| R2-7 | **New IAM Principal Creation Timeline** — `CreateUser`/`CreateRole`/`CreateAccessKey`/`CreateLoginProfile` over time | Identity | `echarts_timeseries_bar` | event_name IN(...) over time | T1136 | Medium |
| R2-8 | **RunInstances Spike by Region / Type** (cryptomining) — instance launches grouped by region | Computing | `echarts_timeseries_bar` | `event_name=RunInstances` by `aws_region` | T1496 | Medium |
| R2-9 | **Error-Code Composition** — distribution of `error_code` (AccessDenied / UnauthorizedOperation / Throttling) over time | API Activity | `echarts_timeseries_bar` | `error_code` grouped | TA0007 | Low |

### R3 — Charts to Remove or Merge

| Req | Chart(s) | Action | Rationale |
|-----|----------|--------|-----------|
| R3-1 | HRM `Top Source IPs`, HRM `By Region` | **Remove** from HRM | Duplicate the API Activity tab; reachable via cross-filter. |
| R3-2 | `geo_identity_by_country`, `geo_event_name_by_country` | **Merge** into one parameterized GeoIP breakdown | Two near-identical breakdowns add noise. |
| R3-3 | `fs_user_agent` (first/last seen user agent) | **Merge** into a combined first/last-seen table or remove | Lowest DFIR signal of the first-seen family; UA is easily spoofed. |
| R3-4 | `write_read_ratio` | **Move to Overview as a KPI** or remove standalone | Low value as a standalone full-width chart. |
| R3-5 | `container_platform_events` | **Verify overlap** with `ecs_task_definition` / EKS coverage; merge if redundant | Possible duplication of compute events. |

> Removal targets are candidates pending data-volume validation on a real corpus; confirm low
> hit-rate / redundancy before deleting.

### R4 — Layout Changes

| Req | Description | Addresses |
|-----|-------------|:---------:|
| R4-1 | New **Overview** tab: a single row of `big_number` cards (height ~30, width 2–3 each), followed by the global event timeseries and the defense-evasion summary. | F-1 |
| R4-2 | Pair related single-chart rows into 2-up rows to reduce vertical scrolling on dense tabs (Computing has 13 stacked full-width rows today). | F-2 |
| R4-3 | Standardize chart heights: timeseries 50, tables 50–60, KPI cards 30; full-width (12) for tables, half-width (6) for paired bar/timeseries. | — |
| R4-4 | Add a Markdown header row at the top of each tab stating the tab's hunting question + relevant MITRE tactics. | F-9 |
| R4-5 | Group the filter panel with section dividers (Who / Where / What / When). | F-6 |

### R5 — Ordering Changes

**R5-1 Tab order (triage-first).** Reorder to follow incident-response priority:

| New # | Tab | Change |
|:-----:|-----|--------|
| 1 | 🚦 **Overview / Triage** | **NEW** |
| 2 | 🎯 Threat Detection (defense evasion / audit tampering) | ↑ from 2 |
| 3 | 🔑 Identity & Access | ↓ from 1 |
| 4 | 🚨 High-Risk API Monitor | ↑ from 9 (promote next to Identity) |
| 5 | 📊 API Activity | = |
| 6 | 🪣 S3 & RDS (data impact / exfil / anti-forensics) | ↑ from 6 |
| 7 | 🖥️ Computing | ↓ |
| 8 | 🌐 Network | ↓ |
| 9 | 🕒 Temporal Analysis | ↓ |
| 10 | 🌍 GeoIP Intelligence | = (last; enrichment-dependent) |

> Rationale: lead with the question "was logging/detection tampered with?", then "who did it?",
> then "what high-risk actions?", then "what data was touched?". GeoIP last because it is
> optional/enrichment-gated.

**R5-2 Intra-tab order.** Within each tab, order charts **CRITICAL → HIGH → MEDIUM → CONTEXT**
(top to bottom), so the highest-severity hunt is always the first thing seen. Most tabs already
do this in comments; make it consistent and remove context/baseline charts (timeseries) to the
bottom of their tab.

---

## 5. Proposed Target Structure (summary)

```
1. 🚦 Overview / Triage      ← NEW: KPI cards + global timeseries + defense-evasion summary
2. 🎯 Threat Detection       ← tampering, logging gap (NEW), errors, throttling
3. 🔑 Identity & Access      ← +impossible-travel, new-IP-key, auth-sequence, new-principal
4. 🚨 High-Risk API Monitor  ← trimmed (drop region/source-IP dupes)
5. 📊 API Activity
6. 🪣 S3 & RDS
7. 🖥️ Computing             ← +RunInstances spike
8. 🌐 Network
9. 🕒 Temporal Analysis      ← first/last-seen consolidated
10. 🌍 GeoIP Intelligence    ← empty-state note; merged breakdowns
```

---

## 6. Non-Functional Requirements & Constraints

- **Single dataset.** All charts continue to use `cloudtrail_events` on DuckDB in READ_ONLY mode;
  no ingester schema change unless a requirement explicitly calls for a new column.
- **Idempotent import.** Changes ship via the `cloudtrail_default` import bundle and must remain
  re-importable by `import_dashboard.py` without manual steps.
- **Stable UUIDs.** Preserve existing chart/dataset UUIDs when editing; assign fresh UUIDs only to
  net-new charts to avoid clobbering user-saved state on re-import.
- **Performance.** New KPI/`COUNT(DISTINCT)` cards must respect the 8 h `DATA_CACHE_CONFIG` TTL;
  avoid per-card full scans where a shared query can serve several cards.
- **Language policy.** All YAML comments, descriptions, and docs in English (per `ARCHITECTURE.md`).

---

## 7. Acceptance Criteria

- [ ] An Overview tab exists as Tab 1 with ≥8 KPI cards reflecting the active filter range.
- [ ] `login_heatmap` renders as a true heatmap; no chart's viz_type contradicts its name/intent.
- [ ] Tab order matches R5-1; intra-tab order matches R5-2 (CRITICAL first).
- [ ] At least R2-2 (Impossible Travel) and R2-5 (Logging Gap) added and populated on sample data.
- [ ] Removed/merged charts per R3 (post-validation); no broken references in `dashboard.yaml`.
- [ ] Critical tables show severity conditional formatting; MITRE IDs visible in chart subtitles.
- [ ] `dashboard.yaml` header/description/tooltips no longer reference a stale tab count.
- [ ] Bundle re-imports cleanly via `import_dashboard.py`; existing UUIDs unchanged.

---

## 8. Phasing (suggested)

| Phase | Content | Effort |
|-------|---------|:------:|
| P1 | R1-9 (metadata fix), R5-1/R5-2 (reorder), R2-1 + R4-1 (Overview tab) | S |
| P2 | R1-2/R1-3 (viz + severity), R2-2/R2-4/R2-5 (top hunts), R3 removals | M |
| P3 | R1-5/R1-6 (filter grouping + cross-filter), R2 remainder, R4-2/R4-4 | M |

---

## 9. Out of Scope

- New ingester-side enrichment columns (e.g., bytes-transferred for exfil volume) — tracked
  separately; this document assumes the current 24-column schema.
- Alerting / scheduled reports (Alerts & Reports feature is intentionally disabled in v1.0).
- Changes to the Suzaku summary viewer and the AWS Config resource graph.
