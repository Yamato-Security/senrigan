# Requirements Document — Suzaku `aws-ct-summary` Visualization

## Senrigan - Suzaku CloudTrail Summary Viewer

| Field | Details |
|-------|---------|
| Document Version | 0.1 (Draft) |
| Date | 2026-06-20 |
| Status | Under Review |
| Related | [PRD.md](PRD.md), [ARCHITECTURE.md](ARCHITECTURE.md) |

---

## 1. Executive Summary

[Suzaku](https://github.com/Yamato-Security/suzaku) is a Yamato-Security tool that performs Sigma-based threat hunting on cloud logs. Its `aws-ct-summary` command aggregates CloudTrail activity into a **per-identity (per `user_arn`) threat profile** and emits the result as a JSON file.

This document defines the requirements for a feature that visualizes the `aws-ct-summary` JSON inside Senrigan, enabling analysts to triage which AWS identities behaved suspiciously and drill down into the abused APIs, source IPs, and credentials behind that activity.

**Hard constraint:** No new Docker components, volumes, or `docker-compose` changes. The feature must be hosted inside an existing service.

---

## 2. Background and Problem Statement

### 2.1 Problems to Solve

| Problem | Description |
|---------|-------------|
| Raw summary is hard to read | The `aws-ct-summary` output is a 4 MB+ JSON with deeply nested arrays — impractical to read by hand during triage |
| No identity-centric overview | Senrigan's existing hunts are query-centric; there is no single view that ranks identities by suspicious activity |
| Context switching | Analysts currently inspect APIs, IPs, and credentials separately; the summary already correlates them per identity but lacks a UI |

### 2.2 Target Users

- Cloud security analysts performing initial triage of a potentially compromised account
- Incident responders needing to quickly identify which identity and which APIs drove an incident

---

## 3. Goals and Non-Goals

### 3.1 Goals

- Let an analyst load a Suzaku `aws-ct-summary` JSON and immediately see which identities are most suspicious
- Provide drill-down from the identity list into abused APIs, source IPs, regions, user agents, and access keys
- Ship with **zero changes to the Docker topology**

### 3.2 Non-Goals (v1.0)

- Re-running or invoking Suzaku itself from Senrigan (the JSON is produced externally)
- Persisting uploaded summaries into DuckDB or any datastore
- Cross-summary diffing or historical trend tracking
- Full geo-map rendering with latitude/longitude (see §7)

---

## 4. Scope and Placement

### 4.1 Host Component

The feature is implemented as a **new page in the `agent` Streamlit app** (port 8501).

| Decision | Rationale |
|----------|-----------|
| Host = `agent` (Streamlit) | Python/pandas/charting already available; analyst-facing UI; matches the identity-centric threat-hunting mental model |
| Not Superset | Nested arrays would require flattening into DuckDB tables plus dataset/chart definitions — heavy |
| Not config-viz (React) | Graph-oriented; would require new FastAPI routes plus a React frontend |

### 4.2 Data Input

Input is via **in-UI file upload** (`st.file_uploader`, `.json`).

| Decision | Rationale |
|----------|-----------|
| Upload from UI | No mounted path, no volume, no `docker-compose` change → satisfies the hard constraint |
| No DuckDB ingestion | The data is already aggregated by Suzaku; relational storage adds no value for this view |

> Streamlit's default upload limit is 200 MB; the ~4 MB sample is comfortably within range.

### 4.3 Architectural Impact

- `agent` becomes a multi-page Streamlit app (`agent/pages/` or `st.navigation`).
- The new page is **read-only and self-contained**: it does not touch the DuckDB connection, OpenAI integration, or the existing chat page.

---

## 5. Input Data Model

The `aws-ct-summary` JSON is an **array of identity summary objects**. Each object has the following shape:

| Field | Type | Description |
|-------|------|-------------|
| `user_arn` | string | The IAM/STS identity (e.g. `arn:aws:iam::…:user/backup`) |
| `user_types` | string | Identity type (`IAMUser`, `AssumedRole`, `Root`, …) |
| `num_of_events` | number | Total CloudTrail events attributed to this identity |
| `first_timestamp` / `last_timestamp` | string (`YYYY-MM-DD HH:MM:SS`) | Activity window |
| `abused_apis_success` | array\<ApiEntry\> | Attack-relevant APIs that **succeeded** (Suzaku-curated, with `description`) |
| `abused_apis_failed` | array\<ApiEntry\> | Attack-relevant APIs that **failed** |
| `other_apis_success` | array\<ApiEntry\> | Non-flagged APIs that succeeded |
| `other_apis_failed` | array\<ApiEntry\> | Non-flagged APIs that failed |
| `aws_regions` | array\<ValueEntry\> | Per-region activity |
| `src_ips` | array\<ValueEntry\> | Source IPs with embedded GeoIP text |
| `user_access_key_ids` | array\<ValueEntry\> | Per access-key-ID activity |
| `user_agents` | array\<ValueEntry\> | Per user-agent activity |

**`ApiEntry`**: `{ api, description, count, first_seen, last_seen }`
- `api` example: `"RunInstances (ec2.amazonaws.com)"`
- `description` example: `"Spin up EC2 instances (crypto mining, tools)"`

**`ValueEntry`**: `{ value, count, first_seen, last_seen }`
- `src_ips.value` embeds GeoIP as free text: `"5.205.62.253 (Telefonica De Espana S.a.u., Madrid, Spain)"`
- a `value` of `"-"` denotes unknown/not-applicable.

> Observed in the sample: identities `user/backup` (680,449 events) and `user/Level6` (651,646 events) dominate, driven by `RunInstances` flagged as crypto mining — a typical compromise pattern.

---

## 6. Functional Requirements

### F1 — Upload & Validation

- `st.file_uploader` accepting a single `.json` file.
- Parse the JSON array; validate that each element contains the required keys (`user_arn`, `num_of_events`, `abused_apis_success`, `abused_apis_failed`, …).
- On malformed input, show a clear error and do not render downstream views.
- Parse once and cache with `st.cache_data` keyed on file content.

### F2 — Triage Table (landing view)

- One row per `user_arn`. Columns: `user_type`, `total events`, `abused success #`, `abused failed #`, `activity window (first → last)`, `# regions`, `# src_ips`, `# access keys`.
- Default sort: number of abused APIs (desc), then `num_of_events` (desc).
- Visually emphasize rows that have any abused APIs.
- Selecting a row drills down to the identity detail view (F3).

### F3 — Identity Detail View

For the selected `user_arn`:

- **Header**: ARN, type, total events, activity window.
- 🔴 **Abused APIs** (success / failed): table including `description` and `count`, plus a horizontal bar chart by count. This is the primary threat signal.
- **Source IPs / Regions / User Agents / Access Key IDs**: Top-N bar chart plus a full sortable table for each.
- **Activity timeline**: per-API spans derived from `first_seen → last_seen`.
- **Other APIs** (success / failed): collapsed inside `st.expander` (can be large).

### F4 — Export

- CSV download for the triage table and for each per-identity detail table.

---

## 7. Non-Functional Requirements & Notes

| Area | Requirement / Note |
|------|--------------------|
| GeoIP | `src_ips.value` carries GeoIP as embedded text with no lat/long. v1.0 renders a **per-country aggregated bar chart** (country parsed via regex). A true geo-map is deferred. |
| Performance | Logically small (~12 identities) but the JSON is several MB due to many APIs/IPs/UAs. Parse once via `st.cache_data`; render detail only for the selected identity. |
| Isolation | The page must not import or hold the DuckDB connection, and must function without `OPENAI_API_KEY`. |
| Testability | Parsing and aggregation logic implemented as pure functions in line with `agent/tests/` conventions, covered by unit tests. |
| Security | Treat uploaded content as untrusted input; never `eval`; render values as text. |

---

## 8. Open Questions

| # | Question | Provisional Decision |
|---|----------|----------------------|
| 1 | Is an interactive geo-map required? | No for v1.0 — per-country bar chart is sufficient |
| 2 | Should a risk score replace the simple "abused-count" sort? | No for v1.0 — abused-count + event-count sort is sufficient |
| 3 | Should multiple summaries be loadable/comparable in one session? | Out of scope for v1.0 |

---

## 9. Acceptance Criteria

- Uploading the `aws-ct-summary` sample renders a triage table ranking `user/backup` and `user/Level6` at the top.
- Selecting an identity shows its abused APIs (with descriptions), source IPs, regions, user agents, and access keys.
- The feature runs entirely within the existing `agent` service — no `docker-compose.yml`, volume, or new-service changes.
- The page works with no `OPENAI_API_KEY` set.
- Parsing/aggregation logic is covered by unit tests.
