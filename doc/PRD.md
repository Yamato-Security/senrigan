# Product Requirements Document (PRD)

## Senrigan - AWS Log Threat Hunting Tool

| Field | Details |
|-------|---------|
| Document Version | 0.1 (Draft) |
| Date | 2026-03-10 |
| Status | Under Review |

---

## 1. Executive Summary

This product is a locally-executed threat hunting tool targeting AWS logs, primarily CloudTrail. By combining AI-Agent-assisted analysis with a built-in dashboard — without requiring logs to be ingested into a SIEM — it enables security analysts who lack deep AWS log expertise to perform fast and effective threat hunting on their own machines.

---

## 2. Background and Problem Statement

### 2.1 Problems to Solve

| Problem | Description |
|---------|-------------|
| Log expertise barrier | Detecting and analyzing threats is difficult without deep knowledge of AWS log formats such as CloudTrail |
| SIEM dependency | Existing threat hunting workflows assume ingestion into a SIEM (Splunk, Elasticsearch, etc.), resulting in high operational costs |
| Scalability gap | Few tools can process tens of gigabytes of logs quickly on a local PC |
| Knowledge silos | Without SQL skills or an understanding of log structure, analysts cannot write custom queries to investigate incidents |

### 2.2 Target Users

- Cloud security analysts (beginner to intermediate AWS log experience)
- Incident responders (requiring rapid initial triage)
- Security engineers (building or evaluating in-house log analysis tooling)

---

## 3. Product Vision and Goals

### 3.1 Vision

> "An open tool that empowers anyone to perform fast, high-precision threat hunting on a local PC — no AWS log expertise required."

### 3.2 Success Metrics (KPIs)

| Metric | Target |
|--------|--------|
| Ingestion time for 10 GB of logs | Within a few minutes (target: under 5 minutes) |
| Full scan of 50 GB of logs | Completable on a single PC |
| AI-generated SQL adoption rate | 50%+ of analysts execute AI-generated queries without modification |
| Automated threat hunting report generation | One-click output available per investigation session |

---

## 4. Scope

### 4.1 In Scope (v1.0)

- Local ingestion of CloudTrail logs (JSON / gz-compressed) and storage in DuckDB
- AI-Agent-assisted SQL query generation, execution, and analysis
- Automated threat hunting report generation
- Built-in dashboard powered by Apache Superset
- Single-command launch via Docker Compose

### 4.2 Out of Scope (v1.0)

- Direct S3 ingestion (deferred to v2+)
- Support for VPC Flow Logs, WAF logs, etc. (future plug-in extension)
- Sigma rule conversion (future)
- MITRE ATT&CK mapping (future)
- SaaS / cloud-hosted deployment

---

## 5. System Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Docker Compose                       │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │   ingester   │  │    agent     │  │  dashboard   │  │
│  │  (Rust)      │  │  (Streamlit) │  │  (Superset)  │  │
│  │              │  │              │  │              │  │
│  │ CloudTrail   │  │  AI-Agent    │  │   Visualize  │  │
│  │ gz ingest    │  │ SQL gen/exec │  │              │  │
│  └──────┬───────┘  └──────┬───────┘  └───────┬──────┘  │
│         │                 │                  │         │
│         │        ┌────────┴──────┐           │         │
│         │        │  config_viz   │           │         │
│         │        │ (FastAPI+     │           │         │
│         │        │  React)       │           │         │
│         │        │ Resource Graph│           │         │
│         │        └──────┬────────┘           │         │
│         └───────────────┴────────────────────┘         │
│                         │                              │
│                 ┌────────▼──────┐                      │
│                 │   DuckDB      │                      │
│                 │  (Bind Mount) │                      │
│                 └───────────────┘                      │
└─────────────────────────────────────────────────────────┘
```

---

## 6. Module Requirements

### 6.1 ingester Module

#### Overview
A data ingestion pipeline that reads CloudTrail logs from the local filesystem and stores them in DuckDB.

#### Technology Stack
- Language: Rust
- Storage: DuckDB

#### Functional Requirements

| ID | Feature | Priority |
|----|---------|----------|
| ING-01 | Read CloudTrail JSON log files | Must |
| ING-02 | On-the-fly decompression of gz-compressed files | Must |
| ING-03 | Bulk ingestion of multiple files and directories | Must |
| ING-04 | Automatic schema inference and storage in DuckDB | Must |
| ING-05 | Console progress display (record count, throughput, ETA) | Should |
| ING-06 | Duplicate ingestion prevention (checksum or filename tracking) | Should |
| ING-07 | Ingestion error log output | Should |
| ING-08 | Plug-in interface for extending log source support | Could (future) |

#### Non-Functional Requirements

| Item | Requirement |
|------|-------------|
| Ingestion speed | Complete 10 GB within 5 minutes |
| Maximum throughput | Complete 50 GB on a 16 GB RAM machine |
| Supported OS | Linux / macOS (via Docker) |

---

### 6.2 agent Module

#### Overview
An interactive threat hunting UI that leverages an AI-Agent to assist with analyzing logs stored in DuckDB.

#### Technology Stack
- Frontend: Streamlit
- AI integration: OpenAI API (with future support for Codex CLI, etc.)
- DB client: DuckDB Python client

#### Functional Requirements

| ID | Feature | Priority |
|----|---------|----------|
| AGT-01 | Natural language threat hunting instruction input (chat interface) | Must |
| AGT-02 | AI-powered automatic DuckDB SQL query generation | Must |
| AGT-03 | Review, edit, and execute generated SQL | Must |
| AGT-04 | Tabular display of SQL execution results | Must |
| AGT-05 | AI-generated analysis comments on query results | Must |
| AGT-06 | Automated threat hunting report generation (Markdown / PDF) | Must |
| AGT-07 | Built-in preset threat hunting prompt library | Should |
| AGT-08 | Save and recall past investigation sessions | Should |
| AGT-09 | OpenAI API key configuration UI | Must |

#### Built-in Prompt Examples (Reference)

- "List all API calls executed for the first time within the past 24 hours."
- "Identify IAM users with a high number of failed console login attempts."
- "Extract all actions performed by the root account."
- "Detect API calls made during anomalous hours (e.g., late night)."
- "List newly created IAM users and access keys."

---

### 6.3 config_viz Module

#### Overview
An interactive web UI that visualises AWS Config snapshot resources as a hierarchical graph.
Built with FastAPI (Python 3.14) on the backend and React 18 + React Flow on the frontend.

#### Technology Stack
- Backend: FastAPI + DuckDB Python client (READ_ONLY)
- Frontend: React 18 + Vite + TypeScript + React Flow + dagre

#### Functional Requirements

| ID | Feature | Priority |
|----|---------|----------|
| CFG-01 | List all ingested AWS Config snapshots | Must |
| CFG-02 | Display resource graph with hierarchical layout (VPC / Subnet / EC2 nesting) | Must |
| CFG-03 | Filter graph by AWS resource type | Must |
| CFG-04 | Click-to-inspect detail panel (configuration + tags) | Must |
| CFG-05 | Hover tooltip (resource ID, name, region, type) | Must |
| CFG-06 | Layout toggle (Top-Bottom / Left-Right) | Should |
| CFG-07 | AWS service icons for resource types | Should |

---

### 6.4 dashboard Module

#### Overview
A BI dashboard for visualizing logs stored in DuckDB. Powered by Apache Superset, it runs in a Docker container fully independent from the agent UI.

#### Technology Stack
- BI tool: Apache Superset
- DB connection: DuckDB Superset connector

#### Functional Requirements

| ID | Feature | Priority |
|----|---------|----------|
| DSH-01 | CloudTrail event time-series chart | Must |
| DSH-02 | Top-N API call ranking | Must |
| DSH-03 | Activity aggregation by IAM entity | Must |
| DSH-04 | Error (AccessDenied, etc.) occurrence trend | Must |
| DSH-05 | Source IP address geo-map visualization | Should |
| DSH-06 | Ad-hoc visualization via custom SQL | Must |
| DSH-07 | Dashboard export (PNG / PDF) | Should |

---

## 7. Infrastructure and Deployment Requirements

### 7.1 Docker Compose Services

| Service | Default Port | Description |
|---------|-------------|-------------|
| ingester | — | Log ingestion worker (CLI, profile: `ingest`) |
| agent | 8501 | Streamlit AI threat hunting UI |
| config_viz | 8502 | AWS Config resource graph (FastAPI + React) |
| dashboard | 8088 | Apache Superset BI dashboard |

### 7.2 Hardware Requirements

| Item | Minimum                        | Recommended                   |
|------|--------------------------------|-------------------------------|
| Memory | 8 GB                           | 16 GB                         |
| Storage | 10 GB free                     | 100 GB free (SSD recommended) |
| CPU | 4 cores                        | 8+ cores                      |
| OS | Docker-compatible Linux / macOS | Ubuntu 24.04 / macOS 13+      |

---

## 8. Security Requirements

| ID | Requirement | Description |
|----|-------------|-------------|
| SEC-01 | Network isolation | Runs within local network only; external exposure is not supported |
| SEC-02 | API key management | OpenAI API key managed via environment variables or `.env` file; never displayed in plaintext in the UI |
| SEC-03 | Log data protection | DuckDB files stored on local disk only; no cloud upload functionality in v1.0 |
| SEC-04 | Authentication | v1.0 assumes local use; authentication is optional (Superset's built-in basic auth may be used) |

---

## 9. Non-Functional Requirements Summary

| Category | Requirement |
|----------|-------------|
| Performance | Ingest and query 10 GB of logs within 5 minutes |
| Scalability | Process 50 GB of logs on a single PC (16 GB RAM) |
| Availability | No SLA defined (local tool) |
| Maintainability | Each module is an independent container; individual updates are possible |
| Extensibility | Log sources can be added via plug-in interface (future) |
| Usability | All services launched with a single `docker compose up` command |

---

## 10. Future Roadmap (Backlog)

### v2.0 Candidates

| Feature | Description |
|---------|-------------|
| Plug-in log source extensions | Architecture allowing addition of S3 access logs, VPC Flow Logs, AWS WAF logs, etc. |
| Direct S3 ingestion | Real-time ingestion from S3 buckets via AWS SDK |
| Sigma rule support | Convert Sigma rules to DuckDB SQL for automated detection of known attack patterns |
| MITRE ATT&CK mapping | Automatically map detected events to ATT&CK techniques and visualize coverage |
| Multi-user support | Shared team usage with authentication and RBAC |
| Alerting | Real-time notifications when events match defined conditions |

---

## 11. Open Issues and Decisions

### 11.1 DuckDB Container Sharing Strategy [RESOLVED]

**Decision: Adopt Docker Bind Mount + 1-writer / n-readers architecture**

DuckDB is an in-process database and does not support concurrent writes from multiple processes (a second process attempting to write will fail due to file locking). However, multiple READ_ONLY connections are permitted while one process holds a write lock. Given this constraint, the following architecture is adopted.

```
┌──────────────────────────────────────────────────────────────┐
│           Bind Mount: docker/data/db/threat_hunting.db        │
│           Mounted on host NVMe/SSD (recommended)              │
└────────────┬────────────────────────┬─────────────────────────┘
             │ READ_WRITE (1)          │ READ_ONLY (multiple)
             ▼                         ▼
        ingester             agent / config_viz / dashboard
      (write only)                  (read only)
```

Rationale and technical comparison:

| Option | Performance | Concurrent Access | Implementation Cost | Decision |
|--------|-------------|-------------------|--------------------|---------:|
| **Bind Mount + READ_ONLY** | ◎ Near-direct NVMe speed | 1W / nR | Low | **Adopted** |
| Named Volume | ◎ Same as above | Same | Low | Equivalent; bind mount preferred (avoids WSL2 path issues) |
| DuckLake (ducklake extension) | ○ | ◎ Multiple writers | High (requires separate catalog DB) | Consider for v2+ |
| Arrow Flight proxy | △ Network overhead | ◎ | High | Rejected (avoids complexity in v1) |
| NAS / network storage | ✕ Officially discouraged by DuckDB | ✕ | Low | Rejected |

**Implementation guidelines:**
- Each service declares its own `volumes:` entry in `docker-compose.yml` pointing to the host bind-mount path.
- ingester opens the database as `READ_WRITE`; agent, config_viz, and dashboard open as `READ_ONLY`.
- The default flow is sequential: ingester completes ingestion and releases the lock before read-only services start.
- SSD (SATA or NVMe) is strongly recommended for storage; HDD is discouraged (per DuckDB official guidelines).

---

### 11.2 OpenAI API Model Selection [RESOLVED]

**Decision: Adopt `gpt-5.4` as the primary model**
**Configuration guidelines:**
- Default model: `gpt-5.4`
- Model switchable in the UI settings screen
- Future models accommodated via the custom input field

---

### 11.3 Plug-in Interface API Specification [v2.0 DIRECTION RESOLVED]

**Decision: Design a Rust Trait-based plug-in interface in v2.0**

v1.0 will use a fixed CloudTrail implementation. v2.0 will define the following trait as the public API.

```rust
// v2.0 plug-in specification (conceptual design)
pub trait LogIngester: Send + Sync {
    /// Identifier for the log source (e.g., "cloudtrail", "vpc_flowlogs", "waf")
    fn source_id(&self) -> &str;

    /// Receives an input path (local directory or URI) and writes to DuckDB
    fn ingest(&self, input: &IngesterInput, db: &DuckDBHandle) -> Result<IngestStats>;

    /// File extensions / patterns supported by this plug-in
    fn supported_patterns(&self) -> Vec<&str>;
}
```

Built-in plug-in candidates for v2.0:

| Plug-in Name | Target Log | Target Version |
|-------------|-----------|---------------|
| `cloudtrail` | CloudTrail JSON/gz | v1.0 (fixed) |
| `vpc_flowlogs` | VPC Flow Logs | v2.0 |
| `s3_access` | S3 Access Logs | v2.0 |
| `waf` | AWS WAF Logs | v2.0 |
| `guardduty` | GuardDuty Findings | v2.0 |

---

### 11.4 Superset Initial Dashboard Seeding Strategy [RESOLVED]

**Decision: Auto-import dashboards at container startup using Superset's `import_dashboards` CLI command**

```yaml
# docker-compose.yml snippet
superset-init:
  image: apache/superset
  entrypoint: |
    superset import_dashboards -p /app/dashboards/cloudtrail_default.zip
  volumes:
    - ./dashboard/assets:/app/dashboards
```

Dashboard management policy:

| Item | Policy |
|------|--------|
| Dashboard definition file format | Superset export format (ZIP / YAML) |
| Storage location | Repository `dashboard/assets/` directory |
| Update process | Edit in Superset UI → export → overwrite and commit |
| Data source connection | `duckdb:///data/threat_hunting.db` bundled as the default configuration |

---

### 11.5 License Policy [RESOLVED]

**Decision: Release the entire project under GNU Affero General Public License v3.0 (AGPL-3.0)**

Rationale: AGPL-3.0 ensures that any hosted/network-accessible modifications must also be released as open source.

| Component | License | Compatibility |
|-----------|---------|---------------|
| Rust (language & standard library) | MIT OR Apache 2.0 | ◎ Compatible with AGPL-3.0 |
| DuckDB | MIT | ◎ MIT is compatible with AGPL-3.0 |
| Streamlit | Apache 2.0 | ◎ Apache 2.0 is compatible with AGPL-3.0 |
| Apache Superset | Apache 2.0 | ◎ Compatible |
| Docker Compose | Apache 2.0 | ◎ Compatible |
| OpenAI API client (usage only) | Terms of Service (separate from OSS distribution) | ◎ API usage is outside license scope |
| **This project** | **AGPL-3.0** | ◎ See [LICENSE](../LICENSE) |

---

## 12. Glossary

| Term | Definition |
|------|------------|
| CloudTrail | AWS service that records API call history |
| DuckDB | An embeddable, columnar OLAP database engine |
| SIEM | Security Information and Event Management system |
| MITRE ATT&CK | A knowledge base of adversary tactics, techniques, and procedures (TTPs) |
| Sigma | A generic, open signature format for log-based detection rules |
| TTP | Tactics, Techniques, and Procedures — describing how adversaries operate |

---

*This document is a draft prepared from an initial outline. It should be finalized following review and stakeholder alignment.*

