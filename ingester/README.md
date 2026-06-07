# ingester

AWS CloudTrail log and AWS Config snapshot ingestion module for Senrigan.

- **`ingest`** — Reads CloudTrail log files (`.json` / `.json.gz`), optionally enriches each event with GeoIP data, and inserts all records into DuckDB via high-throughput batch appends.
- **`enrich`** — Back-fills GeoIP columns on an existing database without re-ingesting.
- **`config-import`** — Reads AWS Config snapshot JSON files and populates the `config_snapshots`, `config_resources`, and `config_edges` tables.

This is the **only** component that opens DuckDB in `READ_WRITE` mode.

---

## Table of Contents

- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Processing Pipeline](#processing-pipeline)
  - [Sequence Diagram — ingest](#sequence-diagram--ingest)
  - [Sequence Diagram — enrich](#sequence-diagram--enrich)
  - [Sequence Diagram — config-import](#sequence-diagram--config-import)
- [Database Schema](#database-schema)
- [Module Structure](#module-structure)
- [Development](#development)

---

## Quick Start

```bash
# Ingest a directory
ingester ingest --path /logs/cloudtrail/ --db /data/threat_hunting.db

# Date-range filter (January 2024 only)
ingester ingest --path /logs/ --from 20240101 --to 20240131

# Path-pattern filter (CloudTrail logs only, skip a region)
ingester ingest --path /logs/ --include "*CloudTrail*" --exclude "*ap-northeast-3*"

# With GeoIP enrichment
ingester ingest --path /logs/ \
  --geoip-city    /data/geoip/GeoLite2-City.mmdb \
  --geoip-asn     /data/geoip/GeoLite2-ASN.mmdb

# Strip low-signal fields from requestParameters / responseElements (lean DB)
ingester ingest --path /logs/ --strip-fields

# Strip both low-signal fields AND the raw_event column (smallest possible DB)
ingester ingest --path /logs/ --strip-fields --strip-raw-event \
  --db /data/lean_hunting.db

# Back-fill GeoIP data on an existing database (no re-ingest needed)
ingester enrich \
  --geoip-city /data/geoip/GeoLite2-City.mmdb \
  --geoip-asn  /data/geoip/GeoLite2-ASN.mmdb

# Import AWS Config snapshots
ingester config-import --path /data/config-snapshots/
```

---

## CLI Reference

### `ingest`

```
ingester ingest --path <PATH>
               [--db <PATH>]              DuckDB file (default: /data/db/threat_hunting.db)
               [--from <YYYYMMDD>]        Include files on or after this date
               [--to   <YYYYMMDD>]        Include files on or before this date
               [--include <GLOBS>]        Comma-separated glob patterns to include
               [--exclude <GLOBS>]        Comma-separated glob patterns to exclude
               [--workers <N>]            Parallel parse threads (default: CPU count)
               [--no-progress]            Disable progress bar
               [--geoip-city    <PATH>]   GeoLite2-City.mmdb
               [--geoip-country <PATH>]   GeoLite2-Country.mmdb (lighter alternative)
               [--geoip-asn     <PATH>]   GeoLite2-ASN.mmdb
               [--strip-fields]           Strip low-signal keys from requestParameters / responseElements
               [--strip-raw-event]        Write NULL for raw_event column (saves storage)
```

#### `--strip-fields`

Removes a fixed list of low-signal CloudTrail keys from `requestParameters` and
`responseElements` before they are written to DuckDB.  The categories stripped are:

| Category | Keys |
|----------|------|
| Pagination / size limits | `maxResults`, `MaxResults`, `maxItems`, `MaxItems`, `nextToken`, `NextToken`, `marker`, `Marker`, `pageSize`, `PageSize` |
| Idempotency / dry-run | `dryRun`, `DryRun`, `clientToken`, `ClientToken`, `clientRequestToken`, `ClientRequestToken` |
| Opaque ephemeral credentials | `sessionToken`, `SessionToken`, `secretAccessKey`, `SecretAccessKey` |
| AWS catalogue / reference data | `eventCategoriesMapList`, `reservedNodeOfferings`, `sslPolicies`, `orderableClusterOptions` |
| Query-time filter echoes | `filterSet`, `ownersSet` |
| Redundant transport headers | `Host`, `host` |

The stripping is recursive (nested objects and arrays are also processed).
The `raw_event` column is **never** modified by this flag, so the full original
record is always recoverable via full-text search on that column.

#### `--strip-raw-event`

Writes `NULL` instead of the full JSON blob to the `raw_event` column.
All Step-A extended columns (`user_identity_access_key_id`,
`session_mfa_authenticated`, `resources`, `tls_*`, etc.) are still populated,
so investigation queries that target dedicated columns continue to work.
Only the unscoped full-text fallback via `WHERE raw_event LIKE …` is no longer
available.

Combine with `--strip-fields` to produce the **smallest possible DB** for
high-volume CloudTrail data.  Use `--db <path>` to write to a dedicated file.

---

### `enrich`

```
ingester enrich
               [--db <PATH>]
               [--geoip-city    <PATH>]
               [--geoip-country <PATH>]
               [--geoip-asn     <PATH>]
```

Back-fills `geo_*` columns on rows that were ingested without a GeoIP database.
Only rows where `geo_country_code IS NULL` are updated.

---

### `config-import`

```
ingester config-import --path <PATH>
                       [--db <PATH>]        DuckDB file (default: /data/db/threat_hunting.db)
                       [--no-progress]      Disable progress bar
```

Walks `<PATH>` for `.json` files and writes records to three tables:
`config_snapshots`, `config_resources`, and `config_edges`.

SHA-256 deduplication via the shared `ingested_files` table prevents re-importing
unchanged files across runs.

**Dangling edge filter:** relationship entries whose `resourceId` target does not
exist in the same snapshot are silently dropped, keeping the graph self-contained.

Example output:

```
Config import complete: files_processed=1 files_skipped=0 resources_inserted=134 edges_inserted=46 errors=0 elapsed_secs=0.08
```

**DB path resolution order (all subcommands):** `--db` CLI arg → `DUCKDB_PATH` env var → `/data/db/threat_hunting.db`

`--include`/`--exclude` glob patterns (`ingest` only) use `*` that crosses `/` boundaries.
Files without a recognisable `yyyy/mm/dd` date segment in their path are always included.

---

## Processing Pipeline

### Sequence Diagram — `ingest`

```mermaid
sequenceDiagram
    participant CLI   as main.rs (CLI)
    participant IG    as ingest.rs
    participant PF    as path_filter.rs
    participant DF    as date_filter.rs
    participant WD    as WalkDir
    participant Ray   as rayon (thread pool)
    participant P     as parser.rs
    participant GEO   as geoip.rs
    participant DB    as db.rs (DuckDB Appender)

    CLI->>IG: ingest_with_filters(path, filters, geoip, conn)
    IG->>DB: ensure_table(conn)
    DB-->>IG: tables ready

    IG->>DB: fetch_ingested_files_map(conn)
    DB-->>IG: HashMap<path, sha256> (already-ingested)

    IG->>WD: walk directory tree
    WD-->>IG: list of all file paths

    loop For each file path
        IG->>PF: PathFilter::matches(path)
        PF-->>IG: include/exclude decision
        IG->>DF: DateFilter::matches(path)
        DF-->>IG: date range decision
    end

    Note over IG,Ray: Filtered file list split into chunks of 256

    loop Per chunk (parallel)
        IG->>Ray: parse_file_content(path) × N
        Ray->>P: parse_cloudtrail_log(bytes)
        P-->>Ray: Vec<CloudTrailEvent> + SHA-256
        Ray-->>IG: ParseOutcome per file
    end

    loop Per parsed chunk (sequential — DB write)
        IG->>GEO: lookup(source_ip_address) per event
        GEO-->>IG: GeoInfo (country, city, ASN, …)
        IG->>DB: insert_events_with_geo(events, geoip)
        DB-->>IG: rows inserted
        IG->>DB: batch_mark_ingested(file_paths)
    end

    IG-->>CLI: IngestStats {files, records, errors, elapsed}
    CLI->>CLI: print summary
```

**Key design points:**

| Aspect | Detail |
|--------|--------|
| Parallelism | File parsing runs in a `rayon` thread pool (chunk size 256). DB writes are serial (single writer). |
| Deduplication | SHA-256 of raw bytes is checked against `ingested_files` before inserting. Duplicate files are silently skipped. |
| Memory cap | `sync_channel` with depth 2 keeps at most 3 chunks (≈768 MB worst-case) in flight at once. |
| Batch insert | `duckdb::Appender` is used instead of individual `INSERT` statements for high throughput. |
| GeoIP | Lookup is done per-event in the insert loop. Private/reserved IPs return `None` and are stored as `NULL`. |

---

### Sequence Diagram — `enrich`

The `enrich` command back-fills geo columns on rows that were originally
ingested without a GeoIP database.

```mermaid
sequenceDiagram
    participant CLI  as main.rs (CLI)
    participant EN   as enrich.rs
    participant GEO  as geoip.rs
    participant DB   as DuckDB (READ_WRITE)

    CLI->>EN: enrich_existing(conn, geoip)
    EN->>DB: ensure_geo_columns (ALTER TABLE … ADD COLUMN IF NOT EXISTS)
    DB-->>EN: columns confirmed

    EN->>DB: SELECT DISTINCT source_ip_address WHERE geo_country_code IS NULL
    DB-->>EN: list of pending IPs

    loop For each unique IP
        EN->>GEO: lookup(ip)
        GEO-->>EN: GeoInfo
        EN->>DB: UPDATE cloudtrail_events SET geo_* = … WHERE source_ip = ip AND geo_country_code IS NULL
        DB-->>EN: rows affected
    end

    EN-->>CLI: EnrichStats {enriched_count, skipped_count, elapsed}
    CLI->>CLI: print summary
```

---

### Sequence Diagram — `config-import`

```mermaid
sequenceDiagram
    participant CLI  as main.rs (CLI)
    participant CI   as config_import.rs
    participant CP   as config_parser.rs
    participant WD   as WalkDir
    participant DB   as config_db.rs (DuckDB Appender)

    CLI->>CI: import_config(path, conn, opts)
    CI->>DB: ensure_table (ingested_files)
    CI->>DB: ensure_config_tables (config_snapshots / resources / edges)
    DB-->>CI: tables ready

    CI->>DB: fetch_ingested_files_map(conn)
    DB-->>CI: HashMap<path, sha256>

    CI->>WD: walk directory for *.json files
    WD-->>CI: list of file paths

    loop For each .json file
        CI->>CI: compute_sha256(file)
        CI-->>CI: skip if SHA-256 matches ingested_files
        CI->>CP: parse_config_snapshot(bytes)
        CP-->>CI: ParsedSnapshot {snapshot_id, resources, edges}
        CI->>DB: insert_config_snapshot(metadata)
        CI->>DB: insert_config_resources(resources) via Appender
        CI->>CI: filter dangling edges (target must exist in snapshot)
        CI->>DB: insert_config_edges(edges) via Appender
    end

    CI->>DB: batch_mark_ingested(newly_ingested)
    CI-->>CLI: ImportStats {files, resources, edges, errors, elapsed}
    CLI->>CLI: print summary
```

**Key design points:**

| Aspect | Detail |
|--------|--------|
| Deduplication | SHA-256 via shared `ingested_files` table — unchanged snapshot files are skipped on re-run. |
| Dangling edges | Relationship entries whose `resourceId` target is absent from the snapshot are dropped at import time. |
| Empty tags | `tags: {}` is normalised to `NULL` rather than storing a meaningless empty JSON string. |
| Timestamp | ISO 8601 capture times (`2026-01-01T00:00:00.000Z`) are normalised to `YYYY-MM-DD HH:MM:SS.mmm` for DuckDB's `TIMESTAMP` column. |
| Batch insert | Resources and edges use `duckdb::Appender` for throughput; snapshot metadata uses `INSERT OR IGNORE` for idempotency. |

---

## Database Schema

### `cloudtrail_events` (48 columns)

**Core (17):**

| Column | Type | Description |
|--------|------|-------------|
| `event_time` | TIMESTAMP (nullable) | Time the API call was made; NULL when `eventTime` is absent from the record |
| `event_name` | VARCHAR | API action name (e.g. `GetCallerIdentity`) |
| `event_source` | VARCHAR | AWS service endpoint (e.g. `sts.amazonaws.com`) |
| `aws_region` | VARCHAR | AWS region of the API call |
| `source_ip_address` | VARCHAR | Caller IP address |
| `user_agent` | VARCHAR | HTTP User-Agent of the caller |
| `user_identity_type` | VARCHAR | IAM identity type (Root, IAMUser, AssumedRole, …) |
| `user_identity_arn` | VARCHAR | Full ARN of the principal |
| `user_identity_account_id` | VARCHAR | AWS account ID |
| `request_parameters` | VARCHAR | JSON blob of request parameters |
| `response_elements` | VARCHAR | JSON blob of response elements |
| `error_code` | VARCHAR | AWS error code (NULL on success) |
| `error_message` | VARCHAR | AWS error message (NULL on success) |
| `read_only` | BOOLEAN | `true` if the event is a read-only action |
| `event_type` | VARCHAR | CloudTrail event type (`AwsApiCall`, `AwsConsoleSignIn`, …) |
| `recipient_account_id` | VARCHAR | Account that received the event |
| `raw_event` | VARCHAR | Full raw JSON of the CloudTrail record |

**GeoIP (7, nullable):**

| Column | Type | Description |
|--------|------|-------------|
| `geo_country_code` | VARCHAR | ISO 3166-1 alpha-2 country code |
| `geo_country_name` | VARCHAR | Country name |
| `geo_city` | VARCHAR | City name |
| `geo_latitude` | DOUBLE | Latitude |
| `geo_longitude` | DOUBLE | Longitude |
| `geo_asn` | VARCHAR | Autonomous System Number |
| `geo_org` | VARCHAR | AS organization name |

**Extended (24, nullable):** hoisted sub-fields from `userIdentity`, `sessionContext`, `tlsDetails`, etc. — see `db.rs` for the full list.

JSON blobs (`request_parameters`, `response_elements`, `raw_event`) are stored as `VARCHAR`.
Use `json_extract_string(column, '$.field')` for ad-hoc queries.

**ART Indexes on `cloudtrail_events`:**

| Index | Column | Purpose |
|-------|--------|---------|
| `idx_event_name` | `event_name` | Equality / IN filters on API action name |
| `idx_event_source` | `event_source` | Equality filters on AWS service endpoint |
| `idx_user_identity_type` | `user_identity_type` | Equality filters on identity type (Root, IAMUser, …) |
| `idx_error_code` | `error_code` | Equality filters on error code (AccessDenied, …) |
| `idx_source_ip_address` | `source_ip_address` | IP-based threat hunting queries |
| `idx_user_identity_access_key_id` | `user_identity_access_key_id` | Access key tracing queries |
| `idx_recipient_account_id` | `recipient_account_id` | Multi-account environment filtering |

Range-filter columns (e.g. `event_time`) rely on DuckDB's automatic zone maps (per-row-group min/max) and do not have explicit indexes.

---

### `ingested_files`

Shared by both `ingest` and `config-import` for SHA-256 deduplication.

| Column | Type | Description |
|--------|------|-------------|
| `file_path` | VARCHAR (PK) | Absolute path of the ingested file |
| `sha256` | VARCHAR | SHA-256 hex digest of the raw file bytes |
| `ingested_at` | TIMESTAMP | Timestamp when the file was first ingested |

---

### `config_snapshots`

One row per imported Config snapshot file.

| Column | Type | Description |
|--------|------|-------------|
| `snapshot_id` | VARCHAR (PK) | `configSnapshotId` from the JSON |
| `account_id` | VARCHAR | AWS account ID (from first item) |
| `aws_region` | VARCHAR | AWS region (from first item) |
| `captured_at` | TIMESTAMP | Latest `configurationItemCaptureTime` across all items |
| `source_path` | VARCHAR | Absolute path of the source JSON file |
| `record_count` | INTEGER | Number of configuration items in the snapshot |

---

### `config_resources`

One row per `configurationItem` in a snapshot.

| Column | Type | Description |
|--------|------|-------------|
| `resource_id` | VARCHAR (PK, part) | AWS resource ID |
| `snapshot_id` | VARCHAR (PK, part) | Parent snapshot ID |
| `resource_type` | VARCHAR (PK, part) | AWS resource type (e.g. `AWS::EC2::Instance`) |
| `aws_region` | VARCHAR | Region of the resource |
| `resource_name` | VARCHAR | Human-readable resource name |
| `configuration` | VARCHAR | Compact JSON of the `configuration` sub-object |
| `tags` | VARCHAR | Compact JSON of the `tags` map (NULL when empty) |

---

### `config_edges`

Directed relationships between resources within the same snapshot.

| Column | Type | Description |
|--------|------|-------------|
| `snapshot_id` | VARCHAR (PK, part) | Parent snapshot ID |
| `source_id` | VARCHAR (PK, part) | Resource ID of the relationship origin |
| `target_id` | VARCHAR (PK, part) | Resource ID of the relationship target |
| `edge_type` | VARCHAR (PK, part) | Relationship label (e.g. `Is associated with`) |

> Edges whose `target_id` does not exist in `config_resources` for the same
> `snapshot_id` are dropped at import time (dangling edge filter).

---

## Module Structure

```
ingester/
├── Cargo.toml
├── src/
│   ├── main.rs            # CLI entry point (clap) — subcommands: ingest, enrich, config-import
│   ├── lib.rs             # Public API re-exports
│   ├── parser.rs          # CloudTrail JSON parsing (serde_json)
│   ├── db.rs              # DuckDB schema management + batch insert (Appender) + geo columns
│   ├── ingest.rs          # CloudTrail pipeline (walk → filter → parallel parse → insert)
│   ├── enrich.rs          # GeoIP back-fill for existing rows (UPDATE per unique IP)
│   ├── geoip.rs           # MaxMind GeoLite2 lookup + private-IP classification
│   ├── field_filter.rs    # --strip-fields: recursive JSON key removal (FieldFilter)
│   ├── date_filter.rs     # --from / --to filter (extracts yyyy/mm/dd from path)
│   ├── path_filter.rs     # --include / --exclude glob filter
│   ├── progress.rs        # Progress bar wrapper (indicatif)
│   ├── config_parser.rs   # Config snapshot JSON → ParsedSnapshot / ParsedResource / ParsedEdge
│   ├── config_db.rs       # Config table schema + Appender writes (config_snapshots/resources/edges)
│   └── config_import.rs   # Config import pipeline (walk → SHA-256 dedup → parse → insert)
└── tests/
    ├── cli_test.rs              # CLI integration tests (ingest / enrich)
    ├── config_import_test.rs    # CLI integration tests (config-import)
    ├── integration_test.rs      # End-to-end ingest tests with a real DuckDB
    ├── testdata/                # CloudTrail JSON / gz fixtures + malformed sample
    └── testdata_config/         # Config snapshot JSON fixtures
```

---

## Development

> **Note:** The `duckdb` crate compiles libduckdb from source on first build.
> This can take **5–10 minutes**. Subsequent builds are fast thanks to Cargo's incremental compilation.

```bash
cd ingester

cargo build                   # Debug build
cargo build --release         # Release build

cargo test                    # All tests (unit + integration + CLI)
cargo test --lib              # Unit tests only
cargo clippy -- -D warnings   # Lint
cargo fmt                     # Format
```

### Environment variables (development)

| Variable | Description |
|----------|-------------|
| `DUCKDB_PATH` | Override the default DB path for ad-hoc testing |
| `RAYON_NUM_THREADS` | Limit the rayon thread pool size |
| `GEOIP_CITY_PATH` | Path to GeoLite2-City.mmdb |
| `GEOIP_COUNTRY_PATH` | Path to GeoLite2-Country.mmdb |
| `GEOIP_ASN_PATH` | Path to GeoLite2-ASN.mmdb |
