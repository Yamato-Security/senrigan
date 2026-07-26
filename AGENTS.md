# AGENTS.md — Senrigan

AI coding agent guide for the Senrigan project.
Module-level detail: [ingester/AGENTS.md](ingester/AGENTS.md) · [agent/AGENTS.md](agent/AGENTS.md)

---

## Architecture at a Glance

Four Docker containers share one DuckDB file via a **bind mount** (`docker/data/db/threat_hunting.db`).

| Container | Language | DuckDB mode | Port |
|-----------|----------|-------------|------|
| `ingester` | Rust 1.85+ | READ_WRITE (sole writer) | — |
| `agent` | Python 3.14+ / Streamlit | READ_ONLY | 8501 |
| `dashboard` | Apache Superset | READ_ONLY | 8088 |
| `config_viz` | Python 3.14+ / FastAPI + React 18 (ELK layout) | READ_ONLY | 8502 |

The `agent` container is a multi-page Streamlit app (`st.navigation`): **🔭 Senrigan** (the chat
hunting page) and **☁️ Suzaku CT Summary** (an upload-based viewer for Suzaku `aws-ct-summary`
JSON — read-only, no DuckDB, no API key required).

The bind-mount (not a named volume) is intentional — Docker Engine on Linux/WSL2 misresolves
relative paths for named-volume `driver_opts`, so each service declares its own `volumes:` entry
in `docker/docker-compose.yml`.

`ingester` must finish before `agent`/`dashboard`/`config_viz` start. Concurrent write sessions are not supported.

---

## Development Methodology: TDD

This project strictly follows **Test-Driven Development** (Red-Green-Refactor).

1. Write a test list before coding any feature.
2. Write ONE failing test (Red) — confirm it fails before proceeding.
3. Write the **minimum** code to make it pass (Green).
4. Refactor while keeping all tests green.
5. Repeat for the next item on the test list.

**Never write production code without a corresponding failing test first.**

When implementing a feature:
- Ask: "What is the test list for this feature?"
- Rust: `#[test]` in `#[cfg(test)] mod tests` within the same source file.
- Python: `def test_*` in `agent/tests/test_*.py` or `config_viz/tests/test_*.py`.
- TypeScript (frontend): `*.test.tsx` / `*.test.ts` in `config_viz/frontend/src/__tests__/`.

---

## Coding Conventions

### All modules

- **Language:** All code comments, `///` doc comments, docstrings, commit messages, and PR
  descriptions MUST be written in **English**. No exceptions.
- **Commits:** Conventional Commits — `feat:`, `fix:`, `test:`, `refactor:`, `docs:`, `chore:`.
- **Branch naming:** `feature/<module>-<short-desc>` / `fix/<module>-<short-desc>`.

### Rust (`ingester/`)

- **Formatter:** `rustfmt` (default settings) — run `cargo fmt`.
- **Linter:** `clippy` — all warnings must be resolved (`cargo clippy -- -D warnings`).
- **Errors:** `anyhow::Result` everywhere; `.with_context(|| format!("..."))` for context.
- **DB writes:** always use `duckdb::Appender`, never individual `INSERT` statements.
- **Tests:** unit tests in `#[cfg(test)] mod tests` in the same file; integration tests in
  `ingester/tests/`.

### Python (`agent/` and `config_viz/backend/`)

- **Formatter:** `black` (line length 88).
- **Linter:** `ruff`.
- **Type hints:** required on all function signatures.
- **Docstrings:** Google style.
- **Imports:** stdlib → third-party → local (enforced by `ruff`).
- **OpenAI mocks:** mock as `llm.OpenAI`, **not** `agent.llm.OpenAI`.
  `pytest.ini` sets `pythonpath = .` so modules resolve at the top level.
- **DuckDB in tests:** use `tmp_path / "test.db"` via the `tmp_duckdb` fixture in
  `agent/tests/conftest.py`. Never use a shared file.
- **Real API calls in tests are forbidden** — always mock `llm.OpenAI`.

---

## Essential Commands

Run from `docker/`:

```bash
# First-time ingest (CloudTrail)
docker compose --profile ingest run --rm ingester ingest --path /data/logs

# First-time ingest (AWS Config snapshots)
docker compose --profile ingest run --rm ingester config-import --path /data/config

# Start agent + dashboard + config_viz
docker compose up -d --build

# Re-ingest from scratch
docker compose down
rm -f data/db/threat_hunting.db data/db/threat_hunting.db.wal
docker compose --profile ingest run --rm ingester ingest --path /data/logs
docker compose up -d --build

# Fix blank dashboard after re-ingest (re-syncs column metadata)
docker compose --profile resync run --rm superset-resync
```

**After editing any file under `dashboard/assets/cloudtrail_default/`** (chart/dashboard YAML):
Superset never reads those YAML files directly — it only applies them from the compiled
`cloudtrail_default.zip` and `cloudtrail_rare.zip` (the derived "Rare Events" dashboard),
imported into Superset's own metadata DB by the one-shot `superset-init` container.
Editing the YAML (or even rebuilding the zips) alone has no effect on the running
dashboards. Always finish with all steps:

```bash
cd dashboard/assets && python3 rebuild_zip.py && python3 rebuild_rare_zip.py   # regenerate both zips
cd ../../docker && docker compose run --rm superset-init   # re-import into Superset (idempotent)
```

Development (run from module directories):

```bash
# Rust (ingester/)
cargo test                    # unit + integration + CLI tests
cargo clippy -- -D warnings   # lint
cargo fmt                     # format

# Python backend (agent/)
pytest                        # all tests
pytest --cov=. --cov-report=term-missing
ruff check .                  # lint
black .                       # format
```

```bash
# Python backend (config_viz/)
pytest                        # all tests (67 backend tests)
ruff check .                  # lint
black .                       # format

# TypeScript frontend (config_viz/frontend/)
npm test                      # all tests (114 frontend tests)
npm run build                 # Vite production build → ../static/
```

```bash
# Dashboard (dashboard/) — YAML/asset/config validation suite
pytest                        # all tests (605 tests)
```

Approximate test totals: ingester ≈ 185 (Rust), agent ≈ 509 (pytest), config_viz ≈ 67 backend +
114 frontend, dashboard ≈ 655, root `tests/` ≈ 5 (Makefile / compose / docs consistency).
Test count must not decrease in a PR.

---

## DuckDB Schema

### `cloudtrail_events` (48 columns)

JSON blobs are stored as **`VARCHAR`**, not DuckDB JSON type.
Use `json_extract_string(column, '$.field')` for ad-hoc queries.

Column layout: **core (17) → geo (7) → extended (24)**.
Geo and extended columns are added via `ALTER TABLE ADD COLUMN IF NOT EXISTS` so existing
databases are migrated transparently on the next ingest run.

```sql
CREATE TABLE IF NOT EXISTS cloudtrail_events (
    -- Core columns (17)
    event_time               TIMESTAMP,
    event_name               VARCHAR,
    event_source             VARCHAR,
    aws_region               VARCHAR,
    source_ip_address        VARCHAR,
    user_agent               VARCHAR,
    user_identity_type       VARCHAR,
    user_identity_arn        VARCHAR,
    user_identity_account_id VARCHAR,
    request_parameters       VARCHAR,   -- JSON stored as VARCHAR
    response_elements        VARCHAR,   -- JSON stored as VARCHAR
    error_code               VARCHAR,
    error_message            VARCHAR,
    read_only                BOOLEAN,
    event_type               VARCHAR,
    recipient_account_id     VARCHAR,
    raw_event                VARCHAR    -- full original event JSON as VARCHAR; NULL when --strip-raw-event
);

-- GeoIP columns (7) — added via ALTER TABLE ADD COLUMN IF NOT EXISTS
-- NULL when ingested without a GeoLite2 database
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS geo_country_code VARCHAR;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS geo_country_name VARCHAR;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS geo_city         VARCHAR;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS geo_latitude     DOUBLE;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS geo_longitude    DOUBLE;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS geo_asn          VARCHAR;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS geo_org          VARCHAR;

-- Extended columns (24) — hoisted sub-fields; added via ALTER TABLE ADD COLUMN IF NOT EXISTS
-- userIdentity sub-fields
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS user_identity_principal_id      VARCHAR;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS user_identity_access_key_id     VARCHAR;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS user_identity_user_name         VARCHAR;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS user_identity_invoked_by        VARCHAR;
-- userIdentity.sessionContext.attributes
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS session_mfa_authenticated       VARCHAR;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS session_creation_date           VARCHAR;
-- userIdentity.sessionContext.sessionIssuer
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS session_issuer_type             VARCHAR;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS session_issuer_arn              VARCHAR;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS session_issuer_account_id       VARCHAR;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS session_issuer_user_name        VARCHAR;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS session_issuer_principal_id     VARCHAR;
-- top-level identifiers / categorisation
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS event_id                        VARCHAR;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS event_category                  VARCHAR;
-- resources / additional / shared / VPC
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS resources                       VARCHAR;  -- JSON array
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS additional_event_data           VARCHAR;  -- JSON object
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS shared_event_id                 VARCHAR;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS vpc_endpoint_id                 VARCHAR;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS management_event                VARCHAR;  -- "true"/"false"
-- TLS posture
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS tls_version                     VARCHAR;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS tls_cipher_suite                VARCHAR;
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS tls_client_provided_host_header VARCHAR;
-- service-specific / misc
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS service_event_details           VARCHAR;  -- JSON object
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS session_credential_from_console VARCHAR;  -- "true"/"false"
ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS api_version                     VARCHAR;
```

### `ingested_files`

`file_path` (PK), `sha256`, `ingested_at` — tracks ingested files for SHA-256-based deduplication.

### DuckDB Access Rules

1. `ingester` is the **sole writer** — never open `READ_WRITE` from `agent` or `dashboard`.
2. `agent` and `dashboard` always use `read_only=True`.
3. Tests must use temporary databases (`tempfile` in Rust, `tmp_path` in pytest).
4. SSD storage is strongly recommended for the DuckDB bind mount.

---

## SQL Safety in `agent/`

Before executing any LLM-generated SQL, `query.py` applies three guards in order:

1. **Keyword blocklist** — rejects `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`
   (regex, word-boundary, case-insensitive).
2. **EXPLAIN validation** — runs `EXPLAIN <sql>` on the READ_ONLY connection.
3. **Row-limit cap** — wraps queries without `LIMIT` in `SELECT * FROM (...) AS _limited LIMIT N`.

If validation fails, `execute_with_retry` calls `fix_sql_with_llm` once for automatic correction.

Date-range UI filters inject a `_ct_filtered` CTE — see `apply_date_filter()` in `agent/query.py`.

`agent/builtin_hunts.yaml` ships pre-built queries with `label`, `description`, `prompt`, and an
optional `sql` field. Entries with `sql` run without an OpenAI API key.

---

## Ingester CLI Reference

```
ingester ingest --path <dir>
                [--db           <path>]     # overrides DUCKDB_PATH env var
                [--from         <YYYYMMDD>]
                [--to           <YYYYMMDD>]
                [--include      <globs>]    # comma-separated, e.g. "*CloudTrail*"
                [--exclude      <globs>]    # comma-separated, e.g. "*us-west-2*"
                [--workers      <N>]        # parallel threads (default: CPU count)
                [--no-progress]
                [--geoip-city   <path>]     # GeoLite2-City.mmdb   (or GEOIP_CITY_PATH)
                [--geoip-country <path>]    # GeoLite2-Country.mmdb (or GEOIP_COUNTRY_PATH)
                [--geoip-asn    <path>]     # GeoLite2-ASN.mmdb    (or GEOIP_ASN_PATH)
                [--strip-fields]            # remove low-signal keys from requestParameters / responseElements
                [--strip-raw-event]         # write NULL for raw_event column (saves storage)

ingester enrich
                [--db           <path>]
                [--geoip-city / --geoip-country / --geoip-asn <path>]
```

DB path resolution order: `--db` CLI arg → `DUCKDB_PATH` env var → `/data/db/threat_hunting.db`.

`--include`/`--exclude` globs use `*` that crosses `/` boundaries.
Files without a recognisable `yyyy/mm/dd` segment in their path are always included.

---

## Environment Variables

| Variable | Used by | Default | Notes |
|----------|---------|---------|-------|
| `OPENAI_API_KEY` | agent | — | Required for AI features |
| `DUCKDB_PATH` | all | — | Overrides default DB path |
| `OPENAI_MODEL` | agent | `gpt-5.5` | SQL generation + analysis model (`gpt-5.5`, `gpt-5.4`, `gpt-5.4-mini` available) |
| `OPENAI_MODEL_LITE` | agent | `gpt-5.4-mini` | Optional lighter model |
| `DUCKDB_HOST_PATH` | docker host | `./data/db` | Host-side bind-mount directory |
| `GEOIP_HOST_PATH` | docker host | `./data/geoip` | Host-side GeoIP directory |
| `GEOIP_CITY_PATH` | ingester | — | Path to GeoLite2-City.mmdb |
| `GEOIP_COUNTRY_PATH` | ingester | — | Path to GeoLite2-Country.mmdb |
| `GEOIP_ASN_PATH` | ingester | — | Path to GeoLite2-ASN.mmdb |
| `SUPERSET_SECRET_KEY` | dashboard | auto-generated | `make up` writes a per-install key to `docker/.env`; Superset refuses to start without one |
| `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` | agent | — | CA bundle for corporate TLS proxy |
| `RAYON_NUM_THREADS` | ingester | CPU count | Limits rayon thread pool |

---

## Security Rules

1. **API keys:** never hardcode — always read from environment variables.
2. **SQL safety:** `READ_ONLY` DuckDB connection + keyword blocklist + `EXPLAIN` validation (applies to `agent` and `config_viz` backend).
3. **No external data upload:** only the OpenAI API call sends data externally (SQL prompt + results).
4. **Network:** all services are local-only by default.

---

## File Structure

```
senrigan/
├── .github/
│   ├── AGENTS.md              # Short pointer → see root AGENTS.md
│   └── copilot-instructions.md
├── ingester/                  # Rust log ingestion engine
│   ├── AGENTS.md              # Ingester-specific TDD context
│   ├── README.md
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs            # CLI (ingest + enrich + config-import subcommands)
│       ├── lib.rs
│       ├── parser.rs          # CloudTrail JSON parsing (serde_json)
│       ├── db.rs              # DuckDB schema, batch insert (Appender), geo columns
│       ├── ingest.rs          # Pipeline: walk → filter → parallel parse → insert
│       ├── enrich.rs          # Geo back-fill (UPDATE per unique IP)
│       ├── geoip.rs           # MaxMind GeoLite2 lookup + private-IP classification
│       ├── field_filter.rs    # --strip-fields: recursive JSON key removal (FieldFilter)
│       ├── date_filter.rs     # --from / --to path-based date filter
│       ├── path_filter.rs     # --include / --exclude glob filter
│       ├── progress.rs        # Progress bar (indicatif)
│       ├── config_parser.rs   # AWS Config snapshot JSON → typed structs
│       ├── config_db.rs       # Config tables schema + Appender writes
│       ├── config_import.rs   # config-import pipeline: walk → SHA dedup → parse → insert
│       └── test_util.rs       # Shared test fixtures (only compiled under #[cfg(test)])
├── agent/                     # Python / Streamlit AI-agent UI (multi-page via st.navigation)
│   ├── AGENTS.md              # Agent-specific TDD context
│   ├── app.py                 # Entry point: st.navigation (chat page + Suzaku CT Summary page)
│   ├── handlers.py            # Stateful handler functions
│   ├── llm.py
│   ├── query.py
│   ├── report.py              # Chat-session Markdown / PDF report
│   ├── schema.py
│   ├── config.py
│   ├── builtin_hunts.yaml
│   ├── suzaku_summary.py      # Parse + aggregate Suzaku aws-ct-summary JSON (pure functions)
│   ├── suzaku_report.py       # Markdown / HTML report for the Suzaku summary (pure functions)
│   ├── views/
│   │   └── suzaku_ct_summary.py   # st.navigation page: upload-based Suzaku summary viewer
│   └── prompts/
│       ├── system_prompt.py
│       └── analysis_prompt.py
├── config_viz/                # AWS Config resource graph (FastAPI + React)
│   ├── PLAN.md                # Implementation plan (Phase A/B/C — all complete)
│   ├── README.md              # config_viz module documentation
│   ├── Dockerfile             # Multi-stage: Node build → Python runtime
│   ├── backend/               # FastAPI backend (Python 3.14+)
│   │   ├── __init__.py
│   │   ├── main.py            # FastAPI app + 4 REST endpoints + /icons static mount
│   │   ├── db.py              # DuckDB READ_ONLY connection (get_conn dependency)
│   │   ├── query.py           # SQL queries + keyword blocklist
│   │   ├── requirements.txt
│   │   └── scripts/
│   │       └── extract_icons.py   # AWS icon download (runs at Docker build time; failure-safe)
│   ├── frontend/              # React 18 + Vite + TypeScript SPA
│   │   ├── package.json       # (type: module) — reactflow + elkjs
│   │   ├── vite.config.ts     # outDir: ../static
│   │   ├── vitest.config.ts
│   │   └── src/
│   │       ├── App.tsx        # Root component (state management)
│   │       ├── types.ts       # Shared TypeScript types
│   │       ├── api.ts         # fetch wrappers for 4 API endpoints
│   │       ├── components/
│   │       │   ├── AwsNode.tsx        # Leaf node + hover tooltip
│   │       │   ├── AwsGroupNode.tsx   # Container node (dashed border)
│   │       │   ├── GraphCanvas.tsx    # ReactFlow + ELK layout
│   │       │   ├── Sidebar.tsx        # Snapshot list + filter + layout toggle
│   │       │   ├── DetailPanel.tsx    # Resource detail slide-in panel
│   │       │   ├── CollapseContext.tsx # Collapse/expand state for group nodes
│   │       │   └── Legend.tsx         # Service-color legend
│   │       ├── utils/
│   │       │   ├── layout.ts        # ELK (elkjs) Sugiyama layered layout for the compound graph
│   │       │   ├── collapse.ts      # Group collapse/expand helpers
│   │       │   ├── label.ts         # Node label formatting
│   │       │   ├── serviceColors.ts # AWS service → color mapping
│   │       │   └── icons.ts         # AWS resource type → icon URL (with fallback)
│   │       └── mocks/          # MSW v2 handlers for tests
│   ├── static/                # Vite build output (served by FastAPI)
│   └── tests/
│       ├── conftest.py         # tmp_db_empty, tmp_db_seeded, tmp_db_hierarchy fixtures
│       └── test_query.py       # backend tests (BA-* series)
├── dashboard/                 # Apache Superset BI dashboard
│   ├── Dockerfile
│   ├── superset_config.py
│   ├── pytest.ini
│   ├── assets/                # cloudtrail_default.zip + cloudtrail_rare.zip + YAML definitions
│   ├── init/                  # bootstrap.sh, register_duckdb.py
│   └── tests/                 # YAML/asset/config/Dockerfile validation suite
├── doc/                       # Documentation
│   ├── ARCHITECTURE.md
│   ├── DEVELOPMENT.md
│   ├── PRD.md
│   ├── PRD_SUZAKU_SUMMARY.md  # Suzaku aws-ct-summary viewer requirements
│   ├── PRD_DASHBOARD_REVIEW.md # Superset dashboard DFIR review & redesign
│   ├── PLAN_SUGIYAMA.md       # config_viz layout migration (dagre → ELK/Sugiyama)
│   ├── PLAN_GEO_ENRICHMENT.md # auto geo columns for IP output (agent + dashboard)
│   ├── PLAN_THREAT_CATALOG.md # Threat Technique Catalog for AWS coverage + TID annotations
│   ├── TDD_GUIDE.md
│   └── TESTING.md
└── docker/
    └── docker-compose.yml     # Orchestration (5 services + profiles)
```
