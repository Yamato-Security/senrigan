# AGENTS.md — Senrigan

Reference context for AI coding agents. Working rules (TDD, conventions, schema-change and
documentation checklists) are in [CLAUDE.md](CLAUDE.md) and apply to every agent. Module detail:
[ingester/AGENTS.md](ingester/AGENTS.md) · [agent/AGENTS.md](agent/AGENTS.md). Background:
[doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) · [doc/DEVELOPMENT.md](doc/DEVELOPMENT.md) ·
[doc/TESTING.md](doc/TESTING.md) · [doc/TDD_GUIDE.md](doc/TDD_GUIDE.md) · [doc/PRD.md](doc/PRD.md).

---

## Architecture

Four containers share one DuckDB file (`docker/data/db/threat_hunting.db`) via a bind mount.
`docker/docker-compose.yml` declares six services: three long-running (`agent`, `config-viz`,
`superset`) and three one-shot runners — `ingester` (profile `ingest`), `superset-init` (every
`up`) and `superset-resync` (profile `resync`).

| Container | Language | DuckDB mode | Port |
|-----------|----------|-------------|------|
| `ingester` | Rust 1.85+ | READ_WRITE (sole writer) | — |
| `agent` | Python 3.14+ / Streamlit | READ_ONLY | 8501 |
| `dashboard` | Apache Superset | READ_ONLY | 8088 |
| `config_viz` | Python 3.14+ / FastAPI + React 18 (ELK layout) | READ_ONLY | 8502 |

`ingester` must finish before the readers start; concurrent writers are unsupported. The bind
mount (not a named volume) is intentional — Docker Engine on Linux/WSL2 misresolves relative
paths for named-volume `driver_opts`, so each service declares its own `volumes:` entry.

**The agent's four pages** (`st.navigation`, one `DatasetProfile` from `agent/profiles.py` each):
🔭 Senrigan (`cloudtrail_events`) and 🕒 Suzaku Timeline (the `timeline` table of an
`aws-ct-timeline` export) are *chat* pages sharing one pipeline, with the LLM writing the SQL.
👤 Suzaku Summary and 📊 Suzaku Metrics are *explorer* pages (`chat_enabled=False`) running only
reviewed, parameterized SQL from `agent/suzaku_{summary,metrics}_queries.py`; a profile reaching
the chat pipeline raises rather than sending an empty prompt to OpenAI. Generating SQL over
pre-aggregated Suzaku output would add cost and a hallucination surface for no gain — the
dashboard answers "what does this run look like?", the explorer drills down, compares, pivots
into the timeline page and pins findings into a report.

**Suzaku files are read as-is** — never imported into `threat_hunting.db`, never opened writable,
so the 1-writer invariant holds. Names are arbitrary: the producing command and the
`schema_version` both readers check come from the file's own `suzaku_meta` table (a version newer
than this release is refused). Detection, fitness and selection live only in `agent/suzaku_db.py`,
bind-mounted into the Superset init/resync containers and imported by
`dashboard/init/register_suzaku_dbs.py` — `tests/test_suzaku_detection_shared.py` guards that.
With several files for one command, exactly one wins (`generated_at` → mtime → path, among files
carrying every column in `REQUIRED_COLUMNS`), so both UIs agree; `make status` reports the winner
and the rejected candidates.

---

## Essential Commands

Run from the repository root. `make` with no arguments prints the five user-facing
commands; `make help-all` lists every target grouped by section.

```bash
make ingest    # Load CloudTrail logs from docker/logs/ into DuckDB
make up        # Start agent + dashboard + config_viz
make down      # Stop everything
make logs      # Tail service logs (SERVICE=agent|superset|config-viz for one)
make reset     # Stop, delete the DuckDB file, and start over (FORCE=1 to skip the prompt)
```

Unadvertised: `make status` (state, DB size, which Suzaku file each dashboard uses),
`make resync` (blank dashboard after re-ingest), `make check` (everything CI enforces).

`make ingest` takes **no flags** — it reads the compose bind-mount directories
(`GEOIP_HOST_PATH` / `CONFIG_HOST_PATH` / `DUCKDB_HOST_PATH`) and enables the matching options
itself: GeoLite2 `.mmdb` files add the `--geoip-*` flags (City supersedes Country), a non-empty
`docker/data/config-snapshots/` runs `config-import` as a second pass. Overrides
(`ingest-full`, `ingest-geoip`, `ingest-config`, `enrich`) sit under `##@ Advanced ingest` in
`make help-all`; operational detail in [doc/DEVELOPMENT.md](doc/DEVELOPMENT.md).

**Editing dashboard YAML changes nothing on its own** — Superset applies only the compiled ZIPs,
imported by the one-shot `superset-init` container, so every edit under
`dashboard/assets/<bundle>/` ends with both steps:

```bash
cd dashboard/assets && python3 rebuild_zip.py && python3 rebuild_rare_zip.py   # or rebuild_suzaku_<name>_zip.py
cd ../../docker && docker compose run --rm superset-init   # re-import into Superset (idempotent)
```

Per-module loops — Rust (`ingester/`): `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt`.
Python (`agent/`, `config_viz/` (67 backend tests), `dashboard/` (793 dashboard tests)): `pytest`,
`ruff check .`, `black .`. TypeScript (`config_viz/frontend/`): `npm test -- --run`
(114 frontend tests), `npm run build` (Vite → `../static/`).

Approximate test totals: ingester ≈ 187 (Rust), agent ≈ 825 (pytest), config_viz ≈ 67 backend +
114 frontend, dashboard ≈ 793, root `tests/` ≈ 238 (Makefile / compose / docs / Suzaku selection
and lifecycle). Test count must not decrease in a PR, and a PR that changes one updates this line
and [CLAUDE.md](CLAUDE.md) together.

---

## DuckDB Schema

`cloudtrail_events` — **48 columns**, laid out core (17) → geo (7) → extended (24). Everything is
`VARCHAR` except `event_time TIMESTAMP`, `read_only BOOLEAN`, and `geo_latitude` / `geo_longitude`
`DOUBLE`. JSON blobs (`request_parameters`, `response_elements`, `resources`,
`additional_event_data`, `service_event_details`, `raw_event`) are stored as `VARCHAR`, not DuckDB
JSON type — query them with `json_extract_string(column, '$.field')`. `ingester/src/db.rs` is the
authority; geo and extended columns are added with `ALTER TABLE ADD COLUMN IF NOT EXISTS`, so
existing databases migrate transparently on the next ingest run.

```text
core (17)     event_time, event_name, event_source, aws_region, source_ip_address, user_agent,
              user_identity_type, user_identity_arn, user_identity_account_id,
              request_parameters, response_elements, error_code, error_message, read_only,
              event_type, recipient_account_id, raw_event   -- raw_event NULL with --strip-raw-event

geo (7)       geo_country_code, geo_country_name, geo_city, geo_latitude, geo_longitude,
              geo_asn, geo_org                              -- NULL without a GeoLite2 database

extended (24) userIdentity:   user_identity_principal_id, user_identity_access_key_id,
                              user_identity_user_name, user_identity_invoked_by
              sessionContext: session_mfa_authenticated, session_creation_date
              sessionIssuer:  session_issuer_type, session_issuer_arn, session_issuer_account_id,
                              session_issuer_user_name, session_issuer_principal_id
              identifiers:    event_id, event_category, shared_event_id, vpc_endpoint_id
              payloads:       resources, additional_event_data, service_event_details
              TLS:            tls_version, tls_cipher_suite, tls_client_provided_host_header
              misc:           management_event, session_credential_from_console, api_version
                              -- the two boolean-ish ones hold the strings "true"/"false"
```

Only the 17 core + 7 GeoIP columns are exposed to the LLM (`agent/schema.py`); the 24 extended
ones are withheld to keep the prompt small. Adding or exposing a column follows the
schema-change checklist in [CLAUDE.md](CLAUDE.md).

Other tables: `ingested_files` (`file_path` PK, `sha256`, `ingested_at`) drives SHA-256
deduplication for both `ingest` and `config-import`; `config_snapshots`, `config_resources` and
`config_edges` are written by `config-import` and read by `config_viz`.

**Access rules:** `ingester` is the sole `READ_WRITE` opener; every other service passes
`read_only=True`; tests use temporary databases (`tempfile` in Rust, `tmp_path` in pytest).
SSD/NVMe storage is strongly recommended for the bind mount.

---

## SQL Safety

`agent/query.py` applies three guards to LLM-generated SQL, in order: a **keyword blocklist**
(`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`; word-boundary, case-insensitive),
**EXPLAIN validation** on the READ_ONLY connection, and a **row-limit cap** wrapping un-`LIMIT`ed
queries in `SELECT * FROM (...) AS _limited LIMIT N`. On failure `execute_with_retry` calls
`fix_sql_with_llm` once. The same blocklist + EXPLAIN pair guards `config_viz/backend/query.py`.

Date-range UI filters inject a `_ct_filtered` CTE (`apply_date_filter()` in `agent/query.py`).
`agent/builtin_hunts.yaml` entries carry `label`, `description`, `prompt` and an optional `sql`;
those with `sql` run without an OpenAI API key.

## Ingester CLI

```
ingester ingest --path <dir>
                [--db <path>]                   # else DUCKDB_PATH, else /data/db/threat_hunting.db
                [--from <YYYYMMDD>] [--to <YYYYMMDD>]
                [--include <globs>] [--exclude <globs>]   # comma-separated; * crosses /
                [--workers <N>]                 # default: CPU count
                [--no-progress]
                [--geoip-city|--geoip-country|--geoip-asn <path>]   # or GEOIP_*_PATH
                [--strip-fields]                # drop low-signal request/response keys
                [--strip-raw-event]             # write NULL for raw_event

ingester enrich [--db <path>] [--geoip-city|--geoip-country|--geoip-asn <path>]
ingester config-import --path <dir> [--db <path>] [--no-progress]
```

Files without a recognisable `yyyy/mm/dd` segment in their path are always included by the
`--from` / `--to` filter.

## Environment Variables

| Variable | Used by | Default | Notes |
|----------|---------|---------|-------|
| `OPENAI_API_KEY` | agent | — | Required for AI features |
| `OPENAI_MODEL` / `OPENAI_MODEL_LITE` | agent | `gpt-5.5` / `gpt-5.4-mini` | UI offers `gpt-5.5`, `gpt-5.4`, `gpt-5.4-mini`; see [CLAUDE.md](CLAUDE.md) before changing |
| `DUCKDB_PATH` | all | — | Overrides the default DB path |
| `DUCKDB_PATH_LITE` | agent | — | Optional `--strip-fields` DB; enables the Full/Lite selector |
| `SUZAKU_{TIMELINE,SUMMARY,METRICS}_DB` | agent, dashboard | — | Pin one Suzaku file instead of discovery |
| `DUCKDB_HOST_PATH` / `GEOIP_HOST_PATH` / `CONFIG_HOST_PATH` | docker host | `./data/{db,geoip,config-snapshots}` | Host-side bind-mount dirs; also drive `make ingest` detection |
| `GEOIP_CITY_PATH` / `GEOIP_COUNTRY_PATH` / `GEOIP_ASN_PATH` | ingester | — | GeoLite2 `.mmdb` paths |
| `SUPERSET_SECRET_KEY` | dashboard | auto-generated | `make up` writes a per-install key to `docker/.env`; Superset refuses to start without one |
| `CUSTOM_CA_CERT_BASE64` | docker build | empty | Base64 CA for TLS-inspecting proxies |
| `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` | agent | — | CA bundle for a corporate TLS proxy |
| `RAYON_NUM_THREADS` | ingester | CPU count | Limits the rayon thread pool |

## Security

API keys come from environment variables, never hardcoded. LLM-generated SQL runs on a READ_ONLY
connection behind the blocklist + EXPLAIN guards (`agent` and `config_viz`). The OpenAI call (SQL
prompt + results) is the only outbound traffic; all services are local-only by default.

## Documentation

**One owner per fact** — a count, path or command name lives in one place and everything else
links to it. The root suite asserts the ones that must appear in prose anyway, so run
`make test-repo` after touching docs. Ownership table and the `doc/` vs `website/docs/` rules:
[CLAUDE.md](CLAUDE.md).

---

## File Structure

```
senrigan/
├── .github/                   # AGENTS.md pointer, copilot-instructions.md, workflows
├── ingester/                  # Rust ingestion engine (see ingester/AGENTS.md)
│   └── src/                   # main.rs (CLI) · parser.rs · db.rs · ingest.rs · enrich.rs
│                              #   geoip.rs · field_filter.rs · date_filter.rs · path_filter.rs
│                              #   progress.rs · config_{parser,db,import}.rs · test_util.rs
├── agent/                     # Streamlit UI — 2 chat + 2 explorer pages (see agent/AGENTS.md)
│   ├── app.py                 # Entry point: st.navigation over the four pages
│   ├── handlers.py            # Stateful handler functions
│   ├── session.py             # Per-profile session state + built-in hunt loading
│   ├── llm.py                 # OpenAI calls: SQL generation, analysis, SQL fix
│   ├── query.py               # Execution, validation, date filter, row limit, retry
│   ├── report.py              # Chat-session Markdown / PDF report
│   ├── schema.py              # Columns the LLM sees (17 core + 7 GeoIP)
│   ├── profiles.py            # DatasetProfile: chat pages vs explorer pages
│   ├── suzaku_db.py           # Suzaku file detection, fitness and selection
│   ├── suzaku_queries.py      # QueryResult, bound-parameter helpers, timeline pivot SQL
│   ├── geo.py                 # Best-effort geo enrichment of IP result columns
│   ├── config.py              # Env-var configuration helpers
│   ├── views/                 # charts.py · db_selector.py · explorer.py · one file per Suzaku page
│   ├── prompts/               # system_prompt.py · suzaku_timeline_prompt.py · analysis_prompt.py
│   └── tests/                 # pytest suite
│                              # plus builtin_hunts.yaml, suzaku_timeline_hunts.yaml,
│                              #   suzaku_{summary,metrics}_queries.py (reviewed SQL)
├── config_viz/                # AWS Config resource graph
│   ├── backend/               # FastAPI, READ_ONLY DuckDB, SQL keyword blocklist
│   ├── frontend/              # React 18 + Vite + TS (reactflow + elkjs layout)
│   ├── static/                # Vite build output, served by FastAPI
│   └── tests/                 # Backend tests (BA-* series)
├── dashboard/                 # Apache Superset
│   ├── assets/                # cloudtrail_{default,rare} + suzaku_{timeline,summary,metrics}
│   │                          #   bundles, their ZIPs, and the rebuild scripts
│   ├── init/                  # bootstrap.sh, register_duckdb.py, register_suzaku_dbs.py
│   └── tests/                 # YAML/asset/config validation suite
├── doc/                       # ARCHITECTURE, DEVELOPMENT, TESTING, TDD_GUIDE, PRD,
│                              #   PRD_SUZAKU_SUMMARY, PRD_DASHBOARD_REVIEW (point-in-time)
├── docker/                    # docker-compose.yml (6 services + ingest/resync profiles)
├── sample/                    # sample/suzaku: trimmed fixtures + generate_fixtures.py
├── tests/                     # Repository-level consistency suite (Makefile / compose / docs)
├── website/                   # Material for MkDocs site, 15 locales
├── Makefile                   # The command surface
├── CLAUDE.md                  # Working rules for coding agents
├── README.md                  # Landing page → the documentation site
└── OLD-README.md              # Frozen pre-site single-page README
```
