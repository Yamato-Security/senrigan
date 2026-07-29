# CLAUDE.md

Guidance for Claude Code when working in the **Senrigan** repository.

> Senrigan is a locally-executed, AI-assisted threat hunting tool for AWS CloudTrail logs.
> Source of truth for agent context is [AGENTS.md](AGENTS.md); module-level detail lives in
> [ingester/AGENTS.md](ingester/AGENTS.md) and [agent/AGENTS.md](agent/AGENTS.md).
> Background docs are under [doc/](doc/) — see [ARCHITECTURE.md](doc/ARCHITECTURE.md),
> [DEVELOPMENT.md](doc/DEVELOPMENT.md), [TESTING.md](doc/TESTING.md),
> [TDD_GUIDE.md](doc/TDD_GUIDE.md), [PRD.md](doc/PRD.md),
> [PRD_SUZAKU_SUMMARY.md](doc/PRD_SUZAKU_SUMMARY.md),
> [PRD_DASHBOARD_REVIEW.md](doc/PRD_DASHBOARD_REVIEW.md),
> [PLAN_SUGIYAMA.md](doc/PLAN_SUGIYAMA.md), [PLAN_GEO_ENRICHMENT.md](doc/PLAN_GEO_ENRICHMENT.md),
> [PLAN_THREAT_CATALOG.md](doc/PLAN_THREAT_CATALOG.md),
> [PLAN_MAKEFILE_UX.md](doc/PLAN_MAKEFILE_UX.md),
> [PLAN_SUZAKU_VIEWS.md](doc/PLAN_SUZAKU_VIEWS.md),
> [PLAN_SUZAKU_SCHEMA.md](doc/PLAN_SUZAKU_SCHEMA.md),
> and [PLAN_SUZAKU_TIMELINE_DASHBOARD.md](doc/PLAN_SUZAKU_TIMELINE_DASHBOARD.md).

---

## Architecture at a Glance

Four Docker containers share **one DuckDB file** via a bind mount
(`docker/data/db/threat_hunting.db`) using a **1-writer / N-readers** model.

| Container    | Language                                | DuckDB mode               | Port |
|--------------|-----------------------------------------|---------------------------|------|
| `ingester`   | Rust 1.85+                              | READ_WRITE (sole writer)  | —    |
| `agent`      | Python 3.14+ / Streamlit                | READ_ONLY                 | 8501 |
| `dashboard`  | Apache Superset                         | READ_ONLY                 | 8088 |
| `config_viz` | Python 3.14+ / FastAPI + React 18 (ELK) | READ_ONLY                 | 8502 |

- `agent` is a two-page Streamlit app (`st.navigation`): **🔭 Senrigan** (chat hunting over
  `cloudtrail_events`) and **🕒 Suzaku Timeline** (chat hunting over Suzaku's `timeline` table).
  Both pages share one pipeline, parameterized by a `DatasetProfile` (`agent/profiles.py`);
  see [doc/PLAN_SUZAKU_VIEWS.md](doc/PLAN_SUZAKU_VIEWS.md) §4.
- **Suzaku output** (`*.duckdb` from `aws-ct-timeline` / `aws-ct-summary` / `aws-ct-metrics`) is read
  as-is from the same mounted directory — never imported, never written. The producing command is
  read from the file's own `suzaku_meta` table, in `agent/suzaku_db.py` and again in
  `dashboard/init/register_suzaku_dbs.py` (the Superset image cannot import the agent package;
  `tests/test_suzaku_detection_parity.py` keeps the two copies identical). Both refuse a
  `schema_version` newer than they were written against.
  `aws-ct-summary` / `aws-ct-metrics` are dashboard-only by design — Suzaku already aggregated them.
  The **Suzaku Metrics** dashboard requires a run with `--geo-ip`: Suzaku writes
  `SrcASN`/`SrcCity`/`SrcCountry` only for an enriched run, and the dataset selects them.
- `config_viz`'s frontend uses **`elkjs`** (ELK layered / Sugiyama algorithm) for graph layout —
  migrated from `@dagrejs/dagre`; see [doc/PLAN_SUGIYAMA.md](doc/PLAN_SUGIYAMA.md).
- `ingester` must finish before the read-only services start. Concurrent writes are **not** supported.
- The bind mount (not a named volume) is intentional — Docker on Linux/WSL2 misresolves relative
  paths for named-volume `driver_opts`, so each service declares its own `volumes:` entry in
  `docker/docker-compose.yml`.
- SSD/NVMe storage is strongly recommended for the DuckDB file.

---

## Development Methodology: TDD (Non-Negotiable)

This project strictly follows **Test-Driven Development** (Red → Green → Refactor).

1. Write a **test list** before coding any feature.
2. Write ONE failing test (Red) — confirm it fails first.
3. Write the **minimum** code to make it pass (Green).
4. Refactor while keeping all tests green.
5. Repeat for the next list item.

**Never write production code without a corresponding failing test first.** When in doubt, ask
"What is the test list for this feature?" See [doc/TDD_GUIDE.md](doc/TDD_GUIDE.md).

Test homes:
- **Rust:** `#[test]` in `#[cfg(test)] mod tests` in the same source file; integration tests in `ingester/tests/`.
- **Python:** `def test_*` in `agent/tests/` or `config_viz/tests/`.
- **TypeScript:** `*.test.tsx` / `*.test.ts` in `config_viz/frontend/src/__tests__/`.

Strict-TDD exceptions: boilerplate (Dockerfiles, compose, config), UI layout (test the logic
behind it), and third-party wiring (mock + test the interface). Always TDD business logic and data
transformations.

---

## Coding Conventions

### All modules
- **Language:** every comment, doc comment, docstring, commit message, and PR description MUST be
  in **English**. No exceptions, anywhere in the codebase or git history.
- **Commits:** Conventional Commits — `feat:`, `fix:`, `test:`, `refactor:`, `docs:`, `chore:`.
- **Branches:** `feature/<module>-<short-desc>` / `fix/<module>-<short-desc>`.

### Rust (`ingester/`)
- Format with `cargo fmt`; lint with `cargo clippy -- -D warnings` (zero warnings).
- Errors: `anyhow::Result` everywhere; add context with `.with_context(|| format!("..."))`.
- DB writes: **always** use `duckdb::Appender`, never individual `INSERT` statements.
- Tests use temporary DBs (`tempfile::NamedTempFile`); keep the temp handle alive.

### Python (`agent/`, `config_viz/backend/`)
- Format with `black` (line length 88); lint with `ruff`.
- Type hints required on all signatures; Google-style docstrings.
- Imports: stdlib → third-party → local (enforced by `ruff`).
- **OpenAI mocks:** patch `llm.OpenAI`, **not** `agent.llm.OpenAI` (`pytest.ini` sets `pythonpath = .`).
- DuckDB in tests: use temp DBs via the `tmp_duckdb` / `tmp_db_*` fixtures — never a shared file.
- **Real OpenAI API calls in tests are forbidden** — always mock `llm.OpenAI`.

---

## Essential Commands

From the repository root. `make` with no arguments prints the five commands below;
`make help-all` lists every target grouped by section.

```bash
make ingest    # Load CloudTrail logs from docker/logs/ into DuckDB
make up        # Start agent + dashboard + config_viz
make down      # Stop everything
make logs      # Tail service logs (SERVICE=agent|superset|config-viz for one)
make reset     # Stop, delete the DuckDB file, and start over (FORCE=1 to skip the prompt)
make status    # Container state, database size, and what ingest would detect
make resync    # Fix a blank dashboard after re-ingest (re-syncs column metadata)
```

`make ingest` takes **no flags**. It reads the compose bind-mount directories and enables
the matching ingester options itself, echoing what it found and what it skipped:

| Directory | Effect on `make ingest` |
|-----------|-------------------------|
| `docker/data/geoip/GeoLite2-{City,Country,ASN}.mmdb` | adds the matching `--geoip-*` flags (City supersedes Country) |
| `docker/data/config-snapshots/` non-empty | runs `config-import` as a second pass |

Explicit overrides live under `##@ Advanced ingest` in `make help-all`
(`ingest-full`, `ingest-geoip`, `ingest-config`, `enrich`). Detection paths follow
`GEOIP_HOST_PATH` / `CONFIG_HOST_PATH` / `DUCKDB_HOST_PATH`, matching
`docker/docker-compose.yml`. See [doc/PLAN_MAKEFILE_UX.md](doc/PLAN_MAKEFILE_UX.md).

**After editing any file under `dashboard/assets/cloudtrail_default/`** (chart/dashboard YAML):
Superset never reads those YAML files directly — it only applies them from the compiled
`cloudtrail_default.zip` and `cloudtrail_rare.zip` (the "Rare Events" dashboard, derived
from `cloudtrail_default/` by `rebuild_rare_zip.py` with ascending/bottom-N ordering),
which are imported into Superset's own metadata DB by the one-shot `superset-init`
container. Editing the YAML alone (or even rebuilding the zips alone) has no effect on the
running dashboards. Always finish with all steps:

```bash
cd dashboard/assets && python3 rebuild_zip.py && python3 rebuild_rare_zip.py   # regenerate both zips
cd ../../docker && docker compose run --rm superset-init   # re-import into Superset (idempotent)
```

The same rule applies to the three Suzaku bundles (`suzaku_timeline/`,
`suzaku_summary/`, `suzaku_metrics/`) — rebuild with
`python3 rebuild_suzaku_<name>_zip.py`. `dashboard/tests/test_rebuild_suzaku_zips.py`
fails when a committed Suzaku ZIP is stale, so an unrebuilt edit cannot pass CI.

Per-module dev loops (`make check` runs everything CI enforces in one go):

```bash
# Rust (ingester/)
cargo test                    # unit + integration + CLI tests
cargo clippy -- -D warnings   # lint
cargo fmt --check             # format check

# Python (agent/, config_viz/, dashboard/)
pytest                        # all tests
ruff check .                  # lint
black --check .               # format check

# TypeScript (config_viz/frontend/)
npm test -- --run             # single-pass test
npm run build                 # Vite production build → ../static/
```

Approximate test totals (must not decrease in a PR): ingester ≈ 185 (Rust), agent ≈ 730 (pytest),
config_viz ≈ 67 backend + 114 frontend, dashboard ≈ 757 (asset/YAML/config validation suite —
run with `make test-dashboard`), root `tests/` ≈ 115 (Makefile / compose / docs consistency —
run with `make test-repo`).
When your PR changes a count, update this line and [AGENTS.md](AGENTS.md) in the same PR —
stale counts here cause false "regression" alarms in later sessions.

Every PR must pass: all tests green, no lint warnings, format compliance, and no test-count regression.

---

## DuckDB Schema & Access Rules

`cloudtrail_events` has **48 columns** (17 core → 7 GeoIP → 24 extended). JSON blobs are stored as
**`VARCHAR`**, not DuckDB JSON type — query them with `json_extract_string(col, '$.field')`.
GeoIP and extended columns are added via `ALTER TABLE ADD COLUMN IF NOT EXISTS`, so existing DBs
migrate transparently. `ingested_files` (`file_path` PK, `sha256`, `ingested_at`) drives SHA-256
dedup. Full schema: [AGENTS.md](AGENTS.md#duckdb-schema).

The LLM only "sees" the columns listed in `agent/schema.py` (currently the 17 core + 7 GeoIP
columns — the 24 extended columns are deliberately excluded to keep the prompt small). A column
that exists in DuckDB but not in `agent/schema.py` will never be used by AI-generated SQL.

**Schema-change checklist** — when adding or newly exposing a column, update every one of:
1. `ingester/` Rust schema + migration (`ALTER TABLE ADD COLUMN IF NOT EXISTS`),
2. `agent/schema.py` (if the LLM should use it) and the idioms in `agent/prompts/system_prompt.py`,
3. the schema section in [AGENTS.md](AGENTS.md#duckdb-schema),
4. `dashboard/assets/cloudtrail_default/datasets/` YAML, then rebuild both zips + re-import
   (see the dashboard-assets steps above) and run the `superset-resync` profile.

Access rules:
1. `ingester` is the **sole writer** — never open `READ_WRITE` from `agent`/`dashboard`/`config_viz`.
2. Readers always use `read_only=True`.
3. Tests must use temporary databases (`tempfile` in Rust, `tmp_path` in pytest).

---

## SQL Safety (`agent/` and `config_viz/backend/`)

Before executing any LLM-generated SQL, three guards run in order:
1. **Keyword blocklist** — rejects `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`
   (word-boundary, case-insensitive regex).
2. **EXPLAIN validation** — runs `EXPLAIN <sql>` on the READ_ONLY connection.
3. **Row-limit cap** — wraps un-`LIMIT`ed queries in `SELECT * FROM (...) AS _limited LIMIT N`.

On failure, `agent`'s `execute_with_retry` calls `fix_sql_with_llm` once for automatic correction.
Date-range UI filters inject a `_ct_filtered` CTE (see `apply_date_filter()` in `agent/query.py`).
`agent/builtin_hunts.yaml` ships pre-built hunts; entries with an `sql` field run without an API key.
Query results containing IP columns are automatically geo-enriched (`agent/geo.py`; sidebar toggle,
best-effort — see [doc/PLAN_GEO_ENRICHMENT.md](doc/PLAN_GEO_ENRICHMENT.md)).

---

## Ingester CLI Reference

```
ingester ingest --path <dir>
                [--db <path>] [--from <YYYYMMDD>] [--to <YYYYMMDD>]
                [--include <globs>] [--exclude <globs>]   # comma-separated; * crosses /
                [--workers <N>] [--no-progress]
                [--geoip-city <path>] [--geoip-country <path>] [--geoip-asn <path>]
                [--strip-fields]      # drop low-signal keys from request/responseParameters
                [--strip-raw-event]   # write NULL for raw_event (saves storage)

ingester enrich [--db <path>] [--geoip-city/--geoip-country/--geoip-asn <path>]
ingester config-import --path <dir> [--db <path>]
```

DB path resolution: `--db` → `DUCKDB_PATH` env → `/data/db/threat_hunting.db`.

---

## Key Environment Variables

| Variable | Used by | Default | Notes |
|----------|---------|---------|-------|
| `OPENAI_API_KEY` | agent | — | Required for AI features |
| `OPENAI_MODEL` | agent | `gpt-5.5` | SQL generation + analysis model |
| `OPENAI_MODEL_LITE` | agent | `gpt-5.4-mini` | Optional lighter model |
| `DUCKDB_PATH` | all | — | Overrides default DB path |
| `DUCKDB_HOST_PATH` | docker host | `./data/db` | Host-side bind-mount dir |
| `GEOIP_CITY/COUNTRY/ASN_PATH` | ingester | — | GeoLite2 mmdb paths |
| `SUZAKU_{TIMELINE,SUMMARY,METRICS}_DB` | agent, dashboard | — | Pin one Suzaku `.duckdb` instead of discovery |
| `SUPERSET_SECRET_KEY` | dashboard | auto-generated | `make up` writes a per-install key to `docker/.env`; Superset refuses to start without one |
| `CUSTOM_CA_CERT_BASE64` | docker build | empty | Base64 CA for TLS-inspecting proxies (see DEVELOPMENT.md §6) |

---

## Security Rules

1. **API keys:** never hardcode — always read from environment variables / `.env` (git-ignored).
2. **SQL safety:** READ_ONLY connection + keyword blocklist + EXPLAIN validation (agent & config_viz).
3. **No external data upload:** the only external call is the OpenAI API (SQL prompt + results).
   DuckDB data never leaves the local machine.
4. **Network:** all services are local-only by default.

---

## Repository Map

```
senrigan/
├── ingester/    # Rust log ingestion engine (ingest/enrich/config-import subcommands)
├── agent/       # Python/Streamlit AI threat-hunting UI — CloudTrail + Suzaku timeline pages
│               #   (llm.py, query.py, report.py, profiles.py, suzaku_db.py,
│               #    builtin_hunts.yaml, suzaku_timeline_hunts.yaml, views/)
├── config_viz/  # AWS Config resource graph — FastAPI backend + React 18/Vite/TS frontend (ELK layout)
├── dashboard/   # Apache Superset config + pre-built dashboard assets + asset-validation tests/
│               #   (cloudtrail_default, cloudtrail_rare, suzaku_{timeline,summary,metrics})
├── sample/      # Trimmed Suzaku DuckDB fixtures + generate_fixtures.py (full runs are git-ignored)
├── docker/      # docker-compose.yml (5 services + ingest/resync profiles)
└── doc/         # ARCHITECTURE, DEVELOPMENT, TESTING, TDD_GUIDE, PRD,
                 #   PRD_SUZAKU_SUMMARY, PRD_DASHBOARD_REVIEW, PLAN_SUGIYAMA, PLAN_GEO_ENRICHMENT,
                 #   PLAN_THREAT_CATALOG, PLAN_MAKEFILE_UX, PLAN_SUZAKU_VIEWS,
                 #   PLAN_SUZAKU_SCHEMA, PLAN_SUZAKU_TIMELINE_DASHBOARD
```

See [AGENTS.md](AGENTS.md#file-structure) for the full file-level breakdown.
