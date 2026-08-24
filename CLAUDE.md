# CLAUDE.md

Senrigan — a locally-executed, AI-assisted threat hunting tool for AWS CloudTrail logs.

This file holds only what changes how you act. Reference material is linked, never copied:
[AGENTS.md](AGENTS.md) (schema, CLI, env vars, file map), [ingester/AGENTS.md](ingester/AGENTS.md),
[agent/AGENTS.md](agent/AGENTS.md), [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md),
[doc/DEVELOPMENT.md](doc/DEVELOPMENT.md), [doc/TESTING.md](doc/TESTING.md),
[doc/TDD_GUIDE.md](doc/TDD_GUIDE.md), [doc/PRD.md](doc/PRD.md).

---

## Architecture

Four containers share **one DuckDB file** (`docker/data/db/threat_hunting.db`) via a bind mount,
**1 writer / N readers**.

| Container | Language | DuckDB mode | Port |
|-----------|----------|-------------|------|
| `ingester` | Rust 1.85+ | READ_WRITE (sole writer) | — |
| `agent` | Python 3.14+ / Streamlit | READ_ONLY | 8501 |
| `dashboard` | Apache Superset | READ_ONLY | 8088 |
| `config_viz` | Python 3.14+ / FastAPI + React 18 (ELK) | READ_ONLY | 8502 |

- **`ingester` is the sole writer.** Readers pass `read_only=True`; it must finish before they
  start, and concurrent writers are unsupported.
- **Suzaku output is read as-is** — never imported, never opened writable. Detection, fitness and
  file selection live **only** in `agent/suzaku_db.py`, bind-mounted into `superset-init` /
  `superset-resync` for `dashboard/init/register_suzaku_dbs.py` (guarded by
  `tests/test_suzaku_detection_shared.py`). Fix selection bugs there, not in a second copy.
- **One file wins per Suzaku command** — `generated_at` → mtime → path, among files carrying every
  column in `REQUIRED_COLUMNS`, so both UIs agree. Hence the Metrics dashboard needs a Suzaku run
  with `--geo-ip`: without `SrcASN`/`SrcCity`/`SrcCountry` the file is rejected with a reason
  instead of failing at render time. `make status` prints winner and losers.
- **The bind mount is deliberate** — Docker on Linux/WSL2 misresolves relative paths for
  named-volume `driver_opts`, so each service declares its own `volumes:` entry.
- **`agent` is four pages** (`st.navigation`, one `DatasetProfile` each): two *chat* pages where
  the LLM writes SQL (🔭 Senrigan, 🕒 Suzaku Timeline) and two *explorer* pages
  (`chat_enabled=False`) running only reviewed SQL from `agent/suzaku_{summary,metrics}_queries.py`
  — an explorer profile raises if it reaches the chat pipeline.

## TDD (non-negotiable)

Red → Green → Refactor: write the test list, write ONE failing test, confirm it fails, write the
minimum code to pass, refactor green, repeat. **Never write production code without a failing test
first.** Exceptions: boilerplate (Dockerfile, compose, config), UI layout (test the logic behind
it), third-party wiring (mock + test the interface). Business logic and data transformations are
never exempt.

Tests live in `#[cfg(test)] mod tests` + `ingester/tests/` (Rust), `agent|config_viz|dashboard/tests/`
and root `tests/` (Python), `config_viz/frontend/src/__tests__/` (TypeScript).

## Conventions

- **English everywhere** — comments, docstrings, commits, PRs, `doc/`, `website/docs/`.
- **Commits:** Conventional Commits. **Branches:** `feature|fix/<module>-<short-desc>`.
- **Rust:** `cargo fmt`, `cargo clippy -- -D warnings` (zero warnings), `anyhow::Result` with
  `.with_context(...)`, DB writes **always** via `duckdb::Appender`, temp DBs in tests
  (keep the `NamedTempFile` handle alive).
- **Python:** `black` (88) + `ruff` (rule set pinned in root `ruff.toml` — a lint failure after a
  Ruff upgrade is fixed in the code or by a deliberate `select` change, never by suppression),
  type hints everywhere, Google docstrings. Patch OpenAI as
  `llm.OpenAI`, **not** `agent.llm.OpenAI` (`pytest.ini` sets `pythonpath = .`). Use the
  `tmp_duckdb` / `tmp_db_*` fixtures, never a shared file. **Real OpenAI calls in tests are
  forbidden.**

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
```

Not advertised: `make status` (state, DB size, which Suzaku file each dashboard uses),
`make resync` (stale dashboard: re-sync columns, re-resolve Suzaku paths), `make check`
(everything CI enforces). Per-module loops: `cargo test` / `cargo clippy -- -D warnings` /
`cargo fmt --check`; `pytest` / `ruff check .` / `black --check .`; `npm test -- --run` /
`npm run build`.

`make ingest` takes **no flags** — it reads the compose bind-mount directories
(`GEOIP_HOST_PATH` / `CONFIG_HOST_PATH` / `DUCKDB_HOST_PATH`) and enables the matching options
itself, echoing what it found and skipped: GeoLite2 `.mmdb` files add the `--geoip-*` flags (City
supersedes Country), a non-empty `docker/data/config-snapshots/` runs `config-import` as a second
pass. Overrides live under `##@ Advanced ingest` in `make help-all`; see
[doc/DEVELOPMENT.md](doc/DEVELOPMENT.md).

**Dashboard YAML is compiled, not read.** Superset applies only the ZIPs, imported by the one-shot
`superset-init` container, so editing YAML alone — or rebuilding the ZIP alone — changes nothing
in a running dashboard. Finish every edit under `dashboard/assets/<bundle>/` with both steps:

```bash
cd dashboard/assets && python3 rebuild_zip.py && python3 rebuild_rare_zip.py   # or rebuild_suzaku_<name>_zip.py
cd ../../docker && docker compose run --rm superset-init   # re-import (idempotent)
```

`cloudtrail_rare.zip` is derived from `cloudtrail_default/` (ascending/bottom-N ordering) and is a
**subset**: only charts declaring `params.order_desc` have an ordering to invert, so KPI cards,
time series, the world map and the heatmaps are not mirrored and a tab left with no chart is
dropped. `dashboard/tests/test_rebuild_suzaku_zips.py` fails on a stale committed Suzaku ZIP.

Suite sizes (must not decrease in a PR): ingester ≈ 187 (Rust), agent ≈ 2240 (pytest),
config_viz ≈ 67 backend + 114 frontend, dashboard ≈ 1368 (`make test-dashboard`), root `tests/` ≈ 238
(`make test-repo`). A PR that changes a count updates this line **and** [AGENTS.md](AGENTS.md)
together — stale counts cause false "regression" alarms later.

---

## Schema & SQL

`cloudtrail_events` has **48 columns** (17 core → 7 GeoIP → 24 extended; full inventory in
[AGENTS.md](AGENTS.md#duckdb-schema)). JSON blobs are `VARCHAR`, not DuckDB JSON — read them with
`json_extract_string(col, '$.field')`. GeoIP and extended columns arrive via `ALTER TABLE ADD
COLUMN IF NOT EXISTS`, so existing DBs migrate transparently. `ingested_files` drives SHA-256
dedup. The LLM sees only the columns in `agent/schema.py` (17 core + 6 extended + 7 GeoIP) —
anything absent
there never appears in generated SQL.

**Adding or exposing a column** touches: (1) the Rust schema + migration, (2) `agent/schema.py`
and the idioms in `agent/prompts/system_prompt.py`, (3) [AGENTS.md](AGENTS.md#duckdb-schema),
(4) `dashboard/assets/cloudtrail_default/datasets/` YAML → rebuild ZIPs → re-import → `make resync`.

Three guards run before any LLM-generated SQL executes (`agent/query.py`,
`config_viz/backend/query.py`): a **keyword blocklist** (`INSERT`, `UPDATE`, `DELETE`, `DROP`,
`ALTER`, `CREATE`), **EXPLAIN validation** on the READ_ONLY connection, and a **row-limit cap**
wrapping un-`LIMIT`ed queries. On failure `execute_with_retry` calls `fix_sql_with_llm` once.
Date filters inject a `_ct_filtered` CTE; hunts in `agent/builtin_hunts.yaml` with an `sql` field
run without an API key; IP columns in results are geo-enriched best-effort (`agent/geo.py`).

## OpenAI models

Defaults `gpt-5.5` / `gpt-5.4-mini` (`OPENAI_MODEL` / `OPENAI_MODEL_LITE` in
`docker/docker-compose.yml`); the sidebar offers `gpt-5.5`, `gpt-5.4`, `gpt-5.4-mini`. When the
lineup changes, move all of these together or the UI will offer a model the API rejects:
`MODEL_OPTIONS` in `agent/app.py` and the default in `agent/session.py`; `_NO_TEMPERATURE_MODELS`
in `agent/llm.py` (models that reject an explicit temperature, `gpt-5.5` among them); the compose
defaults; the tables in [AGENTS.md](AGENTS.md#environment-variables) and
[agent/AGENTS.md](agent/AGENTS.md). Everything else about the API surface is a code detail — read
`agent/llm.py`.

---

## Documentation

**One owner per fact.** A number, path or command name lives in one place; every other mention
links to it. Repetition is how these docs decayed before. Where a fact must appear in prose
anyway, the root suite asserts it against the artifact that produces it — run `make test-repo`
after touching docs and it names the stale sentence.

| Fact | Owned by | Asserted by |
|------|----------|-------------|
| Hunt counts and names | `agent/*_hunts.yaml` | `tests/test_doc_counts.py` |
| Chart counts and names | `dashboard/assets/<bundle>/charts/` | `tests/test_doc_counts.py` |
| Suite sizes | the suites | `tests/test_doc_counts.py` (cross-file agreement) |
| The five front-page commands | `Makefile` | `tests/test_doc_structure.py` |
| Repository layout | the working tree | `tests/test_doc_structure.py` |
| Locale coverage | `website/mkdocs.yml` | `tests/test_docs.py` |

`doc/` is internal, `website/docs/` is the product — a user-facing change needs the site page in
all 15 locales, since a missing locale silently serves English. `PRD_*` are point-in-time records:
update their `Status:` line, never rewrite them. `OLD-README.md` is frozen.

## Security

API keys come from env vars / git-ignored `.env`, never hardcoded. SQL safety = READ_ONLY +
blocklist + EXPLAIN. The OpenAI call (prompt + results) is the only outbound traffic; DuckDB data
never leaves the machine. All services are local-only by default.

## Repository Map

```
senrigan/
├── ingester/    # Rust ingestion engine (ingest / enrich / config-import)
├── agent/       # Streamlit UI — 2 AI chat pages + 2 Suzaku explorer pages
├── config_viz/  # AWS Config resource graph — FastAPI + React 18/Vite/TS (ELK)
├── dashboard/   # Superset config, asset bundles, asset-validation tests
├── sample/      # Trimmed Suzaku fixtures (full runs are git-ignored)
├── docker/      # docker-compose.yml (6 services + ingest/resync profiles)
├── tests/       # Repository-level consistency suite (Makefile / compose / docs)
├── website/     # Material for MkDocs site — docs/ in 15 locales
└── doc/         # ARCHITECTURE, DEVELOPMENT, TESTING, TDD_GUIDE, PRD*
```

File-level breakdown: [AGENTS.md](AGENTS.md#file-structure).
