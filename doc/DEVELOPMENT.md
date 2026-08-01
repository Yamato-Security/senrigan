# Development Guide

## Language Policy

All contributions to this project MUST use English for:

- Source code comments (`//`, `///`, `//!` in Rust; `#` and docstrings in Python)
- Documentation files (`.md`, `.txt`, `.rst`)
- Commit messages and PR descriptions

Non-English text anywhere in the codebase or version history is not permitted.

## Prerequisites

| Tool              | Version      | Purpose                              |
| ----------------- | ------------ | ------------------------------------ |
| Rust              | 1.85+        | ingester development                 |
| Python            | 3.14+        | agent development                    |
| Docker Desktop    | Latest       | Container orchestration              |
| Docker Compose    | v2           | Multi-service management             |
| DuckDB CLI        | 1.2+         | (Optional) Ad-hoc database inspection|
| Git               | 2.40+        | Version control                      |

## Initial Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan
```

### 2. Configure Environment

Compose reads `docker/.env`. `make up` creates it and generates
`SUPERSET_SECRET_KEY` on first run, so the only thing you normally add by hand is the
OpenAI key:

```bash
cat >> docker/.env <<'EOF'
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-5.5              # optional; this is the default
OPENAI_MODEL_LITE=gpt-5.4-mini    # optional
EOF
```

Set `SUPERSET_SECRET_KEY` yourself only when invoking `docker compose` directly — Superset
refuses to start without one, and `make up` is what normally supplies it.

### 3. ingester (Rust) Setup

```bash
cd ingester

# Install Rust toolchain (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify
rustc --version    # 1.85+
cargo --version

# Build
cargo build

# Run tests
cargo test

# Lint
cargo clippy -- -D warnings

# Format check
cargo fmt --check
```

### 4. agent (Python) Setup

```bash
cd agent

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest

# Lint
ruff check .

# Format check
black --check .
```

### 5. config_viz (Python + Node) Setup

```bash
# Backend (FastAPI)
cd config_viz
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt -r requirements-dev.txt

# Run backend tests
pytest

# Frontend (React + Vite)
cd config_viz/frontend
npm install

# Run frontend tests
npm test

# Production build → config_viz/static/
npm run build
```

### 6. Corporate Proxy / Custom CA Certificate

If you are behind a **TLS-inspecting corporate proxy**, all container builds will fail when
trying to pull packages from the internet (Cargo crates, npm packages, pip wheels, etc.).

You only need to edit **one file** — no Dockerfile changes are required.

**Step 1.** Base64-encode your corporate CA certificate (PEM format, single line, no line wrapping):

```bash
# macOS
export CUSTOM_CA_CERT_BASE64=$(base64 -i /path/to/custom-ca.crt)

# Linux
export CUSTOM_CA_CERT_BASE64=$(base64 -w0 /path/to/custom-ca.crt)
```

**Step 2.** Add it to `docker/.env`:

```bash
echo "CUSTOM_CA_CERT_BASE64=${CUSTOM_CA_CERT_BASE64}" >> docker/.env
```

**Step 3.** Build as usual:

```bash
cd docker
docker compose build
```

That's it. Docker Compose passes `CUSTOM_CA_CERT_BASE64` as a build argument to every
service. Each Dockerfile installs the certificate inside the container at build time and
configures the relevant tool (`cargo`, `pip`, `npm`, `requests`) to trust it automatically.

| Tool | Environment variable set automatically |
|------|----------------------------------------|
| OpenSSL / system | `SSL_CERT_FILE` |
| Python `requests` | `REQUESTS_CA_BUNDLE` |
| `pip` | `PIP_CERT` |
| Rust `cargo` | `CARGO_HTTP_CAINFO` |
| Node.js | `NODE_EXTRA_CA_CERTS` |

> **Note:** When `CUSTOM_CA_CERT_BASE64` is empty (the default), the conditional `RUN` block
> in each Dockerfile is skipped entirely — there is no impact on non-proxy builds.

### 7. Docker Compose (Full Stack)

```bash
cd docker

# Build all services
docker compose build

# Start agent + config-viz + dashboard
docker compose up -d

# Run ingester to load CloudTrail logs
docker compose --profile ingest run --rm ingester ingest --path /data/logs

# (Optional) Import AWS Config snapshots
docker compose --profile ingest run --rm ingester config-import --path /data/config

# View logs
docker compose logs -f agent
docker compose logs -f config-viz
docker compose logs -f superset

# Stop
docker compose down
```

## Development Workflow

### TDD Cycle (Every Feature)

This project follows **TDD**. Every code change must follow the Red-Green-Refactor cycle.

```
1. Write test list        → Enumerate expected behaviors
2. Pick simplest test     → Write a failing test
3. Red                    → Run test, confirm FAIL
4. Green                  → Write minimum code to pass
5. Refactor               → Clean up, keep tests green
6. Repeat                 → Next test from the list
```

See [TDD_GUIDE.md](TDD_GUIDE.md) for detailed methodology and examples.

### The whole loop in one command

Everything CI enforces runs from the repository root, with no per-module virtualenv to
activate first:

```bash
make check              # lint + format + every suite — what CI runs
make test               # every suite, no lint
make lint               # ruff + clippy
make fmt-check          # black + rustfmt

make test-ingester      # one suite at a time
make test-agent
make test-config-viz
make test-frontend
make test-dashboard
make test-repo
```

Reach for the per-module commands below when you are iterating inside one module and want
a watch mode or a single test; reach for `make check` before you open a PR.

### Module-Specific Development

#### ingester (Rust)

```bash
cd ingester

# TDD loop
cargo test                        # Run all tests
cargo test test_name              # Run a specific test
cargo test -- --nocapture         # See println! output
cargo test -- --test-threads=1    # Run tests sequentially

# Watch mode (requires cargo-watch)
cargo install cargo-watch
cargo watch -x test               # Auto-run tests on file change
```

#### agent (Python)

```bash
cd agent
source .venv/bin/activate

# TDD loop
pytest                            # Run all tests
pytest tests/test_query.py        # Run a specific test file
pytest -k "test_connect"          # Run tests matching a pattern
pytest -v                         # Verbose output
pytest --tb=short                 # Short traceback

# Watch mode (requires pytest-watch)
pip install pytest-watch
ptw                               # Auto-run tests on file change
```

#### config_viz backend (Python)

```bash
cd config_viz
source .venv/bin/activate

pytest                            # Run all backend tests (~67)
pytest -v --tb=short
ruff check .
black --check .
```

#### config_viz frontend (TypeScript)

```bash
cd config_viz/frontend

npm test                          # Run all Vitest tests (~114)
npm test -- --run                 # Single-pass (no watch)
npm run build                     # Production build → ../static/
```

#### dashboard (Superset assets)

The asset-validation suite (~793 tests) executes every dataset and chart expression
against the committed Suzaku fixtures, so it catches a broken SQL expression without a
running Superset.

```bash
cd dashboard
pytest                            # Asset / YAML / config validation
```

Superset itself never reads the YAML — it imports the compiled ZIPs. After editing
anything under `assets/<bundle>/`, rebuild and re-import, or the running dashboard keeps
the old definition:

```bash
cd dashboard/assets
python3 rebuild_zip.py && python3 rebuild_rare_zip.py       # CloudTrail bundles
python3 rebuild_suzaku_timeline_zip.py                      # or the matching Suzaku one
cd ../../docker && docker compose run --rm superset-init    # idempotent re-import
```

`dashboard/tests/test_rebuild_suzaku_zips.py` fails when a committed ZIP is stale, so an
unrebuilt edit cannot reach main.

#### Repository consistency (root `tests/`)

```bash
pytest                            # From the repository root (~134 tests)
```

This suite owns the claims no module can check alone: that the `Makefile`,
`docker/docker-compose.yml` and the documentation agree with each other — command names,
mount paths, chart and hunt counts, and the 15 localized site pages. See
[AGENTS.md](../AGENTS.md#documentation).

#### Working with Suzaku output

Suzaku's `*.duckdb` files are third-party input: copy them into the mounted database
directory (`docker/data/db/` by default) and restart. Nothing imports them and nothing
writes to them.

Tests never need a real Suzaku run — `sample/suzaku/` ships trimmed fixtures, regenerated
by `sample/suzaku/generate_fixtures.py`. Full Suzaku runs dropped in that directory are
git-ignored. `SUZAKU_{TIMELINE,SUMMARY,METRICS}_DB` pin a specific file when you want to
bypass discovery.

## Directory Convention

The full file-level breakdown lives in [AGENTS.md](../AGENTS.md#file-structure) and is kept
there so it has one owner. What matters while developing is where each kind of thing goes:

| You are adding | It belongs in | Its test goes in |
|----------------|---------------|------------------|
| Rust ingestion logic | `ingester/src/` | the same file (`#[cfg(test)] mod tests`), or `ingester/tests/` for CLI-level behaviour |
| Agent pipeline or UI logic | `agent/` (`views/` for a page) | `agent/tests/test_<module>.py` |
| A built-in hunt | `agent/builtin_hunts.yaml` or `agent/suzaku_timeline_hunts.yaml` | `agent/tests/test_builtin_hunts_*.py` |
| A chart or dashboard | `dashboard/assets/<bundle>/` | `dashboard/tests/` — and rebuild the ZIP |
| A backend endpoint or query | `config_viz/backend/` | `config_viz/tests/` |
| A frontend component | `config_viz/frontend/src/` | `config_viz/frontend/src/__tests__/` |
| A Makefile target or compose service | `Makefile`, `docker/docker-compose.yml` | root `tests/` |
| User-facing documentation | `website/docs/` — all 15 locales | root `tests/` |

## CI Pipeline

`.github/workflows/ci.yml` runs five independent jobs on every push and pull request, plus
a nightly schedule. They do not depend on each other, so a Rust failure does not hide a
frontend failure.

| Job | Working directory | What it runs |
| --- | ----------------- | ------------ |
| `ingester (Rust)` | `ingester/` | `cargo fmt --all -- --check` · `cargo clippy --all-targets --all-features -- -D warnings` · `cargo test --all` |
| `agent (Python)` | `agent/` | `black --check .` · `ruff check .` · `pytest` |
| `dashboard YAML validation` | `dashboard/` | every asset YAML parsed · required ZIP entries present · `black --check .` · `ruff check .` · `pytest` |
| `repo consistency (Makefile / docs)` | repository root | `pytest` — the root suite |
| `frontend (Node / Vite)` | `config_viz/frontend/` | `npm ci` · `npm audit --audit-level=high` · `npm run lint` · `npm test` · `npm run build` · CycloneDX SBOM |

`make check` runs the same checks locally, with one difference worth knowing: it also runs
the **config_viz backend** suite (`config_viz/tests/`, ~67 tests), which no CI job currently
executes. Run `make check` before opening a PR rather than relying on CI alone.

No job builds Docker images; image builds are exercised by `release.yml`, and the docs site
by `docs.yml`.

## Useful Commands

```bash
# Inspect DuckDB directly (requires DuckDB CLI)
duckdb docker/data/db/threat_hunting.db "SELECT COUNT(*) FROM cloudtrail_events"

# View table schema
duckdb docker/data/db/threat_hunting.db ".schema cloudtrail_events"

# Quick data check
duckdb docker/data/db/threat_hunting.db "SELECT * FROM cloudtrail_events LIMIT 5"

# What ingest would detect, which Suzaku file each dashboard picked, database size
make status

# Inspect a Suzaku file the same way the services see it (read-only)
duckdb -readonly docker/data/db/<suzaku>.duckdb "SELECT * FROM suzaku_meta"
```

> The shared database is a **bind mount**, not a named volume — `docker volume inspect`
> will not find it. Look at `docker/data/db/` on the host, or wherever
> `DUCKDB_HOST_PATH` points.
