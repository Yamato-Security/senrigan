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

```bash
cp .env.example .env
# Edit .env and set:
#   OPENAI_API_KEY=sk-...
#   OPENAI_MODEL=gpt-5.4         (optional, default)
#   SUPERSET_SECRET_KEY=...       (optional for dev)
```

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

## Directory Convention

```
senrigan/
├── .github/
│   └── AGENTS.md              # Copilot Agents root instructions
├── ingester/
│   ├── AGENTS.md              # Module-specific Copilot instructions
│   ├── Cargo.toml             # Rust dependencies
│   └── src/                   # Source code
│       ├── main.rs            # CLI entry point
│       ├── lib.rs             # Library root
│       ├── parser.rs          # CloudTrail JSON parsing
│       ├── db.rs              # DuckDB operations
│       ├── ingest.rs          # Orchestration
│       ├── config_parser.rs   # AWS Config snapshot parsing
│       ├── config_db.rs       # Config table schema + inserts
│       ├── config_import.rs   # Config import pipeline
│       └── progress.rs        # Progress display
├── agent/
│   ├── AGENTS.md              # Module-specific Copilot instructions
│   ├── app.py                 # Streamlit entry point
│   ├── handlers.py            # Stateful handler functions
│   ├── llm.py                 # OpenAI integration
│   ├── query.py               # DuckDB query execution
│   ├── report.py              # Report generation
│   ├── schema.py              # CloudTrail schema description
│   ├── config.py              # Configuration (env vars)
│   ├── builtin_hunts.yaml     # Pre-built hunt queries
│   ├── prompts/               # Prompt templates (system_prompt.py, analysis_prompt.py)
│   ├── suzaku_summary.py      # Suzaku aws-ct-summary parsing/aggregation (pure functions)
│   ├── suzaku_report.py       # Suzaku summary Markdown/HTML report (pure functions)
│   ├── views/                 # st.navigation pages (suzaku_ct_summary.py)
│   ├── requirements.txt       # Python dependencies
│   ├── requirements-dev.txt   # Dev dependencies
│   └── tests/                 # pytest tests (~351 tests)
├── config_viz/
│   ├── PLAN.md                # Phase A/B/C implementation plan
│   ├── README.md              # Module documentation
│   ├── Dockerfile             # Multi-stage: Node build → Python runtime
│   ├── backend/               # FastAPI backend
│   │   ├── main.py            # FastAPI app + 4 REST endpoints
│   │   ├── db.py              # DuckDB READ_ONLY connection
│   │   ├── query.py           # SQL queries + blocklist
│   │   ├── requirements.txt
│   │   └── scripts/
│   │       └── extract_icons.py  # AWS icon download (build time)
│   ├── frontend/              # React 18 + Vite SPA (reactflow + elkjs)
│   │   ├── package.json
│   │   ├── vite.config.ts     # outDir: ../static
│   │   └── src/               # Components, utils (ELK layout), tests, MSW mocks
│   ├── static/                # Vite build output + icons/
│   └── tests/                 # pytest backend tests (~67 tests)
├── dashboard/                 # Superset config + pre-built dashboard assets
│   └── assets/                # Dashboard definitions and ZIP exports
├── docker/
│   └── docker-compose.yml     # Orchestration (5 services + profiles)
└── doc/                       # Documentation
```

## CI Pipeline (Expected)

The CI pipeline should enforce the following stages:

```
┌──────────┐    ┌──────────┐    ┌──────────┐
│  Lint    │───▶│  Test    │───▶│  Build   │
│          │    │          │    │          │
│ clippy   │    │ cargo    │    │ docker   │
│ rustfmt  │    │   test   │    │ compose  │
│ ruff     │    │ pytest   │    │   build  │
│ black    │    │ npm test │    │          │
└──────────┘    └──────────┘    └──────────┘
```

### Stage Details

| Stage  | ingester (Rust)                   | agent (Python)              | config_viz (Python + TS)         |
| ------ | --------------------------------- | --------------------------- | -------------------------------- |
| Lint   | `cargo clippy -- -D warnings`     | `ruff check .`              | `ruff check .` / (ESLint)        |
| Format | `cargo fmt --check`               | `black --check .`           | `black --check .`                |
| Test   | `cargo test`                      | `pytest`                    | `pytest` + `npm test`            |
| Build  | `cargo build --release`           | N/A (interpreted)           | `npm run build`                  |
| Docker | `docker build -t ingester .`      | `docker build -t agent .`   | `docker build -t config-viz .`   |

## Useful Commands

```bash
# Inspect DuckDB directly (requires DuckDB CLI)
duckdb data/db/threat_hunting.db "SELECT COUNT(*) FROM cloudtrail_events"

# View table schema
duckdb data/db/threat_hunting.db ".schema cloudtrail_events"

# Quick data check
duckdb data/db/threat_hunting.db "SELECT * FROM cloudtrail_events LIMIT 5"

# Docker volume inspection
docker volume inspect threat-hunting-duckdb
```

