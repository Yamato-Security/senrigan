# config_viz — AWS Config Resource Graph Viewer

A read-only web UI that visualises AWS Config snapshot resources as an interactive graph.  
Built with **FastAPI** (Python 3.14) on the backend and **React 18 + React Flow** on the frontend.

> **Implementation status**
>
> | Phase | Description | Status |
> |-------|-------------|--------|
> | A | FastAPI backend (pytest) | ✅ Complete — 34/34 tests passing |
> | B | React frontend (Vitest) | ✅ Complete — 33/33 tests passing |
> | C | Docker integration | ✅ Complete |

---

## Architecture

```
config_viz/
├── backend/          # FastAPI app (Python 3.14+)
│   ├── main.py       # FastAPI app + 4 REST endpoints + static file serving
│   ├── db.py         # DuckDB READ_ONLY connection (get_conn dependency)
│   ├── query.py      # SQL queries + keyword blocklist + EXPLAIN validation
│   └── requirements.txt
├── frontend/         # React 18 + Vite + TypeScript SPA
│   ├── src/
│   │   ├── App.tsx           # Root component (state management)
│   │   ├── types.ts          # Shared TypeScript types
│   │   ├── api.ts            # fetch wrappers for 4 API endpoints
│   │   ├── components/
│   │   │   ├── AwsNode.tsx       # Leaf node + hover tooltip
│   │   │   ├── AwsGroupNode.tsx  # Container node (dashed border)
│   │   │   ├── GraphCanvas.tsx   # ReactFlow + dagre layout
│   │   │   ├── Sidebar.tsx       # Snapshot list + filter + layout toggle
│   │   │   └── DetailPanel.tsx   # Resource detail slide-in panel
│   │   └── utils/
│   │       ├── layout.ts   # applyDagreLayout() (compound graph)
│   │       └── icons.ts    # AWS resource type → icon URL (with fallback)
│   ├── vite.config.ts        # outDir: ../static
│   └── vitest.config.ts
├── static/           # Vite build output (served by FastAPI)
├── tests/            # pytest backend tests (34 tests, BA-01 to BA-14)
│   ├── conftest.py
│   └── test_query.py
├── pytest.ini
└── requirements-dev.txt
```

**Tech stack**

| Layer | Technology |
|-------|-----------|
| Backend API | FastAPI + DuckDB READ_ONLY |
| Frontend | React 18 + Vite + TypeScript |
| Graph rendering | React Flow v11 (`reactflow`) |
| Auto layout | `@dagrejs/dagre` |
| Styling | Tailwind CSS |
| Server state | TanStack Query v5 |
| Backend tests | pytest |
| Frontend tests | Vitest + @testing-library/react + MSW v2 |

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/snapshots` | List all ingested Config snapshots |
| `GET` | `/api/snapshots/{id}/resource-types` | Distinct resource types in a snapshot |
| `GET` | `/api/snapshots/{id}/graph` | Nodes + edges in React Flow format |
| `GET` | `/api/snapshots/{id}/resources/{rid}` | Single resource detail (configuration + tags) |
| `GET` | `/` | React SPA (`static/index.html`) |

**Query parameters for `/graph`**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `resource_type` | — | Filter nodes to a specific AWS resource type |
| `limit` | `5000` | Maximum number of nodes to return |

---

## Graph Features

- **Hierarchical layout**: Region / VPC / Subnet shown as nested container boxes  
  (like standard AWS architecture diagrams).
- **Node types**: `awsGroupNode` (container, dashed border) and `awsNode` (leaf).
- `parentId` in nodes drives the nesting; "Contains" edges are excluded from the edge list.
- **Hover tooltip**: resource ID, Name, Region, Type.
- **Click → Detail panel**: full `configuration` and `tags` JSON.
- **Layout toggle**: Top-Bottom / Left-Right (dagre `rankdir`).
- **Resource type filter**: dropdown in the sidebar re-fetches with `resource_type=` param.

---

## DuckDB Tables

Written by the Rust `ingester config-import` command.  
The `config_viz` backend always opens DuckDB in **READ_ONLY** mode.

```sql
CREATE TABLE IF NOT EXISTS config_snapshots (
    snapshot_id  VARCHAR PRIMARY KEY,
    account_id   VARCHAR,
    aws_region   VARCHAR,
    captured_at  TIMESTAMP,
    source_path  VARCHAR,
    record_count INTEGER
);

CREATE TABLE IF NOT EXISTS config_resources (
    resource_id   VARCHAR,
    snapshot_id   VARCHAR,
    resource_type VARCHAR,
    aws_region    VARCHAR,
    resource_name VARCHAR,
    configuration VARCHAR,  -- JSON stored as VARCHAR
    tags          VARCHAR,  -- JSON stored as VARCHAR
    PRIMARY KEY (resource_id, snapshot_id)
);

CREATE TABLE IF NOT EXISTS config_edges (
    snapshot_id VARCHAR,
    source_id   VARCHAR,
    target_id   VARCHAR,
    edge_type   VARCHAR,
    PRIMARY KEY (snapshot_id, source_id, target_id, edge_type)
);
```

> Edges where either endpoint is absent from `config_resources` (dangling edges) are
> automatically filtered out by the API.

---

## Development

### Prerequisites

- Python 3.14+
- Node.js 20+
- [Rust ingester](../ingester/README.md) — to populate the DuckDB tables

### Backend (FastAPI)

```bash
cd config_viz

# Install dependencies
pip install -r backend/requirements.txt -r requirements-dev.txt

# Run tests
pytest

# Run with coverage
pytest --cov=backend --cov-report=term-missing

# Lint / format
ruff check .
black .

# Start dev server (no Docker)
uvicorn backend.main:app --reload --port 8502
```

`DUCKDB_PATH` environment variable controls which database file is opened
(default: `/data/db/threat_hunting.db`).

### Frontend (React + Vite)

```bash
cd config_viz/frontend

# Install dependencies
npm install

# Run tests
npm test

# Run tests with coverage
npm run coverage

# Start Vite dev server (proxies /api/* to localhost:8502)
npm run dev

# Production build → ../static/
npm run build
```

---

## Running with Docker

The `config-viz` service is part of the standard Docker Compose stack.

```bash
cd docker

# Start config-viz (and all other services)
docker compose up -d --build

# Start config-viz only
docker compose up -d --build config-viz
```

The service will be available at **http://localhost:8502**.

> **Prerequisite**: run `ingester config-import` first to populate the Config tables.
>
> ```bash
> docker compose --profile ingest run --rm ingester config-import --path /data/config
> ```

### AWS Icons

AWS service icons are downloaded from the
[aws-icons-for-plantuml](https://github.com/awslabs/aws-icons-for-plantuml) GitHub
repository during the Docker image build (`extract_icons.py`).

If the download fails (no internet access, TLS proxy, etc.) the build **still succeeds**
and the frontend falls back to a grey placeholder (`/icons/default.png`) for all resource
types.  The app is fully functional either way.

To supply custom icons without network access, place PNG files in
`config_viz/static/icons/` before running `docker compose build`:
the `extract_icons.py` script skips files that already exist.

### `docker-compose.yml` entry

```yaml
config-viz:
  build:
    context: ../config_viz
    dockerfile: Dockerfile
  container_name: threat-hunting-config-viz
  ports:
    - "8502:8502"
  volumes:
    - ${DUCKDB_HOST_PATH:-./data/db}:/data/db:ro
  environment:
    - DUCKDB_PATH=/data/db/threat_hunting.db
  restart: unless-stopped
  healthcheck:
    test: ["CMD", "curl", "-f", "http://localhost:8502/api/snapshots"]
    interval: 30s
    timeout: 10s
    retries: 3
```


---

## Security

- DuckDB is always opened **READ_ONLY** — no writes are possible from this service.
- SQL keyword blocklist (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`) +
  `EXPLAIN` validation guard all query execution paths.
- No API keys or external service calls — entirely local.

---

## Ingest Config Snapshots

Config snapshot JSON files must first be imported by the Rust ingester:

```bash
# From docker/
docker compose --profile ingest run --rm ingester config-import --path /data/config
```

See the [ingester README](../ingester/README.md) for full CLI options.

