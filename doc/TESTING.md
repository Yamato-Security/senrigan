# Testing Strategy

## Language Policy

All test code, comments, docstrings, and test descriptions MUST be written in English.

## Overview

Every module in Senrigan must have comprehensive test coverage. Tests are written **before** implementation following TDD (see [TDD_GUIDE.md](TDD_GUIDE.md)).

## Test Pyramid

```
         ┌───────────┐
         │  E2E /    │  Docker Compose integration (manual + CI)
         │  Manual   │
         ├───────────┤
         │Integration│  Cross-module tests (DuckDB read/write, API mocks)
         ├───────────┤
         │   Unit    │  Majority of tests — fast, isolated, deterministic
         └───────────┘
```

| Level         | Scope                            | Speed    | Frequency     |
| ------------- | -------------------------------- | -------- | ------------- |
| Unit          | Single function / struct         | < 1 ms   | Every save    |
| Integration   | Module + DuckDB / file I/O       | < 1 sec  | Every commit  |
| E2E           | Full pipeline (ingest → query)   | < 1 min  | CI / manual   |

---

## ingester (Rust) Testing

### Test Framework

- Built-in `#[test]` attribute (no external framework needed)
- `cargo test` to run all tests

### Test Organization

```
ingester/
├── src/
│   ├── parser.rs          # Unit tests in #[cfg(test)] mod tests { ... }
│   ├── db.rs              # Unit tests in #[cfg(test)] mod tests { ... }
│   ├── ingest.rs          # Unit tests in #[cfg(test)] mod tests { ... }
│   ├── config_parser.rs   # Unit tests in #[cfg(test)] mod tests { ... }
│   ├── config_db.rs       # Unit tests in #[cfg(test)] mod tests { ... }
│   ├── config_import.rs   # Unit tests in #[cfg(test)] mod tests { ... }
│   └── test_util.rs       # Shared test fixtures (only compiled under #[cfg(test)])
└── tests/
    ├── cli_test.rs             # CLI integration tests (ingest + enrich)
    ├── config_import_test.rs   # CLI integration tests (config-import)
    ├── integration_test.rs     # End-to-end pipeline tests
    └── testdata/
        ├── single_event.json
        ├── multi_event.json
        ├── single_event.json.gz
        ├── nested_dir/
        │   └── deep_event.json
        └── malformed.json
```

### Unit Tests (same file)

```rust
// src/parser.rs

pub fn parse_cloudtrail_log(json: &str) -> Result<CloudTrailLog> {
    // ...implementation...
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_event() {
        let json = include_str!("../tests/testdata/single_event.json");
        let log = parse_cloudtrail_log(json).unwrap();
        assert_eq!(log.records.len(), 1);
        assert_eq!(log.records[0].event_name, "DescribeInstances");
    }

    #[test]
    fn test_parse_malformed_json_returns_error() {
        let result = parse_cloudtrail_log("not valid json");
        assert!(result.is_err());
    }
}
```

### Integration Tests (separate files)

```rust
// tests/integration_test.rs

use tempfile::{NamedTempFile, TempDir};
use ingester::{ingest_path, IngestStats};

#[test]
fn test_full_ingestion_pipeline() {
    // Create temp DuckDB
    let tmp_db = NamedTempFile::new().unwrap();
    let testdata = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/testdata");

    let stats = ingest_path(testdata, tmp_db.path()).unwrap();

    assert!(stats.files_processed > 0);
    assert!(stats.records_inserted > 0);
    assert_eq!(stats.errors, 0);
}
```

### Key Rust Test Crates

| Crate          | Purpose                                          |
| -------------- | ------------------------------------------------ |
| `tempfile`     | Create temporary files/dirs for DuckDB databases |
| `assert_cmd`   | Test CLI binary invocation (optional)            |
| `predicates`   | Rich assertions for CLI output (optional)        |

### DuckDB in Rust Tests

```rust
use tempfile::NamedTempFile;
use duckdb::Connection;

/// Helper to create a temporary DuckDB connection for testing.
fn temp_duckdb() -> (Connection, NamedTempFile) {
    let tmp = NamedTempFile::new().unwrap();
    let conn = Connection::open(tmp.path()).unwrap();
    (conn, tmp) // tmp must be kept alive to prevent deletion
}

#[test]
fn test_create_table_and_insert() {
    let (conn, _tmp) = temp_duckdb();

    conn.execute_batch("
        CREATE TABLE cloudtrail_events (
            event_name VARCHAR,
            event_time TIMESTAMP
        );
        INSERT INTO cloudtrail_events VALUES ('Test', '2024-01-01');
    ").unwrap();

    let mut stmt = conn.prepare("SELECT COUNT(*) FROM cloudtrail_events").unwrap();
    let count: i64 = stmt.query_row([], |row| row.get(0)).unwrap();
    assert_eq!(count, 1);
}
```

### Running Rust Tests

```bash
cd ingester

cargo test                              # All tests
cargo test test_parse                   # Tests matching "test_parse"
cargo test -- --nocapture               # Show stdout/stderr
cargo test -- --test-threads=1          # Sequential (for file-based tests)
cargo test --test integration_test      # Only integration tests
```

---

## agent (Python) Testing

### Test Framework

- **pytest** >= 8.0
- **pytest-mock** for mocking

### Test Organization

```
agent/
├── app.py
├── handlers.py
├── llm.py
├── query.py
├── report.py
├── schema.py
├── config.py
├── prompts/
│   ├── system_prompt.py
│   └── analysis_prompt.py
└── tests/
    ├── conftest.py          # Shared fixtures
    ├── test_config.py
    ├── test_llm.py
    ├── test_prompts.py
    ├── test_query.py
    ├── test_report.py
    ├── test_schema.py
    └── test_app.py
```

### Shared Fixtures (conftest.py)

```python
# agent/tests/conftest.py
import pytest
import duckdb
from unittest.mock import MagicMock, patch


@pytest.fixture
def tmp_duckdb(tmp_path):
    """Create a temporary DuckDB with sample cloudtrail_events data."""
    db_path = tmp_path / "test.db"
    conn = duckdb.connect(str(db_path))
    conn.execute("""
        CREATE TABLE cloudtrail_events (
            event_time           TIMESTAMP,
            event_name           VARCHAR,
            event_source         VARCHAR,
            aws_region           VARCHAR,
            source_ip_address    VARCHAR,
            user_agent           VARCHAR,
            user_identity_type   VARCHAR,
            user_identity_arn    VARCHAR,
            user_identity_account_id VARCHAR,
            request_parameters   VARCHAR,
            response_elements    VARCHAR,
            error_code           VARCHAR,
            error_message        VARCHAR,
            read_only            BOOLEAN,
            event_type           VARCHAR,
            recipient_account_id VARCHAR,
            raw_event            VARCHAR
        )
    """)
    conn.execute("""
        INSERT INTO cloudtrail_events
            (event_time, event_name, event_source, aws_region, source_ip_address)
        VALUES
            ('2024-01-15 10:30:00', 'DescribeInstances', 'ec2.amazonaws.com',
             'us-east-1', '198.51.100.1'),
            ('2024-01-15 10:31:00', 'CreateUser', 'iam.amazonaws.com',
             'us-east-1', '198.51.100.2'),
            ('2024-01-15 10:32:00', 'ConsoleLogin', 'signin.amazonaws.com',
             'us-east-1', '203.0.113.5')
    """)
    conn.close()
    yield str(db_path)


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client returning a SQL query."""
    with patch("llm.OpenAI") as mock_cls:   # <-- 'llm.OpenAI', not 'agent.llm.OpenAI'
        client = MagicMock()
        mock_cls.return_value = client

        response = MagicMock()
        response.choices = [MagicMock()]
        response.choices[0].message.content = (
            "SELECT event_name, COUNT(*) as cnt "
            "FROM cloudtrail_events "
            "GROUP BY event_name ORDER BY cnt DESC LIMIT 10"
        )
        client.chat.completions.create.return_value = response
        yield client
```

### Example Tests

```python
# tests/test_query.py
import pytest
import duckdb


class TestDuckDBConnection:
    def test_connect_readonly(self, tmp_duckdb):
        """DuckDB opens in read-only mode."""
        conn = duckdb.connect(tmp_duckdb, read_only=True)
        result = conn.execute("SELECT COUNT(*) FROM cloudtrail_events").fetchone()
        assert result[0] == 3
        conn.close()

    def test_readonly_rejects_write(self, tmp_duckdb):
        """READ_ONLY connection cannot insert data."""
        conn = duckdb.connect(tmp_duckdb, read_only=True)
        with pytest.raises(duckdb.InvalidInputException):
            conn.execute("INSERT INTO cloudtrail_events (event_name) VALUES ('x')")
        conn.close()


class TestSQLValidation:
    def test_accepts_select(self, tmp_duckdb):
        from query import validate_query
        conn = duckdb.connect(tmp_duckdb, read_only=True)
        validate_query(conn, "SELECT * FROM cloudtrail_events")  # no exception
        conn.close()

    def test_rejects_insert(self):
        from query import QueryValidationError, validate_sql_blocklist
        with pytest.raises(QueryValidationError):
            validate_sql_blocklist("INSERT INTO t VALUES (1)")

    def test_rejects_drop_case_insensitive(self):
        from query import QueryValidationError, validate_sql_blocklist
        with pytest.raises(QueryValidationError):
            validate_sql_blocklist("drop table cloudtrail_events")
```

### OpenAI API Mocking

**Rule: Never call the real OpenAI API in tests.**

**Important:** `pytest.ini` sets `pythonpath = .`, so mock as `llm.OpenAI`,
**not** `agent.llm.OpenAI`.

```python
# tests/test_llm.py

def test_generate_sql_returns_query(mock_openai_client):
    from llm import generate_sql

    sql = generate_sql("Show all root account activity")
    assert "SELECT" in sql
    assert "cloudtrail_events" in sql


def test_generate_sql_strips_markdown_fences(mock_openai_client):
    # Override mock response with markdown-wrapped SQL
    mock_openai_client.chat.completions.create.return_value.choices[
        0
    ].message.content = "```sql\nSELECT * FROM cloudtrail_events\n```"

    from llm import generate_sql

    sql = generate_sql("Show everything")
    assert not sql.startswith("```")
    assert sql.strip() == "SELECT * FROM cloudtrail_events"
```

### Running Python Tests

```bash
cd agent
source .venv/bin/activate

pytest                                  # All tests (134 tests)
pytest tests/test_query.py              # Specific file
pytest -k "test_validate"              # Pattern match
pytest -v --tb=short                   # Verbose + short traceback
pytest --cov=. --cov-report=term       # Coverage report
```

---

## Test Data Management

### Location

```
ingester/tests/testdata/       # For Rust ingester tests
agent/tests/testdata/          # For Python agent tests (if needed)
```

### Sample CloudTrail Event (Minimal)

```json
{
  "Records": [
    {
      "eventTime": "2024-01-15T10:30:00Z",
      "eventName": "DescribeInstances",
      "eventSource": "ec2.amazonaws.com",
      "awsRegion": "us-east-1",
      "sourceIPAddress": "198.51.100.1",
      "userAgent": "aws-cli/2.0",
      "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::123456789012:user/testuser",
        "accountId": "123456789012"
      },
      "readOnly": true,
      "eventType": "AwsApiCall",
      "recipientAccountId": "123456789012"
    }
  ]
}
```

### Guidelines

1. **Minimal data**: Use the smallest JSON that exercises the feature under test.
2. **No real data**: Never commit actual CloudTrail logs — use synthetic data only.
3. **Diverse scenarios**: Include events with errors, missing fields, different event types.
4. **gz files**: Generate programmatically in test setup or commit small pre-compressed files.

---

## Coverage Targets

| Module     | Target Coverage | Focus Areas                                                   |
| ---------- | --------------- | ------------------------------------------------------------- |
| ingester   | 80%+            | parser, db insert logic, config import pipeline               |
| agent      | 80%+            | SQL validation, LLM response parsing, reports                 |
| config_viz | 80%+            | query functions, blocklist, graph endpoint, frontend components |
| dashboard  | N/A             | Configuration-only; tested via manual QA                      |

### Measuring Coverage

```bash
# Rust
cargo install cargo-tarpaulin
cargo tarpaulin --out Html

# Python (agent)
pytest --cov=. --cov-report=html
open htmlcov/index.html

# Python (config_viz)
cd config_viz
pytest --cov=backend --cov-report=html

# TypeScript (config_viz frontend)
cd config_viz/frontend
npm run coverage
```

---

## config_viz Testing

### Test Framework

- **Backend:** `pytest` >= 8.0 + `httpx` (FastAPI TestClient)
- **Frontend:** `vitest` + `@testing-library/react` + MSW v2

### Test Organization

```
config_viz/
├── backend/
│   ├── main.py
│   ├── db.py
│   └── query.py
├── frontend/
│   └── src/
│       └── __tests__/          # Vitest frontend tests (33 tests)
│           ├── App.test.tsx
│           ├── Sidebar.test.tsx
│           ├── GraphCanvas.test.tsx
│           ├── AwsNode.test.tsx
│           ├── AwsGroupNode.test.tsx
│           ├── DetailPanel.test.tsx
│           ├── layout.test.ts
│           └── icons.test.ts
└── tests/
    ├── conftest.py             # tmp_db_empty, tmp_db_seeded, tmp_db_hierarchy, client_* fixtures
    └── test_query.py           # 34 backend tests (BA-01 to BA-14)
```

### Backend Tests (pytest)

34 tests covering all API endpoints and SQL safety:

| Test ID | Coverage |
|---------|---------|
| BA-01/02 | `GET /api/snapshots` — empty DB and populated DB |
| BA-03 | `GET /api/snapshots/{id}/resource-types` |
| BA-04/05 | `GET /api/snapshots/{id}/graph` — node count + dangling edge filter |
| BA-06 | `GET /api/snapshots/{id}/resources/{rid}` — detail |
| BA-07 | 404 for non-existent snapshot |
| BA-08/09 | `resource_type=` filter + `limit=` cap |
| BA-10 | Keyword blocklist rejects write SQL |
| BA-11 | Hierarchical `parentId` / `awsGroupNode` / "Contains" edge exclusion |
| BA-12 | Graceful handling when Config tables are absent from DB |
| BA-13 | Service group nodes in full graph view |
| BA-14 | Containment hierarchy depth (region → service → VPC → subnet → instance) |

```bash
cd config_viz
pytest                          # All 34 tests
pytest -v --tb=short
pytest --cov=backend --cov-report=term-missing
```

### Frontend Tests (Vitest)

33 tests using `@testing-library/react` and MSW v2 for API mocking:

| Test ID | Coverage |
|---------|---------|
| BF-01 | `Sidebar` fetches snapshot list |
| BF-02 | Snapshot selection triggers graph API call |
| BF-03/12 | `GraphCanvas` renders nodes, edges, and compound nodes |
| BF-04 | `AwsNode` tooltip on hover |
| BF-05/06 | Click → `DetailPanel` opens + fetches detail |
| BF-07/10 | Resource type filter + layout toggle |
| BF-08 | `applyDagreLayout()` assigns positions (compound graph) |
| BF-09 | `icons.ts` fallback for unknown resource types |
| BF-11 | `AwsGroupNode` dashed border rendering |

```bash
cd config_viz/frontend
npm test                        # Watch mode
npm test -- --run               # Single-pass (CI)
npm run coverage                # With coverage report
```

### DuckDB Fixtures (conftest.py)

```python
# config_viz/tests/conftest.py
@pytest.fixture
def tmp_db_seeded(tmp_path):
    """Temporary DuckDB with one snapshot + resources + edges."""
    db_path = tmp_path / "test.db"
    conn = duckdb.connect(str(db_path))
    # Creates config_snapshots, config_resources, config_edges tables
    # and inserts minimal test data
    ...
    conn.close()
    yield db_path

@pytest.fixture
def tmp_db_hierarchy(tmp_path):
    """Temporary DuckDB with VPC → Subnet → EC2 containment hierarchy."""
    ...
```

---

## Continuous Integration Checks

Every PR must pass:

1. **All tests green** (`cargo test` + `pytest` for agent + `pytest` for config_viz + `npm test` for config_viz frontend)
2. **No lint warnings** (`cargo clippy -- -D warnings` + `ruff check .` + `black --check .`)
3. **Format compliance** (`cargo fmt --check`)
4. **No new test regressions** (test count must not decrease)

