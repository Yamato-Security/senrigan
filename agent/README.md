# agent

AI-assisted threat hunting module for Senrigan.

Enter a natural language question → OpenAI generates DuckDB SQL → safety guards validate the query
→ results are executed against the CloudTrail log database → AI delivers a fact-based threat analysis summary.
DuckDB is always opened in **`READ_ONLY`** mode.

---

## Table of Contents

- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
  - [Sequence Diagram — AI Query Flow](#sequence-diagram--ai-query-flow)
  - [Sequence Diagram — Direct SQL (Built-in Hunt)](#sequence-diagram--direct-sql-built-in-hunt)
  - [Sequence Diagram — SQL Fix Retry](#sequence-diagram--sql-fix-retry)
- [SQL Safety Guards](#sql-safety-guards)
- [Date-Range Filter](#date-range-filter)
- [Built-in Hunts](#built-in-hunts)
- [Report Generation](#report-generation)
- [Module Structure](#module-structure)
- [Suzaku CloudTrail Summary Page](#suzaku-cloudtrail-summary-page)
- [Configuration](#configuration)
- [Development](#development)

---

## Quick Start

```bash
# Run from docker/
docker compose up -d agent

# Open the UI
open http://localhost:8501
```

`OPENAI_API_KEY` is required for AI SQL generation and analysis.
Built-in hunts with a `sql` field can be executed without an API key.

---

## How It Works

### Sequence Diagram — AI Query Flow

The main flow: a user asks a natural language question and the agent
generates, validates, executes, and analyses a SQL query.

```mermaid
sequenceDiagram
    participant U    as User (Browser)
    participant APP  as app.py (Streamlit)
    participant LLM  as llm.py (OpenAI)
    participant QRY  as query.py
    participant DB   as DuckDB (READ_ONLY)
    participant OAI  as OpenAI API

    U->>APP: natural language question
    APP->>LLM: generate_sql(user_query, api_key, model, context)
    LLM->>OAI: chat.completions.create (system_prompt + schema + history + query)
    OAI-->>LLM: raw SQL (may be wrapped in ```sql ... ```)
    LLM->>LLM: _strip_markdown_fences(raw)
    LLM-->>APP: sql string

    APP->>QRY: apply_date_filter(sql, start_date, end_date)
    QRY-->>APP: sql with _ct_filtered CTE injected

    APP->>QRY: apply_row_limit(sql, row_limit)
    QRY-->>APP: sql with LIMIT clause

    APP->>QRY: execute_query(conn, sql)
    QRY->>QRY: validate_query — keyword blocklist check
    QRY->>DB: EXPLAIN <sql>
    DB-->>QRY: plan (or error)
    QRY->>DB: execute sql
    DB-->>QRY: result rows
    QRY-->>APP: pandas DataFrame

    APP->>LLM: generate_analysis(sql, dataframe, api_key, model)
    LLM->>OAI: chat.completions.create (results as Markdown table)
    OAI-->>LLM: fact-based bullet summary
    LLM-->>APP: analysis Markdown

    APP-->>U: show table + analysis in chat
    APP->>APP: append to conversation_context (for follow-up questions)
```

---

### Sequence Diagram — Direct SQL (Built-in Hunt)

Built-in hunts that have a pre-written `sql` field bypass the OpenAI
SQL generation step entirely.

```mermaid
sequenceDiagram
    participant U    as User (Browser)
    participant APP  as app.py (Streamlit)
    participant QRY  as query.py
    participant DB   as DuckDB (READ_ONLY)
    participant OAI  as OpenAI API (optional)

    U->>APP: select category → click ⚡ Direct SQL
    APP->>APP: load builtin_hunts.yaml → find entry with sql field
    APP->>QRY: apply_date_filter(sql, start_date, end_date)
    APP->>QRY: apply_row_limit(sql, row_limit)
    APP->>QRY: execute_query(conn, sql)
    QRY->>QRY: validate_query
    QRY->>DB: EXPLAIN + execute
    DB-->>QRY: result rows
    QRY-->>APP: pandas DataFrame
    APP-->>U: show results table

    opt API key is configured
        APP->>OAI: generate_analysis(sql, dataframe, …)
        OAI-->>APP: analysis Markdown
        APP-->>U: show analysis
    end
```

---

### Sequence Diagram — SQL Fix Retry

When generated SQL fails validation, the agent automatically asks the LLM
to fix it (up to one retry).

```mermaid
sequenceDiagram
    participant APP  as app.py (Streamlit)
    participant QRY  as query.py
    participant LLM  as llm.py
    participant OAI  as OpenAI API
    participant DB   as DuckDB (READ_ONLY)

    APP->>QRY: execute_with_retry(conn, sql, api_key, model)
    QRY->>QRY: validate_query(sql)
    Note over QRY: QueryValidationError raised

    QRY->>LLM: fix_sql_with_llm(broken_sql, error_message, api_key, model)
    LLM->>OAI: chat.completions.create (broken SQL + error → fix)
    OAI-->>LLM: corrected SQL
    LLM-->>QRY: fixed_sql

    QRY->>QRY: validate_query(fixed_sql)
    QRY->>DB: EXPLAIN + execute fixed_sql
    DB-->>QRY: result rows
    QRY-->>APP: pandas DataFrame
```

---

## SQL Safety Guards

Before executing any LLM-generated SQL, `query.py` applies three guards in order:

| Guard | Mechanism | Rejects |
|-------|-----------|---------|
| **Keyword blocklist** | Regex word-boundary match (case-insensitive) | `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE` |
| **EXPLAIN validation** | Runs `EXPLAIN <sql>` on the READ_ONLY connection | Syntactically invalid SQL |
| **Row-limit cap** | Wraps queries without `LIMIT` in `SELECT * FROM (…) AS _limited LIMIT N` | Unbounded result sets |

If validation fails, `execute_with_retry` calls `fix_sql_with_llm` once to attempt
an automatic correction. If the fixed SQL also fails, a `QueryValidationError` is surfaced
to the user.

Queries always execute against a **READ_ONLY** DuckDB connection — write operations
are impossible at the connection level even if a query bypassed the keyword filter.

---

## Date-Range Filter

The sidebar exposes **From** / **To** date pickers. When set, `apply_date_filter()`
injects a `_ct_filtered` CTE that wraps `cloudtrail_events` with the selected
`event_time` bounds, then replaces every reference to `cloudtrail_events` in the
original SQL with `_ct_filtered`.

```sql
-- Example: user selects 2024-01-01 → 2024-01-31
WITH _ct_filtered AS (
    SELECT * FROM cloudtrail_events
    WHERE event_time >= TIMESTAMP '2024-01-01 00:00:00'
      AND event_time <= TIMESTAMP '2024-01-31 23:59:59'
)
-- original query follows, with cloudtrail_events replaced by _ct_filtered
SELECT event_name, COUNT(*) FROM _ct_filtered GROUP BY 1 ORDER BY 2 DESC
```

Existing `WITH` chains are extended correctly — no duplicate `WITH` keyword is emitted.

---

## Built-in Hunts

`builtin_hunts.yaml` ships categorised threat hunting queries.

Each entry has:

| Field | Required | Description |
|-------|----------|-------------|
| `label` | Yes | Short display name shown in the sidebar |
| `description` | Yes | One-line description of the hunt |
| `prompt` | Yes | Natural language prompt sent to the LLM |
| `sql` | No | Pre-written SQL; when present, no API key is needed |

- Entries **with** `sql` → **Direct SQL** button is shown; executes immediately without OpenAI.
- Entries **without** `sql` → **Ask AI** button only; requires `OPENAI_API_KEY`.

---

## Report Generation

After one or more queries, the **Download Report** button in the sidebar
generates a Markdown report via `report.py`:

- Each query result is captured as a `ReportEntry` (question, SQL, result table, analysis).
- Sensitive values (ARNs, account IDs, IP addresses) are partially redacted.
- The final report includes a header, timestamp, all query entries, and a summary section.

---

## Module Structure

```
agent/
├── app.py                 # Streamlit entry point — UI layout, session state, event loop
├── llm.py                 # OpenAI API integration (SQL generation, analysis, SQL fix)
├── query.py               # Query execution, validation, date filter, row limit, retry
├── report.py              # Report generation (Markdown + sensitive data redaction)
├── schema.py              # CloudTrail table schema description for the system prompt
├── config.py              # Configuration management (env vars)
├── suzaku_summary.py      # Parsing + aggregation for Suzaku aws-ct-summary JSON (pure functions)
├── suzaku_report.py       # Markdown / HTML report generation for the Suzaku summary (pure functions)
├── builtin_hunts.yaml     # Pre-built threat hunting queries (categorised)
├── views/
│   └── suzaku_ct_summary.py    # st.navigation page: Suzaku aws-ct-summary viewer (upload + triage)
├── prompts/
│   └── system_prompt.py   # System prompt template for SQL generation
├── requirements.txt
├── requirements-dev.txt
├── Dockerfile
└── tests/
    ├── conftest.py        # Shared fixtures: mock_openai_client, tmp_duckdb
    ├── test_config.py
    ├── test_schema.py
    ├── test_query.py
    ├── test_llm.py
    ├── test_report.py
    ├── test_suzaku_summary.py
    ├── test_suzaku_report.py
    └── test_app.py
```

## Suzaku CloudTrail Summary Page

The app uses `st.navigation` (defined in `app.py`): the sidebar shows
**🔭 Senrigan** (the chat page) and **☁️ Suzaku CT Summary**. The latter
visualizes the JSON output of Suzaku's
[`aws-ct-summary`](https://github.com/Yamato-Security/suzaku) command. It is
self-contained and read-only: it does not touch DuckDB or OpenAI, and works
without an API key.

- **Upload** the `aws-ct-summary` JSON via the in-page file uploader (no mounted
  path or `docker-compose` change required).
- **Triage table** — one row per identity (`user_arn`), sorted by abused-API
  count then event count. Select a row to drill down.
- **Identity detail** — abused APIs (success/failed) with descriptions, an
  activity timeline, and Top-N breakdowns of source IPs, source countries,
  regions, user agents, and access-key IDs, with CSV export.
- **Report export** — download the whole summary as a **Markdown** or
  self-contained **HTML** report (one section per identity, ordered by triage
  rank). High-cardinality lists are capped at the top 20 rows per identity.
  Access-key IDs and source IPs are kept verbatim — in this view they are the
  indicators of compromise being reported (the summary holds no secret keys).

Parsing/aggregation live in `suzaku_summary.py` and report rendering in
`suzaku_report.py`, both as pure functions (unit-tested in
`tests/test_suzaku_summary.py` and `tests/test_suzaku_report.py`); the page
keeps only Streamlit rendering.

---

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_API_KEY` | Yes (AI features) | — | OpenAI API key |
| `DUCKDB_PATH` | Yes | — | Path to DuckDB file |
| `OPENAI_MODEL` | No | `gpt-5.4` | Model for SQL generation + analysis |
| `OPENAI_MODEL_LITE` | No | `gpt-5.4-mini` | Lighter model (optional override) |
| `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` | No | — | CA bundle for corporate TLS proxy |

---

## Development

```bash
cd agent
pip install -r requirements.txt -r requirements-dev.txt

pytest                                        # Run all tests
pytest -v --tb=short                          # Verbose output
pytest --cov=. --cov-report=term-missing      # With coverage
ruff check .                                  # Lint
black .                                       # Format
```

### Testing notes

- All tests that touch `llm.py` must mock `llm.OpenAI` (not `agent.llm.OpenAI`).
  `pytest.ini` sets `pythonpath = .`, so modules resolve as top-level names.
- DuckDB connections in tests use the `tmp_duckdb` fixture from `conftest.py`
  (`tmp_path / "test.db"`), never a shared file.
- Real OpenAI API calls in tests are **forbidden** — use `mock_openai_client`.

