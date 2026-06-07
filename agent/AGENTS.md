# AGENTS.md — Agent Module (Python / Streamlit)

> Module-specific TDD context for the `agent` module.
> For project-wide instructions, see the root [AGENTS.md](../AGENTS.md).
> For feature requirements, see [doc/PRD.md](../doc/PRD.md).

## Module Purpose

The agent provides an interactive Streamlit UI for AI-assisted threat hunting.
Users enter natural language questions; the AI generates DuckDB SQL, executes it, and
provides a fact-based analysis summary. It also supports automated report generation
and pre-built preset queries.

**DuckDB is always opened in `READ_ONLY` mode in this module.**

## Technology Stack

| Item | Value |
|------|-------|
| Language | Python 3.14+ |
| Framework | Streamlit |
| AI Integration | OpenAI API (`gpt-5.4` default; `gpt-5.5`, `gpt-5.4-mini` also available) |
| DB Client | `duckdb` Python package |
| Data Processing | `pandas` |
| Test Framework | `pytest`, `pytest-mock` |
| Linter | `ruff` |
| Formatter | `black` |

## Module Structure

```
agent/
├── app.py                 # Streamlit entry point — UI layout, session state, event loop
├── handlers.py            # Stateful handler functions (_handle_direct_sql, _handle_user_query, etc.)
├── llm.py                 # OpenAI API integration (SQL generation, analysis, SQL fix)
├── query.py               # DuckDB query execution, validation, date filter, row limit, retry
├── report.py              # Threat hunting report generation (Markdown + sensitive data redaction)
├── schema.py              # CloudTrail table schema description for the system prompt
├── config.py              # Configuration management (env vars)
├── builtin_hunts.yaml     # Pre-built threat hunting queries (categorised)
├── prompts/
│   ├── __init__.py
│   ├── system_prompt.py   # System prompt template for SQL generation
│   └── analysis_prompt.py # System prompt + user template for analysis
├── requirements.txt
├── requirements-dev.txt
├── Dockerfile
├── pytest.ini             # Sets pythonpath = . so modules resolve as `llm`, not `agent.llm`
└── tests/
    ├── __init__.py
    ├── conftest.py        # Shared fixtures: mock_openai_client, tmp_duckdb
    ├── test_config.py
    ├── test_schema.py
    ├── test_query.py
    ├── test_llm.py
    ├── test_prompts.py
    ├── test_report.py
    ├── test_handlers.py       # UI-03 bulk_mode / source field tests
    └── test_app.py
```

## Implemented Tests

291 tests across 9 test files. Key coverage areas per module:

### config.py (`test_config.py` — 10 tests)
- `test_get_duckdb_path_returns_env_var` — Config loads `DUCKDB_PATH` from environment.
- `test_get_duckdb_path_returns_default_when_unset` — Default constant used when unset.
- `test_get_duckdb_path_for_variant_full_returns_full_path` — `full` variant resolves full path.
- `test_get_duckdb_path_for_variant_lite_returns_lite_path` — `lite` variant resolves lite path.
- `test_get_duckdb_path_for_variant_lite_falls_back_to_full` — falls back to full when lite unset.
- Plus 5 additional edge cases for empty env vars and lite-only paths.

### schema.py (`test_schema.py` — 2 tests)
- `test_get_schema_description_returns_string` — Returns a human-readable schema description.
- `test_get_column_names_returns_list` — Returns the expected column name list.

### query.py (`test_query.py` — 17 tests)
- `test_connect_duckdb_readonly` — Opens DuckDB in read-only mode.
- `test_execute_select_query` — Executes `SELECT` and returns a `pd.DataFrame`.
- `test_execute_query_returns_empty_dataframe_for_no_results` — Empty result → empty DataFrame.
- `test_validate_query_with_explain` — `EXPLAIN <sql>` succeeds on valid SQL.
- `test_validate_query_rejects_write_statements` — `INSERT`/`UPDATE`/`DELETE`/`DROP`/`ALTER`/`CREATE` rejected.
- `test_execute_query_timeout` — Long-running queries raise a timeout error.
- `test_execute_query_uses_default_row_limit` — Default row limit applied automatically.
- `test_execute_query_truncates_to_custom_row_limit` — Custom limit is honoured.
- `test_execute_query_overrides_existing_sql_limit` — Existing `LIMIT` in SQL is replaced.
- `test_execute_with_retry_succeeds_on_first_attempt` — No retry needed on clean SQL.
- `test_execute_with_retry_calls_fix_sql_on_validation_error` — Calls `fix_sql_with_llm` once.
- `test_execute_with_retry_raises_after_max_retries_exceeded` — Raises after max retries.
- `test_execute_with_retry_does_not_retry_on_timeout` — Timeout errors are not retried.
- `test_execute_with_retry_forwards_row_limit` — row_limit passed through retry path.
- `test_default_row_limit_is_500` — `DEFAULT_ROW_LIMIT` constant equals 500.
- Plus 2 additional execute_query_large_row_limit and forwarding tests.

### llm.py (`test_llm.py` — 13 tests)
- `test_build_system_prompt_includes_schema` — System prompt includes schema description.
- `test_build_system_prompt_includes_duckdb_dialect` — DuckDB dialect note included.
- `test_generate_sql_returns_sql_string` — Mocked OpenAI response → SQL string returned.
- `test_generate_sql_strips_markdown_fences` — ` ```sql ... ``` ` wrappers stripped.
- `test_generate_sql_with_context_injects_messages` — Prior conversation turns injected.
- `test_generate_sql_context_none_is_backward_compatible` — `context=None` still works.
- `test_generate_sql_context_max_items_truncated` — Context truncated to `MAX_CONTEXT_TURNS`.
- `test_generate_sql_handles_api_error` — `OpenAIError` caught → user-friendly message.
- `test_generate_analysis_returns_markdown` — Query results → Markdown analysis.
- `test_generate_analysis_uses_analysis_system_prompt` — Uses `ANALYSIS_SYSTEM_PROMPT`.
- `test_generate_analysis_user_message_contains_sql` — SQL included in user message.
- `test_fix_sql_with_llm_returns_corrected_sql` — Broken SQL + error → corrected SQL.
- `test_fix_sql_with_llm_strips_markdown_fences` — Markdown fences stripped from fix response.
- `test_fix_sql_with_llm_handles_api_error` — API error during fix handled gracefully.
- Plus 2 client-caching tests (`test_create_client_reuses_same_instance`, etc.).

### prompts/ (`test_prompts.py` — 11 tests)
- `test_system_prompt_is_nonempty` / `test_system_prompt_contains_schema_placeholder`
- `test_system_prompt_contains_duckdb_rule` / `test_system_prompt_contains_mitre_tactics`
- `test_system_prompt_contains_no_write_rule` / `test_system_prompt_contains_json_extraction_guidance`
- `test_system_prompt_contains_statistical_function_guidance`
- `test_analysis_system_prompt_is_nonempty` / `test_analysis_system_prompt_fact_based_rule`
- `test_analysis_user_template_has_sql_placeholder` / `test_analysis_user_template_renders_correctly`

### report.py (`test_report.py` — 15 tests)
- `test_generate_report_markdown` — Session produces Markdown report.
- `test_report_includes_timestamp` — Report header contains generation timestamp.
- `test_report_includes_all_queries` — All query/result/analysis triples included.
- `test_report_sanitizes_sensitive_data` — AWS ARNs and account IDs redacted.
- `test_report_entry_chart_config_defaults_to_none` — `chart_config` field defaults to `None`.
- `test_report_entry_chart_config_stores_dict` — `chart_config` stores a dict correctly.
- **UI-01:** `test_report_entry_has_analyst_note_field` — `analyst_note` defaults to `""`.
- **UI-01:** `test_report_entry_analyst_note_stores_value` — `analyst_note` persists value.
- **UI-01:** `test_generate_report_includes_analyst_note_section` — `### Analyst Note` in report.
- **UI-01:** `test_generate_report_omits_analyst_note_section_when_empty` — Omitted when empty.
- **UI-01:** `test_report_sanitizes_analyst_note` — Sensitive patterns redacted in notes.
- **UI-02:** `test_report_entry_has_label_and_category_fields` — `label`/`category` default to `""`.
- **UI-02:** `test_report_entry_label_and_category_store_values` — Fields persist provided values.
- **UI-02:** `test_generate_report_includes_label_in_heading` — Label in query section heading.
- **UI-02:** `test_generate_report_includes_category_when_set` — Category in report section.

### handlers.py (`test_handlers.py` — 5 tests) — NEW
- **UI-03:** `test_handle_direct_sql_bulk_mode_does_not_append_message` — `bulk_mode=True` skips chat.
- **UI-03:** `test_handle_direct_sql_bulk_mode_appends_to_query_history` — Results stored.
- **UI-03:** `test_handle_direct_sql_bulk_mode_sets_source_bulk` — `source == "bulk"` set.
- **UI-03:** `test_handle_direct_sql_default_mode_sets_source_chat` — `source == "chat"` default.
- **UI-03:** `test_handle_direct_sql_bulk_mode_stores_label_and_category` — Metadata stored.

### app.py (`test_app.py` — 60+ tests)
- Session state initialisation and idempotency
- Model options, built-in hunt YAML validation
- Direct SQL execution (no API key path, date filter application)
- Conversation context retention and `MAX_CONTEXT_TURNS` enforcement
- SQL auto-correction retry loop (`execute_with_retry` integration)
- No-API-key guidance banner rendering
- Row limit session state defaults and enforcement
- Chart rendering (bar, timeseries, auto modes)
- Edit/rerun SQL handler
- `ReportEntry.description` field storage
- Query index in messages
- **UI-01:** `analyst_notes` session state default (`{}`)
- **UI-01:** `_export_session()` includes `analyst_note` per query
- **UI-02:** `_handle_direct_sql()` stores label/category in ReportEntry
- **UI-04:** `bulk_progress` session state default (`None`)

## OpenAI API Mocking Strategy

All tests involving OpenAI API calls MUST use mocks. Never call the real API in tests.

**Important:** `pytest.ini` sets `pythonpath = .`, so mock the module as `llm.OpenAI`,
**not** `agent.llm.OpenAI`.

```python
# agent/tests/conftest.py
import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client that returns a predefined SQL response."""
    with patch("llm.OpenAI") as mock_cls:          # <-- 'llm.OpenAI', not 'agent.llm.OpenAI'
        client = MagicMock()
        mock_cls.return_value = client

        response = MagicMock()
        response.choices = [MagicMock()]
        response.choices[0].message.content = (
            "SELECT event_name, COUNT(*) AS cnt "
            "FROM cloudtrail_events "
            "GROUP BY event_name ORDER BY cnt DESC LIMIT 10"
        )
        client.chat.completions.create.return_value = response
        yield client


@pytest.fixture
def tmp_duckdb(tmp_path):
    """Create a temporary DuckDB with the cloudtrail_events table and sample data."""
    import duckdb

    db_path = tmp_path / "test.db"
    conn = duckdb.connect(str(db_path))
    conn.execute("""
        CREATE TABLE cloudtrail_events (
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
            request_parameters       VARCHAR,
            response_elements        VARCHAR,
            error_code               VARCHAR,
            error_message            VARCHAR,
            read_only                BOOLEAN,
            event_type               VARCHAR,
            recipient_account_id     VARCHAR,
            raw_event                VARCHAR,
            -- Geo columns (7)
            geo_country_code         VARCHAR,
            geo_country_name         VARCHAR,
            geo_city                 VARCHAR,
            geo_latitude             DOUBLE,
            geo_longitude            DOUBLE,
            geo_asn                  VARCHAR,
            geo_org                  VARCHAR,
            -- Extended columns (24)
            user_identity_principal_id      VARCHAR,
            user_identity_access_key_id     VARCHAR,
            user_identity_user_name         VARCHAR,
            user_identity_invoked_by        VARCHAR,
            session_mfa_authenticated       VARCHAR,
            session_creation_date           VARCHAR,
            session_issuer_type             VARCHAR,
            session_issuer_arn              VARCHAR,
            session_issuer_account_id       VARCHAR,
            session_issuer_user_name        VARCHAR,
            session_issuer_principal_id     VARCHAR,
            event_id                        VARCHAR,
            event_category                  VARCHAR,
            resources                       VARCHAR,
            additional_event_data           VARCHAR,
            shared_event_id                 VARCHAR,
            vpc_endpoint_id                 VARCHAR,
            management_event                VARCHAR,
            tls_version                     VARCHAR,
            tls_cipher_suite                VARCHAR,
            tls_client_provided_host_header VARCHAR,
            service_event_details           VARCHAR,
            session_credential_from_console VARCHAR,
            api_version                     VARCHAR
        )
    """)
    conn.execute("""
        INSERT INTO cloudtrail_events (event_time, event_name, event_source, aws_region)
        VALUES
            ('2024-01-15 10:30:00', 'DescribeInstances', 'ec2.amazonaws.com', 'us-east-1'),
            ('2024-01-15 10:31:00', 'DescribeInstances', 'ec2.amazonaws.com', 'us-east-1'),
            ('2024-01-15 10:32:00', 'CreateUser',        'iam.amazonaws.com', 'us-east-1')
    """)
    conn.close()
    yield str(db_path)
```

## SQL Safety Rules

1. **READ_ONLY connection:** `duckdb.connect(..., read_only=True)` always.
2. **Keyword blocklist:** `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE` rejected (regex, word-boundary, case-insensitive).
3. **EXPLAIN validation:** `EXPLAIN <sql>` runs before execution.
4. **Row-limit cap:** Queries without `LIMIT` are wrapped in `SELECT * FROM (...) AS _limited LIMIT N`. Existing `LIMIT` is replaced so the sidebar setting is always the effective cap.
5. **Timeout:** Queries are cancelled after `QUERY_TIMEOUT_SECONDS = 30` seconds.
6. **Retry:** `execute_with_retry` calls `fix_sql_with_llm` once on `QueryValidationError`.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DUCKDB_PATH` | (required) | Path to the DuckDB database file |
| `OPENAI_API_KEY` | (required for AI) | OpenAI API key |
| `OPENAI_MODEL` | `gpt-5.4` | Model for SQL generation and analysis (`gpt-5.5`, `gpt-5.4`, `gpt-5.4-mini` available) |
| `OPENAI_MODEL_LITE` | `gpt-5.4-mini` | Lightweight model (optional) |
| `SSL_CERT_FILE` | — | CA bundle for corporate TLS inspection proxy |
| `REQUESTS_CA_BUNDLE` | — | Alternative CA bundle path (same purpose) |

## Dependencies

**requirements.txt**
```
streamlit>=1.40.0
openai>=1.60.0
duckdb>=1.2.0
pandas>=2.2.0
pyyaml>=6.0.0
tabulate>=0.9.0
httpx>=0.27.0
```

**requirements-dev.txt**
```
pytest>=8.0.0
pytest-mock>=3.14.0
ruff>=0.9.0
black>=24.0.0
```
