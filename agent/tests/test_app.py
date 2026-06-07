"""Tests for the Streamlit app entry point (app.py).

Test #22: session state initialization (Phase 6 of TDD plan).
Tests #23-#25: built-in hunt YAML structure and Direct SQL execution.
Tests #DF-A/B: date range filter session state and _handle_direct_sql integration.
Tests #CTX: conversation context retention (Proposal 1).
Tests #RETRY: SQL auto-correction retry loop (Proposal 2).
Tests #BANNER: no-api-key guidance banner (Proposal 3).
"""

import json
from datetime import date
from unittest.mock import MagicMock, patch

import duckdb
import pandas as pd


def test_session_state_initialization():
    """Session state is populated with expected keys on startup.

    Test #22 — AGT-01/AGT-09: verifies that _init_session_state() creates
    all required keys in st.session_state when they are absent.
    """
    mock_state = {}
    with patch("streamlit.session_state", mock_state):
        from app import SESSION_STATE_DEFAULTS, _init_session_state

        _init_session_state()
        for key in SESSION_STATE_DEFAULTS:
            assert key in mock_state, f"Expected session state key '{key}' to be set"


def test_session_state_does_not_overwrite_existing_keys():
    """Existing session state keys must not be overwritten by _init_session_state().

    Ensures idempotent behavior when the page reloads mid-session.
    """
    existing_messages = [{"role": "user", "content": "hello"}]
    mock_state = {"messages": existing_messages}
    with patch("streamlit.session_state", mock_state):
        from app import _init_session_state

        _init_session_state()
        assert mock_state["messages"] == existing_messages


def test_session_state_messages_default_is_empty_list():
    """messages key must default to an empty list."""
    mock_state = {}
    with patch("streamlit.session_state", mock_state):
        from app import _init_session_state

        _init_session_state()
        assert mock_state["messages"] == []


def test_session_state_query_history_default_is_empty_list():
    """query_history key must default to an empty list."""
    mock_state = {}
    with patch("streamlit.session_state", mock_state):
        from app import _init_session_state

        _init_session_state()
        assert mock_state["query_history"] == []


def test_session_state_model_default():
    """model key must default to 'gpt-5.5'."""
    mock_state = {}
    with patch("streamlit.session_state", mock_state):
        from app import _init_session_state

        _init_session_state()
        assert mock_state["model"] == "gpt-5.5"


def test_model_options_include_gpt_5_5():
    """gpt-5.5 must appear in the available model options list.

    Verifies that the recently released gpt-5.5 model is present in
    the MODEL_OPTIONS constant used for the sidebar dropdown.
    """
    from app import MODEL_OPTIONS

    assert (
        "gpt-5.5" in MODEL_OPTIONS
    ), f"gpt-5.5 not found in MODEL_OPTIONS: {MODEL_OPTIONS}"


def test_load_builtin_prompts_returns_nonempty_list():
    """_load_builtin_prompts() must return a non-empty list of dicts with label/prompt keys."""
    from app import _load_builtin_prompts

    prompts = _load_builtin_prompts()
    assert isinstance(prompts, list)
    assert len(prompts) > 0
    for entry in prompts:
        assert "label" in entry, "Each prompt entry must have a 'label' key"
        assert "prompt" in entry, "Each prompt entry must have a 'prompt' key"


def test_load_builtin_prompts_includes_root_account():
    """Built-in prompts must include a root account activity entry."""
    from app import _load_builtin_prompts

    prompts = _load_builtin_prompts()
    labels = [p["label"] for p in prompts]
    assert any(
        "Root" in label for label in labels
    ), "Expected a 'Root Account' entry in built-in prompts"


def test_export_session_returns_valid_json():
    """_export_session() must return a JSON-serialisable string."""

    from app import _export_session
    from report import ReportEntry

    entries = [
        ReportEntry(
            sql="SELECT 1",
            results=pd.DataFrame({"a": [1]}),
        )
    ]
    result = _export_session(entries, title="Test Hunt")
    # Must be valid JSON
    parsed = json.loads(result)
    assert parsed["title"] == "Test Hunt"
    assert len(parsed["queries"]) == 1
    assert parsed["queries"][0]["sql"] == "SELECT 1"


def test_export_session_empty_entries():
    """_export_session() must handle an empty entry list gracefully."""
    from app import _export_session

    result = _export_session([], title="Empty Hunt")
    parsed = json.loads(result)
    assert parsed["queries"] == []


# ---------------------------------------------------------------------------
# Test #23 — builtin_hunts.yaml structure validation
# ---------------------------------------------------------------------------


def test_builtin_hunts_yaml_has_required_fields():
    """All entries in builtin_hunts.yaml must have category, label, description, prompt.

    Test #23: enforces the v2 schema after the built-in query enhancement.
    """
    from app import _load_builtin_prompts

    prompts = _load_builtin_prompts()
    assert len(prompts) > 0, "builtin_hunts.yaml must not be empty"
    for entry in prompts:
        label = entry.get("label", "<unknown>")
        assert "category" in entry, f"Missing 'category' in entry: {label!r}"
        assert "label" in entry, "Missing 'label' in entry"
        assert "description" in entry, f"Missing 'description' in entry: {label!r}"
        assert "prompt" in entry, f"Missing 'prompt' in entry: {label!r}"


def test_builtin_hunts_yaml_has_direct_sql_entries():
    """At least one entry must contain a 'sql' field for direct execution.

    Test #23b: verifies that the sql field enhancement was actually applied.
    """
    from app import _load_builtin_prompts

    prompts = _load_builtin_prompts()
    sql_entries = [p for p in prompts if p.get("sql")]
    assert (
        len(sql_entries) >= 10
    ), f"Expected at least 10 direct-SQL entries, got {len(sql_entries)}"


# ---------------------------------------------------------------------------
# Tests for "Run All Hunts" button
# ---------------------------------------------------------------------------


def test_build_all_hunt_queries_returns_all_sql_entries():
    """_build_all_hunt_queries() must return every entry that has a non-empty sql field."""
    from app import _build_all_hunt_queries, _load_builtin_prompts

    prompts = _load_builtin_prompts()
    expected = [p for p in prompts if p.get("sql", "").strip()]
    result = _build_all_hunt_queries(prompts)

    assert len(result) == len(expected)


def test_build_all_hunt_queries_output_shape():
    """_build_all_hunt_queries() items must have sql, description, chart_config, label, category."""
    from app import _build_all_hunt_queries, _load_builtin_prompts

    prompts = _load_builtin_prompts()
    result = _build_all_hunt_queries(prompts)

    assert len(result) > 0
    for item in result:
        assert "sql" in item
        assert "description" in item
        assert "chart_config" in item
        assert "label" in item
        assert "category" in item


def test_build_all_hunt_queries_strips_whitespace():
    """_build_all_hunt_queries() must strip leading/trailing whitespace from sql."""
    from app import _build_all_hunt_queries

    prompts = [
        {"label": "A", "category": "C", "description": "d", "sql": "  SELECT 1  "},
        {"label": "B", "category": "C", "description": "d", "sql": ""},
    ]
    result = _build_all_hunt_queries(prompts)

    assert len(result) == 1
    assert result[0]["sql"] == "SELECT 1"


def test_build_all_hunt_queries_excludes_entries_without_sql():
    """_build_all_hunt_queries() must exclude entries that have no sql field."""
    from app import _build_all_hunt_queries

    prompts = [
        {"label": "A", "category": "C", "description": "d", "prompt": "p"},
        {"label": "B", "category": "C", "description": "d", "sql": "SELECT 1"},
    ]
    result = _build_all_hunt_queries(prompts)

    assert len(result) == 1
    assert result[0]["label"] == "B"


# ---------------------------------------------------------------------------
# Test #24 — Direct SQL entries must be valid DuckDB
# ---------------------------------------------------------------------------


def test_builtin_hunts_direct_sql_is_valid_duckdb(tmp_path):
    """Every 'sql' field in builtin_hunts.yaml must pass DuckDB EXPLAIN validation.

    Test #24: prevents broken SQL from shipping in built-in presets.
    Uses a temporary DB with the full cloudtrail_events schema.
    """
    from app import _load_builtin_prompts
    from query import validate_query

    db_path = str(tmp_path / "test.db")
    conn_rw = duckdb.connect(db_path)
    conn_rw.execute("""
        CREATE TABLE cloudtrail_events (
            event_time                          TIMESTAMP,
            event_name                          VARCHAR,
            event_source                        VARCHAR,
            aws_region                          VARCHAR,
            source_ip_address                   VARCHAR,
            user_agent                          VARCHAR,
            user_identity_type                  VARCHAR,
            user_identity_arn                   VARCHAR,
            user_identity_account_id            VARCHAR,
            request_parameters                  VARCHAR,
            response_elements                   VARCHAR,
            error_code                          VARCHAR,
            error_message                       VARCHAR,
            read_only                           BOOLEAN,
            event_type                          VARCHAR,
            recipient_account_id                VARCHAR,
            raw_event                           VARCHAR,
            geo_country_code                    VARCHAR,
            geo_country_name                    VARCHAR,
            geo_city                            VARCHAR,
            geo_latitude                        DOUBLE,
            geo_longitude                       DOUBLE,
            geo_asn                             VARCHAR,
            geo_org                             VARCHAR,
            user_identity_principal_id          VARCHAR,
            user_identity_access_key_id         VARCHAR,
            user_identity_user_name             VARCHAR,
            user_identity_invoked_by            VARCHAR,
            session_mfa_authenticated           VARCHAR,
            session_creation_date               VARCHAR,
            session_issuer_type                 VARCHAR,
            session_issuer_arn                  VARCHAR,
            session_issuer_account_id           VARCHAR,
            session_issuer_user_name            VARCHAR,
            session_issuer_principal_id         VARCHAR,
            event_id                            VARCHAR,
            event_category                      VARCHAR,
            resources                           VARCHAR,
            additional_event_data               VARCHAR,
            shared_event_id                     VARCHAR,
            vpc_endpoint_id                     VARCHAR,
            management_event                    VARCHAR,
            tls_version                         VARCHAR,
            tls_cipher_suite                    VARCHAR,
            tls_client_provided_host_header     VARCHAR,
            service_event_details               VARCHAR,
            session_credential_from_console     VARCHAR,
            api_version                         VARCHAR
        )
    """)
    conn_rw.close()

    conn_ro = duckdb.connect(db_path, read_only=True)
    try:
        prompts = _load_builtin_prompts()
        for entry in prompts:
            sql = entry.get("sql")
            if sql:
                (
                    validate_query(conn_ro, sql),
                    (f"SQL validation failed for preset {entry['label']!r}"),
                )
    finally:
        conn_ro.close()


# ---------------------------------------------------------------------------
# Test #25 — _handle_direct_sql() works without an API key
# ---------------------------------------------------------------------------


def test_handle_direct_sql_no_api_key_shows_results(tmp_duckdb):
    """Direct SQL execution must succeed and populate session state without an API key.

    Test #25: verifies the _handle_direct_sql() path that bypasses OpenAI.
    last_sql must reflect the effective SQL (with row_limit applied), not the
    original SQL passed in.
    """
    from query import apply_row_limit, DEFAULT_ROW_LIMIT
    from tests.conftest import MockSessionState

    sql = (
        "SELECT event_time, event_name, aws_region "
        "FROM cloudtrail_events ORDER BY event_time DESC LIMIT 10"
    )

    mock_state = MockSessionState(
        api_key="",  # no API key
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,  # no date filter
        date_end=None,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("streamlit.warning"),
    ):
        # spinner must work as a context manager
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from app import _handle_direct_sql

        _handle_direct_sql(sql, tmp_duckdb)

    # last_sql must be the effective SQL (LIMIT replaced by row_limit)
    expected_sql = apply_row_limit(sql, DEFAULT_ROW_LIMIT)
    assert mock_state["last_sql"] == expected_sql
    assert mock_state["last_results"] is not None
    assert len(mock_state["last_results"]) == 3  # 3 rows from conftest fixture
    # Without an API key, summary should be empty
    assert mock_state["last_summary"] == ""
    # One assistant message must be appended
    assert len(mock_state["messages"]) == 1
    assert mock_state["messages"][0]["role"] == "assistant"
    # Query history must be updated
    assert len(mock_state["query_history"]) == 1


# ---------------------------------------------------------------------------
# Tests #DF-A / #DF-B — Date range filter
# ---------------------------------------------------------------------------


def test_session_state_has_date_filter_defaults():
    """Session state must include date_start and date_end keys defaulting to None.

    Test #DF-A: verifies that _init_session_state() creates date filter keys.
    """
    mock_state = {}
    with patch("streamlit.session_state", mock_state):
        from app import _init_session_state

        _init_session_state()

    assert "date_start" in mock_state, "Expected 'date_start' key in session state"
    assert "date_end" in mock_state, "Expected 'date_end' key in session state"
    assert mock_state["date_start"] is None
    assert mock_state["date_end"] is None


# ---------------------------------------------------------------------------
# Tests #AI-A / #AI-B / #AI-C — _analyze_current_results()
# ---------------------------------------------------------------------------


def test_analyze_current_results_sets_last_summary_without_appending_message():
    """_analyze_current_results() must store the analysis in last_summary only.

    Test #AI-A: The analysis result is displayed below the results table via
    last_summary, NOT appended to the chat message history.
    _analyze_current_results delegates to _analyze_entry_results for the last entry.
    """
    from report import ReportEntry
    from tests.conftest import MockSessionState

    results_df = pd.DataFrame(
        {"event_name": ["ConsoleLogin"], "aws_region": ["us-east-1"]}
    )
    sql = "SELECT event_name, aws_region FROM cloudtrail_events"
    entry = ReportEntry(sql=sql, results=results_df, analysis="")
    mock_state = MockSessionState(
        api_key="sk-test",
        model="gpt-5.4",
        messages=[],
        query_history=[entry],
        last_sql=sql,
        last_results=results_df,
        last_summary="",
        date_start=None,
        date_end=None,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("llm.OpenAI") as mock_openai_cls,
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_response = MagicMock()
        mock_response.choices[0].message.content = "• 1 ConsoleLogin event observed"
        mock_client.chat.completions.create.return_value = mock_response

        from handlers import _analyze_current_results

        _analyze_current_results()

    assert mock_state["last_summary"] == "• 1 ConsoleLogin event observed"
    # Analysis must NOT be added to the chat message history
    assert len(mock_state["messages"]) == 0


def test_analyze_current_results_no_api_key_appends_warning():
    """_analyze_current_results() must append a warning when no API key is set.

    Test #AI-B: verifies early-return behavior without an API key.
    generate_analysis must NOT be called.
    _analyze_current_results delegates to _analyze_entry_results for the last entry.
    """
    from report import ReportEntry
    from tests.conftest import MockSessionState

    results_df = pd.DataFrame({"a": [1]})
    entry = ReportEntry(sql="SELECT 1", results=results_df, analysis="")
    mock_state = MockSessionState(
        api_key="",
        model="gpt-5.4",
        messages=[],
        query_history=[entry],
        last_sql="SELECT 1",
        last_results=results_df,
        last_summary="",
        date_start=None,
        date_end=None,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("llm.OpenAI") as mock_openai_cls,
    ):
        from handlers import _analyze_current_results

        _analyze_current_results()

    mock_openai_cls.assert_not_called()
    assert len(mock_state["messages"]) == 1
    assert "API key" in mock_state["messages"][0]["content"]


def test_analyze_current_results_no_results_does_nothing():
    """_analyze_current_results() must be a no-op when last_results is None.

    Test #AI-C: verifies that nothing is appended when there are no results to analyse.
    """
    from tests.conftest import MockSessionState

    mock_state = MockSessionState(
        api_key="sk-test",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("llm.OpenAI") as mock_openai_cls,
    ):
        from handlers import _analyze_current_results

        _analyze_current_results()

    mock_openai_cls.assert_not_called()
    assert len(mock_state["messages"]) == 0


def test_handle_direct_sql_applies_date_filter_from_session_state(tmp_duckdb):
    """_handle_direct_sql stores date-filtered SQL when date_start/date_end are set.

    Test #DF-B: verifies that apply_date_filter is applied inside _handle_direct_sql
    when date_start and date_end are present in session state.
    """
    from tests.conftest import MockSessionState

    sql = "SELECT * FROM cloudtrail_events LIMIT 10"

    mock_state = MockSessionState(
        api_key="",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=date(2024, 1, 1),
        date_end=date(2024, 12, 31),
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("streamlit.warning"),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from app import _handle_direct_sql

        _handle_direct_sql(sql, tmp_duckdb)

    # The stored SQL must include the date filter CTE
    assert (
        "_ct_filtered" in mock_state["last_sql"]
    ), "Expected '_ct_filtered' CTE in last_sql when date filter is active"
    assert "2024-01-01" in mock_state["last_sql"]
    assert "2024-12-31" in mock_state["last_sql"]
    # All 3 rows must be returned (all are within 2024)
    assert mock_state["last_results"] is not None
    assert len(mock_state["last_results"]) == 3


# ---------------------------------------------------------------------------
# Tests #BANNER — Proposal 3: no-api-key guidance banner
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Tests #CTX — Proposal 1: conversation context retention
# ---------------------------------------------------------------------------


def test_session_state_has_conversation_context_default():
    """SESSION_STATE_DEFAULTS includes conversation_context defaulting to [].

    Test #CTX-1: verifies _init_session_state() creates the key.
    """
    mock_state = {}
    with patch("streamlit.session_state", mock_state):
        from app import _init_session_state

        _init_session_state()

    assert "conversation_context" in mock_state
    assert mock_state["conversation_context"] == []


def test_handle_user_query_passes_context_to_generate_sql(tmp_duckdb):
    """_handle_user_query() passes conversation_context to generate_sql.

    Test #CTX-2: verifies the context kwarg is forwarded correctly.
    """
    from tests.conftest import MockSessionState

    existing_context = [{"user_query": "prev", "sql": "SELECT 1", "summary": "test"}]
    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"
    result_df = pd.DataFrame({"event_name": ["CreateUser"]})

    mock_state = MockSessionState(
        api_key="sk-test",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
        conversation_context=list(existing_context),
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("handlers.generate_sql", return_value=sql) as mock_gen_sql,
        patch("handlers.execute_with_retry", return_value=(result_df, sql)),
        patch("handlers.generate_analysis", return_value="Test summary"),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from app import _handle_user_query

        _handle_user_query("Show me all events", tmp_duckdb)

    mock_gen_sql.assert_called_once_with(
        "Show me all events",
        api_key="sk-test",
        model="gpt-5.4",
        context=existing_context,
    )


def test_conversation_context_appended_after_successful_query(tmp_duckdb):
    """conversation_context gains a new entry after a successful query.

    Test #CTX-3: verifies the entry structure is correct.
    The sql field must contain the effective SQL (with row_limit applied).
    """
    from query import apply_row_limit
    from tests.conftest import MockSessionState

    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"
    result_df = pd.DataFrame({"event_name": ["CreateUser"]})

    mock_state = MockSessionState(
        api_key="sk-test",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
        conversation_context=[],
        row_limit=1000,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("handlers.generate_sql", return_value=sql),
        patch("handlers.execute_with_retry", return_value=(result_df, sql)),
        patch("handlers.generate_analysis", return_value="Test summary"),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from app import _handle_user_query

        _handle_user_query("Show me events", tmp_duckdb)

    assert len(mock_state["conversation_context"]) == 1
    entry = mock_state["conversation_context"][0]
    assert entry["user_query"] == "Show me events"
    # sql in context must be the effective SQL (LIMIT 5 replaced by row_limit=1000)
    assert entry["sql"] == apply_row_limit(sql, mock_state["row_limit"])
    assert entry["summary"] == "Test summary"


def test_conversation_context_max_size_enforced(tmp_duckdb):
    """conversation_context is trimmed to MAX_CONTEXT_TURNS after exceeding the limit.

    Test #CTX-4: oldest entries are dropped; the newest entry is at the end.
    """
    from tests.conftest import MockSessionState

    from app import MAX_CONTEXT_TURNS

    existing_context = [
        {"user_query": f"query {i}", "sql": f"SELECT {i}", "summary": f"summary {i}"}
        for i in range(MAX_CONTEXT_TURNS)
    ]

    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"
    result_df = pd.DataFrame({"event_name": ["CreateUser"]})

    mock_state = MockSessionState(
        api_key="sk-test",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
        conversation_context=list(existing_context),
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("handlers.generate_sql", return_value=sql),
        patch("handlers.execute_with_retry", return_value=(result_df, sql)),
        patch("handlers.generate_analysis", return_value="New summary"),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from app import _handle_user_query

        _handle_user_query("New query", tmp_duckdb)

    assert len(mock_state["conversation_context"]) == MAX_CONTEXT_TURNS
    assert mock_state["conversation_context"][-1]["user_query"] == "New query"
    assert mock_state["conversation_context"][0]["user_query"] == "query 1"


# ---------------------------------------------------------------------------
# Tests #RETRY — Proposal 2: SQL auto-correction retry loop in _handle_user_query
# ---------------------------------------------------------------------------


def test_handle_user_query_uses_execute_with_retry(tmp_duckdb):
    """_handle_user_query() calls execute_with_retry instead of execute_query directly.

    Test #RETRY-1: verifies the retry-capable path is used for AI-generated queries.
    """
    from tests.conftest import MockSessionState

    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"
    result_df = pd.DataFrame({"event_name": ["CreateUser"]})

    mock_state = MockSessionState(
        api_key="sk-test",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
        conversation_context=[],
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("handlers.generate_sql", return_value=sql),
        patch(
            "handlers.execute_with_retry", return_value=(result_df, sql)
        ) as mock_retry,
        patch("handlers.generate_analysis", return_value="Summary"),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from app import _handle_user_query

        _handle_user_query("Show me all events", tmp_duckdb)

    mock_retry.assert_called_once()


def test_handle_user_query_message_does_not_contain_summary(tmp_duckdb):
    """_handle_user_query() must NOT include the AI analysis in the chat message.

    Test #DUPL-1: the analysis is shown only in the 'AI Analysis' section of the
    query results history, not duplicated as 'Summary:' in the assistant message.
    The analysis must still be stored in query_history[-1].analysis.
    """
    from tests.conftest import MockSessionState

    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"
    result_df = pd.DataFrame({"event_name": ["CreateUser"]})

    mock_state = MockSessionState(
        api_key="sk-test",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
        conversation_context=[],
        row_limit=1000,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("handlers.generate_sql", return_value=sql),
        patch("handlers.execute_with_retry", return_value=(result_df, sql)),
        patch("handlers.generate_analysis", return_value="AI analysis text"),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from app import _handle_user_query

        _handle_user_query("Show me events", tmp_duckdb)

    content = mock_state["messages"][0]["content"]
    # Analysis must NOT appear in the chat message
    assert "AI analysis text" not in content
    assert "Summary:" not in content
    # Analysis must still be stored in query_history for the AI Analysis section
    assert mock_state["query_history"][0].analysis == "AI analysis text"
    # last_summary must be cleared (analysis is shown via query_history)
    assert mock_state["last_summary"] == ""


def test_handle_user_query_shows_retry_notice_in_chat(tmp_duckdb):
    """When SQL is auto-corrected, the assistant message contains a retry notice.

    Test #RETRY-2: verifies that a correction notice is appended when the
    final SQL differs from the originally generated SQL.
    """
    from tests.conftest import MockSessionState

    original_sql = "SELECT * FROM cloudtrail_events"
    corrected_sql = "SELECT event_name FROM cloudtrail_events LIMIT 10"
    result_df = pd.DataFrame({"event_name": ["CreateUser"]})

    mock_state = MockSessionState(
        api_key="sk-test",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
        conversation_context=[],
        row_limit=1000,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("handlers.generate_sql", return_value=original_sql),
        patch("handlers.execute_with_retry", return_value=(result_df, corrected_sql)),
        patch("handlers.generate_analysis", return_value="Summary"),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from app import _handle_user_query

        _handle_user_query("Show me all events", tmp_duckdb)

    assert len(mock_state["messages"]) == 1
    content = mock_state["messages"][0]["content"]
    assert "auto-corrected" in content


# ---------------------------------------------------------------------------
# Tests #RL — Row limit sidebar setting
# ---------------------------------------------------------------------------


def test_session_state_has_row_limit_default():
    """SESSION_STATE_DEFAULTS includes row_limit defaulting to DEFAULT_ROW_LIMIT.

    Test #RL-A1: verifies that _init_session_state() creates the row_limit key.
    """
    from query import DEFAULT_ROW_LIMIT

    mock_state = {}
    with patch("streamlit.session_state", mock_state):
        from app import _init_session_state

        _init_session_state()

    assert "row_limit" in mock_state, "Expected 'row_limit' key in session state"
    assert mock_state["row_limit"] == DEFAULT_ROW_LIMIT


def test_handle_direct_sql_uses_session_row_limit(tmp_duckdb):
    """_handle_direct_sql passes st.session_state.row_limit to execute_query.

    Test #RL-A2: verifies a custom row_limit from session state is forwarded
    instead of using the module-level DEFAULT_ROW_LIMIT constant.
    """
    from tests.conftest import MockSessionState

    sql = "SELECT * FROM cloudtrail_events LIMIT 10"

    mock_state = MockSessionState(
        api_key="",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
        row_limit=50,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("handlers.execute_query", return_value=pd.DataFrame()) as mock_exec,
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from app import _handle_direct_sql

        _handle_direct_sql(sql, tmp_duckdb)

    mock_exec.assert_called_once()
    assert mock_exec.call_args.kwargs.get("row_limit") == 50


def test_handle_user_query_uses_session_row_limit(tmp_duckdb):
    """_handle_user_query passes st.session_state.row_limit to execute_with_retry.

    Test #RL-A3: verifies a custom row_limit from session state is forwarded.
    """
    from tests.conftest import MockSessionState

    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"
    result_df = pd.DataFrame({"event_name": ["CreateUser"]})

    mock_state = MockSessionState(
        api_key="sk-test",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
        conversation_context=[],
        row_limit=200,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("handlers.generate_sql", return_value=sql),
        patch(
            "handlers.execute_with_retry", return_value=(result_df, sql)
        ) as mock_retry,
        patch("handlers.generate_analysis", return_value="Summary"),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from app import _handle_user_query

        _handle_user_query("Show me all events", tmp_duckdb)

    mock_retry.assert_called_once()
    assert mock_retry.call_args.kwargs.get("row_limit") == 200


# ---------------------------------------------------------------------------
# Tests #RERUN — Edit & Re-run SQL without API key
# ---------------------------------------------------------------------------


def test_handle_edit_rerun_sql_no_api_key_executes_sql(tmp_duckdb):
    """Edit & Re-run SQL must execute successfully even when no API key is configured.

    Test #RERUN-1: generate_analysis must NOT be called, results and query_history
    must be populated, and one assistant message must be appended.
    """
    from tests.conftest import MockSessionState

    sql = (
        "SELECT event_time, event_name, aws_region "
        "FROM cloudtrail_events ORDER BY event_time DESC LIMIT 10"
    )

    mock_state = MockSessionState(
        api_key="",  # no API key
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql=sql,
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
        row_limit=1000,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("handlers.generate_analysis") as mock_gen_analysis,
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from handlers import _handle_edit_rerun_sql

        _handle_edit_rerun_sql(sql, tmp_duckdb)

    # generate_analysis must NOT be called when no API key is present
    mock_gen_analysis.assert_not_called()
    # Results must be populated
    assert mock_state["last_results"] is not None
    assert len(mock_state["last_results"]) == 3  # 3 rows in conftest fixture
    # One assistant message must be appended
    assert len(mock_state["messages"]) == 1
    assert mock_state["messages"][0]["role"] == "assistant"
    # Query history must be updated
    assert len(mock_state["query_history"]) == 1
    # Summary must be empty (no analysis without API key)
    assert mock_state["query_history"][0].analysis == ""


def test_handle_edit_rerun_sql_with_api_key_calls_generate_analysis(tmp_duckdb):
    """Edit & Re-run SQL must call generate_analysis when an API key is present.

    Test #RERUN-2: analysis must be stored in the assistant message and query_history.
    """
    from tests.conftest import MockSessionState

    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"

    mock_state = MockSessionState(
        api_key="sk-test",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql=sql,
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
        row_limit=1000,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("handlers.generate_analysis", return_value="AI summary here") as mock_gen,
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from handlers import _handle_edit_rerun_sql

        _handle_edit_rerun_sql(sql, tmp_duckdb)

    # generate_analysis must be called with API key present
    mock_gen.assert_called_once()
    # Summary must NOT appear in the assistant chat message (shown only in AI Analysis section)
    assert "AI summary here" not in mock_state["messages"][0]["content"]
    assert "Summary:" not in mock_state["messages"][0]["content"]
    # Analysis must be stored in query_history to be shown in the AI Analysis section
    assert mock_state["query_history"][0].analysis == "AI summary here"


def test_handle_edit_rerun_sql_error_appends_error_message(tmp_duckdb):
    """Edit & Re-run SQL must append an error message on query failure.

    Test #RERUN-3: verifies graceful error handling — no results in query_history.
    """
    from tests.conftest import MockSessionState

    bad_sql = "SELECT * FROM nonexistent_table"

    mock_state = MockSessionState(
        api_key="",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql=bad_sql,
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
        row_limit=1000,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from handlers import _handle_edit_rerun_sql

        _handle_edit_rerun_sql(bad_sql, tmp_duckdb)

    # An error message must be appended
    assert len(mock_state["messages"]) == 1
    assert mock_state["messages"][0]["role"] == "assistant"
    assert (
        "error" in mock_state["messages"][0]["content"].lower()
        or "validation" in mock_state["messages"][0]["content"].lower()
    )
    # No entry must be added to query_history on failure
    assert len(mock_state["query_history"]) == 0


# ---------------------------------------------------------------------------
# Tests #DESC — Preset description displayed in Query Results History
# ---------------------------------------------------------------------------


def test_report_entry_has_description_field():
    """ReportEntry must accept an optional description field.

    Test #DESC-1: verifies that the description field is accessible and defaults
    to an empty string when not provided.
    """
    import pandas as pd

    from report import ReportEntry

    entry = ReportEntry(sql="SELECT 1", results=pd.DataFrame())
    assert hasattr(entry, "description"), "ReportEntry must have a 'description' field"
    assert entry.description == ""

    entry_with_desc = ReportEntry(
        sql="SELECT 1",
        results=pd.DataFrame(),
        description="Detects root account usage",
    )
    assert entry_with_desc.description == "Detects root account usage"


def test_handle_direct_sql_stores_description_in_query_history(tmp_duckdb):
    """_handle_direct_sql() must store the description in the ReportEntry.

    Test #DESC-2: verifies that when a description is passed to _handle_direct_sql,
    it is persisted in query_history[0].description.
    """
    from tests.conftest import MockSessionState

    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"
    desc = "List all root account API calls"

    mock_state = MockSessionState(
        api_key="",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("streamlit.warning"),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from handlers import _handle_direct_sql

        _handle_direct_sql(sql, tmp_duckdb, description=desc)

    assert len(mock_state["query_history"]) == 1
    assert mock_state["query_history"][0].description == desc


def test_handle_direct_sql_description_defaults_to_empty(tmp_duckdb):
    """_handle_direct_sql() description defaults to empty string when omitted.

    Test #DESC-3: backward-compatible behavior — existing callers are unaffected.
    """
    from tests.conftest import MockSessionState

    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"

    mock_state = MockSessionState(
        api_key="",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("streamlit.warning"),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from handlers import _handle_direct_sql

        _handle_direct_sql(sql, tmp_duckdb)

    assert len(mock_state["query_history"]) == 1
    assert mock_state["query_history"][0].description == ""


def test_truncation_message_shows_session_row_limit(tmp_duckdb):
    """Direct SQL truncation notice uses st.session_state.row_limit, not DEFAULT_ROW_LIMIT.

    Test #RL-A4: result count >= row_limit triggers the truncation message
    which must contain the session row_limit value (not the hard-coded 1000).
    """
    from tests.conftest import MockSessionState

    custom_limit = 777  # Unique value distinct from DEFAULT_ROW_LIMIT (200)
    # Return exactly custom_limit rows so truncation is detected.
    result_df = pd.DataFrame({"event_name": ["A"] * custom_limit})

    sql = "SELECT * FROM cloudtrail_events"
    mock_state = MockSessionState(
        api_key="",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
        row_limit=custom_limit,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("handlers.execute_query", return_value=result_df),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from app import _handle_direct_sql

        _handle_direct_sql(sql, tmp_duckdb)

    assert len(mock_state["messages"]) == 1
    content = mock_state["messages"][0]["content"]
    # The truncation notice must contain the session row_limit (777), not 1,000.
    # Before the fix, truncated = len(results) >= DEFAULT_ROW_LIMIT (200) → False,
    # so no truncation notice is emitted and "truncated to 777" is absent.
    assert "truncated to 777" in content


# ---------------------------------------------------------------------------
# Tests #CHART — render_chart() visualisation
# ---------------------------------------------------------------------------


def test_render_chart_type_none_skips_all_rendering():
    """render_chart() with type='none' must not call st.plotly_chart or st.bar_chart.

    Test #CHART-1: explicit opt-out must suppress chart rendering entirely.
    """
    df = pd.DataFrame({"event_name": ["CreateUser"], "count": [5]})
    config = {"type": "none"}
    with (
        patch("streamlit.plotly_chart") as mock_plotly,
        patch("streamlit.bar_chart") as mock_bar,
    ):
        from app import render_chart

        render_chart(df, config)

    mock_plotly.assert_not_called()
    mock_bar.assert_not_called()


def test_render_chart_type_bar_calls_plotly_chart():
    """render_chart() with type='bar' must invoke st.plotly_chart inside an expander.

    Test #CHART-2: verifies Plotly Express horizontal bar chart rendering path.
    """
    df = pd.DataFrame(
        {"event_name": ["CreateUser", "DeleteUser"], "api_count": [10, 5]}
    )
    config = {"type": "bar", "x": "event_name", "y": ["api_count"]}
    with (
        patch("streamlit.plotly_chart") as mock_plotly,
        patch("streamlit.expander") as mock_expander,
    ):
        mock_expander.return_value.__enter__ = MagicMock(return_value=None)
        mock_expander.return_value.__exit__ = MagicMock(return_value=False)

        from app import render_chart

        render_chart(df, config)

    mock_plotly.assert_called_once()


def test_render_chart_type_timeseries_calls_line_chart():
    """render_chart() with type='timeseries' must bucket event_time and call st.line_chart.

    Test #CHART-3: line chart is more appropriate than bar chart for time-series data
    because it clearly shows trends and continuity over time.
    """
    df = pd.DataFrame(
        {
            "event_time": pd.to_datetime(["2024-01-01", "2024-01-01", "2024-01-02"]),
            "event_name": ["A", "B", "C"],
        }
    )
    config = {"type": "timeseries", "bucket": "day"}
    with (
        patch("streamlit.line_chart") as mock_line,
        patch("streamlit.expander") as mock_expander,
    ):
        mock_expander.return_value.__enter__ = MagicMock(return_value=None)
        mock_expander.return_value.__exit__ = MagicMock(return_value=False)

        from app import render_chart

        render_chart(df, config)

    mock_line.assert_called_once()


def test_render_chart_timeseries_single_bucket_skips():
    """render_chart() with type='timeseries' and only one distinct date must skip.

    Test #CHART-4: a single-bar chart provides no visual value.
    """
    df = pd.DataFrame(
        {
            "event_time": pd.to_datetime(["2024-01-01", "2024-01-01"]),
            "event_name": ["A", "B"],
        }
    )
    config = {"type": "timeseries", "bucket": "day"}
    with (
        patch("streamlit.bar_chart") as mock_bar,
        patch("streamlit.expander"),
    ):
        from app import render_chart

        render_chart(df, config)

    mock_bar.assert_not_called()


def test_render_chart_timeseries_no_event_time_skips():
    """render_chart() with type='timeseries' but no event_time column must skip.

    Test #CHART-5: guards against schema mismatches.
    """
    df = pd.DataFrame({"event_name": ["A", "B"], "count": [1, 2]})
    config = {"type": "timeseries"}
    with (
        patch("streamlit.bar_chart") as mock_bar,
        patch("streamlit.plotly_chart") as mock_plotly,
    ):
        from app import render_chart

        render_chart(df, config)

    mock_bar.assert_not_called()
    mock_plotly.assert_not_called()


def test_render_chart_auto_with_numeric_calls_plotly_chart():
    """render_chart() with config=None and a numeric column must call st.plotly_chart.

    Test #CHART-6: auto-detection path falls back to Plotly bar chart.
    """
    df = pd.DataFrame({"event_name": ["A", "B"], "count": [3, 7]})
    with (
        patch("streamlit.plotly_chart") as mock_plotly,
        patch("streamlit.expander") as mock_expander,
    ):
        mock_expander.return_value.__enter__ = MagicMock(return_value=None)
        mock_expander.return_value.__exit__ = MagicMock(return_value=False)

        from app import render_chart

        render_chart(df, None)

    mock_plotly.assert_called_once()


def test_render_chart_auto_without_numeric_skips():
    """render_chart() with config=None and no numeric columns must not render a chart.

    Test #CHART-7: pure-text result sets should not produce an empty chart.
    """
    df = pd.DataFrame({"event_name": ["A", "B"], "region": ["us-east-1", "us-west-2"]})
    with (
        patch("streamlit.plotly_chart") as mock_plotly,
        patch("streamlit.bar_chart") as mock_bar,
    ):
        from app import render_chart

        render_chart(df, None)

    mock_plotly.assert_not_called()
    mock_bar.assert_not_called()


def test_handle_direct_sql_stores_chart_config_in_report_entry(tmp_duckdb):
    """_handle_direct_sql() must persist chart_config into the ReportEntry.

    Test #CHART-8: verifies the chart_config kwarg is threaded through to query_history.
    """
    from tests.conftest import MockSessionState

    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"
    chart_config = {"type": "bar", "x": "event_name", "y": ["count"]}

    mock_state = MockSessionState(
        api_key="",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("streamlit.warning"),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from handlers import _handle_direct_sql

        _handle_direct_sql(sql, tmp_duckdb, chart_config=chart_config)

    assert len(mock_state["query_history"]) == 1
    assert mock_state["query_history"][0].chart_config == chart_config


def test_handle_direct_sql_chart_config_defaults_to_none(tmp_duckdb):
    """_handle_direct_sql() must store None for chart_config when not provided.

    Test #CHART-9: backward-compatible — existing callers are unaffected.
    """
    from tests.conftest import MockSessionState

    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"

    mock_state = MockSessionState(
        api_key="",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("streamlit.warning"),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from handlers import _handle_direct_sql

        _handle_direct_sql(sql, tmp_duckdb)

    assert mock_state["query_history"][0].chart_config is None


def test_builtin_hunts_chart_field_valid_types():
    """All chart fields in builtin_hunts.yaml must have valid type values.

    Test #CHART-10: prevents typos in the chart.type enum from shipping.
    """
    from app import _load_builtin_prompts

    valid_types = {"bar", "timeseries", "none"}
    prompts = _load_builtin_prompts()
    for entry in prompts:
        chart = entry.get("chart")
        if chart is not None:
            assert isinstance(
                chart, dict
            ), f"chart must be a dict in {entry['label']!r}"
            chart_type = chart.get("type")
            assert (
                chart_type in valid_types
            ), f"chart.type {chart_type!r} not in {valid_types} for {entry['label']!r}"


# ---------------------------------------------------------------------------
# Tests #INTERLEAVE — query_index links messages to query_history entries
# ---------------------------------------------------------------------------


def test_handle_direct_sql_success_adds_query_index_to_message(tmp_duckdb):
    """_handle_direct_sql() must set query_index on the assistant message on success.

    Test #INTERLEAVE-1: the query_index must equal the index of the newly appended
    query_history entry so the UI can render results inline after the message.
    """
    from tests.conftest import MockSessionState

    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"

    mock_state = MockSessionState(
        api_key="",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("streamlit.warning"),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from handlers import _handle_direct_sql

        _handle_direct_sql(sql, tmp_duckdb)

    assert len(mock_state["messages"]) == 1
    assert mock_state["messages"][0].get("query_index") == 0


def test_handle_direct_sql_error_does_not_add_query_index(tmp_duckdb):
    """_handle_direct_sql() must NOT set query_index when the query fails.

    Test #INTERLEAVE-2: error messages must not carry a query_index because no
    query_history entry is appended on failure.
    """
    from tests.conftest import MockSessionState

    bad_sql = "SELECT * FROM nonexistent_table_xyz"

    mock_state = MockSessionState(
        api_key="",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from handlers import _handle_direct_sql

        _handle_direct_sql(bad_sql, tmp_duckdb)

    assert len(mock_state["messages"]) == 1
    assert mock_state["messages"][0].get("query_index") is None


def test_handle_user_query_success_adds_query_index_to_message(tmp_duckdb):
    """_handle_user_query() must set query_index on the assistant message on success.

    Test #INTERLEAVE-3: verifies the interleaved rendering link for AI-generated queries.
    """
    from tests.conftest import MockSessionState

    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"
    result_df = pd.DataFrame({"event_name": ["CreateUser"]})

    mock_state = MockSessionState(
        api_key="sk-test",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
        conversation_context=[],
        row_limit=1000,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("handlers.generate_sql", return_value=sql),
        patch("handlers.execute_with_retry", return_value=(result_df, sql)),
        patch("handlers.generate_analysis", return_value="Summary"),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from handlers import _handle_user_query

        _handle_user_query("Show me events", tmp_duckdb)

    assert len(mock_state["messages"]) == 1
    assert mock_state["messages"][0].get("query_index") == 0


def test_handle_edit_rerun_sql_success_adds_query_index_to_message(tmp_duckdb):
    """_handle_edit_rerun_sql() must set query_index on the assistant message on success.

    Test #INTERLEAVE-4: verifies the interleaved rendering link for edited SQL queries.
    """
    from tests.conftest import MockSessionState

    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"

    mock_state = MockSessionState(
        api_key="",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql=sql,
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
        row_limit=1000,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from handlers import _handle_edit_rerun_sql

        _handle_edit_rerun_sql(sql, tmp_duckdb)

    assert len(mock_state["messages"]) == 1
    assert mock_state["messages"][0].get("query_index") == 0


def test_query_index_increments_across_multiple_queries(tmp_duckdb):
    """query_index must reflect the correct position after multiple successful queries.

    Test #INTERLEAVE-5: the second message's query_index must be 1, not 0.
    """
    from tests.conftest import MockSessionState

    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"

    mock_state = MockSessionState(
        api_key="",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("streamlit.warning"),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from handlers import _handle_direct_sql

        _handle_direct_sql(sql, tmp_duckdb)
        _handle_direct_sql(sql, tmp_duckdb)

    assert len(mock_state["messages"]) == 2
    assert mock_state["messages"][0].get("query_index") == 0
    assert mock_state["messages"][1].get("query_index") == 1


# ---------------------------------------------------------------------------
# Tests #UI-01 — analyst_notes session state default
# ---------------------------------------------------------------------------


def test_session_state_has_analyst_notes_default():
    """SESSION_STATE_DEFAULTS must include analyst_notes defaulting to empty dict.

    Test #UI-01-S1: verifies _init_session_state() creates the key.
    """
    mock_state = {}
    with patch("streamlit.session_state", mock_state):
        from app import _init_session_state

        _init_session_state()

    assert (
        "analyst_notes" in mock_state
    ), "Expected 'analyst_notes' key in session state"
    assert mock_state["analyst_notes"] == {}


# ---------------------------------------------------------------------------
# Tests #UI-04 — bulk_progress session state default
# ---------------------------------------------------------------------------


def test_session_state_has_bulk_progress_default():
    """SESSION_STATE_DEFAULTS must include bulk_progress defaulting to None.

    Test #UI-04-1: verifies _init_session_state() creates the key.
    """
    mock_state = {}
    with patch("streamlit.session_state", mock_state):
        from app import _init_session_state

        _init_session_state()

    assert (
        "bulk_progress" in mock_state
    ), "Expected 'bulk_progress' key in session state"
    assert mock_state["bulk_progress"] is None


# ---------------------------------------------------------------------------
# Tests #UI-02 — label/category passed through _handle_direct_sql
# ---------------------------------------------------------------------------


def test_handle_direct_sql_stores_label_and_category_in_query_history(tmp_duckdb):
    """_handle_direct_sql() must store label and category in the ReportEntry.

    Test #UI-02-H1: verifies label/category kwargs are threaded to query_history.
    """
    from tests.conftest import MockSessionState

    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"

    mock_state = MockSessionState(
        api_key="",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("streamlit.warning"),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from handlers import _handle_direct_sql

        _handle_direct_sql(
            sql,
            tmp_duckdb,
            label="🔑 Root Account Activity",
            category="🔑 Identity & Access",
        )

    assert mock_state["query_history"][0].label == "🔑 Root Account Activity"
    assert mock_state["query_history"][0].category == "🔑 Identity & Access"


def test_export_session_includes_analyst_note():
    """_export_session() must include analyst_note in each query entry.

    Test #UI-01-S2: notes must survive JSON export for re-import.
    """
    from app import _export_session
    from report import ReportEntry

    entry = ReportEntry(
        sql="SELECT 1",
        results=pd.DataFrame({"a": [1]}),
        analyst_note="Important finding here.",
    )
    result = _export_session([entry], title="Test Hunt")
    parsed = json.loads(result)
    assert parsed["queries"][0]["analyst_note"] == "Important finding here."


def test_export_session_analyst_note_defaults_to_empty():
    """_export_session() must export empty string when no analyst_note is set.

    Test #UI-01-S3: backward-compatible — existing sessions without notes work.
    """
    from app import _export_session
    from report import ReportEntry

    entry = ReportEntry(sql="SELECT 1", results=pd.DataFrame())
    result = _export_session([entry], title="Test Hunt")
    parsed = json.loads(result)
    assert parsed["queries"][0]["analyst_note"] == ""


# ---------------------------------------------------------------------------
# Tests #UI-BADGE — _result_badge and _build_expander_title
# ---------------------------------------------------------------------------


def test_result_badge_no_results():
    """_result_badge returns '⬜ no results' for empty DataFrame.

    Test #UI-BADGE-1: collapsed card shows no-results state at a glance.
    """
    from app import _result_badge
    from report import ReportEntry

    entry = ReportEntry(sql="SELECT 1", results=pd.DataFrame())
    mock_state = {"row_limit": 500}
    with patch("streamlit.session_state", mock_state):
        badge = _result_badge(entry)
    assert badge == "⬜ no results"


def test_result_badge_with_results_below_limit():
    """_result_badge returns '✅ N rows' when results are below the row limit.

    Test #UI-BADGE-2: green badge for normal result sets.
    """
    from app import _result_badge
    from report import ReportEntry

    entry = ReportEntry(
        sql="SELECT 1", results=pd.DataFrame({"event_name": ["A", "B", "C"]})
    )
    mock_state = {"row_limit": 500}
    with patch("streamlit.session_state", mock_state):
        badge = _result_badge(entry)
    assert badge == "✅ 3 rows"


def test_result_badge_at_row_limit():
    """_result_badge returns '⚠️ N rows' when results equal the row limit.

    Test #UI-BADGE-3: warning badge signals possible truncation.
    """
    from app import _result_badge
    from report import ReportEntry

    entry = ReportEntry(
        sql="SELECT 1",
        results=pd.DataFrame({"event_name": ["A"] * 500}),
    )
    mock_state = {"row_limit": 500}
    with patch("streamlit.session_state", mock_state):
        badge = _result_badge(entry)
    assert badge == "⚠️ 500 rows"


def test_build_expander_title_with_label_and_category():
    """_build_expander_title includes category, label, and result badge.

    Test #UI-BADGE-4: full title format for preset queries.
    """
    from app import _build_expander_title
    from report import ReportEntry

    entry = ReportEntry(
        sql="SELECT 1",
        results=pd.DataFrame({"event_name": ["A"]}),
        label="🔑 Root Account Activity",
        category="🔑 Identity & Access",
    )
    mock_state = {"row_limit": 500}
    with patch("streamlit.session_state", mock_state):
        title = _build_expander_title(entry, 1)
    assert "🔑 Identity & Access" in title
    assert "🔑 Root Account Activity" in title
    assert "✅ 1 rows" in title
    assert "│" in title


def test_build_expander_title_no_label_fallback():
    """_build_expander_title falls back to 'Query #N' when label is empty.

    Test #UI-BADGE-5: backward-compatible for AI-generated queries.
    """
    from app import _build_expander_title
    from report import ReportEntry

    entry = ReportEntry(sql="SELECT 1", results=pd.DataFrame())
    mock_state = {"row_limit": 500}
    with patch("streamlit.session_state", mock_state):
        title = _build_expander_title(entry, 3)
    assert "Query #3" in title
    assert "⬜ no results" in title


# ---------------------------------------------------------------------------
# Tests #UI-FILTER — _apply_entry_filter
# ---------------------------------------------------------------------------


def _make_entry(
    has_results: bool, label: str = "", category: str = "", description: str = ""
):
    """Helper: create a ReportEntry with or without results."""
    from report import ReportEntry

    results = pd.DataFrame({"a": [1]}) if has_results else pd.DataFrame()
    return ReportEntry(
        sql="SELECT 1",
        results=results,
        label=label,
        category=category,
        description=description,
    )


def test_apply_entry_filter_all_returns_all():
    """_apply_entry_filter with 'All' returns all entries unchanged.

    Test #UI-FILTER-1: no filter applied.
    """
    from app import _apply_entry_filter

    entries = [(0, _make_entry(True)), (1, _make_entry(False)), (2, _make_entry(True))]
    result = _apply_entry_filter(entries, "All", "")
    assert len(result) == 3


def test_apply_entry_filter_results_only():
    """_apply_entry_filter with '✅ Results' keeps only entries with rows.

    Test #UI-FILTER-2: entries without results are excluded.
    """
    from app import _apply_entry_filter

    entries = [(0, _make_entry(True)), (1, _make_entry(False)), (2, _make_entry(True))]
    result = _apply_entry_filter(entries, "✅ Results", "")
    assert len(result) == 2
    assert all(not e.results.empty for _, e in result)


def test_apply_entry_filter_no_results_only():
    """_apply_entry_filter with '⬜ No results' keeps only empty entries.

    Test #UI-FILTER-3: entries with results are excluded.
    """
    from app import _apply_entry_filter

    entries = [(0, _make_entry(True)), (1, _make_entry(False)), (2, _make_entry(True))]
    result = _apply_entry_filter(entries, "⬜ No results", "")
    assert len(result) == 1
    assert result[0][1].results.empty


def test_apply_entry_filter_keyword_match():
    """_apply_entry_filter with keyword keeps entries matching label/category/description.

    Test #UI-FILTER-4: keyword filter is case-insensitive.
    """
    from app import _apply_entry_filter

    entries = [
        (0, _make_entry(True, label="Root Account Activity", category="Identity")),
        (1, _make_entry(True, label="S3 Bucket Access", category="Storage")),
        (2, _make_entry(False, label="MFA Disabled", category="Identity")),
    ]
    result = _apply_entry_filter(entries, "All", "identity")
    assert len(result) == 2
    labels = [e.label for _, e in result]
    assert "Root Account Activity" in labels
    assert "MFA Disabled" in labels


def test_apply_entry_filter_keyword_no_match():
    """_apply_entry_filter returns empty list when keyword matches nothing.

    Test #UI-FILTER-5: no entries match an unknown keyword.
    """
    from app import _apply_entry_filter

    entries = [
        (0, _make_entry(True, label="Root Account Activity")),
        (1, _make_entry(True, label="S3 Bucket Access")),
    ]
    result = _apply_entry_filter(entries, "All", "nonexistent_xyz")
    assert result == []


def test_apply_entry_filter_combined_result_and_keyword():
    """_apply_entry_filter applies both result filter and keyword together.

    Test #UI-FILTER-6: combined filter narrows results correctly.
    """
    from app import _apply_entry_filter

    entries = [
        (0, _make_entry(True, label="Root Account Activity", category="Identity")),
        (1, _make_entry(False, label="MFA Disabled", category="Identity")),
        (2, _make_entry(True, label="S3 Access", category="Storage")),
    ]
    # Results only + keyword "identity" → only index 0
    result = _apply_entry_filter(entries, "✅ Results", "identity")
    assert len(result) == 1
    assert result[0][1].label == "Root Account Activity"
