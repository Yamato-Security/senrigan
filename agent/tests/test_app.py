"""Tests for the Streamlit app entry point (app.py).

The session-state lifecycle moved to ``test_session.py`` and chart rendering to
``test_charts.py`` when those helpers left ``app.py``; what remains here is the
query handlers driven from the page plus the result-card and filter widgets.

Tests #23-#25: built-in hunt YAML structure and Direct SQL execution.
Tests #DF-B: date range filter applied by _handle_direct_sql.
Tests #CTX: conversation context retention (Proposal 1).
Tests #RETRY: SQL auto-correction retry loop (Proposal 2).
Tests #BANNER: no-api-key guidance banner (Proposal 3).
"""

from datetime import date
from unittest.mock import MagicMock, patch

import duckdb
import pandas as pd
import pytest

from profiles import CLOUDTRAIL_PROFILE, SUZAKU_TIMELINE_PROFILE
from tests.conftest import MockSessionState


def test_model_options_include_gpt_5_5():
    """gpt-5.5 must appear in the available model options list.

    Verifies that the recently released gpt-5.5 model is present in
    the MODEL_OPTIONS constant used for the sidebar dropdown.
    """
    from app import MODEL_OPTIONS

    assert (
        "gpt-5.5" in MODEL_OPTIONS
    ), f"gpt-5.5 not found in MODEL_OPTIONS: {MODEL_OPTIONS}"


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
    from query import DEFAULT_ROW_LIMIT, apply_row_limit
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


# ---------------------------------------------------------------------------
# Tests #AI-A / #AI-B / #AI-C — _analyze_entry_results()
# ---------------------------------------------------------------------------


def test_analyze_entry_results_sets_last_summary_without_appending_message():
    """_analyze_entry_results() must store the analysis in last_summary only.

    Test #AI-A: The analysis result is displayed below the results table via
    last_summary (when the entry is the last one), NOT appended to the chat
    message history.
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

        from handlers import _analyze_entry_results

        _analyze_entry_results(0)

    assert mock_state["last_summary"] == "• 1 ConsoleLogin event observed"
    # Analysis must NOT be added to the chat message history
    assert len(mock_state["messages"]) == 0


def test_analyze_entry_results_no_api_key_appends_warning():
    """_analyze_entry_results() must append a warning when no API key is set.

    Test #AI-B: verifies early-return behavior without an API key.
    generate_analysis must NOT be called.
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
        from handlers import _analyze_entry_results

        _analyze_entry_results(0)

    mock_openai_cls.assert_not_called()
    assert len(mock_state["messages"]) == 1
    assert "API key" in mock_state["messages"][0]["content"]


def test_analyze_entry_results_empty_results_does_nothing():
    """_analyze_entry_results() must be a no-op when the entry has no results.

    Test #AI-C: verifies that nothing is analysed or appended when the entry's
    results DataFrame is empty.
    """
    from report import ReportEntry
    from tests.conftest import MockSessionState

    entry = ReportEntry(sql="SELECT 1", results=pd.DataFrame(), analysis="")
    mock_state = MockSessionState(
        api_key="sk-test",
        model="gpt-5.4",
        messages=[],
        query_history=[entry],
        last_sql="SELECT 1",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("llm.OpenAI") as mock_openai_cls,
    ):
        from handlers import _analyze_entry_results

        _analyze_entry_results(0)

    mock_openai_cls.assert_not_called()
    assert len(mock_state["messages"]) == 0
    assert entry.analysis == ""


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
        # The dataset profile selects the table and system prompt; the
        # CloudTrail page always passes its own (see profiles.py).
        profile=CLOUDTRAIL_PROFILE,
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
    from app import MAX_CONTEXT_TURNS
    from tests.conftest import MockSessionState

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


# ---------------------------------------------------------------------------
# Tests #UI-04 — bulk_progress session state default
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Tests #GEO-1 / #GEO-2 / #GEO-3 — automatic geo enrichment in handlers
# ---------------------------------------------------------------------------


def _geo_mock_state(**overrides):
    """Session state for the geo-enrichment handler tests."""
    from tests.conftest import MockSessionState

    defaults = {
        "api_key": "",
        "model": "gpt-5.4",
        "messages": [],
        "query_history": [],
        "last_sql": "",
        "last_results": None,
        "last_summary": "",
        "date_start": None,
        "date_end": None,
    }
    defaults.update(overrides)
    return MockSessionState(**defaults)


def test_handle_direct_sql_enriches_ip_results_with_geo(tmp_duckdb_geo):
    """Test #GEO-1: results with an IP column gain geo columns (toggle default ON)."""
    sql = (
        "SELECT event_name, source_ip_address "
        "FROM cloudtrail_events ORDER BY event_time LIMIT 10"
    )
    mock_state = _geo_mock_state()

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from handlers import _handle_direct_sql

        _handle_direct_sql(sql, tmp_duckdb_geo)

    entry = mock_state["query_history"][0]
    assert "geo_country_code" in entry.results.columns
    assert entry.results["geo_country_code"].tolist() == ["US", "JP"]
    assert mock_state["last_results"] is entry.results


def test_handle_direct_sql_geo_toggle_off_skips_enrichment(tmp_duckdb_geo):
    """Test #GEO-2: geo_enrich=False must leave results untouched."""
    sql = "SELECT event_name, source_ip_address FROM cloudtrail_events LIMIT 10"
    mock_state = _geo_mock_state(geo_enrich=False)

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from handlers import _handle_direct_sql

        _handle_direct_sql(sql, tmp_duckdb_geo)

    entry = mock_state["query_history"][0]
    assert "geo_country_code" not in entry.results.columns


def test_handle_direct_sql_enrichment_failure_keeps_results(tmp_duckdb_geo):
    """Test #GEO-3: a failing enrichment must never fail the query itself."""
    sql = "SELECT event_name, source_ip_address FROM cloudtrail_events LIMIT 10"
    mock_state = _geo_mock_state()

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("handlers.enrich_with_geo", side_effect=RuntimeError("boom")),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from handlers import _handle_direct_sql

        _handle_direct_sql(sql, tmp_duckdb_geo)

    entry = mock_state["query_history"][0]
    assert len(entry.results) == 2
    assert "geo_country_code" not in entry.results.columns


# ---------------------------------------------------------------------------
# Query filter bar — the "✕ Clear" button
# ---------------------------------------------------------------------------


class _WidgetLockedState(MockSessionState):
    """Session state that enforces Streamlit's widget-key write rule.

    Streamlit raises ``StreamlitAPIException`` when a script assigns to the
    session-state key of a widget that has already been instantiated in the same
    run. The real object enforces it; a plain dict does not, which is how the
    "✕ Clear" button shipped writing to both filter keys after rendering them.
    """

    def instantiate(self, key: str) -> None:
        """Record that a widget with *key* was rendered in this run."""
        self.setdefault("_instantiated", set()).add(key)

    def __setitem__(self, key, value) -> None:  # type: ignore[override]
        if key in self.get("_instantiated", set()):
            raise RuntimeError(
                f"st.session_state.{key} cannot be modified after the widget "
                f"with key {key} is instantiated."
            )
        super().__setitem__(key, value)


@pytest.mark.parametrize(
    "profile", [CLOUDTRAIL_PROFILE, SUZAKU_TIMELINE_PROFILE], ids=lambda p: p.key
)
def test_clear_button_resets_filters_without_writing_live_widget_keys(profile):
    """The Clear button must reset through a callback, not an inline assignment.

    Assigning to a widget's key after that widget has been rendered is a
    Streamlit error, so the reset has to happen in ``on_click`` — which runs
    before the next script run instantiates the widgets.
    """
    from app import _render_query_filter

    prefix = profile.key
    result_key = f"_{prefix}_qf_result_filter"
    keyword_key = f"_{prefix}_qf_keyword"
    state = _WidgetLockedState(**{result_key: "✅ Results", keyword_key: "root"})
    captured: dict = {}

    def _widget(*_args, key=None, **_kwargs):
        state.instantiate(key)
        return state.get(key)

    def _button(*_args, key=None, **kwargs):
        state.instantiate(key)
        captured.update(kwargs)
        return True  # the analyst clicked Clear

    column = MagicMock()
    column.__enter__ = MagicMock(return_value=column)
    column.__exit__ = MagicMock(return_value=False)

    with (
        patch("streamlit.session_state", state),
        patch("streamlit.columns", return_value=(column, column, column)),
        patch("streamlit.subheader"),
        patch("streamlit.radio", _widget),
        patch("streamlit.text_input", _widget),
        patch("streamlit.button", _button),
        patch("streamlit.rerun") as mock_rerun,
    ):
        _render_query_filter(profile)

        # Rendering must not have touched the keys of its own widgets.
        assert state[result_key] == "✅ Results"
        assert state[keyword_key] == "root"

        # Clicking a button already reruns the script; an explicit rerun inside
        # the click branch would only re-raise the same error one run later.
        mock_rerun.assert_not_called()

        # The callback is what does the reset, and it runs before the widgets
        # of the next run exist.
        state.pop("_instantiated", None)
        captured["on_click"](*captured.get("args", ()))

    assert state[result_key] == "All"
    assert state[keyword_key] == ""


# ---------------------------------------------------------------------------
# Sidebar database section — which DuckDB file the CloudTrail page reads
# ---------------------------------------------------------------------------


def _render_db_section(profile, **env):
    """Render the sidebar database section and report what it drew.

    ``format_func`` is applied inside the render because it resolves paths from
    the environment, which is only patched for the duration of the call.

    Args:
        profile: Dataset profile the section is rendered for.
        env:     Environment variables for the render, plus an optional
                 ``variant`` seeding the session's current selection.

    Returns:
        ``(state, subheader, options, labels, captions)`` for the render, where
        *options* are the pulldown's values and *labels* what it displays.
    """
    from app import _render_db_variant_section
    from config import DB_VARIANT_FULL

    state = MockSessionState(db_variant=env.pop("variant", DB_VARIANT_FULL))
    options: list[str] = []
    labels: list[str] = []

    def _selectbox(_label, **kwargs):
        options.extend(kwargs["options"])
        labels.extend(kwargs["format_func"](option) for option in kwargs["options"])
        return options[kwargs["index"]]

    with (
        patch.dict("os.environ", env, clear=False),
        patch("streamlit.session_state", state),
        patch("streamlit.subheader") as subheader,
        patch("streamlit.selectbox", side_effect=_selectbox),
        patch("streamlit.caption") as caption,
    ):
        _render_db_variant_section(profile)

    captions = " ".join(
        str(call.args[0]) for call in caption.call_args_list if call.args
    )
    return state, subheader, options, labels, captions


def test_database_section_names_the_active_file_without_a_lite_db(monkeypatch):
    """The page must say which DuckDB it reads even when there is one choice."""
    monkeypatch.delenv("DUCKDB_PATH_LITE", raising=False)

    _, subheader, options, labels, captions = _render_db_section(
        CLOUDTRAIL_PROFILE, DUCKDB_PATH="/data/db/threat_hunting.db"
    )

    assert subheader.called
    assert options == ["Full"]
    # The pulldown labels the option with the file it resolves to.
    assert labels == ["Full — threat_hunting.db"]
    assert "/data/db/threat_hunting.db" in captions


def test_database_section_offers_both_variants_as_a_pulldown(monkeypatch):
    """With a Lite DB configured the pulldown carries both files."""
    state, _, options, labels, captions = _render_db_section(
        CLOUDTRAIL_PROFILE,
        DUCKDB_PATH="/data/db/full.db",
        DUCKDB_PATH_LITE="/data/db/lite.db",
        variant="Lite",
    )

    assert options == ["Full", "Lite"]
    assert labels == ["Full — full.db", "Lite — lite.db"]
    # The selection round-trips through the shared session key, and the caption
    # names the file that selection resolves to.
    assert state["db_variant"] == "Lite"
    assert "/data/db/lite.db" in captions


def test_database_section_is_silent_for_a_suzaku_profile(monkeypatch):
    """Suzaku pages have their own picker; a second one would contradict it."""
    monkeypatch.delenv("DUCKDB_PATH_LITE", raising=False)

    _, subheader, options, _, _ = _render_db_section(
        SUZAKU_TIMELINE_PROFILE, DUCKDB_PATH="/data/db/threat_hunting.db"
    )

    assert not subheader.called
    assert options == []
