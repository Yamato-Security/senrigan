"""Tests for the session-state lifecycle and hunt loading (``session.py``).

Moved verbatim from ``test_app.py`` when these helpers left ``app.py``. They
cover the per-profile ``st.session_state`` namespace (defaults, idempotency,
isolation), the built-in hunt YAML loader, the bulk-query builder, and the JSON
session export.

Test #22: session state initialization (Phase 6 of the TDD plan).
Tests #DF-A: date range filter session-state defaults.
Tests #CTX: conversation context retention (Proposal 1).
Tests #UI-01 / #UI-04: analyst_notes and bulk_progress defaults.
"""

import json
from unittest.mock import patch

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
