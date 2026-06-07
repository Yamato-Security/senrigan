"""Tests for query.py — DuckDB query execution and validation."""

import concurrent.futures
from datetime import date
from unittest.mock import patch

import duckdb
import pandas as pd
import pytest

from query import (
    DEFAULT_ROW_LIMIT,
    QueryValidationError,
    apply_date_filter,
    apply_row_limit,
    connect_duckdb,
    execute_query,
    execute_with_retry,
    validate_query,
)


def test_default_row_limit_is_200():
    """DEFAULT_ROW_LIMIT must be 200 to balance LLM context capacity and UI visibility."""
    assert DEFAULT_ROW_LIMIT == 200


def test_connect_duckdb_readonly(tmp_duckdb):
    """Opens DuckDB in read-only mode successfully."""
    conn = connect_duckdb(tmp_duckdb)

    assert conn is not None
    conn.close()


def test_execute_select_query(tmp_duckdb):
    """Executes a simple SELECT and returns a pandas DataFrame."""
    conn = connect_duckdb(tmp_duckdb)

    df = execute_query(conn, "SELECT event_name FROM cloudtrail_events LIMIT 5")

    assert isinstance(df, pd.DataFrame)
    assert "event_name" in df.columns
    assert len(df) > 0
    conn.close()


def test_execute_query_returns_empty_dataframe_for_no_results(tmp_duckdb):
    """Empty result returns an empty DataFrame, not an error."""
    conn = connect_duckdb(tmp_duckdb)

    df = execute_query(
        conn,
        "SELECT event_name FROM cloudtrail_events WHERE event_name = '__no_such_event__'",
    )

    assert isinstance(df, pd.DataFrame)
    assert len(df) == 0
    conn.close()


def test_validate_query_with_explain(tmp_duckdb):
    """Running EXPLAIN before execution does not raise on valid SQL."""
    conn = connect_duckdb(tmp_duckdb)

    # Should not raise
    validate_query(conn, "SELECT event_name FROM cloudtrail_events LIMIT 10")

    conn.close()


def test_validate_query_rejects_write_statements(tmp_duckdb):
    """INSERT, UPDATE, DELETE, DROP statements are rejected before execution."""
    conn = connect_duckdb(tmp_duckdb)

    forbidden = [
        "INSERT INTO cloudtrail_events (event_name) VALUES ('x')",
        "UPDATE cloudtrail_events SET event_name = 'x'",
        "DELETE FROM cloudtrail_events",
        "DROP TABLE cloudtrail_events",
        "ALTER TABLE cloudtrail_events ADD COLUMN foo VARCHAR",
        "CREATE TABLE foo (id INT)",
    ]
    for stmt in forbidden:
        with pytest.raises(QueryValidationError, match="(?i)not allowed"):
            validate_query(conn, stmt)

    conn.close()


def test_execute_query_timeout(tmp_duckdb, monkeypatch):
    """Queries exceeding the timeout limit raise a TimeoutError."""
    original_submit = concurrent.futures.ThreadPoolExecutor.submit

    def mock_submit(self, fn, *args, **kwargs):
        future = original_submit(self, fn, *args, **kwargs)
        # Replace result() so it always raises TimeoutError
        future.result = lambda timeout=None: (_ for _ in ()).throw(
            concurrent.futures.TimeoutError()
        )
        return future

    monkeypatch.setattr(concurrent.futures.ThreadPoolExecutor, "submit", mock_submit)

    conn = connect_duckdb(tmp_duckdb)
    with pytest.raises(TimeoutError):
        execute_query(conn, "SELECT 1")
    conn.close()


# ---------------------------------------------------------------------------
# Row-limit tests
# ---------------------------------------------------------------------------


def test_apply_row_limit_adds_limit_when_missing():
    """apply_row_limit wraps SQL with LIMIT when no LIMIT clause is present."""
    sql = "SELECT * FROM cloudtrail_events"
    result = apply_row_limit(sql, 100)
    assert "LIMIT 100" in result.upper()
    assert "cloudtrail_events" in result


def test_apply_row_limit_overrides_existing_limit():
    """apply_row_limit replaces an existing LIMIT clause with the new limit.

    Behaviour change from the original safety-cap design: the caller's *limit*
    always wins so that the sidebar row-limit setting is honoured even when
    the SQL already contains a LIMIT clause.
    """
    sql = "SELECT * FROM cloudtrail_events LIMIT 5"
    result = apply_row_limit(sql, 100)
    # Original LIMIT 5 must be replaced by LIMIT 100
    assert result.upper().endswith("LIMIT 100")
    assert "LIMIT 5" not in result


def test_apply_row_limit_case_insensitive():
    """apply_row_limit replaces a lower-case 'limit' clause too."""
    sql = "SELECT * FROM cloudtrail_events limit 10"
    result = apply_row_limit(sql, 500)
    # lower-case limit 10 must be replaced with the new limit
    assert result.upper().endswith("LIMIT 500")
    assert result != sql


def test_apply_row_limit_strips_trailing_semicolon():
    """apply_row_limit strips a trailing semicolon before wrapping."""
    sql = "SELECT * FROM cloudtrail_events;"
    result = apply_row_limit(sql, 50)
    assert "LIMIT 50" in result.upper()
    # The wrapped SQL must not have a bare semicolon inside the subquery
    assert result.count(";") == 0


# ---------------------------------------------------------------------------
# Edge-case tests — patterns the LLM commonly generates (Test #RL-EC1~3)
# ---------------------------------------------------------------------------


def test_apply_row_limit_wraps_when_limit_only_in_subquery():
    """apply_row_limit wraps the statement when LIMIT exists only inside a subquery.

    Test #RL-EC1: the inner LIMIT must be preserved and an outer LIMIT added.
    Without this guard, the inner LIMIT would fool the regex into thinking a
    top-level cap is already present, leaving the outer query uncapped.
    """
    sql = "SELECT * FROM (SELECT event_name FROM cloudtrail_events LIMIT 50) sub"
    result = apply_row_limit(sql, 100)
    # The outer LIMIT cap must be present.
    assert "LIMIT 100" in result.upper()
    # The inner LIMIT 50 must still be there (subquery not modified).
    assert "LIMIT 50" in result


def test_apply_row_limit_replaces_limit_offset():
    """apply_row_limit replaces LIMIT N OFFSET M with LIMIT cap (OFFSET dropped).

    Test #RL-EC2: OFFSET is discarded because the row-limit cap is a hard
    safety ceiling, not a pagination directive.
    """
    sql = "SELECT * FROM cloudtrail_events ORDER BY event_time LIMIT 5 OFFSET 10"
    result = apply_row_limit(sql, 100)
    assert result.upper().endswith("LIMIT 100")
    # LIMIT 5 and OFFSET must no longer appear at the top level.
    assert "LIMIT 5" not in result
    assert "OFFSET" not in result.upper()


def test_apply_row_limit_replaces_cte_trailing_limit():
    """apply_row_limit replaces the trailing LIMIT of a CTE query in-place.

    Test #RL-EC3: the WITH clause must not be wrapped in an outer subquery —
    DuckDB does not allow CTEs inside a derived-table FROM clause.
    """
    sql = "WITH cte AS (SELECT * FROM cloudtrail_events) SELECT * FROM cte LIMIT 10"
    result = apply_row_limit(sql, 200)
    # Must replace in-place, not wrap.
    assert result.upper().endswith("LIMIT 200")
    assert "WITH" in result.upper()
    assert "LIMIT 10" not in result


def test_execute_query_truncates_to_custom_row_limit(tmp_duckdb):
    """execute_query returns at most row_limit rows (custom limit < total rows)."""
    conn = connect_duckdb(tmp_duckdb)
    # The fixture has 3 rows; request at most 2
    df = execute_query(conn, "SELECT * FROM cloudtrail_events", row_limit=2)
    assert len(df) <= 2
    conn.close()


def test_execute_query_uses_default_row_limit(tmp_duckdb):
    """execute_query applies DEFAULT_ROW_LIMIT when row_limit is not specified."""
    conn = connect_duckdb(tmp_duckdb)
    df = execute_query(conn, "SELECT * FROM cloudtrail_events")
    assert len(df) <= DEFAULT_ROW_LIMIT
    conn.close()


def test_execute_query_overrides_existing_sql_limit(tmp_duckdb):
    """execute_query overrides a SQL LIMIT clause with the row_limit parameter.

    LIMIT 1 in the SQL is replaced by row_limit=100; the fixture has 3 rows
    so all 3 are returned.
    """
    conn = connect_duckdb(tmp_duckdb)
    df = execute_query(conn, "SELECT * FROM cloudtrail_events LIMIT 1", row_limit=100)
    # LIMIT 1 was replaced by row_limit=100; fixture has 3 rows
    assert len(df) == 3
    conn.close()


def test_execute_query_large_row_limit_returns_all_rows(tmp_duckdb):
    """execute_query returns all rows when row_limit exceeds the result size."""
    conn = connect_duckdb(tmp_duckdb)
    # Fixture has 3 rows; limit=100 should return all 3
    df = execute_query(conn, "SELECT * FROM cloudtrail_events", row_limit=100)
    assert len(df) == 3
    conn.close()


# ---------------------------------------------------------------------------
# Date-filter tests (apply_date_filter)
# ---------------------------------------------------------------------------


def test_apply_date_filter_returns_unchanged_when_no_dates():
    """apply_date_filter returns the original SQL when both dates are None.

    Test #DF-1: passthrough guard.
    """
    sql = "SELECT * FROM cloudtrail_events LIMIT 10"
    assert apply_date_filter(sql, None, None) == sql


def test_apply_date_filter_injects_cte_with_start_only():
    """apply_date_filter injects a date-range CTE when only start_date is given.

    Test #DF-2: start_date only.
    """
    sql = "SELECT * FROM cloudtrail_events LIMIT 10"
    result = apply_date_filter(sql, date(2024, 1, 1), None)
    assert "_ct_filtered" in result
    assert "2024-01-01" in result
    # cloudtrail_events must appear only once — inside the CTE body
    assert result.count("cloudtrail_events") == 1


def test_apply_date_filter_injects_cte_with_end_only():
    """apply_date_filter injects a date-range CTE when only end_date is given.

    Test #DF-3: end_date only.
    """
    sql = "SELECT * FROM cloudtrail_events LIMIT 10"
    result = apply_date_filter(sql, None, date(2024, 1, 31))
    assert "_ct_filtered" in result
    assert "2024-01-31" in result
    assert result.count("cloudtrail_events") == 1


def test_apply_date_filter_injects_cte_with_both_dates():
    """apply_date_filter injects a date-range CTE with both start and end dates.

    Test #DF-4: both dates present.
    """
    sql = "SELECT * FROM cloudtrail_events LIMIT 10"
    result = apply_date_filter(sql, date(2024, 1, 1), date(2024, 1, 31))
    assert "_ct_filtered" in result
    assert "2024-01-01" in result
    assert "2024-01-31" in result
    assert result.count("cloudtrail_events") == 1


def test_apply_date_filter_result_is_valid_duckdb(tmp_duckdb):
    """The date-filtered SQL must be accepted by DuckDB EXPLAIN.

    Test #DF-5: DuckDB integration smoke test.
    """
    sql = (
        "SELECT event_name, COUNT(*) AS cnt FROM cloudtrail_events GROUP BY event_name"
    )
    filtered = apply_date_filter(sql, date(2024, 1, 1), date(2024, 12, 31))
    conn = duckdb.connect(tmp_duckdb, read_only=True)
    try:
        validate_query(conn, filtered)  # must not raise
    finally:
        conn.close()


def test_apply_date_filter_handles_sql_with_existing_with_clause():
    """apply_date_filter works when the SQL already has a WITH clause.

    Test #DF-6: existing CTE is preserved and _ct_filtered is prepended.
    """
    sql = "WITH foo AS (SELECT 1 AS x) SELECT * FROM cloudtrail_events"
    result = apply_date_filter(sql, date(2024, 1, 1), date(2024, 1, 31))
    assert "_ct_filtered" in result
    assert "foo" in result
    # Exactly one WITH keyword at the top level
    assert (
        result.upper().count("\nWITH ")
        + (1 if result.upper().startswith("WITH ") else 0)
        == 1
    )


def test_apply_date_filter_actually_filters_rows(tmp_duckdb):
    """apply_date_filter restricts the result set to the given date range.

    Test #DF-7: end-to-end row filtering.
    The tmp_duckdb fixture has 3 rows all in 2024-01-15.
    - Filter covering 2024-01-01 → 2024-12-31: returns all 3 rows.
    - Filter covering 2025-01-01 → 2025-12-31: returns 0 rows.
    """
    sql = "SELECT * FROM cloudtrail_events"

    conn = connect_duckdb(tmp_duckdb)

    # Range that includes all fixture rows
    filtered_in = apply_date_filter(sql, date(2024, 1, 1), date(2024, 12, 31))
    df_in = execute_query(conn, filtered_in, row_limit=100)
    assert len(df_in) == 3, "Expected all 3 rows to match the 2024 range"

    # Range that excludes all fixture rows
    filtered_out = apply_date_filter(sql, date(2025, 1, 1), date(2025, 12, 31))
    df_out = execute_query(conn, filtered_out, row_limit=100)
    assert len(df_out) == 0, "Expected 0 rows for the 2025 range"

    conn.close()


# ---------------------------------------------------------------------------
# Proposal 2 — execute_with_retry
# ---------------------------------------------------------------------------


def test_execute_with_retry_succeeds_on_first_attempt(tmp_duckdb):
    """execute_with_retry returns (DataFrame, sql) when the first attempt succeeds."""
    conn = connect_duckdb(tmp_duckdb)
    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"

    df, final_sql = execute_with_retry(conn, sql, api_key="", model="gpt-5.4")

    assert isinstance(df, pd.DataFrame)
    assert final_sql == sql
    conn.close()


def test_execute_with_retry_calls_fix_sql_on_validation_error(tmp_duckdb):
    """execute_with_retry calls fix_sql_with_llm and retries when QueryValidationError occurs."""
    conn = connect_duckdb(tmp_duckdb)
    bad_sql = "SELECT * FROM nonexistent_table"
    good_sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"

    with patch("query.fix_sql_with_llm", return_value=good_sql) as mock_fix:
        df, final_sql = execute_with_retry(
            conn, bad_sql, api_key="sk-test", model="gpt-5.4"
        )

    mock_fix.assert_called_once()
    assert isinstance(df, pd.DataFrame)
    assert final_sql == good_sql
    conn.close()


def test_execute_with_retry_raises_after_max_retries_exceeded(tmp_duckdb):
    """execute_with_retry re-raises QueryValidationError after exhausting all retries."""
    conn = connect_duckdb(tmp_duckdb)
    bad_sql = "SELECT * FROM nonexistent_table"

    # fix_sql returns the same bad SQL on every attempt
    with patch("query.fix_sql_with_llm", return_value=bad_sql) as mock_fix:
        with pytest.raises(QueryValidationError):
            execute_with_retry(
                conn, bad_sql, api_key="sk-test", model="gpt-5.4", max_retries=1
            )

    assert mock_fix.call_count == 1  # one correction attempt was made
    conn.close()


def test_execute_with_retry_does_not_retry_on_timeout(tmp_duckdb):
    """execute_with_retry does not call fix_sql_with_llm when a TimeoutError occurs."""
    conn = connect_duckdb(tmp_duckdb)
    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"

    with (
        patch("query.execute_query", side_effect=TimeoutError("timed out")),
        patch("query.fix_sql_with_llm") as mock_fix,
    ):
        with pytest.raises(TimeoutError):
            execute_with_retry(conn, sql, api_key="sk-test", model="gpt-5.4")

    mock_fix.assert_not_called()
    conn.close()


def test_execute_with_retry_forwards_row_limit(tmp_duckdb):
    """execute_with_retry passes the row_limit argument to execute_query.

    Test #RL-Q1: verifies the row_limit kwarg is forwarded so the caller
    can control the per-query row cap end-to-end.
    """
    conn = connect_duckdb(tmp_duckdb)
    sql = "SELECT * FROM cloudtrail_events"

    with patch("query.execute_query", return_value=pd.DataFrame()) as mock_exec:
        execute_with_retry(conn, sql, api_key="", model="gpt-5.4", row_limit=50)

    mock_exec.assert_called_once_with(conn, sql, row_limit=50)
    conn.close()
