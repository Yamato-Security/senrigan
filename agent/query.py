"""DuckDB query execution and validation.

Provides safe, read-only DuckDB query execution with keyword filtering,
EXPLAIN validation, result limiting, and timeout protection.
"""

import concurrent.futures
import logging
import re
from contextlib import contextmanager
from datetime import date
from typing import Generator

import duckdb
import pandas as pd

from llm import fix_sql_with_llm

logger = logging.getLogger(__name__)

QUERY_TIMEOUT_SECONDS: int = 30
DEFAULT_ROW_LIMIT: int = 200

# Forbidden SQL keywords that must never be executed (case-insensitive, word boundary).
_FORBIDDEN_PATTERN = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b",
    re.IGNORECASE,
)

# Matches the leading WITH keyword of a CTE (case-insensitive, multi-line safe).
_WITH_PREFIX_PATTERN = re.compile(r"^\s*WITH\s+", re.IGNORECASE | re.DOTALL)


class QueryValidationError(Exception):
    """Raised when a SQL query fails safety validation."""


def apply_date_filter(
    sql: str,
    start_date: date | None,
    end_date: date | None,
) -> str:
    """Inject a date-range CTE into *sql* to filter cloudtrail_events by event_time.

    If both *start_date* and *end_date* are ``None`` the original *sql* is
    returned unchanged.

    The function:

    1. Builds a ``_ct_filtered`` CTE that wraps ``cloudtrail_events`` with the
       requested ``event_time`` bounds (inclusive on both sides; end-of-day is
       used for *end_date*).
    2. Replaces every occurrence of ``cloudtrail_events`` in the original SQL
       with ``_ct_filtered`` (case-insensitive word-boundary match).
    3. Prepends the CTE, extending any existing ``WITH`` chain rather than
       creating a duplicate keyword.

    Args:
        sql:        Original SQL string (may already contain a WITH clause).
        start_date: Inclusive lower bound for ``event_time``, or ``None``.
        end_date:   Inclusive upper bound for ``event_time`` (end-of-day
                    23:59:59), or ``None``.

    Returns:
        SQL string with the date filter CTE applied, or the original SQL when
        both date arguments are ``None``.
    """
    if start_date is None and end_date is None:
        return sql

    # Build WHERE conditions for the CTE.
    conditions: list[str] = []
    if start_date is not None:
        conditions.append(f"event_time >= TIMESTAMP '{start_date!s} 00:00:00'")
    if end_date is not None:
        conditions.append(f"event_time <= TIMESTAMP '{end_date!s} 23:59:59'")
    where_clause = "\n      AND ".join(conditions)

    cte_body = (
        f"_ct_filtered AS (\n"
        f"    SELECT * FROM cloudtrail_events\n"
        f"    WHERE {where_clause}\n"
        f")"
    )

    # Replace cloudtrail_events references in the original SQL.
    modified_sql = re.sub(
        r"\bcloudtrail_events\b", "_ct_filtered", sql, flags=re.IGNORECASE
    )

    # Prepend the CTE, handling an existing WITH clause correctly.
    if _WITH_PREFIX_PATTERN.match(modified_sql):
        # Append _ct_filtered as the first entry in the existing WITH chain.
        result = _WITH_PREFIX_PATTERN.sub(f"WITH {cte_body},\n", modified_sql, count=1)
    else:
        result = f"WITH {cte_body}\n{modified_sql}"

    return result


def apply_row_limit(sql: str, limit: int) -> str:
    """Apply *limit* to *sql*, always honouring the caller's value.

    If the SQL already contains a trailing ``LIMIT`` clause it is replaced
    **in-place** with *limit* so that the caller's value is always the
    effective row cap — regardless of any limit already present in the SQL.
    This ensures the sidebar row-limit setting overrides hard-coded limits in
    preset queries.

    If the SQL has no ``LIMIT`` clause the whole statement is wrapped with
    ``SELECT * FROM (...) AS _limited LIMIT {limit}``.

    A trailing semicolon is stripped before processing to keep the resulting
    SQL syntactically valid.

    Args:
        sql:   SQL string to apply the row limit to.
        limit: Maximum number of rows to return.

    Returns:
        SQL string guaranteed to return at most *limit* rows.
    """
    stripped = sql.rstrip().rstrip(";").rstrip()
    # Try to replace a trailing top-level LIMIT clause (with optional OFFSET).
    # The substitution only succeeds when LIMIT appears at the very end of the
    # statement (i.e. as a top-level clause, not inside a subquery or CTE).
    new_sql = re.sub(
        r"\bLIMIT\s+\d+(\s+OFFSET\s+\d+)?\s*$",
        f"LIMIT {limit}",
        stripped,
        flags=re.IGNORECASE,
    )
    if new_sql != stripped:
        # Replacement succeeded — LIMIT was a top-level clause.
        return new_sql
    # No top-level LIMIT found (or LIMIT only exists inside a subquery/CTE).
    # Wrap the whole statement so the cap is always applied.
    return f"SELECT * FROM ({stripped}) AS _limited LIMIT {limit}"


def connect_duckdb(path: str) -> duckdb.DuckDBPyConnection:
    """Open a DuckDB connection in READ_ONLY mode.

    Args:
        path: Filesystem path to the DuckDB database file.

    Returns:
        A DuckDB connection opened in read-only mode.
    """
    return duckdb.connect(path, read_only=True)


@contextmanager
def duckdb_connection(path: str) -> Generator[duckdb.DuckDBPyConnection, None, None]:
    """Context manager for a read-only DuckDB connection.

    Ensures the connection is always closed, even when an exception occurs
    inside the ``with`` block — preventing connection leaks.

    Args:
        path: Filesystem path to the DuckDB database file.

    Yields:
        An open read-only DuckDB connection.

    Example::

        with duckdb_connection(db_path) as conn:
            results = execute_query(conn, sql, row_limit=100)
    """
    conn = connect_duckdb(path)
    try:
        yield conn
    finally:
        conn.close()


def validate_query(conn: duckdb.DuckDBPyConnection, sql: str) -> None:
    """Validate SQL safety using keyword filtering and EXPLAIN.

    Performs two checks in order:
    1. Rejects any statement containing forbidden write/DDL keywords.
    2. Runs ``EXPLAIN <sql>`` to verify the query is syntactically valid
       without executing it.

    Args:
        conn: An open DuckDB connection.
        sql:  The SQL string to validate.

    Raises:
        QueryValidationError: If the query contains forbidden keywords or
                              fails the EXPLAIN check.
    """
    if _FORBIDDEN_PATTERN.search(sql):
        raise QueryValidationError(f"Write/DDL statements are not allowed: {sql[:120]}")

    try:
        conn.execute(f"EXPLAIN {sql}")
    except Exception as exc:
        raise QueryValidationError(f"SQL validation failed: {exc}") from exc


def _run_query(conn: duckdb.DuckDBPyConnection, sql: str) -> pd.DataFrame:
    """Execute SQL and return results as a DataFrame (internal helper)."""
    result = conn.execute(sql)
    return result.df()


def execute_query(
    conn: duckdb.DuckDBPyConnection,
    sql: str,
    row_limit: int = DEFAULT_ROW_LIMIT,
) -> pd.DataFrame:
    """Validate and execute a SQL query, returning results as a DataFrame.

    Enforces safety validation, applies a row cap via :func:`apply_row_limit`,
    then runs the query in a thread with a hard timeout of
    ``QUERY_TIMEOUT_SECONDS`` seconds.

    If the SQL already contains a ``LIMIT`` clause it is used as-is.
    Otherwise the query is wrapped with ``LIMIT {row_limit}`` to prevent
    accidentally fetching millions of rows.

    Args:
        conn:      An open DuckDB connection (must be READ_ONLY).
        sql:       The SQL string to execute.
        row_limit: Maximum number of rows to return (default: DEFAULT_ROW_LIMIT).
                   Ignored when the SQL already contains a LIMIT clause.

    Returns:
        A pandas DataFrame containing the query results.
        Returns an empty DataFrame when the query produces no rows.

    Raises:
        QueryValidationError: If the query fails safety validation.
        TimeoutError:         If the query exceeds the timeout limit.
    """
    validate_query(conn, sql)
    limited_sql = apply_row_limit(sql, row_limit)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_run_query, conn, limited_sql)
        try:
            return future.result(timeout=QUERY_TIMEOUT_SECONDS)
        except concurrent.futures.TimeoutError as exc:
            raise TimeoutError(
                f"Query exceeded the {QUERY_TIMEOUT_SECONDS}s timeout limit."
            ) from exc


def execute_with_retry(
    conn: duckdb.DuckDBPyConnection,
    sql: str,
    api_key: str,
    model: str,
    max_retries: int = 2,
    row_limit: int = DEFAULT_ROW_LIMIT,
) -> tuple[pd.DataFrame, str]:
    """Execute a SQL query with automatic LLM-assisted correction on validation failure.

    Attempts to run the query via :func:`execute_query`. If a
    :class:`QueryValidationError` occurs and *api_key* is set, calls
    :func:`~llm.fix_sql_with_llm` to obtain a corrected SQL and retries.
    At most *max_retries* corrections are attempted.

    :class:`TimeoutError` is never retried — it propagates immediately.

    Args:
        conn:        An open DuckDB connection (READ_ONLY).
        sql:         The SQL query to execute.
        api_key:     OpenAI API key for LLM-assisted correction.
                     When empty, no retries are attempted.
        model:       Model name used for SQL correction.
        max_retries: Maximum number of LLM correction retries (default: 2).
        row_limit:   Maximum number of rows to return (default: DEFAULT_ROW_LIMIT).
                     Forwarded to :func:`execute_query` on every attempt.

    Returns:
        A tuple ``(DataFrame, final_sql)`` where *final_sql* may differ from
        the input *sql* when LLM corrections were applied.

    Raises:
        QueryValidationError: If the query fails validation after all retries
                              are exhausted, or when *api_key* is empty.
        TimeoutError:         If the query exceeds the timeout limit.
    """
    for attempt in range(max_retries + 1):
        try:
            df = execute_query(conn, sql, row_limit=row_limit)
            return df, sql
        except QueryValidationError as exc:
            if attempt == max_retries or not api_key:
                raise
            logger.info(
                "SQL validation failed (attempt %d/%d), requesting LLM correction: %s",
                attempt + 1,
                max_retries,
                exc,
            )
            corrected = fix_sql_with_llm(sql, str(exc), api_key, model)
            if corrected.startswith("[error]"):
                raise QueryValidationError(
                    f"LLM-based SQL correction failed: {corrected}"
                ) from exc
            sql = corrected

    # Unreachable; satisfies type checkers.
    raise QueryValidationError(
        "execute_with_retry exhausted without result"
    )  # pragma: no cover
