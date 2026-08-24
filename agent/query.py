"""DuckDB query execution and validation.

Provides safe, read-only DuckDB query execution with keyword filtering,
EXPLAIN validation, result limiting, and timeout protection.
"""

import concurrent.futures
import logging
import re
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from datetime import date

import duckdb
import pandas as pd

from llm import fix_sql_with_llm
from profiles import CLOUDTRAIL_PROFILE, DatasetProfile

logger = logging.getLogger(__name__)

QUERY_TIMEOUT_SECONDS: int = 30
DEFAULT_ROW_LIMIT: int = 200

# Forbidden SQL keywords/functions that must never be executed (case-insensitive,
# word boundary). Besides write/DDL statements, this blocks DuckDB constructs that
# touch the filesystem or load extensions — a READ_ONLY connection does NOT sandbox
# those (COPY ... TO writes files; read_text/read_csv/read_blob/glob read arbitrary
# files; ATTACH/INSTALL/LOAD extend the engine). Defense in depth on top of the
# ``enable_external_access=false`` connection config (see :func:`connect_duckdb`).
_FORBIDDEN_PATTERN = re.compile(
    r"\b("
    r"INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|"
    r"ATTACH|DETACH|COPY|INSTALL|LOAD|"
    r"read_text|read_csv|read_csv_auto|read_parquet|read_json|read_json_auto|"
    r"read_blob|glob"
    r")\b",
    re.IGNORECASE,
)

# Matches the leading WITH keyword of a CTE (case-insensitive, multi-line safe).
_WITH_PREFIX_PATTERN = re.compile(r"^\s*WITH\s+", re.IGNORECASE | re.DOTALL)

# Matches a single-quoted SQL string literal (with '' escaping) so table-name
# rewriting can skip over string contents.
_SQL_STRING_LITERAL = re.compile(r"'(?:[^']|'')*'")

# Matches a trailing top-level LIMIT clause (with optional OFFSET) at the very
# end of a statement — used to override a preset/edited row cap in place.
_TRAILING_LIMIT = re.compile(r"\bLIMIT\s+\d+(\s+OFFSET\s+\d+)?\s*$", re.IGNORECASE)


class QueryValidationError(Exception):
    """Raised when a SQL query fails safety validation."""


def _mask_string_literals(sql: str) -> str:
    """Blank out the contents of single-quoted literals, preserving length.

    The forbidden-keyword scan runs over raw SQL text, so it fires on any query
    that merely *mentions* a keyword — including inside a quoted literal, where
    it is data and cannot execute. Legitimate hunts hit this: matching AWS API
    names with ``LIKE 'Create%'``, or reading the S3 ``x-amz-copy-source``
    header, whose hyphens are regex word boundaries around ``copy``.

    Masking is length-preserving so error messages still point at the right
    offset, and an *unterminated* quote is deliberately left unmasked: swallowing
    the remainder of the statement as literal text is exactly how a keyword would
    be smuggled past the scan.

    Args:
        sql: SQL text to mask.

    Returns:
        The SQL with the inside of every closed single-quoted literal replaced
        by spaces.
    """

    def blank(match: re.Match) -> str:
        return "'" + " " * (len(match.group(0)) - 2) + "'"

    return _SQL_STRING_LITERAL.sub(blank, sql)


def _sub_outside_string_literals(pattern: re.Pattern, repl: str, sql: str) -> str:
    """Apply ``pattern.sub(repl, ...)`` to *sql* but skip single-quoted literals.

    Splits *sql* on single-quoted string literals, substitutes only in the
    non-literal segments, and re-joins with the literals untouched. This keeps
    identifier rewriting (e.g. ``cloudtrail_events`` → ``_ct_filtered``) from
    corrupting a string value that merely contains the same text.

    Args:
        pattern: Compiled regex to substitute (matched only outside literals).
        repl:    Replacement string.
        sql:     SQL text to transform.

    Returns:
        The transformed SQL string.
    """
    segments = _SQL_STRING_LITERAL.split(sql)
    literals = _SQL_STRING_LITERAL.findall(sql)
    out: list[str] = []
    for i, segment in enumerate(segments):
        out.append(pattern.sub(repl, segment))
        if i < len(literals):
            out.append(literals[i])
    return "".join(out)


def _line_comment_start(line: str) -> int | None:
    """Return the index of a top-level ``--`` comment in *line*, or ``None``.

    A ``--`` that appears inside a single-quoted string literal is ignored so a
    value such as ``'a--b'`` is not mistaken for a comment.
    """
    in_string = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if ch == "'":
            if in_string and i + 1 < n and line[i + 1] == "'":
                i += 2  # '' escape inside a string literal
                continue
            in_string = not in_string
        elif ch == "-" and not in_string and i + 1 < n and line[i + 1] == "-":
            return i
        i += 1
    return None


def _strip_trailing_comments(sql: str) -> str:
    """Strip trailing SQL comments (and semicolons) from *sql*.

    Removes any ``-- line`` comment on the final line and any ``/* block */``
    comment at the end, repeatedly, so that a commented-out ``LIMIT`` can
    neither hide nor be mistaken for a real row cap and a dangling line comment
    cannot swallow a wrapper's closing clause. String literals are respected.

    Args:
        sql: SQL text.

    Returns:
        *sql* with trailing comments and semicolons removed.
    """
    cur = sql.rstrip().rstrip(";").rstrip()
    while True:
        if cur.endswith("*/"):
            start = cur.rfind("/*")
            if start != -1:
                cur = cur[:start].rstrip().rstrip(";").rstrip()
                continue
        newline = cur.rfind("\n")
        last_line = cur[newline + 1 :]
        pos = _line_comment_start(last_line)
        if pos is not None:
            cur = (cur[: newline + 1] + last_line[:pos]).rstrip().rstrip(";").rstrip()
            continue
        break
    return cur


def _inject_filter_cte(sql: str, profile: DatasetProfile, conditions: list[str]) -> str:
    """Wrap *profile*'s table in a CTE applying *conditions* and rewrite *sql*.

    All active filters share a single CTE: two separate CTEs would each have to
    rewrite the table reference, and the second would rewrite the first's alias.

    Args:
        sql:        Original SQL (may already contain a ``WITH`` clause).
        profile:    Dataset profile naming the table and the CTE alias.
        conditions: SQL boolean expressions, ANDed together. Empty means the
                    SQL is returned unchanged.

    Returns:
        The rewritten SQL.
    """
    if not conditions:
        return sql

    where_clause = "\n      AND ".join(conditions)
    cte_body = (
        f"{profile.filter_alias} AS (\n"
        f"    SELECT * FROM {profile.table}\n"
        f"    WHERE {where_clause}\n"
        f")"
    )

    # Replace table references in the original SQL, but never inside
    # single-quoted string literals (rewriting a literal that merely contains
    # the table name would silently change query semantics).
    modified_sql = _sub_outside_string_literals(
        re.compile(rf"\b{re.escape(profile.table)}\b", re.IGNORECASE),
        profile.filter_alias,
        sql,
    )

    # Prepend the CTE, handling an existing WITH clause correctly.
    if _WITH_PREFIX_PATTERN.match(modified_sql):
        # Append the filter CTE as the first entry in the existing WITH chain.
        return _WITH_PREFIX_PATTERN.sub(f"WITH {cte_body},\n", modified_sql, count=1)
    return f"WITH {cte_body}\n{modified_sql}"


def _date_conditions(
    profile: DatasetProfile,
    start_date: date | None,
    end_date: date | None,
) -> list[str]:
    """Return the time-bound conditions for *profile*, inclusive on both sides.

    A profile whose time column is text — none ship today, but the field exists
    for a dataset that stores its timestamps rendered — is CAST first so the
    comparison is temporal rather than lexicographic.
    """
    column = profile.quote(profile.time_column)
    if profile.time_is_varchar:
        column = f"CAST({column} AS TIMESTAMP)"

    conditions: list[str] = []
    if start_date is not None:
        conditions.append(f"{column} >= TIMESTAMP '{start_date!s} 00:00:00'")
    if end_date is not None:
        conditions.append(f"{column} <= TIMESTAMP '{end_date!s} 23:59:59'")
    return conditions


def _level_condition(profile: DatasetProfile, levels: Sequence[str]) -> list[str]:
    """Return the severity condition for *profile*, or ``[]`` when inactive.

    Selecting every known severity is the same as no filter, so it produces no
    condition rather than a redundant ``IN`` list.

    Raises:
        ValueError: If *profile* has no severity column, or a value is not one of
                    the profile's known severities. The values reach the SQL
                    string directly, so an unknown one is rejected rather than
                    quoted and hoped for.
    """
    if not levels:
        return []
    if not profile.level_column:
        raise ValueError(f"profile {profile.key!r} has no severity column to filter")

    unknown = [level for level in levels if level not in profile.level_order]
    if unknown:
        raise ValueError(f"unknown severity level(s): {unknown!r}")

    if set(levels) == set(profile.level_order):
        return []

    values = ", ".join(f"'{level}'" for level in levels)
    return [f"{profile.quote(profile.level_column)} IN ({values})"]


def apply_filters(
    sql: str,
    *,
    profile: DatasetProfile = CLOUDTRAIL_PROFILE,
    start_date: date | None = None,
    end_date: date | None = None,
    levels: Sequence[str] | None = None,
) -> str:
    """Inject every active UI filter into *sql* as one CTE.

    Args:
        sql:        SQL to rewrite.
        profile:    Dataset profile describing the table being queried.
        start_date: Inclusive lower time bound, or ``None``.
        end_date:   Inclusive upper time bound (end-of-day), or ``None``.
        levels:     Severities to keep. ``None``/empty means no severity filter;
                    only valid for a profile with a severity column.

    Returns:
        The SQL with a filter CTE applied, or the original when no filter is
        active.

    Raises:
        ValueError: If *levels* is set for a profile without a severity column,
                    or contains a value the profile does not define.
    """
    conditions = _date_conditions(profile, start_date, end_date)
    conditions += _level_condition(profile, levels or ())
    return _inject_filter_cte(sql, profile, conditions)


def apply_date_filter(
    sql: str,
    start_date: date | None,
    end_date: date | None,
    *,
    profile: DatasetProfile = CLOUDTRAIL_PROFILE,
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
        profile:    Dataset profile describing the table and time column
                    (defaults to ``cloudtrail_events`` / ``event_time``).

    Returns:
        SQL string with the date filter CTE applied, or the original SQL when
        both date arguments are ``None``.
    """
    return apply_filters(sql, profile=profile, start_date=start_date, end_date=end_date)


def apply_row_limit(sql: str, limit: int) -> str:
    """Apply *limit* to *sql*, always honouring the caller's value.

    Trailing SQL comments and semicolons are stripped first (see
    :func:`_strip_trailing_comments`) so that a commented-out ``LIMIT`` can
    neither hide a missing cap nor be mistaken for a real one.

    If the comment-free statement ends in a top-level ``LIMIT`` clause it is
    replaced **in place** with *limit*, so the caller's value overrides any
    limit already present (up or down) — this also keeps CTE (``WITH``) queries
    valid, since they cannot always be wrapped in a derived table.

    Otherwise the whole statement is wrapped with
    ``SELECT * FROM (\n{sql}\n) AS _limited LIMIT {limit}``. The subquery is
    placed on its own lines so that no inner trailing token can merge with the
    closing ``) AS _limited``.

    Args:
        sql:   SQL string to apply the row limit to.
        limit: Maximum number of rows to return.

    Returns:
        SQL string guaranteed to return at most *limit* rows.
    """
    core = _strip_trailing_comments(sql)
    new_sql = _TRAILING_LIMIT.sub(f"LIMIT {limit}", core)
    if new_sql != core:
        # A genuine top-level LIMIT was replaced in place.
        return new_sql
    # No top-level LIMIT (or LIMIT only inside a subquery/CTE): wrap to cap.
    return f"SELECT * FROM (\n{core}\n) AS _limited LIMIT {limit}"


# DuckDB connection config for reader services. ``read_only`` alone does NOT
# sandbox the filesystem — COPY ... TO writes files and read_text/read_csv/glob
# read arbitrary files even on a read-only connection. Disabling external access
# turns those into permission errors, and locking the configuration prevents SQL
# from re-enabling it at runtime (e.g. ``SET enable_external_access=true``).
_READONLY_CONFIG: dict[str, str] = {
    "enable_external_access": "false",
    "lock_configuration": "true",
}


def connect_duckdb(path: str) -> duckdb.DuckDBPyConnection:
    """Open a DuckDB connection in READ_ONLY mode with the filesystem sandboxed.

    The connection disables DuckDB's external file access so that LLM-generated
    or hand-edited SQL cannot read/write local files (``read_text``, ``COPY ...
    TO``, ``INSTALL``, ``glob``, …) via the query path.

    Args:
        path: Filesystem path to the DuckDB database file.

    Returns:
        A DuckDB connection opened in read-only mode with external access off.
    """
    return duckdb.connect(path, read_only=True, config=_READONLY_CONFIG)


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

    Performs three checks in order:
    1. Rejects multi-statement input. ``conn.execute("EXPLAIN <sql>")`` would
       run every statement after the first ``;`` for real (the ``EXPLAIN``
       prefix only binds to the first statement), so a stacked statement such
       as ``SELECT 1; COPY (...) TO '/tmp/x'`` must be rejected *before* the
       EXPLAIN step — otherwise it executes during "validation", bypassing the
       row-limit and timeout wrappers entirely.
    2. Rejects any statement containing forbidden write/DDL/filesystem keywords.
    3. Runs ``EXPLAIN <sql>`` to verify the query is syntactically valid
       without executing it.

    Args:
        conn: An open DuckDB connection.
        sql:  The SQL string to validate.

    Raises:
        QueryValidationError: If the query is multi-statement, contains
                              forbidden keywords, or fails the EXPLAIN check.
    """
    try:
        statements = conn.extract_statements(sql)
    except Exception as exc:
        raise QueryValidationError(f"SQL validation failed: {exc}") from exc
    if len(statements) != 1:
        raise QueryValidationError(
            "Only a single SQL statement is allowed "
            f"(got {len(statements)}): {sql[:120]}"
        )

    if _FORBIDDEN_PATTERN.search(_mask_string_literals(sql)):
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
    profile: DatasetProfile = CLOUDTRAIL_PROFILE,
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
        profile:     Dataset profile forwarded to the LLM so a correction is
                     written against the right table.

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
            corrected = fix_sql_with_llm(sql, str(exc), api_key, model, profile=profile)
            if corrected.startswith("[error]"):
                raise QueryValidationError(
                    f"LLM-based SQL correction failed: {corrected}"
                ) from exc
            sql = corrected

    # Unreachable; satisfies type checkers.
    raise QueryValidationError(
        "execute_with_retry exhausted without result"
    )  # pragma: no cover
