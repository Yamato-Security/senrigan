"""The write/DDL blocklist must ignore keywords inside string literals.

The blocklist scans raw SQL text, so it fires on any query that merely *mentions*
a forbidden word — including inside a quoted literal, where the word is data and
cannot execute. Two legitimate hunts hit this:

  * ``json_extract_string(request_parameters, '$."x-amz-copy-source"')`` — the S3
    header name contains ``copy``, and ``-`` is a regex word boundary.
  * ``event_name LIKE 'Create%'`` — matching AWS API names by prefix.

Masking literals before the keyword scan keeps the guard's actual job intact: a
statement that really writes has the keyword outside quotes, where it still
matches. The EXPLAIN check and the READ_ONLY connection remain unchanged.
"""

from __future__ import annotations

import duckdb
import pytest

from query import QueryValidationError, validate_query


@pytest.fixture()
def conn():
    connection = duckdb.connect(":memory:")
    connection.execute(
        "CREATE TABLE cloudtrail_events (event_name VARCHAR, request_parameters VARCHAR)"
    )
    try:
        yield connection
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Literals are data, not statements
# ---------------------------------------------------------------------------

ALLOWED = [
    "SELECT * FROM cloudtrail_events WHERE event_name LIKE 'Create%'",
    "SELECT * FROM cloudtrail_events WHERE event_name LIKE 'Delete%'",
    "SELECT * FROM cloudtrail_events WHERE event_name IN ('CreateUser', 'UpdateUser')",
    "SELECT json_extract_string(request_parameters, '$.\"x-amz-copy-source\"') "
    "FROM cloudtrail_events",
    "SELECT * FROM cloudtrail_events WHERE request_parameters LIKE '%copy-source%'",
    "SELECT 'read_csv is only a word here' AS note FROM cloudtrail_events",
]


@pytest.mark.parametrize("sql", ALLOWED)
def test_keywords_inside_literals_are_allowed(conn, sql: str) -> None:
    validate_query(conn, sql)


# ---------------------------------------------------------------------------
# Real writes are still refused
# ---------------------------------------------------------------------------

FORBIDDEN = [
    "DROP TABLE cloudtrail_events",
    "DELETE FROM cloudtrail_events",
    "INSERT INTO cloudtrail_events VALUES ('x', '{}')",
    "UPDATE cloudtrail_events SET event_name = 'x'",
    "ALTER TABLE cloudtrail_events ADD COLUMN x VARCHAR",
    "CREATE TABLE t AS SELECT 1",
    "COPY cloudtrail_events TO '/tmp/out.csv'",
    "ATTACH '/tmp/other.db' AS other",
    "SELECT * FROM read_csv('/etc/passwd')",
    "SELECT * FROM glob('/etc/*')",
]


@pytest.mark.parametrize("sql", FORBIDDEN)
def test_write_and_file_access_statements_are_refused(conn, sql: str) -> None:
    with pytest.raises(QueryValidationError):
        validate_query(conn, sql)


def test_keyword_after_a_literal_is_still_caught(conn) -> None:
    """Masking a literal must not hide what follows it."""
    with pytest.raises(QueryValidationError):
        validate_query(
            conn,
            "SELECT 'harmless' AS note FROM cloudtrail_events; DROP TABLE cloudtrail_events",
        )


def test_unterminated_literal_does_not_swallow_the_rest(conn) -> None:
    """A dangling quote must not mask everything after it as literal text."""
    with pytest.raises(QueryValidationError):
        validate_query(conn, "SELECT 'oops FROM cloudtrail_events DROP TABLE x")
