"""Shared plumbing for the Suzaku explorer query layers.

Both explorer pages run reviewed SQL rather than generated SQL, so their query
modules need only two things in common: a way to run a parameterized statement
against a read-only connection, and a return type that carries the statement
along with its rows — a pinned panel reports the SQL it ran.

No Streamlit import here, or in the modules that build on it, so every query is
unit-tested against the committed fixtures directly.

See ``doc/PLAN_SUZAKU_EXPLORERS.md`` §5.2.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

import pandas as pd

from schema import SUZAKU_TIMELINE_COLUMNS, get_column_names

# Columns the timeline pivot may filter on. The value is embedded as a literal
# there — the chat page takes a SQL string, not parameters — so the column is
# checked against the real schema rather than trusted.
TIMELINE_COLUMNS: frozenset[str] = frozenset(get_column_names(SUZAKU_TIMELINE_COLUMNS))

# Columns the pivot projects. Enough to recognise a detection without returning
# the whole 22-column row.
_PIVOT_PROJECTION: tuple[str, ...] = (
    "Timestamp",
    "Level",
    "RuleTitle",
    "EventName",
    "EventSource",
    "AwsRegion",
    "SrcIP",
    "UserAgent",
    "UserARN",
    "ErrorCode",
    "EventID",
)


@dataclass(frozen=True)
class QueryResult:
    """One statement, its bound parameters, and the rows it returned.

    Attributes:
        sql:    The statement as executed, ``?`` placeholders included.
        params: The values bound to those placeholders.
        df:     The rows, as a DataFrame.
    """

    sql: str
    params: tuple = ()
    df: pd.DataFrame = field(default_factory=pd.DataFrame)


def run(conn, sql: str, params: Sequence = ()) -> QueryResult:
    """Execute *sql* on *conn* and return it together with its rows.

    Args:
        conn:   An open read-only DuckDB connection.
        sql:    The statement to run; every data-derived value is a ``?``.
        params: Values for the placeholders.

    Returns:
        A :class:`QueryResult`.
    """
    sql = sql.strip()
    frame = conn.execute(sql, list(params)).fetchdf()
    return QueryResult(sql=sql, params=tuple(params), df=frame)


def sql_literal(value: str) -> str:
    """Return *value* as a single-quoted SQL string literal.

    Used only by :func:`timeline_pivot_sql`, which has to produce a standalone
    statement rather than a parameterized one. Doubling the quote is what keeps
    a value carrying an apostrophe — or a deliberate injection attempt — inside
    the literal.

    Args:
        value: The value to embed.

    Returns:
        The escaped literal, quotes included.
    """
    return "'" + str(value).replace("'", "''") + "'"


def timeline_pivot_sql(column: str, value: str, *, limit: int = 200) -> str:
    """Return the timeline query that follows *value* into the detections.

    The explorer pages read pre-aggregated files; the raw detections live in a
    different Suzaku file, read by the timeline page. This is the statement that
    page runs when an analyst pivots — a direct-SQL preset, so it needs no API
    key.

    Args:
        column: A ``timeline`` column, checked against :data:`TIMELINE_COLUMNS`.
        value:  The value to filter on, embedded as an escaped literal.
        limit:  Row cap for the pivot.

    Returns:
        A complete ``SELECT`` statement.

    Raises:
        ValueError: When *column* is not a real ``timeline`` column.
    """
    if column not in TIMELINE_COLUMNS:
        raise ValueError(f"{column!r} is not a timeline column")
    projection = ", ".join(f'"{name}"' for name in _PIVOT_PROJECTION)
    return (
        f"SELECT {projection}\n"
        f"FROM timeline\n"
        f'WHERE "{column}" = {sql_literal(value)}\n'
        f'ORDER BY "Timestamp" DESC\n'
        f"LIMIT {int(limit)}"
    )


def limit_clause(limit: int | None) -> str:
    """Return a ``LIMIT`` clause for *limit*, or an empty string.

    The value is cast to ``int`` before it reaches the statement: it comes from
    a slider rather than from the data, and this is the only fragment of these
    queries that is not a bound parameter.

    Args:
        limit: Maximum rows, or None for no cap.

    Returns:
        ``"LIMIT n"`` or ``""``.

    Raises:
        ValueError: When *limit* is not a positive integer.
    """
    if limit is None:
        return ""
    limit = int(limit)
    if limit < 1:
        raise ValueError(f"limit must be positive, got {limit}")
    return f"LIMIT {limit}"
