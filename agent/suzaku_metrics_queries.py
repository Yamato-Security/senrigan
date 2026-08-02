"""Reviewed SQL for Suzaku's ``aws-ct-metrics`` output.

The file is one row per observed value of whatever field the analyst asked
Suzaku to count, so **every statement here is parameterized on ``Field``**. The
shipped fixture holds a single field (``eventName``), and hard-coding it would
break the first file that holds two.

Suzaku's ``Percent`` is the share of the whole field, computed from
``FieldTotal``. Once the page's controls narrow the rows, that share no longer
adds up, so each statement also returns ``share_of_filtered`` — the share within
whatever subset the analyst is looking at. Both are meaningful and the
difference between them is exactly what the filter did.
"""

from __future__ import annotations

from datetime import date, datetime

import pandas as pd

from suzaku_db import GEO_COLUMNS
from suzaku_queries import QueryResult, limit_clause, run

_FIELDS_SQL = """
SELECT "Field"                AS field,
       any_value("TimelineColumn") AS timeline_column,
       count(*)               AS distinct_values,
       sum("Count")           AS total_count,
       min("FirstSeen")       AS first_seen,
       max("LastSeen")        AS last_seen
FROM metrics
GROUP BY 1
ORDER BY total_count DESC, field
"""

_STATS_SQL = """
SELECT count(*)                                            AS distinct_values,
       COALESCE(sum("Count"), 0)                           AS total_count,
       COALESCE(
           100.0 * max("Count") / NULLIF(sum("Count"), 0), 0
       )                                                   AS top_share,
       count(*) FILTER (WHERE "Count" = 1)                 AS singletons,
       min("FirstSeen")                                    AS first_seen,
       max("LastSeen")                                     AS last_seen
FROM metrics
WHERE "Field" = ?
"""


def fields(conn) -> QueryResult:
    """Return every field this file counts, busiest first.

    Args:
        conn: An open read-only connection to a metrics database.

    Returns:
        Field, its timeline column, and how much it covers.
    """
    return run(conn, _FIELDS_SQL)


def _value_conditions(
    field: str,
    *,
    min_count: int | None,
    max_count: int | None,
    search: str,
    seen_after: date | datetime | None,
) -> tuple[str, list]:
    """Build the shared ``WHERE`` fragment for the value queries.

    Args:
        field:      The field to report on.
        min_count:  Keep values seen at least this often, or None.
        max_count:  Keep values seen at most this often, or None.
        search:     Case-insensitive substring filter; empty disables it.
        seen_after: Keep values first seen after this moment, or None.

    Returns:
        ``(sql_fragment, params)`` — every value bound, nothing interpolated.
    """
    conditions = ['"Field" = ?']
    params: list = [field]
    if min_count is not None:
        conditions.append('"Count" >= ?')
        params.append(int(min_count))
    if max_count is not None:
        conditions.append('"Count" <= ?')
        params.append(int(max_count))
    if search:
        conditions.append('lower("Value") LIKE lower(?)')
        params.append(f"%{search}%")
    if seen_after is not None:
        conditions.append('"FirstSeen" >= ?')
        params.append(seen_after)
    return " AND ".join(conditions), params


def values(
    conn,
    field: str,
    *,
    limit: int | None = 20,
    ascending: bool = False,
    min_count: int | None = None,
    max_count: int | None = None,
    search: str = "",
    seen_after: date | datetime | None = None,
) -> QueryResult:
    """Return the values of *field*, filtered by the page's live controls.

    Args:
        conn:       An open read-only connection.
        field:      The field to report on.
        limit:      Maximum rows, or None for all of them.
        ascending:  True sorts rarest-first — the rare-value view.
        min_count:  Keep values seen at least this often.
        max_count:  Keep values seen at most this often (1 = singletons only).
        search:     Case-insensitive substring filter.
        seen_after: Keep values first seen after this moment — "newly seen".

    Returns:
        Value, count, Suzaku's percent, the share within the filtered subset,
        and the first/last time the value was seen.
    """
    where, params = _value_conditions(
        field,
        min_count=min_count,
        max_count=max_count,
        search=search,
        seen_after=seen_after,
    )
    direction = "ASC" if ascending else "DESC"
    sql = f"""
SELECT "Value"   AS value,
       "Count"   AS count,
       "Percent" AS percent,
       100.0 * "Count" / NULLIF(sum("Count") OVER (), 0) AS share_of_filtered,
       "FirstSeen" AS first_seen,
       "LastSeen"  AS last_seen
FROM metrics
WHERE {where}
ORDER BY count {direction}, value
{limit_clause(limit)}
"""
    return run(conn, sql, params)


def value_stats(conn, field: str) -> QueryResult:
    """Return the headline counters for one field.

    Args:
        conn:  An open read-only connection.
        field: The field to summarise.

    Returns:
        A single row: distinct values, total occurrences, the top value's share,
        how many values were seen exactly once, and the observed span.
    """
    return run(conn, _STATS_SQL, [field])


def pareto(conn, field: str, limit: int | None = 50) -> QueryResult:
    """Return the concentration curve of *field*.

    Answers "how many values do I have to read before I have seen most of the
    traffic?" — the question that decides whether a field is worth reading at
    all. The cumulative share is over the whole field, so a truncated curve
    still says how much of the field the head covers.

    Args:
        conn:  An open read-only connection.
        field: The field to report on.
        limit: Points to return, or None for the whole curve.

    Returns:
        Value, count and the cumulative percentage up to and including it.
    """
    sql = f"""
SELECT value, count, cumulative_percent
FROM (
    SELECT "Value" AS value,
           "Count" AS count,
           100.0 * sum("Count") OVER (
               ORDER BY "Count" DESC, "Value"
               ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
           ) / NULLIF(sum("Count") OVER (), 0) AS cumulative_percent,
           row_number() OVER (ORDER BY "Count" DESC, "Value") AS rank
    FROM metrics
    WHERE "Field" = ?
) AS curve
ORDER BY rank
{limit_clause(limit)}
"""
    return run(conn, sql, [field])


def values_covering(curve: pd.DataFrame, percent: float) -> int:
    """Return how many values of a :func:`pareto` curve cover *percent*.

    Args:
        curve:   The frame from :func:`pareto`.
        percent: The share to reach, e.g. ``90.0``.

    Returns:
        The number of values needed, or 0 for an empty curve.
    """
    if curve is None or curve.empty:
        return 0
    reached = curve[curve["cumulative_percent"] >= percent]
    if reached.empty:
        return len(curve)
    return int(reached.index[0]) + 1


def has_geo_data(conn, field: str) -> bool:
    """Return whether this file actually carries geo values for *field*.

    Detection only requires the geo **columns** to exist — that is what a
    ``--geo-ip`` run guarantees. The fixture proves the columns can be present
    and entirely NULL, in which case the page must say so rather than draw three
    empty charts, which is what the Superset dashboard does today.

    Args:
        conn:  An open read-only connection.
        field: The field being explored.

    Returns:
        True when at least one geo column has a non-empty value.
    """
    conditions = " OR ".join(
        f'("{column}" IS NOT NULL AND "{column}" <> \'\')' for column in GEO_COLUMNS
    )
    (found,) = conn.execute(
        f'SELECT count(*) FROM metrics WHERE "Field" = ? AND ({conditions}) LIMIT 1',
        [field],
    ).fetchone()
    return bool(found)


def geo_breakdown(
    conn, field: str, column: str, *, limit: int | None = 15
) -> QueryResult:
    """Return the top values of one geo column for *field*.

    Args:
        conn:   An open read-only connection.
        field:  The field being explored.
        column: One of :data:`~suzaku_db.GEO_COLUMNS`.
        limit:  Maximum rows, or None for all of them.

    Returns:
        Value and how many occurrences it accounts for.

    Raises:
        ValueError: When *column* is not a Suzaku geo column.
    """
    if column not in GEO_COLUMNS:
        raise ValueError(f"column must be one of {GEO_COLUMNS}, got {column!r}")

    sql = f"""
SELECT "{column}"   AS value,
       sum("Count") AS count,
       count(*)     AS distinct_values
FROM metrics
WHERE "Field" = ?
  AND "{column}" IS NOT NULL
  AND "{column}" <> ''
GROUP BY 1
ORDER BY count DESC, value
{limit_clause(limit)}
"""
    return run(conn, sql, [field])


def compare_fields(
    conn, field_a: str, field_b: str, *, limit: int | None = 200
) -> QueryResult:
    """Return the shared / only-A / only-B partition of two fields' values.

    Only meaningful when one file holds several fields, which is why the page
    shows this panel only then.

    Args:
        conn:    An open read-only connection.
        field_a: The field on the left.
        field_b: The field on the right.
        limit:   Maximum rows, or None for all of them.

    Returns:
        One row per value, with ``side`` and each field's count.
    """
    sql = f"""
WITH a AS (
    SELECT "Value" AS value, sum("Count") AS count
    FROM metrics WHERE "Field" = ? AND "Value" IS NOT NULL GROUP BY 1
),
b AS (
    SELECT "Value" AS value, sum("Count") AS count
    FROM metrics WHERE "Field" = ? AND "Value" IS NOT NULL GROUP BY 1
)
SELECT COALESCE(a.value, b.value) AS value,
       CASE
           WHEN a.value IS NOT NULL AND b.value IS NOT NULL THEN 'shared'
           WHEN a.value IS NOT NULL THEN 'only_a'
           ELSE 'only_b'
       END AS side,
       CAST(COALESCE(a.count, 0) AS BIGINT) AS count_a,
       CAST(COALESCE(b.count, 0) AS BIGINT) AS count_b
FROM a
FULL OUTER JOIN b ON a.value = b.value
ORDER BY side, count_a + count_b DESC, value
{limit_clause(limit)}
"""
    return run(conn, sql, [field_a, field_b])
