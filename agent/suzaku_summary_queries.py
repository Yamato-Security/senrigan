"""Reviewed SQL for Suzaku's ``aws-ct-summary`` output.

Suzaku aggregates CloudTrail into a per-identity threat profile across three
tables — ``summary``, ``summary_api_calls`` and ``summary_attributes``. Every
statement the Summary page runs lives here so it can be read, reviewed and
tested; the page itself only chooses which one to run and how to draw it.

Two rules hold throughout:

* **Every value that comes from the data is a bound parameter.** An identity ARN
  or an attribute value is never formatted into the statement, whatever it
  contains.
* **Columns are renamed to snake_case.** Suzaku writes PascalCase, the Superset
  virtual datasets already rename, and a report reads better with one
  convention.
"""

from __future__ import annotations

import pandas as pd

from suzaku_queries import QueryResult, limit_clause, run

# ``Outcome`` is an ENUM of exactly these two values. It selects a code path in
# the UI, so anything else is a bug rather than an empty result.
OUTCOMES: tuple[str, ...] = ("success", "failed")

# What two identities can be compared on. ``api`` reads ``summary_api_calls``;
# the rest are ``summary_attributes.Attribute`` values. Free text is refused
# because the choice picks a table and a column.
COMPARE_DIMENSIONS: tuple[str, ...] = (
    "api",
    "SrcIP",
    "UserAgent",
    "UserAccessKeyID",
    "AwsRegion",
)

# The identity triage table: one row per identity, with the abuse counts and the
# attribute breadth that decide which identity to open first.
_OVERVIEW_SQL = """
WITH abuse AS (
    SELECT "UserARN" AS user_arn,
           count(*) FILTER (WHERE "IsAbused" AND "Outcome" = 'success')
               AS abused_success,
           count(*) FILTER (WHERE "IsAbused" AND "Outcome" = 'failed')
               AS abused_failed,
           count(*) FILTER (WHERE NOT "IsAbused") AS other_apis
    FROM summary_api_calls
    GROUP BY 1
),
attrs AS (
    SELECT "UserARN" AS user_arn,
           count(DISTINCT "Value") FILTER (WHERE "Attribute" = 'SrcIP')
               AS src_ips,
           count(DISTINCT "Value") FILTER (WHERE "Attribute" = 'UserAgent')
               AS user_agents,
           count(DISTINCT "Value") FILTER (WHERE "Attribute" = 'AwsRegion')
               AS aws_regions,
           count(DISTINCT "Value") FILTER (WHERE "Attribute" = 'UserAccessKeyID')
               AS access_keys
    FROM summary_attributes
    GROUP BY 1
)
SELECT s."UserARN"                          AS user_arn,
       array_to_string(s."UserTypes", ', ') AS user_types,
       s."NumOfEvents"                      AS num_of_events,
       s."FirstTimestamp"                   AS first_seen,
       s."LastTimestamp"                    AS last_seen,
       COALESCE(abuse.abused_success, 0)    AS abused_success,
       COALESCE(abuse.abused_failed, 0)     AS abused_failed,
       COALESCE(abuse.other_apis, 0)        AS other_apis,
       COALESCE(attrs.src_ips, 0)           AS src_ips,
       COALESCE(attrs.user_agents, 0)       AS user_agents,
       COALESCE(attrs.aws_regions, 0)       AS aws_regions,
       COALESCE(attrs.access_keys, 0)       AS access_keys
FROM summary AS s
LEFT JOIN abuse ON abuse.user_arn = s."UserARN"
LEFT JOIN attrs ON attrs.user_arn = s."UserARN"
ORDER BY abused_success DESC, abused_failed DESC, num_of_events DESC
"""

_FACTS_SQL = """
SELECT "UserARN"                          AS user_arn,
       array_to_string("UserTypes", ', ') AS user_types,
       "NumOfEvents"                      AS num_of_events,
       "FirstTimestamp"                   AS first_seen,
       "LastTimestamp"                    AS last_seen
FROM summary
WHERE "UserARN" = ?
"""


def identity_overview(conn) -> QueryResult:
    """Return the triage table: every identity, abused counts first.

    Args:
        conn: An open read-only connection to a summary database.

    Returns:
        One row per identity, ordered so the identity to open first is on top.
    """
    return run(conn, _OVERVIEW_SQL)


def overview_kpis(overview: pd.DataFrame) -> dict[str, int]:
    """Return the run-wide counters shown above the triage table.

    Derived from the triage frame rather than re-queried: the numbers must match
    the table an analyst is looking at, and they are the same numbers the
    Superset KPI row shows, which is how the two UIs are checked against each
    other.

    Args:
        overview: The frame from :func:`identity_overview`.

    Returns:
        ``identities``, ``total_events``, ``abused_apis``, ``failed_abuse``,
        ``identities_abused``; zeros for an empty frame.
    """
    if overview is None or overview.empty:
        return {
            "identities": 0,
            "total_events": 0,
            "abused_apis": 0,
            "failed_abuse": 0,
            "identities_abused": 0,
        }
    abused_total = overview["abused_success"] + overview["abused_failed"]
    return {
        "identities": len(overview),
        "total_events": int(overview["num_of_events"].sum()),
        "abused_apis": int(overview["abused_success"].sum()),
        "failed_abuse": int(overview["abused_failed"].sum()),
        "identities_abused": int((abused_total > 0).sum()),
    }


def resolve_identity(arns: list[str], clicked_row: int | None, stored: str) -> str:
    """Return the identity the page should show.

    Three inputs decide it, in priority order: a row the analyst just clicked in
    the triage table, the identity they were already on, and — failing both —
    the first row, which is the most abused one.

    Args:
        arns:        Identities in the order the triage table lists them.
        clicked_row: Positional index of a clicked row, or None.
        stored:      Identity held in session state, possibly stale.

    Returns:
        The identity to render, or ``""`` when there are none.
    """
    if not arns:
        return ""
    if clicked_row is not None and 0 <= clicked_row < len(arns):
        return arns[clicked_row]
    if stored in arns:
        return stored
    return arns[0]


def identity_facts(conn, user_arn: str) -> QueryResult:
    """Return the header row for one identity.

    Args:
        conn:     An open read-only connection.
        user_arn: The identity to describe.

    Returns:
        A single row, or an empty frame when the ARN is not in this file.
    """
    return run(conn, _FACTS_SQL, [user_arn])


def api_calls(
    conn,
    user_arn: str,
    *,
    abused: bool = True,
    outcome: str = "success",
    limit: int | None = 10,
) -> QueryResult:
    """Return one quadrant of the ``IsAbused`` x ``Outcome`` matrix.

    The abused quadrants are the analytic centre of the file — 221 of the
    fixture's 2,667 rows — which is why they are addressed separately rather
    than filtered out of one big table.

    Args:
        conn:     An open read-only connection.
        user_arn: The identity to report on.
        abused:   True for APIs Suzaku flags as attack-relevant.
        outcome:  ``"success"`` or ``"failed"``.
        limit:    Maximum rows, or None for all of them.

    Returns:
        API, description, count and the first/last time it was seen.

    Raises:
        ValueError: When *outcome* is not one of :data:`OUTCOMES`.
    """
    if outcome not in OUTCOMES:
        raise ValueError(f"outcome must be one of {OUTCOMES}, got {outcome!r}")

    sql = f"""
SELECT "API" || ' (' || "EventSource" || ')' AS api,
       "API"                                 AS api_name,
       "EventSource"                         AS event_source,
       "Description"                         AS description,
       "Count"                               AS count,
       "FirstSeen"                           AS first_seen,
       "LastSeen"                            AS last_seen
FROM summary_api_calls
WHERE "UserARN" = ?
  AND "IsAbused" = ?
  AND CAST("Outcome" AS VARCHAR) = ?
ORDER BY count DESC, api
{limit_clause(limit)}
"""
    return run(conn, sql, [user_arn, abused, outcome])


def attribute_kinds(conn) -> list[str]:
    """Return the attribute names this file actually carries.

    Read from the data rather than hard-coded, so a Suzaku release that adds an
    attribute gets its own tab without a code change.

    Args:
        conn: An open read-only connection.

    Returns:
        The distinct ``Attribute`` values, alphabetically.
    """
    rows = conn.execute(
        'SELECT DISTINCT "Attribute" FROM summary_attributes ORDER BY 1'
    ).fetchall()
    return [name for (name,) in rows]


def attribute_values(
    conn,
    user_arn: str,
    attribute: str,
    *,
    limit: int | None = 10,
    ascending: bool = False,
    search: str = "",
) -> QueryResult:
    """Return one identity's values for one attribute.

    Args:
        conn:      An open read-only connection.
        user_arn:  The identity to report on.
        attribute: ``SrcIP`` / ``UserAgent`` / ``AwsRegion`` / ``UserAccessKeyID``
                   or whatever else :func:`attribute_kinds` found.
        limit:     Maximum rows, or None for all of them.
        ascending: True sorts rarest-first — the rare-value view.
        search:    Case-insensitive substring filter; empty disables it.

    Returns:
        Value, count and the first/last time it was seen.
    """
    params: list = [user_arn, attribute]
    condition = ""
    if search:
        condition = 'AND lower("Value") LIKE lower(?)'
        params.append(f"%{search}%")

    direction = "ASC" if ascending else "DESC"
    sql = f"""
SELECT "Value"     AS value,
       "Count"     AS count,
       "FirstSeen" AS first_seen,
       "LastSeen"  AS last_seen
FROM summary_attributes
WHERE "UserARN" = ?
  AND "Attribute" = ?
  {condition}
ORDER BY count {direction}, value
{limit_clause(limit)}
"""
    return run(conn, sql, params)


def identities_sharing(
    conn, attribute: str, value: str, *, limit: int | None = 50
) -> QueryResult:
    """Return every identity that used one attribute value.

    This is the drill-down the Superset dashboard cannot offer: from "this IP
    appears under the identity I am reading" to "who else used it".

    Args:
        conn:      An open read-only connection.
        attribute: The attribute the value belongs to.
        value:     The exact value, bound as a parameter.
        limit:     Maximum rows, or None for all of them.

    Returns:
        Identity, count and the first/last time it used the value.
    """
    sql = f"""
SELECT "UserARN"   AS user_arn,
       "Count"     AS count,
       "FirstSeen" AS first_seen,
       "LastSeen"  AS last_seen
FROM summary_attributes
WHERE "Attribute" = ?
  AND "Value" = ?
ORDER BY count DESC, user_arn
{limit_clause(limit)}
"""
    return run(conn, sql, [attribute, value])


def _dimension_source(dimension: str) -> tuple[str, str, list]:
    """Return the table, value expression and extra parameters for *dimension*.

    Args:
        dimension: One of :data:`COMPARE_DIMENSIONS`.

    Returns:
        ``(table, value_expression, extra_conditions_params)``.

    Raises:
        ValueError: When *dimension* is not one of :data:`COMPARE_DIMENSIONS`.
    """
    if dimension not in COMPARE_DIMENSIONS:
        raise ValueError(
            f"dimension must be one of {COMPARE_DIMENSIONS}, got {dimension!r}"
        )
    if dimension == "api":
        return (
            "summary_api_calls",
            "\"API\" || ' (' || \"EventSource\" || ')'",
            [],
        )
    return ("summary_attributes", '"Value"', [dimension])


def dimension_values(conn, user_arn: str, dimension: str) -> list[str]:
    """Return the distinct values one identity has along *dimension*.

    Args:
        conn:      An open read-only connection.
        user_arn:  The identity to read.
        dimension: One of :data:`COMPARE_DIMENSIONS`.

    Returns:
        The values, unordered duplicates removed.
    """
    table, expression, extra = _dimension_source(dimension)
    condition = 'AND "Attribute" = ?' if extra else ""
    rows = conn.execute(
        f"SELECT DISTINCT {expression} FROM {table} "
        f'WHERE "UserARN" = ? {condition} AND {expression} IS NOT NULL',
        [user_arn, *extra],
    ).fetchall()
    return [value for (value,) in rows]


def compare_identities(
    conn, user_arn_a: str, user_arn_b: str, dimension: str, *, limit: int | None = 200
) -> QueryResult:
    """Return the shared / only-A / only-B partition of two identities.

    A set comparison is not something a Superset chart can express, and it is
    the fastest way to answer "did these two identities come from the same
    hands?".

    Args:
        conn:       An open read-only connection.
        user_arn_a: The identity on the left.
        user_arn_b: The identity on the right.
        dimension:  One of :data:`COMPARE_DIMENSIONS`.
        limit:      Maximum rows, or None for all of them.

    Returns:
        One row per value, with ``side`` in ``shared`` / ``only_a`` / ``only_b``
        and the count each identity contributed.

    Raises:
        ValueError: When *dimension* is not one of :data:`COMPARE_DIMENSIONS`.
    """
    table, expression, extra = _dimension_source(dimension)
    condition = 'AND "Attribute" = ?' if extra else ""

    # NULL is a real state in this file (an identity with no access key, for
    # instance). Both sides exclude it: "both used <unknown>" is not evidence
    # that two identities are related, which is the question this panel asks.
    sql = f"""
WITH a AS (
    SELECT {expression} AS value, sum("Count") AS count
    FROM {table}
    WHERE "UserARN" = ? {condition}
      AND {expression} IS NOT NULL
    GROUP BY 1
),
b AS (
    SELECT {expression} AS value, sum("Count") AS count
    FROM {table}
    WHERE "UserARN" = ? {condition}
      AND {expression} IS NOT NULL
    GROUP BY 1
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
    return run(conn, sql, [user_arn_a, *extra, user_arn_b, *extra])
