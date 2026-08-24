"""Tests for the ``aws-ct-summary`` query layer.

Every statement the Summary page runs lives here, so this is where the SQL is
proved: against the committed fixture, with a hand-written control query
wherever a number matters, and with bound parameters wherever a value comes
from the data.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import duckdb
import pytest

import suzaku_summary_queries as sq

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "sample"
    / "suzaku"
    / "fixtures"
    / "suzaku-aws-ct-summary.duckdb"
)

# The two identities that dominate the fixture (680,449 and 651,646 events).
TOP_ARN = "arn:aws:iam::811596193553:user/backup"
SECOND_ARN = "arn:aws:iam::811596193553:user/Level6"


@pytest.fixture(scope="module")
def conn() -> Iterator[duckdb.DuckDBPyConnection]:
    """One read-only connection to the committed summary fixture."""
    connection = duckdb.connect(str(FIXTURE), read_only=True)
    try:
        yield connection
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Identity overview (tests 5-6)
# ---------------------------------------------------------------------------


def test_identity_overview_returns_one_row_per_identity(conn) -> None:
    """Test 5: the triage table is the landing view — one row per identity."""
    result = sq.identity_overview(conn)

    assert len(result.df) == 22
    assert result.df["user_arn"].is_unique
    assert {
        "user_arn",
        "user_types",
        "num_of_events",
        "first_seen",
        "last_seen",
        "abused_success",
        "abused_failed",
        "src_ips",
        "user_agents",
        "aws_regions",
        "access_keys",
    } <= set(result.df.columns)


def test_identity_overview_sorts_abused_identities_first(conn) -> None:
    """Triage order is what the analyst reads top-down."""
    df = sq.identity_overview(conn).df

    assert list(df["abused_success"]) == sorted(df["abused_success"], reverse=True)
    assert df.iloc[0]["abused_success"] > 0


def test_identity_overview_counts_match_a_control_query(conn) -> None:
    """Test 6: the abused counts drive triage, so they are checked directly."""
    df = sq.identity_overview(conn).df.set_index("user_arn")

    control = conn.execute("""
        SELECT "UserARN",
               count(*) FILTER (WHERE "IsAbused" AND "Outcome" = 'success'),
               count(*) FILTER (WHERE "IsAbused" AND "Outcome" = 'failed')
        FROM summary_api_calls
        GROUP BY 1
        """).fetchall()

    for arn, success, failed in control:
        assert int(df.loc[arn, "abused_success"]) == success
        assert int(df.loc[arn, "abused_failed"]) == failed


def test_identity_overview_flattens_user_types(conn) -> None:
    """Test 15: ``UserTypes`` is a VARCHAR[]; a list would break every widget."""
    df = sq.identity_overview(conn).df

    assert all(isinstance(value, str) for value in df["user_types"])
    assert "IAMUser" in set(df["user_types"])


def test_identity_facts_describes_one_identity(conn) -> None:
    """The header row of the identity view: type, events, first and last seen."""
    df = sq.identity_facts(conn, TOP_ARN).df

    assert len(df) == 1
    row = df.iloc[0]
    assert row["user_arn"] == TOP_ARN
    assert row["user_types"] == "IAMUser"
    assert int(row["num_of_events"]) == 680_449


def test_overview_kpis_summarise_the_run(conn) -> None:
    """The KPI row must agree with the table under it, and with the dashboard."""
    overview = sq.identity_overview(conn).df
    kpis = sq.overview_kpis(overview)

    identities, events = conn.execute(
        'SELECT count(*), sum("NumOfEvents") FROM summary'
    ).fetchone()
    abused_success, abused_failed = conn.execute("""
        SELECT count(*) FILTER (WHERE "IsAbused" AND "Outcome" = 'success'),
               count(*) FILTER (WHERE "IsAbused" AND "Outcome" = 'failed')
        FROM summary_api_calls
        """).fetchone()

    assert kpis["identities"] == identities == 22
    assert kpis["total_events"] == events
    assert kpis["abused_apis"] == abused_success == 150
    assert kpis["failed_abuse"] == abused_failed == 71
    assert 0 < kpis["identities_abused"] <= identities


def test_overview_kpis_handle_an_empty_frame() -> None:
    """An empty file must render zeros, not raise."""
    import pandas as pd

    assert sq.overview_kpis(pd.DataFrame())["identities"] == 0


def test_resolve_identity_prefers_a_clicked_row(conn) -> None:
    """Clicking the triage table is the drill-down; it wins over the stored one."""
    arns = ["a", "b", "c"]

    assert sq.resolve_identity(arns, 2, "a") == "c"
    assert sq.resolve_identity(arns, None, "b") == "b"
    # A stale selection (file switched) falls back to the most abused identity.
    assert sq.resolve_identity(arns, None, "gone") == "a"
    assert sq.resolve_identity(arns, 99, "b") == "b"
    assert sq.resolve_identity([], None, "a") == ""


# ---------------------------------------------------------------------------
# API calls (tests 7-8)
# ---------------------------------------------------------------------------


def test_api_calls_partition_the_abuse_matrix(conn) -> None:
    """Test 7: ``IsAbused`` x ``Outcome`` is a 2x2 that must add up."""
    counts = {
        (abused, outcome): len(
            sq.api_calls(conn, TOP_ARN, abused=abused, outcome=outcome, limit=10_000).df
        )
        for abused in (True, False)
        for outcome in ("success", "failed")
    }
    total = conn.execute(
        'SELECT count(*) FROM summary_api_calls WHERE "UserARN" = ?', [TOP_ARN]
    ).fetchone()[0]

    assert sum(counts.values()) == total
    # The abused quadrants are the point of the page and are never empty here.
    assert counts[(True, "success")] > 0
    assert counts[(True, "failed")] > 0


def test_api_calls_are_ordered_and_capped(conn) -> None:
    """Test 8: the panel shows a Top-N, ordered by count, with descriptions."""
    result = sq.api_calls(conn, TOP_ARN, abused=True, outcome="success", limit=5)
    df = result.df

    assert len(df) == 5
    assert list(df["count"]) == sorted(df["count"], reverse=True)
    assert "description" in df.columns
    # The screenshot's label format: action plus the service that owns it.
    assert df.iloc[0]["api"].endswith(")")
    assert "amazonaws.com" in df.iloc[0]["api"]


def test_api_calls_rejects_an_unknown_outcome(conn) -> None:
    """``Outcome`` picks a code path, so an unexpected value is a bug."""
    with pytest.raises(ValueError):
        sq.api_calls(conn, TOP_ARN, abused=True, outcome="maybe")


# ---------------------------------------------------------------------------
# Attributes (tests 9-11)
# ---------------------------------------------------------------------------


def test_attribute_kinds_come_from_the_data(conn) -> None:
    """Test 9: a Suzaku release adding an attribute must need no code change."""
    assert sq.attribute_kinds(conn) == [
        "AwsRegion",
        "SrcIP",
        "UserAccessKeyID",
        "UserAgent",
    ]


def test_attribute_values_returns_the_top_slice(conn) -> None:
    """The default view of an attribute tab: busiest values first."""
    df = sq.attribute_values(conn, TOP_ARN, "SrcIP", limit=10).df

    assert len(df) == 10
    assert list(df["count"]) == sorted(df["count"], reverse=True)
    assert set(df.columns) >= {"value", "count", "first_seen", "last_seen"}


def test_attribute_values_ascending_surfaces_the_rare_tail(conn) -> None:
    """Test 10a: rare values are the interesting ones, so they are reachable."""
    df = sq.attribute_values(conn, TOP_ARN, "SrcIP", limit=10, ascending=True).df

    assert list(df["count"]) == sorted(df["count"])
    assert df.iloc[0]["count"] <= df.iloc[-1]["count"]


def test_attribute_values_search_is_case_insensitive(conn) -> None:
    """Test 10b: the search box is a live filter, not an exact match."""
    df = sq.attribute_values(conn, TOP_ARN, "UserAgent", limit=50, search="AWS").df
    lowered = sq.attribute_values(conn, TOP_ARN, "UserAgent", limit=50, search="aws").df

    assert not df.empty
    assert len(df) == len(lowered)
    assert all("aws" in value.lower() for value in df["value"])


def test_identities_sharing_finds_every_user_of_a_value(conn) -> None:
    """Test 11: the drill-down that turns a summary into an investigation."""
    shared_ip = conn.execute("""
        SELECT "Value"
        FROM summary_attributes
        WHERE "Attribute" = 'SrcIP'
        GROUP BY 1
        HAVING count(DISTINCT "UserARN") > 1
        ORDER BY count(DISTINCT "UserARN") DESC
        LIMIT 1
        """).fetchone()[0]
    expected = conn.execute(
        'SELECT count(DISTINCT "UserARN") FROM summary_attributes '
        'WHERE "Attribute" = \'SrcIP\' AND "Value" = ?',
        [shared_ip],
    ).fetchone()[0]

    df = sq.identities_sharing(conn, "SrcIP", shared_ip).df

    assert len(df) == expected > 1
    assert df["user_arn"].is_unique


# ---------------------------------------------------------------------------
# Comparison (test 12)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("dimension", ["api", "SrcIP", "UserAgent", "UserAccessKeyID"])
def test_compare_identities_partitions_both_sets(conn, dimension: str) -> None:
    """Test 12: shared / only-A / only-B must be a partition, not an overlap."""
    df = sq.compare_identities(conn, TOP_ARN, SECOND_ARN, dimension, limit=None).df

    sides = {side: set(rows["value"]) for side, rows in df.groupby("side")}
    shared = sides.get("shared", set())
    only_a = sides.get("only_a", set())
    only_b = sides.get("only_b", set())

    assert not shared & only_a
    assert not shared & only_b
    assert not only_a & only_b

    a_values = set(sq.dimension_values(conn, TOP_ARN, dimension))
    assert shared | only_a == a_values


def test_compare_identities_ignores_unknown_values(conn) -> None:
    """A shared NULL is not evidence that two identities are related."""
    df = sq.compare_identities(
        conn, TOP_ARN, SECOND_ARN, "UserAccessKeyID", limit=None
    ).df

    assert not df.empty
    assert df["value"].notna().all()


def test_compare_identities_rejects_an_unknown_dimension(conn) -> None:
    """The dimension selects columns and a table, so it is never free text."""
    with pytest.raises(ValueError):
        sq.compare_identities(conn, TOP_ARN, SECOND_ARN, "DROP TABLE summary")


# ---------------------------------------------------------------------------
# Robustness (tests 13-14)
# ---------------------------------------------------------------------------


def test_unknown_identity_returns_empty_frames(conn) -> None:
    """Test 13: a stale selection must render an empty panel, not a traceback."""
    missing = "arn:aws:iam::000000000000:user/ghost"

    assert sq.identity_facts(conn, missing).df.empty
    assert sq.api_calls(conn, missing, abused=True, outcome="success").df.empty
    assert sq.attribute_values(conn, missing, "SrcIP").df.empty


def test_values_from_the_data_are_bound_not_interpolated(conn) -> None:
    """Test 14: an ARN carrying a quote must be a value, never SQL."""
    hostile = "arn:aws:iam::1:user/x' OR 1=1 --"

    assert sq.identity_facts(conn, hostile).df.empty
    assert sq.attribute_values(conn, hostile, "SrcIP").df.empty
    assert sq.identities_sharing(conn, "SrcIP", "'; DROP TABLE summary; --").df.empty


def test_every_result_carries_the_sql_it_ran(conn) -> None:
    """A pinned panel reports its own SQL, so the query layer returns it."""
    result = sq.identity_overview(conn)

    assert "FROM summary" in result.sql
    assert result.sql.strip().upper().startswith(("SELECT", "WITH"))
