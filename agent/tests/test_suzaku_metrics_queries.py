"""Tests for the ``aws-ct-metrics`` query layer.

Covers PLAN_SUZAKU_EXPLORERS.md §5.2 and §6 (tests 16-23). Two properties matter
most here and both are asserted directly: every statement is parameterized on
``Field`` — the file may hold several, and the shipped fixture's single
``eventName`` must never be baked in — and a file whose geo columns exist but are
empty is reported as having no geo data rather than drawn as three blank charts.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Iterator

import duckdb
import pytest

import suzaku_metrics_queries as mq

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "sample"
    / "suzaku"
    / "fixtures"
    / "suzaku-aws-ct-metrics.duckdb"
)

FIELD = "eventName"


@pytest.fixture(scope="module")
def conn() -> Iterator[duckdb.DuckDBPyConnection]:
    """One read-only connection to the committed metrics fixture."""
    connection = duckdb.connect(str(FIXTURE), read_only=True)
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture
def geo_conn(tmp_path: Path) -> Iterator[duckdb.DuckDBPyConnection]:
    """A tiny metrics database whose geo columns are actually populated.

    The committed fixture comes from a ``--geo-ip`` run whose geo columns are
    all NULL, so this is the only way to cover the populated branch.
    """
    path = tmp_path / "metrics_geo.duckdb"
    connection = duckdb.connect(str(path))
    connection.execute("""
        CREATE TABLE metrics (
            "Field" VARCHAR, "TimelineColumn" VARCHAR, "Value" VARCHAR,
            "Count" BIGINT, "FieldTotal" BIGINT, "Percent" DOUBLE,
            "FirstSeen" TIMESTAMP, "LastSeen" TIMESTAMP,
            "SrcASN" VARCHAR, "SrcCity" VARCHAR, "SrcCountry" VARCHAR
        )
        """)
    connection.execute("""
        INSERT INTO metrics VALUES
            ('eventName', 'EventName', 'RunInstances', 8, 10, 80.0,
             '2024-01-01 00:00:00', '2024-01-02 00:00:00',
             'AS16509 Amazon', 'Ashburn', 'United States'),
            ('eventName', 'EventName', 'CreateUser', 2, 10, 20.0,
             '2024-01-03 00:00:00', '2024-01-04 00:00:00',
             'AS4713 NTT', 'Tokyo', 'Japan')
        """)
    connection.close()

    connection = duckdb.connect(str(path), read_only=True)
    try:
        yield connection
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Fields (test 16)
# ---------------------------------------------------------------------------


def test_fields_describes_every_field_in_the_file(conn) -> None:
    """Test 16: the field selector is built from the data, never hard-coded."""
    df = mq.fields(conn).df

    assert len(df) == 1
    row = df.iloc[0]
    assert row["field"] == FIELD
    assert row["timeline_column"] == "EventName"
    assert int(row["distinct_values"]) == 1_344
    assert int(row["total_count"]) == 1_972_588


# ---------------------------------------------------------------------------
# Values and the live controls (tests 17-18)
# ---------------------------------------------------------------------------


def test_values_returns_the_top_slice(conn) -> None:
    """The default panel: busiest values first, with both shares."""
    result = mq.values(conn, FIELD, limit=10)

    assert len(result.df) == 10
    assert list(result.df["count"]) == sorted(result.df["count"], reverse=True)
    assert {
        "value",
        "count",
        "percent",
        "share_of_filtered",
        "first_seen",
        "last_seen",
    } <= set(result.df.columns)


def test_values_controls_compose(conn) -> None:
    """Test 17: Top-N, minimum count, search and cut-off all filter together."""
    baseline = len(mq.values(conn, FIELD, limit=None).df)
    capped = len(mq.values(conn, FIELD, limit=5).df)
    frequent = mq.values(conn, FIELD, limit=None, min_count=1_000).df
    searched = mq.values(conn, FIELD, limit=None, search="describe").df
    recent = mq.values(conn, FIELD, limit=None, seen_after=datetime(2019, 1, 1)).df
    combined = mq.values(
        conn,
        FIELD,
        limit=None,
        min_count=1_000,
        search="describe",
        seen_after=datetime(2019, 1, 1),
    ).df

    assert capped == 5
    assert 0 < len(frequent) < baseline
    assert 0 < len(searched) < baseline
    assert all("describe" in value.lower() for value in searched["value"])
    assert all(count >= 1_000 for count in frequent["count"])
    assert 0 < len(recent) <= baseline
    assert len(combined) <= min(len(frequent), len(searched), len(recent))


def test_values_ascending_surfaces_the_singletons(conn) -> None:
    """Test 18: 225 of the fixture's 1,344 values were seen exactly once."""
    df = mq.values(conn, FIELD, limit=None, ascending=True).df

    assert list(df["count"]) == sorted(df["count"])
    assert int(df.iloc[0]["count"]) == 1
    assert len(mq.values(conn, FIELD, limit=None, max_count=1).df) == 225


def test_share_of_filtered_is_recomputed_over_the_subset(conn) -> None:
    """Suzaku's ``Percent`` is the share of the field; the filter needs its own."""
    df = mq.values(conn, FIELD, limit=None, min_count=1_000).df

    assert df["share_of_filtered"].sum() == pytest.approx(100.0, abs=0.01)
    # The filtered subset is a fraction of the field, so its own shares are larger.
    assert (df["share_of_filtered"] >= df["percent"]).all()


# ---------------------------------------------------------------------------
# Statistics and concentration (tests 19-20)
# ---------------------------------------------------------------------------


def test_value_stats_match_control_queries(conn) -> None:
    """Test 20: the KPI row is checked against the table it summarises."""
    stats = mq.value_stats(conn, FIELD).df.iloc[0]

    distinct, total, top = conn.execute(
        'SELECT count(*), sum("Count"), max("Count") FROM metrics WHERE "Field" = ?',
        [FIELD],
    ).fetchone()
    singletons = conn.execute(
        'SELECT count(*) FROM metrics WHERE "Field" = ? AND "Count" = 1', [FIELD]
    ).fetchone()[0]

    assert int(stats["distinct_values"]) == distinct == 1_344
    assert int(stats["total_count"]) == total
    assert int(stats["singletons"]) == singletons == 225
    assert stats["top_share"] == pytest.approx(100.0 * top / total, abs=0.01)


def test_pareto_accumulates_to_the_whole_field(conn) -> None:
    """Test 19: "how many values cover 90%?" is one glance at this curve."""
    df = mq.pareto(conn, FIELD, limit=None).df

    assert list(df["cumulative_percent"]) == sorted(df["cumulative_percent"])
    assert df.iloc[-1]["cumulative_percent"] == pytest.approx(100.0, abs=0.01)
    assert 0 < mq.values_covering(df, 90.0) < 1_344


def test_pareto_respects_its_limit(conn) -> None:
    """The chart shows a head of the curve, not 1,344 points."""
    assert len(mq.pareto(conn, FIELD, limit=20).df) == 20


# ---------------------------------------------------------------------------
# Geo (tests 21-22)
# ---------------------------------------------------------------------------


def test_has_geo_data_is_false_when_the_columns_are_empty(conn) -> None:
    """Test 21: the fixture is a ``--geo-ip`` run with no geo values at all.

    Fitness only requires the columns to *exist*, which is why the page has to
    ask this separately instead of trusting detection.
    """
    assert mq.has_geo_data(conn, FIELD) is False


def test_geo_breakdown_is_empty_rather_than_broken(conn) -> None:
    """Test 22: an empty geo column returns no rows and raises nothing."""
    for column in ("SrcCountry", "SrcCity", "SrcASN"):
        assert mq.geo_breakdown(conn, FIELD, column).df.empty


def test_geo_breakdown_reads_a_populated_file(geo_conn) -> None:
    """Test 30 (query half): the populated branch must actually work."""
    assert mq.has_geo_data(geo_conn, FIELD) is True

    df = mq.geo_breakdown(geo_conn, FIELD, "SrcCountry").df
    assert list(df["value"]) == ["United States", "Japan"]
    assert list(df["count"]) == [8, 2]


def test_geo_breakdown_rejects_a_column_outside_the_geo_set(conn) -> None:
    """The column names a real column, so it is never free text."""
    with pytest.raises(ValueError):
        mq.geo_breakdown(conn, FIELD, "Value")


# ---------------------------------------------------------------------------
# Parameterization (test 23)
# ---------------------------------------------------------------------------


def test_field_is_bound_not_interpolated(conn) -> None:
    """Test 23: a field name carrying a quote must be a value, never SQL."""
    hostile = "eventName' OR 1=1 --"

    assert mq.values(conn, hostile).df.empty
    assert mq.pareto(conn, hostile).df.empty
    assert mq.geo_breakdown(conn, hostile, "SrcCountry").df.empty
    assert int(mq.value_stats(conn, hostile).df.iloc[0]["distinct_values"]) == 0


def test_compare_fields_partitions_two_fields(geo_conn, tmp_path: Path) -> None:
    """Two fields in one file can be compared by the values they share."""
    path = tmp_path / "two_fields.duckdb"
    writable = duckdb.connect(str(path))
    writable.execute("""
        CREATE TABLE metrics AS
        SELECT * FROM (VALUES
            ('eventName', 'EventName', 'shared', 5, 10, 50.0,
             TIMESTAMP '2024-01-01', TIMESTAMP '2024-01-02', NULL, NULL, NULL),
            ('eventName', 'EventName', 'only_a', 5, 10, 50.0,
             TIMESTAMP '2024-01-01', TIMESTAMP '2024-01-02', NULL, NULL, NULL),
            ('userName', 'UserName', 'shared', 3, 6, 50.0,
             TIMESTAMP '2024-01-01', TIMESTAMP '2024-01-02', NULL, NULL, NULL),
            ('userName', 'UserName', 'only_b', 3, 6, 50.0,
             TIMESTAMP '2024-01-01', TIMESTAMP '2024-01-02', NULL, NULL, NULL)
        ) AS t("Field", "TimelineColumn", "Value", "Count", "FieldTotal",
               "Percent", "FirstSeen", "LastSeen", "SrcASN", "SrcCity",
               "SrcCountry")
        """)
    writable.close()

    reader = duckdb.connect(str(path), read_only=True)
    try:
        df = reader.execute("SELECT count(*) FROM metrics").fetchone()
        assert df[0] == 4
        result = mq.compare_fields(reader, "eventName", "userName", limit=None).df
    finally:
        reader.close()

    sides = dict(zip(result["value"], result["side"]))
    assert sides == {"shared": "shared", "only_a": "only_a", "only_b": "only_b"}
