"""Every hunt's ``chart`` config must match the columns its SQL actually returns.

A bar chart hands ``chart.x`` and ``chart.y`` straight to Plotly Express, so a
config naming a column the query never selects raises at render time::

    ValueError: Value of 'x' is not the name of a column in 'data_frame'.

The analyst sees a traceback where a chart should be, after the query already
ran. Nothing in the YAML makes the mismatch visible, so it is checked here by
binding each hunt's SQL against its catalogue's schema and reading the result's
column names — no rows needed.

Time-series charts fail more quietly: :func:`_render_timeseries_chart` returns
without drawing when it cannot find a time column, so a mis-specified hunt shows
no chart and no error at all. Both are covered below.

Every test runs over both catalogues (see ``hunt_catalogue.py``). The Suzaku
catalogue shipped six bar charts with ``x`` and ``y`` the wrong way round for
exactly as long as this file looked at ``builtin_hunts.yaml`` alone.
"""

from __future__ import annotations

import pytest

from tests.hunt_catalogue import CATALOGUES, Catalogue, hunt_params

# Kept in sync with views.charts._TIME_COLUMN_CANDIDATES via the test below.
TIME_COLUMN_CANDIDATES = (
    "event_time",
    "timestamp",
    "day",
    "hour",
    "week",
    "month",
    "bucket",
    "hour_bucket",
    "day_bucket",
    "first_seen",
    "last_seen",
)

# The buckets `_render_timeseries_chart` knows how to resample.
SUPPORTED_BUCKETS = ("hour", "day", "week", "month")

NUMERIC_TYPE_PREFIXES = (
    "TINYINT",
    "SMALLINT",
    "INTEGER",
    "BIGINT",
    "HUGEINT",
    "UTINYINT",
    "USMALLINT",
    "UINTEGER",
    "UBIGINT",
    "FLOAT",
    "DOUBLE",
    "DECIMAL",
    "REAL",
)

BAR_HUNTS, BAR_IDS = hunt_params("bar")
TIMESERIES_HUNTS, TIMESERIES_IDS = hunt_params("timeseries")
CHARTED_HUNTS, CHARTED_IDS = hunt_params("charted")


@pytest.fixture(scope="module")
def connections() -> dict[str, object]:
    """One open connection per catalogue, keyed by ``Catalogue.key``."""
    conns = {catalogue.key: catalogue.connect() for catalogue in CATALOGUES}
    try:
        yield conns
    finally:
        for conn in conns.values():
            conn.close()


def result_columns(conn, sql: str) -> list[str]:
    return [description[0] for description in conn.execute(sql).description]


def result_types(conn, sql: str) -> dict[str, str]:
    return {
        name: str(type_code) for name, type_code, *_ in conn.execute(sql).description
    }


def declared_columns(chart: dict) -> list[tuple[str, str]]:
    """The (key, column) pairs a chart config names."""
    pairs = []
    if chart.get("x"):
        pairs.append(("x", chart["x"]))
    y_columns = chart.get("y") or []
    if isinstance(y_columns, str):
        y_columns = [y_columns]
    pairs.extend(("y", column) for column in y_columns)
    return pairs


def _is_numeric(duckdb_type: str) -> bool:
    """DuckDB reports concrete types (``BIGINT``, ``DECIMAL(2,1)``), not DB-API codes."""
    return duckdb_type.upper().startswith(NUMERIC_TYPE_PREFIXES)


# ---------------------------------------------------------------------------
# Bar charts — a missing column raises at render time
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("catalogue", "hunt"), BAR_HUNTS, ids=BAR_IDS)
def test_bar_chart_columns_are_returned_by_the_sql(
    catalogue: Catalogue, hunt: dict, connections
) -> None:
    columns = result_columns(connections[catalogue.key], hunt["sql"])
    missing = [
        f"{key}={column!r}"
        for key, column in declared_columns(hunt["chart"])
        if column not in columns
    ]
    assert not missing, (
        f"{hunt['label']}: chart names {', '.join(missing)}, but the SQL returns "
        f"{columns}. Plotly raises ValueError on render."
    )


@pytest.mark.parametrize(("catalogue", "hunt"), BAR_HUNTS, ids=BAR_IDS)
def test_bar_chart_declares_both_axes(catalogue: Catalogue, hunt: dict) -> None:
    """A bar config missing either axis silently renders nothing."""
    chart = hunt["chart"]
    assert chart.get("x"), f"{hunt['label']}: bar chart has no x"
    assert chart.get("y"), f"{hunt['label']}: bar chart has no y"


@pytest.mark.parametrize(("catalogue", "hunt"), BAR_HUNTS, ids=BAR_IDS)
def test_bar_chart_y_columns_are_numeric(
    catalogue: Catalogue, hunt: dict, connections
) -> None:
    """The y columns are the measured values, so they have to be numbers.

    ``_render_bar_chart`` draws ``px.bar(x=chart.y, y=chart.x, orientation="h")``
    — ``y`` is the bar *length*. A category there still renders, against a string
    axis, which is how the reversed Suzaku configs went unnoticed.
    """
    types = result_types(connections[catalogue.key], hunt["sql"])
    non_numeric = [
        column
        for key, column in declared_columns(hunt["chart"])
        if key == "y" and not _is_numeric(types.get(column, ""))
    ]
    assert not non_numeric, (
        f"{hunt['label']}: y columns {non_numeric} are not numeric "
        f"({ {c: types.get(c) for c in non_numeric} }) — x is the category, "
        f"y the measure"
    )


@pytest.mark.parametrize(("catalogue", "hunt"), BAR_HUNTS, ids=BAR_IDS)
def test_bar_chart_x_column_is_a_category(
    catalogue: Catalogue, hunt: dict, connections
) -> None:
    """``chart.x`` labels the bars, so a measure there means the axes are swapped."""
    types = result_types(connections[catalogue.key], hunt["sql"])
    x_column = hunt["chart"].get("x")
    assert not _is_numeric(types.get(x_column, "")), (
        f"{hunt['label']}: x={x_column!r} is numeric ({types.get(x_column)}) — "
        f"x names the bars, y measures them"
    )


# ---------------------------------------------------------------------------
# Time-series charts — a missing time column draws nothing, silently
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("catalogue", "hunt"), TIMESERIES_HUNTS, ids=TIMESERIES_IDS)
def test_timeseries_sql_returns_a_time_column(
    catalogue: Catalogue, hunt: dict, connections
) -> None:
    columns = {
        c.lower() for c in result_columns(connections[catalogue.key], hunt["sql"])
    }
    assert columns & set(TIME_COLUMN_CANDIDATES), (
        f"{hunt['label']}: declares a timeseries chart but returns none of "
        f"{TIME_COLUMN_CANDIDATES}; the chart would never render"
    )


@pytest.mark.parametrize(("catalogue", "hunt"), TIMESERIES_HUNTS, ids=TIMESERIES_IDS)
def test_timeseries_bucket_is_supported(catalogue: Catalogue, hunt: dict) -> None:
    """An unknown bucket resamples to nothing and the chart comes out empty."""
    bucket = hunt["chart"].get("bucket")
    assert bucket in SUPPORTED_BUCKETS, f"{hunt['label']}: bucket {bucket!r}"


def test_time_column_candidates_match_the_renderer() -> None:
    """This module hardcodes the candidate list; keep it honest."""
    from views.charts import _TIME_COLUMN_CANDIDATES

    assert _TIME_COLUMN_CANDIDATES == TIME_COLUMN_CANDIDATES


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


def test_chart_types_are_known() -> None:
    types = {hunt["chart"].get("type") for _, hunt in CHARTED_HUNTS}
    assert types <= {"bar", "timeseries"}, f"unknown chart type: {types}"


def test_every_charted_hunt_is_checked() -> None:
    assert len(BAR_HUNTS) + len(TIMESERIES_HUNTS) == len(CHARTED_HUNTS)


def test_both_catalogues_are_covered() -> None:
    """A catalogue silently dropping out of the parametrization proves nothing."""
    covered = {catalogue.key for catalogue, _ in CHARTED_HUNTS}
    assert covered == {catalogue.key for catalogue in CATALOGUES}, covered
