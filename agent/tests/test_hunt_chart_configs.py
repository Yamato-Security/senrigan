"""Every hunt's ``chart`` config must match the columns its SQL actually returns.

A bar chart hands ``chart.x`` and ``chart.y`` straight to Plotly Express, so a
config naming a column the query never selects raises at render time::

    ValueError: Value of 'x' is not the name of a column in 'data_frame'.

The analyst sees a traceback where a chart should be, after the query already
ran. Nothing in the YAML makes the mismatch visible, so it is checked here by
binding each hunt's SQL against the real 48-column schema and reading the
result's column names — no rows needed.

Time-series charts fail more quietly: :func:`_render_timeseries_chart` returns
without drawing when it cannot find a time column, so a mis-specified hunt shows
no chart and no error at all. Both are covered below.
"""

from __future__ import annotations

import pathlib
from typing import Any

import duckdb
import pytest
import yaml

AGENT_DIR = pathlib.Path(__file__).parent.parent
YAML_PATH = AGENT_DIR / "builtin_hunts.yaml"

# The full cloudtrail_events schema (17 core + 7 GeoIP + 24 extended). Hunt SQL
# may use any of them, including the 18 columns withheld from the LLM.
CORE_COLUMNS = [
    "event_time TIMESTAMP",
    "event_name VARCHAR",
    "event_source VARCHAR",
    "aws_region VARCHAR",
    "source_ip_address VARCHAR",
    "user_agent VARCHAR",
    "user_identity_type VARCHAR",
    "user_identity_arn VARCHAR",
    "user_identity_account_id VARCHAR",
    "request_parameters VARCHAR",
    "response_elements VARCHAR",
    "error_code VARCHAR",
    "error_message VARCHAR",
    "read_only BOOLEAN",
    "event_type VARCHAR",
    "recipient_account_id VARCHAR",
    "raw_event VARCHAR",
]
GEO_COLUMNS = [
    "geo_country_code VARCHAR",
    "geo_country_name VARCHAR",
    "geo_city VARCHAR",
    "geo_latitude DOUBLE",
    "geo_longitude DOUBLE",
    "geo_asn VARCHAR",
    "geo_org VARCHAR",
]
EXTENDED_COLUMNS = [
    "user_identity_principal_id VARCHAR",
    "user_identity_access_key_id VARCHAR",
    "user_identity_user_name VARCHAR",
    "user_identity_invoked_by VARCHAR",
    "session_mfa_authenticated VARCHAR",
    "session_creation_date VARCHAR",
    "session_issuer_type VARCHAR",
    "session_issuer_arn VARCHAR",
    "session_issuer_account_id VARCHAR",
    "session_issuer_user_name VARCHAR",
    "session_issuer_principal_id VARCHAR",
    "event_id VARCHAR",
    "event_category VARCHAR",
    "shared_event_id VARCHAR",
    "vpc_endpoint_id VARCHAR",
    "resources VARCHAR",
    "additional_event_data VARCHAR",
    "service_event_details VARCHAR",
    "tls_version VARCHAR",
    "tls_cipher_suite VARCHAR",
    "tls_client_provided_host_header VARCHAR",
    "management_event VARCHAR",
    "session_credential_from_console VARCHAR",
    "api_version VARCHAR",
]

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


def _load() -> list[dict[str, Any]]:
    with open(YAML_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def charted_hunts() -> list[dict[str, Any]]:
    """Hunts that carry both a chart config and pre-built SQL."""
    return [h for h in _load() if h.get("chart") and h.get("sql")]


@pytest.fixture(scope="module")
def schema_conn():
    """An empty cloudtrail_events table with the full production schema."""
    conn = duckdb.connect(":memory:")
    columns = CORE_COLUMNS + GEO_COLUMNS + EXTENDED_COLUMNS
    conn.execute(f"CREATE TABLE cloudtrail_events ({', '.join(columns)})")
    try:
        yield conn
    finally:
        conn.close()


def result_columns(conn, sql: str) -> list[str]:
    return [description[0] for description in conn.execute(sql).description]


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


def _is_numeric(duckdb_type: str) -> bool:
    """DuckDB reports concrete types (``BIGINT``, ``DECIMAL(2,1)``), not DB-API codes."""
    return duckdb_type.upper().startswith(NUMERIC_TYPE_PREFIXES)


def _ids(hunts: list[dict]) -> list[str]:
    return [h["label"] for h in hunts]


BAR_HUNTS = [h for h in charted_hunts() if h["chart"].get("type") == "bar"]
TIMESERIES_HUNTS = [
    h for h in charted_hunts() if h["chart"].get("type") == "timeseries"
]


# ---------------------------------------------------------------------------
# Bar charts — a missing column raises at render time
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("hunt", BAR_HUNTS, ids=_ids(BAR_HUNTS))
def test_bar_chart_columns_are_returned_by_the_sql(hunt: dict, schema_conn) -> None:
    columns = result_columns(schema_conn, hunt["sql"])
    missing = [
        f"{key}={column!r}"
        for key, column in declared_columns(hunt["chart"])
        if column not in columns
    ]
    assert not missing, (
        f"{hunt['label']}: chart names {', '.join(missing)}, but the SQL returns "
        f"{columns}. Plotly raises ValueError on render."
    )


@pytest.mark.parametrize("hunt", BAR_HUNTS, ids=_ids(BAR_HUNTS))
def test_bar_chart_declares_both_axes(hunt: dict) -> None:
    """A bar config missing either axis silently renders nothing."""
    chart = hunt["chart"]
    assert chart.get("x"), f"{hunt['label']}: bar chart has no x"
    assert chart.get("y"), f"{hunt['label']}: bar chart has no y"


@pytest.mark.parametrize("hunt", BAR_HUNTS, ids=_ids(BAR_HUNTS))
def test_bar_chart_y_columns_are_numeric(hunt: dict, schema_conn) -> None:
    """The y columns are the measured values, so they have to be numbers.

    ``_render_bar_chart`` picks its numeric columns via
    ``df.select_dtypes(include="number")`` only in the auto-detect path, but a
    non-numeric y still produces a meaningless bar length, so it is caught here.
    """
    described = schema_conn.execute(hunt["sql"]).description
    types = {name: str(type_code) for name, type_code, *_ in described}
    non_numeric = [
        column
        for key, column in declared_columns(hunt["chart"])
        if key == "y" and not _is_numeric(types.get(column, ""))
    ]
    assert not non_numeric, (
        f"{hunt['label']}: y columns {non_numeric} are not numeric "
        f"({ {c: types.get(c) for c in non_numeric} })"
    )


# ---------------------------------------------------------------------------
# Time-series charts — a missing time column draws nothing, silently
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("hunt", TIMESERIES_HUNTS, ids=_ids(TIMESERIES_HUNTS))
def test_timeseries_sql_returns_a_time_column(hunt: dict, schema_conn) -> None:
    columns = {c.lower() for c in result_columns(schema_conn, hunt["sql"])}
    assert columns & set(TIME_COLUMN_CANDIDATES), (
        f"{hunt['label']}: declares a timeseries chart but returns none of "
        f"{TIME_COLUMN_CANDIDATES}; the chart would never render"
    )


def test_time_column_candidates_match_the_renderer() -> None:
    """This module hardcodes the candidate list; keep it honest."""
    from views.charts import _TIME_COLUMN_CANDIDATES

    assert _TIME_COLUMN_CANDIDATES == TIME_COLUMN_CANDIDATES


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


def test_chart_types_are_known() -> None:
    types = {h["chart"].get("type") for h in charted_hunts()}
    assert types <= {"bar", "timeseries"}, f"unknown chart type: {types}"


def test_every_charted_hunt_is_checked() -> None:
    assert len(BAR_HUNTS) + len(TIMESERIES_HUNTS) == len(charted_hunts())
