"""Tests for import_dashboard.py — query_context orderby generation.

Superset renders dashboard charts from the stored query_context, whose
queries[0].orderby entries are [metric, is_ascending] pairs.  An empty
orderby produces SQL with NO ORDER BY at all (order_desc alone is ignored
by the v1 chart-data path), so LIMIT then returns arbitrary rows.

_first_orderby must therefore emit an orderby for BOTH named metrics and
adhoc metric dicts (via their label, which Superset resolves to the SELECT
alias), honoring params.order_desc: order_desc=True -> [[metric, False]]
(descending), order_desc=False -> [[metric, True]] (ascending).

_needs_query_context must flag stale contexts (metrics present but empty
orderby) for regeneration so already-imported charts get repaired on the
next superset-init run.
"""

import json
import os
import sys

import yaml

INIT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "init"))
if INIT_DIR not in sys.path:
    sys.path.insert(0, INIT_DIR)

from import_dashboard import (  # noqa: E402
    _first_orderby,
    _needs_query_context,
    _patch_metadata_type,
)

IMPORT_DASHBOARD_PATH = os.path.join(INIT_DIR, "import_dashboard.py")

ADHOC_METRIC = {
    "expressionType": "SQL",
    "sqlExpression": "COUNT(*)",
    "label": "call_count",
}


def test_first_orderby_named_metric_descending() -> None:
    """order_desc=True keeps the current descending behavior."""
    assert _first_orderby(["count"], order_desc=True) == [["count", False]]


def test_first_orderby_named_metric_ascending() -> None:
    """order_desc=False must produce an ascending orderby tuple."""
    assert _first_orderby(["count"], order_desc=False) == [["count", True]]


def test_first_orderby_empty_metrics() -> None:
    """No metrics -> no orderby, regardless of direction."""
    assert _first_orderby([], order_desc=True) == []
    assert _first_orderby([], order_desc=False) == []


def test_first_orderby_adhoc_metric_uses_label() -> None:
    """Adhoc metric dicts order by their label (the SELECT alias).

    Verified against Superset 6.1: orderby [["<label>", asc]] generates
    ORDER BY <alias>; an empty orderby generates no ORDER BY at all.
    """
    assert _first_orderby([ADHOC_METRIC], order_desc=True) == [["call_count", False]]
    assert _first_orderby([ADHOC_METRIC], order_desc=False) == [["call_count", True]]


def test_first_orderby_adhoc_metric_without_label_returns_empty() -> None:
    """An adhoc metric with no label cannot be referenced in orderby."""
    adhoc = {"expressionType": "SQL", "sqlExpression": "COUNT(*)"}
    assert _first_orderby([adhoc], order_desc=True) == []
    assert _first_orderby([adhoc], order_desc=False) == []


# ---------------------------------------------------------------------------
# _needs_query_context — stale-context detection
# ---------------------------------------------------------------------------


def _make_qc(orderby: list, metrics: list) -> str:
    return json.dumps(
        {
            "datasource": {"id": 1, "type": "table"},
            "queries": [{"metrics": metrics, "orderby": orderby}],
        }
    )


def test_needs_query_context_missing_or_invalid() -> None:
    """Absent, placeholder, or malformed contexts must be (re)built."""
    assert _needs_query_context(None, "table") is True
    assert _needs_query_context("", "table") is True
    assert _needs_query_context("null", "table") is True
    assert _needs_query_context("{}", "table") is True
    assert _needs_query_context("not json", "table") is True
    assert _needs_query_context(json.dumps({"queries": []}), "table") is True


def test_needs_query_context_valid_with_orderby() -> None:
    """A context with a populated orderby is healthy — keep it."""
    qc = _make_qc(orderby=[["call_count", True]], metrics=[ADHOC_METRIC])
    assert _needs_query_context(qc, "table") is False


def test_needs_query_context_stale_empty_orderby() -> None:
    """Metrics with an empty orderby is the stale shape produced by the
    old adhoc-metric code path — must be regenerated."""
    qc = _make_qc(orderby=[], metrics=[ADHOC_METRIC])
    assert _needs_query_context(qc, "table") is True


def test_needs_query_context_pie_sunburst_exempt() -> None:
    """Pie/sunburst sort via sort_by_metric — empty orderby is correct."""
    qc = _make_qc(orderby=[], metrics=[ADHOC_METRIC])
    assert _needs_query_context(qc, "pie") is False
    assert _needs_query_context(qc, "sunburst") is False


def test_needs_query_context_no_metrics_empty_orderby_ok() -> None:
    """No metrics -> nothing to order by; empty orderby is not stale."""
    qc = _make_qc(orderby=[], metrics=[])
    assert _needs_query_context(qc, "table") is False


# ---------------------------------------------------------------------------
# ImportAssetsCommand — charts must be overwritten on re-import
# ---------------------------------------------------------------------------


def test_patch_metadata_type_rewrites_dashboard_to_assets() -> None:
    """ImportAssetsCommand requires metadata type "assets"; the ZIPs ship
    type "Dashboard" (kept for UI-import compatibility), so the script
    rewrites it in memory."""
    src = b"version: 1.0.0\ntype: Dashboard\ntimestamp: '2025-01-01'\n"
    patched = yaml.safe_load(_patch_metadata_type(src))
    assert patched["type"] == "assets"
    assert patched["version"] == "1.0.0"


def test_patch_metadata_type_handles_missing_metadata() -> None:
    """A ZIP without metadata.yaml still gets a valid assets metadata."""
    patched = yaml.safe_load(_patch_metadata_type(None))
    assert patched["type"] == "assets"
    assert patched["version"]


def test_import_uses_assets_command() -> None:
    """import_dashboard.py must import via ImportAssetsCommand.

    ImportDashboardsCommand imports bundled charts with overwrite=False
    (hardcoded in Superset), so edits to chart YAML never reach charts
    that already exist — re-running superset-init silently keeps stale
    params.  ImportAssetsCommand imports everything with overwrite=True.
    """
    with open(IMPORT_DASHBOARD_PATH, encoding="utf-8") as fh:
        source = fh.read()
    assert "ImportAssetsCommand" in source
    assert "ImportDashboardsCommand(" not in source, (
        "ImportDashboardsCommand must not be used — it imports charts "
        "with overwrite=False, so chart YAML changes are never applied "
        "to existing charts."
    )


# ── build_query_context: the stored context must ask what the chart asks ─────
#
# Superset uses the stored query_context for chart-data API calls, alerts,
# reports and thumbnails. It used to carry adhoc filters only under a key the
# API ignores, and to replace a singular `metric` with COUNT(*), so those paths
# got an unfiltered count. The shapes below are the ones Superset holds after
# importing every bundle (dist_bar arrives migrated to echarts_timeseries_bar).

from import_dashboard import build_query_context  # noqa: E402

SQL_WHERE = {
    "expressionType": "SQL",
    "clause": "WHERE",
    "sqlExpression": "action = 'REJECT'",
}
SQL_WHERE_2 = {
    "expressionType": "SQL",
    "clause": "WHERE",
    "sqlExpression": "dstport = 22",
}
SQL_HAVING = {
    "expressionType": "SQL",
    "clause": "HAVING",
    "sqlExpression": "COUNT(*) > 1",
}
SIMPLE_IN = {
    "expressionType": "SIMPLE",
    "clause": "WHERE",
    "subject": "event_name",
    "operator": "IN",
    "comparator": ["CreateUser", "DeleteTrail"],
}


def _query(
    params: dict, viz_type: str, default_time_column: str = "start_time"
) -> dict:
    qc = build_query_context(
        params, viz_type, datasource_id=7, default_time_column=default_time_column
    )
    assert qc["datasource"] == {"id": 7, "type": "table"}
    return qc["queries"][0]


def test_qc_sql_filters_become_the_where_clause() -> None:
    q = _query(
        {
            "metrics": [ADHOC_METRIC],
            "groupby": ["a"],
            "adhoc_filters": [SQL_WHERE, SQL_WHERE_2],
        },
        "table",
    )
    assert q["extras"]["where"] == "(action = 'REJECT') AND (dstport = 22)"


def test_qc_having_filters_become_the_having_clause() -> None:
    q = _query(
        {"metrics": [ADHOC_METRIC], "groupby": ["a"], "adhoc_filters": [SQL_HAVING]},
        "table",
    )
    assert q["extras"]["having"] == "(COUNT(*) > 1)"
    assert q["extras"]["where"] == ""


def test_qc_simple_filters_become_structured_filters() -> None:
    q = _query(
        {"metrics": [ADHOC_METRIC], "groupby": ["a"], "adhoc_filters": [SIMPLE_IN]},
        "table",
    )
    assert q["filters"] == [
        {"col": "event_name", "op": "IN", "val": ["CreateUser", "DeleteTrail"]}
    ]


def test_qc_singular_metric_is_kept() -> None:
    """big_number_total, pie, world_map and heatmap_v2 carry `metric`, not `metrics`."""
    q = _query({"metric": ADHOC_METRIC, "adhoc_filters": []}, "big_number_total")
    assert q["metrics"] == [ADHOC_METRIC]
    assert q["orderby"] == [["call_count", False]]


def test_qc_world_map_groups_by_its_entity() -> None:
    q = _query(
        {"metric": ADHOC_METRIC, "entity": "remote_geo_country_code"}, "world_map"
    )
    assert q["columns"] == ["remote_geo_country_code"]


def test_qc_echarts_uses_x_axis_and_groupby_and_ignores_legacy_columns() -> None:
    params = {
        "metrics": [ADHOC_METRIC],
        "x_axis": "pkt_dst_aws_service",
        "groupby": ["traffic_path_label"],
        "columns": ["traffic_path_label"],  # left behind by the dist_bar migration
    }
    q = _query(params, "echarts_timeseries_bar")
    assert q["columns"] == ["pkt_dst_aws_service", "traffic_path_label"]


def test_qc_heatmap_keeps_adhoc_axes() -> None:
    x = {
        "expressionType": "SQL",
        "sqlExpression": "EXTRACT(HOUR FROM start_time)",
        "label": "hour",
    }
    y = {
        "expressionType": "SQL",
        "sqlExpression": "EXTRACT(DOW FROM start_time)",
        "label": "dow",
    }
    q = _query({"metric": ADHOC_METRIC, "x_axis": x, "groupby": [y]}, "heatmap_v2")
    assert q["columns"] == [x, y]


def test_qc_pie_has_no_orderby() -> None:
    q = _query({"metric": ADHOC_METRIC, "groupby": ["a"]}, "pie")
    assert q["orderby"] == []


def test_qc_table_sorts_by_its_sort_metric() -> None:
    sort = {
        "expressionType": "SQL",
        "sqlExpression": "MAX(start_time)",
        "label": "last_seen",
    }
    q = _query(
        {
            "metrics": [ADHOC_METRIC],
            "groupby": ["a"],
            "timeseries_limit_metric": sort,
            "order_desc": True,
        },
        "table",
    )
    assert q["orderby"] == [[sort, False]]


def test_qc_time_column_defaults_to_the_datasets_own() -> None:
    """Defaulting to event_time breaks every dataset that has no such column."""
    qc = build_query_context(
        {"metric": ADHOC_METRIC},
        "big_number_total",
        datasource_id=1,
        default_time_column="start_time",
    )
    assert qc["form_data"]["granularity_sqla"] == "start_time"
    assert qc["queries"][0]["granularity"] == "start_time"
    declared = build_query_context(
        {"metric": ADHOC_METRIC, "granularity_sqla": "first_seen"},
        "big_number_total",
        datasource_id=1,
        default_time_column="start_time",
    )
    assert declared["queries"][0]["granularity"] == "first_seen"


def test_qc_row_limit_and_time_range() -> None:
    q = _query({"metrics": [ADHOC_METRIC], "groupby": ["a"], "row_limit": 25}, "table")
    assert q["row_limit"] == 25
    assert q["time_range"] == "No filter"
