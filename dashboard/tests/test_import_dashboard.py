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
