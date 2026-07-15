"""Tests for rebuild_rare_zip.py — the Rare Events dashboard generator.

The generator derives a second Superset dashboard from cloudtrail_default/
(single source of truth): same 11-tab / 91-chart layout, but every chart
that declares params.order_desc is flipped to ascending (bottom-N) so the
dashboard surfaces the LEAST frequent — and therefore most anomalous —
events.  Charts without order_desc (KPI cards, timeseries, world map,
heatmap) are mirrored unchanged apart from uuid and slice_name.
"""

import copy
import os
import re
import sys

import yaml

ASSETS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "assets"))
if ASSETS_DIR not in sys.path:
    sys.path.insert(0, ASSETS_DIR)

import rebuild_rare_zip  # noqa: E402
from rebuild_zip import FILE_MAP, SOURCE_DIR  # noqa: E402

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DEFAULT_DASHBOARD_UUID = "c3d4e5f6-a7b8-9012-cdef-123456789012"
DATASET_UUID = "d8444b4a-ac55-4710-a777-a5b940bebabe"


def _load_yaml(rel_path: str) -> dict:
    with open(os.path.join(SOURCE_DIR, rel_path), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _load_all_charts() -> dict[str, dict]:
    charts_dir = os.path.join(SOURCE_DIR, "charts")
    return {
        fname: _load_yaml(os.path.join("charts", fname))
        for fname in sorted(os.listdir(charts_dir))
        if fname.endswith(".yaml")
    }


# ---------------------------------------------------------------------------
# derive_uuid
# ---------------------------------------------------------------------------


def test_derive_uuid_deterministic_and_distinct() -> None:
    """derive_uuid must be deterministic, lowercase UUID, and != input."""
    src = DEFAULT_DASHBOARD_UUID
    derived = rebuild_rare_zip.derive_uuid(src)
    assert derived == rebuild_rare_zip.derive_uuid(src)
    assert UUID_RE.match(derived), f"not a lowercase uuid: {derived}"
    assert derived != src


# ---------------------------------------------------------------------------
# transform_chart
# ---------------------------------------------------------------------------


def test_transform_chart_flips_order_desc() -> None:
    """A top-N chart (order_desc: true) must become ascending (false)."""
    src = _load_yaml("charts/top_api_calls.yaml")
    assert src["params"]["order_desc"] is True  # precondition
    out = rebuild_rare_zip.transform_chart(src)
    assert out["params"]["order_desc"] is False
    assert out["description"].startswith(rebuild_rare_zip.RARE_DESCRIPTION_PREFIX)


def test_transform_chart_without_order_desc_unchanged() -> None:
    """A KPI chart (no order_desc) changes only uuid and slice_name."""
    src = _load_yaml("charts/kpi_total_events.yaml")
    assert "order_desc" not in src["params"]  # precondition
    src_snapshot = copy.deepcopy(src)
    out = rebuild_rare_zip.transform_chart(src)
    assert src == src_snapshot, "transform_chart must not mutate its input"
    stripped_out = {k: v for k, v in out.items() if k not in ("uuid", "slice_name")}
    stripped_src = {k: v for k, v in src.items() if k not in ("uuid", "slice_name")}
    assert stripped_out == stripped_src


def test_transform_chart_uuid_slice_name_dataset() -> None:
    """uuid is derived, slice_name gets the suffix, dataset_uuid is shared."""
    src = _load_yaml("charts/source_ip_requests.yaml")
    out = rebuild_rare_zip.transform_chart(src)
    assert out["uuid"] == rebuild_rare_zip.derive_uuid(src["uuid"])
    assert out["slice_name"] == src["slice_name"] + rebuild_rare_zip.RARE_SUFFIX
    assert out["dataset_uuid"] == DATASET_UUID


def test_transform_chart_table_sets_sort_by_metric() -> None:
    """Table charts must get SORT BY (timeseries_limit_metric) = first metric.

    The Superset 6.1 table plugin's buildQuery ignores order_desc unless a
    sort-by metric is set (it falls back to a hardcoded descending orderby
    on the first metric), so ascending order only takes effect with an
    explicit timeseries_limit_metric.
    """
    # Adhoc-metric table chart
    src = _load_yaml("charts/root_account_usage.yaml")
    assert src["viz_type"] == "table" and "order_desc" in src["params"]
    out = rebuild_rare_zip.transform_chart(src)
    assert out["params"]["timeseries_limit_metric"] == src["params"]["metrics"][0]
    # Named-metric table chart
    src = _load_yaml("charts/source_ip_requests.yaml")
    assert src["viz_type"] == "table" and "order_desc" in src["params"]
    out = rebuild_rare_zip.transform_chart(src)
    assert out["params"]["timeseries_limit_metric"] == src["params"]["metrics"][0]


def test_transform_chart_non_table_gets_no_sort_by_metric() -> None:
    """Non-table charts rely on normalizeOrderBy (which honors order_desc),
    so they must not get a timeseries_limit_metric injected."""
    src = _load_yaml("charts/top_api_calls.yaml")
    assert src["viz_type"] != "table" and "order_desc" in src["params"]
    out = rebuild_rare_zip.transform_chart(src)
    assert "timeseries_limit_metric" not in out["params"]


def test_transform_chart_corpus_properties() -> None:
    """Across all 91 charts: order_desc flips exactly where present, table
    charts get a sort-by metric, and derived uuids are unique and disjoint
    from the source uuid set."""
    charts = _load_all_charts()
    assert len(charts) == 91
    src_uuids = {doc["uuid"] for doc in charts.values()}
    derived_uuids = set()
    flipped = 0
    sorted_tables = 0
    for fname, doc in charts.items():
        out = rebuild_rare_zip.transform_chart(doc)
        derived_uuids.add(out["uuid"])
        if "order_desc" in doc["params"]:
            assert out["params"]["order_desc"] is False, fname
            flipped += 1
            if doc["viz_type"] == "table":
                assert (
                    out["params"]["timeseries_limit_metric"]
                    == doc["params"]["metrics"][0]
                ), fname
                sorted_tables += 1
            else:
                assert "timeseries_limit_metric" not in out["params"], fname
        else:
            assert out["params"] == doc["params"], fname
    assert flipped == 73
    assert sorted_tables == 62
    assert len(derived_uuids) == len(charts)
    assert derived_uuids.isdisjoint(src_uuids)


# ---------------------------------------------------------------------------
# transform_dashboard
# ---------------------------------------------------------------------------


def test_transform_dashboard_identity_fields() -> None:
    src = _load_yaml("dashboard.yaml")
    out = rebuild_rare_zip.transform_dashboard(src)
    assert out["uuid"] == rebuild_rare_zip.derive_uuid(DEFAULT_DASHBOARD_UUID)
    assert out["dashboard_title"] == "CloudTrail Threat Hunting — Rare Events"
    assert out["slug"] == "cloudtrail-rare-events"


def test_transform_dashboard_position_structure_preserved() -> None:
    """Same node ids, types, and children; CHART meta remapped only."""
    src = _load_yaml("dashboard.yaml")
    src_snapshot = copy.deepcopy(src)
    out = rebuild_rare_zip.transform_dashboard(src)
    assert src == src_snapshot, "transform_dashboard must not mutate its input"

    assert set(out["position"].keys()) == set(src["position"].keys())
    tabs = 0
    for key, src_node in src["position"].items():
        out_node = out["position"][key]
        if not isinstance(src_node, dict):
            assert out_node == src_node
            continue
        assert out_node.get("type") == src_node.get("type")
        assert out_node.get("children") == src_node.get("children")
        if src_node.get("type") == "TAB":
            tabs += 1
            assert out_node == src_node
        elif src_node.get("type") == "CHART":
            assert out_node["meta"]["uuid"] == rebuild_rare_zip.derive_uuid(
                src_node["meta"]["uuid"]
            )
            assert (
                out_node["meta"]["sliceName"]
                == src_node["meta"]["sliceName"] + rebuild_rare_zip.RARE_SUFFIX
            )
        else:
            assert out_node == src_node
    assert tabs == 11


def test_transform_dashboard_native_filters_verbatim() -> None:
    """All 28 native filters are copied unchanged (ids, datasetUuid)."""
    src = _load_yaml("dashboard.yaml")
    out = rebuild_rare_zip.transform_dashboard(src)
    src_nf = src["metadata"]["native_filter_configuration"]
    out_nf = out["metadata"]["native_filter_configuration"]
    assert out_nf == src_nf
    assert len(out_nf) == 28
    ids = [f["id"] for f in out_nf]
    assert len(ids) == len(set(ids))


def test_transform_dashboard_metadata_charts_suffixed() -> None:
    src = _load_yaml("dashboard.yaml")
    out = rebuild_rare_zip.transform_dashboard(src)
    src_charts = src["metadata"]["charts"]
    out_charts = out["metadata"]["charts"]
    assert len(out_charts) == len(src_charts)
    for src_c, out_c in zip(src_charts, out_charts):
        assert out_c["slice_name"] == src_c["slice_name"] + rebuild_rare_zip.RARE_SUFFIX
        assert {k: v for k, v in out_c.items() if k != "slice_name"} == {
            k: v for k, v in src_c.items() if k != "slice_name"
        }


# ---------------------------------------------------------------------------
# build_rare_files
# ---------------------------------------------------------------------------


def test_build_rare_files_structure() -> None:
    """The generated file set mirrors FILE_MAP with the rare dashboard arc."""
    files = rebuild_rare_zip.build_rare_files()
    assert "metadata.yaml" in files
    assert rebuild_rare_zip.DASHBOARD_ARC == "dashboards/cloudtrail_rare_events.yaml"
    assert rebuild_rare_zip.DASHBOARD_ARC in files
    assert "databases/CloudTrail_DuckDB.yaml" in files
    assert "datasets/CloudTrail_DuckDB/cloudtrail_events.yaml" in files
    chart_arcs = [n for n in files if n.startswith("charts/")]
    assert len(chart_arcs) == 91


def test_build_rare_files_shared_objects_verbatim() -> None:
    """Database/dataset/metadata files are byte-identical to the source
    tree so Superset's uuid-keyed overwrite stays idempotent."""
    files = rebuild_rare_zip.build_rare_files()
    for src_rel, arc in FILE_MAP.items():
        if src_rel == "dashboard.yaml" or src_rel.startswith("charts/"):
            continue
        with open(os.path.join(SOURCE_DIR, src_rel), "rb") as fh:
            assert files[arc] == fh.read(), arc


def test_build_rare_files_no_dangling_chart_refs() -> None:
    """Every CHART uuid in the rare dashboard resolves to a chart entry."""
    files = rebuild_rare_zip.build_rare_files()
    dashboard = yaml.safe_load(files[rebuild_rare_zip.DASHBOARD_ARC])
    chart_uuids = {
        yaml.safe_load(data)["uuid"]
        for arc, data in files.items()
        if arc.startswith("charts/")
    }
    dangling = {
        key: node["meta"]["uuid"]
        for key, node in dashboard["position"].items()
        if isinstance(node, dict)
        and node.get("type") == "CHART"
        and node["meta"]["uuid"] not in chart_uuids
    }
    assert not dangling
