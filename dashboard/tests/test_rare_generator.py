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
INIT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "init"))
if INIT_DIR not in sys.path:
    sys.path.insert(0, INIT_DIR)

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
    """Across all 115 charts: order_desc flips exactly where present, table
    charts get a sort-by metric, and derived uuids are unique and disjoint
    from the source uuid set."""
    charts = _load_all_charts()
    assert len(charts) == 115
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
    assert flipped == 93
    assert sorted_tables == 79
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
    """Surviving node ids, types and children are untouched; CHART meta remapped.

    Charts with no rare reading are dropped along with any row they emptied,
    so the rare layout is a subset of the source layout — never a reordering
    or a renaming of what remains.
    """
    src = _load_yaml("dashboard.yaml")
    src_snapshot = copy.deepcopy(src)
    out = rebuild_rare_zip.transform_dashboard(src)
    assert src == src_snapshot, "transform_dashboard must not mutate its input"

    assert set(out["position"].keys()) <= set(src["position"].keys())
    tabs = 0
    for key, src_node in src["position"].items():
        if key not in out["position"]:
            continue  # dropped: an excluded chart, or a row it left empty
        out_node = out["position"][key]
        if not isinstance(src_node, dict):
            assert out_node == src_node
            continue
        assert out_node.get("type") == src_node.get("type")
        assert set(out_node.get("children") or []) <= set(
            src_node.get("children") or []
        )
        if src_node.get("type") == "TAB":
            tabs += 1
            assert out_node["meta"] == src_node["meta"]
        elif src_node.get("type") == "CHART":
            assert out_node["meta"]["uuid"] == rebuild_rare_zip.derive_uuid(
                src_node["meta"]["uuid"]
            )
            assert (
                out_node["meta"]["sliceName"]
                == src_node["meta"]["sliceName"] + rebuild_rare_zip.RARE_SUFFIX
            )
        else:
            # ROW / GRID / MARKDOWN: identical apart from children a dropped
            # chart removed, already asserted to be a subset above.
            assert {k: v for k, v in out_node.items() if k != "children"} == {
                k: v for k, v in src_node.items() if k != "children"
            }
    # 10 of the source dashboard's 11 tabs survive: Overview held nothing but
    # KPI cards, none of which has a bottom-N reading.
    assert tabs == 10


def test_rare_dashboard_drops_a_tab_left_with_no_charts() -> None:
    """A tab whose every chart was excluded is removed, markdown included.

    Keeping it ships a page of prose introducing charts that are not there.
    """
    src = _load_yaml("dashboard.yaml")
    out = rebuild_rare_zip.transform_dashboard(src)

    def tab_titles(doc: dict) -> set[str]:
        return {
            node["meta"]["text"]
            for node in doc["position"].values()
            if isinstance(node, dict) and node.get("type") == "TAB"
        }

    assert tab_titles(src) - tab_titles(out) == {"🚦 Overview"}

    # Nothing is left stranded: every surviving node is reachable from ROOT_ID.
    reachable, stack = {"ROOT_ID"}, ["ROOT_ID"]
    while stack:
        node = out["position"].get(stack.pop())
        for child in (node or {}).get("children", []):
            if child not in reachable:
                reachable.add(child)
                stack.append(child)
    stranded = set(out["position"]) - reachable - {"DASHBOARD_VERSION_KEY"}
    assert not stranded, f"orphaned layout nodes: {sorted(stranded)}"


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
    """Surviving inventory entries get the suffix; dropped charts leave it."""
    src = _load_yaml("dashboard.yaml")
    out = rebuild_rare_zip.transform_dashboard(src)
    out_charts = out["metadata"]["charts"]
    src_by_name = {c["slice_name"]: c for c in src["metadata"]["charts"]}

    assert out_charts, "the rare inventory must not be emptied"
    assert len(out_charts) <= len(src_by_name)
    for out_c in out_charts:
        assert out_c["slice_name"].endswith(rebuild_rare_zip.RARE_SUFFIX)
        src_c = src_by_name[out_c["slice_name"][: -len(rebuild_rare_zip.RARE_SUFFIX)]]
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
    # 93 of the 115 source charts declare order_desc; the rest have no rare
    # reading and are not mirrored (see has_rare_variant).
    assert len(chart_arcs) == 93


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


# ---------------------------------------------------------------------------
# Rare-variant eligibility
# ---------------------------------------------------------------------------


def test_only_ordered_charts_have_a_rare_variant() -> None:
    """``has_rare_variant`` accepts exactly the charts ordering can invert.

    "Rare" is defined by flipping ``order_desc``, so a chart that does not
    declare it has no rare reading — a KPI total, a time series, a world map
    and a heatmap all render identically in both dashboards.
    """
    charts = _load_all_charts()
    eligible = {
        f for f, doc in charts.items() if rebuild_rare_zip.has_rare_variant(doc)
    }
    declares = {f for f, doc in charts.items() if "order_desc" in doc["params"]}
    assert eligible == declares
    assert len(eligible) == 93


def test_rare_bundle_omits_charts_with_no_rare_reading() -> None:
    """The 22 unorderable charts must not be mirrored into the rare ZIP.

    Shipping them appends " (Rare)" to a chart whose numbers are byte-identical
    to the default dashboard's, which tells a reader the two differ when they
    do not.
    """
    files = rebuild_rare_zip.build_rare_files()
    chart_files = [arc for arc in files if arc.startswith("charts/")]
    assert len(chart_files) == 93

    names = {yaml.safe_load(files[arc])["slice_name"] for arc in chart_files}
    assert not [
        n for n in names if "Total Events" in n
    ], "a KPI total has no rare variant"


def test_rare_dashboard_positions_only_the_charts_it_ships() -> None:
    """Excluded charts leave neither a position node nor a parent reference.

    A CHART node whose uuid has no chart file makes Superset render an empty
    slot, and a children list that still names the removed node breaks the
    layout outright.
    """
    files = rebuild_rare_zip.build_rare_files()
    dashboard = yaml.safe_load(files[rebuild_rare_zip.DASHBOARD_ARC])
    position = dashboard["position"]

    shipped = {
        yaml.safe_load(data)["uuid"]
        for arc, data in files.items()
        if arc.startswith("charts/")
    }
    chart_nodes = {
        key: node
        for key, node in position.items()
        if isinstance(node, dict) and node.get("type") == "CHART"
    }
    assert len(chart_nodes) == 93
    assert all(node["meta"]["uuid"] in shipped for node in chart_nodes.values())

    for key, node in position.items():
        if isinstance(node, dict):
            for child in node.get("children", []):
                assert child in position, f"{key} references removed node {child}"


def test_retired_uuids_cover_every_dropped_rare_chart() -> None:
    """Superset keeps an imported chart until something deletes it.

    The 22 rare copies already exist in any instance imported before this
    change, so their *derived* uuids have to be in RETIRED_UUIDS or they stay
    on the dashboard forever.
    """
    import import_dashboard

    charts = _load_all_charts()
    dropped = {
        rebuild_rare_zip.derive_uuid(doc["uuid"])
        for doc in charts.values()
        if not rebuild_rare_zip.has_rare_variant(doc)
    }
    assert len(dropped) == 22
    assert dropped <= import_dashboard.RETIRED_UUIDS
