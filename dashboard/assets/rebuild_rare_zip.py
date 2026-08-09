#!/usr/bin/env python3
"""Rebuild cloudtrail_rare.zip — the "Rare Events" variant dashboard.

Derives a second Superset dashboard from cloudtrail_default/ (the single
source of truth): the same tab layout, but every chart that declares
params.order_desc is flipped to ascending (bottom-N) so the dashboard
surfaces the LEAST frequent — and therefore potentially most anomalous —
values.

Charts without order_desc have no rare variant: a KPI card, a time series,
a world map or a heatmap reads identically in both dashboards, so mirroring
them would ship a second copy under a "(Rare)" name that means nothing.
They are skipped, and the tabs that positioned them lose those slots.
See RARE_EXCLUDED_VIZ_TYPES.

Transformation rules:
  - Dashboard and chart uuids are derived deterministically via
    uuid5(RARE_NAMESPACE, source_uuid), so re-imports stay idempotent and
    never collide with the source dashboard's uuids.
  - slice_name (and position meta.sliceName) gets the " (Rare)" suffix so
    both dashboards can coexist in one Superset instance without confusion.
  - databases/, datasets/, and metadata.yaml are copied byte-for-byte:
    both dashboards share the same database and dataset objects.

Note: retiring a rare chart later requires adding its DERIVED uuid (not the
source uuid) to RETIRED_UUIDS in init/import_dashboard.py.

The ZIP is byte-deterministic (fixed ZipInfo timestamps, stable YAML dump),
so rebuilding without source changes produces a zero git diff.
"""

import copy
import os
import uuid
import zipfile

import yaml

from rebuild_zip import FILE_MAP, SOURCE_DIR

BASE = os.path.dirname(os.path.abspath(__file__))
OUTPUT_ZIP = os.path.join(BASE, "cloudtrail_rare.zip")

# Fixed namespace for uuid5 derivation — never change, or every re-import
# would create a duplicate set of charts instead of overwriting.
RARE_NAMESPACE = uuid.UUID("5e12a9b4-3c6d-4f8e-9a71-2b0c8d5e4f6a")

RARE_SUFFIX = " (Rare)"
RARE_TITLE = "CloudTrail Threat Hunting — Rare Events"
RARE_SLUG = "cloudtrail-rare-events"
RARE_DESCRIPTION_PREFIX = "Rare-events variant (ascending / bottom-N ordering). "
DASHBOARD_ARC = "dashboards/cloudtrail_rare_events.yaml"

# Fixed timestamp for deterministic ZIP output (ZIP epoch).
ZIP_DATE_TIME = (1980, 1, 1, 0, 0, 0)


def derive_uuid(source_uuid: str) -> str:
    """Derive the rare-dashboard uuid for a source uuid (deterministic)."""
    return str(uuid.uuid5(RARE_NAMESPACE, source_uuid))


def has_rare_variant(doc: dict) -> bool:
    """Return whether a chart has a meaningful rare (bottom-N) reading.

    "Rare" here means one thing only: invert the ordering and read the tail
    instead of the head. A chart that does not declare ``params.order_desc``
    has no ordering to invert — a KPI total, a time series, a world map and a
    heatmap all produce byte-identical numbers in both dashboards — so it is
    not mirrored at all rather than shipped under a name implying it differs.
    """
    return "order_desc" in (doc.get("params") or {})


def excluded_source_uuids() -> set[str]:
    """Return the source uuids of every chart with no rare variant."""
    charts_dir = os.path.join(SOURCE_DIR, "charts")
    excluded = set()
    for fname in sorted(os.listdir(charts_dir)):
        if not fname.endswith(".yaml"):
            continue
        with open(os.path.join(charts_dir, fname), encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        if not has_rare_variant(doc):
            excluded.add(doc["uuid"])
    return excluded


def _dump_yaml(doc: dict) -> bytes:
    """Serialize a YAML document deterministically (stable key order)."""
    return yaml.safe_dump(
        doc,
        sort_keys=False,
        allow_unicode=True,
        default_flow_style=False,
        width=100000,
    ).encode("utf-8")


def transform_chart(doc: dict) -> dict:
    """Return the rare-events variant of a chart document.

    Flips params.order_desc to False when present (ascending / bottom-N);
    otherwise the chart is mirrored unchanged apart from uuid/slice_name.

    Table charts additionally get SORT BY (timeseries_limit_metric) set to
    their first metric: the Superset 6.1 table plugin's buildQuery ignores
    order_desc unless a sort-by metric is set — without it, the frontend
    falls back to a hardcoded descending orderby on the first metric.
    Non-table charts go through normalizeOrderBy, which already honors
    order_desc, so they need no sort-by metric.
    """
    out = copy.deepcopy(doc)
    out["uuid"] = derive_uuid(doc["uuid"])
    out["slice_name"] = doc["slice_name"] + RARE_SUFFIX
    params = out.get("params", {})
    if "order_desc" in params:
        params["order_desc"] = False
        if doc.get("viz_type") == "table" and params.get("metrics"):
            params["timeseries_limit_metric"] = params["metrics"][0]
        out["description"] = RARE_DESCRIPTION_PREFIX + (doc.get("description") or "")
    return out


def transform_dashboard(doc: dict) -> dict:
    """Return the rare-events variant of the dashboard document.

    Position structure (node ids, types, children, rows, tabs, markdown
    headers) is preserved exactly; only CHART meta.uuid is remapped and
    meta.sliceName suffixed.  Native filters are dashboard-scoped and
    reference only the shared dataset, so they are copied verbatim.
    """
    out = copy.deepcopy(doc)
    out["uuid"] = derive_uuid(doc["uuid"])
    out["dashboard_title"] = RARE_TITLE
    out["slug"] = RARE_SLUG
    out["description"] = RARE_DESCRIPTION_PREFIX + (doc.get("description") or "")

    excluded = excluded_source_uuids()
    dropped_names = set()

    for key, node in list(out["position"].items()):
        if not (isinstance(node, dict) and node.get("type") == "CHART"):
            continue
        if node["meta"]["uuid"] in excluded:
            dropped_names.add(node["meta"]["sliceName"])
            del out["position"][key]
            continue
        node["meta"]["uuid"] = derive_uuid(node["meta"]["uuid"])
        node["meta"]["sliceName"] = node["meta"]["sliceName"] + RARE_SUFFIX

    _prune_dangling_children(out["position"])

    out["metadata"]["charts"] = [
        {**chart, "slice_name": chart["slice_name"] + RARE_SUFFIX}
        for chart in out.get("metadata", {}).get("charts", [])
        if chart["slice_name"] not in dropped_names
    ]

    return out


def _has_chart_descendant(position: dict, key: str) -> bool:
    """Return whether the subtree rooted at *key* still positions any chart."""
    node = position.get(key)
    if not isinstance(node, dict):
        return False
    if node.get("type") == "CHART":
        return True
    return any(_has_chart_descendant(position, c) for c in node.get("children", []))


def _prune_dangling_children(position: dict) -> None:
    """Drop references to removed nodes, then everything left with no chart.

    Removing a CHART node leaves its id in the parent ROW's ``children``, which
    Superset treats as a fatal layout error rather than a missing chart. A ROW
    that held nothing but excluded charts is then empty, and an empty ROW
    renders as a gap.

    A TAB can empty too: the rare dashboard's Overview held nothing but KPI
    cards, none of which has a bottom-N reading, so what survived was a tab of
    prose introducing no data. A tab whose whole subtree lost its charts is
    dropped along with its markdown, rather than shipped as an empty page.

    The pass repeats until the layout is stable, since removing a row can
    empty the tab above it.
    """
    while True:
        for node in position.values():
            if isinstance(node, dict) and "children" in node:
                node["children"] = [c for c in node["children"] if c in position]

        dead = {
            key
            for key, node in position.items()
            if isinstance(node, dict)
            and node.get("type") in ("ROW", "COLUMN", "TAB")
            and not _has_chart_descendant(position, key)
        }
        if not dead:
            _drop_unreachable(position)
            return
        for key in dead:
            del position[key]


def _drop_unreachable(position: dict) -> None:
    """Remove nodes no longer reachable from ROOT_ID.

    Deleting a TAB orphans the markdown headers inside it: they are gone from
    every ``children`` list but still occupy a key, so they would travel into
    the ZIP as layout nodes belonging to nothing.
    """
    reachable = {"DASHBOARD_VERSION_KEY", "ROOT_ID"}
    stack = ["ROOT_ID"]
    while stack:
        node = position.get(stack.pop())
        if not isinstance(node, dict):
            continue
        for child in node.get("children", []):
            if child not in reachable:
                reachable.add(child)
                stack.append(child)

    for key in [k for k in position if k not in reachable]:
        del position[key]


def build_rare_files() -> dict[str, bytes]:
    """Build the {arc_name: content} map for the rare-events ZIP.

    Reuses rebuild_zip.FILE_MAP so any chart added to the default
    dashboard automatically flows into the rare dashboard.
    """
    files: dict[str, bytes] = {}
    for src_rel, arc_name in FILE_MAP.items():
        abs_path = os.path.join(SOURCE_DIR, src_rel)
        if src_rel == "dashboard.yaml":
            with open(abs_path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            files[DASHBOARD_ARC] = _dump_yaml(transform_dashboard(doc))
        elif src_rel.startswith("charts/"):
            with open(abs_path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            if not has_rare_variant(doc):
                continue
            files[arc_name] = _dump_yaml(transform_chart(doc))
        else:
            # metadata.yaml, databases/, datasets/ — shared objects,
            # copied byte-for-byte so uuid-keyed overwrite stays idempotent.
            with open(abs_path, "rb") as fh:
                files[arc_name] = fh.read()
    return files


def main() -> None:
    """Rebuild cloudtrail_rare.zip deterministically."""
    files = build_rare_files()

    if os.path.exists(OUTPUT_ZIP):
        os.remove(OUTPUT_ZIP)
        print(f"Removed old: {OUTPUT_ZIP}")

    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc_name in sorted(files):
            info = zipfile.ZipInfo(arc_name, date_time=ZIP_DATE_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, files[arc_name])
            print(f"  Added: {arc_name}")

    print(f"\nCreated: {OUTPUT_ZIP} ({len(files)} files)")


if __name__ == "__main__":
    main()
