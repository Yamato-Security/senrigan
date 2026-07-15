#!/usr/bin/env python3
"""Rebuild cloudtrail_rare.zip — the "Rare Events" variant dashboard.

Derives a second Superset dashboard from cloudtrail_default/ (the single
source of truth): identical 11-tab / 91-chart layout, but every chart that
declares params.order_desc is flipped to ascending (bottom-N) so the
dashboard surfaces the LEAST frequent — and therefore potentially most
anomalous — values.  Charts without order_desc (KPI cards, timeseries,
world map, heatmap) are mirrored unchanged apart from uuid and slice_name.

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

    for node in out["position"].values():
        if isinstance(node, dict) and node.get("type") == "CHART":
            node["meta"]["uuid"] = derive_uuid(node["meta"]["uuid"])
            node["meta"]["sliceName"] = node["meta"]["sliceName"] + RARE_SUFFIX

    for chart in out.get("metadata", {}).get("charts", []):
        chart["slice_name"] = chart["slice_name"] + RARE_SUFFIX

    return out


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
