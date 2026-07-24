"""import_dashboard.py — Import a pre-built dashboard ZIP into Superset.

Uses the Superset Python API (ImportAssetsCommand) instead of the CLI,
because the CLI requires a --username flag and does not work well in
non-interactive bootstrap scripts.

ImportAssetsCommand (not ImportDashboardsCommand) is required: the
dashboard importer hardcodes overwrite=False for bundled charts, so chart
YAML edits would never reach charts that already exist in the metadata DB.
The assets importer overwrites everything by uuid, making re-imports
actually sync the YAML state ("assets as code").

This script runs inside the superset-init container as part of bootstrap.sh.
The ZIP to import is selected via the DASHBOARD_ZIP environment variable.
"""

import json
import os
import sys
import zipfile

import yaml

DASHBOARD_ZIP = os.environ.get(
    "DASHBOARD_ZIP", "/app/dashboards/cloudtrail_default.zip"
)
ADMIN_USERNAME = os.environ.get("SUPERSET_ADMIN_USERNAME", "admin")


def _first_orderby(metrics_list: list, order_desc: bool = True) -> list:
    """Build an orderby pair for the first metric.

    An empty orderby generates SQL with NO ORDER BY at all — order_desc
    alone is ignored by the v1 chart-data path, so LIMIT then returns
    arbitrary rows.  Named metrics are referenced directly; adhoc metric
    dicts are referenced by their label, which Superset resolves to the
    SELECT alias of the metric expression (verified on Superset 6.1).

    The second element of an orderby pair is is_ascending, so it is the
    inverse of order_desc.
    """
    if not metrics_list:
        return []
    first = metrics_list[0]
    if isinstance(first, str):
        return [[first, not order_desc]]
    if isinstance(first, dict) and first.get("label"):
        return [[first["label"], not order_desc]]
    # Adhoc metric without a label cannot be referenced in orderby.
    return []


def _patch_metadata_type(metadata_yaml) -> bytes:
    """Rewrite the bundle metadata type to "assets" (in memory only).

    ImportAssetsCommand validates that metadata.yaml declares
    type: assets.  The shipped ZIPs keep type: Dashboard so they stay
    importable through the Superset UI, so the type is patched here just
    before the import runs.
    """
    doc = yaml.safe_load(metadata_yaml) if metadata_yaml else None
    if not isinstance(doc, dict):
        doc = {}
    doc["type"] = "assets"
    doc.setdefault("version", "1.0.0")
    return yaml.safe_dump(doc, sort_keys=False).encode("utf-8")


def _query_metrics(params: dict) -> list:
    """The metrics a chart's query must run.

    Single-metric visualisations (big_number_total, world_map, heatmap) store
    their metric under `metric`, not `metrics`.  Falling straight through to
    the literal "count" for those made the stored query_context compute
    COUNT(*) instead of the chart's own expression, so a KPI card rendered a
    different number from the one its definition asks for.
    """
    metrics = params.get("metrics")
    if metrics:
        return metrics
    metric = params.get("metric")
    if metric:
        return [metric]
    return ["count"]


def _apply_time_params(params: dict, main_dttm_col: str | None) -> dict:
    """Fill in the time controls Superset needs, from the chart's own dataset.

    The temporal column differs per dataset — cloudtrail_events.event_time vs
    suzaku_detections.detected_at — so it has to come from the dataset the
    chart actually reads.  A hardcoded default silently breaks every chart on
    any other dataset with "column does not exist".
    """
    if not params.get("granularity_sqla") and main_dttm_col:
        params["granularity_sqla"] = main_dttm_col
    if not params.get("time_range"):
        params["time_range"] = "No filter"
    return params


def _needs_query_context(query_context, viz_type: str) -> bool:
    """Return True when a chart's stored query_context must be (re)built.

    Besides missing/placeholder/malformed contexts, a context is stale
    when its first query declares metrics but an empty orderby: an older
    version of this script emitted no orderby for adhoc metrics, producing
    SQL without ORDER BY.  Pie/sunburst charts are exempt — they sort via
    sort_by_metric and an empty orderby is correct for them.
    """
    if not query_context or query_context.strip() in ("", "null", "{}"):
        return True
    try:
        qc = json.loads(query_context)
    except (json.JSONDecodeError, AttributeError):
        return True
    if not (qc.get("datasource") and qc.get("queries")):
        return True
    if viz_type in ("pie", "sunburst"):
        return False
    query = qc["queries"][0]
    if query.get("metrics") and not query.get("orderby"):
        return True
    return False


def main() -> None:
    """Import the dashboard ZIP using the Superset Python API."""
    if not os.path.exists(DASHBOARD_ZIP):
        print(f"    Dashboard ZIP not found at {DASHBOARD_ZIP} — skipping.")
        sys.exit(0)

    # Step 1: create the Flask app (no model imports yet).
    from superset import create_app, security_manager  # noqa: PLC0415

    app = create_app()
    app_ctx = app.app_context()
    app_ctx.push()

    # Step 2: push a request context and set g.user so permission checks pass.
    req_ctx = app.test_request_context()
    req_ctx.push()

    from flask import g  # noqa: PLC0415

    admin = security_manager.find_user(ADMIN_USERNAME)
    if admin is None:
        print(f"    User '{ADMIN_USERNAME}' not found — aborting import.")
        sys.exit(1)
    g.user = admin

    # Step 3: load ZIP and run import command.
    from superset.commands.importers.v1.assets import (  # noqa: PLC0415
        ImportAssetsCommand,
    )

    with zipfile.ZipFile(DASHBOARD_ZIP) as z:
        contents = {name: z.read(name) for name in z.namelist()}
    contents["metadata.yaml"] = _patch_metadata_type(contents.get("metadata.yaml"))

    try:
        ImportAssetsCommand(contents).run()
        print("    Dashboard imported successfully.")
        _remove_retired_charts()
        _generate_query_contexts()
    except Exception as exc:  # noqa: BLE001
        print(f"    Dashboard import failed: {exc}")
        import traceback  # noqa: PLC0415

        traceback.print_exc()
        sys.exit(1)
    finally:
        req_ctx.pop()
        app_ctx.pop()


def _remove_retired_charts() -> None:
    """Delete charts that have been retired from the dashboard ZIP.

    When a chart is removed from the ZIP, Superset keeps the Slice object
    in its database.  This function explicitly deletes charts by UUID so
    they no longer appear in the Charts list or on the dashboard.

    Add UUIDs here whenever a chart YAML is intentionally removed.
    For charts on the Rare Events dashboard, add the DERIVED uuid produced
    by assets/rebuild_rare_zip.py, not the source chart's uuid.
    """
    from superset.extensions import db  # noqa: PLC0415
    from superset.models.slice import Slice  # noqa: PLC0415

    # UUIDs of charts that have been intentionally removed from the dashboard.
    RETIRED_UUIDS = {
        "e3f4a5b6-c7d8-9012-cdef-012345678901",  # DSH-10: AWS Service Breakdown (removed)
        "41c3d4e5-f6a7-8901-cdef-012345678941",  # HRM-41: High-Risk API by Attack Category (removed)
    }

    removed = 0
    for uuid in RETIRED_UUIDS:
        chart = db.session.query(Slice).filter_by(uuid=uuid).first()
        if chart:
            db.session.delete(chart)
            removed += 1
            print(f"    Removed retired chart: {chart.slice_name} ({uuid})")

    if removed:
        db.session.commit()
        print(f"    Cleaned up {removed} retired chart(s).")
    else:
        print("    No retired charts to clean up.")


def _generate_query_contexts() -> None:
    """Generate query_context for charts that lack one or hold a stale one.

    Superset requires a stored query_context to render charts on dashboards.
    The v1 ZIP import does not populate it, so we build a minimal one from
    each chart's params.  Contexts whose first query has metrics but an
    empty orderby (the old adhoc-metric code path) are rebuilt as well.
    """
    from superset.extensions import db  # noqa: PLC0415
    from superset.models.slice import Slice  # noqa: PLC0415

    charts = db.session.query(Slice).all()
    fixed = 0
    for c in charts:
        if not _needs_query_context(c.query_context, c.viz_type or ""):
            continue

        params = json.loads(c.params) if c.params else {}
        metrics = _query_metrics(params)
        groupby = params.get("groupby", [])
        columns = groupby.copy()

        x_axis = params.get("x_axis")
        if x_axis and x_axis not in columns:
            columns = [x_axis] + columns

        # Ensure granularity_sqla is set — required by many chart types — using
        # the temporal column of the dataset this chart actually reads.
        table = getattr(c, "table", None)
        params = _apply_time_params(params, getattr(table, "main_dttm_col", None))
        c.params = json.dumps(params)

        # Carry adhoc_filters into the query so WHERE clauses are applied.
        adhoc_filters = params.get("adhoc_filters", [])

        # Pie/sunburst charts sort via sort_by_metric — orderby must be empty.
        # For all other chart types, order by the first metric in the
        # direction given by params.order_desc (default descending).
        viz_type = c.viz_type or ""
        order_desc = params.get("order_desc", True)
        orderby = (
            []
            if viz_type in ("pie", "sunburst")
            else _first_orderby(metrics, order_desc)
        )

        query_context = {
            "datasource": {"id": c.datasource_id, "type": "table"},
            "force": False,
            "queries": [
                {
                    "filters": [],
                    "extras": {"having": "", "where": ""},
                    "applied_time_extras": {},
                    "columns": columns,
                    "metrics": metrics,
                    "orderby": orderby,
                    "row_limit": params.get("row_limit", 10000),
                    "series_limit": 0,
                    "order_desc": order_desc,
                    "url_params": {},
                    "custom_params": {},
                    "custom_form_data": {},
                    "adhoc_filters": adhoc_filters,
                }
            ],
            "form_data": params,
            "result_format": "json",
            "result_type": "full",
        }
        c.query_context = json.dumps(query_context)
        fixed += 1

    if fixed:
        db.session.commit()
        print(f"    Generated query_context for {fixed} chart(s).")


if __name__ == "__main__":
    main()
