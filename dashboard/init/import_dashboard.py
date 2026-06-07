"""import_dashboard.py — Import the pre-built CloudTrail dashboard into Superset.

Uses the Superset Python API (ImportDashboardsCommand) instead of the CLI,
because the CLI requires a --username flag and does not work well in
non-interactive bootstrap scripts.

This script runs inside the superset-init container as part of bootstrap.sh.
"""

import os
import sys
import zipfile

DASHBOARD_ZIP = os.environ.get(
    "DASHBOARD_ZIP", "/app/dashboards/cloudtrail_default.zip"
)
ADMIN_USERNAME = os.environ.get("SUPERSET_ADMIN_USERNAME", "admin")


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
    from superset.commands.dashboard.importers.dispatcher import (  # noqa: PLC0415
        ImportDashboardsCommand,
    )

    with zipfile.ZipFile(DASHBOARD_ZIP) as z:
        contents = {name: z.read(name) for name in z.namelist()}

    try:
        ImportDashboardsCommand(contents, overwrite=True).run()
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
    """
    import json  # noqa: PLC0415

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
    """Generate query_context for charts that lack one.

    Superset requires a stored query_context to render charts on dashboards.
    The v1 ZIP import does not populate it, so we build a minimal one from
    each chart's params.
    """
    import json  # noqa: PLC0415

    from superset.extensions import db  # noqa: PLC0415
    from superset.models.slice import Slice  # noqa: PLC0415

    charts = db.session.query(Slice).all()
    fixed = 0
    for c in charts:
        # Skip charts that already have a valid query_context.
        if c.query_context and c.query_context.strip() not in ("", "null", "{}"):
            try:
                qc = json.loads(c.query_context)
                if qc.get("datasource") and qc.get("queries"):
                    continue
            except (json.JSONDecodeError, AttributeError):
                pass

        params = json.loads(c.params) if c.params else {}
        metrics = params.get("metrics", ["count"])
        groupby = params.get("groupby", [])
        columns = groupby.copy()

        x_axis = params.get("x_axis")
        if x_axis and x_axis not in columns:
            columns = [x_axis] + columns

        # Build a safe orderby for named metrics only.
        # Adhoc metric dicts (expressionType/sqlExpression) cause
        # "Field may not be null" schema validation errors in Superset 4.x
        # when placed in orderby.  For adhoc metrics, return [] and rely on
        # order_desc in params to sort by the first metric descending.
        def _first_orderby(metrics_list: list) -> list:
            if not metrics_list:
                return []
            first = metrics_list[0]
            if isinstance(first, str):
                return [[first, False]]
            # Adhoc metric dict — let Superset handle ordering via order_desc.
            return []

        # Ensure granularity_sqla is set — required by many chart types.
        if "granularity_sqla" not in params:
            params["granularity_sqla"] = "event_time"
        if "time_range" not in params:
            params["time_range"] = "No filter"
        c.params = json.dumps(params)

        # Carry adhoc_filters into the query so WHERE clauses are applied.
        adhoc_filters = params.get("adhoc_filters", [])

        # Pie/sunburst charts sort via sort_by_metric — orderby must be empty.
        # For all other chart types, order by the first metric descending.
        viz_type = c.viz_type or ""
        orderby = [] if viz_type in ("pie", "sunburst") else _first_orderby(metrics)

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
                    "order_desc": params.get("order_desc", True),
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
