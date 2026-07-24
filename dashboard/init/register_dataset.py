"""register_dataset.py — Register Senrigan's Superset datasets.

This script runs inside the superset-init container as part of bootstrap.sh.
It creates a Superset SqlaTable (dataset) for each table the pre-built
dashboards read, all linked to the "CloudTrail DuckDB" database connection
registered by register_duckdb.py:

  * cloudtrail_events      — CloudTrail Threat Hunting dashboards
  * suzaku_detections      — Suzaku Detections dashboard (one row per rule hit)
  * suzaku_detection_tags  — its MITRE ATT&CK tab (one row per ATT&CK tag)

The registration is idempotent: running this script multiple times is safe.

Re-sync mode:
    Set the environment variable FORCE_RESYNC=true to force a column metadata
    re-sync on an already-registered dataset.  This is useful when:
      - superset-init ran before the ingester populated the DuckDB file, so
        column metadata was not fetched during initial registration.
      - Logs were re-ingested and the schema changed.
    Usage (via docker compose):
      docker compose --profile resync run --rm superset-resync

Implementation note:
    Same context-push pattern as register_duckdb.py — superset model imports
    must happen AFTER app context is pushed to avoid Werkzeug LocalProxy errors.
"""

import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Superset models are only importable inside the container after the app
    # context is pushed, so at runtime they are imported lazily inside
    # functions; these imports exist solely for the type annotations.
    from superset.connectors.sqla.models import SqlaTable
    from superset.models.core import Database

DB_NAME = "CloudTrail DuckDB"
TABLE_NAME = "cloudtrail_events"
MAIN_DTTM_COL = "event_time"
DESCRIPTION = "AWS CloudTrail events ingested by the Senrigan ingester (Rust)."
# Fixed UUID — must match datasets/CloudTrail_DuckDB/cloudtrail_events.yaml in the ZIP
DATASET_UUID = "d8444b4a-ac55-4710-a777-a5b940bebabe"

# Suzaku detection tables, written by `ingester suzaku-import`.
# UUIDs must match datasets/CloudTrail_DuckDB/*.yaml in suzaku_detections.zip.
SUZAKU_DETECTIONS_TABLE = "suzaku_detections"
SUZAKU_DETECTIONS_UUID = "7c1f9d2a-6b35-4e88-9a10-0d5f3b7e4c21"
SUZAKU_TAGS_TABLE = "suzaku_detection_tags"
SUZAKU_TAGS_UUID = "3e8a5c47-91d2-4fb6-8c03-6a7e2d914b58"

# Set FORCE_RESYNC=true to re-sync column metadata even if the dataset already exists.
FORCE_RESYNC = os.environ.get("FORCE_RESYNC", "").lower() in ("1", "true", "yes")


def main() -> None:
    """Register every Senrigan dataset that does not already exist."""
    # Step 1 — create Flask app without importing models yet.
    from superset import create_app  # noqa: PLC0415

    app = create_app()

    # Step 2 — push context so Werkzeug LocalProxy resolves current_app.
    ctx = app.app_context()
    ctx.push()

    try:
        # Step 3 — safe to import models now.
        from superset.extensions import db  # noqa: PLC0415
        from superset.models.core import Database  # noqa: PLC0415

        # Look up the target database connection.
        database = db.session.query(Database).filter_by(database_name=DB_NAME).first()
        if not database:
            print(f"    ERROR: Database '{DB_NAME}' not found.")
            print("    Run register_duckdb.py first.")
            sys.exit(1)

        for spec in DATASETS:
            _register_one(database, spec)
    finally:
        ctx.pop()


def _register_one(database: "Database", spec: dict) -> None:
    """Create (or re-sync) a single dataset from its specification."""
    from superset.connectors.sqla.models import SqlaTable  # noqa: PLC0415
    from superset.extensions import db  # noqa: PLC0415

    table_name = spec["table_name"]

    existing = (
        db.session.query(SqlaTable)
        .filter_by(table_name=table_name, database_id=database.id)
        .first()
    )
    if existing:
        if FORCE_RESYNC:
            print(
                f"    Dataset '{table_name}' already registered — forcing metadata re-sync..."
            )
            _sync_metadata(existing, table_name)
            _register_columns(existing, spec["columns"])
            _register_metrics(existing, spec["metrics"])
        else:
            print(f"    Dataset '{table_name}' already registered — skipping.")
            print("    Tip: set FORCE_RESYNC=true to re-sync column metadata.")
        return

    # Create the dataset with a fixed UUID so the dashboard ZIP can reference it.
    import uuid as _uuid  # noqa: PLC0415

    dataset = SqlaTable(
        table_name=table_name,
        database_id=database.id,
        main_dttm_col=spec["main_dttm_col"],
        description=spec["description"],
        filter_select_enabled=True,
        uuid=_uuid.UUID(spec["uuid"]),
    )
    db.session.add(dataset)
    db.session.commit()

    # Attempt to fetch column metadata from DuckDB.
    # This may fail if the DB file is empty or the table does not exist yet
    # (e.g. `suzaku-import` has not been run).  In that case run:
    #   docker compose --profile resync run --rm superset-resync
    _sync_metadata(dataset, table_name)
    # Explicitly register the declared columns as a fallback so that
    # ImportDashboardsCommand never raises "Columns missing in dataset" even
    # when fetch_metadata() failed because the table was absent at init time.
    _register_columns(dataset, spec["columns"])

    print(f"    Dataset '{table_name}' registered successfully.")
    print(f"    Linked to database: '{DB_NAME}' (id={database.id})")

    # Register custom metrics required by dashboard charts.
    _register_metrics(dataset, spec["metrics"])


def _sync_metadata(dataset: "SqlaTable", table_name: str) -> None:
    """Fetch column metadata from DuckDB and commit.  Logs a warning on failure."""
    from superset.extensions import db  # noqa: PLC0415

    try:
        dataset.fetch_metadata()
        db.session.commit()
        print(f"    Column metadata synced from '{table_name}'.")
    except Exception as exc:  # noqa: BLE001
        print(f"    Warning: could not sync column metadata: {exc}")
        print("    Columns will be auto-synced on first SQL Lab access.")
        print("    If the dashboard shows no data, run:")
        print("      docker compose --profile resync run --rm superset-resync")


# Custom metrics used by the pre-built dashboard charts.
CUSTOM_METRICS = [
    ("event_count", "COUNT(*)", "Total event count"),
    ("call_count", "COUNT(*)", "API call count"),
    ("total_events", "COUNT(*)", "Total events per entity"),
    (
        "write_events",
        "COUNT(CASE WHEN read_only = false THEN 1 END)",
        "Write (mutating) events",
    ),
    (
        "error_events",
        "COUNT(CASE WHEN error_code IS NOT NULL THEN 1 END)",
        "Events with error code",
    ),
    (
        "error_count",
        "COUNT(CASE WHEN error_code IS NOT NULL THEN 1 END)",
        "Error event count",
    ),
    ("request_count", "COUNT(*)", "Request count per source IP"),
    ("unique_identities", "COUNT(DISTINCT user_identity_arn)", "Unique IAM identities"),
    (
        "write_requests",
        "COUNT(CASE WHEN read_only = false THEN 1 END)",
        "Write requests per source IP",
    ),
]


def _register_metrics(dataset: "SqlaTable", metrics: list) -> None:
    """Add custom metrics to the dataset if they do not already exist."""
    from superset.connectors.sqla.models import SqlMetric  # noqa: PLC0415
    from superset.extensions import db  # noqa: PLC0415

    existing_names = {m.metric_name for m in dataset.metrics}
    added = 0
    for name, expression, description in metrics:
        if name in existing_names:
            continue
        metric = SqlMetric(
            metric_name=name,
            expression=expression,
            description=description,
            metric_type="count",
            table_id=dataset.id,
        )
        db.session.add(metric)
        added += 1

    if added:
        db.session.commit()
        print(f"    Registered {added} custom metrics.")
    else:
        print("    Custom metrics already registered — skipping.")


# All 17 core columns of the cloudtrail_events table.
# These are registered explicitly as a fallback so that Superset dataset metadata
# is always populated even when fetch_metadata() fails (e.g. DuckDB is empty at
# init time).  Without this fallback, ImportDashboardsCommand raises
# "Columns missing in dataset: ['user_identity_arn', 'source_ip_address', ...]"
# because no columns exist in the DB.
# Tuple: (col_name, col_type, verbose_name, groupby, filterable, is_dttm)
CORE_COLUMNS = [
    ("event_time", "TIMESTAMP", "Event Time", True, True, True),
    ("event_name", "VARCHAR", "Event Name", True, True, False),
    ("event_source", "VARCHAR", "Event Source", True, True, False),
    ("aws_region", "VARCHAR", "AWS Region", True, True, False),
    ("source_ip_address", "VARCHAR", "Source IP Address", True, True, False),
    ("user_agent", "VARCHAR", "User Agent", False, True, False),
    ("user_identity_type", "VARCHAR", "Identity Type", True, True, False),
    ("user_identity_arn", "VARCHAR", "Identity ARN", True, True, False),
    ("user_identity_account_id", "VARCHAR", "Account ID", True, True, False),
    ("request_parameters", "VARCHAR", "Request Parameters", False, False, False),
    ("response_elements", "VARCHAR", "Response Elements", False, False, False),
    ("error_code", "VARCHAR", "Error Code", True, True, False),
    ("error_message", "VARCHAR", "Error Message", False, True, False),
    ("read_only", "BOOLEAN", "Read Only", True, True, False),
    ("event_type", "VARCHAR", "Event Type", True, True, False),
    ("recipient_account_id", "VARCHAR", "Recipient Account ID", True, True, False),
    ("raw_event", "VARCHAR", "Raw Event", False, False, False),
]


def _register_columns(dataset: "SqlaTable", columns: list) -> None:
    """Explicitly register a dataset's declared columns in Superset.

    This acts as a fallback for when fetch_metadata() could not discover columns
    (e.g. the DuckDB file was empty, or the Suzaku tables did not exist yet
    because `suzaku-import` had not been run).  Without this, Superset's
    ImportDashboardsCommand raises "Columns missing in dataset" for every column
    referenced in chart groupby params.

    Accepts both column shapes used below: 6-tuples that carry an explicit
    is_dttm flag, and 5-tuples (the GeoIP list) where it is always False.
    """
    from superset.connectors.sqla.models import TableColumn  # noqa: PLC0415
    from superset.extensions import db  # noqa: PLC0415

    existing_names = {col.column_name for col in dataset.columns}
    added = 0
    for column in columns:
        col_name, col_type, verbose_name, groupby, filterable = column[:5]
        is_dttm = column[5] if len(column) > 5 else False
        if col_name in existing_names:
            continue
        col = TableColumn(
            column_name=col_name,
            type=col_type,
            verbose_name=verbose_name,
            groupby=groupby,
            filterable=filterable,
            is_dttm=is_dttm,
            is_active=True,
            table_id=dataset.id,
        )
        db.session.add(col)
        added += 1

    if added:
        db.session.commit()
        print(f"    Registered {added} column(s) in dataset '{dataset.table_name}'.")
    else:
        print(f"    Columns already registered for '{dataset.table_name}' — skipping.")


# GeoIP enrichment columns to register explicitly in the Superset dataset.
# These columns are always added to the schema by the ingester (ALTER TABLE …
# ADD COLUMN IF NOT EXISTS), but their values are NULL when ingested without a
# GeoLite2 database.  Registering them here ensures that dashboard charts that
# reference geo_* columns can be imported and rendered regardless of whether
# GeoIP enrichment has been performed.
GEO_COLUMNS = [
    ("geo_country_code", "VARCHAR", "Country Code", True, True),
    ("geo_country_name", "VARCHAR", "Country Name", True, True),
    ("geo_city", "VARCHAR", "City", True, True),
    ("geo_latitude", "FLOAT", "Latitude", False, False),
    ("geo_longitude", "FLOAT", "Longitude", False, False),
    ("geo_asn", "INTEGER", "ASN", False, False),
    ("geo_org", "VARCHAR", "ASN Organization", True, True),
]


# ---------------------------------------------------------------------------
# Suzaku detection tables
#
# Written by `ingester suzaku-import`, which normalises the `timeline` table of
# a `suzaku ... -t duckdb` output.  The column lists mirror
# assets/suzaku_detections/datasets/*.yaml exactly — tests/test_suzaku_assets.py
# asserts they stay in step, because a column that is declared in one place and
# not the other breaks the dashboard import with "Columns missing in dataset".
# Tuple: (col_name, col_type, verbose_name, groupby, filterable, is_dttm)
# ---------------------------------------------------------------------------
SUZAKU_DETECTION_COLUMNS = [
    ("detected_at", "TIMESTAMP", "Detected At", True, True, True),
    ("rule_title", "VARCHAR", "Rule", True, True, False),
    ("rule_id", "VARCHAR", "Rule ID", True, True, False),
    ("rule_author", "VARCHAR", "Rule Author", True, True, False),
    ("level", "VARCHAR", "Severity", True, True, False),
    ("level_rank", "INTEGER", "Severity Rank", True, True, False),
    ("tags", "VARCHAR", "Tags", True, True, False),
    ("mitre_tactics", "VARCHAR", "ATT&CK Tactics", True, True, False),
    ("mitre_techniques", "VARCHAR", "ATT&CK Techniques", True, True, False),
    ("cloud_provider", "VARCHAR", "Cloud", True, True, False),
    ("event_name", "VARCHAR", "API Action", True, True, False),
    ("event_source", "VARCHAR", "Service", True, True, False),
    ("aws_region", "VARCHAR", "AWS Region", True, True, False),
    ("source_ip", "VARCHAR", "Source IP", True, True, False),
    ("src_country", "VARCHAR", "Country", True, True, False),
    ("src_city", "VARCHAR", "City", True, True, False),
    ("src_asn", "VARCHAR", "ASN", True, True, False),
    ("user_name", "VARCHAR", "Principal", True, True, False),
    ("user_type", "VARCHAR", "Identity Type", True, True, False),
    ("user_arn", "VARCHAR", "Principal ARN", True, True, False),
    ("account_id", "VARCHAR", "Account ID", True, True, False),
    ("principal_id", "VARCHAR", "Principal ID", True, True, False),
    ("access_key_id", "VARCHAR", "Access Key ID", True, True, False),
    ("user_agent", "VARCHAR", "User Agent", True, True, False),
    ("error_code", "VARCHAR", "Error Code", True, True, False),
    ("error_message", "VARCHAR", "Error Message", False, True, False),
    ("outcome", "VARCHAR", "Outcome", True, True, False),
    ("event_id", "VARCHAR", "Event ID", True, True, False),
    ("target_object", "VARCHAR", "Target Object", True, True, False),
    ("record_type", "VARCHAR", "Record Type", True, True, False),
    ("app_id", "VARCHAR", "Application ID", True, True, False),
    ("category", "VARCHAR", "Category", True, True, False),
    ("details", "VARCHAR", "Details", False, True, False),
    ("source_path", "VARCHAR", "Source File", True, True, False),
    ("source_sha", "VARCHAR", "Source SHA-256", False, True, False),
    ("raw_row", "VARCHAR", "Raw Suzaku Row", False, False, False),
    ("detection_id", "VARCHAR", "Detection ID", False, True, False),
]

SUZAKU_DETECTION_METRICS = [
    ("count", "COUNT(*)", "Number of detections"),
    ("detections", "COUNT(*)", "Number of Suzaku detections"),
    (
        "critical_high",
        "COUNT(*) FILTER (WHERE level_rank >= 4)",
        "Detections at level critical or high",
    ),
    ("distinct_rules", "COUNT(DISTINCT rule_title)", "Number of distinct Sigma rules"),
    (
        "distinct_principals",
        "COUNT(DISTINCT COALESCE(user_arn, user_name))",
        "Number of distinct identities",
    ),
    (
        "distinct_ips",
        "COUNT(DISTINCT source_ip)",
        "Number of distinct source IP addresses",
    ),
    ("max_severity_rank", "MAX(level_rank)", "Worst severity reached"),
]

SUZAKU_TAG_COLUMNS = [
    ("detected_at", "TIMESTAMP", "Detected At", True, True, True),
    ("tag_type", "VARCHAR", "Tag Type", True, True, False),
    ("tag_value", "VARCHAR", "Tag", True, True, False),
    ("rule_title", "VARCHAR", "Rule", True, True, False),
    ("level", "VARCHAR", "Severity", True, True, False),
    ("level_rank", "INTEGER", "Severity Rank", True, True, False),
    ("cloud_provider", "VARCHAR", "Cloud", True, True, False),
    ("user_name", "VARCHAR", "Principal", True, True, False),
    ("source_ip", "VARCHAR", "Source IP", True, True, False),
    ("src_country", "VARCHAR", "Country", True, True, False),
    ("detection_id", "VARCHAR", "Detection ID", False, True, False),
    ("source_sha", "VARCHAR", "Source SHA-256", False, True, False),
]

SUZAKU_TAG_METRICS = [
    ("count", "COUNT(*)", "Number of tagged detections"),
    ("detections", "COUNT(*)", "Number of tagged detections"),
    (
        "distinct_rules",
        "COUNT(DISTINCT rule_title)",
        "Number of distinct Sigma rules carrying the tag",
    ),
]


# Every dataset the pre-built dashboards read, in registration order.
DATASETS = [
    {
        "table_name": TABLE_NAME,
        "uuid": DATASET_UUID,
        "main_dttm_col": MAIN_DTTM_COL,
        "description": DESCRIPTION,
        # GeoIP columns are appended by `ALTER TABLE … ADD COLUMN IF NOT EXISTS`
        # and hold NULL when ingested without a GeoLite2 database, so they are
        # declared here for the same reason as the core columns.
        "columns": CORE_COLUMNS + GEO_COLUMNS,
        "metrics": CUSTOM_METRICS,
    },
    {
        "table_name": SUZAKU_DETECTIONS_TABLE,
        "uuid": SUZAKU_DETECTIONS_UUID,
        "main_dttm_col": "detected_at",
        "description": (
            "Suzaku Sigma-rule detections imported by `ingester suzaku-import`."
        ),
        "columns": SUZAKU_DETECTION_COLUMNS,
        "metrics": SUZAKU_DETECTION_METRICS,
    },
    {
        "table_name": SUZAKU_TAGS_TABLE,
        "uuid": SUZAKU_TAGS_UUID,
        "main_dttm_col": "detected_at",
        "description": "MITRE ATT&CK tags of Suzaku detections, one row per tag.",
        "columns": SUZAKU_TAG_COLUMNS,
        "metrics": SUZAKU_TAG_METRICS,
    },
]


if __name__ == "__main__":
    main()
    sys.exit(0)
