"""register_dataset.py — Register the cloudtrail_events dataset in Superset.

This script runs inside the superset-init container as part of bootstrap.sh.
It creates a Superset SqlaTable (dataset) for cloudtrail_events, linked to
the "CloudTrail DuckDB" database connection registered by register_duckdb.py.

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

DB_NAME = "CloudTrail DuckDB"
TABLE_NAME = "cloudtrail_events"
MAIN_DTTM_COL = "event_time"
DESCRIPTION = "AWS CloudTrail events ingested by the Senrigan ingester (Rust)."
# Fixed UUID — must match datasets/CloudTrail_DuckDB/cloudtrail_events.yaml in the ZIP
DATASET_UUID = "d8444b4a-ac55-4710-a777-a5b940bebabe"

# Set FORCE_RESYNC=true to re-sync column metadata even if the dataset already exists.
FORCE_RESYNC = os.environ.get("FORCE_RESYNC", "").lower() in ("1", "true", "yes")


def main() -> None:
    """Register the cloudtrail_events dataset if it does not already exist."""
    # Step 1 — create Flask app without importing models yet.
    from superset import create_app  # noqa: PLC0415

    app = create_app()

    # Step 2 — push context so Werkzeug LocalProxy resolves current_app.
    ctx = app.app_context()
    ctx.push()

    try:
        # Step 3 — safe to import models now.
        from superset.connectors.sqla.models import SqlaTable  # noqa: PLC0415
        from superset.extensions import db  # noqa: PLC0415
        from superset.models.core import Database  # noqa: PLC0415

        # Look up the target database connection.
        database = db.session.query(Database).filter_by(database_name=DB_NAME).first()
        if not database:
            print(f"    ERROR: Database '{DB_NAME}' not found.")
            print("    Run register_duckdb.py first.")
            sys.exit(1)

        # Check if the dataset already exists.
        existing = (
            db.session.query(SqlaTable)
            .filter_by(table_name=TABLE_NAME, database_id=database.id)
            .first()
        )
        if existing:
            if FORCE_RESYNC:
                print(
                    f"    Dataset '{TABLE_NAME}' already registered — forcing metadata re-sync..."
                )
                _sync_metadata(existing)
                _register_core_columns(existing)
                _register_metrics(existing)
                _register_geo_columns(existing)
            else:
                print(f"    Dataset '{TABLE_NAME}' already registered — skipping.")
                print("    Tip: set FORCE_RESYNC=true to re-sync column metadata.")
            return

        # Create the dataset with a fixed UUID so the dashboard ZIP can reference it.
        import uuid as _uuid  # noqa: PLC0415

        dataset = SqlaTable(
            table_name=TABLE_NAME,
            database_id=database.id,
            main_dttm_col=MAIN_DTTM_COL,
            description=DESCRIPTION,
            filter_select_enabled=True,
            uuid=_uuid.UUID(DATASET_UUID),
        )
        db.session.add(dataset)
        db.session.commit()

        # Attempt to fetch column metadata from DuckDB.
        # This may fail if the DB file is empty or not yet populated by the ingester.
        # In that case run: docker compose --profile resync run --rm superset-resync
        _sync_metadata(dataset)
        # Explicitly register all 17 core columns as a fallback so that
        # ImportDashboardsCommand never raises "Columns missing in dataset" even
        # when fetch_metadata() failed because DuckDB was empty at init time.
        _register_core_columns(dataset)

        print(f"    Dataset '{TABLE_NAME}' registered successfully.")
        print(f"    Linked to database: '{DB_NAME}' (id={database.id})")

        # Register custom metrics required by dashboard charts.
        _register_metrics(dataset)
        # Register GeoIP columns explicitly so dashboard charts can reference them
        # even when the DuckDB table was ingested without a GeoLite2 database.
        _register_geo_columns(dataset)
    finally:
        ctx.pop()


def _sync_metadata(dataset: "SqlaTable") -> None:
    """Fetch column metadata from DuckDB and commit.  Logs a warning on failure."""
    from superset.extensions import db  # noqa: PLC0415

    try:
        dataset.fetch_metadata()
        db.session.commit()
        print(f"    Column metadata synced from '{TABLE_NAME}'.")
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


def _register_metrics(dataset: "SqlaTable") -> None:
    """Add custom metrics to the dataset if they do not already exist."""
    from superset.connectors.sqla.models import SqlMetric  # noqa: PLC0415
    from superset.extensions import db  # noqa: PLC0415

    existing_names = {m.metric_name for m in dataset.metrics}
    added = 0
    for name, expression, description in CUSTOM_METRICS:
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


def _register_core_columns(dataset: "SqlaTable") -> None:
    """Explicitly register the 17 core cloudtrail_events columns in the Superset dataset.

    This acts as a fallback for when fetch_metadata() could not discover columns
    (e.g. DuckDB file was empty at container init time).  Without this, Superset's
    ImportDashboardsCommand raises "Columns missing in dataset" for every column
    referenced in chart groupby params.
    """
    from superset.connectors.sqla.models import TableColumn  # noqa: PLC0415
    from superset.extensions import db  # noqa: PLC0415

    existing_names = {col.column_name for col in dataset.columns}
    added = 0
    for col_name, col_type, verbose_name, groupby, filterable, is_dttm in CORE_COLUMNS:
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
        print(f"    Registered {added} core column(s) in dataset.")
    else:
        print("    Core columns already registered — skipping.")


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


def _register_geo_columns(dataset: "SqlaTable") -> None:
    """Explicitly register GeoIP columns in the Superset dataset.

    fetch_metadata() only discovers columns that already exist in DuckDB.
    When the ingester was run without a GeoLite2 database the geo_* columns
    may not be present in the DuckDB file, so they are added here explicitly.
    This prevents ImportDashboardsCommand from raising "Columns missing in
    dataset" errors when importing the GeoIP charts (DSH-15 ~ DSH-18).
    """
    from superset.connectors.sqla.models import TableColumn  # noqa: PLC0415
    from superset.extensions import db  # noqa: PLC0415

    existing_names = {col.column_name for col in dataset.columns}
    added = 0
    for col_name, col_type, verbose_name, groupby, filterable in GEO_COLUMNS:
        if col_name in existing_names:
            continue
        col = TableColumn(
            column_name=col_name,
            type=col_type,
            verbose_name=verbose_name,
            groupby=groupby,
            filterable=filterable,
            is_active=True,
            table_id=dataset.id,
        )
        db.session.add(col)
        added += 1

    if added:
        db.session.commit()
        print(f"    Registered {added} GeoIP column(s) in dataset.")
    else:
        print("    GeoIP columns already registered — skipping.")


if __name__ == "__main__":
    main()
    sys.exit(0)
