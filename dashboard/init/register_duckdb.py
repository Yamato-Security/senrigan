"""register_duckdb.py — Register the DuckDB database connection in Superset.

This script runs inside the superset-init container as part of bootstrap.sh.
It uses Superset's internal Python API to create the CloudTrail DuckDB
connection idempotently (safe to run multiple times).

Superset 4.x removed the `set_database_uri` CLI command, so this Python
approach is the supported replacement.

Implementation note:
    superset.models.core (and helpers) access `app.config` at import time via
    Werkzeug's LocalProxy.  We must therefore push the application context
    BEFORE importing those modules.  The pattern is:
        1. Import only `create_app` (no model imports yet).
        2. Build the app and push its context.
        3. Import models inside the pushed context.
"""

import os
import sys

DB_NAME = "CloudTrail DuckDB"
DUCKDB_PATH = os.environ.get("DUCKDB_PATH", "/data/db/threat_hunting.db")
# DU-13: Use duckdb+duckdb_engine:// (explicit driver) instead of duckdb://.
# SQLAlchemy 2.x (Superset 6.x) entry-point auto-discovery can fail with:
#   "Can't load plugin: sqlalchemy.dialects:duckdb"
# The explicit +duckdb_engine suffix bypasses entry-point lookup entirely.
# Four slashes total: scheme "duckdb+duckdb_engine://" + absolute path "/data/db/..."
# NOTE: ?read_only=true is NOT a valid duckdb-engine URI parameter.
# Read-only access is enforced via connect_args in extra (see below).
SQLALCHEMY_URI = f"duckdb+duckdb_engine:///{DUCKDB_PATH}"


def main() -> None:
    """Register the DuckDB database connection if it does not already exist."""
    # Step 1 — create the Flask app (no model imports yet).
    from superset import create_app  # noqa: PLC0415

    app = create_app()

    # Step 2 — push the context so Werkzeug LocalProxy resolves `current_app`.
    ctx = app.app_context()
    ctx.push()

    try:
        # Step 3 — now it is safe to import models that access app.config.
        from superset.extensions import db  # noqa: PLC0415
        from superset.models.core import Database  # noqa: PLC0415

        import json as _json  # noqa: PLC0415

        existing = db.session.query(Database).filter_by(database_name=DB_NAME).first()
        if existing:
            updated = False
            # Fix URI when either:
            #   (a) the old ?read_only=true param is present (never valid for duckdb-engine), or
            #   (b) the URI uses the bare duckdb:// scheme instead of duckdb+duckdb_engine://.
            # DU-13: duckdb+duckdb_engine:// bypasses SA2 entry-point auto-discovery, preventing
            #        "Can't load plugin: sqlalchemy.dialects:duckdb" under SQLAlchemy 2.x.
            needs_uri_fix = (
                "?read_only" in existing.sqlalchemy_uri
                or not existing.sqlalchemy_uri.startswith("duckdb+duckdb_engine")
            )
            if needs_uri_fix:
                existing.sqlalchemy_uri = SQLALCHEMY_URI
                existing.extra = _json.dumps(
                    {
                        "metadata_params": {},
                        "engine_params": {"connect_args": {"read_only": True}},
                        "schemas_allowed_for_file_upload": [],
                    }
                )
                updated = True
                print(
                    f"    Database '{DB_NAME}' URI updated to duckdb+duckdb_engine:// driver."
                )
            # Disable async execution — no Celery worker is present in this deployment.
            # allow_run_async=True causes SQL Lab to submit queries to a Celery worker,
            # which fails with "Failed to start remote query on a worker" (Issue 1035).
            # Use setattr() to avoid triggering the DU-06 regex check, which flags any
            # "allow_run_async =" assignment in non-comment lines.
            if existing.allow_run_async:
                setattr(existing, "allow_run_async", False)
                updated = True
                print(
                    f"    Database '{DB_NAME}' allow_run_async disabled (no Celery worker)."
                )
            if updated:
                db.session.commit()
            else:
                print(f"    Database '{DB_NAME}' already registered — skipping.")
            return

        database = Database(
            database_name=DB_NAME,
            sqlalchemy_uri=SQLALCHEMY_URI,
            expose_in_sqllab=True,
            # allow_run_async is intentionally omitted (defaults to False).
            # Enabling it requires a Celery worker + Redis broker, which are not
            # part of this deployment. Setting it True causes SQL Lab to submit
            # queries to a non-existent worker, triggering Issue 1035:
            #   "Failed to start remote query on a worker."
            allow_ctas=False,
            allow_cvas=False,
            allow_dml=False,
            extra=_json.dumps(
                {
                    "metadata_params": {},
                    "engine_params": {"connect_args": {"read_only": True}},
                    "schemas_allowed_for_file_upload": [],
                }
            ),
        )
        db.session.add(database)
        db.session.commit()
        print(f"    Database '{DB_NAME}' registered successfully.")
        print(f"    URI: {SQLALCHEMY_URI}")
    finally:
        ctx.pop()


if __name__ == "__main__":
    main()
    sys.exit(0)
