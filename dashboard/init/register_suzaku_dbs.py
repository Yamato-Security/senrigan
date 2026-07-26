"""register_suzaku_dbs.py — Register Suzaku DuckDB connections in Superset.

Runs inside the superset-init container as part of ``bootstrap.sh``, before
``register_dataset.py``.

Suzaku (https://github.com/Yamato-Security/suzaku) writes its ``aws-ct-*``
results as DuckDB files that an analyst copies into the mounted database
directory. The file names are arbitrary, so the producing command is inferred
from the schema, and each detected command is registered as its own Superset
database under a **fixed name and UUID**. Dataset and chart YAMLs reference that
UUID, so re-running Suzaku under a different file name only updates a stored URI
— no asset ever has to change.

Superset stores one file path per database connection, resolved once here; that
is why detection cannot live only in the agent. :data:`SUZAKU_SIGNATURES` is a
copy of the table in ``agent/suzaku_db.py`` (the Superset image cannot import the
agent package) and ``tests/test_suzaku_detection_parity.py`` asserts the two stay
identical.

Run it **twice** from ``bootstrap.sh``: once before the dataset step so the
databases exist, and once after the dashboard ZIPs are imported. Superset's
``ImportAssetsCommand`` applies the bundle's ``databases/*.yaml`` onto the
existing object (matched by UUID), which replaces the detected path with the
placeholder shipped in the YAML — so the second run is what makes an
arbitrarily-named Suzaku file actually work.

``--list`` prints the detected commands and exits, without importing Superset;
``bootstrap.sh`` uses it to skip a bundle whose database was never copied in.
Importing that bundle anyway would register a database pointing at a file that
does not exist, and every chart on it would fail with an IOError.

Superset imports happen lazily inside :func:`main` so this module can be
imported — and its detection tested — outside the container. The
app-context-before-model-import pattern matches ``register_duckdb.py``.
"""

from __future__ import annotations

import glob
import json
import os
import sys

# Directory holding both Senrigan's own database and any Suzaku exports.
DB_DIR = os.path.dirname(os.environ.get("DUCKDB_PATH", "/data/db/threat_hunting.db"))

# Senrigan's own table: a file containing it is the ingester's output.
SENRIGAN_TABLE = "cloudtrail_events"

# Signature per Suzaku command: every listed table must exist and hold at least
# the listed columns. Extra tables and columns are allowed so a later Suzaku
# release that adds either still matches.
#
# Keep in sync with agent/suzaku_db.py (guarded by
# tests/test_suzaku_detection_parity.py).
SUZAKU_SIGNATURES: dict[str, dict[str, frozenset[str]]] = {
    "aws-ct-timeline": {
        "timeline": frozenset(
            {"Timestamp", "RuleTitle", "Level", "RuleID", "EventName"}
        ),
    },
    "aws-ct-summary": {
        "summary": frozenset({"UserARN", "NumOfEvents"}),
        "summary_api_calls": frozenset({"UserARN", "Category", "API", "Count"}),
        "summary_attributes": frozenset({"UserARN", "Attribute", "Value", "Count"}),
    },
    "aws-ct-metrics": {
        "metrics": frozenset({"Field", "Value", "Count", "Percent"}),
    },
}

# Superset database name per command. Fixed: shown in SQL Lab and referenced by
# the bundle's databases/*.yaml.
DATABASE_NAMES: dict[str, str] = {
    "aws-ct-timeline": "Suzaku Timeline DuckDB",
    "aws-ct-summary": "Suzaku Summary DuckDB",
    "aws-ct-metrics": "Suzaku Metrics DuckDB",
}

# Fixed UUIDs — these are what dataset YAMLs reference, so they must never
# change once shipped.
DATABASE_UUIDS: dict[str, str] = {
    "aws-ct-timeline": "5a021001-0000-4000-8000-000000000001",
    "aws-ct-summary": "5a021001-0000-4000-8000-000000000002",
    "aws-ct-metrics": "5a021001-0000-4000-8000-000000000003",
}

# Superset asset bundle -> the Suzaku command whose database it needs.
# bootstrap.sh imports a bundle only when its command was detected.
BUNDLE_COMMANDS: dict[str, str] = {
    "suzaku_timeline": "aws-ct-timeline",
    "suzaku_summary": "aws-ct-summary",
    "suzaku_metrics": "aws-ct-metrics",
}

# Environment variable pinning one file per command, overriding discovery.
ENV_OVERRIDES: dict[str, str] = {
    "aws-ct-timeline": "SUZAKU_TIMELINE_DB",
    "aws-ct-summary": "SUZAKU_SUMMARY_DB",
    "aws-ct-metrics": "SUZAKU_METRICS_DB",
}


def detect_commands(tables: dict[str, list[str]]) -> set[str]:
    """Return every Suzaku command whose signature *tables* satisfies.

    Matching is case-insensitive (DuckDB identifiers are) and tolerant of extra
    tables and columns.

    Args:
        tables: ``{table_name: [column, ...]}`` describing one database.

    Returns:
        The matching command names; empty when unrecognised, including when the
        file is Senrigan's own database.
    """
    normalised = {
        name.lower(): {column.lower() for column in columns}
        for name, columns in tables.items()
    }
    if SENRIGAN_TABLE in normalised:
        return set()

    matched: set[str] = set()
    for command, signature in SUZAKU_SIGNATURES.items():
        if all(
            table.lower() in normalised
            and {column.lower() for column in required} <= normalised[table.lower()]
            for table, required in signature.items()
        ):
            matched.add(command)
    return matched


def detect_commands_in(path: str) -> set[str]:
    """Return the Suzaku commands whose output *path* looks like.

    Never raises: a file that cannot be opened read-only is reported as
    unrecognised, because one stray file must not abort the bootstrap.

    Args:
        path: Candidate ``.duckdb`` file.

    Returns:
        The matching command names, or an empty set.
    """
    import duckdb  # noqa: PLC0415 — keeps the module importable without duckdb

    try:
        conn = duckdb.connect(str(path), read_only=True)
    except Exception as exc:  # noqa: BLE001
        print(f"    Skipping {path}: {exc}")
        return set()

    try:
        rows = conn.execute(
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema = 'main'"
        ).fetchall()
    except Exception as exc:  # noqa: BLE001
        print(f"    Skipping {path}: {exc}")
        return set()
    finally:
        conn.close()

    tables: dict[str, list[str]] = {}
    for table_name, column_name in rows:
        tables.setdefault(table_name, []).append(column_name)
    return detect_commands(tables)


def discover_databases(directory: str = DB_DIR) -> dict[str, str]:
    """Map each detected Suzaku command to the file that should serve it.

    Only ``*.duckdb`` is scanned, which excludes Senrigan's own
    ``threat_hunting.db``. When several files match one command the newest wins,
    so re-running Suzaku and copying the result in is enough. A
    ``SUZAKU_*_DB`` environment variable overrides discovery for its command.

    Args:
        directory: Directory to scan.

    Returns:
        ``{command: absolute_path}`` for every command that has a database.
    """
    found: dict[str, str] = {}

    if os.path.isdir(directory):
        candidates = sorted(
            glob.glob(os.path.join(directory, "*.duckdb")),
            key=os.path.getmtime,
            reverse=True,
        )
        for path in candidates:
            for command in detect_commands_in(path):
                found.setdefault(command, os.path.abspath(path))

    for command, variable in ENV_OVERRIDES.items():
        override = os.environ.get(variable)
        if override and command in detect_commands_in(override):
            found[command] = os.path.abspath(override)

    return found


def build_uri(path: str) -> str:
    """Return the SQLAlchemy URI for a DuckDB file.

    DU-13: the explicit ``+duckdb_engine`` driver bypasses SQLAlchemy 2.x
    entry-point discovery, which can fail with "Can't load plugin:
    sqlalchemy.dialects:duckdb". Read-only access is set through
    ``connect_args`` (see :func:`build_extra`), never as a URI parameter.

    Args:
        path: Absolute path to the DuckDB file.

    Returns:
        A ``duckdb+duckdb_engine:///…`` URI.
    """
    return f"duckdb+duckdb_engine:///{path}"


def build_extra() -> dict:
    """Return the Superset ``extra`` payload: read-only, no file uploads."""
    return {
        "metadata_params": {},
        "engine_params": {"connect_args": {"read_only": True}},
        "schemas_allowed_for_file_upload": [],
    }


def print_detected(directory: str = DB_DIR) -> None:
    """Print the Suzaku commands detected in *directory*, one per line.

    Used by ``bootstrap.sh`` (``--list``) to decide which dashboard bundles to
    import. Deliberately does not touch Superset, so it stays fast and cannot
    fail on a half-initialised metadata database.

    Args:
        directory: Directory to scan.
    """
    for command in sorted(discover_databases(directory)):
        print(command)


def main() -> None:
    """Register (or update) one Superset database per detected Suzaku command.

    Idempotent, and safe to run repeatedly: the second run after the ZIP imports
    is what restores the detected file path over the bundle's placeholder.
    """
    found = discover_databases()
    if not found:
        print(f"    No Suzaku DuckDB files detected in {DB_DIR} — skipping.")
        return

    # Step 1 — create the Flask app (no model imports yet).
    from superset import create_app  # noqa: PLC0415

    app = create_app()

    # Step 2 — push the context so Werkzeug LocalProxy resolves current_app.
    ctx = app.app_context()
    ctx.push()

    try:
        # Step 3 — now it is safe to import models that access app.config.
        from superset.extensions import db  # noqa: PLC0415
        from superset.models.core import Database  # noqa: PLC0415

        for command, path in sorted(found.items()):
            name = DATABASE_NAMES[command]
            uri = build_uri(path)
            extra = json.dumps(build_extra())

            existing = db.session.query(Database).filter_by(database_name=name).first()
            if existing:
                updated = False
                if existing.sqlalchemy_uri != uri:
                    existing.sqlalchemy_uri = uri
                    existing.extra = extra
                    updated = True
                    print(f"    Database '{name}' now points at {path}.")
                # Async execution needs a Celery worker, which is not deployed.
                if existing.allow_run_async:
                    setattr(existing, "allow_run_async", False)
                    updated = True
                if updated:
                    db.session.commit()
                else:
                    print(f"    Database '{name}' already registered — skipping.")
                continue

            database = Database(
                database_name=name,
                sqlalchemy_uri=uri,
                uuid=DATABASE_UUIDS[command],
                expose_in_sqllab=True,
                allow_ctas=False,
                allow_cvas=False,
                allow_dml=False,
                extra=extra,
            )
            db.session.add(database)
            db.session.commit()
            print(f"    Database '{name}' registered for {command}.")
            print(f"    URI: {uri}")
    finally:
        ctx.pop()


if __name__ == "__main__":
    if "--list" in sys.argv[1:]:
        print_detected()
    else:
        main()
    sys.exit(0)
