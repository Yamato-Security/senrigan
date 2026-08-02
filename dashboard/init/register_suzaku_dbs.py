"""register_suzaku_dbs.py — Register Suzaku DuckDB connections in Superset.

Runs inside the superset-init container as part of ``bootstrap.sh``, before
``register_dataset.py``.

Suzaku (https://github.com/Yamato-Security/suzaku) writes its ``aws-ct-*``
results as DuckDB files that an analyst copies into the mounted database
directory. The file names are arbitrary, so the producing command is read from
the file's own ``suzaku_meta`` table, and each detected command is registered as
its own Superset database under a **fixed name and UUID**. Dataset and chart
YAMLs reference that UUID, so re-running Suzaku under a different file name only
updates a stored URI — no asset ever has to change.

Superset stores one file path per database connection, resolved once here; that
is why the choice cannot live only in the agent. Detection, fitness and the
choice itself come from ``agent/suzaku_db.py``, which
``docker/docker-compose.yml`` bind-mounts next to this script — the Superset
image cannot install the agent package, but it can import one module. This file
is only the Superset adapter: names, UUIDs and the metadata writes.

Run it **twice** from ``bootstrap.sh``: once before the dataset step so the
databases exist, and once after the dashboard ZIPs are imported. Superset's
``ImportAssetsCommand`` applies the bundle's ``databases/*.yaml`` onto the
existing object (matched by UUID), which replaces the detected path with the
placeholder shipped in the YAML — so the second run is what makes an
arbitrarily-named Suzaku file actually work.

Command line:

``--scan FILE``   inspect the directory once and write the inventory to FILE.
``--from FILE``   select from that inventory instead of re-opening every file.
``--list``        print the commands that have a usable file, one per line;
                  ``bootstrap.sh`` uses it to skip a bundle whose database was
                  never copied in. Importing that bundle anyway would register a
                  database pointing at a file that does not exist, and every
                  chart on it would fail with an IOError.
``--report``      print what was chosen, what was passed over and what was
                  rejected, with reasons.

None of these touch Superset, so they stay fast and cannot fail on a
half-initialised metadata database. Superset imports happen lazily inside
:func:`main` so this module can be imported — and tested — outside the
container. The app-context-before-model-import pattern matches
``register_duckdb.py``.
"""

from __future__ import annotations

import json
import os
import sys

from suzaku_db import (
    DbInfo,
    Selection,
    SuzakuKind,
    discover,
    inventory_from_json,
    inventory_to_json,
    select,
)

# Directory holding both Senrigan's own database and any Suzaku exports.
DB_DIR = os.path.dirname(os.environ.get("DUCKDB_PATH", "/data/db/threat_hunting.db"))

# Superset database name per command. Fixed: shown in SQL Lab and referenced by
# the bundle's databases/*.yaml.
DATABASE_NAMES: dict[str, str] = {
    SuzakuKind.TIMELINE.value: "Suzaku Timeline DuckDB",
    SuzakuKind.SUMMARY.value: "Suzaku Summary DuckDB",
    SuzakuKind.METRICS.value: "Suzaku Metrics DuckDB",
}

# Fixed UUIDs — these are what dataset YAMLs reference, so they must never
# change once shipped.
DATABASE_UUIDS: dict[str, str] = {
    SuzakuKind.TIMELINE.value: "5a021001-0000-4000-8000-000000000001",
    SuzakuKind.SUMMARY.value: "5a021001-0000-4000-8000-000000000002",
    SuzakuKind.METRICS.value: "5a021001-0000-4000-8000-000000000003",
}

# Superset asset bundle -> the Suzaku command whose database it needs.
# bootstrap.sh imports a bundle only when its command was detected.
BUNDLE_COMMANDS: dict[str, str] = {
    "suzaku_timeline": SuzakuKind.TIMELINE.value,
    "suzaku_summary": SuzakuKind.SUMMARY.value,
    "suzaku_metrics": SuzakuKind.METRICS.value,
}


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


# ---------------------------------------------------------------------------
# Scanning — one pass, reused by every step of bootstrap.sh
# ---------------------------------------------------------------------------


def write_inventory(destination: str, directory: str = DB_DIR) -> list[DbInfo]:
    """Scan *directory* once and write the result to *destination*.

    ``bootstrap.sh`` calls this before anything else so that registering,
    listing and reporting do not each re-open every file — a directory of
    200 MB timelines makes that the dominant cost of initialization.

    Args:
        destination: File to write the inventory JSON to.
        directory:   Directory to scan.

    Returns:
        The inventory, for callers that want it in-process.
    """
    infos = discover(directory)
    with open(destination, "w", encoding="utf-8") as handle:
        handle.write(inventory_to_json(infos))
    return infos


def load_inventory(
    inventory_path: str | None = None, directory: str = DB_DIR
) -> list[DbInfo]:
    """Return a scan, reading a saved one when it is usable.

    A missing or unreadable inventory falls back to scanning, so a failed
    ``--scan`` degrades to the slower path rather than to no dashboards.

    Args:
        inventory_path: File written by :func:`write_inventory`, or None.
        directory:      Directory to scan when there is no usable inventory.

    Returns:
        One :class:`DbInfo` per candidate file.
    """
    if inventory_path and os.path.isfile(inventory_path):
        try:
            with open(inventory_path, encoding="utf-8") as handle:
                return inventory_from_json(handle.read())
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"    Inventory {inventory_path} unusable ({exc}) — rescanning.")
    return discover(directory)


def load_selections(
    inventory_path: str | None = None, directory: str = DB_DIR
) -> dict[SuzakuKind, Selection]:
    """Return the per-command decision, from a saved scan when one is given.

    Args:
        inventory_path: File written by :func:`write_inventory`, or None.
        directory:      Directory to scan when there is no usable inventory.

    Returns:
        ``{kind: Selection}`` for every :class:`SuzakuKind`.
    """
    return select(directory, inventory=load_inventory(inventory_path, directory))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def print_detected(selections: dict[SuzakuKind, Selection]) -> None:
    """Print one line per command that has a usable database.

    Args:
        selections: Output of :func:`load_selections`.
    """
    for kind in sorted(selections, key=lambda item: item.value):
        if selections[kind].chosen is not None:
            print(kind.value)


def _describe(info: DbInfo) -> str:
    """Return a one-line description of a file for the report."""
    parts = [info.path.name]
    if info.generated_at:
        parts.append(f"generated {info.generated_at:%Y-%m-%d %H:%M}")
    rows = sum(info.row_counts.values())
    if rows:
        parts.append(f"{rows:,} rows")
    return ", ".join(parts)


def format_report(
    selections: dict[SuzakuKind, Selection],
    inventory: list[DbInfo] | None = None,
    directory: str = DB_DIR,
) -> str:
    """Return a human-readable account of every decision.

    Names the file each dashboard will query, the usable files it beat, the
    files rejected as unqueryable and why, and anything that could not be
    opened. A silently dropped candidate is what makes "the dashboard shows old
    numbers" unanswerable.

    Args:
        selections: Output of :func:`load_selections`.
        inventory:  The scan behind *selections*, for the unreadable-file
                    section. Omitted sections are simply not printed.
        directory:  Directory the scan covered, for the header.

    Returns:
        The report, without a trailing newline.
    """
    lines = [f"Suzaku databases in {directory}:"]

    for kind in sorted(selections, key=lambda item: item.value):
        selection = selections[kind]
        if selection.chosen is None:
            lines.append(f"  {kind.value:<16} — no usable file")
        else:
            suffix = (
                " (pinned by environment)" if selection.source == "override" else ""
            )
            lines.append(f"  {kind.value:<16} {_describe(selection.chosen)}{suffix}")
        for info in selection.ignored:
            lines.append(f"      ignored:  {_describe(info)}")
        for info in selection.rejected:
            lines.append(f"      rejected: {info.path.name} — {info.reject_reason}")

    unreadable = [info for info in (inventory or []) if info.error]
    for info in unreadable:
        lines.append(f"  unreadable: {info.path.name} — {info.hint or info.error}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Superset registration
# ---------------------------------------------------------------------------


def uri_target(uri: str) -> str:
    """Return the file path a DuckDB SQLAlchemy URI points at.

    Args:
        uri: A URI as produced by :func:`build_uri`.

    Returns:
        The absolute path, or ``""`` when the URI carries none.
    """
    _, separator, path = uri.partition("///")
    return path if separator else ""


def is_stale(uri: str) -> bool:
    """Return True when a registered connection points at a file that is gone.

    Deleting or renaming a Suzaku export leaves the Superset database behind,
    and every chart on it then fails with an IOError that names a path the
    analyst no longer recognises. A URI with no
    parseable path is left alone: retiring a connection on a guess is worse
    than leaving it.

    Args:
        uri: The stored ``sqlalchemy_uri``.

    Returns:
        True when the target is missing.
    """
    path = uri_target(uri)
    return bool(path) and not os.path.exists(path)


def main(inventory_path: str | None = None) -> None:
    """Register, repoint or retire one Superset database per Suzaku command.

    Idempotent, and safe to run repeatedly: the second run after the ZIP imports
    is what restores the detected file path over the bundle's placeholder.

    Superset is opened even when no file was found, because a command with no
    file today may still have a registration from yesterday pointing at one that
    was deleted.

    Args:
        inventory_path: A scan written by :func:`write_inventory`, when one is
                        available.
    """
    selections = load_selections(inventory_path)
    found = {
        kind.value: str(selection.chosen.path.resolve())
        for kind, selection in selections.items()
        if selection.chosen is not None
    }
    if not found:
        print(
            f"    No usable Suzaku DuckDB files in {DB_DIR} — "
            "checking for registrations left behind."
        )

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

        # Retire what is left pointing at a deleted file. The row itself stays:
        # its UUID has to survive so a later re-import, or a replacement file,
        # lands on the same object instead of creating a duplicate.
        for command, name in sorted(DATABASE_NAMES.items()):
            if command in found:
                continue
            existing = db.session.query(Database).filter_by(database_name=name).first()
            if existing is None or not is_stale(existing.sqlalchemy_uri):
                continue
            print(
                f"    Database '{name}' points at {uri_target(existing.sqlalchemy_uri)}, "
                "which is gone — hiding it until a replacement is copied in."
            )
            if existing.expose_in_sqllab:
                setattr(existing, "expose_in_sqllab", False)
                db.session.commit()
    finally:
        ctx.pop()


def _option(argv: list[str], flag: str) -> str | None:
    """Return the value following *flag*, or None when it is absent."""
    if flag in argv:
        index = argv.index(flag)
        if index + 1 < len(argv):
            return argv[index + 1]
    return None


if __name__ == "__main__":
    args = sys.argv[1:]
    inventory_file = _option(args, "--from")

    scan_target = _option(args, "--scan")
    if scan_target:
        write_inventory(scan_target)
    elif "--list" in args:
        print_detected(load_selections(inventory_file))
    elif "--report" in args:
        scan = load_inventory(inventory_file)
        print(format_report(select(DB_DIR, inventory=scan), scan))
    else:
        main(inventory_file)
    sys.exit(0)
