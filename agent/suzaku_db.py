"""Discovery and kind detection for Suzaku DuckDB output.

`Suzaku <https://github.com/Yamato-Security/suzaku>`_ writes its ``aws-ct-*``
results as DuckDB files. Senrigan reads them as-is: they are third-party,
read-only artifacts that the ingester never touches, which keeps the
1-writer / N-readers invariant intact.

Since Suzaku's DuckDB ``schema_version`` 1 every file carries a one-row
``suzaku_meta`` table naming the command that produced it, so the producing
command is *read* rather than inferred from a table signature. ``schema_version``
is checked before anything else: a file written by a layout Senrigan does not
know is refused rather than mis-visualized.

This module is pure Python with no Streamlit dependency so it stays unit
testable. ``dashboard/init/register_suzaku_dbs.py`` holds a second copy of the
detection constants (the Superset image cannot import this package); the root
test suite asserts the two stay identical.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import duckdb

# Default directory the reader services mount the DuckDB files into. Suzaku
# files sit next to Senrigan's own threat_hunting.db.
DEFAULT_DB_DIR = Path("/data/db")

# Senrigan's own table. A file containing it is the ingester's output, never a
# Suzaku export, whatever its metadata claims.
SENRIGAN_TABLE = "cloudtrail_events"

# Suzaku's provenance table and the layout version Senrigan is written against
# (suzaku's src/core/duckdb_out.rs: SCHEMA_VERSION).
#
# Keep in sync with dashboard/init/register_suzaku_dbs.py (guarded by
# tests/test_suzaku_detection_parity.py).
META_TABLE = "suzaku_meta"
SUPPORTED_SCHEMA_VERSION = 1


class SuzakuKind(str, Enum):
    """The Suzaku subcommand that produced a DuckDB file.

    The value is exactly what Suzaku writes to ``suzaku_meta.command``.
    """

    TIMELINE = "aws-ct-timeline"
    SUMMARY = "aws-ct-summary"
    METRICS = "aws-ct-metrics"


# Payload tables per kind. Only these are row-counted: counting every table in
# an arbitrary file is pointless, and `suzaku_meta` is always one row.
#
# Keep in sync with dashboard/init/register_suzaku_dbs.py.
SUZAKU_TABLES: dict[SuzakuKind, tuple[str, ...]] = {
    SuzakuKind.TIMELINE: ("timeline",),
    SuzakuKind.SUMMARY: ("summary", "summary_api_calls", "summary_attributes"),
    SuzakuKind.METRICS: ("metrics",),
}

# Environment variable pinning one file per kind, overriding discovery. Useful
# when several runs are kept side by side, and in tests.
ENV_OVERRIDES: dict[SuzakuKind, str] = {
    SuzakuKind.TIMELINE: "SUZAKU_TIMELINE_DB",
    SuzakuKind.SUMMARY: "SUZAKU_SUMMARY_DB",
    SuzakuKind.METRICS: "SUZAKU_METRICS_DB",
}


@dataclass(frozen=True)
class DbInfo:
    """What inspecting one candidate DuckDB file revealed.

    Attributes:
        path:       The inspected file.
        kind:       Suzaku command that wrote it, or None when unrecognised.
        tables:     ``{table_name: [column, ...]}`` as stored in the file.
        row_counts: ``{table_name: rows}`` for the payload tables of *kind*.
        error:      DuckDB's message when the file could not be read, else "".
        hint:       Operator-facing explanation of *error*, of a rejected schema
                    version, or of a stale WAL.
    """

    path: Path
    kind: SuzakuKind | None = None
    tables: dict[str, list[str]] = field(default_factory=dict)
    row_counts: dict[str, int] = field(default_factory=dict)
    error: str = ""
    hint: str = ""

    @property
    def label(self) -> str:
        """Return a one-line description for a selectbox or a status line."""
        if self.error:
            return f"{self.path.name} — unreadable"
        kind = self.kind.value if self.kind else "unrecognised"
        rows = sum(self.row_counts.values())
        return f"{self.path.name} — {kind} ({rows:,} rows)"


def detect_kind(command: str | None) -> SuzakuKind | None:
    """Return the kind *command* names, or ``None`` when it is not one of ours.

    Args:
        command: The ``suzaku_meta.command`` value, or None when absent.

    Returns:
        The matching :class:`SuzakuKind`, or ``None`` for an unknown command —
        Suzaku's Azure subcommands, or one added after this release.
    """
    if not command:
        return None
    normalised = command.strip().lower()
    for kind in SuzakuKind:
        if kind.value == normalised:
            return kind
    return None


def _wal_hint(path: Path) -> str:
    """Return a warning when *path* has a sibling write-ahead log.

    Every Senrigan reader opens ``/data/db`` read-only, and DuckDB cannot
    replay a WAL without write access, so an un-checkpointed file fails to open
    inside the containers even though it works on the host.
    """
    if path.with_name(path.name + ".wal").exists():
        return (
            "A .wal file sits next to this database. DuckDB cannot replay it on a "
            "read-only mount — re-export it, or open it once read-write and run "
            "CHECKPOINT before copying."
        )
    return ""


def _error_hint(message: str) -> str:
    """Translate a DuckDB open failure into something actionable."""
    lowered = message.lower()
    if "newer version" in lowered or "too new" in lowered:
        return (
            "This file was written by a newer DuckDB than the one Senrigan "
            "bundles. Upgrade the duckdb dependency, or re-export from Suzaku "
            "with a matching version."
        )
    if "not a valid duckdb" in lowered or "magic bytes" in lowered:
        return (
            "Not a DuckDB database. Suzaku's CSV/JSON output cannot be read "
            "here — re-run the command with DuckDB output."
        )
    return "The file could not be opened read-only. See the error above."


def _read_meta(conn: duckdb.DuckDBPyConnection) -> tuple[int | None, str | None]:
    """Return ``(schema_version, command)`` from ``suzaku_meta``.

    Args:
        conn: An open read-only connection.

    Returns:
        ``(None, None)`` when the table is missing — which is what any DuckDB
        file that is not Suzaku output looks like.
    """
    try:
        row = conn.execute(
            f"SELECT schema_version, command FROM {META_TABLE} LIMIT 1"
        ).fetchone()
    except duckdb.Error:
        return (None, None)
    if not row:
        return (None, None)
    version, command = row
    return (int(version) if version is not None else None, command)


def inspect_db(path: Path) -> DbInfo:
    """Inspect one candidate file and classify it.

    Never raises: an unreadable file is reported through :attr:`DbInfo.error`
    with a matching :attr:`DbInfo.hint`, because these paths come from an
    operator copying files into a directory, and the UI has to explain the
    problem rather than crash.

    Args:
        path: The ``.duckdb`` file to inspect.

    Returns:
        A :class:`DbInfo` describing the file.
    """
    path = Path(path)
    if not path.exists():
        return DbInfo(
            path=path,
            error=f"{path} does not exist",
            hint="The file was moved or deleted after it was discovered.",
        )

    try:
        conn = duckdb.connect(str(path), read_only=True)
    except Exception as exc:  # noqa: BLE001 — any open failure must be reported
        message = str(exc)
        return DbInfo(path=path, error=message, hint=_error_hint(message))

    try:
        rows = conn.execute(
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema = 'main' ORDER BY table_name, ordinal_position"
        ).fetchall()
        tables: dict[str, list[str]] = {}
        for table_name, column_name in rows:
            tables.setdefault(table_name, []).append(column_name)

        version, command = _read_meta(conn)
        kind = detect_kind(command)
        hint = _wal_hint(path)

        if any(name.lower() == SENRIGAN_TABLE for name in tables):
            # Senrigan's own database can never be a Suzaku export.
            kind = None
        elif version is None:
            kind = None
            hint = hint or (
                f"No {META_TABLE} table. Senrigan reads Suzaku output from "
                "schema_version 1 onwards — re-export with a current Suzaku."
            )
        elif version > SUPPORTED_SCHEMA_VERSION:
            kind = None
            hint = (
                f"This file declares schema_version {version}; Senrigan reads "
                f"up to {SUPPORTED_SCHEMA_VERSION}. Upgrade Senrigan rather "
                "than risk misreading the columns."
            )

        row_counts: dict[str, int] = {}
        if kind is not None:
            wanted = {name.lower() for name in SUZAKU_TABLES[kind]}
            for table in tables:
                if table.lower() in wanted:
                    (count,) = conn.execute(
                        f'SELECT count(*) FROM "{table}"'
                    ).fetchone()
                    row_counts[table] = int(count)
    except Exception as exc:  # noqa: BLE001 — a readable file can still be odd
        message = str(exc)
        return DbInfo(path=path, error=message, hint=_error_hint(message))
    finally:
        conn.close()

    return DbInfo(
        path=path,
        kind=kind,
        tables=tables,
        row_counts=row_counts,
        hint=hint,
    )


def discover(directory: Path | str = DEFAULT_DB_DIR) -> list[DbInfo]:
    """Inspect every ``*.duckdb`` file in *directory*, newest first.

    Only the ``.duckdb`` extension is scanned, which naturally excludes
    Senrigan's own ``threat_hunting.db``; :func:`inspect_db` rejects it a
    second time by table name.

    Args:
        directory: Directory to scan. A missing directory yields ``[]``.

    Returns:
        One :class:`DbInfo` per candidate file, ordered by modification time
        descending so a freshly copied Suzaku run comes first.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return []

    candidates = sorted(
        directory.glob("*.duckdb"), key=lambda p: p.stat().st_mtime, reverse=True
    )
    return [inspect_db(path) for path in candidates]


def find_db(kind: SuzakuKind, directory: Path | str = DEFAULT_DB_DIR) -> DbInfo | None:
    """Return the database to use for *kind*, or ``None`` when there is none.

    An existing ``SUZAKU_*_DB`` environment override wins over discovery. A
    stale override — one naming a file that is gone or is of another kind —
    falls back to discovery rather than hiding a usable database.

    Args:
        kind:      The Suzaku kind wanted.
        directory: Directory to scan when no override applies.

    Returns:
        The matching :class:`DbInfo`, newest first, or ``None``.
    """
    override = os.environ.get(ENV_OVERRIDES[kind])
    if override:
        info = inspect_db(Path(override))
        if not info.error and info.kind is kind:
            return info

    for info in discover(directory):
        if info.kind is kind:
            return info
    return None
