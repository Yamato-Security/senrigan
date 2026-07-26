"""Discovery and schema-based kind detection for Suzaku DuckDB output.

`Suzaku <https://github.com/Yamato-Security/suzaku>`_ writes its ``aws-ct-*``
results as DuckDB files. Senrigan reads them as-is: they are third-party,
read-only artifacts that the ingester never touches, which keeps the
1-writer / N-readers invariant intact.

The files carry no metadata table, so the producing command has to be inferred
from the schema — see ``doc/PLAN_SUZAKU_SCHEMA.md`` P1 for the upstream proposal
that would turn this heuristic into a single column read.

This module is pure Python with no Streamlit dependency so it stays unit
testable. ``dashboard/init/register_suzaku_dbs.py`` holds a second copy of
:data:`SUZAKU_SIGNATURES` (the Superset image cannot import this package); the
root test suite asserts the two stay identical.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable, Mapping

import duckdb

# Default directory the reader services mount the DuckDB files into. Suzaku
# files sit next to Senrigan's own threat_hunting.db.
DEFAULT_DB_DIR = Path("/data/db")

# Senrigan's own table. A file containing it is the ingester's output, never a
# Suzaku export, whatever else it happens to contain.
SENRIGAN_TABLE = "cloudtrail_events"


class SuzakuKind(str, Enum):
    """The Suzaku subcommand that produced a DuckDB file."""

    TIMELINE = "aws-ct-timeline"
    SUMMARY = "aws-ct-summary"
    METRICS = "aws-ct-metrics"


# Signature per kind: every listed table must exist and must contain at least
# the listed columns. Extra tables and extra columns are allowed so a future
# Suzaku release that adds either still matches.
#
# Keep in sync with dashboard/init/register_suzaku_dbs.py (guarded by
# tests/test_suzaku_detection_parity.py).
SUZAKU_SIGNATURES: dict[SuzakuKind, dict[str, frozenset[str]]] = {
    SuzakuKind.TIMELINE: {
        "timeline": frozenset(
            {"Timestamp", "RuleTitle", "Level", "RuleID", "EventName"}
        ),
    },
    SuzakuKind.SUMMARY: {
        "summary": frozenset({"UserARN", "NumOfEvents"}),
        "summary_api_calls": frozenset({"UserARN", "Category", "API", "Count"}),
        "summary_attributes": frozenset({"UserARN", "Attribute", "Value", "Count"}),
    },
    SuzakuKind.METRICS: {
        "metrics": frozenset({"Field", "Value", "Count", "Percent"}),
    },
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
        kinds:      Suzaku kinds the schema matches; empty when unrecognised.
        tables:     ``{table_name: [column, ...]}`` as stored in the file.
        row_counts: ``{table_name: rows}`` for the tables of a matched kind.
        error:      DuckDB's message when the file could not be read, else "".
        hint:       Operator-facing explanation of *error*, or of a stale WAL.
    """

    path: Path
    kinds: set[SuzakuKind] = field(default_factory=set)
    tables: dict[str, list[str]] = field(default_factory=dict)
    row_counts: dict[str, int] = field(default_factory=dict)
    error: str = ""
    hint: str = ""

    @property
    def label(self) -> str:
        """Return a one-line description for a selectbox or a status line."""
        if self.error:
            return f"{self.path.name} — unreadable"
        kinds = ", ".join(sorted(kind.value for kind in self.kinds)) or "unrecognised"
        rows = sum(self.row_counts.values())
        return f"{self.path.name} — {kinds} ({rows:,} rows)"


def detect_kinds(tables: Mapping[str, Iterable[str]]) -> set[SuzakuKind]:
    """Return every Suzaku kind whose signature *tables* satisfies.

    Matching is case-insensitive on both table and column names because DuckDB
    identifiers are, and tolerant of extras so added tables or columns in a
    later Suzaku release do not break detection.

    Args:
        tables: ``{table_name: columns}`` describing one database.

    Returns:
        The matching kinds — empty when the schema is not recognisable as
        Suzaku output, including when it is Senrigan's own database.
    """
    normalised = {
        name.lower(): {column.lower() for column in columns}
        for name, columns in tables.items()
    }

    # Senrigan's own database can never be a Suzaku export.
    if SENRIGAN_TABLE in normalised:
        return set()

    matched: set[SuzakuKind] = set()
    for kind, signature in SUZAKU_SIGNATURES.items():
        if all(
            table.lower() in normalised
            and {column.lower() for column in required} <= normalised[table.lower()]
            for table, required in signature.items()
        ):
            matched.add(kind)
    return matched


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

        kinds = detect_kinds(tables)

        # Row counts only for the tables a matched signature names: counting a
        # multi-million-row table is cheap in DuckDB, counting every unrelated
        # table in an unrecognised file is pointless.
        wanted = {
            table.lower()
            for kind in kinds
            for table in SUZAKU_SIGNATURES[kind]  # signature tables only
        }
        row_counts: dict[str, int] = {}
        for table in tables:
            if table.lower() in wanted:
                (count,) = conn.execute(f'SELECT count(*) FROM "{table}"').fetchone()
                row_counts[table] = int(count)
    except Exception as exc:  # noqa: BLE001 — a readable file can still be odd
        message = str(exc)
        return DbInfo(path=path, error=message, hint=_error_hint(message))
    finally:
        conn.close()

    return DbInfo(
        path=path,
        kinds=kinds,
        tables=tables,
        row_counts=row_counts,
        hint=_wal_hint(path),
    )


def discover(directory: Path | str = DEFAULT_DB_DIR) -> list[DbInfo]:
    """Inspect every ``*.duckdb`` file in *directory*, newest first.

    Only the ``.duckdb`` extension is scanned, which naturally excludes
    Senrigan's own ``threat_hunting.db``; :func:`detect_kinds` rejects it a
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
        if not info.error and kind in info.kinds:
            return info

    for info in discover(directory):
        if kind in info.kinds:
            return info
    return None
