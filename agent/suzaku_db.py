"""Discovery, fitness and selection for Suzaku DuckDB output.

`Suzaku <https://github.com/Yamato-Security/suzaku>`_ writes its ``aws-ct-*``
results as DuckDB files. Senrigan reads them as-is: they are third-party,
read-only artifacts that the ingester never touches, which keeps the
1-writer / N-readers invariant intact.

Since Suzaku's DuckDB ``schema_version`` 1 every file carries a one-row
``suzaku_meta`` table naming the command that produced it, so the producing
command is *read* rather than inferred from a table signature. ``schema_version``
is checked before anything else: a file written by a layout Senrigan does not
know is refused rather than mis-visualized.

An analyst can leave several files in the mounted directory, so this module also
decides **which one** each consumer uses, and records what it passed over:

* **Fitness** — a file serves a command only when it carries the payload tables
  *and* the columns the shipped dashboards select. A metrics file from a run
  without ``--geo-ip`` has no ``SrcASN``/``SrcCity``/``SrcCountry``, and
  registering it would leave every Metrics chart failing at render time.
* **Ordering** — ``generated_at`` (when Suzaku ran) beats mtime (when the file
  was copied), and the path breaks a full tie so the choice is identical on
  every machine.
* **Reporting** — :func:`select` returns the runners-up and the rejects with
  reasons, so "the dashboard shows old numbers" is answerable.

This module is pure Python with no Streamlit dependency so it stays unit
testable, and ``docker/docker-compose.yml`` bind-mounts it into the
``superset-init`` container: ``dashboard/init/register_suzaku_dbs.py`` imports
it rather than carrying a second copy of the rules.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import duckdb

# Default directory the reader services mount the DuckDB files into. Suzaku
# files sit next to Senrigan's own threat_hunting.db.
DEFAULT_DB_DIR = Path("/data/db")

# Senrigan's own table. A file containing it is the ingester's output, never a
# Suzaku export, whatever its metadata claims.
SENRIGAN_TABLE = "cloudtrail_events"

# Where the ingester writes, and the fallback name. Both are skipped without
# being opened: that file can be tens of gigabytes and is never a candidate.
DEFAULT_SENRIGAN_DB_NAME = "threat_hunting.db"

# Extensions scanned. `.db` is included because the extension is the analyst's
# choice, not Suzaku's; Senrigan's own database is excluded by name and then a
# second time by table.
DB_SUFFIXES = (".duckdb", ".db")

# Suzaku's provenance table and the layout version Senrigan is written against
# (suzaku's src/core/duckdb_out.rs: SCHEMA_VERSION).
META_TABLE = "suzaku_meta"
SUPPORTED_SCHEMA_VERSION = 1

# GeoIP columns Suzaku writes only for a `--geo-ip` run. Named separately so a
# file missing exactly these gets an actionable message instead of a list.
GEO_COLUMNS = ("SrcASN", "SrcCity", "SrcCountry")


class SuzakuKind(str, Enum):
    """The Suzaku subcommand that produced a DuckDB file.

    The value is exactly what Suzaku writes to ``suzaku_meta.command``.
    """

    TIMELINE = "aws-ct-timeline"
    SUMMARY = "aws-ct-summary"
    METRICS = "aws-ct-metrics"


# Payload tables and the columns the shipped Superset datasets select from them
# (dashboard/assets/suzaku_*/datasets/*.yaml). A file missing any of these
# cannot serve its dashboard, so it is rejected at detection time rather than
# at chart render time.
#
# `suzaku_meta`'s own columns are deliberately not listed: they drive the
# provenance header only, and gating a whole run on them would reject files
# every data chart could read.
REQUIRED_COLUMNS: dict[SuzakuKind, dict[str, tuple[str, ...]]] = {
    SuzakuKind.TIMELINE: {
        "timeline": (
            "Timestamp",
            "RuleTitle",
            "RuleID",
            "RuleAuthor",
            "Level",
            "EventName",
            "EventSource",
            "AwsRegion",
            "ErrorCode",
            "ErrorMessage",
            "SrcIP",
            "UserAgent",
            "UserName",
            "UserType",
            "UserAccountID",
            "UserARN",
            "UserPrincipalID",
            "UserAccessKeyID",
            "EventID",
            "Tactics",
            "TechniqueIDs",
            "OtherTags",
        ),
    },
    SuzakuKind.SUMMARY: {
        "summary": (
            "UserARN",
            "UserTypes",
            "NumOfEvents",
            "FirstTimestamp",
            "LastTimestamp",
        ),
        "summary_api_calls": (
            "UserARN",
            "IsAbused",
            "Outcome",
            "API",
            "EventSource",
            "Description",
            "Count",
            "FirstSeen",
            "LastSeen",
        ),
        "summary_attributes": (
            "UserARN",
            "Attribute",
            "Value",
            "Count",
            "FirstSeen",
            "LastSeen",
        ),
    },
    SuzakuKind.METRICS: {
        "metrics": (
            "Field",
            "TimelineColumn",
            "Value",
            "Count",
            "FieldTotal",
            "Percent",
            "FirstSeen",
            "LastSeen",
            *GEO_COLUMNS,
        ),
    },
}

# Payload tables per kind, derived so the two can never disagree.
SUZAKU_TABLES: dict[SuzakuKind, tuple[str, ...]] = {
    kind: tuple(tables) for kind, tables in REQUIRED_COLUMNS.items()
}

# Environment variable pinning one file per kind, overriding discovery. Useful
# when several runs are kept side by side, and in tests.
ENV_OVERRIDES: dict[SuzakuKind, str] = {
    SuzakuKind.TIMELINE: "SUZAKU_TIMELINE_DB",
    SuzakuKind.SUMMARY: "SUZAKU_SUMMARY_DB",
    SuzakuKind.METRICS: "SUZAKU_METRICS_DB",
}

# Counters read from `suzaku_meta` when present. Older files predate them.
_META_COUNTERS = ("scanned_files", "scanned_events", "output_rows")

# Sort floor for a file whose meta row has no `generated_at`.
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class DbInfo:
    """What inspecting one candidate DuckDB file revealed.

    Attributes:
        path:            The inspected file.
        kind:            Suzaku command this file can actually serve, or None
                         when unrecognised or unfit.
        declared_kind:   Command ``suzaku_meta`` claims, regardless of fitness.
                         A file can declare a kind it cannot serve; the report
                         needs to name it under that kind anyway.
        tables:          ``{table_name: [column, ...]}`` as stored in the file.
        row_counts:      ``{table_name: rows}`` for the payload tables of *kind*.
        generated_at:    ``suzaku_meta.generated_at`` — when Suzaku ran.
        suzaku_version:  Version string from ``suzaku_meta``.
        scanned_files:   How many log files the run read, when recorded.
        scanned_events:  How many events the run read, when recorded.
        output_rows:     How many rows the run wrote, when recorded.
        mtime:           File modification time, the ordering fallback.
        missing_columns: Required columns the file does not have.
        reject_reason:   Why *declared_kind* is not *kind*, else "".
        is_senrigan:     True when this is the ingester's own database.
        error:           DuckDB's message when the file could not be read, else "".
        hint:            Operator-facing explanation of *error*, of a rejected
                         schema version, or of a stale WAL.
    """

    path: Path
    kind: SuzakuKind | None = None
    declared_kind: SuzakuKind | None = None
    tables: dict[str, list[str]] = field(default_factory=dict)
    row_counts: dict[str, int] = field(default_factory=dict)
    generated_at: datetime | None = None
    suzaku_version: str = ""
    scanned_files: int | None = None
    scanned_events: int | None = None
    output_rows: int | None = None
    mtime: float = 0.0
    missing_columns: tuple[str, ...] = ()
    reject_reason: str = ""
    is_senrigan: bool = False
    error: str = ""
    hint: str = ""

    @property
    def label(self) -> str:
        """Return a one-line description for a selectbox or a status line."""
        if self.error:
            return f"{self.path.name} — unreadable"
        kind = self.kind.value if self.kind else "unrecognised"
        rows = sum(self.row_counts.values())
        label = f"{self.path.name} — {kind} ({rows:,} rows)"
        if self.generated_at:
            label += f", generated {self.generated_at:%Y-%m-%d %H:%M}"
        return label


@dataclass(frozen=True)
class Selection:
    """The decision made for one Suzaku kind, with everything it passed over.

    Attributes:
        kind:     The command this decision is about.
        chosen:   The file that will be queried, or None when there is none.
        ignored:  Usable files that lost on ordering, best first.
        rejected: Files declaring *kind* that cannot serve it, with reasons.
        source:   ``"override"``, ``"discovery"`` or ``"none"``.
    """

    kind: SuzakuKind
    chosen: DbInfo | None = None
    ignored: tuple[DbInfo, ...] = ()
    rejected: tuple[DbInfo, ...] = ()
    source: str = "none"


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


def senrigan_db_name() -> str:
    """Return the file name of Senrigan's own database.

    Follows ``DUCKDB_PATH`` so a relocated database is still skipped by name
    rather than opened to find out what it is.
    """
    configured = os.environ.get("DUCKDB_PATH") or DEFAULT_SENRIGAN_DB_NAME
    return os.path.basename(configured)


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


def _read_meta(
    conn: duckdb.DuckDBPyConnection, meta_columns: list[str]
) -> dict[str, object]:
    """Return the ``suzaku_meta`` row as a dict, restricted to columns present.

    Suzaku added columns over time, so the projection is built from what the
    file actually has: asking for ``generated_at`` on an older export would
    fail the whole read.

    The read is deliberately in **two stages**. Only ``schema_version`` and
    ``command`` decide whether a file is usable; everything else is display.
    Reading them together once cost three healthy files their dashboards: the
    DuckDB Python client needs ``pytz`` to hand back a ``TIMESTAMP WITH TIME
    ZONE``, the agent image does not ship it, the whole projection raised, and
    the files reported "No suzaku_meta table". ``generated_at`` is therefore
    also cast to VARCHAR in SQL so no timezone-aware value ever crosses into
    Python, and a failure in the optional stage costs only the optional fields.

    Args:
        conn:         An open read-only connection.
        meta_columns: Column names of ``suzaku_meta`` in this file.

    Returns:
        ``{}`` when the table is missing, empty, or does not identify a
        command — which is what any DuckDB file that is not Suzaku output
        looks like.
    """
    essential = [name for name in ("schema_version", "command") if name in meta_columns]
    if "command" not in essential:
        return {}

    projection = ", ".join(f'"{name}"' for name in essential)
    try:
        row = conn.execute(f"SELECT {projection} FROM {META_TABLE} LIMIT 1").fetchone()
    except duckdb.Error:
        return {}
    if not row:
        return {}
    meta: dict[str, object] = dict(zip(essential, row))

    # Optional, best-effort: never let a display field decide detection.
    optional = [
        name
        for name in ("suzaku_version", "generated_at", *_META_COUNTERS)
        if name in meta_columns
    ]
    if not optional:
        return meta

    projection = ", ".join(
        f'CAST("{name}" AS VARCHAR)' if name == "generated_at" else f'"{name}"'
        for name in optional
    )
    try:
        row = conn.execute(f"SELECT {projection} FROM {META_TABLE} LIMIT 1").fetchone()
    except duckdb.Error:
        return meta
    if row:
        meta.update(dict(zip(optional, row)))
    return meta


def _as_utc(value: object) -> datetime | None:
    """Return *value* as a UTC datetime, or None.

    Accepts what DuckDB hands back for a cast ``TIMESTAMP WITH TIME ZONE`` —
    a string whose offset is rendered as ``+09``, not ``+09:00`` — as well as a
    real datetime. A hand-rebuilt file may carry a naive timestamp; comparing
    naive and aware values raises, so naive ones are read as UTC.

    The result is converted to UTC, not merely made aware: DuckDB renders that
    cast in the session's timezone, so the same file reads ``+09`` in Tokyo and
    ``-07`` in California, and reports print the value verbatim. Ordering is
    unaffected either way — display is what would otherwise disagree.

    Args:
        value: The raw ``generated_at``.

    Returns:
        A UTC datetime, or ``None`` when there is nothing usable. Never
        raises: ordering falls back to mtime rather than refusing the file.
    """
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.strip())
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _as_int(value: object) -> int | None:
    """Return *value* as an int when it is numeric, else None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


def _missing_columns(kind: SuzakuKind, tables: dict[str, list[str]]) -> tuple[str, ...]:
    """Return the required columns *kind* needs that *tables* does not have.

    Comparison is case-insensitive: DuckDB preserves the case Suzaku wrote, and
    a rebuilt file may differ.

    Args:
        kind:   The command the file declares.
        tables: ``{table_name: [column, ...]}`` describing the file.

    Returns:
        Missing columns as ``table.column``, in declaration order.
    """
    present = {
        name.lower(): {column.lower() for column in columns}
        for name, columns in tables.items()
    }
    missing: list[str] = []
    for table, columns in REQUIRED_COLUMNS[kind].items():
        available = present.get(table.lower())
        if available is None:
            missing.append(f"{table} (table)")
            continue
        missing.extend(
            f"{table}.{column}" for column in columns if column.lower() not in available
        )
    return tuple(missing)


def _reject_reason(kind: SuzakuKind, missing: tuple[str, ...]) -> str:
    """Explain, in one line, why a file declaring *kind* cannot serve it."""
    geo = {f"metrics.{column}".lower() for column in GEO_COLUMNS}
    if kind is SuzakuKind.METRICS and {name.lower() for name in missing} == geo:
        return (
            f"missing {', '.join(GEO_COLUMNS)} — re-run Suzaku with --geo-ip, "
            "which is what the Metrics dashboard charts"
        )
    tables_missing = [name for name in missing if name.endswith(" (table)")]
    if tables_missing:
        listed = ", ".join(name.removesuffix(" (table)") for name in tables_missing)
        return f"declares {kind.value} but has no {listed} table"
    return f"missing columns {', '.join(missing)}"


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

    mtime = path.stat().st_mtime

    try:
        conn = duckdb.connect(str(path), read_only=True)
    except Exception as exc:  # noqa: BLE001 — any open failure must be reported
        message = str(exc)
        return DbInfo(
            path=path,
            mtime=mtime,
            error=message,
            hint=_wal_hint(path) or _error_hint(message),
        )

    try:
        rows = conn.execute(
            "SELECT table_name, column_name FROM information_schema.columns "
            "WHERE table_schema = 'main' ORDER BY table_name, ordinal_position"
        ).fetchall()
        tables: dict[str, list[str]] = {}
        for table_name, column_name in rows:
            tables.setdefault(table_name, []).append(column_name)

        meta = _read_meta(conn, tables.get(META_TABLE, []))
        version = _as_int(meta.get("schema_version"))
        declared = detect_kind(meta.get("command"))  # type: ignore[arg-type]
        kind = declared
        hint = _wal_hint(path)
        reject_reason = ""
        missing: tuple[str, ...] = ()
        is_senrigan = any(name.lower() == SENRIGAN_TABLE for name in tables)

        if is_senrigan:
            # Senrigan's own database can never be a Suzaku export.
            kind = declared = None
        elif version is None:
            kind = declared = None
            hint = hint or (
                f"No {META_TABLE} table. Senrigan reads Suzaku output from "
                "schema_version 1 onwards — re-export with a current Suzaku."
            )
        elif version > SUPPORTED_SCHEMA_VERSION:
            kind = None
            reject_reason = (
                f"declares schema_version {version}; Senrigan reads up to "
                f"{SUPPORTED_SCHEMA_VERSION}"
            )
            hint = (
                f"This file declares schema_version {version}; Senrigan reads "
                f"up to {SUPPORTED_SCHEMA_VERSION}. Upgrade Senrigan rather "
                "than risk misreading the columns."
            )
        elif kind is not None:
            missing = _missing_columns(kind, tables)
            if missing:
                reject_reason = _reject_reason(kind, missing)
                hint = hint or reject_reason
                kind = None

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
        return DbInfo(path=path, mtime=mtime, error=message, hint=_error_hint(message))
    finally:
        conn.close()

    return DbInfo(
        path=path,
        kind=kind,
        declared_kind=declared,
        tables=tables,
        row_counts=row_counts,
        generated_at=_as_utc(meta.get("generated_at")),
        suzaku_version=str(meta.get("suzaku_version") or ""),
        scanned_files=_as_int(meta.get("scanned_files")),
        scanned_events=_as_int(meta.get("scanned_events")),
        output_rows=_as_int(meta.get("output_rows")),
        mtime=mtime,
        missing_columns=missing,
        reject_reason=reject_reason,
        is_senrigan=is_senrigan,
        hint=hint,
    )


def sort_inventory(infos: list[DbInfo]) -> list[DbInfo]:
    """Order candidates best-first, deterministically.

    ``generated_at`` — when Suzaku ran — comes first, because mtime records
    only when the file was copied and ``cp`` rewrites it while ``rsync -a``
    does not. mtime breaks a tie between two exports of one run, and the path
    breaks a full tie so every machine picks the same file.

    Args:
        infos: Candidates to order, mutated in place.

    Returns:
        *infos*, sorted.
    """
    # Two stable passes: the ascending name sort survives as the tie-break of
    # the descending sort that follows.
    infos.sort(key=lambda info: info.path.name)
    infos.sort(key=lambda info: (info.generated_at or _EPOCH, info.mtime), reverse=True)
    return infos


def discover(directory: Path | str = DEFAULT_DB_DIR) -> list[DbInfo]:
    """Inspect every candidate DuckDB file in *directory*, best first.

    Each file is opened exactly once. Senrigan's own database is skipped by
    name before it is opened, and any other file holding ``cloudtrail_events``
    is dropped after inspection.

    Args:
        directory: Directory to scan. A missing directory yields ``[]``.

    Returns:
        One :class:`DbInfo` per candidate file, ordered by :func:`sort_inventory`.
    """
    directory = Path(directory)
    if not directory.is_dir():
        return []

    skip = {senrigan_db_name(), DEFAULT_SENRIGAN_DB_NAME}
    candidates = sorted(
        path
        for path in directory.iterdir()
        if path.suffix in DB_SUFFIXES and path.name not in skip and path.is_file()
    )
    infos = [inspect_db(path) for path in candidates]
    return sort_inventory([info for info in infos if not info.is_senrigan])


def select(
    directory: Path | str = DEFAULT_DB_DIR,
    inventory: list[DbInfo] | None = None,
) -> dict[SuzakuKind, Selection]:
    """Decide which file serves each kind, and record what was passed over.

    Every kind is present in the result, so a caller can report "no usable
    file" as explicitly as it reports a choice.

    Args:
        directory: Directory to scan when *inventory* is not supplied.
        inventory: A scan produced earlier — by :func:`discover` or restored
                   with :func:`inventory_from_json` — so one scan can serve
                   several consumers.

    Returns:
        ``{kind: Selection}`` for every :class:`SuzakuKind`.
    """
    infos = list(inventory) if inventory is not None else discover(directory)

    selections: dict[SuzakuKind, Selection] = {}
    for kind in SuzakuKind:
        candidates = [info for info in infos if info.declared_kind is kind]
        fit = [info for info in candidates if info.kind is kind]
        rejected = tuple(info for info in candidates if info.kind is not kind)

        chosen = fit[0] if fit else None
        ignored = fit[1:]
        source = "discovery" if chosen else "none"

        override = os.environ.get(ENV_OVERRIDES[kind])
        if override:
            pinned = inspect_db(Path(override))
            if pinned.kind is kind:
                chosen = pinned
                ignored = [info for info in fit if info.path != pinned.path]
                source = "override"

        selections[kind] = Selection(
            kind=kind,
            chosen=chosen,
            ignored=tuple(ignored),
            rejected=rejected,
            source=source,
        )
    return selections


def find_db(kind: SuzakuKind, directory: Path | str = DEFAULT_DB_DIR) -> DbInfo | None:
    """Return the database to use for *kind*, or ``None`` when there is none.

    An existing ``SUZAKU_*_DB`` environment override wins over discovery. A
    stale override — one naming a file that is gone, is unfit, or is of another
    kind — falls back to discovery rather than hiding a usable database.

    Args:
        kind:      The Suzaku kind wanted.
        directory: Directory to scan when no override applies.

    Returns:
        The matching :class:`DbInfo`, or ``None``.
    """
    return select(directory)[kind].chosen


# ---------------------------------------------------------------------------
# Inventory serialization — one scan, several processes
# ---------------------------------------------------------------------------


def _info_to_dict(info: DbInfo) -> dict:
    """Return *info* as JSON-safe primitives."""
    return {
        "path": str(info.path),
        "kind": info.kind.value if info.kind else None,
        "declared_kind": info.declared_kind.value if info.declared_kind else None,
        "tables": info.tables,
        "row_counts": info.row_counts,
        "generated_at": (info.generated_at.isoformat() if info.generated_at else None),
        "suzaku_version": info.suzaku_version,
        "scanned_files": info.scanned_files,
        "scanned_events": info.scanned_events,
        "output_rows": info.output_rows,
        "mtime": info.mtime,
        "missing_columns": list(info.missing_columns),
        "reject_reason": info.reject_reason,
        "is_senrigan": info.is_senrigan,
        "error": info.error,
        "hint": info.hint,
    }


def _info_from_dict(payload: dict) -> DbInfo:
    """Rebuild a :class:`DbInfo` from :func:`_info_to_dict` output."""
    generated_at = payload.get("generated_at")
    return DbInfo(
        path=Path(payload["path"]),
        kind=SuzakuKind(payload["kind"]) if payload.get("kind") else None,
        declared_kind=(
            SuzakuKind(payload["declared_kind"])
            if payload.get("declared_kind")
            else None
        ),
        tables=payload.get("tables", {}),
        row_counts=payload.get("row_counts", {}),
        generated_at=datetime.fromisoformat(generated_at) if generated_at else None,
        suzaku_version=payload.get("suzaku_version", ""),
        scanned_files=payload.get("scanned_files"),
        scanned_events=payload.get("scanned_events"),
        output_rows=payload.get("output_rows"),
        mtime=payload.get("mtime", 0.0),
        missing_columns=tuple(payload.get("missing_columns", ())),
        reject_reason=payload.get("reject_reason", ""),
        is_senrigan=payload.get("is_senrigan", False),
        error=payload.get("error", ""),
        hint=payload.get("hint", ""),
    )


def inventory_to_json(infos: list[DbInfo]) -> str:
    """Serialize a scan so another process can select from it without rescanning.

    Args:
        infos: The result of :func:`discover`.

    Returns:
        A JSON document carrying its schema version, for
        :func:`inventory_from_json`.
    """
    payload = {
        "inventory_version": 1,
        "databases": [_info_to_dict(info) for info in infos],
    }
    return json.dumps(payload, indent=2)


def inventory_from_json(document: str) -> list[DbInfo]:
    """Rebuild a scan produced by :func:`inventory_to_json`.

    Args:
        document: JSON as written by :func:`inventory_to_json`.

    Returns:
        The candidates, in the order they were serialized.

    Raises:
        ValueError: When the document is not an inventory this release reads.
    """
    payload = json.loads(document)
    if payload.get("inventory_version") != 1:
        raise ValueError(
            f"unsupported inventory_version {payload.get('inventory_version')!r}"
        )
    return [_info_from_dict(entry) for entry in payload.get("databases", [])]
