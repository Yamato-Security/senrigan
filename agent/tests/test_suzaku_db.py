"""Tests for Suzaku DuckDB discovery and metadata-based kind detection.

Covers PLAN_SUZAKU_VIEWS.md §2.4 and §4.5. Since Suzaku schema_version 1 every
output file carries a ``suzaku_meta`` table naming the command that wrote it, so
the producing command is read rather than inferred from a table signature —
see doc/PLAN_SUZAKU_SCHEMA.md P1.
"""

from __future__ import annotations

import os
from pathlib import Path

import duckdb
import pytest

from suzaku_db import (
    ENV_OVERRIDES,
    META_TABLE,
    SUPPORTED_SCHEMA_VERSION,
    SUZAKU_TABLES,
    DbInfo,
    SuzakuKind,
    detect_kind,
    discover,
    find_db,
    inspect_db,
)

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "sample" / "suzaku" / "fixtures"

# Minimal payload tables per command — only enough for row counts to be non-zero.
PAYLOAD_TABLES: dict[SuzakuKind, dict[str, list[str]]] = {
    SuzakuKind.TIMELINE: {"timeline": ["Timestamp", "RuleTitle", "Level"]},
    SuzakuKind.SUMMARY: {
        "summary": ["UserARN", "NumOfEvents"],
        "summary_api_calls": ["UserARN", "API"],
        "summary_attributes": ["UserARN", "Attribute"],
    },
    SuzakuKind.METRICS: {"metrics": ["Field", "Value"]},
}


def _make_db(
    path: Path,
    kind: SuzakuKind | None,
    *,
    schema_version: int = SUPPORTED_SCHEMA_VERSION,
    command: str | None = None,
    tables: dict[str, list[str]] | None = None,
) -> Path:
    """Create a DuckDB file shaped like one Suzaku output file.

    Only ``suzaku_meta`` drives detection, so the payload tables stay empty
    VARCHAR columns; that keeps these tests in the millisecond range.

    Args:
        path:           File to create.
        kind:           Command to record, or ``None`` to omit ``suzaku_meta``.
        schema_version: Value to write into ``suzaku_meta.schema_version``.
        command:        Overrides the command string written for *kind*.
        tables:         Payload tables, defaulting to *kind*'s own.

    Returns:
        *path*, for chaining.
    """
    if tables is None:
        tables = PAYLOAD_TABLES[kind] if kind else {}
    conn = duckdb.connect(str(path))
    try:
        for table, columns in tables.items():
            column_defs = ", ".join(f'"{column}" VARCHAR' for column in columns)
            conn.execute(f'CREATE TABLE "{table}" ({column_defs})')
        if kind is not None or command is not None:
            conn.execute(
                f"CREATE TABLE {META_TABLE} "
                "(schema_version INTEGER, suzaku_version VARCHAR, command VARCHAR)"
            )
            conn.execute(
                f"INSERT INTO {META_TABLE} VALUES (?, '2.0.0', ?)",
                [schema_version, command or (kind.value if kind else "")],
            )
    finally:
        conn.close()
    return path


# ---------------------------------------------------------------------------
# detect_kind — pure command mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", list(SuzakuKind))
def test_every_command_maps_to_its_kind(kind: SuzakuKind) -> None:
    """The command string Suzaku writes is the kind's own value."""
    assert detect_kind(kind.value) is kind


def test_command_matching_is_case_insensitive_and_trimmed() -> None:
    """A hand-edited meta row must not defeat detection on whitespace alone."""
    assert detect_kind("  AWS-CT-Timeline ") is SuzakuKind.TIMELINE


def test_unknown_command_is_none() -> None:
    """An Azure command, or a future one, is simply not readable here yet."""
    assert detect_kind("azure-timeline") is None
    assert detect_kind(None) is None
    assert detect_kind("") is None


def test_table_map_covers_every_kind() -> None:
    """A kind without tables would report zero rows for a healthy file."""
    assert set(SUZAKU_TABLES) == set(SuzakuKind)
    assert set(ENV_OVERRIDES) == set(SuzakuKind)


# ---------------------------------------------------------------------------
# inspect_db — reading a real file
# ---------------------------------------------------------------------------


def test_inspect_db_on_broken_file_reports_error(tmp_path: Path) -> None:
    """A non-DuckDB file yields an error, never an exception."""
    broken = tmp_path / "not-a-database.duckdb"
    broken.write_text("this is not a DuckDB file", encoding="utf-8")

    info = inspect_db(broken)

    assert isinstance(info, DbInfo)
    assert info.error
    assert info.kind is None
    assert info.hint  # operator-facing explanation


def test_inspect_db_on_missing_file_reports_error(tmp_path: Path) -> None:
    """A path that no longer exists is an operator mistake, not a crash."""
    info = inspect_db(tmp_path / "absent.duckdb")
    assert info.error
    assert info.kind is None


def test_inspect_db_flags_an_uncheckpointed_wal(tmp_path: Path) -> None:
    """A stale .wal cannot be replayed from a read-only mount — say so."""
    db = _make_db(tmp_path / "timeline.duckdb", SuzakuKind.TIMELINE)
    (tmp_path / "timeline.duckdb.wal").write_bytes(b"\x00")

    info = inspect_db(db)

    assert "wal" in info.hint.lower()


def test_file_without_suzaku_meta_is_unrecognised(tmp_path: Path) -> None:
    """Pre-schema_version-1 output, and any other DuckDB file, is not readable."""
    db = _make_db(
        tmp_path / "legacy.duckdb",
        None,
        tables={"timeline": ["Timestamp", "RuleTitle", "Level"]},
    )

    info = inspect_db(db)

    assert info.kind is None
    assert not info.error
    assert "suzaku_meta" in info.hint


def test_newer_schema_version_is_refused_with_a_hint(tmp_path: Path) -> None:
    """schema_version exists so a consumer can refuse what it cannot read."""
    db = _make_db(
        tmp_path / "future.duckdb",
        SuzakuKind.TIMELINE,
        schema_version=SUPPORTED_SCHEMA_VERSION + 1,
    )

    info = inspect_db(db)

    assert info.kind is None
    assert str(SUPPORTED_SCHEMA_VERSION + 1) in info.hint
    assert "senrigan" in info.hint.lower()


def test_senrigan_database_is_never_a_suzaku_kind(tmp_path: Path) -> None:
    """cloudtrail_events means this is Senrigan's own database."""
    db = _make_db(
        tmp_path / "mixed.duckdb",
        SuzakuKind.TIMELINE,
        tables={
            "timeline": ["Timestamp"],
            "cloudtrail_events": ["event_time", "event_name"],
        },
    )

    assert inspect_db(db).kind is None


def test_inspect_db_reads_tables_and_row_counts(tmp_path: Path) -> None:
    """The UI shows row counts, so inspect_db must collect them."""
    db = _make_db(tmp_path / "timeline.duckdb", SuzakuKind.TIMELINE)
    conn = duckdb.connect(str(db))
    conn.execute("INSERT INTO timeline VALUES ('2024-01-01 00:00:00', 'Rule', 'high')")
    conn.close()

    info = inspect_db(db)

    assert info.kind is SuzakuKind.TIMELINE
    assert info.tables["timeline"]
    assert info.row_counts["timeline"] == 1
    assert not info.error


def test_label_names_the_command_and_row_count(tmp_path: Path) -> None:
    """The selectbox label is all an analyst sees before picking a file."""
    db = _make_db(tmp_path / "metrics.duckdb", SuzakuKind.METRICS)

    label = inspect_db(db).label

    assert "metrics.duckdb" in label
    assert SuzakuKind.METRICS.value in label


@pytest.mark.parametrize(
    ("fixture_name", "kind"),
    [
        ("suzaku-aws-ct-timeline.duckdb", SuzakuKind.TIMELINE),
        ("suzaku-aws-ct-summary.duckdb", SuzakuKind.SUMMARY),
        ("suzaku-aws-ct-metrics.duckdb", SuzakuKind.METRICS),
    ],
)
def test_inspect_db_classifies_real_fixtures(
    fixture_name: str, kind: SuzakuKind
) -> None:
    """Detection must work on real Suzaku output, not just synthetic tables."""
    info = inspect_db(FIXTURE_DIR / fixture_name)
    assert info.kind is kind, info.error
    assert info.row_counts, "signature tables must be counted"


def test_fixtures_are_at_the_supported_schema_version() -> None:
    """A fixture ahead of SUPPORTED_SCHEMA_VERSION would silently skip tests."""
    for fixture in sorted(FIXTURE_DIR.glob("*.duckdb")):
        conn = duckdb.connect(str(fixture), read_only=True)
        try:
            (version,) = conn.execute(
                f"SELECT schema_version FROM {META_TABLE}"
            ).fetchone()
        finally:
            conn.close()
        assert version == SUPPORTED_SCHEMA_VERSION, fixture.name


# ---------------------------------------------------------------------------
# discover / find_db
# ---------------------------------------------------------------------------


def test_discover_only_globs_duckdb_files(tmp_path: Path) -> None:
    """Senrigan's own threat_hunting.db must never be scanned."""
    _make_db(tmp_path / "timeline.duckdb", SuzakuKind.TIMELINE)
    _make_db(tmp_path / "threat_hunting.db", None, tables={"cloudtrail_events": ["id"]})
    (tmp_path / "notes.txt").write_text("ignored", encoding="utf-8")

    found = discover(tmp_path)

    assert [info.path.name for info in found] == ["timeline.duckdb"]


def test_discover_orders_newest_first(tmp_path: Path) -> None:
    """Re-running Suzaku should surface the newer file first."""
    older = _make_db(tmp_path / "older.duckdb", SuzakuKind.TIMELINE)
    newer = _make_db(tmp_path / "newer.duckdb", SuzakuKind.TIMELINE)
    os.utime(older, (1_000_000, 1_000_000))
    os.utime(newer, (2_000_000, 2_000_000))

    assert [info.path.name for info in discover(tmp_path)] == [
        "newer.duckdb",
        "older.duckdb",
    ]


def test_discover_on_missing_directory_is_empty(tmp_path: Path) -> None:
    """An absent /data/db is an empty result, not an error."""
    assert discover(tmp_path / "nope") == []


def test_find_db_returns_newest_matching_kind(tmp_path: Path) -> None:
    """With several files of one kind, the newest wins."""
    older = _make_db(tmp_path / "a.duckdb", SuzakuKind.TIMELINE)
    newer = _make_db(tmp_path / "b.duckdb", SuzakuKind.TIMELINE)
    os.utime(older, (1_000_000, 1_000_000))
    os.utime(newer, (2_000_000, 2_000_000))

    found = find_db(SuzakuKind.TIMELINE, tmp_path)

    assert found is not None
    assert found.path.name == "b.duckdb"


def test_find_db_returns_none_when_kind_absent(tmp_path: Path) -> None:
    """A metrics-only directory has no timeline DB."""
    _make_db(tmp_path / "metrics.duckdb", SuzakuKind.METRICS)
    assert find_db(SuzakuKind.TIMELINE, tmp_path) is None


def test_env_override_takes_precedence(tmp_path: Path, monkeypatch) -> None:
    """SUZAKU_TIMELINE_DB pins one file regardless of mtime order."""
    pinned = _make_db(tmp_path / "pinned.duckdb", SuzakuKind.TIMELINE)
    newer = _make_db(tmp_path / "newer.duckdb", SuzakuKind.TIMELINE)
    os.utime(pinned, (1_000_000, 1_000_000))
    os.utime(newer, (2_000_000, 2_000_000))
    monkeypatch.setenv(ENV_OVERRIDES[SuzakuKind.TIMELINE], str(pinned))

    found = find_db(SuzakuKind.TIMELINE, tmp_path)

    assert found is not None
    assert found.path.name == "pinned.duckdb"


def test_env_override_pointing_at_a_missing_file_falls_back(
    tmp_path: Path, monkeypatch
) -> None:
    """A stale override must not hide a perfectly good discovered database."""
    discovered = _make_db(tmp_path / "found.duckdb", SuzakuKind.TIMELINE)
    monkeypatch.setenv(
        ENV_OVERRIDES[SuzakuKind.TIMELINE], str(tmp_path / "absent.duckdb")
    )

    found = find_db(SuzakuKind.TIMELINE, tmp_path)

    assert found is not None
    assert found.path == discovered
