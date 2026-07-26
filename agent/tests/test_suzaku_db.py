"""Tests for Suzaku DuckDB discovery and schema-based kind detection.

Covers PLAN_SUZAKU_VIEWS.md §2.4 and §4.5 (tests 1-10). Suzaku output files carry
no metadata table, so the producing command has to be inferred from the schema —
see doc/PLAN_SUZAKU_SCHEMA.md P1 for the upstream proposal that would make this
a lookup instead of a heuristic.
"""

from __future__ import annotations

import os
from pathlib import Path

import duckdb
import pytest

from suzaku_db import (
    ENV_OVERRIDES,
    SUZAKU_SIGNATURES,
    DbInfo,
    SuzakuKind,
    detect_kinds,
    discover,
    find_db,
    inspect_db,
)

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "sample" / "suzaku" / "fixtures"

TIMELINE_TABLES = {
    "timeline": [
        "Timestamp",
        "RuleTitle",
        "RuleAuthor",
        "Level",
        "EventName",
        "RuleID",
    ]
}
SUMMARY_TABLES = {
    "summary": ["UserARN", "NumOfEvents", "FirstTimestamp", "LastTimestamp"],
    "summary_api_calls": ["UserARN", "Category", "API", "Count", "FirstSeen"],
    "summary_attributes": ["UserARN", "Attribute", "Value", "Count"],
}
METRICS_TABLES = {
    "metrics": ["Field", "Value", "Count", "Percent", "FirstSeen", "LastSeen"]
}


def _make_db(path: Path, tables: dict[str, list[str]]) -> Path:
    """Create a DuckDB file with *tables* as empty VARCHAR/BIGINT columns.

    Only the schema matters for detection, so the tables stay empty — this keeps
    signature tests in the millisecond range instead of loading a fixture.
    """
    conn = duckdb.connect(str(path))
    try:
        for table, columns in tables.items():
            column_defs = ", ".join(
                f'"{column}" {"BIGINT" if column in ("Count", "NumOfEvents") else "VARCHAR"}'
                for column in columns
            )
            conn.execute(f'CREATE TABLE "{table}" ({column_defs})')
    finally:
        conn.close()
    return path


# ---------------------------------------------------------------------------
# detect_kinds — pure signature matching (tests 1-7)
# ---------------------------------------------------------------------------


def test_detects_timeline_signature() -> None:
    """Test 1: the timeline table alone identifies aws-ct-timeline."""
    assert detect_kinds(TIMELINE_TABLES) == {SuzakuKind.TIMELINE}


def test_detects_summary_only_with_all_three_tables() -> None:
    """Test 2: a partial summary export must not be claimed as aws-ct-summary."""
    assert detect_kinds(SUMMARY_TABLES) == {SuzakuKind.SUMMARY}

    partial = {
        name: columns
        for name, columns in SUMMARY_TABLES.items()
        if name != "summary_attributes"
    }
    assert detect_kinds(partial) == set()


def test_detects_metrics_signature() -> None:
    """Test 3: the metrics table identifies aws-ct-metrics."""
    assert detect_kinds(METRICS_TABLES) == {SuzakuKind.METRICS}


def test_extra_tables_and_columns_still_match() -> None:
    """Test 4: forward compatibility — a future Suzaku may add either."""
    extended = {
        "timeline": TIMELINE_TABLES["timeline"] + ["SrcCountry", "TechniqueIDs"],
        "suzaku_meta": ["schema_version", "command"],
    }
    assert detect_kinds(extended) == {SuzakuKind.TIMELINE}


def test_column_matching_is_case_insensitive() -> None:
    """Test 5a: DuckDB identifiers are case-insensitive, so detection is too."""
    lowered = {"TIMELINE": [column.lower() for column in TIMELINE_TABLES["timeline"]]}
    assert detect_kinds(lowered) == {SuzakuKind.TIMELINE}


def test_missing_required_column_is_unknown() -> None:
    """Test 5b: a table named `timeline` without Level is not a Suzaku timeline."""
    without_level = {
        "timeline": [c for c in TIMELINE_TABLES["timeline"] if c != "Level"]
    }
    assert detect_kinds(without_level) == set()


def test_senrigan_database_is_never_a_suzaku_kind() -> None:
    """Test 6: cloudtrail_events means this is Senrigan's own database."""
    senrigan = {**TIMELINE_TABLES, "cloudtrail_events": ["event_time", "event_name"]}
    assert detect_kinds(senrigan) == set()


def test_multiple_kinds_in_one_file() -> None:
    """Test 7: a combined export reports every kind it contains."""
    combined = {**TIMELINE_TABLES, **METRICS_TABLES}
    assert detect_kinds(combined) == {SuzakuKind.TIMELINE, SuzakuKind.METRICS}


def test_signature_table_covers_every_kind() -> None:
    """Every enum member needs a signature, or detection silently ignores it."""
    assert set(SUZAKU_SIGNATURES) == set(SuzakuKind)
    assert set(ENV_OVERRIDES) == set(SuzakuKind)


# ---------------------------------------------------------------------------
# inspect_db — reading a real file (test 8)
# ---------------------------------------------------------------------------


def test_inspect_db_on_broken_file_reports_error(tmp_path: Path) -> None:
    """Test 8: a non-DuckDB file yields an error, never an exception."""
    broken = tmp_path / "not-a-database.duckdb"
    broken.write_text("this is not a DuckDB file", encoding="utf-8")

    info = inspect_db(broken)

    assert isinstance(info, DbInfo)
    assert info.error
    assert info.kinds == set()
    assert info.hint  # operator-facing explanation


def test_inspect_db_on_missing_file_reports_error(tmp_path: Path) -> None:
    """A path that no longer exists is an operator mistake, not a crash."""
    info = inspect_db(tmp_path / "absent.duckdb")
    assert info.error
    assert info.kinds == set()


def test_inspect_db_flags_an_uncheckpointed_wal(tmp_path: Path) -> None:
    """A stale .wal cannot be replayed from a read-only mount — say so."""
    db = _make_db(tmp_path / "timeline.duckdb", TIMELINE_TABLES)
    (tmp_path / "timeline.duckdb.wal").write_bytes(b"\x00")

    info = inspect_db(db)

    assert "wal" in info.hint.lower()


def test_inspect_db_reads_tables_and_row_counts(tmp_path: Path) -> None:
    """The UI shows row counts, so inspect_db must collect them."""
    db = _make_db(tmp_path / "timeline.duckdb", TIMELINE_TABLES)
    conn = duckdb.connect(str(db))
    conn.execute(
        "INSERT INTO timeline VALUES "
        "('2024-01-01 00:00:00', 'Rule', 'Author', 'high', 'RunInstances', 'rid')"
    )
    conn.close()

    info = inspect_db(db)

    assert info.kinds == {SuzakuKind.TIMELINE}
    assert info.tables["timeline"]
    assert info.row_counts["timeline"] == 1
    assert not info.error


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
    """The signatures must match real Suzaku output, not just synthetic tables."""
    info = inspect_db(FIXTURE_DIR / fixture_name)
    assert info.kinds == {kind}, info.error


# ---------------------------------------------------------------------------
# discover / find_db (tests 9-10)
# ---------------------------------------------------------------------------


def test_discover_only_globs_duckdb_files(tmp_path: Path) -> None:
    """Test 9a: Senrigan's own threat_hunting.db must never be scanned."""
    _make_db(tmp_path / "timeline.duckdb", TIMELINE_TABLES)
    _make_db(tmp_path / "threat_hunting.db", {"cloudtrail_events": ["event_time"]})
    (tmp_path / "notes.txt").write_text("ignored", encoding="utf-8")

    found = discover(tmp_path)

    assert [info.path.name for info in found] == ["timeline.duckdb"]


def test_discover_orders_newest_first(tmp_path: Path) -> None:
    """Test 9b: re-running Suzaku should surface the newer file first."""
    older = _make_db(tmp_path / "older.duckdb", TIMELINE_TABLES)
    newer = _make_db(tmp_path / "newer.duckdb", TIMELINE_TABLES)
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
    older = _make_db(tmp_path / "a.duckdb", TIMELINE_TABLES)
    newer = _make_db(tmp_path / "b.duckdb", TIMELINE_TABLES)
    os.utime(older, (1_000_000, 1_000_000))
    os.utime(newer, (2_000_000, 2_000_000))

    found = find_db(SuzakuKind.TIMELINE, tmp_path)

    assert found is not None
    assert found.path.name == "b.duckdb"


def test_find_db_returns_none_when_kind_absent(tmp_path: Path) -> None:
    """A metrics-only directory has no timeline DB."""
    _make_db(tmp_path / "metrics.duckdb", METRICS_TABLES)
    assert find_db(SuzakuKind.TIMELINE, tmp_path) is None


def test_env_override_takes_precedence(tmp_path: Path, monkeypatch) -> None:
    """Test 10: SUZAKU_TIMELINE_DB pins one file regardless of mtime order."""
    pinned = _make_db(tmp_path / "pinned.duckdb", TIMELINE_TABLES)
    newer = _make_db(tmp_path / "newer.duckdb", TIMELINE_TABLES)
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
    discovered = _make_db(tmp_path / "found.duckdb", TIMELINE_TABLES)
    monkeypatch.setenv(
        ENV_OVERRIDES[SuzakuKind.TIMELINE], str(tmp_path / "absent.duckdb")
    )

    found = find_db(SuzakuKind.TIMELINE, tmp_path)

    assert found is not None
    assert found.path == discovered
