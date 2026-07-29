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
    REQUIRED_COLUMNS,
    SUPPORTED_SCHEMA_VERSION,
    SUZAKU_TABLES,
    DbInfo,
    SuzakuKind,
    detect_kind,
    discover,
    find_db,
    inspect_db,
    inventory_from_json,
    inventory_to_json,
    select,
)

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "sample" / "suzaku" / "fixtures"

# Payload tables per command, taken from the module's own fitness contract so a
# synthetic file is shaped like one a dashboard could actually query.
PAYLOAD_TABLES: dict[SuzakuKind, dict[str, list[str]]] = {
    kind: {table: list(columns) for table, columns in tables.items()}
    for kind, tables in REQUIRED_COLUMNS.items()
}


def _make_db(
    path: Path,
    kind: SuzakuKind | None,
    *,
    schema_version: int = SUPPORTED_SCHEMA_VERSION,
    command: str | None = None,
    tables: dict[str, list[str]] | None = None,
    generated_at: str | None = None,
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
        generated_at:   Timestamp to record, or ``None`` to omit the column —
                        which is what a pre-``generated_at`` file looks like.

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
            extra_column = ", generated_at TIMESTAMP WITH TIME ZONE"
            conn.execute(
                f"CREATE TABLE {META_TABLE} "
                "(schema_version INTEGER, suzaku_version VARCHAR, command VARCHAR"
                f"{extra_column if generated_at else ''})"
            )
            values = [schema_version, command or (kind.value if kind else "")]
            placeholders = "?, '2.0.0', ?"
            if generated_at:
                placeholders += ", ?"
                values.append(generated_at)
            conn.execute(f"INSERT INTO {META_TABLE} VALUES ({placeholders})", values)
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
    conn.execute(
        'INSERT INTO timeline ("Timestamp", "RuleTitle", "Level") '
        "VALUES ('2024-01-01 00:00:00', 'Rule', 'high')"
    )
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


# ---------------------------------------------------------------------------
# Provenance — PLAN_SUZAKU_MULTI_DB.md Phase 0
# ---------------------------------------------------------------------------


def test_inspect_db_reads_generated_at(tmp_path: Path) -> None:
    """`generated_at` is when Suzaku ran — the only honest ordering key."""
    db = _make_db(
        tmp_path / "timeline.duckdb",
        SuzakuKind.TIMELINE,
        generated_at="2026-07-28 07:32:13+09:00",
    )

    info = inspect_db(db)

    assert info.generated_at is not None
    assert info.generated_at.year == 2026
    assert info.suzaku_version == "2.0.0"


def test_inspect_db_without_generated_at_is_not_an_error(tmp_path: Path) -> None:
    """An older meta row simply has no timestamp; that must not fail detection."""
    db = _make_db(tmp_path / "timeline.duckdb", SuzakuKind.TIMELINE)

    info = inspect_db(db)

    assert info.kind is SuzakuKind.TIMELINE
    assert info.generated_at is None
    assert not info.error


def test_inspect_db_reads_run_size_counters(tmp_path: Path) -> None:
    """`make status` and the run-info chart both report what was scanned."""
    db = _make_db(tmp_path / "timeline.duckdb", SuzakuKind.TIMELINE)
    conn = duckdb.connect(str(db))
    conn.execute(f"ALTER TABLE {META_TABLE} ADD COLUMN scanned_events BIGINT")
    conn.execute(f"ALTER TABLE {META_TABLE} ADD COLUMN output_rows BIGINT")
    conn.execute(f"UPDATE {META_TABLE} SET scanned_events = 42, output_rows = 7")
    conn.close()

    info = inspect_db(db)

    assert info.scanned_events == 42
    assert info.output_rows == 7


# ---------------------------------------------------------------------------
# Deterministic ordering — PLAN_SUZAKU_MULTI_DB.md F-3 / F-4
# ---------------------------------------------------------------------------


def test_generated_at_beats_mtime(tmp_path: Path) -> None:
    """`cp` rewrites mtime; the run that produced the data does not change."""
    stale_copy = _make_db(
        tmp_path / "a.duckdb",
        SuzakuKind.TIMELINE,
        generated_at="2026-07-01 00:00:00+00:00",
    )
    real_newer = _make_db(
        tmp_path / "b.duckdb",
        SuzakuKind.TIMELINE,
        generated_at="2026-07-20 00:00:00+00:00",
    )
    # The older run was copied in last, so its mtime is the newest.
    os.utime(real_newer, (1_000_000, 1_000_000))
    os.utime(stale_copy, (2_000_000, 2_000_000))

    assert [info.path.name for info in discover(tmp_path)] == ["b.duckdb", "a.duckdb"]


def test_equal_generated_at_falls_back_to_mtime(tmp_path: Path) -> None:
    """Two exports of one run: the one placed most recently wins."""
    when = "2026-07-01 00:00:00+00:00"
    first = _make_db(tmp_path / "a.duckdb", SuzakuKind.TIMELINE, generated_at=when)
    second = _make_db(tmp_path / "b.duckdb", SuzakuKind.TIMELINE, generated_at=when)
    os.utime(first, (1_000_000, 1_000_000))
    os.utime(second, (2_000_000, 2_000_000))

    assert [info.path.name for info in discover(tmp_path)] == ["b.duckdb", "a.duckdb"]


def test_full_tie_breaks_on_path_not_filesystem_order(tmp_path: Path) -> None:
    """Identical timestamps must still select the same file on every machine."""
    when = "2026-07-01 00:00:00+00:00"
    names = ["c.duckdb", "a.duckdb", "b.duckdb"]
    for name in names:
        _make_db(tmp_path / name, SuzakuKind.TIMELINE, generated_at=when)
        os.utime(tmp_path / name, (1_000_000, 1_000_000))

    assert [info.path.name for info in discover(tmp_path)] == sorted(names)
    assert find_db(SuzakuKind.TIMELINE, tmp_path).path.name == "a.duckdb"


# ---------------------------------------------------------------------------
# Candidate set — PLAN_SUZAKU_MULTI_DB.md F-10
# ---------------------------------------------------------------------------


def test_db_extension_is_discovered(tmp_path: Path) -> None:
    """Suzaku's output is a DuckDB file whatever the analyst named it."""
    _make_db(tmp_path / "run1.db", SuzakuKind.TIMELINE)

    assert [info.path.name for info in discover(tmp_path)] == ["run1.db"]


def test_senrigan_database_is_excluded_from_discovery(tmp_path: Path, monkeypatch):
    """A .db file holding cloudtrail_events is Senrigan's, not a candidate."""
    monkeypatch.delenv("DUCKDB_PATH", raising=False)
    _make_db(
        tmp_path / "some_other_name.db",
        None,
        tables={"cloudtrail_events": ["event_time"]},
    )
    _make_db(tmp_path / "timeline.duckdb", SuzakuKind.TIMELINE)

    assert [info.path.name for info in discover(tmp_path)] == ["timeline.duckdb"]


def test_configured_senrigan_path_is_never_opened(tmp_path: Path, monkeypatch) -> None:
    """The ingester's own database can be huge — do not open it to find that out."""
    senrigan = tmp_path / "custom_name.db"
    _make_db(senrigan, None, tables={"cloudtrail_events": ["event_time"]})
    monkeypatch.setenv("DUCKDB_PATH", str(senrigan))

    opened = _spy_on_connect(monkeypatch)
    discover(tmp_path)

    assert str(senrigan) not in opened


def _spy_on_connect(monkeypatch) -> list[str]:
    """Record every path passed to ``duckdb.connect``."""
    opened: list[str] = []
    original = duckdb.connect

    def spy(path, *args, **kwargs):
        opened.append(str(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(duckdb, "connect", spy)
    return opened


def test_discover_opens_each_file_once(tmp_path: Path, monkeypatch) -> None:
    """Bootstrap scans a directory of 200 MB files — one open each, no more."""
    for name in ("a.duckdb", "b.duckdb", "c.duckdb"):
        _make_db(tmp_path / name, SuzakuKind.TIMELINE)

    opened = _spy_on_connect(monkeypatch)
    discover(tmp_path)

    assert sorted(opened) == sorted(
        str(tmp_path / name) for name in ("a.duckdb", "b.duckdb", "c.duckdb")
    )


# ---------------------------------------------------------------------------
# select — one stated choice per kind, with the runners-up named
# ---------------------------------------------------------------------------


def test_select_names_the_choice_and_the_runners_up(tmp_path: Path) -> None:
    """A silently dropped candidate is the whole problem this fixes (F-5)."""
    _make_db(
        tmp_path / "old.duckdb",
        SuzakuKind.TIMELINE,
        generated_at="2026-07-01 00:00:00+00:00",
    )
    _make_db(
        tmp_path / "new.duckdb",
        SuzakuKind.TIMELINE,
        generated_at="2026-07-20 00:00:00+00:00",
    )

    selection = select(tmp_path)[SuzakuKind.TIMELINE]

    assert selection.chosen.path.name == "new.duckdb"
    assert [info.path.name for info in selection.ignored] == ["old.duckdb"]
    assert selection.source == "discovery"


def test_select_reports_a_kind_with_no_file(tmp_path: Path) -> None:
    """Every kind is present in the report, so "nothing found" is stated."""
    _make_db(tmp_path / "timeline.duckdb", SuzakuKind.TIMELINE)

    selection = select(tmp_path)[SuzakuKind.METRICS]

    assert selection.chosen is None
    assert selection.source == "none"


def test_select_marks_an_env_override(tmp_path: Path, monkeypatch) -> None:
    """An override is a decision the operator made — say so in the report."""
    pinned = _make_db(
        tmp_path / "pinned.duckdb",
        SuzakuKind.TIMELINE,
        generated_at="2026-07-01 00:00:00+00:00",
    )
    _make_db(
        tmp_path / "newer.duckdb",
        SuzakuKind.TIMELINE,
        generated_at="2026-07-20 00:00:00+00:00",
    )
    monkeypatch.setenv(ENV_OVERRIDES[SuzakuKind.TIMELINE], str(pinned))

    selection = select(tmp_path)[SuzakuKind.TIMELINE]

    assert selection.chosen.path.name == "pinned.duckdb"
    assert selection.source == "override"
    assert [info.path.name for info in selection.ignored] == ["newer.duckdb"]


# ---------------------------------------------------------------------------
# Inventory JSON — one scan crosses the process boundary (F-9)
# ---------------------------------------------------------------------------


def test_inventory_json_round_trip(tmp_path: Path) -> None:
    """bootstrap.sh scans once and hands the result to three consumers."""
    _make_db(
        tmp_path / "timeline.duckdb",
        SuzakuKind.TIMELINE,
        generated_at="2026-07-20 00:00:00+00:00",
    )
    _make_db(tmp_path / "broken.duckdb", SuzakuKind.METRICS, tables={})

    original = discover(tmp_path)
    restored = inventory_from_json(inventory_to_json(original))

    assert [info.path for info in restored] == [info.path for info in original]
    assert [info.kind for info in restored] == [info.kind for info in original]
    assert [info.generated_at for info in restored] == [
        info.generated_at for info in original
    ]
    assert [info.reject_reason for info in restored] == [
        info.reject_reason for info in original
    ]


def test_select_accepts_a_restored_inventory(tmp_path: Path) -> None:
    """Selection from JSON must equal selection from a live scan."""
    _make_db(tmp_path / "timeline.duckdb", SuzakuKind.TIMELINE)

    restored = inventory_from_json(inventory_to_json(discover(tmp_path)))
    selection = select(tmp_path, inventory=restored)[SuzakuKind.TIMELINE]

    assert selection.chosen.path.name == "timeline.duckdb"


# ---------------------------------------------------------------------------
# Fitness — PLAN_SUZAKU_MULTI_DB.md Phase 1 / F-1
# ---------------------------------------------------------------------------


def _without_column(kind: SuzakuKind, table: str, column: str) -> dict[str, list[str]]:
    """Return *kind*'s payload tables with one column removed."""
    tables = {name: list(columns) for name, columns in PAYLOAD_TABLES[kind].items()}
    tables[table].remove(column)
    return tables


def test_metrics_without_geo_columns_is_rejected(tmp_path: Path) -> None:
    """A run without --geo-ip cannot serve the Metrics dashboard (F-1)."""
    tables = {
        name: list(columns)
        for name, columns in PAYLOAD_TABLES[SuzakuKind.METRICS].items()
    }
    for column in ("SrcASN", "SrcCity", "SrcCountry"):
        tables["metrics"].remove(column)
    db = _make_db(tmp_path / "nogeo.duckdb", SuzakuKind.METRICS, tables=tables)

    info = inspect_db(db)

    assert info.kind is None, "an unqueryable file must not be selectable"
    assert info.declared_kind is SuzakuKind.METRICS, "the report still names it"
    assert "--geo-ip" in info.reject_reason
    assert set(info.missing_columns) == {
        "metrics.SrcASN",
        "metrics.SrcCity",
        "metrics.SrcCountry",
    }


def test_a_fit_file_beats_a_newer_unfit_one(tmp_path: Path) -> None:
    """The whole point: one bad copy must not take the dashboard down."""
    tables = {
        name: list(columns)
        for name, columns in PAYLOAD_TABLES[SuzakuKind.METRICS].items()
    }
    for column in ("SrcASN", "SrcCity", "SrcCountry"):
        tables["metrics"].remove(column)
    _make_db(
        tmp_path / "good.duckdb",
        SuzakuKind.METRICS,
        generated_at="2026-07-01 00:00:00+00:00",
    )
    _make_db(
        tmp_path / "nogeo.duckdb",
        SuzakuKind.METRICS,
        tables=tables,
        generated_at="2026-07-20 00:00:00+00:00",
    )

    selection = select(tmp_path)[SuzakuKind.METRICS]

    assert selection.chosen.path.name == "good.duckdb"
    assert [info.path.name for info in selection.rejected] == ["nogeo.duckdb"]


def test_timeline_missing_a_charted_column_is_rejected(tmp_path: Path) -> None:
    """Every column the timeline datasets select is part of the contract."""
    db = _make_db(
        tmp_path / "partial.duckdb",
        SuzakuKind.TIMELINE,
        tables=_without_column(SuzakuKind.TIMELINE, "timeline", "RuleID"),
    )

    info = inspect_db(db)

    assert info.kind is None
    assert info.missing_columns == ("timeline.RuleID",)


def test_declared_kind_without_its_table_is_rejected(tmp_path: Path) -> None:
    """A meta row claiming a command the file cannot serve is not usable."""
    db = _make_db(tmp_path / "empty.duckdb", SuzakuKind.TIMELINE, tables={})

    info = inspect_db(db)

    assert info.kind is None
    assert info.declared_kind is SuzakuKind.TIMELINE
    assert "no timeline table" in info.reject_reason


def test_column_matching_is_case_insensitive(tmp_path: Path) -> None:
    """A rebuilt file may differ in case; that is not a missing column."""
    tables = {
        "metrics": [
            column.lower() for column in PAYLOAD_TABLES[SuzakuKind.METRICS]["metrics"]
        ]
    }
    db = _make_db(tmp_path / "lower.duckdb", SuzakuKind.METRICS, tables=tables)

    assert inspect_db(db).kind is SuzakuKind.METRICS


# ---------------------------------------------------------------------------
# Reading the meta row must never be all-or-nothing
#
# Regression: reading `generated_at` (TIMESTAMP WITH TIME ZONE) through the
# DuckDB Python client needs `pytz`, which the agent image does not ship. The
# whole projection raised, the failure was swallowed, and three perfectly good
# Suzaku files reported "No suzaku_meta table".
# ---------------------------------------------------------------------------


class _FakeResult:
    """Minimal stand-in for a DuckDB result."""

    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row


class _PickyConnection:
    """A connection that fails on some projections, recording every query."""

    def __init__(self, *, fail_on: str, row):
        self.fail_on = fail_on
        self.row = row
        self.queries: list[str] = []

    def execute(self, sql, *args, **kwargs):
        self.queries.append(sql)
        if self.fail_on in sql:
            raise duckdb.InvalidInputException(
                "Required module 'pytz' failed to import"
            )
        return _FakeResult(self.row)


def test_meta_read_survives_an_unreadable_optional_column() -> None:
    """One column the client cannot decode must not hide the whole file."""
    from suzaku_db import _read_meta

    conn = _PickyConnection(fail_on="generated_at", row=(1, "aws-ct-timeline"))

    meta = _read_meta(conn, ["schema_version", "command", "generated_at"])

    assert meta["command"] == "aws-ct-timeline"
    assert meta["schema_version"] == 1
    assert meta.get("generated_at") is None


def test_meta_read_never_selects_a_raw_timestamptz() -> None:
    """`generated_at` is cast in SQL, so the client never decodes a tz value."""
    from suzaku_db import _read_meta

    conn = _PickyConnection(fail_on="__never__", row=(1, "aws-ct-timeline"))
    _read_meta(conn, ["schema_version", "command", "generated_at"])

    selecting_generated_at = [q for q in conn.queries if "generated_at" in q]
    assert selecting_generated_at, "the timestamp is still read"
    for query in selecting_generated_at:
        assert 'CAST("generated_at" AS VARCHAR)' in query, query


def test_meta_read_gives_up_only_when_the_command_is_unreadable() -> None:
    """Without schema_version and command there is nothing to detect."""
    from suzaku_db import _read_meta

    conn = _PickyConnection(fail_on="command", row=(1, "aws-ct-timeline"))

    assert _read_meta(conn, ["schema_version", "command"]) == {}


@pytest.mark.parametrize(
    ("value", "expected_offset_hours"),
    [("2026-07-28 00:05:10.058718+00", 0), ("2026-07-28 09:05:10+09", 9)],
)
def test_generated_at_is_parsed_from_duckdbs_string_form(
    value: str, expected_offset_hours: int
) -> None:
    """DuckDB renders the offset as `+09`, not `+09:00`."""
    from suzaku_db import _as_utc

    parsed = _as_utc(value)

    assert parsed is not None
    assert parsed.utcoffset().total_seconds() == expected_offset_hours * 3600


def test_a_naive_timestamp_string_is_read_as_utc() -> None:
    """A hand-rebuilt file may carry no offset; comparing it must not raise."""
    from suzaku_db import _as_utc

    parsed = _as_utc("2026-07-28 00:05:10")

    assert parsed is not None and parsed.tzinfo is not None


def test_unparseable_timestamps_are_dropped_not_fatal() -> None:
    """Ordering falls back to mtime rather than refusing the file."""
    from suzaku_db import _as_utc

    assert _as_utc("not a timestamp") is None
    assert _as_utc(None) is None
