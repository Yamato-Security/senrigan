"""Tests for Suzaku database discovery and registration in Superset.

Covers PLAN_SUZAKU_VIEWS.md §5.1 and §5.5 (tests 1-4). Superset stores a
``sqlalchemy_uri`` per database, resolved once by ``superset-init``, so — unlike
the Streamlit agent, which can glob on every rerun — the Suzaku files have to be
discovered and registered at bootstrap. The registration is keyed by a fixed
name and UUID so chart and dataset YAMLs never reference a file path.

The producing command is read from the file's own ``suzaku_meta`` table, so the
synthetic databases below carry one.

The module under test imports Superset lazily (inside ``main()``), so its
detection logic is importable outside the container.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import duckdb
import pytest

REGISTER_SUZAKU_PATH = (
    Path(__file__).resolve().parent.parent / "init" / "register_suzaku_dbs.py"
)
FIXTURE_DIR = Path(__file__).resolve().parents[2] / "sample" / "suzaku" / "fixtures"


def _load_module():
    """Import register_suzaku_dbs.py by path, without Superset available."""
    spec = importlib.util.spec_from_file_location(
        "register_suzaku_dbs", REGISTER_SUZAKU_PATH
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["register_suzaku_dbs"] = module
    spec.loader.exec_module(module)
    return module


szdb = _load_module()


TIMELINE_TABLES = {
    "timeline": ["Timestamp", "RuleTitle", "Level", "RuleID", "EventName", "SrcIP"]
}
SUMMARY_TABLES = {
    "summary": ["UserARN", "NumOfEvents"],
    "summary_api_calls": ["UserARN", "IsAbused", "Outcome", "API", "Count"],
    "summary_attributes": ["UserARN", "Attribute", "Value", "Count"],
}
METRICS_TABLES = {"metrics": ["Field", "Value", "Count", "Percent"]}


def _make_db(
    path: Path,
    tables: dict[str, list[str]],
    command: str | None = None,
    schema_version: int = 1,
) -> Path:
    """Create a DuckDB file whose schema matches *tables*.

    Args:
        path:           File to create.
        tables:         Payload tables to create, as ``{name: [column, ...]}``.
        command:        Value for ``suzaku_meta.command``; omit the table when None.
        schema_version: Value for ``suzaku_meta.schema_version``.

    Returns:
        *path*, for chaining.
    """
    conn = duckdb.connect(str(path))
    try:
        for table, columns in tables.items():
            defs = ", ".join(f'"{column}" VARCHAR' for column in columns)
            conn.execute(f'CREATE TABLE "{table}" ({defs})')
        if command is not None:
            conn.execute(
                f"CREATE TABLE {szdb.META_TABLE} "
                "(schema_version INTEGER, command VARCHAR)"
            )
            conn.execute(
                f"INSERT INTO {szdb.META_TABLE} VALUES (?, ?)",
                [schema_version, command],
            )
    finally:
        conn.close()
    return path


# ---------------------------------------------------------------------------
# Detection (tests 1-2)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture_name", "command"),
    [
        ("suzaku-aws-ct-timeline.duckdb", "aws-ct-timeline"),
        ("suzaku-aws-ct-summary.duckdb", "aws-ct-summary"),
        ("suzaku-aws-ct-metrics.duckdb", "aws-ct-metrics"),
    ],
)
def test_classifies_each_real_fixture(fixture_name: str, command: str) -> None:
    """Test 1: detection must work on real Suzaku output."""
    assert szdb.detect_command_in(FIXTURE_DIR / fixture_name) == command


def test_partial_summary_export_is_not_a_summary(tmp_path: Path) -> None:
    """Test 2: a file claiming a command it has no tables for is unusable.

    The dataset YAMLs query all three summary tables, so a truncated export
    would register a database whose every chart fails with a binder error.
    """
    partial = {
        name: columns
        for name, columns in SUMMARY_TABLES.items()
        if name != "summary_attributes"
    }
    db = _make_db(tmp_path / "partial.duckdb", partial, command="aws-ct-summary")
    assert szdb.detect_command_in(db) is None


def test_senrigan_database_is_never_a_suzaku_command(tmp_path: Path) -> None:
    """Senrigan's own database must not be registered as Suzaku output."""
    db = _make_db(
        tmp_path / "senrigan.duckdb",
        {**TIMELINE_TABLES, "cloudtrail_events": ["event_time"]},
        command="aws-ct-timeline",
    )
    assert szdb.detect_command_in(db) is None


def test_file_without_suzaku_meta_is_unrecognised(tmp_path: Path) -> None:
    """Detection reads the metadata table; a file without one is not Suzaku's."""
    db = _make_db(tmp_path / "legacy.duckdb", TIMELINE_TABLES)
    assert szdb.detect_command_in(db) is None


def test_newer_schema_version_is_refused(tmp_path: Path) -> None:
    """A layout this bootstrap cannot read must not be mis-visualized."""
    db = _make_db(
        tmp_path / "future.duckdb",
        TIMELINE_TABLES,
        command="aws-ct-timeline",
        schema_version=szdb.SUPPORTED_SCHEMA_VERSION + 1,
    )
    assert szdb.detect_command_in(db) is None


def test_unknown_command_is_unrecognised(tmp_path: Path) -> None:
    """Suzaku's Azure output has no Senrigan dashboard to register."""
    db = _make_db(tmp_path / "azure.duckdb", TIMELINE_TABLES, command="azure-timeline")
    assert szdb.detect_command_in(db) is None


def test_unreadable_file_is_skipped_not_raised(tmp_path: Path) -> None:
    """A stray non-DuckDB file must not abort the whole bootstrap."""
    broken = tmp_path / "broken.duckdb"
    broken.write_text("not a database", encoding="utf-8")
    assert szdb.detect_command_in(broken) is None


# ---------------------------------------------------------------------------
# Discovery (test 3)
# ---------------------------------------------------------------------------


def test_discover_maps_each_command_to_one_file(tmp_path: Path) -> None:
    """One database per command, newest first when several match."""
    older = _make_db(tmp_path / "old.duckdb", TIMELINE_TABLES, "aws-ct-timeline")
    newer = _make_db(tmp_path / "new.duckdb", TIMELINE_TABLES, "aws-ct-timeline")
    _make_db(tmp_path / "metrics.duckdb", METRICS_TABLES, "aws-ct-metrics")
    os.utime(older, (1_000_000, 1_000_000))
    os.utime(newer, (2_000_000, 2_000_000))

    found = szdb.discover_databases(str(tmp_path))

    assert found["aws-ct-timeline"] == str(newer)
    assert found["aws-ct-metrics"] == str(tmp_path / "metrics.duckdb")
    assert "aws-ct-summary" not in found


def test_discover_skips_the_senrigan_database(tmp_path: Path) -> None:
    """Only ``*.duckdb`` is scanned, so threat_hunting.db is never touched."""
    _make_db(
        tmp_path / "threat_hunting.db",
        {"cloudtrail_events": ["event_time"]},
        command="aws-ct-timeline",
    )
    assert szdb.discover_databases(str(tmp_path)) == {}


def test_discover_on_missing_directory_is_empty(tmp_path: Path) -> None:
    """Test 3: no database directory means nothing to register, not a crash."""
    assert szdb.discover_databases(str(tmp_path / "absent")) == {}


def test_env_override_pins_a_file(tmp_path: Path, monkeypatch) -> None:
    """An explicit SUZAKU_*_DB must win over mtime ordering."""
    pinned = _make_db(tmp_path / "pinned.duckdb", TIMELINE_TABLES, "aws-ct-timeline")
    newer = _make_db(tmp_path / "newer.duckdb", TIMELINE_TABLES, "aws-ct-timeline")
    os.utime(pinned, (1_000_000, 1_000_000))
    os.utime(newer, (2_000_000, 2_000_000))
    monkeypatch.setenv("SUZAKU_TIMELINE_DB", str(pinned))

    assert szdb.discover_databases(str(tmp_path))["aws-ct-timeline"] == str(pinned)


# ---------------------------------------------------------------------------
# Registration contract (test 4)
# ---------------------------------------------------------------------------


def test_every_command_has_a_database_name_and_uuid() -> None:
    """Dataset YAMLs reference the database by UUID, so both must be fixed."""
    assert set(szdb.SUZAKU_TABLES) == set(szdb.DATABASE_NAMES)
    assert set(szdb.SUZAKU_TABLES) == set(szdb.DATABASE_UUIDS)

    names = list(szdb.DATABASE_NAMES.values())
    uuids = list(szdb.DATABASE_UUIDS.values())
    assert len(set(names)) == len(names)
    assert len(set(uuids)) == len(uuids)


def test_uri_uses_the_explicit_duckdb_driver() -> None:
    """DU-13: the bare duckdb:// scheme fails SA2 entry-point discovery."""
    uri = szdb.build_uri("/data/db/timeline.duckdb")
    assert uri == "duckdb+duckdb_engine:////data/db/timeline.duckdb"
    assert "?read_only" not in uri  # not a valid duckdb-engine URI parameter


def test_engine_params_enforce_read_only() -> None:
    """Suzaku files are third-party artifacts: never opened writable."""
    extra = szdb.build_extra()
    assert extra["engine_params"]["connect_args"]["read_only"] is True


def test_register_script_does_not_enable_async_queries() -> None:
    """DU-06: allow_run_async needs Celery, which this deployment has not got."""
    source = REGISTER_SUZAKU_PATH.read_text(encoding="utf-8")
    for line in source.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert "allow_run_async = True" not in stripped
        assert "allow_run_async=True" not in stripped


def test_superset_is_imported_lazily() -> None:
    """The module must stay importable outside the Superset container."""
    source = REGISTER_SUZAKU_PATH.read_text(encoding="utf-8")
    for line in source.splitlines():
        if line.startswith(("import superset", "from superset")):
            pytest.fail(f"top-level Superset import: {line!r}")


# ---------------------------------------------------------------------------
# --list mode: bootstrap needs the detected commands before importing bundles
# ---------------------------------------------------------------------------


def test_list_mode_prints_one_command_per_line(tmp_path: Path, capsys) -> None:
    """bootstrap.sh imports a bundle only when its command was detected."""
    _make_db(tmp_path / "anything.duckdb", TIMELINE_TABLES, "aws-ct-timeline")
    _make_db(tmp_path / "other-name.duckdb", METRICS_TABLES, "aws-ct-metrics")

    szdb.print_detected(str(tmp_path))

    printed = {line for line in capsys.readouterr().out.split() if line}
    assert printed == {"aws-ct-timeline", "aws-ct-metrics"}


def test_list_mode_prints_nothing_when_no_database_is_present(
    tmp_path: Path, capsys
) -> None:
    """No Suzaku files means no bundle may be imported."""
    szdb.print_detected(str(tmp_path))
    assert capsys.readouterr().out.strip() == ""


def test_bundle_names_map_to_commands() -> None:
    """bootstrap.sh iterates bundles; the mapping must live with the detection."""
    assert szdb.BUNDLE_COMMANDS == {
        "suzaku_timeline": "aws-ct-timeline",
        "suzaku_summary": "aws-ct-summary",
        "suzaku_metrics": "aws-ct-metrics",
    }
