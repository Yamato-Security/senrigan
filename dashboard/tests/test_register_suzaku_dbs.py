"""Behaviour of the Suzaku registration script outside Superset.

One scan is shared by every bootstrap step, and the report names the file each
dashboard will query along with everything it passed over.

Superset itself is never imported — :func:`register_suzaku_dbs.main` defers
that until it actually writes to the metadata database, so every path exercised
here runs on a plain Python interpreter, exactly as ``--scan`` / ``--list`` /
``--report`` do inside the container.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
INIT_DIR = REPO_ROOT / "dashboard" / "init"
AGENT_DIR = REPO_ROOT / "agent"
SCRIPT = INIT_DIR / "register_suzaku_dbs.py"

for directory in (str(AGENT_DIR), str(INIT_DIR)):
    if directory not in sys.path:
        sys.path.insert(0, directory)

import register_suzaku_dbs as script  # noqa: E402 — needs sys.path set up first
from suzaku_db import (  # noqa: E402
    META_TABLE,
    REQUIRED_COLUMNS,
    SuzakuKind,
    discover,
)


def _make_db(
    path: Path,
    kind: SuzakuKind,
    *,
    generated_at: str = "2026-07-20 00:00:00+00:00",
    drop: tuple[str, ...] = (),
) -> Path:
    """Write a DuckDB file shaped like one Suzaku run.

    Args:
        path:         File to create.
        kind:         Command to record in ``suzaku_meta``.
        generated_at: Timestamp to record.
        drop:         Columns to leave out, to build an unfit file.

    Returns:
        *path*, for chaining.
    """
    conn = duckdb.connect(str(path))
    try:
        for table, columns in REQUIRED_COLUMNS[kind].items():
            kept = [column for column in columns if column not in drop]
            defs = ", ".join(f'"{column}" VARCHAR' for column in kept)
            conn.execute(f'CREATE TABLE "{table}" ({defs})')
        conn.execute(
            f"CREATE TABLE {META_TABLE} (schema_version INTEGER, "
            "suzaku_version VARCHAR, command VARCHAR, "
            "generated_at TIMESTAMP WITH TIME ZONE)"
        )
        conn.execute(
            f"INSERT INTO {META_TABLE} VALUES (1, '2.0.0', ?, ?)",
            [kind.value, generated_at],
        )
    finally:
        conn.close()
    return path


def _run(args: list[str], db_dir: Path) -> str:
    """Run the script as bootstrap.sh does and return its stdout."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(AGENT_DIR), str(INIT_DIR)])
    env["DUCKDB_PATH"] = str(db_dir / "threat_hunting.db")
    for variable in ("SUZAKU_TIMELINE_DB", "SUZAKU_SUMMARY_DB", "SUZAKU_METRICS_DB"):
        env.pop(variable, None)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    return result.stdout


# ---------------------------------------------------------------------------
# One scan, reused (F-9)
# ---------------------------------------------------------------------------


def test_scan_writes_an_inventory_the_other_steps_can_use(tmp_path: Path) -> None:
    """`--scan` then `--from` must reach the same conclusion as a live scan."""
    _make_db(tmp_path / "timeline.duckdb", SuzakuKind.TIMELINE)
    inventory = tmp_path / "inventory.json"

    _run(["--scan", str(inventory)], tmp_path)

    payload = json.loads(inventory.read_text(encoding="utf-8"))
    assert payload["inventory_version"] == 1
    assert [entry["kind"] for entry in payload["databases"]] == [
        SuzakuKind.TIMELINE.value
    ]

    assert _run(["--list", "--from", str(inventory)], tmp_path).split() == [
        SuzakuKind.TIMELINE.value
    ]


def test_selecting_from_an_inventory_opens_no_file(tmp_path: Path, monkeypatch) -> None:
    """The saved scan is the point: bootstrap must not re-read 200 MB files."""
    _make_db(tmp_path / "timeline.duckdb", SuzakuKind.TIMELINE)
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        __import__("suzaku_db").inventory_to_json(discover(tmp_path)), encoding="utf-8"
    )

    opened: list[str] = []
    original = duckdb.connect

    def spy(path, *args, **kwargs):
        opened.append(str(path))
        return original(path, *args, **kwargs)

    monkeypatch.setattr(duckdb, "connect", spy)
    selections = script.load_selections(str(inventory), str(tmp_path))

    assert opened == []
    assert selections[SuzakuKind.TIMELINE].chosen is not None


def test_a_corrupt_inventory_falls_back_to_scanning(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    """A failed scan must degrade to the slow path, not to no dashboards."""
    monkeypatch.delenv("SUZAKU_TIMELINE_DB", raising=False)
    _make_db(tmp_path / "timeline.duckdb", SuzakuKind.TIMELINE)
    inventory = tmp_path / "inventory.json"
    inventory.write_text("{not json", encoding="utf-8")

    selections = script.load_selections(str(inventory), str(tmp_path))

    assert selections[SuzakuKind.TIMELINE].chosen is not None
    assert "rescanning" in capsys.readouterr().out


def test_a_missing_inventory_falls_back_to_scanning(
    tmp_path: Path, monkeypatch
) -> None:
    """`--scan` may never have run; selection must still work."""
    monkeypatch.delenv("SUZAKU_TIMELINE_DB", raising=False)
    _make_db(tmp_path / "timeline.duckdb", SuzakuKind.TIMELINE)

    selections = script.load_selections(str(tmp_path / "absent.json"), str(tmp_path))

    assert selections[SuzakuKind.TIMELINE].chosen is not None


# ---------------------------------------------------------------------------
# --list drives which bundles bootstrap.sh imports
# ---------------------------------------------------------------------------


def test_list_names_only_commands_with_a_usable_file(tmp_path: Path) -> None:
    """A bundle imported without its database fails on every chart."""
    _make_db(tmp_path / "timeline.duckdb", SuzakuKind.TIMELINE)
    _make_db(
        tmp_path / "metrics.duckdb",
        SuzakuKind.METRICS,
        drop=("SrcASN", "SrcCity", "SrcCountry"),
    )

    listed = _run(["--list"], tmp_path).split()

    assert listed == [SuzakuKind.TIMELINE.value], "the unfit metrics file is not usable"


def test_list_is_empty_for_an_empty_directory(tmp_path: Path) -> None:
    """No Suzaku files is a normal state, not an error."""
    assert _run(["--list"], tmp_path).strip() == ""


# ---------------------------------------------------------------------------
# --report (F-5)
# ---------------------------------------------------------------------------


def test_report_names_the_chosen_file_and_the_runners_up(tmp_path: Path) -> None:
    """Which file is live, and what it beat, must both be printed."""
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

    report = _run(["--report"], tmp_path)

    assert "new.duckdb" in report
    assert "ignored:" in report and "old.duckdb" in report
    assert "2026-07-20" in report


def test_report_explains_a_rejected_file(tmp_path: Path) -> None:
    """ "No Metrics dashboard" must come with the reason and the fix."""
    _make_db(
        tmp_path / "metrics.duckdb",
        SuzakuKind.METRICS,
        drop=("SrcASN", "SrcCity", "SrcCountry"),
    )

    report = _run(["--report"], tmp_path)

    assert "rejected: metrics.duckdb" in report
    assert "--geo-ip" in report
    assert "aws-ct-metrics" in report and "no usable file" in report


def test_report_lists_unreadable_files(tmp_path: Path) -> None:
    """A file nobody can open is the other reason a dashboard goes missing."""
    (tmp_path / "broken.duckdb").write_text("not a database", encoding="utf-8")
    inventory = tmp_path / "inventory.json"

    _run(["--scan", str(inventory)], tmp_path)
    report = _run(["--report", "--from", str(inventory)], tmp_path)

    assert "unreadable: broken.duckdb" in report


def test_report_lists_unreadable_files_without_a_saved_scan(tmp_path: Path) -> None:
    """`make status` calls --report on its own; it must be just as complete."""
    (tmp_path / "broken.duckdb").write_text("not a database", encoding="utf-8")

    report = _run(["--report"], tmp_path)

    assert "unreadable: broken.duckdb" in report


def test_report_covers_every_command(tmp_path: Path) -> None:
    """Every kind appears, so "nothing found" is stated rather than implied."""
    report = _run(["--report"], tmp_path)

    for kind in SuzakuKind:
        assert kind.value in report


def test_report_marks_an_environment_override(tmp_path: Path) -> None:
    """A pinned file is a decision the operator made — attribute it."""
    pinned = _make_db(tmp_path / "pinned.duckdb", SuzakuKind.SUMMARY)
    selections = script.load_selections(None, str(tmp_path))
    os.environ["SUZAKU_SUMMARY_DB"] = str(pinned)
    try:
        selections = script.load_selections(None, str(tmp_path))
        report = script.format_report(selections, directory=str(tmp_path))
    finally:
        del os.environ["SUZAKU_SUMMARY_DB"]

    assert "pinned by environment" in report


# ---------------------------------------------------------------------------
# Superset adapter surface
# ---------------------------------------------------------------------------


def test_uri_and_extra_stay_read_only() -> None:
    """Readers never open the DuckDB file read-write (CLAUDE.md access rules)."""
    assert script.build_uri("/data/db/x.duckdb").startswith("duckdb+duckdb_engine:///")
    assert script.build_extra()["engine_params"]["connect_args"]["read_only"] is True


@pytest.mark.parametrize("kind", list(SuzakuKind))
def test_every_kind_has_a_name_and_uuid(kind: SuzakuKind) -> None:
    """A kind without both cannot be registered at all."""
    assert script.DATABASE_NAMES[kind.value]
    assert script.DATABASE_UUIDS[kind.value]


# ---------------------------------------------------------------------------
# Stale registrations
# ---------------------------------------------------------------------------


def test_uri_target_recovers_the_file_path() -> None:
    """Superset stores the path inside the URI; retirement needs it back."""
    assert (
        script.uri_target("duckdb+duckdb_engine:////data/db/run.duckdb")
        == "/data/db/run.duckdb"
    )


def test_a_registration_whose_file_is_gone_is_stale(tmp_path: Path) -> None:
    """Deleting a Suzaku file used to leave every chart raising IOError."""
    assert script.is_stale(script.build_uri(str(tmp_path / "deleted.duckdb")))


def test_a_registration_whose_file_exists_is_not_stale(tmp_path: Path) -> None:
    """The common case must never be mistaken for a broken one."""
    present = _make_db(tmp_path / "timeline.duckdb", SuzakuKind.TIMELINE)
    assert not script.is_stale(script.build_uri(str(present)))


def test_the_shipped_placeholder_uri_is_stale() -> None:
    """The bundles ship an obviously-fake path; it must never look healthy."""
    placeholder = (
        "duckdb+duckdb_engine:////data/db/_placeholder_rewritten_at_bootstrap.duckdb"
    )
    assert script.is_stale(placeholder)


def test_an_unparseable_uri_is_not_reported_as_stale() -> None:
    """Better to leave a connection alone than to retire it on a guess."""
    assert not script.is_stale("duckdb+duckdb_engine://")
    assert not script.is_stale("")


# ---------------------------------------------------------------------------
# Superset compatibility rules that outlived the old signature tests
# (dashboard/tests/test_suzaku_signatures.py, retired with the duplicated
# detection it covered)
# ---------------------------------------------------------------------------


def test_register_script_does_not_enable_async_queries() -> None:
    """DU-06: allow_run_async needs Celery, which this deployment has not got."""
    for line in SCRIPT.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        assert "allow_run_async = True" not in stripped
        assert "allow_run_async=True" not in stripped


def test_superset_is_imported_lazily() -> None:
    """The module must stay importable outside the Superset container.

    Every path except :func:`main` runs on a plain interpreter — that is what
    makes ``--scan`` / ``--list`` / ``--report`` testable and fast.
    """
    for line in SCRIPT.read_text(encoding="utf-8").splitlines():
        if line.startswith(("import superset", "from superset")):
            pytest.fail(f"top-level Superset import: {line!r}")


def test_bundle_names_map_to_commands() -> None:
    """bootstrap.sh iterates bundles; the mapping must live with the adapter."""
    assert script.BUNDLE_COMMANDS == {
        "suzaku_timeline": SuzakuKind.TIMELINE.value,
        "suzaku_summary": SuzakuKind.SUMMARY.value,
        "suzaku_metrics": SuzakuKind.METRICS.value,
    }


@pytest.mark.parametrize(
    ("fixture_name", "kind"),
    [
        ("suzaku-aws-ct-timeline.duckdb", SuzakuKind.TIMELINE),
        ("suzaku-aws-ct-summary.duckdb", SuzakuKind.SUMMARY),
        ("suzaku-aws-ct-metrics.duckdb", SuzakuKind.METRICS),
    ],
)
def test_real_fixtures_are_selected_by_the_superset_path(
    fixture_name: str, kind: SuzakuKind, tmp_path: Path
) -> None:
    """Registration must work on real Suzaku output, not just synthetic tables."""
    import shutil

    fixtures = REPO_ROOT / "sample" / "suzaku" / "fixtures"
    shutil.copy(fixtures / fixture_name, tmp_path / "copied.duckdb")

    selection = script.load_selections(None, str(tmp_path))[kind]

    assert selection.chosen is not None, selection.rejected
    assert selection.chosen.path.name == "copied.duckdb"
