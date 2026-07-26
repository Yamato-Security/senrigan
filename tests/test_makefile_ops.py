"""Tests for the recovery, status, and guardrail targets.

Covers PLAN_MAKEFILE_UX.md Phase 3 (findings F-7 and F-10). `reset` replaces a
hand-copied `rm -f` recipe, so it is the one target in this Makefile that can
destroy user data — most of the tests here exist to keep it narrow.
"""

from __future__ import annotations

import re

from tests.conftest import declared_targets, run_make


def reset_recipe(*args: str) -> str:
    return run_make("reset", *args)


# ── reset: destructive, therefore guarded ──────────────────────────────────


def test_reset_asks_for_confirmation():
    """Deleting the database is never a surprise."""
    assert "read " in reset_recipe(), "`make reset` runs without asking"


def test_reset_force_skips_confirmation():
    """FORCE=1 makes reset usable from a script or CI."""
    assert "read " not in reset_recipe("FORCE=1")


def test_reset_never_recursively_deletes():
    """A typo in a path variable must not be able to wipe a directory tree."""
    assert "rm -rf" not in reset_recipe("FORCE=1")


def _database_removal_lines(recipe: str) -> list[str]:
    """Return reset's own `rm` lines.

    Scoped to lines naming the database: the `ensure-secret` prerequisite has
    an unrelated `rm -f docker/.env.bak` of its own.
    """
    return [
        line.strip()
        for line in recipe.splitlines()
        if line.strip().startswith("rm ") and "threat_hunting.db" in line
    ]


def test_reset_deletes_only_duckdb_files():
    """Every path reset removes is a named DuckDB file, not a directory."""
    removed: list[str] = []
    for line in _database_removal_lines(reset_recipe("FORCE=1")):
        removed.extend(re.sub(r"^rm\s+(-\w+\s+)*", "", line).split())

    assert removed, "reset deletes nothing"

    unexpected = [path for path in removed if not path.endswith((".db", ".db.wal"))]
    assert not unexpected, f"reset removes non-database paths: {unexpected}"


def test_reset_stops_containers_before_deleting():
    """The sole writer must be down before its database file disappears."""
    recipe = reset_recipe("FORCE=1")
    lines = recipe.splitlines()

    down = next(i for i, line in enumerate(lines) if "compose down" in line)
    removal = next(
        i
        for i, line in enumerate(lines)
        if line.strip() in _database_removal_lines(recipe)
    )

    assert down < removal, "reset deletes the database while the writer may be running"


def test_reset_points_at_the_next_step():
    """After a reset the database is gone, so say what to run."""
    assert "make ingest" in reset_recipe("FORCE=1")


# ── Guardrails at the point of failure (F-10) ──────────────────────────────


def test_up_warns_when_database_is_missing():
    """Starting the UI without a database explains the blank dashboards."""
    recipe = run_make("up")

    assert "threat_hunting.db" in recipe
    assert "make ingest" in recipe


def test_ingest_checks_for_logs_before_starting_a_container():
    """An empty docker/logs/ fails fast, with the command that fixes it."""
    recipe = run_make("ingest")

    assert "docker/logs" in recipe
    assert "aws s3 cp" in recipe, "the fast-fail does not say how to get logs"


# ── status and check ───────────────────────────────────────────────────────


def test_status_reports_the_database_and_what_ingest_would_detect():
    """`make status` answers 'is there data, and will enrichment happen?'."""
    recipe = run_make("status")

    assert "compose ps" in recipe
    assert "threat_hunting.db" in recipe
    assert "GeoIP" in recipe


def test_ps_delegates_to_status():
    """`ps` is kept as a compatibility alias."""
    assert "ps" in declared_targets()
    assert "compose ps" in run_make("ps")


def test_check_runs_tests_lint_and_format():
    """One command for contributors, matching what CI enforces."""
    recipe = run_make("check")

    assert "cargo clippy" in recipe
    assert "black --check" in recipe
    assert "pytest" in recipe
