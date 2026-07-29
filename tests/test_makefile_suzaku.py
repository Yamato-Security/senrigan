"""Tests for the Makefile's handling of Suzaku databases.

Covers PLAN_SUZAKU_VIEWS.md §6.2. Suzaku files are copied in by hand, so the
Makefile's job is only to report what it can see — the same "the filesystem is
the configuration" principle as PLAN_MAKEFILE_UX.md §2.3 — and, critically, to
never delete them.
"""

from __future__ import annotations

from tests.conftest import (
    declared_targets,
    documented_targets,
    expand_variables,
    makefile_text,
    run_make,
    variable_definitions,
)


def test_status_reports_suzaku_databases() -> None:
    """`make status` must say whether Suzaku output was detected."""
    recipe = run_make("status")
    assert "Suzaku" in recipe


def test_status_detection_scans_the_database_directory() -> None:
    """Detection has to look where the compose file mounts the databases from."""
    definitions = variable_definitions()
    assert "SUZAKU_DBS" in definitions
    expanded = expand_variables(definitions["SUZAKU_DBS"])
    assert "*.duckdb" in expanded
    assert "data/db" in expanded


def test_reset_never_deletes_a_suzaku_database() -> None:
    """A re-ingest must not throw away hours of Suzaku processing.

    `reset` deletes only the two DuckDB files it owns, by explicit name. A
    wildcard here would take the analyst's Suzaku exports with it.
    """
    recipe = run_make("reset", env={"FORCE": "1"})
    for line in recipe.splitlines():
        if line.strip().startswith("rm "):
            assert ".duckdb" not in line, line
            assert "*" not in line, line


def test_no_new_make_verb_for_suzaku() -> None:
    """Copying a file is the whole workflow; a target would only add ceremony."""
    targets = declared_targets()
    assert not [name for name in targets if name.startswith("suzaku")]


def test_status_stays_documented() -> None:
    """`status` is in the two-tier help, so its description must survive edits."""
    assert "status" in documented_targets()


def test_makefile_mentions_the_suzaku_database_extension() -> None:
    """The detection variable is only obvious if the extension is spelled out."""
    assert ".duckdb" in makefile_text()


# ---------------------------------------------------------------------------
# Which file is live — PLAN_SUZAKU_MULTI_DB.md Phase 3 (F-5)
#
# `SUZAKU_DBS` is a wildcard over the developer's own docker/data/db, so these
# tests override it on the make command line (which wins over `:=`) and pin the
# branch under test. Reading the ambient directory would make them pass on a
# machine with Suzaku files and fail in CI, which is not a property of the
# Makefile.
# ---------------------------------------------------------------------------

# A path that need not exist: only whether the variable is empty selects the branch.
WITH_SUZAKU = "SUZAKU_DBS=docker/data/db/run.duckdb"
WITHOUT_SUZAKU = "SUZAKU_DBS="


def test_status_reports_the_selection_not_just_the_file_names() -> None:
    """Listing four files says nothing about which one a dashboard reads."""
    recipe = run_make("status", WITH_SUZAKU)
    assert "--report" in recipe, "status must ask for the per-command selection"


def test_status_degrades_without_the_dashboard_image() -> None:
    """A cold checkout has no image; `status` must still work and say why."""
    recipe = run_make("status", WITH_SUZAKU)
    assert "docker image inspect" in recipe
    assert "make up" in recipe, "tell the user how to get the full report"


def test_status_without_any_suzaku_file_says_so_and_asks_for_nothing() -> None:
    """The empty case must not start a container just to report emptiness."""
    recipe = run_make("status", WITHOUT_SUZAKU)
    assert "no *.duckdb" in recipe
    assert "--report" not in recipe
    assert "docker image inspect" not in recipe


def test_up_names_the_selected_files() -> None:
    """After start-up the choice is knowable, so print it rather than a hint."""
    recipe = run_make("up", WITH_SUZAKU)
    assert "--report" in recipe


def test_up_without_suzaku_files_does_not_mention_them() -> None:
    """Most users have no Suzaku output; they must not see a Suzaku report."""
    recipe = run_make("up", WITHOUT_SUZAKU)
    assert "--report" not in recipe


def test_detection_includes_the_other_duckdb_extension() -> None:
    """agent/suzaku_db.py scans .db too; the Makefile must not disagree."""
    definitions = variable_definitions()
    expanded = expand_variables(definitions["SUZAKU_DBS"])
    assert "*.duckdb" in expanded
    assert "*.db" in expanded


def test_senrigan_own_database_is_not_reported_as_suzaku() -> None:
    """threat_hunting.db matches *.db but is the ingester's, not Suzaku's."""
    definitions = variable_definitions()
    assert "filter-out" in definitions["SUZAKU_DBS"]
    assert "DB_FILE" in definitions["SUZAKU_DBS"]
