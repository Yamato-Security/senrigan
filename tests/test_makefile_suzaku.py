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
