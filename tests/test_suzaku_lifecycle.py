"""Adding, replacing or deleting a Suzaku file must have a refresh path.

Covers PLAN_SUZAKU_MULTI_DB.md Phase 4 (F-7, F-8). Superset stores one file
path per database connection, resolved at bootstrap, so a running dashboard
keeps reading whatever was there when it started. ``make resync`` — already the
documented "the data changed, fix the dashboard" command — now re-resolves the
Suzaku paths too.

No new ``make`` verb: ``test_no_new_make_verb_for_suzaku`` in
``test_makefile_suzaku.py`` encodes the principle that copying a file is the
whole workflow, and this phase keeps it.
"""

from __future__ import annotations

import yaml

from tests.conftest import COMPOSE_FILE, REPO_ROOT, run_make

RESYNC_SH = REPO_ROOT / "dashboard" / "init" / "resync.sh"


def _resync_service() -> dict:
    """Return the superset-resync service definition."""
    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    return compose["services"]["superset-resync"]


def _resync_calls() -> list[str]:
    """Return the script invocations in resync.sh."""
    return [
        line.strip()
        for line in RESYNC_SH.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("python3")
    ]


def test_resync_script_exists() -> None:
    """`make resync` needs one entrypoint that covers both kinds of metadata."""
    assert RESYNC_SH.is_file()


def test_resync_refreshes_the_cloudtrail_dataset() -> None:
    """The original job of `make resync` must survive the change."""
    assert any("register_dataset.py" in call for call in _resync_calls())


def test_resync_re_resolves_the_suzaku_paths() -> None:
    """Copying in a newer Suzaku run had no refresh path at all before."""
    assert any("register_suzaku_dbs.py" in call for call in _resync_calls())


def test_resync_scans_the_directory_once() -> None:
    """Same cost argument as bootstrap: one pass over 200 MB files, not three."""
    suzaku = [call for call in _resync_calls() if "register_suzaku_dbs.py" in call]
    assert len([call for call in suzaku if "--scan" in call]) == 1
    for call in suzaku:
        if "--scan" not in call:
            assert "--from" in call, f"{call} must reuse the saved inventory"


def test_resync_reports_what_it_selected() -> None:
    """After a re-resolve the user needs to see which file is now live."""
    assert any("--report" in call for call in _resync_calls())


def test_compose_runs_the_resync_script() -> None:
    """The service still has to start something; that something is resync.sh."""
    entrypoint = _resync_service()["entrypoint"]
    assert any("resync.sh" in str(part) for part in entrypoint)


def test_compose_mounts_everything_resync_imports() -> None:
    """A missing mount turns `make resync` into an ImportError at run time."""
    volumes = " ".join(_resync_service()["volumes"])
    for needed in (
        "register_dataset.py",
        "register_suzaku_dbs.py",
        "suzaku_db.py",
        "resync.sh",
    ):
        assert needed in volumes, f"superset-resync must mount {needed}"


def test_resync_never_opens_the_database_read_write() -> None:
    """Resync is a reader like every other service (CLAUDE.md access rules)."""
    volumes = _resync_service()["volumes"]
    db_mounts = [entry for entry in volumes if entry.endswith("/data/db:ro")]
    assert db_mounts, "the database directory must stay read-only"


def test_make_resync_still_uses_the_resync_profile() -> None:
    """The command the docs name must keep working unchanged."""
    recipe = run_make("resync")
    assert "--profile resync" in recipe
    assert "superset-resync" in recipe
