"""Guards on the committed Suzaku DuckDB fixtures.

Covers PLAN_SUZAKU_VIEWS.md Phase 0. Suzaku's real output is hundreds of
megabytes and its file extension (``.duckdb``) was not covered by ``.gitignore``,
so a routine ``git add`` could have written a 247 MiB database into history.
These tests keep the trimmed fixtures small and keep the ignore rules that make
the full-size files unstageable.
"""

from __future__ import annotations

import subprocess

import duckdb
import pytest

from tests.conftest import REPO_ROOT

FIXTURE_DIR = REPO_ROOT / "sample" / "suzaku" / "fixtures"
GENERATOR = REPO_ROOT / "sample" / "suzaku" / "generate_fixtures.py"

FIXTURES = [
    "suzaku-aws-ct-timeline.duckdb",
    "suzaku-aws-ct-summary.duckdb",
    "suzaku-aws-ct-metrics.duckdb",
]

# A fixture this size cannot be a full-size Suzaku run (the reference timeline
# output is 236 MiB) but comfortably fits a Level-balanced sample.
MAX_FIXTURE_BYTES = 5 * 1024 * 1024
MAX_TOTAL_BYTES = 10 * 1024 * 1024

# Every severity must survive trimming: a fixture without `critical` rows would
# let a severity-ordering regression pass unnoticed.
EXPECTED_LEVELS = {"critical", "high", "medium", "low", "informational"}


def _is_ignored(relative_path: str) -> bool:
    """Return whether git would ignore *relative_path*.

    The path need not exist — ``git check-ignore`` matches patterns, not files,
    which lets these tests ask about a hypothetical full-size database.
    """
    result = subprocess.run(
        ["git", "check-ignore", "-q", relative_path],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


@pytest.mark.parametrize("name", FIXTURES)
def test_fixture_exists(name: str) -> None:
    """Both test suites read these files; a missing one is a hard failure."""
    assert (
        FIXTURE_DIR / name
    ).exists(), (
        f"{name} missing — regenerate with: python3 {GENERATOR.relative_to(REPO_ROOT)}"
    )


@pytest.mark.parametrize("name", FIXTURES)
def test_fixture_is_small(name: str) -> None:
    """A fixture over this size means a full-size run was committed by mistake."""
    size = (FIXTURE_DIR / name).stat().st_size
    assert size <= MAX_FIXTURE_BYTES, (
        f"{name} is {size / 1024 / 1024:.1f} MiB — regenerate it with "
        f"{GENERATOR.name} instead of committing a full-size Suzaku run"
    )


def test_fixture_directory_stays_small() -> None:
    """The whole fixture set has to stay cheap to clone."""
    total = sum((FIXTURE_DIR / name).stat().st_size for name in FIXTURES)
    assert total <= MAX_TOTAL_BYTES


@pytest.mark.parametrize("name", FIXTURES)
def test_fixture_is_stageable(name: str) -> None:
    """The ignore-rule negation must let the fixtures into git.

    ``*.duckdb`` is ignored repository-wide, so without the negation for this
    directory the fixtures would be silently unstageable and CI would fail on a
    fresh clone.
    """
    assert not _is_ignored(f"sample/suzaku/fixtures/{name}")


def test_full_size_duckdb_files_are_ignored() -> None:
    """A Suzaku run dropped next to the fixtures must not be stageable."""
    assert _is_ignored("sample/suzaku/sample-aws-ct-timeline.duckdb")
    assert _is_ignored("docker/data/db/timeline.duckdb")


def test_suzaku_text_exports_are_ignored() -> None:
    """Suzaku's CSV/JSON exports are as large as its databases (1.3 GB observed)."""
    assert _is_ignored("sample/timeline.csv")
    assert _is_ignored("sample/timeline.json")


def test_fixture_generator_is_present_and_stageable() -> None:
    """Fixtures are only reproducible if the script that derives them ships."""
    generator = "sample/suzaku/generate_fixtures.py"
    assert (REPO_ROOT / generator).exists()
    assert not _is_ignored(generator)


def test_timeline_fixture_covers_every_level() -> None:
    """Severity-ordering logic is only exercised if every Level is present."""
    conn = duckdb.connect(str(FIXTURE_DIR / FIXTURES[0]), read_only=True)
    try:
        levels = {
            level
            for (level,) in conn.execute(
                'SELECT DISTINCT "Level" FROM timeline'
            ).fetchall()
        }
    finally:
        conn.close()
    assert levels == EXPECTED_LEVELS
