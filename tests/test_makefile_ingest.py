"""Tests for filesystem-driven ingest options and the consolidated logs target.

Covers PLAN_MAKEFILE_UX.md Phase 2 (finding F-5). `make ingest` reads the
directories the compose bind mounts already point at and enables the matching
ingester options itself, so the front page never has to teach a switch.

Every test overrides both host-path variables at an empty or fabricated
directory. Without that the result would depend on whether the developer
running the suite happens to have GeoLite2 files in docker/data/geoip/.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import declared_targets, run_make

# Targets that predate the consolidation. PLAN_MAKEFILE_UX.md §2.3.1 keeps them
# working so existing docs, scripts, and muscle memory do not break.
LEGACY_TARGETS = [
    "ingest-full",
    "ingest-geoip",
    "config-import",
    "enrich",
    "logs-agent",
    "logs-config-viz",
    "logs-superset",
    "ps",
]


@pytest.fixture
def geoip_dir(tmp_path: Path) -> Path:
    """An empty stand-in for docker/data/geoip/."""
    path = tmp_path / "geoip"
    path.mkdir()
    return path


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    """An empty stand-in for docker/data/config-snapshots/."""
    path = tmp_path / "config-snapshots"
    path.mkdir()
    return path


def ingest_recipe(geoip_dir: Path, config_dir: Path) -> str:
    """Expand `make ingest` with detection pointed at the given directories."""
    return run_make(
        "ingest",
        env={
            "GEOIP_HOST_PATH": str(geoip_dir),
            "CONFIG_HOST_PATH": str(config_dir),
        },
    )


# ── Legacy surface ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("target", LEGACY_TARGETS)
def test_legacy_targets_still_resolve(target: str):
    """Consolidation removes nothing: every prior target still runs."""
    assert target in declared_targets()

    recipe = run_make(target)
    assert "docker compose" in recipe, f"`make {target}` expanded to nothing useful"


# ── GeoIP detection ────────────────────────────────────────────────────────


def test_geoip_detected_when_mmdb_present(geoip_dir: Path, config_dir: Path):
    """City and ASN databases on disk switch on the matching flags."""
    (geoip_dir / "GeoLite2-City.mmdb").touch()
    (geoip_dir / "GeoLite2-ASN.mmdb").touch()

    recipe = ingest_recipe(geoip_dir, config_dir)

    assert "--geoip-city" in recipe
    assert "--geoip-asn" in recipe


def test_geoip_absent_adds_no_flags(geoip_dir: Path, config_dir: Path):
    """An empty geoip directory produces a plain ingest — and says so.

    A silent skip is the main failure mode of auto-detection: it is how users
    end up staring at blank GeoIP charts (PRD_DASHBOARD_REVIEW.md F-11).
    """
    recipe = ingest_recipe(geoip_dir, config_dir)

    assert "--geoip-" not in recipe
    assert "IP enrichment skipped" in recipe


def test_country_only_falls_back_to_country_database(geoip_dir: Path, config_dir: Path):
    """Country-only installs still get enrichment, via an .mmdb file path.

    The file path matters: passing the directory is exactly the bug fixed in
    Phase 0 (F-3), and this pins it shut on the detection path too.
    """
    (geoip_dir / "GeoLite2-Country.mmdb").touch()

    recipe = ingest_recipe(geoip_dir, config_dir)

    assert "--geoip-country" in recipe
    assert "GeoLite2-Country.mmdb" in recipe


def test_city_wins_over_country(geoip_dir: Path, config_dir: Path):
    """City supersedes Country; the ingester ignores Country when City is set."""
    (geoip_dir / "GeoLite2-City.mmdb").touch()
    (geoip_dir / "GeoLite2-Country.mmdb").touch()

    recipe = ingest_recipe(geoip_dir, config_dir)

    assert "--geoip-city" in recipe
    assert "--geoip-country" not in recipe


def test_detection_honours_host_path_override(geoip_dir: Path, config_dir: Path):
    """Detection follows GEOIP_HOST_PATH, matching the compose bind mount.

    The repository's own docker/data/geoip/ may well contain databases; this
    passes only if the override is what actually drives detection.
    """
    recipe = ingest_recipe(geoip_dir, config_dir)

    assert "--geoip-" not in recipe
    assert str(geoip_dir) in recipe


# ── AWS Config snapshot detection ──────────────────────────────────────────


def test_config_snapshots_trigger_import(geoip_dir: Path, config_dir: Path):
    """Populated snapshot directory means `ingest` imports it too."""
    (config_dir / "snapshot.json").touch()

    recipe = ingest_recipe(geoip_dir, config_dir)

    assert "config-import" in recipe


def test_no_config_snapshots_means_no_import(geoip_dir: Path, config_dir: Path):
    """An empty snapshot directory adds no second pass."""
    recipe = ingest_recipe(geoip_dir, config_dir)

    assert "config-import" not in recipe


# ── Consolidated logs target ───────────────────────────────────────────────


def test_logs_tails_all_services_by_default():
    """`make logs` with no SERVICE follows every container."""
    recipe = run_make("logs")

    assert "docker compose logs -f" in recipe


def test_logs_accepts_a_single_service():
    """`make logs SERVICE=agent` narrows to one container."""
    assert "logs -f agent" in run_make("logs", "SERVICE=agent")


def test_per_service_log_targets_delegate_to_logs():
    """The legacy per-service targets resolve to the same command."""
    assert "logs -f agent" in run_make("logs-agent")
    assert "logs -f config-viz" in run_make("logs-config-viz")
    assert "logs -f superset" in run_make("logs-superset")
