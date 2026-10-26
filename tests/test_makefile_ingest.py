"""Tests for filesystem-driven ingest options and the consolidated logs target.

`make ingest` reads the directories the compose bind mounts already point at
and enables the matching ingester options itself, so the front page never has
to teach a switch.

Every test overrides both host-path variables at an empty or fabricated
directory. Without that the result would depend on whether the developer
running the suite happens to have GeoLite2 files in docker/data/geoip/.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.conftest import declared_targets, run_make

# Targets that predate the consolidation. They keep working so existing docs,
# scripts, and muscle memory do not break.
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


# ── VPC Flow Logs in the same tree ─────────────────────────────────────────
#
# Flow logs are detected when the recipe runs, not when the Makefile is parsed:
# a parse-time `find` would walk a possibly huge docker/logs/ on every `make`.
# `make -n` prints the recipe, so these assert on what it would run.


def test_ingest_proceeds_on_flow_logs_alone(geoip_dir: Path, config_dir: Path):
    """A Flow-Logs-only S3 copy must not be refused as "no logs found"."""
    recipe = ingest_recipe(geoip_dir, config_dir)

    assert "-name '*_vpcflowlogs_*.log.gz'" in recipe
    assert "No CloudTrail or VPC Flow Logs found" in recipe


def test_ingest_announces_flow_logs(geoip_dir: Path, config_dir: Path):
    """Detection says so, like the GeoIP and Config lines beside it."""
    recipe = ingest_recipe(geoip_dir, config_dir)

    assert "VPC Flow Logs found in" in recipe


def test_no_logs_hint_syncs_the_whole_awslogs_prefix(geoip_dir: Path, config_dir: Path):
    """The hint copies everything; the ingester routes and skips per file."""
    recipe = ingest_recipe(geoip_dir, config_dir)

    assert "aws s3 sync s3://<your-bucket>/AWSLogs/" in recipe
    assert '--include "*.json.gz"' not in recipe


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


# ── The ingester image must match the source it documents ─────────────────
#
# `make ingest` used to run whatever ingester image was already built — by
# default a downloaded release binary — so a release that predated a feature
# (VPC Flow Logs) silently skipped its files while the Makefile announced them.

INGESTER_TARGETS = ["ingest", "ingest-full", "ingest-geoip", "ingest-config", "enrich"]


@pytest.mark.parametrize("target", INGESTER_TARGETS)
def test_every_ingester_target_rebuilds_the_image_first(
    target: str, geoip_dir: Path, config_dir: Path
):
    """A build before the first run brings a stale image in line with compose."""
    recipe = run_make(
        target,
        env={"GEOIP_HOST_PATH": str(geoip_dir), "CONFIG_HOST_PATH": str(config_dir)},
    )
    lines = recipe.splitlines()
    builds = [i for i, line in enumerate(lines) if "build ingester" in line]
    runs = [i for i, line in enumerate(lines) if "run --rm ingester" in line]
    assert runs, f"`make {target}` runs no ingester"
    assert builds and builds[0] < runs[0], f"`make {target}` runs before building"


def test_ingest_refuses_flow_logs_with_an_ingester_that_cannot_read_them(
    geoip_dir: Path, config_dir: Path
):
    """An older ingester would skip every flow log file and still exit 0."""
    recipe = ingest_recipe(geoip_dir, config_dir)

    version_lines = [line for line in recipe.splitlines() if "--version" in line]
    assert version_lines
    # BuildKit writes its progress to stdout when stdout is captured, which
    # would bury the version string the guard reads.
    assert all("--build" not in line for line in version_lines)
    assert "predates VPC Flow Logs support" in recipe
    assert "INGESTER_BUILD_TARGET=runtime" in recipe


def test_prebuilt_ingester_version_matches_the_crate():
    """The release the compose file downloads must be the version the source declares."""
    from tests.conftest import REPO_ROOT

    cargo = (REPO_ROOT / "ingester" / "Cargo.toml").read_text(encoding="utf-8")
    crate_version = re.search(r'^version\s*=\s*"([^"]+)"', cargo, re.MULTILINE).group(1)
    compose = (REPO_ROOT / "docker" / "docker-compose.yml").read_text(encoding="utf-8")
    pinned = re.search(r"INGESTER_VERSION:-(v[\d.]+)\}", compose).group(1)

    assert pinned == f"v{crate_version}"


def test_docker_build_context_excludes_cargo_target():
    """`run --build` sends the context on every ingest; target/ is gigabytes."""
    from tests.conftest import REPO_ROOT

    ignored = (
        (REPO_ROOT / "ingester" / ".dockerignore").read_text(encoding="utf-8").split()
    )
    assert "target" in ignored or "target/" in ignored
