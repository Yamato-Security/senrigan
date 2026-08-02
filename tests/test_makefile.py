"""Consistency tests for the root Makefile and the docs that reference it.

The failure mode these guard against is drift: a target gets renamed, or a
documented host path stops matching the compose bind mount, and nothing notices
until a user runs a command that does not exist.
"""

from __future__ import annotations

import re

import yaml

from tests.conftest import (
    COMPOSE_FILE,
    default_goal,
    declared_targets,
    doc_files,
    expand_variables,
    make_calls_in,
    makefile_text,
)

# ── F-1: bare `make` must help, not act ────────────────────────────────────


def test_default_goal_is_help():
    """`make` with no arguments shows help instead of running the first rule."""
    assert default_goal() == "help"


# ── F-2: every documented target must exist ────────────────────────────────


def test_every_make_command_in_docs_exists():
    """No documentation tells a user to run a target the Makefile lacks."""
    targets = declared_targets()
    missing: list[str] = []

    for path in doc_files():
        for call in sorted(make_calls_in(path.read_text(encoding="utf-8"))):
            if call not in targets:
                missing.append(
                    f"{path.relative_to(COMPOSE_FILE.parent.parent)}: make {call}"
                )

    assert not missing, "documented targets that do not exist:\n" + "\n".join(missing)


# ── F-3: GeoIP flags take .mmdb files, never directories ───────────────────


def test_geoip_flags_point_at_mmdb_files():
    """`--geoip-*` takes a path to a database file; the CLI does no dir walk.

    See ingester/src/main.rs — resolve_geoip_paths() falls back to environment
    variables only, so a directory argument reaches maxminddb and fails.
    """
    offenders: list[str] = []

    for line in makefile_text().splitlines():
        if line.lstrip().startswith("#"):
            continue  # prose about the flags, not a use of them

        # The value is either a literal path or a $(VAR) reference. It ends at
        # the comma or paren of an enclosing $(if ...), not just at whitespace.
        for flag, value in re.findall(
            r"(--geoip-(?:city|country|asn))\s+((?:\$\([A-Z_]+\)|[^\s,)])+)", line
        ):
            if not expand_variables(value).endswith(".mmdb"):
                offenders.append(f"{flag} {value}")

    assert not offenders, "GeoIP flags not pointing at an .mmdb file: " + ", ".join(
        offenders
    )


# ── F-4: documented host paths must match the compose bind mounts ──────────


def _ingester_bind_sources() -> set[str]:
    """Return the ingester service's host-side bind-mount paths.

    Normalised to repo-relative form, with ``${VAR:-default}`` reduced to its
    default so the result matches what the documentation tells users.
    """
    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    sources: set[str] = set()

    for volume in compose["services"]["ingester"]["volumes"]:
        # Resolve ${VAR:-default} before splitting; it contains a colon itself.
        resolved = re.sub(r"\$\{[A-Z_]+:-(.*?)\}", r"\1", volume)
        host = resolved.split(":")[0]
        sources.add("docker/" + host.removeprefix("./"))

    return sources


def test_documented_data_dirs_are_real_bind_mounts():
    """Every `docker/data/...` path in the docs sits in a real ingester mount.

    A path qualifies when it is a mount point or lives inside one — docs refer
    to both the directory (`docker/data/geoip/`) and files within it
    (`docker/data/db/threat_hunting.db`).
    """
    mounts = _ingester_bind_sources()
    offenders: list[str] = []

    for path in doc_files():
        text = path.read_text(encoding="utf-8")
        for mentioned in set(re.findall(r"\bdocker/data/[a-z0-9._/-]*", text)):
            cleaned = mentioned.rstrip("/")
            if not any(
                cleaned == mount or cleaned.startswith(mount + "/") for mount in mounts
            ):
                offenders.append(f"{path.name}: {mentioned}")

    assert not offenders, "documented paths that are not bind mounts:\n" + "\n".join(
        sorted(offenders)
    )


def test_config_snapshots_are_not_documented_under_the_logs_mount():
    """AWS Config snapshots live in their own mount, not inside docker/logs/.

    `docker/logs` is mounted read-only at /data/logs for CloudTrail; Config
    snapshots are a separate mount at /data/config. Files placed under
    docker/logs/config/ are never seen by `config-import`.
    """
    offenders = [
        path.name
        for path in doc_files()
        if "docker/logs/config" in path.read_text(encoding="utf-8")
    ]

    assert not offenders, (
        "docs telling users to put Config snapshots under the CloudTrail "
        "mount: " + ", ".join(sorted(offenders))
    )
