"""Tests keeping the 15 localized Getting Started pages in step with the Makefile.

Covers PLAN_MAKEFILE_UX.md Phase 4. Translations drift silently: a locale can
fall a revision behind and nobody notices until a user follows it. These tests
check structure and command names, which are identical across locales, and say
nothing about the prose, which is not.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT

GETTING_STARTED = sorted(
    (REPO_ROOT / "website" / "docs" / "getting-started").glob("index*.md")
)

# The order matters: it is the order the front page of `make` presents them in.
CORE_COMMANDS = ["make ingest", "make up", "make down", "make logs", "make reset"]

# Superseded by filesystem detection in Phase 2. Still valid targets, but the
# quick start must not send a newcomer down the explicit-override path.
SUPERSEDED = ["make ingest-geoip", "make ingest-config", "make ingest-full"]


def test_every_locale_is_present():
    """A missing locale would silently fall back to English."""
    assert (
        len(GETTING_STARTED) == 15
    ), f"expected 15 locales, found {len(GETTING_STARTED)}"


@pytest.mark.parametrize("path", GETTING_STARTED, ids=lambda p: p.name)
def test_locale_lists_the_core_commands_in_order(path: Path):
    """Each locale documents the same five commands, in the same order."""
    text = path.read_text(encoding="utf-8")
    found = re.findall(r"`(make [a-z-]+)`", text)
    ordered = [cmd for cmd in found if cmd in CORE_COMMANDS]

    # Deduplicate while preserving first appearance.
    seen: list[str] = []
    for cmd in ordered:
        if cmd not in seen:
            seen.append(cmd)

    assert seen == CORE_COMMANDS, f"{path.name} lists {seen}"


@pytest.mark.parametrize("path", GETTING_STARTED, ids=lambda p: p.name)
def test_locale_does_not_teach_superseded_ingest_commands(path: Path):
    """GeoIP and Config are detected from disk; the quick start says so."""
    text = path.read_text(encoding="utf-8")

    leaked = [cmd for cmd in SUPERSEDED if cmd in text]
    assert not leaked, f"{path.name} still instructs: {leaked}"


@pytest.mark.parametrize("path", GETTING_STARTED, ids=lambda p: p.name)
def test_locale_names_both_auto_detected_directories(path: Path):
    """Placing files is now the whole instruction, so the paths must be right."""
    text = path.read_text(encoding="utf-8")

    assert "docker/data/geoip/" in text
    assert "docker/data/config-snapshots/" in text


@pytest.mark.parametrize("path", GETTING_STARTED, ids=lambda p: p.name)
def test_locale_has_four_quick_start_steps(path: Path):
    """Structural parity: every locale numbers the same four steps."""
    text = path.read_text(encoding="utf-8")
    steps = re.findall(r"^\*\*[^*]*?(\d)[^*]*?\*\*", text, re.MULTILINE)

    assert steps == ["1", "2", "3", "4"], f"{path.name} has steps {steps}"
