"""Tests for the two-tier ``make`` help surface.

Covers PLAN_MAKEFILE_UX.md Phase 1 (findings F-6 and F-9). ``make help`` is a
curated, hand-written front page; ``make help-all`` is generated from ``##@``
section headers and ``##`` target comments.
"""

from __future__ import annotations

import re

from tests.conftest import (
    declared_targets,
    documented_targets,
    help_output,
    help_sections,
    phony_targets,
)

# The commands a first-time user needs — PLAN_MAKEFILE_UX.md §2.1.
CORE_COMMANDS = ["ingest", "up", "down", "logs", "reset"]

# Contributor tooling and internal plumbing must not reach the front page.
HIDDEN_FROM_FRONT_PAGE = [
    "test",
    "test-repo",
    "lint",
    "fmt-check",
    "clippy",
    "build-ingester",
    "ensure-secret",
]


def test_help_shows_every_core_command():
    """The front page names each command a new user needs."""
    output = help_output("help")

    missing = [command for command in CORE_COMMANDS if f"make {command}" not in output]

    assert not missing, f"core commands absent from `make help`: {missing}"


def test_help_hides_contributor_and_internal_targets():
    """The front page stays free of dev tooling and plumbing (F-6, F-9)."""
    output = help_output("help")

    leaked = [name for name in HIDDEN_FROM_FRONT_PAGE if name in output]

    assert not leaked, f"`make help` should not mention: {leaked}"


def test_help_points_at_help_all():
    """A user who wants more is told exactly where to look."""
    assert "make help-all" in help_output("help")


def test_help_advertises_no_flags_or_variables():
    """The front page offers commands only — no flags, no VAR=value switches.

    PLAN_MAKEFILE_UX.md §2.3 resolves ingest options from the filesystem
    precisely so that the front page never has to teach a switch.
    """
    output = help_output("help")

    assert "--" not in output, "`make help` advertises a command-line flag"
    assert "=" not in output, "`make help` advertises a variable assignment"


def test_help_only_advertises_real_targets():
    """Every `make <target>` on the front page resolves to a real target."""
    targets = declared_targets()

    advertised = set(re.findall(r"\bmake ([a-z][a-z0-9-]*)\b", help_output("help")))
    phantom = sorted(advertised - targets)

    assert not phantom, f"`make help` advertises targets that do not exist: {phantom}"


def test_help_all_lists_every_documented_target():
    """`make help-all` is a complete inventory of the public surface."""
    output = help_output("help-all")

    missing = [name for name in documented_targets() if name not in output]

    assert not missing, f"targets missing from `make help-all`: {missing}"


def test_help_all_groups_are_declared_and_nonempty():
    """Every `##@` section header has at least one target under it."""
    sections = help_sections()

    assert sections, "no ##@ section headers found in the Makefile"

    empty = [name for name, targets in sections.items() if not targets]
    assert not empty, f"##@ sections with no targets: {empty}"


def test_every_documented_target_is_grouped():
    """No public target sits outside a `##@` section, where help-all would orphan it."""
    grouped = {target for targets in help_sections().values() for target in targets}

    ungrouped = sorted(set(documented_targets()) - grouped)

    assert not ungrouped, f"targets not under any ##@ section: {ungrouped}"


def test_every_documented_target_is_phony():
    """Public targets produce no file, so a stray same-named file must not shadow them."""
    missing = sorted(set(documented_targets()) - phony_targets())

    assert not missing, f"documented targets missing from .PHONY: {missing}"
