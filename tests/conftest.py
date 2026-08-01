"""Shared helpers for the repository-level consistency tests.

These tests span artifacts that no single module owns — the root ``Makefile``,
``docker/docker-compose.yml`` and the documentation under ``doc/`` and
``website/docs/`` — so they live in a repository-level suite rather than in one
of the per-module suites.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
MAKEFILE = REPO_ROOT / "Makefile"
COMPOSE_FILE = REPO_ROOT / "docker" / "docker-compose.yml"
ASSETS_DIR = REPO_ROOT / "dashboard" / "assets"
WEBSITE_DOCS = REPO_ROOT / "website" / "docs"
MKDOCS_FILE = REPO_ROOT / "website" / "mkdocs.yml"


def makefile_text() -> str:
    """Return the raw contents of the root Makefile."""
    return MAKEFILE.read_text(encoding="utf-8")


def make_database() -> str:
    """Return ``make``'s internal database (``make -pn``) as text.

    ``-n`` guarantees no recipe is executed, so these tests never touch Docker,
    the DuckDB file, or ``docker/.env``.
    """
    result = subprocess.run(
        ["make", "-pn"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout


def run_make(*args: str, env: dict[str, str] | None = None) -> str:
    """Expand a target with ``make -n`` and return the recipe it would run.

    ``-n`` guarantees no recipe is executed, so these tests never start a
    container or touch the DuckDB file.
    """
    result = subprocess.run(
        ["make", "-n", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, **(env or {})},
    )
    return result.stdout + result.stderr


def default_goal() -> str | None:
    """Return the goal ``make`` runs when invoked with no arguments."""
    match = re.search(r"^\.DEFAULT_GOAL := (\S+)$", make_database(), re.MULTILINE)
    return match.group(1) if match else None


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def help_output(*args: str) -> str:
    """Run a help target for real and return its output with ANSI stripped.

    Only the help targets are executed here. They print and nothing else — no
    prerequisites, no Docker, no writes to ``docker/.env``.
    """
    result = subprocess.run(
        ["make", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return _ANSI_RE.sub("", result.stdout)


def phony_targets() -> set[str]:
    """Return the target names listed in the Makefile's ``.PHONY`` block."""
    match = re.search(
        r"^\.PHONY:((?:[^\n\\]*\\\n)*[^\n]*)", makefile_text(), re.MULTILINE
    )
    if not match:
        return set()
    return set(match.group(1).replace("\\\n", " ").split())


def documented_targets() -> dict[str, str]:
    """Return ``{target: description}`` for every target carrying a ``##`` comment."""
    return {
        name: description.strip()
        for name, description in re.findall(
            r"^([a-zA-Z0-9][a-zA-Z0-9_-]*)\s*:[^=\n]*##\s*(.+)$",
            makefile_text(),
            re.MULTILINE,
        )
    }


def help_sections() -> dict[str, list[str]]:
    """Return ``{section: [target, ...]}`` as declared by ``##@`` headers."""
    sections: dict[str, list[str]] = {}
    current: str | None = None

    for line in makefile_text().splitlines():
        section = re.match(r"^##@\s*(.+)$", line)
        if section:
            current = section.group(1).strip()
            sections.setdefault(current, [])
            continue

        target = re.match(r"^([a-zA-Z0-9][a-zA-Z0-9_-]*)\s*:[^=\n]*##\s", line)
        if target and current is not None:
            sections[current].append(target.group(1))

    return sections


def declared_targets() -> set[str]:
    """Return every target name defined in the Makefile.

    Parsed from the file rather than from ``make -p`` so the result is limited
    to targets this repository declares, excluding make's built-in rules.
    """
    targets: set[str] = set()
    for line in makefile_text().splitlines():
        match = re.match(r"^([a-zA-Z0-9][a-zA-Z0-9_-]*)\s*:(?!=)", line)
        if match:
            targets.add(match.group(1))
    return targets


def variable_definitions() -> dict[str, str]:
    """Return the Makefile's simple variable assignments (``:=`` / ``?=``)."""
    return {
        name: value.strip()
        for name, value in re.findall(
            r"^([A-Z][A-Z0-9_]*)\s*[:?]=\s*(.*)$", makefile_text(), re.MULTILINE
        )
    }


def expand_variables(value: str) -> str:
    """Expand ``$(VAR)`` references using the Makefile's own definitions."""
    definitions = variable_definitions()
    for _ in range(5):  # bounded to avoid looping on a self-referential value
        expanded = re.sub(
            r"\$[({]([A-Z][A-Z0-9_]*)[)}]",
            lambda m: definitions.get(m.group(1), m.group(0)),
            value,
        )
        if expanded == value:
            break
        value = expanded
    return value


def doc_files() -> list[Path]:
    """Return every Markdown file that documents current, real behaviour.

    ``PLAN_*`` and ``PRD*`` documents are excluded: they describe proposed or
    hypothetical state, so a target they name is not expected to exist yet.
    """
    paths = sorted(REPO_ROOT.glob("*.md"))
    paths += sorted((REPO_ROOT / "doc").rglob("*.md"))
    paths += sorted((REPO_ROOT / "website" / "docs").rglob("*.md"))
    return [
        path for path in paths if not path.name.startswith(("PLAN_", "PRD_", "PRD."))
    ]


# ``make`` followed by a target name, inside a fenced block, an inline code
# span, or an HTML <code> element.
_CODE_SPAN_RE = re.compile(
    r"```.*?```|`[^`\n]+`|<code>.*?</code>", re.DOTALL | re.IGNORECASE
)
_MAKE_CALL_RE = re.compile(r"\bmake\s+([a-z][a-z0-9-]*)\b")


def chart_names(bundle: str) -> set[str]:
    """Return the ``slice_name`` of every chart in a dashboard asset bundle.

    The YAML directory is the source of truth: the ZIP is built from it, and
    ``dashboard/tests/`` already fails when the two disagree.
    """
    return {
        yaml.safe_load(path.read_text(encoding="utf-8"))["slice_name"].strip()
        for path in (ASSETS_DIR / bundle / "charts").glob("*.yaml")
    }


def dataset_names(bundle: str) -> set[str]:
    """Return the dataset names declared by a dashboard asset bundle."""
    return {path.stem for path in (ASSETS_DIR / bundle / "datasets").rglob("*.yaml")}


def hunt_labels(filename: str) -> list[str]:
    """Return the ``label`` of every hunt in one of the agent's hunt catalogues."""
    entries = yaml.safe_load((REPO_ROOT / "agent" / filename).read_text("utf-8"))
    return [entry["label"].strip() for entry in entries]


def hunt_categories(filename: str) -> set[str]:
    """Return the distinct ``category`` of one of the agent's hunt catalogues."""
    entries = yaml.safe_load((REPO_ROOT / "agent" / filename).read_text("utf-8"))
    return {entry["category"].strip() for entry in entries}


def site_locales() -> list[str]:
    """Return the locale codes the documentation site builds, default first.

    Read from ``mkdocs.yml`` rather than hardcoded so adding a language to the
    site is a single-file change.
    """
    return re.findall(r"^\s*- locale: (\S+)$", MKDOCS_FILE.read_text("utf-8"), re.M)


def make_calls_in(text: str) -> set[str]:
    """Extract target names invoked as ``make <target>`` in documentation.

    Prose routinely contains phrases such as "make a bucket public", so a bare
    ``make <word>`` match is not enough. A match counts when it is either
    inside code markup, or hyphenated — English prose does not produce
    hyphenated tokens in this position, while every multi-word target does.
    """
    calls: set[str] = set()

    for code in _CODE_SPAN_RE.findall(text):
        calls.update(_MAKE_CALL_RE.findall(code))

    for target in _MAKE_CALL_RE.findall(text):
        if "-" in target:
            calls.add(target)

    return calls
