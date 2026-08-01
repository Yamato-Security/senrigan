"""Tests keeping structural documentation pointed at things that exist.

Covers PLAN_DOCS_REFRESH.md Phase 1. The repository map in ``AGENTS.md`` and the
link web across ``doc/`` are what an agent reads before it opens any source
file, so a path that moved or a document that was never committed sends the
next session looking in the wrong place. Nothing here reads prose — only paths,
links and command names, which are mechanical enough to check.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT, help_output

# Files whose relative links must resolve. The website is excluded: MkDocs
# resolves its links against the site tree, not the filesystem.
LINKING_DOCS = sorted(
    {
        REPO_ROOT / "README.md",
        REPO_ROOT / "CLAUDE.md",
        REPO_ROOT / "AGENTS.md",
        *(REPO_ROOT / "doc").glob("*.md"),
        *REPO_ROOT.glob("*/AGENTS.md"),
        *REPO_ROOT.glob("*/README.md"),
    }
)

# Files carrying an ASCII tree of the repository.
TREE_DOCS = [REPO_ROOT / "AGENTS.md", REPO_ROOT / "CLAUDE.md"]

# The two files an agent reads before touching anything. They describe the same
# repository twice, so they are the pair most likely to disagree.
AGENT_CONTEXT_DOCS = [REPO_ROOT / "AGENTS.md", REPO_ROOT / "CLAUDE.md"]

# `├── name` / `└── name`, preceded by one four-character unit per nesting level.
_TREE_ENTRY_RE = re.compile(r"^((?:[│ ]   )*)(?:├──|└──) (\S+)")
_MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")


def tree_paths(text: str) -> list[str]:
    """Return every path an ASCII repository tree in ``text`` describes.

    Nesting is reconstructed from the indent, so a file is reported with its
    full path rather than its bare name — the whole point is to catch an entry
    that exists somewhere else in the repository but not where the tree says.
    """
    paths: list[str] = []
    stack: list[str] = []

    for line in text.splitlines():
        entry = _TREE_ENTRY_RE.match(line)
        if not entry:
            continue

        depth = len(entry.group(1)) // 4
        name = entry.group(2).rstrip("/")
        del stack[depth:]
        stack.append(name)
        paths.append("/".join(stack))

    return paths


@pytest.mark.parametrize("doc", TREE_DOCS, ids=lambda p: p.name)
def test_repository_tree_describes_paths_that_exist(doc: Path):
    """Every entry in the tree resolves against the working tree."""
    documented = tree_paths(doc.read_text(encoding="utf-8"))
    assert documented, f"{doc.name} has no parseable repository tree"

    missing = [path for path in documented if not (REPO_ROOT / path).exists()]
    assert not missing, f"{doc.name} points at paths that do not exist: {missing}"


@pytest.mark.parametrize(
    "doc", LINKING_DOCS, ids=lambda p: str(p.relative_to(REPO_ROOT))
)
def test_relative_links_resolve(doc: Path):
    """A link to an uncommitted or renamed document is a dead end for the reader."""
    broken = []
    for target in _MARKDOWN_LINK_RE.findall(doc.read_text(encoding="utf-8")):
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        if "/" not in target and "." not in target:
            continue  # a placeholder such as `[T1562.008 — …](url)`, not a path
        path = doc.parent / target.split("#", 1)[0]
        if not path.exists():
            broken.append(target)

    assert not broken, f"{doc.name} links to missing files: {broken}"


def default_help_targets() -> list[str]:
    """Return the commands ``make`` offers when invoked with no arguments.

    The trailing ``More:`` line points at ``make help-all``; it is signposting
    rather than one of the commands being taught, so it is left out.
    """
    body = [line for line in help_output().splitlines() if "More:" not in line]
    return re.findall(r"\bmake ([a-z][a-z0-9-]*)\b", "\n".join(body))


def essential_commands_block(doc: Path) -> list[str]:
    """Return the targets in the first code block under `## Essential Commands`."""
    section = re.search(
        r"^## Essential Commands\n(.*?)^## ",
        doc.read_text(encoding="utf-8"),
        re.MULTILINE | re.DOTALL,
    )
    assert section, f"{doc.name} has no Essential Commands section"

    block = re.search(r"```bash\n(.*?)```", section.group(1), re.DOTALL)
    assert block, f"{doc.name}: Essential Commands opens with no bash block"

    return re.findall(r"^make ([a-z][a-z0-9-]*)", block.group(1), re.MULTILINE)


@pytest.mark.parametrize("doc", AGENT_CONTEXT_DOCS, ids=lambda p: p.name)
def test_essential_commands_are_the_ones_make_actually_prints(doc: Path):
    """Both files present this block as what bare `make` shows. It must be.

    Targets that exist but are not on the front page — `status`, `resync`,
    `check` — belong in their own block, so an agent reading this one can quote
    it back to a user without being wrong about what they will see.
    """
    assert essential_commands_block(doc) == default_help_targets()


@pytest.mark.parametrize("doc", AGENT_CONTEXT_DOCS, ids=lambda p: p.name)
def test_documented_command_count_matches_the_block(doc: Path):
    """The prose counts the commands ("the five commands below"); so must we."""
    words = {"three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8}

    match = re.search(
        r"prints the ([a-z]+)\s+(?:user-facing\s+)?commands",
        doc.read_text(encoding="utf-8"),
    )
    assert match, f"{doc.name} no longer states how many commands `make` prints"
    assert words[match.group(1)] == len(essential_commands_block(doc))
