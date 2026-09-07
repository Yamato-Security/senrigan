#!/usr/bin/env python3
"""Point at ``make test-repo`` after editing a document the root suite asserts.

The root suite is what makes "one owner per fact" enforceable: it checks the
prose against the Makefile, the compose file, the hunt catalogues and the chart
bundles, and names the stale sentence. It only helps if it is run, and it is
cheap enough to run on every one of these edits.

The list is deliberately short. `doc/` prose is link-checked but carries no
counts, so a reminder there would be noise, and a hook that speaks on every
Markdown edit is a hook that gets tuned out.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _event import edited_path, relative_path, report  # noqa: E402

# Documents and artifacts whose contents `tests/` asserts against each other.
GUARDED_FILES = (
    "AGENTS.md",
    "CLAUDE.md",
    "README.md",
    "Makefile",
    "dashboard/README.md",
    "docker/docker-compose.yml",
    "agent/builtin_hunts.yaml",
    "agent/suzaku_timeline_hunts.yaml",
)
GUARDED_TREES = ("website/docs/",)


def is_guarded(relative: str) -> bool:
    """Return whether the root consistency suite asserts anything about a file."""
    return relative in GUARDED_FILES or relative.startswith(GUARDED_TREES)


def main() -> None:
    """Name the target that checks the file that was just edited."""
    path = edited_path()
    if path is None:
        return

    relative = relative_path(path)
    if relative is None or not is_guarded(relative):
        return

    report(
        f"{relative} is asserted by the repository consistency suite. "
        "Run `make test-repo` — it names the stale sentence."
    )


if __name__ == "__main__":
    main()
