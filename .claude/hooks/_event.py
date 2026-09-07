"""Shared entry point for the PostToolUse hooks.

Claude Code passes the tool event as JSON on stdin. Every hook here needs the
same two things from it — the edited file, resolved against the repository —
and every hook here must never fail the turn over its own bugs: a crashing
hook is reported to the user as a broken tool, which is worse than the rule it
was enforcing going unenforced.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


def edited_path() -> Path | None:
    """Return the file the tool event touched, or ``None`` if it names none."""
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return None

    file_path = (event.get("tool_input") or {}).get("file_path")
    return Path(file_path) if file_path else None


def relative_path(path: Path) -> str | None:
    """Return ``path`` relative to the repository root, or ``None`` if outside."""
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return None


def report(*lines: str) -> None:
    """Send a message to the agent and end the hook.

    Exit code 2 is the only PostToolUse channel the agent actually reads; the
    tool has already run, so this cannot and does not block anything.
    """
    print("\n".join(lines), file=sys.stderr)
    sys.exit(2)
