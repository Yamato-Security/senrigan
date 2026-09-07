#!/usr/bin/env python3
"""Format an edited file the way CI will check it.

`make check` runs `black --check .`, `ruff check .` and `cargo fmt --check`,
and CLAUDE.md asks for zero warnings. Doing it here means the gate is never
reached in a failing state, and the agent never spends a turn on formatting.

Every failure is swallowed on purpose. Mid-edit files do not parse, formatters
are not always installed, and neither is a reason to report a broken tool to
the user.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _event import REPO_ROOT, edited_path, relative_path  # noqa: E402


def run(*command: str, timeout: int = 60) -> None:
    """Run a formatter, discarding its output and any way it can fail."""
    try:
        subprocess.run(
            command,
            cwd=REPO_ROOT,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def main() -> None:
    """Dispatch on the edited file's language."""
    path = edited_path()
    if path is None or not path.is_file():
        return

    if path.suffix == ".py":
        run("black", "--quiet", str(path))
        run("ruff", "check", "--quiet", "--fix", str(path))
        return

    relative = relative_path(path)
    if path.suffix == ".rs" and relative and relative.startswith("ingester/"):
        # rustfmt is per-crate, not per-file; this is the crate that owns it.
        run("cargo", "fmt", "--manifest-path", "ingester/Cargo.toml", timeout=180)


if __name__ == "__main__":
    main()
