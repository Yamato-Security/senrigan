#!/usr/bin/env python3
"""Interrupt an edit under ``dashboard/assets/`` that stops at the YAML.

Superset never reads the asset directories: it imports the compiled ZIPs, and
only the one-shot ``superset-init`` container imports them. So editing a chart
definition — or rebuilding the ZIP without re-importing — leaves the running
dashboard serving the old chart, with no error anywhere to say so. This is the
repository's one failure mode that looks exactly like success.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _event import edited_path, relative_path, report  # noqa: E402


def main() -> None:
    """Report the two remaining steps when an asset source file was edited."""
    path = edited_path()
    if path is None:
        return

    relative = relative_path(path)
    if relative is None or not relative.startswith("dashboard/assets/"):
        return

    if relative.endswith(".zip"):
        return  # A ZIP is a build artifact; editing one is denied, not reminded.

    report(
        f"{relative} was edited. Superset imports the compiled ZIPs, so this "
        "changes nothing in a running dashboard until both steps run:",
        "  cd dashboard/assets && python3 rebuild_zip.py && "
        "python3 rebuild_rare_zip.py   # or rebuild_suzaku_<name>_zip.py",
        "  cd ../../docker && docker compose run --rm superset-init",
    )


if __name__ == "__main__":
    main()
