#!/usr/bin/env python3
"""Rebuild suzaku_timeline.zip — the Suzaku detection timeline dashboard.

Currently an empty template: database + virtual dataset + an importable shell
with no charts. The charts are drafted in a separate PR; adding them means adding
entries to :data:`FILE_MAP` and to ``suzaku_timeline/dashboard.yaml``'s position.

Run after editing anything under ``suzaku_timeline/``, then re-import:

    python3 rebuild_suzaku_timeline_zip.py
    cd ../../docker && docker compose run --rm superset-init
"""

from __future__ import annotations

import os

from zip_builder import build_zip

BASE = os.path.dirname(os.path.abspath(__file__))
SOURCE_DIR = os.path.join(BASE, "suzaku_timeline")
OUTPUT_ZIP = os.path.join(BASE, "suzaku_timeline.zip")

# Map: source path (relative to SOURCE_DIR) -> arc path inside the ZIP.
FILE_MAP = {
    "metadata.yaml": "metadata.yaml",
    "dashboard.yaml": "dashboards/suzaku_detection_timeline.yaml",
    "databases/Suzaku_Timeline_DuckDB.yaml": ("databases/Suzaku_Timeline_DuckDB.yaml"),
    "datasets/suzaku_timeline.yaml": (
        "datasets/Suzaku_Timeline_DuckDB/suzaku_timeline.yaml"
    ),
    # charts/: intentionally empty — see the module docstring.
}


def main() -> None:
    """Rebuild the ZIP from the FILE_MAP sources."""
    build_zip(SOURCE_DIR, OUTPUT_ZIP, FILE_MAP)


if __name__ == "__main__":
    main()
