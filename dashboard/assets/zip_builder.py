#!/usr/bin/env python3
"""Shared ZIP packaging for Superset asset bundles.

Superset's v1 import format expects a flat layout with no top-level directory::

    metadata.yaml
    dashboards/<slug>.yaml
    charts/<slice_name>.yaml
    datasets/<db_name>/<table_name>.yaml
    databases/<db_name>.yaml

Each bundle keeps an explicit source → arc-name map rather than globbing: the arc
names are part of the import contract, and an explicit map also makes "a chart
YAML exists but is not shipped" a testable condition.

Output is byte-deterministic — fixed ZipInfo timestamps and no compression
timestamps — so rebuilding an unchanged bundle produces a zero git diff, which
is what makes "did someone forget to rebuild the ZIP?" visible in review.
"""

from __future__ import annotations

import os
import zipfile

# Fixed timestamp for every entry (1980-01-01), the earliest a ZIP can express.
# Without it, mtimes leak into the archive and every rebuild is a diff.
FIXED_DATE_TIME = (1980, 1, 1, 0, 0, 0)


def build_zip(
    source_dir: str,
    output_zip: str,
    file_map: dict[str, str],
    *,
    verbose: bool = True,
) -> list[str]:
    """Package *file_map* from *source_dir* into *output_zip*.

    Args:
        source_dir: Bundle directory holding the source YAML files.
        output_zip: ZIP path to write, replacing any existing file.
        file_map:   ``{path relative to source_dir: arc name inside the ZIP}``.
        verbose:    Print each entry as it is added.

    Returns:
        The arc names written, in file_map order.

    Raises:
        FileNotFoundError: If a mapped source file is missing. A silently
            dropped chart would import as a dashboard referencing a chart that
            does not exist, so this fails loudly instead.
    """
    missing = [
        src for src in file_map if not os.path.exists(os.path.join(source_dir, src))
    ]
    if missing:
        raise FileNotFoundError(
            f"{output_zip}: missing source file(s): {', '.join(sorted(missing))}"
        )

    if os.path.exists(output_zip):
        os.remove(output_zip)

    written: list[str] = []
    with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for src_rel, arc_name in file_map.items():
            abs_path = os.path.join(source_dir, src_rel)
            info = zipfile.ZipInfo(arc_name, date_time=FIXED_DATE_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            with open(abs_path, "rb") as fh:
                zf.writestr(info, fh.read())
            written.append(arc_name)
            if verbose:
                print(f"  Added: {arc_name}")

    if verbose:
        print(f"\nCreated: {output_zip} ({len(written)} entries)")
    return written
