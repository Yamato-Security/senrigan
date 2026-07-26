"""Streamlit page: hunt over Suzaku ``aws-ct-timeline`` output.

The page is deliberately thin. Everything it shows comes from the shared
hunting UI in ``app.py`` driven by :data:`~profiles.SUZAKU_TIMELINE_PROFILE`:
built-in hunts, date range, severity filter, result filters, Markdown/HTML
report, session export, AI chat and AI analysis.

What is specific to this page is the input: Suzaku databases are third-party
files an analyst copies into the mounted database directory, so the page has to
discover them, let the analyst pick one, and explain itself when there are none.

See ``doc/PLAN_SUZAKU_VIEWS.md`` §4.3.
"""

from __future__ import annotations

import streamlit as st

from profiles import SUZAKU_TIMELINE_PROFILE
from suzaku_db import SuzakuKind

PROFILE = SUZAKU_TIMELINE_PROFILE
KIND = SuzakuKind.TIMELINE


def _render_empty_state(directory: str) -> None:
    """Explain how to produce and place a timeline database.

    Shown instead of the hunting UI when discovery found nothing usable: an
    analyst arriving here with no Suzaku output needs the three commands, not an
    empty table.

    Args:
        directory: The directory that was scanned, shown verbatim.
    """
    st.info(
        f"No Suzaku `{KIND.value}` database was found in `{directory}`.\n\n"
        "Senrigan reads Suzaku's DuckDB output directly — nothing is imported, "
        "and the file is only ever opened read-only."
    )
    st.markdown(f"""
#### Getting a timeline database

1. Run Suzaku against your CloudTrail logs, writing DuckDB output:

   ```bash
   suzaku {KIND.value} -d <cloudtrail-logs> -o timeline.duckdb
   ```

2. Copy the result next to Senrigan's own database:

   ```bash
   cp timeline.duckdb docker/data/db/
   ```

3. Reload this page. The file name does not matter — the Suzaku command is
   detected from the schema.

Copy the file only after Suzaku has exited. A leftover `.wal` file cannot be
replayed from a read-only mount, and the database will not open.
""")


def render() -> None:
    """Render the Suzaku timeline hunting page."""
    # Imported here rather than at module scope: ``app`` imports this module's
    # package to build the navigation, so a module-level import would be circular.
    from app import (  # noqa: PLC0415
        _get_duckdb_path,
        _init_session_state,
        _render_suzaku_db_selector,
        render_chat,
        render_sidebar,
    )

    _init_session_state(PROFILE)

    # No page header: the navigation already names the page, and the CloudTrail
    # page opens straight into its content too.
    with st.sidebar:
        has_db = _render_suzaku_db_selector(PROFILE, KIND)

    if not has_db:
        from config import DB_VARIANT_FULL, get_duckdb_path_for_variant  # noqa: PLC0415
        from pathlib import Path  # noqa: PLC0415

        _render_empty_state(
            str(Path(get_duckdb_path_for_variant(DB_VARIANT_FULL)).parent)
        )
        return

    render_sidebar(PROFILE)

    db_path = _get_duckdb_path(PROFILE)
    if not db_path:
        st.warning("Select a Suzaku database in the sidebar to start hunting.")
        return

    render_chat(PROFILE)
