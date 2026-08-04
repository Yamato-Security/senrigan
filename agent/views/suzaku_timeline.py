"""Streamlit page: hunt over Suzaku ``aws-ct-timeline`` output.

The page is deliberately thin. Everything it shows comes from the shared
hunting UI in ``app.py`` driven by :data:`~profiles.SUZAKU_TIMELINE_PROFILE`:
built-in hunts, date range, severity filter, result filters, Markdown/HTML
report, session export, AI chat and AI analysis.

What is specific to this page is the input: Suzaku databases are third-party
files an analyst copies into the mounted database directory, so the page has to
discover them, let the analyst pick one, and explain itself when there are none.
"""

from __future__ import annotations

import streamlit as st

from profiles import SUZAKU_TIMELINE_PROFILE
from suzaku_db import SuzakuKind
from views.explorer import (
    db_directory,
    load_db_info,
    render_empty_state,
    render_run_info,
)

PROFILE = SUZAKU_TIMELINE_PROFILE
KIND = SuzakuKind.TIMELINE

_COMMAND = "suzaku aws-ct-timeline -d <cloudtrail-logs> -o timeline -t duckdb -G <MAXMIND-DB-DIR>"


def _render_empty_state(directory: str) -> None:
    """Explain how to produce and place a timeline database.

    Shown instead of the hunting UI when discovery found nothing usable: an
    analyst arriving here with no Suzaku output needs the commands, not an
    empty table.

    Args:
        directory: The directory that was scanned, shown verbatim.
    """
    render_empty_state(KIND, directory, command=_COMMAND)


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
        _render_empty_state(db_directory())
        return

    db_path = _get_duckdb_path(PROFILE)
    if not db_path:
        st.warning("Select a Suzaku database in the sidebar to start hunting.")
        return

    # Directly under the picker, as on the explorer pages: the provenance of the
    # file belongs next to the choice of file, not below the hunting controls.
    with st.sidebar:
        render_run_info(load_db_info(db_path))

    render_sidebar(PROFILE)

    render_chat(PROFILE)
