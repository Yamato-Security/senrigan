"""Sidebar picker for the Suzaku database a page reads.

Suzaku output is a third-party file an analyst copies into the mounted database
directory, so every Suzaku page has to discover what is there, let the analyst
choose, and say why a file was rejected. That is all this module does — the
detection, fitness and selection rules themselves live in ``suzaku_db.py``,
which ``dashboard/init/register_suzaku_dbs.py`` imports too so both UIs resolve
the same file (``doc/PLAN_SUZAKU_MULTI_DB.md`` F-6).

Which file the page then *queries* is ``app._get_duckdb_path``: this module only
writes the choice into the profile's session namespace.
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from profiles import DatasetProfile
from suzaku_db import SuzakuKind, discover, select
from views.explorer import db_directory


@st.cache_data(show_spinner=False, ttl=30)
def _discover_suzaku_dbs(directory: str) -> dict:
    """Return the Suzaku databases in *directory* and the choice made for each kind.

    Discovery opens every candidate file, so it is cached for 30 s rather than
    repeated on each Streamlit rerun; the selection is computed from that same
    scan. Plain dicts are returned because ``st.cache_data`` pickles its result.

    ``served`` is what the Superset dashboards resolve to — the same
    :func:`suzaku_db.select` both services use — so this page can point out
    when the analyst is looking at a different file (PLAN_SUZAKU_MULTI_DB.md
    F-6).

    Args:
        directory: Directory to scan.

    Returns:
        ``{"databases": [...], "served": {command: path}}``.
    """
    infos = discover(directory)
    selections = select(directory, inventory=infos)
    return {
        "databases": [
            {
                "path": str(info.path),
                "label": info.label,
                "kind": info.kind.value if info.kind else "",
                "declared_kind": (
                    info.declared_kind.value if info.declared_kind else ""
                ),
                "rows": sum(info.row_counts.values()),
                "reject_reason": info.reject_reason,
                "error": info.error,
                "hint": info.hint,
            }
            for info in infos
        ],
        "served": {
            kind.value: str(selection.chosen.path)
            for kind, selection in selections.items()
            if selection.chosen is not None
        },
    }


def _render_suzaku_db_selector(profile: DatasetProfile, kind: SuzakuKind) -> bool:
    """Render the Suzaku database picker and store the choice in session state.

    Args:
        profile: Dataset profile whose namespace holds the selection.
        kind:    The Suzaku kind this page can read.

    Returns:
        True when a usable database is selected, False when the page should
        render its empty state instead.
    """
    directory = db_directory()
    inventory = _discover_suzaku_dbs(directory)
    found = inventory["databases"]
    matching = [db for db in found if db["kind"] == kind.value]
    # Right command, but missing a table or a column every query needs.
    unfit = [
        db
        for db in found
        if db["declared_kind"] == kind.value and db["kind"] != kind.value
    ]
    served = inventory["served"].get(kind.value, "")

    st.subheader("🗄️ Suzaku Database")
    if not matching:
        st.warning(f"No usable `{kind.value}` database found in `{directory}`.")
        for db in unfit:
            st.caption(f"⚠️ `{Path(db['path']).name}` — {db['reject_reason']}")
        for db in found:
            if db["error"]:
                st.caption(f"⚠️ `{Path(db['path']).name}` — {db['hint']}")
        return False

    paths = [db["path"] for db in matching]
    stored = st.session_state.get(profile.state_key("suzaku_db"), "")
    # Default to the file the dashboards serve, so both UIs open on the same run.
    default = stored if stored in paths else served
    index = paths.index(default) if default in paths else 0
    selected = st.selectbox(
        "File",
        options=paths,
        index=index,
        format_func=lambda path: Path(path).name,
        key=f"_{profile.key}_db_select",
        help="Every DuckDB file in the mounted database directory that can serve "
        "this Suzaku command. Newest run first; the dashboards use the first one.",
    )
    st.session_state[profile.state_key("suzaku_db")] = selected

    chosen = next(db for db in matching if db["path"] == selected)
    st.caption(f"📁 `{selected}`")
    st.caption(f"{chosen['rows']:,} rows")
    if chosen["hint"]:
        st.caption(f"⚠️ {chosen['hint']}")
    if served and served != selected:
        st.caption(
            f"⚠️ The dashboard is showing `{Path(served).name}` — this page and "
            "Superset are on different runs."
        )
    for db in unfit:
        st.caption(f"⚠️ `{Path(db['path']).name}` — {db['reject_reason']}")
    return True
