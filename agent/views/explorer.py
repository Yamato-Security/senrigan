"""Shared building blocks for the Suzaku explorer pages.

The chat pages render a conversation; the explorer pages render *panels* — a
labelled chart-and-table pair over one reviewed SQL statement, with the three
things that make the agent worth opening for pre-aggregated data: the panel can
be pinned into the report, downloaded as CSV, and narrated by the LLM.

Everything here is layout plus session-state plumbing. The SQL lives in
``suzaku_summary_queries.py`` / ``suzaku_metrics_queries.py``, which import no
Streamlit and are unit-tested directly.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

from profiles import DatasetProfile
from report import ReportEntry
from suzaku_db import DbInfo, SuzakuKind


def db_directory() -> str:
    """Return the directory the reader services mount the databases into.

    Read through the ``app`` module rather than ``config`` so a test that
    patches the path for the database selector patches this too.
    """
    from app import get_duckdb_path_for_variant
    from config import DB_VARIANT_FULL

    return str(Path(get_duckdb_path_for_variant(DB_VARIANT_FULL)).parent)


def render_empty_state(
    kind: SuzakuKind, directory: str, *, command: str, note: str = ""
) -> None:
    """Explain how to produce and place a database of *kind*.

    Shown instead of the page body when discovery found nothing usable: an
    analyst arriving with no Suzaku output needs the command, not an empty table.

    Args:
        kind:      The Suzaku command whose output is missing.
        directory: The directory that was scanned, shown verbatim.
        command:   The Suzaku invocation that produces the file.
        note:      Extra guidance appended below the steps, if any.
    """
    st.info(
        f"No Suzaku `{kind.value}` database was found in `{directory}`.\n\n"
        "Senrigan reads Suzaku's DuckDB output directly — nothing is imported, "
        "and the file is only ever opened read-only."
    )
    st.markdown(f"""
#### Getting a `{kind.value}` database

1. Run Suzaku against your CloudTrail logs, writing DuckDB output:

   ```bash
   {command}
   ```

2. Copy the result next to Senrigan's own database:

   ```bash
   cp *.duckdb docker/data/db/
   ```

3. Reload this page. The file name does not matter — the Suzaku command is
   detected from the schema.

Copy the file only after Suzaku has exited. A leftover `.wal` file cannot be
replayed from a read-only mount, and the database will not open.
{note}
""")


@st.cache_data(show_spinner=False, ttl=30)
def _inspect_cached(path: str, stamp: float) -> DbInfo:
    """Inspect *path*, keyed on its modification time.

    Args:
        path:  The database being read.
        stamp: ``st.cache_data`` key — the file's mtime, so a replaced file is
               re-inspected rather than served from the cache.

    Returns:
        The :class:`~suzaku_db.DbInfo` for the file.
    """
    from suzaku_db import inspect_db

    return inspect_db(Path(path))


def load_db_info(path: str) -> DbInfo:
    """Return the provenance of the database the page is reading.

    Args:
        path: The selected database file.

    Returns:
        Its :class:`~suzaku_db.DbInfo`.
    """
    return _inspect_cached(path, Path(path).stat().st_mtime)


def render_run_info(info: DbInfo) -> None:
    """Render the provenance line for the database being read.

    Mirrors the **Suzaku Run Info** card every Suzaku dashboard carries, so an
    analyst can tell at a glance whether both UIs are on the same run.

    Args:
        info: The inspected database backing this page.
    """
    with st.expander("🧾 Suzaku Run Info", expanded=False):
        rows = [
            ("File", f"`{info.path}`"),
            ("Suzaku version", info.suzaku_version or "—"),
            (
                "Generated at",
                f"{info.generated_at:%Y-%m-%d %H:%M %Z}" if info.generated_at else "—",
            ),
            (
                "Scanned",
                (
                    f"{info.scanned_files:,} files / {info.scanned_events:,} events"
                    if info.scanned_files is not None
                    and info.scanned_events is not None
                    else "—"
                ),
            ),
            (
                "Rows",
                ", ".join(
                    f"{name} {count:,}" for name, count in info.row_counts.items()
                )
                or "—",
            ),
        ]
        st.markdown("\n".join(f"- **{label}:** {value}" for label, value in rows))


def render_sidebar_footer(profile: DatasetProfile) -> None:
    """Render the sidebar blocks an explorer page shares with the chat pages.

    The report is the reason these pages exist alongside the dashboards, and the
    API key drives the per-panel 🤖 Explain button. The chat-only blocks — preset
    hunts, date range, severity, row cap — are deliberately absent: this page
    has its own controls and generates no SQL.

    Args:
        profile: The page's dataset profile.
    """
    from app import (
        render_api_section,
        render_report_section,
        render_session_section,
    )

    st.divider()
    render_report_section(profile)
    st.divider()
    render_session_section(profile)
    st.divider()
    render_api_section(profile)


def _pin_entry(profile: DatasetProfile, entry: ReportEntry) -> None:
    """Append *entry* to this page's report history.

    Args:
        profile: The page's dataset profile.
        entry:   The finding to keep.
    """
    st.session_state[profile.state_key("query_history")].append(entry)


def render_panel(
    profile: DatasetProfile,
    *,
    key: str,
    label: str,
    sql: str,
    df: pd.DataFrame,
    category: str = "",
    description: str = "",
    chart: dict | None = None,
    empty_message: str = "No rows.",
    show_table: bool = True,
) -> None:
    """Render one explorer panel: chart, table and the three actions.

    The actions are what separate this page from the Superset dashboard —
    📌 pins the panel into the Markdown/HTML report, ⬇ exports the exact rows on
    screen, and 🤖 asks the LLM to describe them.

    Args:
        profile:       The page's dataset profile; scopes state and widget keys.
        key:           Stable, page-unique suffix for the widget keys.
        label:         Panel heading, also the report entry's label.
        sql:           The statement that produced *df*, shown and reported.
        df:            The rows to display.
        category:      Report grouping, e.g. ``"👤 Identity"``.
        description:   One-line explanation shown under the heading.
        chart:         Chart config for ``app.render_chart``; None auto-detects,
                       ``{"type": "none"}`` suppresses the chart.
        empty_message: Caption shown instead of the table when *df* is empty.
        show_table:    False renders the chart and actions only.
    """
    from app import render_chart

    st.markdown(f"##### {label}")
    if description:
        st.caption(description)

    if df is None or df.empty:
        st.caption(empty_message)
        return

    render_chart(df, chart, key=f"{profile.key}_chart_{key}")
    if show_table:
        st.dataframe(df, use_container_width=True, hide_index=True)

    analysis_key = f"_{profile.key}_analysis_{key}"
    analysis = st.session_state.get(analysis_key, "")
    if analysis:
        st.info(analysis)

    pin, download, explain = st.columns(3)
    with pin:
        if st.button(
            "📌 Pin to report",
            key=f"_{profile.key}_pin_{key}",
            use_container_width=True,
            help="Add this panel to the Markdown / HTML report in the sidebar.",
        ):
            _pin_entry(
                profile,
                ReportEntry(
                    sql=sql,
                    results=df,
                    analysis=analysis,
                    description=description,
                    chart_config=chart,
                    label=label,
                    category=category,
                    source="explorer",
                ),
            )
            st.toast(f"Pinned: {label}")
    with download:
        st.download_button(
            "⬇ CSV",
            data=df.to_csv(index=False),
            file_name=f"{profile.key}_{key}.csv",
            mime="text/csv",
            key=f"_{profile.key}_csv_{key}",
            use_container_width=True,
        )
    with explain:
        has_api_key = bool(st.session_state.get("api_key"))
        if st.button(
            "🤖 Explain",
            key=f"_{profile.key}_explain_{key}",
            use_container_width=True,
            disabled=not has_api_key,
            help=(
                "Summarise the rows above."
                if has_api_key
                else "Enter your OpenAI API key in the sidebar to enable this."
            ),
        ):
            st.session_state[analysis_key] = _explain(df, sql)
            st.rerun()


def render_timeline_pivot(
    *, key: str, column: str, value: str, label: str, category: str = "🕒 Pivot"
) -> None:
    """Render the button that follows a value into the timeline page.

    The explorer pages read what Suzaku aggregated; the raw detections live in
    the ``aws-ct-timeline`` file, which a different page reads. The pivot hands
    that page a ready-made direct-SQL preset — no API key needed — and switches
    to it.

    The two pages may be on different Suzaku runs, so the caption says which
    file the timeline page would use before the analyst commits to the jump.

    Args:
        key:      Stable, page-unique suffix for the widget key.
        column:   The ``timeline`` column to filter on.
        value:    The value to filter for.
        label:    Report label for the resulting query.
        category: Report category for the resulting query.
    """
    from suzaku_queries import timeline_pivot_sql

    if not value:
        return

    if st.button(
        "🕒 Hunt this in the timeline",
        key=f"_pivot_{key}",
        use_container_width=True,
        help="Open the Suzaku Timeline page with this value already filtered.",
    ):
        handoff_to_timeline(
            timeline_pivot_sql(column, value), label=label, category=category
        )


def handoff_to_timeline(sql: str, *, label: str, category: str = "🕒 Pivot") -> None:
    """Queue *sql* on the timeline page and switch to it.

    Reuses the direct-SQL preset hook the chat page already pops on every rerun,
    so the query runs without an API key and lands in that page's own report.

    Args:
        sql:      The statement the timeline page should run.
        label:    Report label for the resulting entry.
        category: Report category for the resulting entry.
    """
    from app import PAGES
    from profiles import SUZAKU_TIMELINE_PROFILE

    prefix = SUZAKU_TIMELINE_PROFILE.key
    st.session_state[f"_{prefix}_pending_direct_sql"] = sql
    st.session_state[f"_{prefix}_pending_preset_label"] = label
    st.session_state[f"_{prefix}_pending_preset_category"] = category
    st.session_state[f"_{prefix}_pending_preset_description"] = (
        "Pivoted from a Suzaku explorer page. The timeline page reads its own "
        "file, which may come from a different Suzaku run."
    )

    target = PAGES.get(SUZAKU_TIMELINE_PROFILE.key)
    if target is not None:
        st.switch_page(target)


def _explain(df: pd.DataFrame, sql: str) -> str:
    """Return the LLM's factual summary of *df*.

    Args:
        df:  The rows on screen.
        sql: The statement that produced them.

    Returns:
        Markdown bullets, or the error message ``generate_analysis`` returns.
    """
    from llm import generate_analysis

    return generate_analysis(
        sql,
        df,
        api_key=st.session_state.get("api_key", ""),
        model=st.session_state.get("model", "gpt-5.5"),
    )
