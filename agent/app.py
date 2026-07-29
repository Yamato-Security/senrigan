"""Streamlit entry point for the Senrigan AI threat hunting agent.

Provides an interactive chat UI for AI-assisted threat hunting on
AWS CloudTrail logs stored in DuckDB.
"""

import json
import logging
from datetime import date
from pathlib import Path

import pandas as pd
import streamlit as st
import yaml

from config import (
    DB_VARIANT_FULL,
    DB_VARIANT_LITE,
    get_duckdb_path_for_variant,
    get_duckdb_path_lite,
)
from handlers import (
    _analyze_entry_results,
    _handle_direct_sql,
    _handle_edit_rerun_sql,
    _handle_user_query,
)
from llm import MAX_CONTEXT_TURNS  # noqa: F401
from profiles import CLOUDTRAIL_PROFILE, SUZAKU_TIMELINE_PROFILE, DatasetProfile
from query import DEFAULT_ROW_LIMIT
from report import ReportEntry, generate_report, generate_html_report
from suzaku_db import SuzakuKind, discover, select

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Path to the built-in threat hunting prompts YAML file.
_BUILTIN_PROMPTS_PATH = Path(__file__).parent / "builtin_hunts.yaml"

# Available OpenAI models for the sidebar model selector.
MODEL_OPTIONS: list[str] = ["gpt-5.5", "gpt-5.4", "gpt-5.4-mini"]

# Session state keys and their default values.
SESSION_STATE_DEFAULTS: dict = {
    "messages": [],  # chat history: list of {role, content}
    "query_history": [],  # list of ReportEntry for report generation
    "last_sql": "",  # most recently generated SQL (editable)
    "last_results": None,  # pandas DataFrame or None
    "last_summary": "",  # fact-based summary from the last query
    "api_key": "",  # entered in sidebar (AGT-09)
    "model": "gpt-5.5",  # selected model
    "date_start": None,  # date | None — lower bound for event_time filter
    "date_end": None,  # date | None — upper bound for event_time filter
    "row_limit": DEFAULT_ROW_LIMIT,  # maximum rows returned per query
    "geo_enrich": True,  # auto-join geo columns next to IP columns in results
    "conversation_context": [],  # recent (user_query, sql, summary) turns for LLM context
    "db_variant": DB_VARIANT_FULL,  # active DB variant; "Lite" only available when DUCKDB_PATH_LITE is set
    "analyst_notes": {},  # UI-01: dict[int, str] — query_index → analyst note text
    "bulk_progress": None,  # UI-04: None | {"current": int, "total": int, "label": str}
    "levels": [],  # severity filter (Suzaku only; empty = no filter)
    "suzaku_db": "",  # path of the selected Suzaku DuckDB file
}


# ---------------------------------------------------------------------------
# Chart rendering helpers
# ---------------------------------------------------------------------------


def _render_bar_chart(df: pd.DataFrame, chart_config: dict | None) -> None:
    """Render a Plotly Express horizontal bar chart.

    Uses the x/y keys from chart_config when provided; falls back to the first
    non-numeric column (y-axis) and all numeric columns (x-axis) for auto-detection.

    Args:
        df:           The query result DataFrame.
        chart_config: Chart configuration dict, or None for auto-detection.
    """
    import plotly.express as px

    numeric_cols = df.select_dtypes(include="number").columns.tolist()
    non_numeric_cols = [c for c in df.columns if c not in numeric_cols]

    if chart_config:
        x_col = chart_config.get("x")
        y_cols = chart_config.get("y", [])
        if isinstance(y_cols, str):
            y_cols = [y_cols]
    else:
        x_col = non_numeric_cols[0] if non_numeric_cols else None
        y_cols = numeric_cols

    if not x_col or not y_cols:
        return

    if len(y_cols) == 1:
        fig = px.bar(df, x=y_cols[0], y=x_col, orientation="h")
    else:
        plot_df = df[[x_col] + y_cols].melt(
            id_vars=x_col, var_name="metric", value_name="value"
        )
        fig = px.bar(
            plot_df,
            x="value",
            y=x_col,
            color="metric",
            orientation="h",
            barmode="group",
        )

    # Rendered inline, not in an expander: the caller (a result card) is already
    # an expander, and Streamlit forbids nesting them.
    st.markdown("**📊 Bar Chart**")
    st.plotly_chart(fig, use_container_width=True)


# Column names a time-series chart can bucket on, in priority order. Results come
# from different tables (``cloudtrail_events.event_time``, Suzaku's
# ``Timestamp``) and hunts frequently bucket in SQL and return an alias.
_TIME_COLUMN_CANDIDATES: tuple[str, ...] = (
    "event_time",
    "timestamp",
    "day",
    "hour",
    "week",
    "month",
    "bucket",
    "first_seen",
    "last_seen",
)


def _find_time_column(df: pd.DataFrame) -> str | None:
    """Return the column a time-series chart should bucket, or None.

    Matching is case-insensitive and follows :data:`_TIME_COLUMN_CANDIDATES`, so
    a query aliasing its bucket as ``day`` charts just as well as one returning
    a raw timestamp.

    Args:
        df: The query result DataFrame.

    Returns:
        The column name to plot, or ``None`` when nothing looks temporal.
    """
    lowered = {str(column).lower(): column for column in df.columns}
    for candidate in _TIME_COLUMN_CANDIDATES:
        if candidate in lowered:
            return lowered[candidate]
    return None


def _render_timeseries_chart(df: pd.DataFrame, chart_config: dict) -> None:
    """Render a time-series chart by bucketing the result's time column.

    Skips rendering when the DataFrame has no recognisable time column, when the
    timestamps cannot be parsed, or when there is only one distinct bucket
    (a single-bar chart provides no visual value).

    Args:
        df:           The query result DataFrame.
        chart_config: Chart configuration dict; uses bucket='day' by default.
    """
    time_column = _find_time_column(df)
    if time_column is None:
        return

    bucket = chart_config.get("bucket", "day")
    ts = pd.to_datetime(df[time_column], errors="coerce").dropna()
    if ts.empty:
        return

    if bucket == "hour":
        bucketed = ts.dt.floor("h").dt.strftime("%Y-%m-%d %H:00")
        title = "📈 Timeline (per hour)"
    else:
        bucketed = ts.dt.date.astype(str)
        title = "📈 Timeline (per day)"

    counts = bucketed.value_counts().sort_index()
    if len(counts) < 2:
        return

    chart_df = counts.reset_index()
    chart_df.columns = ["bucket", "count"]

    # Inline for the same reason as the bar chart: no expander nesting.
    st.markdown(f"**{title}**")
    st.line_chart(chart_df, x="bucket", y="count")


def render_chart(df: pd.DataFrame, chart_config: dict | None) -> None:
    """Render a chart from the query result based on the chart configuration.

    Dispatch table:
    - chart_config=None          → auto-detect: Plotly bar if numeric cols exist
    - type='none'                → skip
    - type='bar'                 → Plotly Express horizontal bar (x/y from config)
    - type='timeseries'          → st.bar_chart bucketed by day or hour

    Args:
        df:           The query result DataFrame.
        chart_config: Chart configuration dict with 'type', 'x', 'y', 'bucket'
                      keys, or None for auto-detection.
    """
    if df is None or df.empty:
        return

    chart_type = chart_config.get("type") if chart_config else None

    if chart_type == "none":
        return

    if chart_type == "timeseries":
        _render_timeseries_chart(df, chart_config or {})
        return

    if chart_type == "bar":
        _render_bar_chart(df, chart_config)
        return

    # Auto-detection: render a bar chart when at least one numeric column exists.
    numeric_cols = df.select_dtypes(include="number").columns.tolist()
    if numeric_cols:
        _render_bar_chart(df, None)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _init_session_state(profile: DatasetProfile = CLOUDTRAIL_PROFILE) -> None:
    """Initialize this profile's session-state namespace with default values.

    Idempotent: only sets keys that are not already present, so existing
    session data is never overwritten on page reload. Per-page keys are
    prefixed by the profile (see ``profiles.py``), so the two pages keep
    independent history, filters and reports while sharing the API key,
    model and row cap.

    Args:
        profile: Dataset profile whose namespace to initialize.
    """
    for key, default in SESSION_STATE_DEFAULTS.items():
        namespaced = profile.state_key(key)
        if namespaced not in st.session_state:
            if key == "levels":
                default = list(profile.default_levels)
            elif key == "row_limit":
                default = profile.default_row_limit
            st.session_state[namespaced] = default


def _format_technique_caption(technique: dict) -> str:
    """Format one Threat Technique Catalog mapping as a caption line.

    Args:
        technique: Dict with tid / name / summary / url keys (all optional
            except tid).

    Returns:
        A Markdown caption like
        ``🎯 [T1562.008 — Impair Defenses: Disable Cloud Logs](url): summary``.
        The link is omitted when no url is present; the summary suffix is
        omitted when no summary is present.
    """
    tid = str(technique.get("tid", ""))
    name = str(technique.get("name", ""))
    url = str(technique.get("url", ""))
    summary = str(technique.get("summary", ""))

    title = f"{tid} — {name}" if name else tid
    if url:
        title = f"[{title}]({url})"
    caption = f"🎯 {title}"
    if summary:
        caption = f"{caption}: {summary}"
    return caption


def _build_all_hunt_queries(prompts: list[dict]) -> list[dict]:
    """Return a flat list of bulk-query dicts for every entry that has a sql field.

    Args:
        prompts: All prompt entries loaded from builtin_hunts.yaml.

    Returns:
        List of dicts with keys sql, description, chart_config, label, category,
        techniques, covering every entry whose sql field is non-empty.  sql
        values are stripped of leading/trailing whitespace.
    """
    return [
        {
            "sql": p["sql"].strip(),
            "description": p.get("description", ""),
            "chart_config": p.get("chart"),
            "label": p["label"],
            "category": p.get("category", ""),
            "techniques": p.get("techniques") or [],
        }
        for p in prompts
        if p.get("sql", "").strip()
    ]


def _load_builtin_prompts(
    profile: DatasetProfile = CLOUDTRAIL_PROFILE,
) -> list[dict]:
    """Load built-in hunt prompts for *profile* from its YAML file.

    Args:
        profile: Dataset profile whose ``hunts_path`` to read.

    Returns:
        A list of dicts, each containing 'label' and 'prompt' keys.
        Falls back to a minimal built-in list if the file is not found.
    """
    path = profile.hunts_path
    try:
        with open(path, encoding="utf-8") as f:
            prompts = yaml.safe_load(f)
        if isinstance(prompts, list):
            return prompts
    except FileNotFoundError:
        logger.warning("hunts YAML not found at %s", path)
    except yaml.YAMLError as exc:
        logger.error("Failed to parse %s: %s", path, exc)

    # Fallback minimal list
    return [
        {
            "label": "🔑 Root Account Activity",
            "prompt": (
                "List all API calls made by the root account. Include event_time, "
                "event_name, source_ip_address, and aws_region. Order by most recent first."
            ),
        },
        {
            "label": "🚫 Access Denied Errors",
            "prompt": (
                "Show all AccessDenied and UnauthorizedAccess errors in the logs. "
                "Group by user identity and event_name to find the top offenders."
            ),
        },
    ]


def _clear_session(profile: DatasetProfile = CLOUDTRAIL_PROFILE) -> None:
    """Reset one page's chat, results, notes and context.

    Only the profile's own namespace is touched, so clearing the Suzaku page
    leaves a CloudTrail investigation — and the shared API key — intact.

    Args:
        profile: Dataset profile whose session state to clear.
    """
    for key, value in (
        ("messages", []),
        ("query_history", []),
        ("last_sql", ""),
        ("last_results", None),
        ("last_summary", ""),
        ("conversation_context", []),
        ("analyst_notes", {}),
    ):
        st.session_state[profile.state_key(key)] = value


def _export_session(
    entries: list[ReportEntry], title: str = "Threat Hunting Session"
) -> str:
    """Export the current session as a JSON string.

    Serialises all ReportEntry objects to a JSON payload for download
    or later re-import (AGT-08).  Includes analyst_note for each query.

    Args:
        entries: List of ReportEntry objects from the current session.
        title:   Human-readable session title.

    Returns:
        A JSON-formatted string representing the session.
    """
    queries = [
        {
            "sql": entry.sql,
            "row_count": len(entry.results) if entry.results is not None else 0,
            "analyst_note": entry.analyst_note,
        }
        for entry in entries
    ]
    payload = {
        "title": title,
        "queries": queries,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# UI rendering
# ---------------------------------------------------------------------------


def _get_duckdb_path(profile: DatasetProfile = CLOUDTRAIL_PROFILE) -> str:
    """Resolve the DuckDB path this profile's queries should run against.

    For Suzaku profiles the path is a file the analyst copied into the mounted
    directory and picked in the sidebar; it is stored in the profile's session
    namespace by :func:`_render_suzaku_db_selector`.

    For the CloudTrail profile the path follows the Full/Lite variant: when
    ``DUCKDB_PATH_LITE`` is set and the user selected Lite in the sidebar, that
    path is returned, otherwise the Full path from ``DUCKDB_PATH``.

    Args:
        profile: Dataset profile being queried.

    Returns:
        The DuckDB file path, or ``""`` when no Suzaku database was selected.
    """
    if profile.key != CLOUDTRAIL_PROFILE.key:
        return str(st.session_state.get(profile.state_key("suzaku_db"), "") or "")
    variant = st.session_state.get("db_variant", DB_VARIANT_FULL)
    return get_duckdb_path_for_variant(variant)


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
    directory = str(Path(get_duckdb_path_for_variant(DB_VARIANT_FULL)).parent)
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


def render_sidebar(profile: DatasetProfile = CLOUDTRAIL_PROFILE) -> None:
    """Render the sidebar: API key, model selection, presets, report, session export.

    Handles AGT-07 (preset prompts), AGT-08 (session export), AGT-09 (API key).

    Every widget key is prefixed with the profile key so the two pages do not
    share widget state, and every history read goes through the profile's
    session namespace.

    Args:
        profile: Dataset profile the page is querying.
    """
    prefix = profile.key
    with st.sidebar:
        # Database variant selector — only shown when a Lite DB has been
        # configured via the DUCKDB_PATH_LITE environment variable.
        # The Lite variant points at a DuckDB file produced by
        # `ingester ingest --strip-fields`, where pagination/idempotency
        # noise has been removed from request_parameters / response_elements.
        lite_path = (
            get_duckdb_path_lite() if profile.key == CLOUDTRAIL_PROFILE.key else None
        )
        if lite_path:
            st.subheader("🗄️ Database")
            variants = [DB_VARIANT_FULL, DB_VARIANT_LITE]
            current = st.session_state.db_variant
            if current not in variants:
                current = DB_VARIANT_FULL
            chosen = st.radio(
                "Variant",
                options=variants,
                index=variants.index(current),
                horizontal=True,
                help=(
                    "Full = original CloudTrail records.  "
                    "Lite = noise fields stripped from request_parameters "
                    "/ response_elements (pagination tokens, idempotency "
                    "tokens, opaque session credentials, AWS catalogue "
                    "echoes, query-time filter echoes, redundant Host "
                    "headers). raw_event is preserved in both variants."
                ),
                key="_db_variant_radio",
            )
            if chosen != st.session_state.db_variant:
                st.session_state.db_variant = chosen
            active_path = get_duckdb_path_for_variant(st.session_state.db_variant)
            st.caption(f"📁 `{active_path}`")

        # AGT-07: Preset threat hunting prompts (v2 — category grouping + Direct SQL)
        st.subheader("🎯 Preset Hunt Queries")
        prompts = _load_builtin_prompts(profile)

        # Build category list preserving insertion order
        categories: list[str] = []
        seen_cats: set[str] = set()
        for p in prompts:
            cat = p.get("category", "Other")
            if cat not in seen_cats:
                categories.append(cat)
                seen_cats.add(cat)

        # Read current category from session state so bulk-run buttons can be
        # rendered ABOVE the selectbox while still reflecting the current selection.
        current_category = st.session_state.get(
            f"_{prefix}_preset_category", "— All categories —"
        )

        # Filter prompts by current category
        if current_category == "— All categories —":
            filtered = prompts
        else:
            filtered = [p for p in prompts if p.get("category") == current_category]

        # Bulk-run buttons — placed ABOVE the Category selectbox
        sql_queries = [p for p in filtered if p.get("sql", "").strip()]
        all_sql_queries = _build_all_hunt_queries(prompts)

        if current_category == "— All categories —":
            # "Run All Hunts" — runs every SQL query across all categories
            if all_sql_queries and st.button(
                f"⚡ Run All Hunts ({len(all_sql_queries)} queries)",
                use_container_width=True,
                key=f"_{prefix}_run_all_hunts",
                help="Run all built-in hunt queries across every category",
            ):
                st.session_state[f"_{prefix}_pending_bulk_queries"] = all_sql_queries
                st.rerun()
        elif sql_queries:
            # "Run All" — runs every SQL query in the selected category
            if st.button(
                f"⚡ Run All ({len(sql_queries)} queries)",
                use_container_width=True,
                key=f"_{prefix}_run_all_category",
                help="Run all queries in this category",
            ):
                st.session_state[f"_{prefix}_pending_bulk_queries"] = [
                    {
                        "sql": p["sql"].strip(),
                        "description": p.get("description", ""),
                        "chart_config": p.get("chart"),
                        "techniques": p.get("techniques") or [],
                        "label": p["label"],
                        "category": p.get("category", ""),
                    }
                    for p in sql_queries
                ]
                st.rerun()

        # Category selectbox — rendered after bulk-run buttons
        selected_category = st.selectbox(
            "Category",
            options=["— All categories —"] + categories,
            key=f"_{prefix}_preset_category",
        )

        # Re-filter when the selectbox value differs from what was used above
        # (i.e. the user just changed the category on this run).
        if selected_category != current_category:
            if selected_category == "— All categories —":
                filtered = prompts
            else:
                filtered = [
                    p for p in prompts if p.get("category") == selected_category
                ]

        preset_labels = ["— Select a preset —"] + [p["label"] for p in filtered]
        selected_label = st.selectbox(
            "Preset",
            options=preset_labels,
            key=f"_{prefix}_preset_label",
        )

        if selected_label != "— Select a preset —":
            matched = next((p for p in filtered if p["label"] == selected_label), None)
            if matched:
                # Show description when available
                desc = matched.get("description", "")
                if desc:
                    st.caption(f"ℹ️ {desc}")

                # Show Threat Technique Catalog mappings when available
                for technique in matched.get("techniques") or []:
                    st.caption(_format_technique_caption(technique))

                has_sql = bool(matched.get("sql", "").strip())

                if has_sql:
                    if st.button(
                        "⚡ Direct SQL",
                        use_container_width=True,
                        key=f"_{prefix}_direct_sql",
                        help="Run without an API key",
                    ):
                        st.session_state[f"_{prefix}_pending_direct_sql"] = matched[
                            "sql"
                        ].strip()
                        st.session_state[f"_{prefix}_pending_preset_description"] = desc
                        st.session_state[f"_{prefix}_pending_chart_config"] = (
                            matched.get("chart")
                        )
                        st.session_state[f"_{prefix}_pending_preset_label"] = matched[
                            "label"
                        ]
                        st.session_state[f"_{prefix}_pending_preset_category"] = (
                            matched.get("category", "")
                        )
                        st.session_state[f"_{prefix}_pending_preset_techniques"] = (
                            matched.get("techniques") or []
                        )
                        st.rerun()
                else:
                    st.button(
                        "⚡ Direct SQL",
                        disabled=True,
                        use_container_width=True,
                        key=f"_{prefix}_direct_sql_disabled",
                        help="No pre-built SQL for this preset",
                    )

        # UI-04: progress bar slot — positioned right below preset queries.
        # Created here (inside the sidebar) so it always appears at this fixed
        # position. render_chat() retrieves and updates it during bulk execution.
        st.session_state[f"_{prefix}_bulk_progress_slot"] = st.empty()

        # Date range filter — placed below preset queries
        st.subheader("📅 Date Range Filter")
        today = date.today()
        dc1, dc2 = st.columns(2)
        with dc1:
            new_start = st.date_input(
                "From",
                value=st.session_state[profile.state_key("date_start")],
                max_value=today,
                format="YYYY-MM-DD",
                key=f"_{prefix}_date_start_input",
            )
        with dc2:
            new_end = st.date_input(
                "To",
                value=st.session_state[profile.state_key("date_end")],
                max_value=today,
                format="YYYY-MM-DD",
                key=f"_{prefix}_date_end_input",
            )

        # Persist date selections
        st.session_state[profile.state_key("date_start")] = new_start or None
        st.session_state[profile.state_key("date_end")] = new_end or None

        if new_start and new_end and new_start > new_end:
            st.error("⚠️ 'From' date must be before or equal to 'To' date.")
        elif new_start or new_end:
            start_s = str(new_start) if new_start else "—"
            end_s = str(new_end) if new_end else "—"
            st.caption(f"🔍 Active filter: **{start_s}** → **{end_s}**")

        # Severity filter — only for a dataset that has severities (Suzaku).
        # low + informational dominate the row count, so they start unselected:
        # without this the page shows noise, not detections.
        if profile.level_column:
            st.subheader("🎚 Severity Filter")
            selected_levels = st.multiselect(
                profile.level_column,
                options=list(profile.level_order),
                default=st.session_state[profile.state_key("levels")],
                key=f"_{prefix}_levels_input",
                help=(
                    "Severities to keep. Selecting all of them is the same as no "
                    "filter. `low` and `informational` are the bulk of the data."
                ),
            )
            st.session_state[profile.state_key("levels")] = selected_levels
            if not selected_levels:
                st.caption("🔍 No severity filter — every level is included.")

        st.divider()

        # AGT-06: Markdown / HTML report download
        st.subheader("📄 Report")
        history = st.session_state[profile.state_key("query_history")]
        report_title = f"Senrigan {profile.label} Report"
        if history:
            report_md = generate_report(history, title=report_title)
            report_html = generate_html_report(history, title=report_title)
            dl1, dl2 = st.columns(2)
            with dl1:
                st.download_button(
                    label="⬇ Markdown",
                    data=report_md,
                    file_name=f"{profile.key}_report.md",
                    mime="text/markdown",
                    use_container_width=True,
                    key=f"_{prefix}_report_md",
                )
            with dl2:
                st.download_button(
                    label="⬇ HTML",
                    data=report_html,
                    file_name=f"{profile.key}_report.html",
                    mime="text/html",
                    use_container_width=True,
                    key=f"_{prefix}_report_html",
                )
        else:
            st.caption("Run at least one query to generate a report.")

        st.divider()

        # AGT-08: Session export
        st.subheader("💾 Session")
        col1, col2 = st.columns(2)
        with col1:
            if history:
                session_json = _export_session(
                    history,
                    title=f"Senrigan {profile.label} Session",
                )
                st.download_button(
                    label="Export JSON",
                    data=session_json,
                    file_name=f"{profile.key}_session.json",
                    mime="application/json",
                    use_container_width=True,
                    key=f"_{prefix}_export_json",
                )
            else:
                st.button(
                    "Export JSON",
                    disabled=True,
                    use_container_width=True,
                    key=f"_{prefix}_export_json_disabled",
                )

        with col2:
            if st.button("🗑 Clear", use_container_width=True, key=f"_{prefix}_clear"):
                _clear_session(profile)
                st.rerun()

        st.divider()

        # Result limit (per-query row cap)
        st.subheader("⚙️ Result Limit")
        new_row_limit = st.number_input(
            "Max rows",
            min_value=1,
            max_value=100_000,
            value=st.session_state.row_limit,
            step=100,
            key=f"_{prefix}_row_limit_input",
            help=(
                "Maximum number of rows returned per query. "
                "Overrides any LIMIT clause already present in the SQL."
            ),
        )
        if int(new_row_limit) != st.session_state.row_limit:
            st.session_state.row_limit = int(new_row_limit)

        # Automatic GeoIP context for IP columns (see agent/geo.py).
        # Hidden for datasets whose table has no geo_* columns: the lookup joins
        # against cloudtrail_events, which a Suzaku database does not contain.
        if profile.supports_geo_enrich:
            st.session_state.geo_enrich = st.checkbox(
                "🌍 Auto geo-enrich IP columns",
                value=st.session_state.geo_enrich,
                key=f"_{prefix}_geo_enrich",
                help=(
                    "When results contain an IP address column, automatically add "
                    "the GeoIP columns (country, city, ISP organization) stored "
                    "on cloudtrail_events next to it. No effect when the "
                    "database was ingested without GeoLite2 databases."
                ),
            )

        st.divider()

        # AGT-09: API key input (placed last — rarely changed after initial setup)
        st.subheader("🔑 API Configuration")
        api_key_input = st.text_input(
            "OpenAI API Key",
            value=st.session_state.api_key,
            type="password",
            key=f"_{prefix}_api_key_input",
            help="Your OpenAI API key. Never stored outside this browser session.",
        )
        if api_key_input != st.session_state.api_key:
            st.session_state.api_key = api_key_input

        # Model selection
        selected_model = st.selectbox(
            "Model",
            options=MODEL_OPTIONS,
            key=f"_{prefix}_model_select",
            index=(
                MODEL_OPTIONS.index(st.session_state.model)
                if st.session_state.model in MODEL_OPTIONS
                else 0
            ),
        )
        if selected_model != st.session_state.model:
            st.session_state.model = selected_model


def _result_badge(entry: ReportEntry) -> str:
    """Return a short result-count badge string for the expander title.

    Shows row count so analysts can see result presence at a glance
    even when the card is collapsed.

    - ``✅ N rows``      — results present, below the row limit
    - ``⚠️ N rows``     — results present but at (or above) the row limit
                          (truncation likely)
    - ``⬜ no results`` — empty DataFrame or None
    """
    if entry.results is None or entry.results.empty:
        return "⬜ no results"
    row_count = len(entry.results)
    row_limit = st.session_state.get("row_limit", DEFAULT_ROW_LIMIT)
    if row_count >= row_limit:
        return f"⚠️ {row_count:,} rows"
    return f"✅ {row_count:,} rows"


def _apply_entry_filter(
    entries: list[tuple[int, ReportEntry]],
    result_filter: str,
    keyword: str,
) -> list[tuple[int, ReportEntry]]:
    """Filter a list of (index, ReportEntry) tuples by result state and keyword.

    Args:
        entries:       List of (query_history_index, entry) pairs to filter.
        result_filter: One of ``"All"``, ``"✅ Results"``, ``"⬜ No results"``.
        keyword:       Case-insensitive substring matched against label,
                       category, and description.  Empty string skips matching.

    Returns:
        Filtered list preserving original order.
    """
    out = []
    kw = keyword.strip().lower()
    for idx, entry in entries:
        has_results = entry.results is not None and not entry.results.empty
        if result_filter == "✅ Results" and not has_results:
            continue
        if result_filter == "⬜ No results" and has_results:
            continue
        if kw:
            searchable = " ".join(
                [entry.label, entry.category, entry.description]
            ).lower()
            if kw not in searchable:
                continue
        out.append((idx, entry))
    return out


def _reset_query_filter(prefix: str) -> None:
    """Reset the query filter widgets to their defaults.

    Used as the ``on_click`` callback of the "✕ Clear" button rather than being
    run inline: Streamlit refuses an assignment to a widget's session-state key
    once that widget has been instantiated in the current run, and both filter
    widgets are rendered before the button. A callback runs *between* runs, so
    the keys are writable and the next run picks the new values up.

    Args:
        prefix: The profile key scoping the widget keys.
    """
    st.session_state[f"_{prefix}_qf_result_filter"] = "All"
    st.session_state[f"_{prefix}_qf_keyword"] = ""


def _render_query_filter(
    profile: DatasetProfile = CLOUDTRAIL_PROFILE,
) -> tuple[str, str]:
    """Render the compact filter bar at the top of the main area.

    Provides result-state filtering (All / Results / No results) and a
    free-text keyword filter applied against label, category, and description.

    Args:
        profile: Dataset profile the page is querying; scopes the widget keys.

    Returns:
        Tuple of (result_filter, keyword).
    """
    prefix = profile.key
    st.subheader("🔍 Query Results Filter", divider=False)
    c1, c2, c3 = st.columns([3, 4, 1], vertical_alignment="bottom")
    with c1:
        result_filter = st.radio(
            "Show",
            options=["All", "✅ Results", "⬜ No results"],
            horizontal=True,
            key=f"_{prefix}_qf_result_filter",
            label_visibility="collapsed",
        )
    with c2:
        keyword = st.text_input(
            "Keyword",
            placeholder="🔍 label / category / description…",
            key=f"_{prefix}_qf_keyword",
            label_visibility="collapsed",
        )
    with c3:
        # The reset runs in on_click, not here: see _reset_query_filter. Clicking
        # a button already triggers a rerun, so no explicit st.rerun() is needed.
        st.button(
            "✕ Clear",
            use_container_width=True,
            key=f"_{prefix}_qf_clear",
            help="Clear filters",
            on_click=_reset_query_filter,
            args=(prefix,),
        )
    return result_filter or "All", keyword or ""


def _build_expander_title(entry: ReportEntry, index: int) -> str:
    """Build the expander title for a query result card.

    Combines label / category with a result-count badge so the state is
    visible without expanding the card.

    Args:
        entry: The ReportEntry whose metadata is used.
        index: 1-based display number.

    Returns:
        A string suitable for use as an st.expander label.
    """
    badge = _result_badge(entry)
    if entry.label:
        if entry.category:
            return f"{entry.category}  ›  {entry.label}  │  {badge}"
        return f"{entry.label}  │  {badge}"
    return f"Query #{index}  │  {badge}"


def _render_result_card(
    query_idx: int,
    entry: ReportEntry,
    expanded: bool = True,
    profile: DatasetProfile = CLOUDTRAIL_PROFILE,
) -> None:
    """Render a single query result as an expander card.

    Displays SQL, results table, chart, AI analysis, analyst note, and Ask AI button.
    The Ask AI button appears below the analyst note for any card without analysis.
    Shared between chat-interleaved and bulk-results views.

    Args:
        query_idx: 0-based index into query_history.
        entry:     The ReportEntry to render.
        expanded:  Whether the expander starts open.
        profile:   Dataset profile owning the entry; scopes state and widget keys.
    """
    prefix = profile.key
    title = _build_expander_title(entry, query_idx + 1)
    with st.expander(title, expanded=expanded):
        # Category + label as large heading inside the card
        if entry.label:
            if entry.category:
                st.markdown(f"### {entry.category}  ›  {entry.label}")
            else:
                st.markdown(f"### {entry.label}")
        if entry.description:
            st.caption(f"ℹ️ {entry.description}")
        for technique in entry.techniques:
            st.caption(_format_technique_caption(technique))
        st.code(entry.sql, language="sql")

        if entry.results is not None and not entry.results.empty:
            if len(entry.results) >= st.session_state.row_limit:
                st.warning(
                    f"⚠️ Results are truncated to **{st.session_state.row_limit:,} rows**. "
                    "Add a `LIMIT` clause or narrow your query for more specific results."
                )
            st.dataframe(entry.results, use_container_width=True)
            render_chart(entry.results, entry.chart_config)
        else:
            st.info("No results returned.")

        if entry.analysis:
            st.markdown("#### 🤖 AI Analysis")
            st.info(entry.analysis)

        # UI-01: Analyst note text area
        st.divider()
        note_key = f"{prefix}_analyst_note_{query_idx}"
        notes = st.session_state[profile.state_key("analyst_notes")]
        current_note = notes.get(query_idx, entry.analyst_note)
        new_note = st.text_area(
            "📝 Analyst Note (Markdown)",
            value=current_note,
            key=note_key,
            height=80,
            placeholder="Write your investigation notes here…",
            label_visibility="visible",
        )
        if new_note != current_note:
            notes[query_idx] = new_note
            entry.analyst_note = new_note

        # Ask AI button — shown for every card that has no analysis yet.
        if not entry.analysis:
            has_api_key = bool(st.session_state.api_key)
            if st.button(
                "🤖 Ask AI — Analyze These Results",
                key=f"{prefix}_ask_ai_btn_{query_idx}",
                use_container_width=True,
                disabled=not has_api_key,
                help=(
                    "Generate a DFIR analysis of the query results above."
                    if has_api_key
                    else "Enter your OpenAI API key in the sidebar to enable AI analysis."
                ),
            ):
                st.session_state[f"_{prefix}_pending_ai_analysis_idx"] = query_idx
                st.rerun()


def render_chat(profile: DatasetProfile = CLOUDTRAIL_PROFILE) -> None:
    """Render the main chat area.

    Displays chat history (AGT-01), SQL editor (AGT-03), results table (AGT-04),
    AI analysis (AGT-05), bulk results section (UI-03), and progress bar (UI-04).

    Args:
        profile: Dataset profile the page is querying. Selects the table, the
                 filters, the session namespace and the widget keys.
    """
    prefix = profile.key

    # ---- Filter bar (always visible at the top) ----
    result_filter, keyword = _render_query_filter(profile)

    db_path = _get_duckdb_path(profile)

    # Handle any pending preset injected from the sidebar
    pending_preset = st.session_state.pop(f"_{prefix}_pending_preset", None)

    # Handle direct SQL execution from a built-in preset (no AI needed)
    pending_direct_sql = st.session_state.pop(f"_{prefix}_pending_direct_sql", None)
    pending_preset_description = st.session_state.pop(
        f"_{prefix}_pending_preset_description", ""
    )
    pending_chart_config = st.session_state.pop(f"_{prefix}_pending_chart_config", None)
    pending_preset_label = st.session_state.pop(f"_{prefix}_pending_preset_label", "")
    pending_preset_category = st.session_state.pop(
        f"_{prefix}_pending_preset_category", ""
    )
    pending_preset_techniques = st.session_state.pop(
        f"_{prefix}_pending_preset_techniques", []
    )
    if pending_direct_sql:
        _handle_direct_sql(
            pending_direct_sql,
            db_path,
            description=pending_preset_description,
            chart_config=pending_chart_config,
            label=pending_preset_label,
            category=pending_preset_category,
            techniques=pending_preset_techniques,
            bulk_mode=True,  # no chat bubble — show in Query Results section
            profile=profile,
        )
        st.rerun()

    # Handle bulk execution of all SQL queries in a selected category (UI-03/04)
    pending_bulk_queries = st.session_state.pop(f"_{prefix}_pending_bulk_queries", None)
    if pending_bulk_queries:
        total = len(pending_bulk_queries)
        # UI-04: use the slot created by render_sidebar() just below preset queries.
        # Falls back to a new sidebar placeholder if the slot is missing (e.g. tests).
        progress_placeholder = (
            st.session_state.get(f"_{prefix}_bulk_progress_slot") or st.sidebar.empty()
        )
        for i, q in enumerate(pending_bulk_queries, 1):
            with progress_placeholder.container():
                st.progress(
                    i / total,
                    text=f"🤖 Running {i}/{total}: {q['label']}",
                )
            _handle_direct_sql(
                q["sql"],
                db_path,
                description=q["description"],
                chart_config=q["chart_config"],
                bulk_mode=True,
                label=q["label"],
                category=q.get("category", ""),
                techniques=q.get("techniques") or [],
                profile=profile,
            )
        progress_placeholder.empty()
        st.rerun()

    # Handle AI analysis request triggered from a result card's Ask AI button.
    pending_ai_analysis_idx = st.session_state.pop(
        f"_{prefix}_pending_ai_analysis_idx", None
    )
    if pending_ai_analysis_idx is not None:
        _analyze_entry_results(pending_ai_analysis_idx, profile)
        st.rerun()

    # ---- Chat history interleaved with query results (AGT-01 / AGT-04) ----
    history = st.session_state[profile.state_key("query_history")]
    query_history_len = len(history)

    for msg in st.session_state[profile.state_key("messages")]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

        query_idx = msg.get("query_index")
        if query_idx is not None and query_idx < query_history_len:
            entry = history[query_idx]
            if entry.source == "chat":
                _render_result_card(query_idx, entry, profile=profile)

    # ---- Bulk results section (UI-03) ----
    # ---- Direct SQL / Bulk results section (UI-03) ----
    # All non-chat entries (source != "chat") are shown here, collapsed by default.
    nonchat_entries = [(i, e) for i, e in enumerate(history) if e.source != "chat"]
    if nonchat_entries:
        filtered_entries = _apply_entry_filter(nonchat_entries, result_filter, keyword)
        st.divider()
        count_str = f"{len(filtered_entries)} / {len(nonchat_entries)}"
        st.markdown(
            f"#### 🤖 Query Results  <small style='font-size:0.8em;color:gray'>({count_str})</small>",
            unsafe_allow_html=True,
        )
        if filtered_entries:
            for idx, entry in filtered_entries:
                _render_result_card(idx, entry, expanded=False, profile=profile)
        else:
            st.caption("No queries match the current filter.")

    # ---- SQL editor for the last query (AGT-03) ----
    last_sql = st.session_state[profile.state_key("last_sql")]
    if last_sql:
        with st.expander("🛠 Edit & Re-run SQL", expanded=False):
            edited_sql = st.text_area(
                "SQL",
                value=last_sql,
                height=150,
                label_visibility="collapsed",
                key=f"_{prefix}_sql_editor",
            )
            if st.button("▶ Run Edited SQL", key=f"_{prefix}_run_edited_sql"):
                _handle_edit_rerun_sql(edited_sql, db_path, profile)
                st.rerun()

    # ---- Chat input (AGT-01) ----
    user_input = (
        st.chat_input("Ask a threat hunting question…", key=f"_{prefix}_chat_input")
        or pending_preset
    )

    if user_input:
        st.session_state[profile.state_key("messages")].append(
            {"role": "user", "content": user_input}
        )
        with st.chat_message("user"):
            st.markdown(user_input)

        _handle_user_query(user_input, db_path, profile)
        st.rerun()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _chat_page() -> None:
    """Render the AI threat-hunting chat page for CloudTrail events."""
    _init_session_state(CLOUDTRAIL_PROFILE)
    render_sidebar(CLOUDTRAIL_PROFILE)
    render_chat(CLOUDTRAIL_PROFILE)


def _suzaku_timeline_page() -> None:
    """Render the Suzaku ``aws-ct-timeline`` hunting page."""
    from views.suzaku_timeline import render  # noqa: PLC0415

    render()


def build_pages() -> list:
    """Return the navigation pages, CloudTrail first.

    Both pages share the hunting UI; they differ only in their
    :class:`~profiles.DatasetProfile` (see ``profiles.py``).

    Returns:
        A list of ``st.Page`` objects for :func:`st.navigation`.
    """
    return [
        st.Page(
            _chat_page,
            title=CLOUDTRAIL_PROFILE.label,
            icon=CLOUDTRAIL_PROFILE.icon,
            url_path="senrigan",
            default=True,
        ),
        st.Page(
            _suzaku_timeline_page,
            title=SUZAKU_TIMELINE_PROFILE.label,
            icon=SUZAKU_TIMELINE_PROFILE.icon,
            url_path="suzaku-timeline",
        ),
    ]


def main() -> None:
    """Configure page chrome and run the multi-page navigation."""
    st.set_page_config(
        page_title="Senrigan",
        page_icon="🔭",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    st.navigation(build_pages()).run()


if __name__ == "__main__":
    main()
