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
from query import DEFAULT_ROW_LIMIT
from report import ReportEntry, generate_report, generate_html_report

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

    with st.expander("📊 Bar Chart", expanded=True):
        st.plotly_chart(fig, use_container_width=True)


def _render_timeseries_chart(df: pd.DataFrame, chart_config: dict) -> None:
    """Render a time-series bar chart by bucketing the event_time column.

    Skips rendering when the DataFrame has no event_time column, when the
    timestamps cannot be parsed, or when there is only one distinct bucket
    (a single-bar chart provides no visual value).

    Args:
        df:           The query result DataFrame containing an event_time column.
        chart_config: Chart configuration dict; uses bucket='day' by default.
    """
    if "event_time" not in df.columns:
        return

    bucket = chart_config.get("bucket", "day")
    ts = pd.to_datetime(df["event_time"], errors="coerce").dropna()
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

    with st.expander(title, expanded=True):
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


def _init_session_state() -> None:
    """Initialize Streamlit session state with default values.

    Idempotent: only sets keys that are not already present, so existing
    session data is never overwritten on page reload.
    """
    for key, default in SESSION_STATE_DEFAULTS.items():
        if key not in st.session_state:
            st.session_state[key] = default


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


def _load_builtin_prompts() -> list[dict]:
    """Load built-in threat hunting prompts from the YAML file.

    Returns:
        A list of dicts, each containing 'label' and 'prompt' keys.
        Falls back to a minimal built-in list if the file is not found.
    """
    try:
        with open(_BUILTIN_PROMPTS_PATH, encoding="utf-8") as f:
            prompts = yaml.safe_load(f)
        if isinstance(prompts, list):
            return prompts
    except FileNotFoundError:
        logger.warning("builtin_hunts.yaml not found at %s", _BUILTIN_PROMPTS_PATH)
    except yaml.YAMLError as exc:
        logger.error("Failed to parse builtin_hunts.yaml: %s", exc)

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


def _get_duckdb_path() -> str:
    """Resolve the DuckDB path for the active session variant.

    When ``DUCKDB_PATH_LITE`` is set and the user has selected the Lite
    variant in the sidebar, return that path. Otherwise return the
    Full path from ``DUCKDB_PATH`` (or the Docker-standard default).
    """
    variant = st.session_state.get("db_variant", DB_VARIANT_FULL)
    return get_duckdb_path_for_variant(variant)


def render_sidebar() -> None:
    """Render the sidebar: API key, model selection, presets, report, session export.

    Handles AGT-07 (preset prompts), AGT-08 (session export), AGT-09 (API key).
    """
    with st.sidebar:
        # Database variant selector — only shown when a Lite DB has been
        # configured via the DUCKDB_PATH_LITE environment variable.
        # The Lite variant points at a DuckDB file produced by
        # `ingester ingest --strip-fields`, where pagination/idempotency
        # noise has been removed from request_parameters / response_elements.
        lite_path = get_duckdb_path_lite()
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
        prompts = _load_builtin_prompts()

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
            "_preset_category", "— All categories —"
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
                help="Run all built-in hunt queries across every category",
            ):
                st.session_state["_pending_bulk_queries"] = all_sql_queries
                st.rerun()
        elif sql_queries:
            # "Run All" — runs every SQL query in the selected category
            if st.button(
                f"⚡ Run All ({len(sql_queries)} queries)",
                use_container_width=True,
                help="Run all queries in this category",
            ):
                st.session_state["_pending_bulk_queries"] = [
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
            key="_preset_category",
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
            key="_preset_label",
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
                        help="Run without an API key",
                    ):
                        st.session_state["_pending_direct_sql"] = matched["sql"].strip()
                        st.session_state["_pending_preset_description"] = desc
                        st.session_state["_pending_chart_config"] = matched.get("chart")
                        st.session_state["_pending_preset_label"] = matched["label"]
                        st.session_state["_pending_preset_category"] = matched.get(
                            "category", ""
                        )
                        st.session_state["_pending_preset_techniques"] = (
                            matched.get("techniques") or []
                        )
                        st.rerun()
                else:
                    st.button(
                        "⚡ Direct SQL",
                        disabled=True,
                        use_container_width=True,
                        help="No pre-built SQL for this preset",
                    )

        # UI-04: progress bar slot — positioned right below preset queries.
        # Created here (inside the sidebar) so it always appears at this fixed
        # position. render_chat() retrieves and updates it during bulk execution.
        st.session_state["_bulk_progress_slot"] = st.empty()

        # Date range filter — placed below preset queries
        st.subheader("📅 Date Range Filter")
        today = date.today()
        dc1, dc2 = st.columns(2)
        with dc1:
            new_start = st.date_input(
                "From",
                value=st.session_state.date_start,
                max_value=today,
                format="YYYY-MM-DD",
                key="_date_start_input",
            )
        with dc2:
            new_end = st.date_input(
                "To",
                value=st.session_state.date_end,
                max_value=today,
                format="YYYY-MM-DD",
                key="_date_end_input",
            )

        # Persist date selections
        st.session_state.date_start = new_start or None
        st.session_state.date_end = new_end or None

        if new_start and new_end and new_start > new_end:
            st.error("⚠️ 'From' date must be before or equal to 'To' date.")
        elif new_start or new_end:
            start_s = str(new_start) if new_start else "—"
            end_s = str(new_end) if new_end else "—"
            st.caption(f"🔍 Active filter: **{start_s}** → **{end_s}**")

        st.divider()

        # AGT-06: Markdown / HTML report download
        st.subheader("📄 Report")
        if st.session_state.query_history:
            report_md = generate_report(
                st.session_state.query_history,
                title="Senrigan Threat Hunting Report",
            )
            report_html = generate_html_report(
                st.session_state.query_history,
                title="Senrigan Threat Hunting Report",
            )
            dl1, dl2 = st.columns(2)
            with dl1:
                st.download_button(
                    label="⬇ Markdown",
                    data=report_md,
                    file_name="threat_hunting_report.md",
                    mime="text/markdown",
                    use_container_width=True,
                )
            with dl2:
                st.download_button(
                    label="⬇ HTML",
                    data=report_html,
                    file_name="threat_hunting_report.html",
                    mime="text/html",
                    use_container_width=True,
                )
        else:
            st.caption("Run at least one query to generate a report.")

        st.divider()

        # AGT-08: Session export
        st.subheader("💾 Session")
        col1, col2 = st.columns(2)
        with col1:
            if st.session_state.query_history:
                session_json = _export_session(
                    st.session_state.query_history,
                    title="Senrigan Session",
                )
                st.download_button(
                    label="Export JSON",
                    data=session_json,
                    file_name="session.json",
                    mime="application/json",
                    use_container_width=True,
                )
            else:
                st.button("Export JSON", disabled=True, use_container_width=True)

        with col2:
            if st.button("🗑 Clear", use_container_width=True):
                st.session_state.messages = []
                st.session_state.query_history = []
                st.session_state.last_sql = ""
                st.session_state.last_results = None
                st.session_state.last_summary = ""
                st.session_state.conversation_context = []
                st.session_state.analyst_notes = {}
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
            help=(
                "Maximum number of rows returned per query. "
                "Overrides any LIMIT clause already present in the SQL."
            ),
        )
        if int(new_row_limit) != st.session_state.row_limit:
            st.session_state.row_limit = int(new_row_limit)

        # Automatic GeoIP context for IP columns (see agent/geo.py)
        st.session_state.geo_enrich = st.checkbox(
            "🌍 Auto geo-enrich IP columns",
            value=st.session_state.geo_enrich,
            help=(
                "When results contain an IP address column, automatically add "
                "the GeoIP columns (country, city, ISP organization) stored on "
                "cloudtrail_events next to it. No effect when the database was "
                "ingested without GeoLite2 databases."
            ),
        )

        st.divider()

        # AGT-09: API key input (placed last — rarely changed after initial setup)
        st.subheader("🔑 API Configuration")
        api_key_input = st.text_input(
            "OpenAI API Key",
            value=st.session_state.api_key,
            type="password",
            help="Your OpenAI API key. Never stored outside this browser session.",
        )
        if api_key_input != st.session_state.api_key:
            st.session_state.api_key = api_key_input

        # Model selection
        selected_model = st.selectbox(
            "Model",
            options=MODEL_OPTIONS,
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


def _render_query_filter() -> tuple[str, str]:
    """Render the compact filter bar at the top of the main area.

    Provides result-state filtering (All / Results / No results) and a
    free-text keyword filter applied against label, category, and description.

    Returns:
        Tuple of (result_filter, keyword).
    """
    st.subheader("🔍 Query Results Filter", divider=False)
    c1, c2, c3 = st.columns([3, 4, 1], vertical_alignment="bottom")
    with c1:
        result_filter = st.radio(
            "Show",
            options=["All", "✅ Results", "⬜ No results"],
            horizontal=True,
            key="_qf_result_filter",
            label_visibility="collapsed",
        )
    with c2:
        keyword = st.text_input(
            "Keyword",
            placeholder="🔍 label / category / description…",
            key="_qf_keyword",
            label_visibility="collapsed",
        )
    with c3:
        if st.button("✕ Clear", use_container_width=True, help="Clear filters"):
            st.session_state["_qf_result_filter"] = "All"
            st.session_state["_qf_keyword"] = ""
            st.rerun()
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
) -> None:
    """Render a single query result as an expander card.

    Displays SQL, results table, chart, AI analysis, analyst note, and Ask AI button.
    The Ask AI button appears below the analyst note for any card without analysis.
    Shared between chat-interleaved and bulk-results views.

    Args:
        query_idx: 0-based index into query_history.
        entry:     The ReportEntry to render.
        expanded:  Whether the expander starts open.
    """
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
        note_key = f"analyst_note_{query_idx}"
        current_note = st.session_state.analyst_notes.get(query_idx, entry.analyst_note)
        new_note = st.text_area(
            "📝 Analyst Note (Markdown)",
            value=current_note,
            key=note_key,
            height=80,
            placeholder="Write your investigation notes here…",
            label_visibility="visible",
        )
        if new_note != current_note:
            st.session_state.analyst_notes[query_idx] = new_note
            entry.analyst_note = new_note

        # Ask AI button — shown for every card that has no analysis yet.
        if not entry.analysis:
            has_api_key = bool(st.session_state.api_key)
            if st.button(
                "🤖 Ask AI — Analyze These Results",
                key=f"ask_ai_btn_{query_idx}",
                use_container_width=True,
                disabled=not has_api_key,
                help=(
                    "Generate a DFIR analysis of the query results above."
                    if has_api_key
                    else "Enter your OpenAI API key in the sidebar to enable AI analysis."
                ),
            ):
                st.session_state["_pending_ai_analysis_idx"] = query_idx
                st.rerun()


def render_chat() -> None:
    """Render the main chat area.

    Displays chat history (AGT-01), SQL editor (AGT-03), results table (AGT-04),
    AI analysis (AGT-05), bulk results section (UI-03), and progress bar (UI-04).
    """

    # ---- Filter bar (always visible at the top) ----
    result_filter, keyword = _render_query_filter()

    db_path = _get_duckdb_path()

    # Handle any pending preset injected from the sidebar
    pending_preset = st.session_state.pop("_pending_preset", None)

    # Handle direct SQL execution from a built-in preset (no AI needed)
    pending_direct_sql = st.session_state.pop("_pending_direct_sql", None)
    pending_preset_description = st.session_state.pop("_pending_preset_description", "")
    pending_chart_config = st.session_state.pop("_pending_chart_config", None)
    pending_preset_label = st.session_state.pop("_pending_preset_label", "")
    pending_preset_category = st.session_state.pop("_pending_preset_category", "")
    pending_preset_techniques = st.session_state.pop("_pending_preset_techniques", [])
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
        )
        st.rerun()

    # Handle bulk execution of all SQL queries in a selected category (UI-03/04)
    pending_bulk_queries = st.session_state.pop("_pending_bulk_queries", None)
    if pending_bulk_queries:
        total = len(pending_bulk_queries)
        # UI-04: use the slot created by render_sidebar() just below preset queries.
        # Falls back to a new sidebar placeholder if the slot is missing (e.g. tests).
        progress_placeholder = (
            st.session_state.get("_bulk_progress_slot") or st.sidebar.empty()
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
            )
        progress_placeholder.empty()
        st.rerun()

    # Handle AI analysis request triggered from a result card's Ask AI button.
    pending_ai_analysis_idx = st.session_state.pop("_pending_ai_analysis_idx", None)
    if pending_ai_analysis_idx is not None:
        _analyze_entry_results(pending_ai_analysis_idx)
        st.rerun()

    # ---- Chat history interleaved with query results (AGT-01 / AGT-04) ----
    query_history_len = len(st.session_state.query_history)

    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

        query_idx = msg.get("query_index")
        if query_idx is not None and query_idx < query_history_len:
            entry = st.session_state.query_history[query_idx]
            if entry.source == "chat":
                _render_result_card(query_idx, entry)

    # ---- Bulk results section (UI-03) ----
    # ---- Direct SQL / Bulk results section (UI-03) ----
    # All non-chat entries (source != "chat") are shown here, collapsed by default.
    nonchat_entries = [
        (i, e)
        for i, e in enumerate(st.session_state.query_history)
        if e.source != "chat"
    ]
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
                _render_result_card(idx, entry, expanded=False)
        else:
            st.caption("No queries match the current filter.")

    # ---- SQL editor for the last query (AGT-03) ----
    if st.session_state.last_sql:
        with st.expander("🛠 Edit & Re-run SQL", expanded=False):
            edited_sql = st.text_area(
                "SQL",
                value=st.session_state.last_sql,
                height=150,
                label_visibility="collapsed",
            )
            if st.button("▶ Run Edited SQL"):
                _handle_edit_rerun_sql(edited_sql, db_path)
                st.rerun()

    # ---- Chat input (AGT-01) ----
    user_input = st.chat_input("Ask a threat hunting question…") or pending_preset

    if user_input:
        st.session_state.messages.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)

        _handle_user_query(user_input, db_path)
        st.rerun()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _chat_page() -> None:
    """Render the AI threat-hunting chat page (the default page)."""
    _init_session_state()
    render_sidebar()
    render_chat()


def main() -> None:
    """Configure page chrome and dispatch to the selected page.

    Uses ``st.navigation`` so the sidebar entries have explicit titles and
    icons (e.g. the default page is labelled "Senrigan", not "app").
    """
    st.set_page_config(
        page_title="Senrigan",
        page_icon="🔭",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    pages = [
        st.Page(_chat_page, title="Senrigan", icon="🔭", default=True),
        st.Page(
            "views/suzaku_ct_summary.py",
            title="Suzaku CT Summary",
            icon="☁️",
        ),
    ]
    st.navigation(pages).run()


if __name__ == "__main__":
    main()
