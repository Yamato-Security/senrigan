"""Streamlit entry point for the Senrigan AI threat hunting agent.

Provides an interactive chat UI for AI-assisted threat hunting on
AWS CloudTrail logs stored in DuckDB.
"""

from datetime import date
from pathlib import Path

import streamlit as st

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
from profiles import (
    CLOUDTRAIL_PROFILE,
    SUZAKU_METRICS_PROFILE,
    SUZAKU_SUMMARY_PROFILE,
    SUZAKU_TIMELINE_PROFILE,
    DatasetProfile,
)
from query import DEFAULT_ROW_LIMIT
from report import ReportEntry, generate_report, generate_html_report

# Re-exported alongside their own use: these names are imported from ``app`` by
# the test suite and, for ``render_chart``, resolved through this module at call
# time by ``views/explorer.py`` — which is also what the explorer tests patch.
from session import (
    SESSION_STATE_DEFAULTS,  # noqa: F401
    _build_all_hunt_queries,
    _clear_session,
    _export_session,
    _format_playbook_caption,
    _format_severity_caption,
    _format_technique_caption,
    _init_session_state,
    _load_builtin_prompts,
)
from views.charts import render_chart
from views.db_selector import (  # noqa: F401
    _discover_suzaku_dbs,
    _render_suzaku_db_selector,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Available OpenAI models for the sidebar model selector.
MODEL_OPTIONS: list[str] = ["gpt-5.5", "gpt-5.4", "gpt-5.4-mini"]


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


def render_sidebar(profile: DatasetProfile = CLOUDTRAIL_PROFILE) -> None:
    """Render the sidebar: API key, model selection, presets, report, session export.

    Handles AGT-07 (preset prompts), AGT-08 (session export), AGT-09 (API key).

    Every widget key is prefixed with the profile key so the two pages do not
    share widget state, and every history read goes through the profile's
    session namespace.

    The call order below *is* the sidebar the analyst reads top to bottom, and
    the two filter groups are deliberately not adjacent: date and severity
    narrow what a query returns, so they sit with the presets that produce it,
    while the row cap and the geo toggle shape how results are shown and sit
    below the report. Every section renders inside this one ``st.sidebar``
    context — none of them opens its own.

    Args:
        profile: Dataset profile the page is querying.
    """
    with st.sidebar:
        _render_db_variant_section(profile)
        _render_preset_section(profile)
        _render_date_filter(profile)
        _render_severity_filter(profile)

        st.divider()

        render_report_section(profile)

        st.divider()

        render_session_section(profile)

        st.divider()

        _render_result_limit_section(profile)

        st.divider()

        render_api_section(profile)


def _render_db_variant_section(profile: DatasetProfile) -> None:
    """Render the pulldown naming the DuckDB file this page reads.

    The Suzaku pages resolve their file by discovery and say so in their own
    🗄️ Suzaku Database picker; the CloudTrail page never did, so an analyst
    running several databases had no way to tell which one answered a query.
    The pulldown always renders here for that reason — with the Lite variant
    as a second option only when ``DUCKDB_PATH_LITE`` is configured, and
    otherwise as a one-entry, read-only statement of the active file.

    Renders nothing at all for the Suzaku profiles: the variant describes how
    ``cloudtrail_events`` was ingested and means nothing to a Suzaku file, and
    a second database control would contradict the picker they already show.

    Args:
        profile: Dataset profile the page is querying.
    """
    if profile.key != CLOUDTRAIL_PROFILE.key:
        return

    # The Lite variant points at a DuckDB file produced by
    # `ingester ingest --strip-fields`, where pagination/idempotency
    # noise has been removed from request_parameters / response_elements.
    lite_path = get_duckdb_path_lite()
    variants = [DB_VARIANT_FULL] + ([DB_VARIANT_LITE] if lite_path else [])

    st.subheader("🗄️ Database")
    current = st.session_state.get("db_variant", DB_VARIANT_FULL)
    if current not in variants:
        current = DB_VARIANT_FULL
    chosen = st.selectbox(
        "Variant",
        options=variants,
        index=variants.index(current),
        format_func=lambda variant: (
            f"{variant} — {Path(get_duckdb_path_for_variant(variant)).name}"
        ),
        # One variant is nothing to choose between; the pulldown is then only
        # there to say what is being read.
        disabled=len(variants) == 1,
        help=(
            "Full = original CloudTrail records.  "
            "Lite = noise fields stripped from request_parameters "
            "/ response_elements (pagination tokens, idempotency "
            "tokens, opaque session credentials, AWS catalogue "
            "echoes, query-time filter echoes, redundant Host "
            "headers). raw_event is preserved in both variants."
        ),
        key="_db_variant_select",
    )
    if chosen != st.session_state.get("db_variant"):
        st.session_state.db_variant = chosen
    active_path = get_duckdb_path_for_variant(st.session_state.db_variant)
    st.caption(f"📁 `{active_path}`")


def _render_bulk_run_buttons(
    prefix: str,
    prompts: list[dict],
    filtered: list[dict],
    current_category: str,
) -> None:
    """Queue every SQL hunt in scope, either the whole catalogue or one category.

    Called *before* the Category selectbox is rendered, so the category it acts
    on is the one read back out of session state rather than the selectbox's
    return value — see :func:`_render_preset_section`.

    Args:
        prefix:           Widget-key prefix (the profile key).
        prompts:          Every hunt loaded for this profile.
        filtered:         The hunts in the current category.
        current_category: Category read from session state this run.
    """
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
                    "severity": p.get("severity", ""),
                    "playbook": p.get("playbook") or {},
                    "next_steps": p.get("next_steps", ""),
                }
                for p in sql_queries
            ]
            st.rerun()


def _render_preset_section(profile: DatasetProfile) -> None:
    """Render the preset hunt picker: bulk-run buttons, category, preset, Direct SQL.

    The bulk-run buttons are rendered *above* the Category selectbox while
    depending on the category the analyst chose. Streamlit renders top to
    bottom, so the category cannot come from the selectbox's return value here —
    it is read back out of session state under the selectbox's own widget key,
    and the prompt list is re-filtered afterwards if the selectbox reports a
    different value on this run. Reordering the two would leave the buttons one
    rerun behind the selection.

    Args:
        profile: Dataset profile whose hunts to offer.
    """
    prefix = profile.key

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
    _render_bulk_run_buttons(prefix, prompts, filtered, current_category)

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
            filtered = [p for p in prompts if p.get("category") == selected_category]

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

            # Triage first: how urgent this is, and which playbook owns the
            # response. Both come before the technique mappings because they are
            # what an analyst acts on.
            severity_caption = _format_severity_caption(matched.get("severity", ""))
            if severity_caption:
                st.caption(severity_caption)
            playbook_caption = _format_playbook_caption(matched.get("playbook"))
            if playbook_caption:
                st.caption(playbook_caption)

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
                    st.session_state[f"_{prefix}_pending_chart_config"] = matched.get(
                        "chart"
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
                    st.session_state[f"_{prefix}_pending_preset_severity"] = (
                        matched.get("severity", "")
                    )
                    st.session_state[f"_{prefix}_pending_preset_playbook"] = (
                        matched.get("playbook") or {}
                    )
                    st.session_state[f"_{prefix}_pending_preset_next_steps"] = (
                        matched.get("next_steps", "")
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


def _render_date_filter(profile: DatasetProfile) -> None:
    """Render the From/To date inputs and persist them in the profile's namespace.

    Args:
        profile: Dataset profile whose date range to edit.
    """
    prefix = profile.key

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


def _render_severity_filter(profile: DatasetProfile) -> None:
    """Render the severity multiselect, for a dataset that has severities.

    Args:
        profile: Dataset profile whose level column to filter on.
    """
    # Severity filter — only for a dataset that has severities (Suzaku).
    # low + informational dominate the row count, so they start unselected:
    # without this the page shows noise, not detections.
    if not profile.level_column:
        return

    st.subheader("🎚 Severity Filter")
    selected_levels = st.multiselect(
        profile.level_column,
        options=list(profile.level_order),
        default=st.session_state[profile.state_key("levels")],
        key=f"_{profile.key}_levels_input",
        help=(
            "Severities to keep. Selecting all of them is the same as no "
            "filter. `low` and `informational` are the bulk of the data."
        ),
    )
    st.session_state[profile.state_key("levels")] = selected_levels
    if not selected_levels:
        st.caption("🔍 No severity filter — every level is included.")


def _render_result_limit_section(profile: DatasetProfile) -> None:
    """Render the per-query row cap and the geo-enrichment toggle.

    Both are output settings shared across pages rather than per-profile state,
    so they are written to the bare session keys, not the profile's namespace.

    Args:
        profile: Dataset profile the page is querying.
    """
    prefix = profile.key

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


def render_report_section(profile: DatasetProfile = CLOUDTRAIL_PROFILE) -> None:
    """Render the Markdown / HTML report downloads (AGT-06).

    Shared with the explorer pages, whose panels pin findings into the same
    ``query_history`` this reads.

    Args:
        profile: Dataset profile whose history to report on.
    """
    prefix = profile.key
    st.subheader("📄 Report")
    history = st.session_state[profile.state_key("query_history")]
    report_title = f"Senrigan {profile.label} Report"
    if not history:
        st.caption("Run at least one query to generate a report.")
        return

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


def render_session_section(profile: DatasetProfile = CLOUDTRAIL_PROFILE) -> None:
    """Render the session export and the Clear button (AGT-08).

    Args:
        profile: Dataset profile whose session this manages.
    """
    prefix = profile.key
    st.subheader("💾 Session")
    history = st.session_state[profile.state_key("query_history")]
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


def render_api_section(profile: DatasetProfile = CLOUDTRAIL_PROFILE) -> None:
    """Render the API key and model selection (AGT-09).

    Both are shared state: entered once, they apply to every page — including
    the explorer pages, where the key enables per-panel AI narration.

    Args:
        profile: Dataset profile the page is on; scopes the widget keys only.
    """
    prefix = profile.key
    # Placed last in the sidebar — rarely changed after initial setup.
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
        severity_caption = _format_severity_caption(entry.severity)
        if severity_caption:
            st.caption(severity_caption)
        playbook_caption = _format_playbook_caption(entry.playbook)
        if playbook_caption:
            st.caption(playbook_caption)
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
            render_chart(
                entry.results,
                entry.chart_config,
                key=f"{prefix}_chart_{query_idx}",
            )
            # Containment guidance belongs with a hit, not with an empty result.
            if entry.next_steps:
                st.warning(f"**Next steps** — {entry.next_steps}")
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
    pending_preset_severity = st.session_state.pop(
        f"_{prefix}_pending_preset_severity", ""
    )
    pending_preset_playbook = st.session_state.pop(
        f"_{prefix}_pending_preset_playbook", {}
    )
    pending_preset_next_steps = st.session_state.pop(
        f"_{prefix}_pending_preset_next_steps", ""
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
            severity=pending_preset_severity,
            playbook=pending_preset_playbook,
            next_steps=pending_preset_next_steps,
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
                severity=q.get("severity", ""),
                playbook=q.get("playbook") or {},
                next_steps=q.get("next_steps", ""),
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


def _suzaku_summary_page() -> None:
    """Render the Suzaku ``aws-ct-summary`` explorer page."""
    from views.suzaku_summary import render  # noqa: PLC0415

    render()


def _suzaku_metrics_page() -> None:
    """Render the Suzaku ``aws-ct-metrics`` explorer page."""
    from views.suzaku_metrics import render  # noqa: PLC0415

    render()


# Page objects built by :func:`build_pages`, keyed by profile. ``st.switch_page``
# needs the very object ``st.navigation`` was given, so the pivot from an
# explorer page into the timeline page reads it
# from here rather than rebuilding one.
PAGES: dict[str, object] = {}


def build_pages() -> list:
    """Return the navigation pages, CloudTrail first.

    The first two are chat pages sharing the hunting UI, differing only in their
    :class:`~profiles.DatasetProfile`. The last two are explorer pages over
    Suzaku's pre-aggregated output, which generate no SQL at all.

    Returns:
        A list of ``st.Page`` objects for :func:`st.navigation`.
    """
    pages = [
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
        st.Page(
            _suzaku_summary_page,
            title=SUZAKU_SUMMARY_PROFILE.label,
            icon=SUZAKU_SUMMARY_PROFILE.icon,
            url_path="suzaku-summary",
        ),
        st.Page(
            _suzaku_metrics_page,
            title=SUZAKU_METRICS_PROFILE.label,
            icon=SUZAKU_METRICS_PROFILE.icon,
            url_path="suzaku-metrics",
        ),
    ]
    PAGES.clear()
    PAGES.update(
        zip(
            (
                CLOUDTRAIL_PROFILE.key,
                SUZAKU_TIMELINE_PROFILE.key,
                SUZAKU_SUMMARY_PROFILE.key,
                SUZAKU_METRICS_PROFILE.key,
            ),
            pages,
        )
    )
    return pages


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
