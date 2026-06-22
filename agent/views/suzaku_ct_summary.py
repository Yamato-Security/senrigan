"""Streamlit page: visualize a Suzaku ``aws-ct-summary`` JSON.

Self-contained, read-only page. It does not touch DuckDB or the OpenAI
integration and works without an API key. The summary JSON is supplied by the
analyst via file upload (no mounted path, no docker-compose change).

Rendered as a page of the ``st.navigation`` app defined in ``app.py``; page
chrome (``st.set_page_config``) is owned by the entry point, not this file.
"""

import plotly.express as px
import streamlit as st

from suzaku_report import generate_html_report, generate_markdown_report
from suzaku_summary import (
    SuzakuSummaryError,
    activity_timeline,
    api_entries_df,
    build_triage_table,
    country_counts,
    find_identity,
    parse_summary,
    top_n,
    value_entries_df,
)

TOP_N = 10


@st.cache_data(show_spinner=False)
def _parse_cached(raw: bytes) -> list[dict]:
    """Parse uploaded bytes once; cached on file content."""
    return parse_summary(raw)


def _render_top_section(
    title: str, df, *, label_col: str, count_col: str = "count"
) -> None:
    """Render a Top-N horizontal bar chart plus the full table for an entry list."""
    st.markdown(f"#### {title}")
    if df.empty:
        st.caption("No data.")
        return

    chart_df = top_n(df, TOP_N)
    fig = px.bar(
        chart_df.iloc[::-1],  # reverse so the largest bar sits on top
        x=count_col,
        y=label_col,
        orientation="h",
    )
    fig.update_layout(
        height=max(200, 28 * len(chart_df)), margin=dict(l=0, r=0, t=10, b=0)
    )
    st.plotly_chart(fig, use_container_width=True, key=f"chart-top-{title}")
    st.dataframe(df, use_container_width=True, hide_index=True, key=f"df-top-{title}")


def _render_detail(summary: dict) -> None:
    """Render the per-identity detail view (F3)."""
    st.subheader(summary.get("user_arn", ""))

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Type", summary.get("user_types", "-"))
    c2.metric("Total events", f"{summary.get('num_of_events', 0):,}")
    c3.metric("First seen", summary.get("first_timestamp", "-"))
    c4.metric("Last seen", summary.get("last_timestamp", "-"))

    # --- Abused APIs (primary threat signal) ---------------------------------
    st.divider()
    st.markdown("### 🔴 Abused APIs")
    a1, a2 = st.columns(2)
    with a1:
        _render_api_block(
            "✅ Succeeded", summary.get("abused_apis_success"), key="abused-success"
        )
    with a2:
        _render_api_block(
            "❌ Failed", summary.get("abused_apis_failed"), key="abused-failed"
        )

    # --- Activity timeline ---------------------------------------------------
    tl = activity_timeline(summary)
    if not tl.empty:
        st.divider()
        st.markdown("### 🕒 Abused-API Activity Timeline")
        fig = px.timeline(
            tl,
            x_start="start",
            x_end="end",
            y="api",
            color="status",
            color_discrete_map={"success": "#d62728", "failed": "#7f7f7f"},
            hover_data=["count"],
        )
        fig.update_yaxes(autorange="reversed")
        fig.update_layout(
            height=max(220, 32 * len(tl)), margin=dict(l=0, r=0, t=10, b=0)
        )
        st.plotly_chart(fig, use_container_width=True, key="chart-timeline")

    # --- Source IPs / Regions / User agents / Access keys --------------------
    st.divider()
    st.markdown("### 🌐 Source & Identity Breakdown")
    b1, b2 = st.columns(2)
    with b1:
        _render_top_section(
            "Source IPs", value_entries_df(summary.get("src_ips")), label_col="value"
        )
        _render_country_section(summary.get("src_ips"))
    with b2:
        _render_top_section(
            "AWS Regions",
            value_entries_df(summary.get("aws_regions")),
            label_col="value",
        )
        _render_top_section(
            "User Agents",
            value_entries_df(summary.get("user_agents")),
            label_col="value",
        )
    _render_top_section(
        "Access Key IDs",
        value_entries_df(summary.get("user_access_key_ids")),
        label_col="value",
    )

    # --- Other (non-flagged) APIs --------------------------------------------
    st.divider()
    st.markdown("### Other APIs (non-flagged)")
    o1, o2 = st.columns(2)
    with o1:
        _render_api_block(
            "✅ Succeeded", summary.get("other_apis_success"), key="other-success"
        )
    with o2:
        _render_api_block(
            "❌ Failed", summary.get("other_apis_failed"), key="other-failed"
        )


def _render_api_block(title: str, entries, *, key: str) -> None:
    """Render an ApiEntry block: a count bar chart plus the full table.

    ``key`` must be unique per call site so the chart/table/download widgets do
    not collide (the same ✅/❌ titles are reused for abused and other APIs).
    """
    st.markdown(f"**{title}**")
    df = api_entries_df(entries)
    if df.empty:
        st.caption("None.")
        return
    chart_df = top_n(df, TOP_N)
    fig = px.bar(chart_df.iloc[::-1], x="count", y="api", orientation="h")
    fig.update_layout(
        height=max(160, 28 * len(chart_df)), margin=dict(l=0, r=0, t=10, b=0)
    )
    st.plotly_chart(fig, use_container_width=True, key=f"chart-api-{key}")
    st.dataframe(df, use_container_width=True, hide_index=True, key=f"df-api-{key}")
    _download_csv(df, f"{key}-apis.csv")


def _render_country_section(src_ips) -> None:
    """Render the per-country aggregation of source-IP activity (F3 / §7 GeoIP)."""
    df = country_counts(src_ips)
    st.markdown("#### Source Countries")
    if df.empty:
        st.caption("No data.")
        return
    chart_df = df.head(TOP_N)
    fig = px.bar(chart_df.iloc[::-1], x="count", y="country", orientation="h")
    fig.update_layout(
        height=max(200, 28 * len(chart_df)), margin=dict(l=0, r=0, t=10, b=0)
    )
    st.plotly_chart(fig, use_container_width=True, key="chart-country")


def _download_csv(df, filename: str) -> None:
    """Render a CSV download button for ``df`` (F4)."""
    st.download_button(
        "⬇️ CSV",
        df.to_csv(index=False).encode("utf-8"),
        file_name=filename,
        mime="text/csv",
        key=f"dl-{filename}-{id(df)}",
    )


@st.cache_data(show_spinner=False)
def _build_reports(summaries: list[dict]) -> tuple[str, str]:
    """Build the Markdown and HTML reports once, cached on the parsed summaries."""
    return generate_markdown_report(summaries), generate_html_report(summaries)


def _render_uploader():
    """Render the file uploader in the left menu and return the uploaded file.

    Kept separate from the Report/Session sections so the uploader is always
    visible in the sidebar, even before a file has been loaded.
    """
    with st.sidebar:
        st.subheader("📁 Summary File")
        st.session_state.setdefault("suzaku_uploader_key", 0)
        return st.file_uploader(
            "aws-ct-summary JSON / JSONL",
            type=["json", "jsonl"],
            key=f"suzaku_upload_{st.session_state.suzaku_uploader_key}",
        )


def _render_sidebar(summaries: list[dict], raw: bytes) -> None:
    """Render the left-menu Report and Session sections.

    Mirrors the chat page's sidebar (📄 Report / 💾 Session) so both pages share
    the same layout. ``raw`` is the original uploaded JSON, re-offered verbatim
    as the session export.
    """
    with st.sidebar:
        st.divider()

        # --- Report ----------------------------------------------------------
        st.subheader("📄 Report")
        markdown_report, html_report = _build_reports(summaries)
        dl1, dl2 = st.columns(2)
        with dl1:
            st.download_button(
                label="⬇ Markdown",
                data=markdown_report,
                file_name="suzaku-summary-report.md",
                mime="text/markdown",
                use_container_width=True,
            )
        with dl2:
            st.download_button(
                label="⬇ HTML",
                data=html_report,
                file_name="suzaku-summary-report.html",
                mime="text/html",
                use_container_width=True,
            )

        st.divider()

        # --- Session ---------------------------------------------------------
        st.subheader("💾 Session")
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                label="Export JSON",
                data=raw,
                file_name="suzaku-summary.json",
                mime="application/json",
                use_container_width=True,
            )
        with col2:
            if st.button("🗑 Clear", use_container_width=True):
                # Reset the file_uploader by rotating its widget key.
                st.session_state.suzaku_uploader_key += 1
                st.rerun()


def main() -> None:
    st.title("☁️ Suzaku CloudTrail Summary")

    uploaded = _render_uploader()
    if uploaded is None:
        st.info(
            "Upload an `aws-ct-summary` JSON or JSONL file in the sidebar to begin."
        )
        return

    raw = uploaded.getvalue()
    try:
        summaries = _parse_cached(raw)
    except SuzakuSummaryError as exc:
        st.error(f"Could not read summary: {exc}")
        return

    triage = build_triage_table(summaries)

    _render_sidebar(summaries, raw)

    st.markdown("### 🎯 Identity Triage")
    st.caption("Sorted by abused-API count, then event count.")
    st.dataframe(triage, use_container_width=True, hide_index=True)
    _download_csv(triage, "suzaku-triage.csv")

    st.divider()

    # Identity drill-down: pick which user_arn to inspect (defaults to the most
    # suspicious one, i.e. the first triage row).
    arns = triage["user_arn"].tolist()
    labels = {
        row.user_arn: (
            f"{row.user_arn}  —  {row.user_type} · "
            f"{row.total_events:,} events · "
            f"abused {row.abused_success}✅/{row.abused_failed}❌"
        )
        for row in triage.itertuples()
    }
    st.markdown("### 👤 Inspect identity")
    selected_arn = st.selectbox(
        "Inspect identity",
        options=arns,
        format_func=lambda a: labels.get(a, a),
        label_visibility="collapsed",
    )

    summary = find_identity(summaries, selected_arn)
    if summary is not None:
        _render_detail(summary)


main()
