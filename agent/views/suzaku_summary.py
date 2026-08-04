"""Streamlit page: explore Suzaku ``aws-ct-summary`` output.

Suzaku has already aggregated this file per identity, so the page generates no
SQL and asks no LLM to write any. What it adds over the Superset dashboard is
the investigation: pick an identity, see what it abused, follow one of its IPs
or keys to whoever else used it, compare two identities, and pin whatever
matters into the report.

The layout follows the prototype in ``doc/img-suzaku-summary.png`` — identity
selector, identity KPI row, abused APIs split succeeded / failed — with the
input changed from an uploaded JSON to the DuckDB file in the mounted directory.
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

import suzaku_summary_queries as queries
from profiles import SUZAKU_SUMMARY_PROFILE
from suzaku_db import SuzakuKind
from suzaku_queries import QueryResult
from views.explorer import (
    db_directory,
    load_db_info,
    render_empty_state,
    render_panel,
    render_run_info,
    render_sidebar_footer,
    render_timeline_pivot,
)

PROFILE = SUZAKU_SUMMARY_PROFILE
KIND = SuzakuKind.SUMMARY

_COMMAND = "suzaku aws-ct-summary -d <cloudtrail-logs> -t duckdb -o summary -G <MAXMIND-DB-DIR>"

# Attributes whose values are worth following to other identities. A region is
# shared by everyone, so offering the drill-down there would be noise.
_DRILLDOWN_ATTRIBUTES = ("SrcIP", "UserAgent", "UserAccessKeyID")


def _render_empty_state(directory: str) -> None:
    """Explain how to produce and place a summary database.

    Args:
        directory: The directory that was scanned, shown verbatim.
    """
    render_empty_state(KIND, directory, command=_COMMAND)


@st.cache_data(show_spinner=False, ttl=300)
def _query(db_path: str, stamp: float, name: str, args: tuple, kwargs: tuple):
    """Run one query from :mod:`suzaku_summary_queries` against *db_path*.

    Cached on the file's modification time as well as its path, so replacing the
    file invalidates every panel rather than serving the previous run's numbers.

    Args:
        db_path: The Suzaku database to read.
        stamp:   The file's mtime — part of the cache key.
        name:    Function name in :mod:`suzaku_summary_queries`.
        args:    Positional arguments after the connection.
        kwargs:  Keyword arguments, as ``(name, value)`` pairs so the key hashes.

    Returns:
        Whatever the named function returns.
    """
    from query import duckdb_connection  # noqa: PLC0415

    with duckdb_connection(db_path) as conn:
        return getattr(queries, name)(conn, *args, **dict(kwargs))


def _run(db_path: str, name: str, *args, **kwargs):
    """Call :func:`_query` with the current mtime of *db_path*."""
    return _query(
        db_path, Path(db_path).stat().st_mtime, name, args, tuple(kwargs.items())
    )


def _render_triage(db_path: str) -> tuple[str, list[str]]:
    """Render the run-wide KPIs and the identity triage table.

    Args:
        db_path: The Suzaku database to read.

    Returns:
        ``(selected_identity, every_identity)``; the first is ``""`` when the
        file holds none.
    """
    overview: QueryResult = _run(db_path, "identity_overview")
    kpis = queries.overview_kpis(overview.df)

    st.markdown("## 🧭 Identity triage")
    columns = st.columns(5)
    for column, (label, value, help_text) in zip(
        columns,
        (
            ("Identities", kpis["identities"], "Principals seen in this run."),
            ("Total events", kpis["total_events"], "CloudTrail events attributed."),
            (
                "Abused APIs ✅",
                kpis["abused_apis"],
                "Attack-relevant API calls that succeeded.",
            ),
            (
                "Abused APIs ❌",
                kpis["failed_abuse"],
                "Attack-relevant API calls that failed — probing.",
            ),
            (
                "With abuse",
                kpis["identities_abused"],
                "Identities with at least one abused API.",
            ),
        ),
    ):
        with column:
            st.metric(label, f"{value:,}", help=help_text)

    if overview.df.empty:
        st.caption("This summary database has no identities.")
        return "", []

    st.caption(
        "Ordered by abused APIs, then events. Click a row to inspect that identity."
    )
    event = st.dataframe(
        overview.df,
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key="_suzaku_summary_triage",
    )

    clicked = None
    rows = getattr(getattr(event, "selection", None), "rows", None)
    if rows:
        clicked = int(rows[0])

    arns = list(overview.df["user_arn"])
    stored = st.session_state.get(PROFILE.state_key("identity"), "")
    selected = queries.resolve_identity(arns, clicked, stored)

    with st.expander("📋 Triage table actions", expanded=False):
        render_panel(
            PROFILE,
            key="triage",
            label="🧭 Identity triage",
            category="👤 Identity",
            description="Every identity in this run, most abused first.",
            sql=overview.sql,
            df=overview.df,
            chart={"type": "none"},
            show_table=False,
        )

    labels = {
        arn: (
            f"{arn} — {row.user_types} · {row.num_of_events:,} events · "
            f"abused {row.abused_success}✅/{row.abused_failed}❌"
        )
        for arn, row in zip(arns, overview.df.itertuples())
    }
    chosen = st.selectbox(
        "👤 Inspect identity",
        options=arns,
        index=arns.index(selected) if selected in arns else 0,
        format_func=lambda arn: labels.get(arn, arn),
        key="_suzaku_summary_identity_select",
    )
    st.session_state[PROFILE.state_key("identity")] = chosen
    return chosen, arns


def _render_identity_header(db_path: str, arn: str) -> None:
    """Render the identity's name and its four headline facts.

    Args:
        db_path: The Suzaku database to read.
        arn:     The identity being inspected.
    """
    facts = _run(db_path, "identity_facts", arn).df
    st.markdown(f"### {arn}")
    if facts.empty:
        st.caption("This identity is not in the selected file.")
        return

    row = facts.iloc[0]
    for column, (label, value) in zip(
        st.columns(4),
        (
            ("Type", row["user_types"] or "—"),
            ("Total events", f"{int(row['num_of_events']):,}"),
            ("First seen", str(row["first_seen"])),
            ("Last seen", str(row["last_seen"])),
        ),
    ):
        with column:
            st.metric(label, value)


def _render_api_pair(db_path: str, arn: str, top_n: int, *, abused: bool) -> None:
    """Render the succeeded / failed pair of API panels side by side.

    Args:
        db_path: The Suzaku database to read.
        arn:     The identity being inspected.
        top_n:   Rows per panel.
        abused:  True for the APIs Suzaku flags as attack-relevant.
    """
    scope = "abused" if abused else "other"
    left, right = st.columns(2)
    for column, outcome, icon in ((left, "success", "✅"), (right, "failed", "❌")):
        with column:
            result = _run(
                db_path,
                "api_calls",
                arn,
                abused=abused,
                outcome=outcome,
                limit=top_n,
            )
            render_panel(
                PROFILE,
                key=f"{scope}_{outcome}",
                label=f"{icon} {scope.capitalize()} APIs — {outcome}",
                category="🔴 API abuse" if abused else "⚪ Other APIs",
                description=(
                    "Suzaku flags these as attack-relevant; the description says why."
                    if abused
                    else "Everything Suzaku did not flag."
                ),
                sql=result.sql,
                df=(
                    result.df[
                        ["api", "description", "count", "first_seen", "last_seen"]
                    ]
                    if not result.df.empty
                    else result.df
                ),
                chart={"type": "bar", "x": "api", "y": ["count"]},
                empty_message=f"No {scope} APIs {outcome} for this identity.",
            )


def _render_attribute_tab(db_path: str, arn: str, attribute: str, top_n: int) -> None:
    """Render one attribute tab: controls, panel and the shared-value drill-down.

    Args:
        db_path:   The Suzaku database to read.
        arn:       The identity being inspected.
        attribute: The attribute this tab covers.
        top_n:     Rows in the panel.
    """
    controls, toggle = st.columns([3, 1])
    with controls:
        search = st.text_input(
            "Filter values",
            key=f"_suzaku_summary_search_{attribute}",
            placeholder="substring, case-insensitive",
        )
    with toggle:
        rare = st.toggle(
            "Rare first",
            key=f"_suzaku_summary_rare_{attribute}",
            help="Sort ascending so single-use values come first.",
        )

    result = _run(
        db_path,
        "attribute_values",
        arn,
        attribute,
        limit=top_n,
        ascending=rare,
        search=search,
    )
    render_panel(
        PROFILE,
        key=f"attr_{attribute}",
        label=f"{'🪶 Rare' if rare else '📈 Top'} {attribute} values",
        category="🌐 Attributes",
        sql=result.sql,
        df=result.df,
        chart={"type": "bar", "x": "value", "y": ["count"]},
        empty_message="No values match.",
    )

    if attribute not in _DRILLDOWN_ATTRIBUTES or result.df.empty:
        return

    values = list(result.df["value"].dropna())
    if not values:
        return

    followed = st.selectbox(
        "Who else used this value?",
        options=["— none —", *values],
        key=f"_suzaku_summary_follow_{attribute}",
        help="The drill-down the dashboard cannot offer: from a value to every "
        "identity that used it.",
    )
    if followed == "— none —":
        return

    shared = _run(db_path, "identities_sharing", attribute, followed)
    others = len(shared.df) - 1
    st.caption(
        f"`{followed}` was used by {len(shared.df)} identities"
        + (f" — {others} besides this one." if others > 0 else " — only this one.")
    )
    render_panel(
        PROFILE,
        key=f"shared_{attribute}",
        label=f"🔗 Identities sharing {attribute}",
        category="🌐 Attributes",
        description=f"Every identity that used `{followed}`.",
        sql=shared.sql,
        df=shared.df,
        chart={"type": "bar", "x": "user_arn", "y": ["count"]},
    )
    render_timeline_pivot(
        key=f"attr_{attribute}",
        column=attribute,
        value=followed,
        label=f"🕒 Timeline — {attribute} {followed}",
    )


def _render_comparison(db_path: str, arn: str, arns: list[str]) -> None:
    """Render the two-identity set comparison.

    Shared APIs, IPs, user agents or access keys are the fastest evidence that
    two identities were driven by the same hands — and a set operation is not
    something a Superset chart can express.

    Args:
        db_path: The Suzaku database to read.
        arn:     The identity being inspected.
        arns:    Every identity in the file, in triage order.
    """
    others = [candidate for candidate in arns if candidate != arn]
    if not others:
        return

    st.markdown("### ⚖️ Compare with another identity")
    left, right = st.columns([3, 2])
    with left:
        other = st.selectbox(
            "Second identity",
            options=others,
            key="_suzaku_summary_compare_arn",
        )
    with right:
        dimension = st.selectbox(
            "Compare on",
            options=list(queries.COMPARE_DIMENSIONS),
            key="_suzaku_summary_compare_dimension",
        )

    result = _run(db_path, "compare_identities", arn, other, dimension)
    if not result.df.empty:
        counts = result.df["side"].value_counts()
        st.caption(
            f"shared {int(counts.get('shared', 0))} · "
            f"only this identity {int(counts.get('only_a', 0))} · "
            f"only the other {int(counts.get('only_b', 0))}"
        )
    render_panel(
        PROFILE,
        key="compare",
        label=f"⚖️ {dimension}: this identity vs {other}",
        category="⚖️ Comparison",
        description="`side` is `shared`, `only_a` (this identity) or `only_b`.",
        sql=result.sql,
        df=result.df,
        chart={"type": "none"},
        empty_message="Neither identity has values along this dimension.",
    )


def _render_identity(db_path: str, arn: str, arns: list[str], top_n: int) -> None:
    """Render everything below the identity selector.

    Args:
        db_path: The Suzaku database to read.
        arn:     The identity being inspected.
        arns:    Every identity in the file, in triage order.
        top_n:   Rows per panel.
    """
    _render_identity_header(db_path, arn)
    render_timeline_pivot(
        key="identity",
        column="UserARN",
        value=arn,
        label=f"🕒 Timeline — {arn}",
    )

    st.markdown("### 🔴 Abused APIs")
    st.caption(
        "The attack-relevant calls Suzaku recognised, split by outcome: "
        "succeeded on the left, failed on the right."
    )
    _render_api_pair(db_path, arn, top_n, abused=True)

    with st.expander("⚪ Other APIs", expanded=False):
        _render_api_pair(db_path, arn, top_n, abused=False)

    st.markdown("### 🌐 Attributes")
    kinds = _run(db_path, "attribute_kinds")
    if kinds:
        for tab, attribute in zip(st.tabs(kinds), kinds):
            with tab:
                _render_attribute_tab(db_path, arn, attribute, top_n)
    else:
        st.caption("This file records no attributes.")

    _render_comparison(db_path, arn, arns)


def render() -> None:
    """Render the Suzaku summary explorer page."""
    # Imported here rather than at module scope: ``app`` imports this module's
    # package to build the navigation, so a module-level import would be circular.
    from app import (  # noqa: PLC0415
        _get_duckdb_path,
        _init_session_state,
        _render_suzaku_db_selector,
    )

    _init_session_state(PROFILE)

    with st.sidebar:
        has_db = _render_suzaku_db_selector(PROFILE, KIND)

    if not has_db:
        _render_empty_state(db_directory())
        return

    db_path = _get_duckdb_path(PROFILE)
    if not db_path:
        st.warning("Select a Suzaku database in the sidebar to start exploring.")
        return

    with st.sidebar:
        render_run_info(load_db_info(db_path))
        st.subheader("⚙️ Panel size")
        top_n = st.slider(
            "Rows per panel",
            min_value=5,
            max_value=100,
            value=10,
            step=5,
            key="_suzaku_summary_top_n",
            help="Applies to every chart and table on this page.",
        )
        render_sidebar_footer(PROFILE)

    arn, arns = _render_triage(db_path)
    if not arn:
        return
    _render_identity(db_path, arn, arns, top_n)
