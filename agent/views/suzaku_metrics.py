"""Streamlit page: explore Suzaku ``aws-ct-metrics`` output.

The file is one row per observed value of whatever field the analyst asked
Suzaku to count, so every query here is parameterized on ``Field`` — never on a
literal such as ``eventName``. What the page adds over the Superset dashboard is
control: the Top-N, the minimum count, the "first seen after" cut-off and the
value search are all live, and any panel can be pinned into the report.
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

import suzaku_metrics_queries as queries
from profiles import SUZAKU_METRICS_PROFILE
from suzaku_db import SuzakuKind
from views.explorer import (
    db_directory,
    load_db_info,
    render_empty_state,
    render_panel,
    render_run_info,
    render_sidebar_footer,
    render_timeline_pivot,
)

PROFILE = SUZAKU_METRICS_PROFILE
KIND = SuzakuKind.METRICS

_COMMAND = (
    "suzaku aws-ct-metrics -d <cloudtrail-logs> -t duckdb -F eventName,sourceIPAddress"
    "-o metrics -G <MAXMIND-DB-DIR>"
)
_NOTE = (
    "\n`--geo-ip` is required: Suzaku writes `SrcASN` / `SrcCity` / `SrcCountry` "
    "only for an enriched run, and a metrics file without those columns is "
    "refused rather than registered and left failing at render time.\n"
)

# The share the concentration panel reports on. 90% is the usual "have I seen
# enough of this field?" threshold.
_COVERAGE_TARGET = 90.0


def _render_empty_state(directory: str) -> None:
    """Explain how to produce and place a metrics database.

    Args:
        directory: The directory that was scanned, shown verbatim.
    """
    render_empty_state(KIND, directory, command=_COMMAND, note=_NOTE)


@st.cache_data(show_spinner=False, ttl=300)
def _query(db_path: str, stamp: float, name: str, args: tuple, kwargs: tuple):
    """Run one query from :mod:`suzaku_metrics_queries` against *db_path*.

    Cached on the file's modification time as well as its path, so replacing the
    file invalidates every panel rather than serving the previous run's numbers.

    Args:
        db_path: The Suzaku database to read.
        stamp:   The file's mtime — part of the cache key.
        name:    Function name in :mod:`suzaku_metrics_queries`.
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


def _render_controls(db_path: str) -> dict:
    """Render the sidebar controls and return what the analyst chose.

    Args:
        db_path: The Suzaku database to read.

    Returns:
        ``field``, ``timeline_column``, ``top_n``, ``min_count``, ``seen_after``
        and ``search``, plus the frame describing every field in the file.
    """
    fields = _run(db_path, "fields").df

    st.subheader("🔎 Field")
    if fields.empty:
        st.caption("This metrics database is empty.")
        return {"field": "", "fields": fields}

    options = list(fields["field"])
    labels = {
        row.field: f"{row.field} ({int(row.distinct_values):,} values)"
        for row in fields.itertuples()
    }
    field = st.selectbox(
        "Counted field",
        options=options,
        format_func=lambda name: labels.get(name, name),
        key="_suzaku_metrics_field",
        help="Whatever field this Suzaku run was asked to count. A file may "
        "hold several.",
    )
    timeline_column = str(
        fields.loc[fields["field"] == field, "timeline_column"].iloc[0]
    )
    st.caption(f"`timeline` column: `{timeline_column}`")

    st.subheader("⚙️ Filters")
    top_n = st.slider(
        "Rows per panel",
        min_value=5,
        max_value=100,
        value=20,
        step=5,
        key="_suzaku_metrics_top_n",
    )
    min_count = st.number_input(
        "Count at least",
        min_value=1,
        value=1,
        step=1,
        key="_suzaku_metrics_min_count",
        help="Drops the long tail. Set to 1 to keep every value.",
    )
    search = st.text_input(
        "Value contains",
        key="_suzaku_metrics_search",
        placeholder="substring, case-insensitive",
    )
    seen_after = st.date_input(
        "First seen after",
        value=None,
        format="YYYY-MM-DD",
        key="_suzaku_metrics_seen_after",
        help="Drives the Newly seen panel, and narrows every other one.",
    )

    return {
        "field": field,
        "fields": fields,
        "timeline_column": timeline_column,
        "top_n": int(top_n),
        "min_count": int(min_count) if int(min_count) > 1 else None,
        "search": search,
        "seen_after": seen_after or None,
    }


def _render_kpis(db_path: str, field: str) -> None:
    """Render the headline counters for the selected field.

    Args:
        db_path: The Suzaku database to read.
        field:   The field being explored.
    """
    stats = _run(db_path, "value_stats", field).df
    if stats.empty:
        return
    row = stats.iloc[0]

    for column, (label, value, help_text) in zip(
        st.columns(5),
        (
            (
                "Distinct values",
                f"{int(row['distinct_values']):,}",
                "How many different values this field took.",
            ),
            (
                "Occurrences",
                f"{int(row['total_count']):,}",
                "Events behind those values.",
            ),
            (
                "Top value share",
                f"{row['top_share']:.1f}%",
                "How much of the field its busiest value covers.",
            ),
            (
                "Seen once",
                f"{int(row['singletons']):,}",
                "Values observed exactly once — the interesting tail.",
            ),
            (
                "Span",
                (
                    f"{row['first_seen']:%Y-%m-%d} → {row['last_seen']:%Y-%m-%d}"
                    if row["first_seen"] is not None and row["last_seen"] is not None
                    else "—"
                ),
                "First and last time any value was seen.",
            ),
        ),
    ):
        with column:
            st.metric(label, value, help=help_text)


def _render_value_panels(db_path: str, choices: dict) -> None:
    """Render the top, rare and newly-seen value panels.

    Args:
        db_path: The Suzaku database to read.
        choices: The sidebar selections from :func:`_render_controls`.
    """
    field = choices["field"]
    top = _run(
        db_path,
        "values",
        field,
        limit=choices["top_n"],
        min_count=choices["min_count"],
        search=choices["search"],
        seen_after=choices["seen_after"],
    )
    render_panel(
        PROFILE,
        key="top_values",
        label="📈 Top values",
        category="📊 Values",
        description=(
            "`percent` is the share of the whole field; `share_of_filtered` is "
            "the share of the rows the sidebar left."
        ),
        sql=top.sql,
        df=top.df,
        chart={"type": "bar", "x": "value", "y": ["count"]},
        empty_message="No values match the current filters.",
    )

    rare = _run(
        db_path,
        "values",
        field,
        limit=choices["top_n"],
        ascending=True,
        max_count=1,
        search=choices["search"],
        seen_after=choices["seen_after"],
    )
    render_panel(
        PROFILE,
        key="rare_values",
        label="🪶 Values seen exactly once",
        category="📊 Values",
        description="Rare is interesting: one-off values are where the unusual "
        "activity hides.",
        sql=rare.sql,
        df=rare.df,
        chart={"type": "none"},
        empty_message="Every value in this field was seen more than once.",
    )

    if not top.df.empty:
        followed = st.selectbox(
            "Follow a value into the timeline",
            options=["— none —", *top.df["value"].dropna()],
            key="_suzaku_metrics_pivot_value",
            help="Opens the Suzaku Timeline page filtered on this value.",
        )
        if followed != "— none —":
            render_timeline_pivot(
                key="value",
                column=choices["timeline_column"],
                value=followed,
                label=f"🕒 Timeline — {choices['timeline_column']} {followed}",
            )

    if choices["seen_after"] is not None:
        newly = _run(
            db_path,
            "values",
            field,
            limit=choices["top_n"],
            search=choices["search"],
            seen_after=choices["seen_after"],
        )
        render_panel(
            PROFILE,
            key="newly_seen",
            label=f"🆕 First seen after {choices['seen_after']}",
            category="📊 Values",
            description="Values absent from the earlier part of the run.",
            sql=newly.sql,
            df=newly.df,
            chart={"type": "none"},
            empty_message="Nothing appeared for the first time after that date.",
        )


def _render_concentration(db_path: str, choices: dict) -> None:
    """Render the Pareto curve and say what it means in one sentence.

    Args:
        db_path: The Suzaku database to read.
        choices: The sidebar selections from :func:`_render_controls`.
    """
    curve = _run(db_path, "pareto", choices["field"], limit=None)
    if curve.df.empty:
        return

    needed = queries.values_covering(curve.df, _COVERAGE_TARGET)
    total_values = len(curve.df)
    occurrences = int(curve.df["count"].sum())
    st.caption(
        f"The top **{needed:,}** of {total_values:,} values cover "
        f"{_COVERAGE_TARGET:.0f}% of {occurrences:,} occurrences."
    )
    head = curve.df.head(max(choices["top_n"], needed))
    st.line_chart(head, x="value", y="cumulative_percent")
    render_panel(
        PROFILE,
        key="concentration",
        label="📉 Concentration",
        category="📊 Values",
        description=(
            f"Cumulative share by value. {needed:,} values reach "
            f"{_COVERAGE_TARGET:.0f}%."
        ),
        sql=curve.sql,
        df=head,
        chart={"type": "none"},
    )


def _render_geo(db_path: str, field: str) -> None:
    """Render the geo panels, or explain why there are none.

    A metrics file is only registered when the geo columns exist, but they can
    exist and be entirely empty — the committed fixture is exactly that. Saying
    so is more useful than three blank charts.

    Args:
        db_path: The Suzaku database to read.
        field:   The field being explored.
    """
    st.markdown("### 🌐 Source geography")
    if not _run(db_path, "has_geo_data", field):
        st.caption(
            "This file has the `SrcASN` / `SrcCity` / `SrcCountry` columns but no "
            "values in them. Re-run Suzaku with `--geo-ip` and a GeoLite2 "
            "database to populate them."
        )
        return

    for column, label in (
        ("SrcCountry", "🌍 Top countries"),
        ("SrcCity", "🏙 Top cities"),
        ("SrcASN", "🛰 Top ASNs"),
    ):
        result = _run(db_path, "geo_breakdown", field, column)
        render_panel(
            PROFILE,
            key=f"geo_{column}",
            label=label,
            category="🌐 Geography",
            sql=result.sql,
            df=result.df,
            chart={"type": "bar", "x": "value", "y": ["count"]},
        )


def _render_field_comparison(db_path: str, choices: dict) -> None:
    """Render the two-field value overlap, when the file holds more than one.

    Args:
        db_path: The Suzaku database to read.
        choices: The sidebar selections from :func:`_render_controls`.
    """
    others = [name for name in choices["fields"]["field"] if name != choices["field"]]
    if not others:
        return

    st.markdown("### 🔀 Compare fields")
    other = st.selectbox(
        "Compare with",
        options=others,
        key="_suzaku_metrics_compare",
    )
    result = _run(db_path, "compare_fields", choices["field"], other)
    render_panel(
        PROFILE,
        key="compare_fields",
        label=f"🔀 {choices['field']} vs {other}",
        category="🔀 Comparison",
        description="Values both fields recorded, and those unique to each.",
        sql=result.sql,
        df=result.df,
        chart={"type": "none"},
    )


def render() -> None:
    """Render the Suzaku metrics explorer page."""
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
        choices = _render_controls(db_path)
        render_sidebar_footer(PROFILE)

    if not choices["field"]:
        st.info("This metrics database contains no rows.")
        return

    st.markdown(f"## 📊 {choices['field']}")
    _render_kpis(db_path, choices["field"])
    _render_value_panels(db_path, choices)
    _render_concentration(db_path, choices)
    _render_geo(db_path, choices["field"])
    _render_field_comparison(db_path, choices)
