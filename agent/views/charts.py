"""Chart rendering for query results, shared by the chat and explorer pages.

One entry point, :func:`render_chart`, dispatching on the ``chart`` config a
hunt (``builtin_hunts.yaml``) or an explorer panel supplies. Every renderer here
draws *inline* — the caller is already inside ``st.expander`` (a result card) or
a panel, and Streamlit forbids nesting expanders.

Charts read the DataFrame they are given and nothing else: no session state, no
database, no profile. That is what makes them testable by patching
``streamlit.plotly_chart`` / ``streamlit.line_chart`` alone.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st


def _render_bar_chart(
    df: pd.DataFrame, chart_config: dict | None, key: str | None = None
) -> None:
    """Render a Plotly Express horizontal bar chart.

    Uses the x/y keys from chart_config when provided; falls back to the first
    non-numeric column (y-axis) and all numeric columns (x-axis) for auto-detection.

    Args:
        df:           The query result DataFrame.
        chart_config: Chart configuration dict, or None for auto-detection.
        key:          Streamlit element key, unique per chart on the page.
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
    #
    # The key is what keeps two cards holding the same result from colliding:
    # Streamlit derives an element id from the type and the parameters, so two
    # identical figures raise StreamlitDuplicateElementId and take the page with
    # them.
    st.markdown("**📊 Bar Chart**")
    st.plotly_chart(fig, use_container_width=True, key=key)


# Column names a time-series chart can bucket on, in priority order. Results come
# from different tables (``cloudtrail_events.event_time``, Suzaku's
# ``Timestamp``) and hunts frequently bucket in SQL and return an alias.
#
# Matching is exact, not substring: ``hour_bucket`` is the alias eleven hunts use
# for ``DATE_TRUNC('hour', event_time)`` and must match, while ``bucket_name`` is
# an S3 bucket and must not.
_TIME_COLUMN_CANDIDATES: tuple[str, ...] = (
    "event_time",
    "timestamp",
    "day",
    "hour",
    "week",
    "month",
    "bucket",
    "hour_bucket",
    "day_bucket",
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

    Rows are counted per bucket, which is what a row-level result means: one row
    is one event. A hunt that has already grouped by its bucket returns exactly
    one row per bucket, so counting rows there would draw a flat line at 1 and
    hide the spike the hunt exists to show — such a result plots its own first
    measure instead.

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
    parsed = pd.to_datetime(df[time_column], errors="coerce")
    ts = parsed.dropna()
    if ts.empty:
        return

    if bucket == "hour":
        bucketed = ts.dt.floor("h").dt.strftime("%Y-%m-%d %H:00")
        title = "📈 Timeline (per hour)"
    else:
        bucketed = ts.dt.date.astype(str)
        title = "📈 Timeline (per day)"

    measure = _pre_aggregated_measure(df, parsed, bucketed)
    if measure is None:
        series = bucketed.value_counts().sort_index()
    else:
        series = df[measure][parsed.notna()].groupby(bucketed).sum().sort_index()
        title = f"{title} — {measure}"

    if len(series) < 2:
        return

    chart_df = series.reset_index()
    chart_df.columns = ["bucket", "count"]

    # Inline for the same reason as the bar chart: no expander nesting.
    st.markdown(f"**{title}**")
    st.line_chart(chart_df, x="bucket", y="count")


def _pre_aggregated_measure(
    df: pd.DataFrame, parsed: pd.Series, bucketed: pd.Series
) -> str | None:
    """Return the column to plot when *df* already holds one row per bucket.

    One row per bucket means the query did the grouping, so the count this
    function's caller would otherwise compute is 1 everywhere. The first numeric
    column is the measure: hunts select their headline count immediately after
    the bucket, and a result with no numeric column has nothing to plot but its
    rows.

    Args:
        df:       The query result.
        parsed:   ``df``'s time column, parsed (NaT where unparseable).
        bucketed: The bucket label of every parseable row.

    Returns:
        The measure column's name, or ``None`` to fall back to counting rows.
    """
    if len(bucketed) != bucketed.nunique():
        return None
    numeric = df.loc[parsed.notna()].select_dtypes(include="number").columns
    return numeric[0] if len(numeric) else None


def render_chart(
    df: pd.DataFrame, chart_config: dict | None, *, key: str | None = None
) -> None:
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
        key:          Streamlit element key. Two charts drawn from the same data
                      share an auto-generated id and raise
                      ``StreamlitDuplicateElementId``, so every caller that can
                      render a chart more than once on one page passes what makes
                      this one different — a result card its position, an
                      explorer panel its own key.
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
        _render_bar_chart(df, chart_config, key)
        return

    # Auto-detection: render a bar chart when at least one numeric column exists.
    numeric_cols = df.select_dtypes(include="number").columns.tolist()
    if numeric_cols:
        _render_bar_chart(df, None, key)
