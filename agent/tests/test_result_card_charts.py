"""Tests for chart rendering inside a result card.

Two defects are covered, both found by smoke-running the pages with
``streamlit.testing.v1.AppTest``:

1. ``_render_result_card`` renders inside ``st.expander``, and both chart
   renderers opened a *second* expander. Streamlit forbids nesting them, so any
   result card that produced a chart raised ``StreamlitAPIException`` — including
   auto-detected charts, i.e. any result with a numeric column.
2. The time-series renderer only accepted an ``event_time`` column, so results
   from any other table (Suzaku's ``Timestamp``, or a bucketed ``day`` alias)
   silently rendered nothing.
"""

from __future__ import annotations

from unittest.mock import patch

import pandas as pd
import pytest

from app import render_chart

BAR_DF = pd.DataFrame({"RuleTitle": ["a", "b"], "detections": [5, 3]})
DAY_DF = pd.DataFrame(
    {"day": ["2024-01-01", "2024-01-02", "2024-01-03"], "detections": [1, 2, 3]}
)
EVENT_TIME_DF = pd.DataFrame(
    {
        "event_time": pd.to_datetime(
            ["2024-01-01 00:00:00", "2024-01-02 00:00:00", "2024-01-03 00:00:00"]
        ),
        "n": [1, 2, 3],
    }
)
TIMESTAMP_DF = pd.DataFrame(
    {
        "Timestamp": [
            "2024-01-01 00:00:00",
            "2024-01-02 00:00:00",
            "2024-01-03 00:00:00",
        ],
        "Level": ["high", "high", "critical"],
    }
)


@pytest.mark.parametrize(
    ("df", "config"),
    [
        (BAR_DF, {"type": "bar", "x": "RuleTitle", "y": ["detections"]}),
        (EVENT_TIME_DF, {"type": "timeseries", "bucket": "day"}),
        (DAY_DF, {"type": "timeseries", "bucket": "day"}),
        (TIMESTAMP_DF, {"type": "timeseries", "bucket": "day"}),
        (BAR_DF, None),  # auto-detection path
    ],
)
def test_chart_renderers_never_open_an_expander(df: pd.DataFrame, config) -> None:
    """Charts render inside an expander already, so they must not open one."""
    with (
        patch("streamlit.expander") as mock_expander,
        patch("streamlit.plotly_chart"),
        patch("streamlit.line_chart"),
        patch("streamlit.markdown"),
    ):
        render_chart(df, config)

    assert (
        not mock_expander.called
    ), "opening an expander here raises StreamlitAPIException inside a result card"


def test_timeseries_accepts_a_bucketed_day_column() -> None:
    """A hunt that buckets in SQL returns `day`, not `event_time`."""
    with (
        patch("streamlit.line_chart") as mock_line,
        patch("streamlit.markdown"),
    ):
        render_chart(DAY_DF, {"type": "timeseries", "bucket": "day"})

    assert mock_line.called


def test_timeseries_accepts_the_suzaku_timestamp_column() -> None:
    """Suzaku's raw detections carry `Timestamp` (VARCHAR), not `event_time`."""
    with (
        patch("streamlit.line_chart") as mock_line,
        patch("streamlit.markdown"),
    ):
        render_chart(TIMESTAMP_DF, {"type": "timeseries", "bucket": "day"})

    assert mock_line.called


def test_timeseries_still_accepts_event_time() -> None:
    """The CloudTrail column must keep working."""
    with (
        patch("streamlit.line_chart") as mock_line,
        patch("streamlit.markdown"),
    ):
        render_chart(EVENT_TIME_DF, {"type": "timeseries", "bucket": "day"})

    assert mock_line.called


def test_timeseries_skips_a_frame_with_no_time_column() -> None:
    """Without a recognisable time column there is nothing to plot."""
    with (
        patch("streamlit.line_chart") as mock_line,
        patch("streamlit.markdown"),
    ):
        render_chart(pd.DataFrame({"a": [1, 2, 3]}), {"type": "timeseries"})

    assert not mock_line.called


def test_timeseries_skips_a_single_bucket() -> None:
    """A one-bar timeline carries no information; the old behaviour is kept."""
    single = pd.DataFrame({"day": ["2024-01-01"], "n": [1]})
    with (
        patch("streamlit.line_chart") as mock_line,
        patch("streamlit.markdown"),
    ):
        render_chart(single, {"type": "timeseries"})

    assert not mock_line.called
