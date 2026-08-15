"""Tests for chart rendering (``views/charts.py``).

Moved verbatim from ``test_app.py`` when ``render_chart`` and its two renderers
left ``app.py``. The renderers are patched through the ``streamlit`` module
itself, not through the module under test, so these tests do not care which
module owns the function — only that it draws inline and picks the right chart.
"""

from unittest.mock import MagicMock, patch

import pandas as pd


def test_render_chart_type_none_skips_all_rendering():
    """render_chart() with type='none' must not call st.plotly_chart or st.bar_chart.

    Test #CHART-1: explicit opt-out must suppress chart rendering entirely.
    """
    df = pd.DataFrame({"event_name": ["CreateUser"], "count": [5]})
    config = {"type": "none"}
    with (
        patch("streamlit.plotly_chart") as mock_plotly,
        patch("streamlit.bar_chart") as mock_bar,
    ):
        from app import render_chart

        render_chart(df, config)

    mock_plotly.assert_not_called()
    mock_bar.assert_not_called()


def test_render_chart_type_bar_calls_plotly_chart():
    """render_chart() with type='bar' must invoke st.plotly_chart inside an expander.

    Test #CHART-2: verifies Plotly Express horizontal bar chart rendering path.
    """
    df = pd.DataFrame(
        {"event_name": ["CreateUser", "DeleteUser"], "api_count": [10, 5]}
    )
    config = {"type": "bar", "x": "event_name", "y": ["api_count"]}
    with (
        patch("streamlit.plotly_chart") as mock_plotly,
        patch("streamlit.expander") as mock_expander,
    ):
        mock_expander.return_value.__enter__ = MagicMock(return_value=None)
        mock_expander.return_value.__exit__ = MagicMock(return_value=False)

        from app import render_chart

        render_chart(df, config)

    mock_plotly.assert_called_once()


def test_render_chart_type_timeseries_calls_line_chart():
    """render_chart() with type='timeseries' must bucket event_time and call st.line_chart.

    Test #CHART-3: line chart is more appropriate than bar chart for time-series data
    because it clearly shows trends and continuity over time.
    """
    df = pd.DataFrame(
        {
            "event_time": pd.to_datetime(["2024-01-01", "2024-01-01", "2024-01-02"]),
            "event_name": ["A", "B", "C"],
        }
    )
    config = {"type": "timeseries", "bucket": "day"}
    with (
        patch("streamlit.line_chart") as mock_line,
        patch("streamlit.expander") as mock_expander,
    ):
        mock_expander.return_value.__enter__ = MagicMock(return_value=None)
        mock_expander.return_value.__exit__ = MagicMock(return_value=False)

        from app import render_chart

        render_chart(df, config)

    mock_line.assert_called_once()


def test_render_chart_timeseries_single_bucket_skips():
    """render_chart() with type='timeseries' and only one distinct date must skip.

    Test #CHART-4: a single-bar chart provides no visual value.
    """
    df = pd.DataFrame(
        {
            "event_time": pd.to_datetime(["2024-01-01", "2024-01-01"]),
            "event_name": ["A", "B"],
        }
    )
    config = {"type": "timeseries", "bucket": "day"}
    with (
        patch("streamlit.bar_chart") as mock_bar,
        patch("streamlit.expander"),
    ):
        from app import render_chart

        render_chart(df, config)

    mock_bar.assert_not_called()


def test_render_chart_timeseries_no_event_time_skips():
    """render_chart() with type='timeseries' but no event_time column must skip.

    Test #CHART-5: guards against schema mismatches.
    """
    df = pd.DataFrame({"event_name": ["A", "B"], "count": [1, 2]})
    config = {"type": "timeseries"}
    with (
        patch("streamlit.bar_chart") as mock_bar,
        patch("streamlit.plotly_chart") as mock_plotly,
    ):
        from app import render_chart

        render_chart(df, config)

    mock_bar.assert_not_called()
    mock_plotly.assert_not_called()


def test_render_chart_auto_with_numeric_calls_plotly_chart():
    """render_chart() with config=None and a numeric column must call st.plotly_chart.

    Test #CHART-6: auto-detection path falls back to Plotly bar chart.
    """
    df = pd.DataFrame({"event_name": ["A", "B"], "count": [3, 7]})
    with (
        patch("streamlit.plotly_chart") as mock_plotly,
        patch("streamlit.expander") as mock_expander,
    ):
        mock_expander.return_value.__enter__ = MagicMock(return_value=None)
        mock_expander.return_value.__exit__ = MagicMock(return_value=False)

        from app import render_chart

        render_chart(df, None)

    mock_plotly.assert_called_once()


def test_render_chart_auto_without_numeric_skips():
    """render_chart() with config=None and no numeric columns must not render a chart.

    Test #CHART-7: pure-text result sets should not produce an empty chart.
    """
    df = pd.DataFrame({"event_name": ["A", "B"], "region": ["us-east-1", "us-west-2"]})
    with (
        patch("streamlit.plotly_chart") as mock_plotly,
        patch("streamlit.bar_chart") as mock_bar,
    ):
        from app import render_chart

        render_chart(df, None)

    mock_plotly.assert_not_called()
    mock_bar.assert_not_called()


def test_render_chart_timeseries_accepts_hour_bucket_alias():
    """A query aliasing its bucket ``hour_bucket`` must still chart.

    Eleven hunts bucket with ``DATE_TRUNC('hour', event_time) AS hour_bucket``.
    Exact-matching only ``bucket`` left those charts silently undrawn — the query
    ran, the table rendered, and the declared timeseries never appeared.
    """
    df = pd.DataFrame(
        {
            "hour_bucket": ["2024-06-10 01:00:00", "2024-06-10 02:00:00"],
            "call_count": [5, 9],
        }
    )
    with patch("streamlit.line_chart") as mock_line:
        from app import render_chart

        render_chart(df, {"type": "timeseries", "bucket": "hour"})

    mock_line.assert_called_once()


def test_render_chart_timeseries_ignores_bucket_name_column():
    """``bucket_name`` is an S3 bucket, not a time bucket."""
    df = pd.DataFrame(
        {"bucket_name": ["prod-data", "pii-archive"], "call_count": [5, 9]}
    )
    with (
        patch("streamlit.line_chart") as mock_line,
        patch("streamlit.plotly_chart") as mock_plotly,
    ):
        from app import render_chart

        render_chart(df, {"type": "timeseries"})

    mock_line.assert_not_called()
    mock_plotly.assert_not_called()


def test_render_chart_timeseries_plots_the_measure_of_a_pre_aggregated_result():
    """A result already grouped per bucket must plot its measure, not its rows.

    `_render_timeseries_chart` counts rows per bucket, which is right for a
    row-level result — one row is one detection. A hunt that has already done
    the GROUP BY returns exactly one row per bucket, so counting rows draws a
    flat line at 1 and hides the very spike the hunt exists to show.
    """
    df = pd.DataFrame(
        {
            "day": pd.to_datetime(["2024-01-01", "2024-01-02", "2024-01-03"]),
            "detections": [120, 4, 999],
        }
    )
    with patch("streamlit.line_chart") as mock_line:
        from app import render_chart

        render_chart(df, {"type": "timeseries", "bucket": "day"})

    mock_line.assert_called_once()
    plotted = mock_line.call_args[0][0]
    assert list(plotted["count"]) == [
        120,
        4,
        999,
    ], "the pre-aggregated measure was replaced by a row count of 1 per bucket"


def test_render_chart_timeseries_still_counts_rows_of_a_row_level_result():
    """Row-level results keep counting rows, even when a numeric column exists.

    A detection listing carrying, say, a port number must not have that number
    mistaken for the measure.
    """
    df = pd.DataFrame(
        {
            "event_time": pd.to_datetime(["2024-01-01", "2024-01-01", "2024-01-02"]),
            "some_number": [443, 22, 8080],
        }
    )
    with patch("streamlit.line_chart") as mock_line:
        from app import render_chart

        render_chart(df, {"type": "timeseries", "bucket": "day"})

    mock_line.assert_called_once()
    plotted = mock_line.call_args[0][0]
    assert list(plotted["count"]) == [2, 1]
