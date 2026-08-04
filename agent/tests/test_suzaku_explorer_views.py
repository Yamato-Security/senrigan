"""Tests for the two Suzaku explorer pages and the kit they share.

These pages read data Suzaku already aggregated, so what needs proving is
different from the chat pages: no SQL is ever generated, every panel can become
a report entry, the four session namespaces stay apart, and a file whose
optional columns are empty is explained rather than drawn as blank charts.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from profiles import (
    CLOUDTRAIL_PROFILE,
    SUZAKU_METRICS_PROFILE,
    SUZAKU_SUMMARY_PROFILE,
    SUZAKU_TIMELINE_PROFILE,
)
from tests.conftest import MockSessionState

FIXTURE_DIR = Path(__file__).resolve().parents[2] / "sample" / "suzaku" / "fixtures"
SUMMARY_FIXTURE = FIXTURE_DIR / "suzaku-aws-ct-summary.duckdb"
METRICS_FIXTURE = FIXTURE_DIR / "suzaku-aws-ct-metrics.duckdb"


@pytest.fixture(autouse=True)
def _clear_discovery_cache():
    """Drop the 30 s discovery cache so tests never see each other's results."""
    from app import _discover_suzaku_dbs

    _discover_suzaku_dbs.clear()
    yield
    _discover_suzaku_dbs.clear()


# ---------------------------------------------------------------------------
# Navigation (test 24)
# ---------------------------------------------------------------------------


def test_navigation_exposes_all_four_pages() -> None:
    """Test 24: both explorers must be reachable, CloudTrail still default."""
    from app import build_pages

    with patch("streamlit.Page") as mock_page:
        build_pages()

    titles = [call.kwargs["title"] for call in mock_page.call_args_list]
    url_paths = [call.kwargs["url_path"] for call in mock_page.call_args_list]
    defaults = [call.kwargs.get("default", False) for call in mock_page.call_args_list]

    assert titles == [
        CLOUDTRAIL_PROFILE.label,
        SUZAKU_TIMELINE_PROFILE.label,
        SUZAKU_SUMMARY_PROFILE.label,
        SUZAKU_METRICS_PROFILE.label,
    ]
    assert url_paths == [
        "senrigan",
        "suzaku-timeline",
        "suzaku-summary",
        "suzaku-metrics",
    ]
    assert defaults == [True, False, False, False]


# ---------------------------------------------------------------------------
# Empty states (test 25)
# ---------------------------------------------------------------------------


def test_summary_empty_state_names_its_command() -> None:
    """Test 25a: an analyst with no summary file needs the command, not a table."""
    from views.suzaku_summary import _render_empty_state

    with (
        patch("streamlit.info") as mock_info,
        patch("streamlit.markdown") as mock_markdown,
    ):
        _render_empty_state("/data/db")

    info_text = mock_info.call_args[0][0]
    markdown_text = mock_markdown.call_args[0][0]
    assert "aws-ct-summary" in info_text
    assert "/data/db" in info_text
    assert "suzaku aws-ct-summary" in markdown_text
    assert ".wal" in markdown_text


def test_metrics_empty_state_requires_geo_ip() -> None:
    """Test 25b: the metrics dataset selects the geo columns, so say so here."""
    from views.suzaku_metrics import _render_empty_state

    with (
        patch("streamlit.info") as mock_info,
        patch("streamlit.markdown") as mock_markdown,
    ):
        _render_empty_state("/data/db")

    info_text = mock_info.call_args[0][0]
    markdown_text = mock_markdown.call_args[0][0]
    assert "aws-ct-metrics" in info_text
    assert "suzaku aws-ct-metrics" in markdown_text
    assert "--geo-ip" in markdown_text
    assert "-F " in markdown_text  # the field flag is mandatory for this command


@pytest.mark.parametrize(
    ("module", "profile"),
    [
        ("views.suzaku_summary", SUZAKU_SUMMARY_PROFILE),
        ("views.suzaku_metrics", SUZAKU_METRICS_PROFILE),
    ],
    ids=["summary", "metrics"],
)
def test_page_renders_empty_state_without_opening_a_database(
    module: str, profile, tmp_path: Path
) -> None:
    """Test 25c: with nothing to read the page must not touch DuckDB at all."""
    import importlib

    view = importlib.import_module(module)

    state = MockSessionState()
    with (
        patch("streamlit.session_state", state),
        patch("app.get_duckdb_path_for_variant", return_value=str(tmp_path / "x.db")),
        patch("streamlit.subheader"),
        patch("streamlit.warning"),
        patch("streamlit.caption"),
        patch("streamlit.info"),
        patch("streamlit.markdown"),
        patch("query.connect_duckdb") as mock_connect,
    ):
        view.render()

    assert not mock_connect.called


# ---------------------------------------------------------------------------
# The panel kit (tests 26, 28)
# ---------------------------------------------------------------------------


def _panel_frame() -> pd.DataFrame:
    """A two-row result standing in for any panel's rows."""
    return pd.DataFrame(
        {
            "api": [
                "RunInstances (ec2.amazonaws.com)",
                "GetBucketAcl (s3.amazonaws.com)",
            ],
            "count": [415552, 28907],
        }
    )


@contextmanager
def _panel_ui(state: MockSessionState, *, clicked: str = ""):
    """Patch the Streamlit surface ``render_panel`` draws on.

    Args:
        state:   Session state the panel reads and writes.
        clicked: Widget-key fragment of the single button treated as pressed.

    Yields:
        The patched ``streamlit.button`` mock.
    """

    def _button(*args, **kwargs) -> bool:
        return bool(clicked) and clicked in kwargs.get("key", "")

    with (
        patch("streamlit.session_state", state),
        patch("streamlit.markdown"),
        patch("streamlit.caption"),
        patch("streamlit.dataframe"),
        patch("streamlit.info"),
        patch("streamlit.toast"),
        patch("streamlit.download_button"),
        patch("streamlit.rerun"),
        patch("streamlit.columns", return_value=[MagicMock() for _ in range(3)]),
        patch("app.render_chart"),
        patch("streamlit.button", side_effect=_button) as button,
    ):
        yield button


def test_pinning_a_panel_creates_one_report_entry() -> None:
    """Test 26: the pin button is how an explorer finding reaches the report."""
    from report import generate_html_report, generate_report
    from views.explorer import render_panel

    state = MockSessionState(szs_query_history=[], api_key="")
    with _panel_ui(state, clicked="_pin_"):
        render_panel(
            SUZAKU_SUMMARY_PROFILE,
            key="abused_success",
            label="✅ Abused APIs — succeeded",
            category="👤 Identity",
            sql='SELECT "API" FROM summary_api_calls WHERE "UserARN" = ?',
            df=_panel_frame(),
        )

    history = state["szs_query_history"]
    assert len(history) == 1
    entry = history[0]
    assert entry.label == "✅ Abused APIs — succeeded"
    assert entry.category == "👤 Identity"
    assert "summary_api_calls" in entry.sql
    assert len(entry.results) == 2

    title = "Senrigan Suzaku Summary Report"
    assert "Abused APIs" in generate_report(history, title=title)
    assert "Abused APIs" in generate_html_report(history, title=title)
    # The other pages' namespaces are untouched.
    assert "query_history" not in state
    assert "sz_query_history" not in state


def test_panel_without_rows_renders_no_actions() -> None:
    """An empty panel must explain itself rather than offer an empty CSV."""
    from views.explorer import render_panel

    state = MockSessionState(szs_query_history=[])
    with _panel_ui(state, clicked="_pin_") as button:
        render_panel(
            SUZAKU_SUMMARY_PROFILE,
            key="empty",
            label="Nothing here",
            sql="SELECT 1",
            df=pd.DataFrame(),
        )

    assert not button.called
    assert state["szs_query_history"] == []


def test_explain_is_disabled_without_an_api_key() -> None:
    """Test 28a: every panel renders without a key; only 🤖 Explain is off."""
    from views.explorer import render_panel

    state = MockSessionState(szs_query_history=[], api_key="")
    with _panel_ui(state) as button:
        render_panel(
            SUZAKU_SUMMARY_PROFILE,
            key="abused_success",
            label="Abused APIs",
            sql="SELECT 1",
            df=_panel_frame(),
        )

    explain_calls = [c for c in button.call_args_list if "_explain_" in c.kwargs["key"]]
    assert len(explain_calls) == 1
    assert explain_calls[0].kwargs["disabled"] is True


def test_explain_calls_the_llm_once_with_the_panel_sql() -> None:
    """Test 28b: the narration must describe the rows actually on screen."""
    from views.explorer import render_panel

    state = MockSessionState(szs_query_history=[], api_key="sk-test", model="gpt-5.4")
    df = _panel_frame()
    with (
        _panel_ui(state, clicked="_explain_"),
        patch("llm.generate_analysis", return_value="- Two APIs.") as analysis,
    ):
        render_panel(
            SUZAKU_SUMMARY_PROFILE,
            key="abused_success",
            label="Abused APIs",
            sql="SELECT abused",
            df=df,
        )

    analysis.assert_called_once()
    assert analysis.call_args[0][0] == "SELECT abused"
    assert analysis.call_args[0][1].equals(df)
    assert state["_suzaku_summary_analysis_abused_success"] == "- Two APIs."


# ---------------------------------------------------------------------------
# End-to-end rendering against the committed fixtures
# ---------------------------------------------------------------------------


@contextmanager
def _page_ui(state: MockSessionState, db_path: Path, **overrides):
    """Patch the whole Streamlit surface a page draws on.

    Widgets return their default so the page renders its landing state: the
    point of the smoke test is that every panel's SQL runs against a real Suzaku
    file and every column it names exists.

    Args:
        state:     Session state the page reads and writes.
        db_path:   The file the database selector should resolve to.
        overrides: Extra ``streamlit`` attributes to patch, by name.

    Yields:
        A dict of the patched mocks, keyed by attribute name.
    """

    def _columns(spec, **kwargs):
        count = spec if isinstance(spec, int) else len(spec)
        return [MagicMock() for _ in range(count)]

    def _selectbox(label, options=(), index=0, **kwargs):
        options = list(options)
        if not options:
            return None
        # Exercise the drill-down rather than leaving it on "— none —".
        if str(label).startswith("Who else"):
            return options[min(1, len(options) - 1)]
        return options[index or 0]

    dataframe = MagicMock()
    dataframe.return_value.selection.rows = []

    patches = {
        "session_state": state,
        "markdown": MagicMock(),
        "caption": MagicMock(),
        "subheader": MagicMock(),
        "info": MagicMock(),
        "warning": MagicMock(),
        "divider": MagicMock(),
        "metric": MagicMock(),
        "toast": MagicMock(),
        "rerun": MagicMock(),
        "dataframe": dataframe,
        "download_button": MagicMock(),
        "button": MagicMock(return_value=False),
        "columns": MagicMock(side_effect=_columns),
        "tabs": MagicMock(side_effect=lambda names: [MagicMock() for _ in names]),
        "expander": MagicMock(),
        "selectbox": MagicMock(side_effect=_selectbox),
        "text_input": MagicMock(return_value=""),
        "toggle": MagicMock(return_value=False),
        "slider": MagicMock(
            side_effect=lambda label, **kwargs: kwargs.get("value", 10)
        ),
        "plotly_chart": MagicMock(),
        "line_chart": MagicMock(),
    }
    patches.update(overrides)

    with (
        patch("app.get_duckdb_path_for_variant", return_value=str(db_path)),
        patch("app.render_chart"),
    ):
        with patch.multiple("streamlit", **patches):
            yield patches


def test_summary_page_renders_against_the_fixture(tmp_path: Path) -> None:
    """Every panel's SQL must run, and every column it names must exist."""
    from views.suzaku_summary import render

    copied = tmp_path / "summary.duckdb"
    copied.write_bytes(SUMMARY_FIXTURE.read_bytes())

    state = MockSessionState(szs_suzaku_db=str(copied), api_key="")
    with _page_ui(state, tmp_path / "threat_hunting.db") as ui:
        render()

    # The run-wide KPI row plus the identity's four headline facts.
    assert ui["metric"].call_count >= 9
    labels = [call.args[0] for call in ui["metric"].call_args_list]
    assert "Identities" in labels
    assert "Total events" in labels
    # The triage table and at least one panel table were drawn.
    assert ui["dataframe"].call_count >= 2
    # The page settled on the most abused identity.
    assert state["szs_identity"].startswith("arn:aws:iam::")


def test_metrics_page_renders_against_the_fixture(tmp_path: Path) -> None:
    """Every panel's SQL must run, and the geo panel must decline politely."""
    from views.suzaku_metrics import render

    copied = tmp_path / "metrics.duckdb"
    copied.write_bytes(METRICS_FIXTURE.read_bytes())

    state = MockSessionState(szm_suzaku_db=str(copied), api_key="")
    with _page_ui(
        state,
        tmp_path / "threat_hunting.db",
        number_input=MagicMock(return_value=1),
        date_input=MagicMock(return_value=None),
    ) as ui:
        render()

    labels = [call.args[0] for call in ui["metric"].call_args_list]
    assert {"Distinct values", "Occurrences", "Seen once"} <= set(labels)

    captions = " ".join(str(call.args[0]) for call in ui["caption"].call_args_list)
    # Test 30: the fixture's geo columns exist but hold nothing.
    assert "--geo-ip" in captions
    # The concentration sentence is the page's one-line verdict on the field.
    assert "cover 90% of" in captions


def test_metrics_page_draws_geo_panels_when_the_columns_hold_values(
    tmp_path: Path,
) -> None:
    """Test 30: the populated branch renders panels instead of the explanation."""
    import duckdb

    from views.suzaku_metrics import render

    path = tmp_path / "metrics_geo.duckdb"
    writable = duckdb.connect(str(path))
    writable.execute("""
        CREATE TABLE metrics (
            "Field" VARCHAR, "TimelineColumn" VARCHAR, "Value" VARCHAR,
            "Count" BIGINT, "FieldTotal" BIGINT, "Percent" DOUBLE,
            "FirstSeen" TIMESTAMP, "LastSeen" TIMESTAMP,
            "SrcASN" VARCHAR, "SrcCity" VARCHAR, "SrcCountry" VARCHAR
        )
    """)
    writable.execute("""
        INSERT INTO metrics VALUES
            ('eventName', 'EventName', 'RunInstances', 8, 10, 80.0,
             '2024-01-01', '2024-01-02', 'AS16509 Amazon', 'Ashburn', 'US'),
            ('eventName', 'EventName', 'CreateUser', 2, 10, 20.0,
             '2024-01-03', '2024-01-04', 'AS4713 NTT', 'Tokyo', 'JP')
    """)
    writable.execute("""
        CREATE TABLE suzaku_meta AS SELECT
            1 AS schema_version, '3.0.0' AS suzaku_version,
            'aws-ct-metrics' AS command, 'suzaku aws-ct-metrics' AS command_line,
            now() AS generated_at, 'UTC' AS timestamp_tz
    """)
    writable.close()

    state = MockSessionState(szm_suzaku_db=str(path), api_key="")
    with _page_ui(
        state,
        tmp_path / "threat_hunting.db",
        number_input=MagicMock(return_value=1),
        date_input=MagicMock(return_value=None),
    ) as ui:
        render()

    headings = " ".join(str(call.args[0]) for call in ui["markdown"].call_args_list)
    assert "Top countries" in headings
    captions = " ".join(str(call.args[0]) for call in ui["caption"].call_args_list)
    assert "--geo-ip" not in captions


# ---------------------------------------------------------------------------
# Pivot into the timeline page (test 29)
# ---------------------------------------------------------------------------


def test_timeline_pivot_sql_escapes_the_value() -> None:
    """The pivot embeds a literal, so a value carrying a quote must stay one."""
    from suzaku_queries import timeline_pivot_sql

    sql = timeline_pivot_sql("UserARN", "arn:aws:iam::1:user/o'brien", limit=50)

    assert "WHERE \"UserARN\" = 'arn:aws:iam::1:user/o''brien'" in sql
    assert sql.endswith("LIMIT 50")
    assert 'ORDER BY "Timestamp" DESC' in sql

    injected = timeline_pivot_sql("SrcIP", "1.2.3.4'; DROP TABLE timeline; --")
    assert "'1.2.3.4''; DROP TABLE timeline; --'" in injected
    # One statement only: the payload never leaves the literal.
    assert injected.count("WHERE") == 1


def test_timeline_pivot_sql_rejects_an_unknown_column() -> None:
    """The column is not escapable, so it is checked against the real schema."""
    from suzaku_queries import timeline_pivot_sql

    with pytest.raises(ValueError):
        timeline_pivot_sql("UserARN; DROP TABLE timeline", "x")


def test_handoff_seeds_the_timeline_page_and_switches_to_it() -> None:
    """Test 29: the pivot must run without an API key, on the other page."""
    from app import build_pages
    from views.explorer import handoff_to_timeline

    with patch("streamlit.Page", side_effect=lambda *a, **kw: MagicMock(**kw)):
        build_pages()

    state = MockSessionState()
    with (
        patch("streamlit.session_state", state),
        patch("streamlit.switch_page") as switch_page,
    ):
        handoff_to_timeline("SELECT 1 FROM timeline", label="🕒 Timeline — x")

    # The chat page's own direct-SQL hook: runs the statement with no LLM call.
    assert state["_suzaku_timeline_pending_direct_sql"] == "SELECT 1 FROM timeline"
    assert state["_suzaku_timeline_pending_preset_label"] == "🕒 Timeline — x"
    assert (
        "different Suzaku run" in state["_suzaku_timeline_pending_preset_description"]
    )
    switch_page.assert_called_once()


def test_render_chat_consumes_a_pivot_exactly_once() -> None:
    """A queued pivot must not re-fire on the next rerun."""
    from app import render_chat

    state = MockSessionState(
        sz_query_history=[],
        sz_messages=[],
        sz_last_sql="",
        sz_suzaku_db="/data/db/timeline.duckdb",
        _suzaku_timeline_pending_direct_sql="SELECT 1 FROM timeline",
        _suzaku_timeline_pending_preset_label="🕒 Timeline — x",
    )
    with (
        patch("streamlit.session_state", state),
        patch("app._render_query_filter", return_value=("All", "")),
        patch("app._handle_direct_sql") as handle,
        patch("streamlit.rerun"),
    ):
        render_chat(SUZAKU_TIMELINE_PROFILE)

    handle.assert_called_once()
    assert handle.call_args[0][0] == "SELECT 1 FROM timeline"
    assert "_suzaku_timeline_pending_direct_sql" not in state


# ---------------------------------------------------------------------------
# Session isolation and the no-generated-SQL contract (tests 27, 31)
# ---------------------------------------------------------------------------


def test_clear_resets_only_the_summary_namespace() -> None:
    """Test 27: four pages share one session; clearing one must not cost another."""
    from app import _clear_session

    state = MockSessionState(
        query_history=["ct"],
        sz_query_history=["timeline"],
        szm_query_history=["metrics"],
        szs_query_history=["summary"],
        szs_messages=[{"role": "user", "content": "x"}],
    )
    with patch("streamlit.session_state", state):
        _clear_session(SUZAKU_SUMMARY_PROFILE)

    assert state["szs_query_history"] == []
    assert state["szs_messages"] == []
    assert state["query_history"] == ["ct"]
    assert state["sz_query_history"] == ["timeline"]
    assert state["szm_query_history"] == ["metrics"]


@pytest.mark.parametrize(
    "module",
    ["views.suzaku_summary", "views.suzaku_metrics"],
    ids=["summary", "metrics"],
)
def test_explorer_pages_never_generate_sql(module: str, tmp_path: Path) -> None:
    """Test 31: these pages run reviewed SQL — the LLM never writes any."""
    import importlib

    view = importlib.import_module(module)

    state = MockSessionState(api_key="sk-test")
    with (
        patch("streamlit.session_state", state),
        patch("app.get_duckdb_path_for_variant", return_value=str(tmp_path / "x.db")),
        patch("streamlit.subheader"),
        patch("streamlit.warning"),
        patch("streamlit.caption"),
        patch("streamlit.info"),
        patch("streamlit.markdown"),
        patch("llm.generate_sql") as generate_sql,
        patch("llm.fix_sql_with_llm") as fix_sql,
    ):
        view.render()

    assert not generate_sql.called
    assert not fix_sql.called
