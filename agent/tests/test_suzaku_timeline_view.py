"""Tests for the Suzaku timeline page and its session isolation.

The page reuses the CloudTrail hunting UI through a profile, so what needs
proving is that the reuse is actually isolated: separate history, separate
filters, no geo enrichment against a table that has no geo columns, and a
usable empty state.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from profiles import CLOUDTRAIL_PROFILE, SUZAKU_TIMELINE_PROFILE
from report import ReportEntry, generate_html_report, generate_report
from tests.conftest import MockSessionState

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "sample"
    / "suzaku"
    / "fixtures"
    / "suzaku-aws-ct-timeline.duckdb"
)


@pytest.fixture(autouse=True)
def _clear_discovery_cache():
    """Drop the 30 s discovery cache so tests never see each other's results."""
    from app import _discover_suzaku_dbs

    _discover_suzaku_dbs.clear()
    yield
    _discover_suzaku_dbs.clear()


# ---------------------------------------------------------------------------
# Navigation and state seeding
# ---------------------------------------------------------------------------


def test_navigation_exposes_the_timeline_page() -> None:
    """The Suzaku page must be reachable, and CloudTrail must stay the default.

    The full page list is asserted in ``test_suzaku_explorer_views.py``; this
    test only owns the timeline page's own entry.
    """
    from app import build_pages

    with patch("streamlit.Page") as mock_page:
        build_pages()

    entries = {
        call.kwargs["url_path"]: call.kwargs for call in mock_page.call_args_list
    }

    assert entries["suzaku-timeline"]["title"] == SUZAKU_TIMELINE_PROFILE.label
    assert entries["suzaku-timeline"].get("default", False) is False
    assert entries["senrigan"]["title"] == CLOUDTRAIL_PROFILE.label
    assert entries["senrigan"]["default"] is True


def test_init_session_state_seeds_the_suzaku_namespace() -> None:
    """Per-page keys are prefixed; the severity default comes from the profile."""
    from app import _init_session_state

    state = MockSessionState()
    with patch("streamlit.session_state", state):
        _init_session_state(SUZAKU_TIMELINE_PROFILE)

    assert state["sz_messages"] == []
    assert state["sz_query_history"] == []
    assert state["sz_levels"] == list(SUZAKU_TIMELINE_PROFILE.default_levels)
    # Shared keys stay un-prefixed so the API key is entered once.
    assert "api_key" in state
    assert "sz_api_key" not in state
    # The CloudTrail page's own namespace is untouched.
    assert "messages" not in state


def test_init_session_state_keeps_pages_independent() -> None:
    """Initializing one page must not disturb the other's live session."""
    from app import _init_session_state

    state = MockSessionState(messages=[{"role": "user", "content": "existing"}])
    with patch("streamlit.session_state", state):
        _init_session_state(SUZAKU_TIMELINE_PROFILE)

    assert state["messages"] == [{"role": "user", "content": "existing"}]


# ---------------------------------------------------------------------------
# Empty state (test 24)
# ---------------------------------------------------------------------------


def test_db_selector_reports_no_database(tmp_path: Path) -> None:
    """Test 24a: with nothing to read the selector must decline, not crash."""
    from app import _render_suzaku_db_selector
    from suzaku_db import SuzakuKind

    state = MockSessionState()
    with (
        patch("streamlit.session_state", state),
        patch("app.get_duckdb_path_for_variant", return_value=str(tmp_path / "x.db")),
        patch("streamlit.subheader"),
        patch("streamlit.warning") as mock_warning,
        patch("streamlit.caption"),
    ):
        assert (
            _render_suzaku_db_selector(SUZAKU_TIMELINE_PROFILE, SuzakuKind.TIMELINE)
            is False
        )

    assert mock_warning.called


def test_db_selector_picks_up_a_real_fixture(tmp_path: Path) -> None:
    """A discovered timeline database is selected and stored in session state."""
    from app import _render_suzaku_db_selector
    from suzaku_db import SuzakuKind

    copied = tmp_path / "timeline.duckdb"
    copied.write_bytes(FIXTURE.read_bytes())

    state = MockSessionState()
    with (
        patch("streamlit.session_state", state),
        patch(
            "app.get_duckdb_path_for_variant",
            return_value=str(tmp_path / "threat_hunting.db"),
        ),
        patch("streamlit.subheader"),
        patch("streamlit.selectbox", return_value=str(copied)),
        patch("streamlit.caption"),
    ):
        assert (
            _render_suzaku_db_selector(SUZAKU_TIMELINE_PROFILE, SuzakuKind.TIMELINE)
            is True
        )

    assert state["sz_suzaku_db"] == str(copied)


def test_empty_state_explains_how_to_produce_a_database() -> None:
    """Test 24b: the guidance panel must name the command and the directory."""
    from views.suzaku_timeline import _render_empty_state

    with (
        patch("streamlit.info") as mock_info,
        patch("streamlit.markdown") as mock_markdown,
    ):
        _render_empty_state("/data/db")

    info_text = mock_info.call_args[0][0]
    markdown_text = mock_markdown.call_args[0][0]
    assert "aws-ct-timeline" in info_text
    assert "/data/db" in info_text
    assert "suzaku aws-ct-timeline" in markdown_text
    assert ".wal" in markdown_text  # the read-only-mount trap is called out


# ---------------------------------------------------------------------------
# Reports and clearing (tests 25-26)
# ---------------------------------------------------------------------------


def _suzaku_history() -> list[ReportEntry]:
    """One report entry standing in for a completed Suzaku hunt."""
    return [
        ReportEntry(
            sql='SELECT "Timestamp" FROM timeline LIMIT 1',
            results=pd.DataFrame({"Timestamp": ["2024-01-01 00:00:00"]}),
            analysis="One detection observed.",
            label="🚨 Critical & High Detections",
            category="🚨 Triage",
            source="bulk",
        )
    ]


def test_report_generation_from_suzaku_history() -> None:
    """Test 25: both report formats must render a Suzaku session."""
    history = _suzaku_history()
    title = f"Senrigan {SUZAKU_TIMELINE_PROFILE.label} Report"

    markdown = generate_report(history, title=title)
    html = generate_html_report(history, title=title)

    assert title in markdown
    assert "Critical &amp; High Detections" in html or "Critical & High" in html
    assert "FROM timeline" in markdown


def test_clear_session_only_resets_its_own_namespace() -> None:
    """Test 26: clearing Suzaku must not discard a CloudTrail investigation."""
    from app import _clear_session

    state = MockSessionState(
        messages=[{"role": "user", "content": "cloudtrail"}],
        query_history=["ct-entry"],
        analyst_notes={0: "ct note"},
        sz_messages=[{"role": "user", "content": "suzaku"}],
        sz_query_history=_suzaku_history(),
        sz_last_sql="SELECT 1",
        sz_last_results=pd.DataFrame({"a": [1]}),
        sz_last_summary="summary",
        sz_conversation_context=[{"user_query": "q"}],
        sz_analyst_notes={0: "sz note"},
    )
    with patch("streamlit.session_state", state):
        _clear_session(SUZAKU_TIMELINE_PROFILE)

    assert state["sz_messages"] == []
    assert state["sz_query_history"] == []
    assert state["sz_last_sql"] == ""
    assert state["sz_last_results"] is None
    assert state["sz_analyst_notes"] == {}
    # The CloudTrail page is untouched.
    assert state["messages"] == [{"role": "user", "content": "cloudtrail"}]
    assert state["query_history"] == ["ct-entry"]
    assert state["analyst_notes"] == {0: "ct note"}


# ---------------------------------------------------------------------------
# Geo enrichment and API key (tests 27-28)
# ---------------------------------------------------------------------------


def test_geo_enrichment_is_skipped_for_the_suzaku_profile() -> None:
    """Test 27: the geo join reads cloudtrail_events, absent from a Suzaku DB."""
    from handlers import _maybe_enrich_geo

    df = pd.DataFrame({"SrcIP": ["8.8.8.8"]})
    state = MockSessionState(geo_enrich=True)
    with (
        patch("streamlit.session_state", state),
        patch("handlers.enrich_with_geo") as mock_enrich,
    ):
        out = _maybe_enrich_geo(MagicMock(), df, SUZAKU_TIMELINE_PROFILE)

    assert not mock_enrich.called
    assert out is df


def test_geo_enrichment_still_runs_for_cloudtrail() -> None:
    """The Suzaku opt-out must not disable enrichment on the CloudTrail page."""
    from handlers import _maybe_enrich_geo

    df = pd.DataFrame({"source_ip_address": ["8.8.8.8"]})
    state = MockSessionState(geo_enrich=True)
    with (
        patch("streamlit.session_state", state),
        patch("handlers.enrich_with_geo", return_value=df) as mock_enrich,
    ):
        _maybe_enrich_geo(MagicMock(), df, CLOUDTRAIL_PROFILE)

    assert mock_enrich.called


def test_user_query_without_api_key_warns_in_the_suzaku_namespace() -> None:
    """Test 28: the warning lands in this page's history, and no API is called."""
    from handlers import _handle_user_query

    state = MockSessionState(
        api_key="",
        model="gpt-5.4",
        sz_messages=[],
        sz_query_history=[],
    )
    with (
        patch("streamlit.session_state", state),
        patch("handlers.generate_sql") as mock_generate,
    ):
        _handle_user_query("top rules", "unused.duckdb", SUZAKU_TIMELINE_PROFILE)

    assert not mock_generate.called
    assert len(state["sz_messages"]) == 1
    assert "API key" in state["sz_messages"][0]["content"]
    assert state["sz_query_history"] == []


# ---------------------------------------------------------------------------
# End-to-end: a built-in hunt against the fixture
# ---------------------------------------------------------------------------


def test_direct_sql_hunt_runs_against_the_fixture_with_filters() -> None:
    """A preset hunt must execute, honour the severity filter, and be recorded."""
    from handlers import _handle_direct_sql

    state = MockSessionState(
        api_key="",
        model="gpt-5.4",
        row_limit=50,
        geo_enrich=True,
        sz_messages=[],
        sz_query_history=[],
        sz_date_start=None,
        sz_date_end=None,
        sz_levels=["critical", "high"],
    )
    sql = (
        'SELECT "Timestamp", "Level", "RuleTitle" FROM timeline '
        'ORDER BY "Timestamp" DESC LIMIT 100'
    )
    with (
        patch("streamlit.session_state", state),
        patch("streamlit.spinner") as mock_spinner,
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)
        _handle_direct_sql(
            sql,
            str(FIXTURE),
            label="🚨 Critical & High Detections",
            category="🚨 Triage",
            bulk_mode=True,
            profile=SUZAKU_TIMELINE_PROFILE,
        )

    history = state["sz_query_history"]
    assert len(history) == 1
    results = history[0].results
    assert not results.empty
    assert len(results) <= 50
    assert set(results["Level"]) <= {"critical", "high"}
    # The severity filter reached the SQL, not just the UI.
    assert "_sz_filtered" in history[0].sql


# ---------------------------------------------------------------------------
# Agreement with the dashboard
# ---------------------------------------------------------------------------


def _copy_fixture(directory: Path, name: str) -> Path:
    """Place a copy of the timeline fixture in *directory*."""
    target = directory / name
    target.write_bytes(FIXTURE.read_bytes())
    return target


def _render(directory: Path, selectbox_returns: str | None = None):
    """Render the selector against *directory* and return the patched mocks."""
    from app import _discover_suzaku_dbs, _render_suzaku_db_selector
    from suzaku_db import SuzakuKind

    _discover_suzaku_dbs.clear()
    state = MockSessionState()
    with (
        patch("streamlit.session_state", state),
        patch(
            "app.get_duckdb_path_for_variant",
            return_value=str(directory / "threat_hunting.db"),
        ),
        patch("streamlit.subheader"),
        patch("streamlit.selectbox") as selectbox,
        patch("streamlit.caption") as caption,
        patch("streamlit.warning") as warning,
    ):
        options: list[str] = []
        selectbox.side_effect = lambda *a, **kw: (
            options.extend(kw["options"]) or (selectbox_returns or kw["options"][0])
        )
        result = _render_suzaku_db_selector(
            SUZAKU_TIMELINE_PROFILE, SuzakuKind.TIMELINE
        )
    _discover_suzaku_dbs.clear()
    captions = " ".join(
        str(call.args[0]) for call in caption.call_args_list if call.args
    )
    warnings = " ".join(
        str(call.args[0]) for call in warning.call_args_list if call.args
    )
    return result, state, options, captions, warnings


def test_the_selector_defaults_to_the_file_the_dashboard_serves(
    tmp_path: Path, monkeypatch
) -> None:
    """Two UIs showing different files without saying so is the bug (F-6)."""
    monkeypatch.delenv("SUZAKU_TIMELINE_DB", raising=False)
    from suzaku_db import SuzakuKind, select

    _copy_fixture(tmp_path, "a-run.duckdb")
    _copy_fixture(tmp_path, "b-run.duckdb")
    expected = select(tmp_path)[SuzakuKind.TIMELINE].chosen

    _, state, _, _, _ = _render(tmp_path)

    assert state["sz_suzaku_db"] == str(expected.path)


def test_choosing_another_file_says_the_dashboard_disagrees(
    tmp_path: Path, monkeypatch
) -> None:
    """Inspecting an older run is fine; not being told it differs is not."""
    monkeypatch.delenv("SUZAKU_TIMELINE_DB", raising=False)
    from suzaku_db import SuzakuKind, select

    _copy_fixture(tmp_path, "a-run.duckdb")
    _copy_fixture(tmp_path, "b-run.duckdb")
    served = select(tmp_path)[SuzakuKind.TIMELINE].chosen
    other = next(str(path) for path in tmp_path.glob("*.duckdb") if path != served.path)

    _, _, _, captions, _ = _render(tmp_path, selectbox_returns=other)

    assert "dashboard" in captions.lower()
    assert served.path.name in captions


def test_no_divergence_note_when_the_choices_agree(tmp_path: Path, monkeypatch) -> None:
    """A note on every render would train the analyst to ignore it."""
    monkeypatch.delenv("SUZAKU_TIMELINE_DB", raising=False)
    _copy_fixture(tmp_path, "only.duckdb")

    _, _, _, captions, _ = _render(tmp_path)

    assert "dashboard is showing" not in captions.lower()


def test_an_unfit_file_is_not_offered_and_is_explained(
    tmp_path: Path, monkeypatch
) -> None:
    """Offering a file no query can read wastes the analyst's time (F-1)."""
    monkeypatch.delenv("SUZAKU_TIMELINE_DB", raising=False)
    import duckdb

    good = _copy_fixture(tmp_path, "good.duckdb")
    unfit = _copy_fixture(tmp_path, "unfit.duckdb")
    conn = duckdb.connect(str(unfit))
    conn.execute('ALTER TABLE timeline DROP COLUMN "RuleID"')
    conn.close()

    _, state, options, captions, _ = _render(tmp_path)

    assert options == [str(good)]
    assert "unfit.duckdb" in captions
    assert "RuleID" in captions
    assert state["sz_suzaku_db"] == str(good)
