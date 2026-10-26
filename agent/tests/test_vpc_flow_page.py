"""Tests for the 🌊 VPC Flow chat page: database, geo, navigation and coverage.

The page reuses the shared hunting UI, so what is tested here is only what
differs from CloudTrail: it reads Senrigan's own database (not a Suzaku file),
its addresses are geo-enriched from ``ip_geo``, and a hunt whose fields the
selected data does not log reports *insufficient coverage* instead of an empty
result — the distinction PRD_VPC_FLOW_LOGS §4.2 requires.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import duckdb
import pytest

from profiles import CLOUDTRAIL_PROFILE, VPC_FLOW_PROFILE
from tests.conftest import MockSessionState

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "sample"
    / "vpc_flow"
    / "fixtures"
    / "vpc-flow-fixture.duckdb"
)
LEGACY_FLOW_LOG = "fl-0f1e2d3c4b5a60002"


def _state(**overrides) -> MockSessionState:
    p = VPC_FLOW_PROFILE.state_key
    defaults = {
        "api_key": "",
        "model": "gpt-5.4",
        p("messages"): [],
        p("query_history"): [],
        p("last_sql"): "",
        p("last_results"): None,
        p("last_summary"): "",
        p("date_start"): None,
        p("date_end"): None,
    }
    defaults.update(overrides)
    return MockSessionState(**defaults)


def _run(sql: str, db_path: str, state: MockSessionState, **kwargs) -> None:
    with (
        patch("streamlit.session_state", state),
        patch("streamlit.spinner") as spinner,
    ):
        spinner.return_value.__enter__ = MagicMock(return_value=None)
        spinner.return_value.__exit__ = MagicMock(return_value=False)
        from handlers import _handle_direct_sql

        _handle_direct_sql(sql, db_path, profile=VPC_FLOW_PROFILE, **kwargs)


def test_flow_results_are_geo_enriched_from_ip_geo() -> None:
    """VF-1: remote_addr gains geo columns from ip_geo, with no IP-like name."""
    state = _state()
    _run(
        "SELECT remote_addr, count(*) AS records FROM vpc_flow_logs "
        "WHERE direction_source = 'record' AND remote_scope = 'public' "
        "GROUP BY remote_addr ORDER BY remote_addr LIMIT 100",
        str(FIXTURE),
        state,
    )
    results = state[VPC_FLOW_PROFILE.state_key("query_history")][0].results
    assert list(results.columns[:2]) == ["remote_addr", "geo_country_code"]
    row = results[results["remote_addr"] == "81.2.69.160"].iloc[0]
    assert row["geo_country_code"] == "GB"


def test_flow_page_reads_senrigans_database() -> None:
    """VF-2: the flow page follows the Full/Lite variant, never the Suzaku picker."""
    from app import _get_duckdb_path

    state = MockSessionState(db_variant="Full", vf_suzaku_db="/ignored.duckdb")
    with (
        patch("streamlit.session_state", state),
        patch.dict("os.environ", {"DUCKDB_PATH": "/data/db/threat_hunting.db"}),
    ):
        assert _get_duckdb_path(VPC_FLOW_PROFILE) == _get_duckdb_path(
            CLOUDTRAIL_PROFILE
        )
        assert _get_duckdb_path(VPC_FLOW_PROFILE) == "/data/db/threat_hunting.db"


@pytest.fixture
def legacy_only_db(tmp_path) -> str:
    """A database whose only flow logs are version 2: no direction, no tcp_flags."""
    path = tmp_path / "legacy.db"
    shutil.copyfile(FIXTURE, path)
    conn = duckdb.connect(str(path))
    conn.execute("DELETE FROM vpc_flow_logs WHERE flow_log_id <> ?", [LEGACY_FLOW_LOG])
    conn.close()
    return str(path)


def test_coverage_gaps_names_unlogged_fields(legacy_only_db) -> None:
    """VF-3: fields absent from every selected record are coverage gaps."""
    from query import coverage_gaps

    conn = duckdb.connect(legacy_only_db, read_only=True)
    try:
        gaps = coverage_gaps(
            conn, VPC_FLOW_PROFILE, ["flow_direction", "tcp_flags", "dstport"]
        )
    finally:
        conn.close()
    assert gaps == ["flow_direction", "tcp_flags"]


def test_coverage_gaps_respects_the_date_filter() -> None:
    """VF-4: a window with no records at all is a gap, not an empty result."""
    from datetime import date

    from query import coverage_gaps

    conn = duckdb.connect(str(FIXTURE), read_only=True)
    try:
        assert coverage_gaps(conn, VPC_FLOW_PROFILE, ["dstport"]) == []
        gaps = coverage_gaps(
            conn,
            VPC_FLOW_PROFILE,
            ["dstport"],
            start_date=date(2023, 1, 1),
            end_date=date(2023, 1, 2),
        )
    finally:
        conn.close()
    assert gaps == ["(no records in the selected window)"]


def test_hunt_without_coverage_reports_it_instead_of_an_empty_result(
    legacy_only_db,
) -> None:
    """VF-5: 'no findings' and 'not observed' must look different to the analyst."""
    from session import _load_builtin_prompts

    hunt = next(
        h
        for h in _load_builtin_prompts(VPC_FLOW_PROFILE)
        if "flow_direction" in h.get("requires", [])
    )
    state = _state()
    _run(hunt["sql"], legacy_only_db, state, label=hunt["label"])

    message = state[VPC_FLOW_PROFILE.state_key("messages")][-1]["content"]
    assert "Insufficient coverage" in message
    assert "flow_direction" in message
    assert state[VPC_FLOW_PROFILE.state_key("last_results")] is None


def test_hunt_with_coverage_runs_normally() -> None:
    """VF-6: the coverage check never blocks a hunt the data can answer."""
    from session import _load_builtin_prompts

    hunt = next(
        h
        for h in _load_builtin_prompts(VPC_FLOW_PROFILE)
        if "flow_direction" in h.get("requires", [])
    )
    state = _state()
    _run(hunt["sql"], str(FIXTURE), state, label=hunt["label"])

    message = state[VPC_FLOW_PROFILE.state_key("messages")][-1]["content"]
    assert "Insufficient coverage" not in message
    assert state[VPC_FLOW_PROFILE.state_key("last_results")] is not None


def test_limitations_travel_with_the_hunt_description() -> None:
    """VF-7: limitations reach every place the description goes, the report included."""
    from session import _load_builtin_prompts

    hunts = [h for h in _load_builtin_prompts(VPC_FLOW_PROFILE) if h.get("limitations")]
    assert hunts, "no hunt declares limitations"
    for hunt in hunts:
        assert "Limitations:" in hunt["description"]
        assert hunt["limitations"].strip() in hunt["description"]


def test_page_knows_when_there_are_no_flow_logs(tmp_path) -> None:
    """VF-8: a CloudTrail-only database shows how to get flow logs, not an empty chat."""
    from views.vpc_flow import has_flow_logs

    assert has_flow_logs(str(FIXTURE)) is True
    assert has_flow_logs(str(tmp_path / "missing.db")) is False
    cloudtrail_only = tmp_path / "ct.db"
    conn = duckdb.connect(str(cloudtrail_only))
    conn.execute("CREATE TABLE cloudtrail_events (event_time TIMESTAMP)")
    conn.close()
    assert has_flow_logs(str(cloudtrail_only)) is False
