"""Technique metadata tests for builtin_hunts.yaml and its rendering.

Implements the Phase-1 test list from doc/PLAN_THREAT_CATALOG.md:
  TC-1: every threat-category hunt declares a non-empty `techniques` list
  TC-2: every tid matches the catalog TID format (T1078, T1562.008,
        T1486.A001, AT1669, AT1023.001)
  TC-3: name and summary are non-empty strings
  TC-4: url points at the catalog page for that tid
  TC-5: no hunt lists the same tid twice
  TC-6: _build_all_hunt_queries() passes techniques through
  TC-7: _handle_direct_sql() stores techniques on the ReportEntry
  TC-8: ReportEntry has a `techniques` field defaulting to an empty list
  TC-9: generate_report() renders a Techniques block (and omits it when empty)
  TC-10: generate_html_report() renders catalog links
  TC-11: _format_technique_caption() renders the sidebar/result-card caption
"""

from __future__ import annotations

import pathlib
import re
from typing import Any
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest
import yaml

from report import ReportEntry, generate_html_report, generate_report

YAML_PATH = pathlib.Path(__file__).parent.parent / "builtin_hunts.yaml"

CATALOG_BASE_URL = (
    "https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/"
)

# T1078 | T1562.008 | T1486.A001 | AT1669 | AT1023.001
TID_RE = re.compile(r"^A?T\d{4}(\.A?\d{3})?$")

# Categories whose hunts detect a concrete threat technique and therefore
# must be mapped to the Threat Technique Catalog.  Baseline/geo summary
# categories are exempt (they profile activity rather than detect a TTP).
THREAT_CATEGORIES = {
    "\U0001f6e1 Detection & Response",
    "\U0001f511 Identity & Access",
    "\U0001faa3 Data & Storage",
    "⚡ Compute & Serverless",
    "\U0001f916 AI & LLM Abuse",
    "\U0001f310 Network & Infrastructure",
    "\U0001f575 Threat Patterns",
    "☁ IaC & Platform",
}

SAMPLE_TECHNIQUES = [
    {
        "tid": "T1562.008",
        "name": "Impair Defenses: Disable Cloud Logs",
        "summary": "Adversaries disable CloudTrail logging to avoid an audit trail.",
        "url": f"{CATALOG_BASE_URL}T1562.008.html",
    },
    {
        "tid": "AT1669",
        "name": "Assume Root into Organization Member Account",
        "summary": "Adversaries pivot to member-account root via sts:AssumeRoot.",
        "url": f"{CATALOG_BASE_URL}AT1669.html",
    },
]


def _load_hunts() -> list[dict[str, Any]]:
    with open(YAML_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _threat_hunts() -> list[dict[str, Any]]:
    return [h for h in _load_hunts() if h.get("category") in THREAT_CATEGORIES]


# ---------------------------------------------------------------------------
# TC-1 … TC-5 — YAML schema validation
# ---------------------------------------------------------------------------


def test_threat_hunts_have_nonempty_techniques():
    """TC-1: every threat-category hunt maps to at least one catalog technique."""
    missing = [
        h["label"]
        for h in _threat_hunts()
        if not isinstance(h.get("techniques"), list) or not h["techniques"]
    ]
    assert not missing, f"Hunts without techniques metadata: {missing}"


def test_technique_tids_match_catalog_format():
    """TC-2: every tid matches the catalog TID grammar."""
    bad = [
        (h["label"], t.get("tid"))
        for h in _load_hunts()
        for t in h.get("techniques") or []
        if not TID_RE.match(str(t.get("tid", "")))
    ]
    assert not bad, f"Invalid TIDs: {bad}"


def test_technique_name_and_summary_are_nonempty():
    """TC-3: name and summary are required, non-empty strings."""
    bad = [
        (h["label"], t.get("tid"))
        for h in _load_hunts()
        for t in h.get("techniques") or []
        if not str(t.get("name", "")).strip() or not str(t.get("summary", "")).strip()
    ]
    assert not bad, f"Techniques with empty name/summary: {bad}"


def test_technique_urls_point_at_catalog_page():
    """TC-4: url must be the catalog page for the declared tid."""
    bad = [
        (h["label"], t.get("tid"), t.get("url"))
        for h in _load_hunts()
        for t in h.get("techniques") or []
        if t.get("url") != f"{CATALOG_BASE_URL}{t.get('tid')}.html"
    ]
    assert not bad, f"URLs not matching catalog pattern: {bad}"


def test_no_duplicate_tids_within_a_hunt():
    """TC-5: a hunt must not list the same tid twice."""
    dupes = []
    for h in _load_hunts():
        tids = [t["tid"] for t in h.get("techniques") or []]
        if len(tids) != len(set(tids)):
            dupes.append((h["label"], tids))
    assert not dupes, f"Duplicate TIDs within a hunt: {dupes}"


# ---------------------------------------------------------------------------
# TC-6 / TC-7 — techniques flow through the query pipeline
# ---------------------------------------------------------------------------


def test_build_all_hunt_queries_includes_techniques():
    """TC-6: bulk-query dicts carry the techniques list (default [])."""
    from app import _build_all_hunt_queries

    prompts = [
        {
            "label": "with techniques",
            "sql": "SELECT 1",
            "techniques": SAMPLE_TECHNIQUES,
        },
        {"label": "without techniques", "sql": "SELECT 2"},
    ]
    queries = _build_all_hunt_queries(prompts)
    assert queries[0]["techniques"] == SAMPLE_TECHNIQUES
    assert queries[1]["techniques"] == []


def test_handle_direct_sql_stores_techniques(tmp_duckdb):
    """TC-7: _handle_direct_sql() propagates techniques onto the ReportEntry."""
    from tests.conftest import MockSessionState

    mock_state = MockSessionState(
        api_key="",
        model="gpt-5.4",
        messages=[],
        query_history=[],
        last_sql="",
        last_results=None,
        last_summary="",
        date_start=None,
        date_end=None,
    )

    with (
        patch("streamlit.session_state", mock_state),
        patch("streamlit.spinner") as mock_spinner,
        patch("streamlit.warning"),
    ):
        mock_spinner.return_value.__enter__ = MagicMock(return_value=None)
        mock_spinner.return_value.__exit__ = MagicMock(return_value=False)

        from app import _handle_direct_sql

        _handle_direct_sql(
            "SELECT event_name FROM cloudtrail_events LIMIT 1",
            tmp_duckdb,
            techniques=SAMPLE_TECHNIQUES,
        )

    assert len(mock_state["query_history"]) == 1
    assert mock_state["query_history"][0].techniques == SAMPLE_TECHNIQUES


# ---------------------------------------------------------------------------
# TC-8 … TC-10 — ReportEntry and report rendering
# ---------------------------------------------------------------------------


def test_report_entry_has_techniques_field_default_empty():
    """TC-8: ReportEntry.techniques defaults to an independent empty list."""
    entry = ReportEntry(sql="SELECT 1", results=pd.DataFrame())
    assert entry.techniques == []
    other = ReportEntry(sql="SELECT 2", results=pd.DataFrame())
    entry.techniques.append({"tid": "T1078"})
    assert other.techniques == []  # default_factory, not a shared list


def test_generate_report_includes_techniques_block():
    """TC-9a: Markdown report renders tid, name, summary, and catalog link."""
    entry = ReportEntry(
        sql="SELECT 1",
        results=pd.DataFrame({"a": [1]}),
        label="Test Hunt",
        techniques=SAMPLE_TECHNIQUES,
    )
    report = generate_report([entry])
    assert "T1562.008" in report
    assert "Impair Defenses: Disable Cloud Logs" in report
    assert f"{CATALOG_BASE_URL}T1562.008.html" in report
    assert "avoid an audit trail" in report
    assert "AT1669" in report


def test_generate_report_omits_techniques_block_when_empty():
    """TC-9b: entries without techniques render exactly as before."""
    entry = ReportEntry(sql="SELECT 1", results=pd.DataFrame({"a": [1]}))
    report = generate_report([entry])
    assert "Techniques" not in report


def test_html_report_includes_technique_links():
    """TC-10: HTML report renders anchors to the catalog pages."""
    entry = ReportEntry(
        sql="SELECT 1",
        results=pd.DataFrame({"a": [1]}),
        label="Test Hunt",
        techniques=SAMPLE_TECHNIQUES,
    )
    html = generate_html_report([entry])
    assert f'href="{CATALOG_BASE_URL}T1562.008.html"' in html
    assert "T1562.008" in html
    assert "Impair Defenses: Disable Cloud Logs" in html


def test_html_report_omits_technique_section_when_empty():
    """TC-10b: no Techniques heading when the entry has no techniques."""
    entry = ReportEntry(sql="SELECT 1", results=pd.DataFrame({"a": [1]}))
    html = generate_html_report([entry])
    assert "Techniques" not in html


# ---------------------------------------------------------------------------
# TC-11 — sidebar / result-card caption formatting
# ---------------------------------------------------------------------------


def test_format_technique_caption_renders_link_and_summary():
    """TC-11a: caption contains a Markdown link and the one-line summary."""
    from app import _format_technique_caption

    caption = _format_technique_caption(SAMPLE_TECHNIQUES[0])
    assert caption == (
        "\U0001f3af [T1562.008 — Impair Defenses: Disable Cloud Logs]"
        f"({CATALOG_BASE_URL}T1562.008.html): "
        "Adversaries disable CloudTrail logging to avoid an audit trail."
    )


def test_format_technique_caption_handles_missing_fields():
    """TC-11b: caption degrades gracefully when optional fields are missing."""
    from app import _format_technique_caption

    caption = _format_technique_caption({"tid": "T1078"})
    assert "T1078" in caption
    assert "(" not in caption  # no link without a url


@pytest.mark.parametrize("field_name", ["tid", "name", "summary", "url"])
def test_all_yaml_technique_values_are_strings(field_name):
    """Schema guard: every present technique field is a plain string."""
    bad = [
        (h["label"], t.get("tid"))
        for h in _load_hunts()
        for t in h.get("techniques") or []
        if field_name in t and not isinstance(t[field_name], str)
    ]
    assert not bad, f"Non-string {field_name} values: {bad}"
