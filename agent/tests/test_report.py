"""Tests for report.py — Threat hunting report generation."""

from datetime import datetime, timezone
from unittest.mock import patch

import pandas as pd

from report import ReportEntry, generate_html_report, generate_report


def test_generate_report_markdown():
    """Given a session (queries + results + summary), generates a Markdown report."""
    entry = ReportEntry(
        sql="SELECT event_name FROM cloudtrail_events LIMIT 5",
        results=pd.DataFrame({"event_name": ["CreateUser", "DescribeInstances"]}),
        analysis="- 2 events found.\n- CreateUser: 1, DescribeInstances: 1.",
    )

    report = generate_report([entry])

    assert isinstance(report, str)
    assert len(report) > 0
    assert "SELECT" in report
    # Summary section must appear; legacy "### Analysis" heading must NOT
    assert "### Summary" in report
    assert "### Analysis" not in report


def test_report_includes_timestamp():
    """The report header includes the generation timestamp."""
    entry = ReportEntry(
        sql="SELECT 1",
        results=pd.DataFrame(),
        analysis="",
    )

    fixed_dt = datetime(2026, 3, 11, 12, 0, 0, tzinfo=timezone.utc)
    with patch("report.datetime") as mock_dt:
        mock_dt.now.return_value = fixed_dt
        report = generate_report([entry])

    # ISO 8601 date portion (YYYY-MM-DD) must appear in the header
    assert "2026-03-11" in report


def test_report_includes_all_queries():
    """Each query-result-summary triple is included in the report."""
    entries = [
        ReportEntry(
            sql="SELECT event_name FROM cloudtrail_events LIMIT 1",
            results=pd.DataFrame({"event_name": ["CreateUser"]}),
            analysis="- 1 CreateUser event found.",
        ),
        ReportEntry(
            sql="SELECT aws_region FROM cloudtrail_events LIMIT 1",
            results=pd.DataFrame({"aws_region": ["us-east-1"]}),
            analysis="- 1 event in us-east-1.",
        ),
    ]

    report = generate_report(entries)

    assert "SELECT event_name FROM cloudtrail_events LIMIT 1" in report
    assert "SELECT aws_region FROM cloudtrail_events LIMIT 1" in report
    assert "1 CreateUser event found." in report
    assert "1 event in us-east-1." in report
    assert "### Summary" in report
    assert "### Analysis" not in report


def test_report_entry_chart_config_defaults_to_none():
    """ReportEntry.chart_config must default to None when not provided.

    Test #CHART-R1: backward-compatible — existing callers are unaffected.
    """
    entry = ReportEntry(sql="SELECT 1", results=pd.DataFrame())
    assert hasattr(
        entry, "chart_config"
    ), "ReportEntry must have a 'chart_config' field"
    assert entry.chart_config is None


def test_report_entry_chart_config_stores_dict():
    """ReportEntry.chart_config must accept and persist a dict.

    Test #CHART-R2: verifies the field is writable with a chart config dict.
    """
    config = {"type": "bar", "x": "event_name", "y": ["api_count"]}
    entry = ReportEntry(sql="SELECT 1", results=pd.DataFrame(), chart_config=config)
    assert entry.chart_config == config


# ---------------------------------------------------------------------------
# Tests #UI-01 — Analyst note per query
# ---------------------------------------------------------------------------


def test_report_entry_has_analyst_note_field():
    """ReportEntry must accept an analyst_note field defaulting to empty string.

    Test #UI-01-1: backward-compatible — existing callers are unaffected.
    """
    entry = ReportEntry(sql="SELECT 1", results=pd.DataFrame())
    assert hasattr(
        entry, "analyst_note"
    ), "ReportEntry must have an 'analyst_note' field"
    assert entry.analyst_note == ""


def test_report_entry_analyst_note_stores_value():
    """ReportEntry.analyst_note must persist the provided value.

    Test #UI-01-2: verifies the field is writable.
    """
    entry = ReportEntry(
        sql="SELECT 1",
        results=pd.DataFrame(),
        analyst_note="Suspicious root activity — investigate further.",
    )
    assert entry.analyst_note == "Suspicious root activity — investigate further."


def test_generate_report_includes_analyst_note_section():
    """generate_report() includes '### Analyst Note' when analyst_note is non-empty.

    Test #UI-01-3: the note must appear under its own heading in the report.
    """
    entry = ReportEntry(
        sql="SELECT event_name FROM cloudtrail_events LIMIT 5",
        results=pd.DataFrame({"event_name": ["CreateUser"]}),
        analysis="- 1 event found.",
        analyst_note="Analyst observation: single CreateUser from root.",
    )
    report = generate_report([entry])
    assert "### Analyst Note" in report
    assert "Analyst observation: single CreateUser from root." in report


def test_generate_report_omits_analyst_note_section_when_empty():
    """generate_report() omits '### Analyst Note' when analyst_note is empty.

    Test #UI-01-4: heading must not appear for empty notes to keep reports clean.
    """
    entry = ReportEntry(
        sql="SELECT 1",
        results=pd.DataFrame(),
        analysis="",
        analyst_note="",
    )
    report = generate_report([entry])
    assert "### Analyst Note" not in report


def test_report_sanitizes_analyst_note():
    """Sensitive patterns in analyst_note must be redacted.

    Test #UI-01-5: redaction covers all text sections including analyst notes.
    """
    key_id = "AKIAIOSFODNN7EXAMPLE"
    entry = ReportEntry(
        sql="SELECT 1",
        results=pd.DataFrame(),
        analyst_note=f"Possible leaked key: {key_id}",
    )
    report = generate_report([entry])
    assert key_id not in report
    assert "REDACTED" in report


# ---------------------------------------------------------------------------
# Tests #UI-02 — Category / query name fields in ReportEntry
# ---------------------------------------------------------------------------


def test_report_entry_has_label_and_category_fields():
    """ReportEntry must accept label and category fields defaulting to empty string.

    Test #UI-02-1: backward-compatible — existing callers are unaffected.
    """
    entry = ReportEntry(sql="SELECT 1", results=pd.DataFrame())
    assert hasattr(entry, "label"), "ReportEntry must have a 'label' field"
    assert hasattr(entry, "category"), "ReportEntry must have a 'category' field"
    assert entry.label == ""
    assert entry.category == ""


def test_report_entry_label_and_category_store_values():
    """ReportEntry label and category must persist provided values.

    Test #UI-02-2: verifies the fields are writable.
    """
    entry = ReportEntry(
        sql="SELECT 1",
        results=pd.DataFrame(),
        label="🔑 Root Account Activity",
        category="🔑 Identity & Access",
    )
    assert entry.label == "🔑 Root Account Activity"
    assert entry.category == "🔑 Identity & Access"


def test_generate_report_includes_label_in_heading():
    """generate_report() includes label in the query section heading when non-empty.

    Test #UI-02-3: the label must appear prominently in the report section.
    """
    entry = ReportEntry(
        sql="SELECT 1",
        results=pd.DataFrame(),
        label="🔑 Root Account Activity",
    )
    report = generate_report([entry])
    assert "🔑 Root Account Activity" in report


def test_generate_report_includes_category_when_set():
    """generate_report() includes category in the report section when non-empty.

    Test #UI-02-4: category must appear as context in the report.
    """
    entry = ReportEntry(
        sql="SELECT 1",
        results=pd.DataFrame(),
        category="🔑 Identity & Access",
        label="🔑 Root Account Activity",
    )
    report = generate_report([entry])
    assert "🔑 Identity & Access" in report


def test_report_sanitizes_sensitive_data():
    """Credentials in query results and summary text are redacted."""
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # 40-char secret-like string
    key_id = "AKIAIOSFODNN7EXAMPLE"  # AWS Access Key ID pattern

    entry = ReportEntry(
        sql="SELECT secret FROM credentials",
        results=pd.DataFrame({"secret": [secret], "key_id": [key_id]}),
        analysis=f"Found secret: {secret} and key: {key_id}",
    )

    report = generate_report([entry])

    assert secret not in report
    assert key_id not in report
    assert "REDACTED" in report
    assert "### Summary" in report
    assert "### Analysis" not in report


# ---------------------------------------------------------------------------
# Tests #UI-SIDEBAR — Sidebar toggle (open/close left menu column)
# ---------------------------------------------------------------------------


def _make_html_report() -> str:
    """Helper: generate a minimal HTML report for sidebar resize tests."""
    entry = ReportEntry(sql="SELECT 1", results=pd.DataFrame(), analysis="test")
    return generate_html_report([entry])


# ---------------------------------------------------------------------------
# Tests #UI-RESIZE — Sidebar drag-to-resize
# ---------------------------------------------------------------------------


def test_html_report_has_sidebar_resizer_element():
    """HTML report must contain a resizer handle element with id='sidebar-resizer'.

    Test #UI-RESIZE-1: the drag handle must exist between the sidebar and content.
    """
    html = _make_html_report()
    assert 'id="sidebar-resizer"' in html


def test_html_report_has_sidebar_resizer_css():
    """HTML report CSS must define a style rule for #sidebar-resizer.

    Test #UI-RESIZE-2: the resizer must be styled so users can see and grab it.
    """
    html = _make_html_report()
    assert "#sidebar-resizer" in html


def test_html_report_has_resize_pointerdown_script():
    """HTML report JS must attach a pointerdown event to the resizer.

    Test #UI-RESIZE-3: drag-to-resize requires a pointerdown handler on the handle.
    """
    html = _make_html_report()
    assert "pointerdown" in html


def test_html_report_resize_persists_to_localstorage():
    """HTML report JS must persist the sidebar width to localStorage after resize.

    Test #UI-RESIZE-4: width must survive page reload.
    """
    html = _make_html_report()
    # Both the key used for width storage and the setItem call must be present.
    assert "localStorage" in html and "sidebar-width" in html


def test_html_report_resize_restores_width_on_load():
    """HTML report JS must restore the saved width from localStorage on page load.

    Test #UI-RESIZE-5: if a width is stored, it must be applied when the page opens.
    """
    html = _make_html_report()
    assert "getItem" in html and "sidebar-width" in html


# ---------------------------------------------------------------------------
# Tests #SQL-HL — SQL syntax highlighting in HTML report
# ---------------------------------------------------------------------------


def test_highlight_sql_wraps_keywords():
    """_highlight_sql wraps SQL keywords in sql-keyword spans.

    Test #SQL-HL-1: SELECT and FROM must be highlighted.
    """
    from report import _highlight_sql

    result = _highlight_sql("SELECT * FROM events")
    assert 'class="sql-keyword"' in result
    assert "SELECT" in result
    assert "FROM" in result


def test_highlight_sql_wraps_single_quoted_strings():
    """_highlight_sql wraps single-quoted strings in sql-string spans.

    Test #SQL-HL-2: quoted literals must receive the sql-string class.
    """
    from report import _highlight_sql

    result = _highlight_sql("WHERE event_name = 'CreateUser'")
    assert 'class="sql-string"' in result
    assert "CreateUser" in result


def test_highlight_sql_wraps_line_comments():
    """_highlight_sql wraps -- comments in sql-comment spans.

    Test #SQL-HL-3: line comments must receive the sql-comment class.
    """
    from report import _highlight_sql

    result = _highlight_sql("SELECT 1 -- count rows")
    assert 'class="sql-comment"' in result
    assert "count rows" in result


def test_highlight_sql_wraps_numbers():
    """_highlight_sql wraps numeric literals in sql-number spans.

    Test #SQL-HL-4: integer and decimal literals must receive the sql-number class.
    """
    from report import _highlight_sql

    result = _highlight_sql("LIMIT 100")
    assert 'class="sql-number"' in result
    assert "100" in result


def test_highlight_sql_escapes_html_special_chars():
    """_highlight_sql HTML-escapes < and > inside SQL text.

    Test #SQL-HL-5: raw angle brackets must appear as &lt; / &gt; in the output.
    """
    from report import _highlight_sql

    result = _highlight_sql("WHERE count > 0 AND size < 10")
    assert "&gt;" in result
    assert "&lt;" in result


def test_html_report_sql_block_has_highlighting_classes():
    """HTML report SQL blocks must contain sql-keyword span elements.

    Test #SQL-HL-6: the rendered HTML must include syntax-highlighted SQL.
    """
    entry = ReportEntry(
        sql="SELECT event_name FROM cloudtrail_events LIMIT 5",
        results=pd.DataFrame(),
    )
    result = generate_html_report([entry])
    assert 'class="sql-keyword"' in result


def test_html_report_has_sql_highlight_css():
    """HTML report must include CSS rules for SQL syntax highlighting classes.

    Test #SQL-HL-7: the style block must define .sql-keyword, .sql-string, etc.
    """
    entry = ReportEntry(sql="SELECT 1", results=pd.DataFrame())
    result = generate_html_report([entry])
    assert ".sql-keyword" in result
    assert ".sql-string" in result
    assert ".sql-comment" in result
    assert ".sql-number" in result
