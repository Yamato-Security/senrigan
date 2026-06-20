"""Tests for suzaku_report.py — Markdown / HTML report generation."""

from suzaku_report import (
    REPORT_TOP_N,
    generate_html_report,
    generate_markdown_report,
)


def _api_entry(api="RunInstances (ec2.amazonaws.com)", count=10, desc="Spin up EC2"):
    return {
        "api": api,
        "description": desc,
        "count": count,
        "first_seen": "2019-08-23 06:00:07",
        "last_seen": "2019-08-23 06:50:59",
    }


def _value_entry(value="us-west-2", count=10):
    return {
        "value": value,
        "count": count,
        "first_seen": "2019-08-23 06:00:07",
        "last_seen": "2019-08-23 06:50:59",
    }


def _identity(**overrides) -> dict:
    base = {
        "user_arn": "arn:aws:iam::111:user/backup",
        "user_types": "IAMUser",
        "num_of_events": 100,
        "first_timestamp": "2019-08-21 08:03:03",
        "last_timestamp": "2020-10-07 21:03:30",
        "abused_apis_success": [_api_entry()],
        "abused_apis_failed": [],
        "other_apis_success": [],
        "other_apis_failed": [],
        "aws_regions": [_value_entry()],
        "src_ips": [_value_entry(value="1.2.3.4 (Org, City, Spain)", count=50)],
        "user_access_key_ids": [_value_entry(value="AKIA1")],
        "user_agents": [_value_entry(value="Boto3")],
    }
    base.update(overrides)
    return base


# --- Markdown --------------------------------------------------------------


def test_markdown_report_has_title_and_counts():
    md = generate_markdown_report([_identity()])
    assert md.startswith("# Suzaku CloudTrail Summary Report")
    assert "**Identities:** 1" in md
    assert "## Overview" in md


def test_markdown_report_custom_title():
    md = generate_markdown_report([_identity()], title="My Report")
    assert md.startswith("# My Report")


def test_markdown_report_includes_identity_and_abused_api():
    md = generate_markdown_report([_identity()])
    assert "arn:aws:iam::111:user/backup (IAMUser)" in md
    assert "RunInstances (ec2.amazonaws.com)" in md
    assert "Abused APIs — Succeeded" in md


def test_markdown_report_orders_by_triage():
    low = _identity(user_arn="low", num_of_events=999, abused_apis_success=[])
    high = _identity(
        user_arn="high",
        num_of_events=1,
        abused_apis_success=[_api_entry(), _api_entry(api="GetBucketAcl")],
    )
    md = generate_markdown_report([low, high])
    # "high" has more abused APIs and must appear before "low" in the body.
    assert md.index("## high") < md.index("## low")


def test_markdown_report_caps_high_cardinality_lists():
    many_ips = [
        _value_entry(value=f"10.0.0.{i}", count=i) for i in range(REPORT_TOP_N + 30)
    ]
    md = generate_markdown_report([_identity(src_ips=many_ips)])
    assert f"(top {REPORT_TOP_N} of" in md


def test_markdown_report_handles_empty_sections():
    md = generate_markdown_report([_identity(abused_apis_failed=[])])
    assert "_(none)_" in md  # empty failed-API table renders the placeholder


# --- HTML ------------------------------------------------------------------


def test_html_report_is_self_contained_document():
    html = generate_html_report([_identity()])
    assert html.startswith("<!DOCTYPE html>")
    assert "<style>" in html
    assert "</html>" in html


def test_html_report_includes_toc_and_section():
    html = generate_html_report([_identity()])
    assert 'id="toc"' in html
    # The identity heading appears in both the TOC link and the section.
    assert html.count("arn:aws:iam::111:user/backup (IAMUser)") >= 2


def test_html_report_escapes_special_characters():
    ident = _identity(user_arn="arn:aws:iam::111:user/<script>")
    html = generate_html_report([ident])
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def test_html_report_renders_overview_table():
    html = generate_html_report([_identity()])
    assert 'id="overview"' in html
    assert "<table" in html
