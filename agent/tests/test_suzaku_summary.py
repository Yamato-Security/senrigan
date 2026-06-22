"""Tests for suzaku_summary.py — parsing and aggregation of aws-ct-summary JSON."""

import json

import pandas as pd
import pytest

from suzaku_summary import (
    API_COLUMNS,
    VALUE_COLUMNS,
    SuzakuSummaryError,
    activity_timeline,
    api_entries_df,
    build_triage_table,
    country_counts,
    extract_country,
    find_identity,
    parse_summary,
    top_n,
    value_entries_df,
)


def _identity(**overrides) -> dict:
    """A minimal valid identity summary, with optional field overrides."""
    base = {
        "user_arn": "arn:aws:iam::111:user/backup",
        "user_types": "IAMUser",
        "num_of_events": 100,
        "first_timestamp": "2019-08-21 08:03:03",
        "last_timestamp": "2020-10-07 21:03:30",
        "abused_apis_success": [],
        "abused_apis_failed": [],
        "other_apis_success": [],
        "other_apis_failed": [],
        "aws_regions": [],
        "src_ips": [],
        "user_access_key_ids": [],
        "user_agents": [],
    }
    base.update(overrides)
    return base


def _api_entry(api="RunInstances (ec2.amazonaws.com)", count=10):
    return {
        "api": api,
        "description": "Spin up EC2 instances",
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


# --- parse_summary ---------------------------------------------------------


def test_parse_summary_accepts_valid_array():
    raw = json.dumps([_identity()])
    result = parse_summary(raw)
    assert len(result) == 1
    assert result[0]["user_arn"] == "arn:aws:iam::111:user/backup"


def test_parse_summary_accepts_bytes():
    raw = json.dumps([_identity()]).encode("utf-8")
    assert len(parse_summary(raw)) == 1


def test_parse_summary_accepts_jsonl():
    raw = "\n".join(
        json.dumps(_identity(user_arn=f"arn:aws:iam::111:user/u{i}")) for i in range(3)
    )
    result = parse_summary(raw)
    assert [r["user_arn"] for r in result] == [
        "arn:aws:iam::111:user/u0",
        "arn:aws:iam::111:user/u1",
        "arn:aws:iam::111:user/u2",
    ]


def test_parse_summary_jsonl_ignores_blank_lines():
    line = json.dumps(_identity())
    raw = f"\n{line}\n\n{line}\n"
    assert len(parse_summary(raw)) == 2


def test_parse_summary_rejects_invalid_json():
    with pytest.raises(SuzakuSummaryError, match="Invalid JSON"):
        parse_summary("{not json")


def test_parse_summary_rejects_non_array():
    with pytest.raises(SuzakuSummaryError, match="array"):
        parse_summary(json.dumps({"user_arn": "x"}))


def test_parse_summary_rejects_empty_array():
    with pytest.raises(SuzakuSummaryError, match="no identities"):
        parse_summary("[]")


def test_parse_summary_rejects_missing_required_key():
    incomplete = _identity()
    del incomplete["abused_apis_success"]
    with pytest.raises(SuzakuSummaryError, match="abused_apis_success"):
        parse_summary(json.dumps([incomplete]))


# --- build_triage_table ----------------------------------------------------


def test_build_triage_table_one_row_per_identity():
    df = build_triage_table(
        [_identity(), _identity(user_arn="arn:aws:iam::111:user/x")]
    )
    assert len(df) == 2


def test_build_triage_table_sorts_by_abused_then_events():
    low_abused = _identity(user_arn="low", num_of_events=999)
    high_abused = _identity(
        user_arn="high",
        num_of_events=1,
        abused_apis_success=[_api_entry(), _api_entry(api="GetBucketAcl")],
    )
    df = build_triage_table([low_abused, high_abused])
    # high_abused has 2 abused APIs and must rank first despite fewer events.
    assert df.iloc[0]["user_arn"] == "high"
    assert df.iloc[0]["abused_success"] == 2


def test_build_triage_table_counts_breakdowns():
    ident = _identity(
        aws_regions=[_value_entry(), _value_entry(value="us-east-1")],
        src_ips=[_value_entry(value="1.2.3.4")],
        user_access_key_ids=[_value_entry(value="AKIA1"), _value_entry(value="AKIA2")],
    )
    row = build_triage_table([ident]).iloc[0]
    assert row["regions"] == 2
    assert row["src_ips"] == 1
    assert row["access_keys"] == 2


def test_build_triage_table_empty_input():
    assert build_triage_table([]).empty


# --- find_identity ---------------------------------------------------------


def test_find_identity_returns_match():
    summaries = [_identity(user_arn="a"), _identity(user_arn="b")]
    assert find_identity(summaries, "b")["user_arn"] == "b"


def test_find_identity_returns_none_when_absent():
    assert find_identity([_identity(user_arn="a")], "missing") is None


# --- api_entries_df / value_entries_df -------------------------------------


def test_api_entries_df_columns_stable_when_empty():
    df = api_entries_df([])
    assert list(df.columns) == list(API_COLUMNS)
    assert df.empty


def test_api_entries_df_preserves_rows():
    df = api_entries_df([_api_entry(), _api_entry(api="X")])
    assert len(df) == 2
    assert "description" in df.columns


def test_value_entries_df_columns_stable_when_empty():
    df = value_entries_df(None)
    assert list(df.columns) == list(VALUE_COLUMNS)
    assert df.empty


# --- top_n -----------------------------------------------------------------


def test_top_n_returns_largest_by_count():
    df = value_entries_df(
        [
            _value_entry(value="a", count=1),
            _value_entry(value="b", count=50),
            _value_entry(value="c", count=10),
        ]
    )
    result = top_n(df, 2)
    assert list(result["value"]) == ["b", "c"]


def test_top_n_handles_empty():
    assert top_n(value_entries_df([])).empty


# --- extract_country / country_counts --------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        ("5.205.62.253 (Telefonica De Espana S.a.u., Madrid, Spain)", "Spain"),
        ("193.29.252.218 (GRASS-MERKUR GmbH & Co. KG, , Germany)", "Germany"),
        ("253.0.255.253 (-, -, -)", "Unknown"),
        ("-", "Unknown"),
        ("", "Unknown"),
        ("10.0.0.1", "Unknown"),
    ],
)
def test_extract_country(value, expected):
    assert extract_country(value) == expected


def test_country_counts_aggregates_and_sorts():
    src_ips = [
        _value_entry(value="1.1.1.1 (Org, City, Spain)", count=100),
        _value_entry(value="2.2.2.2 (Org, City, Germany)", count=50),
        _value_entry(value="3.3.3.3 (Org, City, Spain)", count=25),
    ]
    df = country_counts(src_ips)
    assert list(df["country"]) == ["Spain", "Germany"]
    assert df.iloc[0]["count"] == 125


def test_country_counts_empty():
    assert country_counts([]).empty


# --- activity_timeline -----------------------------------------------------


def test_activity_timeline_combines_success_and_failed():
    ident = _identity(
        abused_apis_success=[_api_entry()],
        abused_apis_failed=[_api_entry(api="AssumeRole")],
    )
    df = activity_timeline(ident)
    assert set(df["status"]) == {"success", "failed"}
    assert pd.api.types.is_datetime64_any_dtype(df["start"])


def test_activity_timeline_drops_unparseable_timestamps():
    bad = _api_entry()
    bad["first_seen"] = "not-a-date"
    ident = _identity(abused_apis_success=[bad])
    assert activity_timeline(ident).empty


def test_activity_timeline_empty_when_no_abused():
    assert activity_timeline(_identity()).empty
