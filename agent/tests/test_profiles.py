"""Tests for the dataset-profile abstraction.

Covers PLAN_SUZAKU_VIEWS.md §4.1 and §4.5 (tests 11-18). A profile describes one
queryable table — Senrigan's own ``cloudtrail_events`` or Suzaku's ``timeline`` —
so the chat pipeline (schema description, prompt, date filter, session state)
works for either without duplicating it.

Every parameterized function keeps ``CLOUDTRAIL_PROFILE`` as its default, which
is what lets the pre-existing agent tests pass unchanged.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from unittest.mock import MagicMock, patch

import duckdb
import pytest

from profiles import (
    CLOUDTRAIL_PROFILE,
    PROFILES,
    SHARED_STATE_KEYS,
    SUZAKU_METRICS_PROFILE,
    SUZAKU_SUMMARY_PROFILE,
    SUZAKU_TIMELINE_PROFILE,
    DatasetProfile,
)
from query import apply_date_filter, apply_filters
from schema import get_column_names, get_schema_description
from suzaku_db import SuzakuKind

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "sample"
    / "suzaku"
    / "fixtures"
    / "suzaku-aws-ct-timeline.duckdb"
)


# ---------------------------------------------------------------------------
# Profile definitions (tests 11-12)
# ---------------------------------------------------------------------------


def test_cloudtrail_profile_reproduces_current_behaviour() -> None:
    """Test 11: the default profile must describe today's hard-coded values."""
    profile = CLOUDTRAIL_PROFILE
    assert profile.table == "cloudtrail_events"
    assert profile.time_column == "event_time"
    assert profile.time_is_varchar is False
    assert profile.filter_alias == "_ct_filtered"
    assert profile.state_prefix == ""
    assert profile.supports_geo_enrich is True
    assert profile.quote_identifiers is False
    assert profile.level_column is None


def test_suzaku_timeline_profile_describes_the_timeline_table() -> None:
    """The Suzaku profile carries every deviation from the CloudTrail table."""
    profile = SUZAKU_TIMELINE_PROFILE
    assert profile.table == "timeline"
    assert profile.time_column == "Timestamp"
    assert profile.time_is_varchar is False  # typed since Suzaku schema_version 1
    assert profile.filter_alias == "_sz_filtered"
    assert profile.state_prefix == "sz_"
    assert profile.supports_geo_enrich is False
    assert profile.quote_identifiers is True
    assert profile.level_column == "Level"
    assert profile.level_order == (
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    )


def test_suzaku_summary_profile_describes_the_summary_tables() -> None:
    """Test 1a: the explorer profile for ``aws-ct-summary``.

    Covers PLAN_SUZAKU_EXPLORERS.md §5.1. It reads a pre-aggregated file, so it
    carries no LLM columns and no hunts — the page drives reviewed SQL instead.
    """
    profile = SUZAKU_SUMMARY_PROFILE
    assert profile.table == "summary"
    assert profile.time_column == "FirstTimestamp"
    assert profile.state_prefix == "szs_"
    assert profile.quote_identifiers is True
    assert profile.supports_geo_enrich is False
    assert profile.chat_enabled is False
    assert profile.suzaku_kind is SuzakuKind.SUMMARY


def test_suzaku_metrics_profile_describes_the_metrics_table() -> None:
    """Test 1b: the explorer profile for ``aws-ct-metrics``."""
    profile = SUZAKU_METRICS_PROFILE
    assert profile.table == "metrics"
    assert profile.time_column == "FirstSeen"
    assert profile.state_prefix == "szm_"
    assert profile.quote_identifiers is True
    assert profile.supports_geo_enrich is False
    assert profile.chat_enabled is False
    assert profile.suzaku_kind is SuzakuKind.METRICS


def test_chat_profiles_stay_chat_enabled() -> None:
    """Test 4: the two chat pages must be unaffected by the new field."""
    assert CLOUDTRAIL_PROFILE.chat_enabled is True
    assert SUZAKU_TIMELINE_PROFILE.chat_enabled is True
    assert CLOUDTRAIL_PROFILE.suzaku_kind is None
    assert SUZAKU_TIMELINE_PROFILE.suzaku_kind is SuzakuKind.TIMELINE


@pytest.mark.parametrize(
    "profile", [SUZAKU_SUMMARY_PROFILE, SUZAKU_METRICS_PROFILE], ids=lambda p: p.key
)
def test_explorer_profiles_refuse_the_chat_pipeline(profile: DatasetProfile) -> None:
    """Test 3: reaching the chat pipeline with an explorer profile is a bug.

    Returning an empty prompt or a missing hunts path would ship the mistake to
    OpenAI; raising makes it a test failure instead.
    """
    with pytest.raises(ValueError):
        profile.hunts_path
    with pytest.raises(ValueError):
        profile.build_system_prompt()


def test_profiles_registry_is_keyed_by_profile_key() -> None:
    """The registry is what the navigation and tests iterate over."""
    assert set(PROFILES) == {
        "cloudtrail",
        "suzaku_timeline",
        "suzaku_summary",
        "suzaku_metrics",
    }
    for key, profile in PROFILES.items():
        assert profile.key == key
        assert profile.default_row_limit > 0
        assert profile.label


def test_state_prefixes_are_unique_across_profiles() -> None:
    """Test 2: four pages share one ``st.session_state``."""
    prefixes = [profile.state_prefix for profile in PROFILES.values()]
    assert len(set(prefixes)) == len(prefixes)

    for name in ("messages", "query_history", "suzaku_db"):
        keys = [profile.state_key(name) for profile in PROFILES.values()]
        assert len(set(keys)) == len(keys), name


def test_state_key_namespaces_per_page_keys() -> None:
    """Test 12: two pages must not share chat history, results or filters."""
    assert CLOUDTRAIL_PROFILE.state_key("messages") == "messages"
    assert SUZAKU_TIMELINE_PROFILE.state_key("messages") == "sz_messages"
    assert SUZAKU_TIMELINE_PROFILE.state_key("query_history") == "sz_query_history"


@pytest.mark.parametrize("name", sorted(SHARED_STATE_KEYS))
def test_shared_state_keys_are_never_namespaced(name: str) -> None:
    """The API key, model and row limit are entered once and apply everywhere."""
    assert SUZAKU_TIMELINE_PROFILE.state_key(name) == name


def test_quote_wraps_identifiers_only_when_required() -> None:
    """PascalCase columns must be quoted; snake_case columns must stay bare."""
    assert SUZAKU_TIMELINE_PROFILE.quote("AwsRegion") == '"AwsRegion"'
    assert CLOUDTRAIL_PROFILE.quote("event_time") == "event_time"


def test_hunts_path_exists_for_every_chat_profile() -> None:
    """A profile whose hunts YAML is missing renders an empty sidebar.

    Explorer profiles are excluded by construction: they have no hunts, and
    asking for the path raises (see
    :func:`test_explorer_profiles_refuse_the_chat_pipeline`).
    """
    chat_profiles = [p for p in PROFILES.values() if p.chat_enabled]
    assert chat_profiles
    for profile in chat_profiles:
        assert profile.hunts_path.exists(), profile.hunts_path


# ---------------------------------------------------------------------------
# Schema description (test 17)
# ---------------------------------------------------------------------------


def test_schema_description_defaults_to_cloudtrail() -> None:
    """Called with no arguments the description must not change."""
    description = get_schema_description()
    assert "Table: cloudtrail_events" in description
    assert "event_time" in description


def test_schema_description_for_suzaku_profile() -> None:
    """Test 17: the Suzaku description names its own table and columns."""
    description = SUZAKU_TIMELINE_PROFILE.schema_description()
    assert "Table: timeline" in description
    assert "cloudtrail_events" not in description
    for column in ("Timestamp", "RuleTitle", "Level", "TechniqueIDs", "AwsRegion"):
        assert column in description


def test_suzaku_profile_columns_match_the_real_fixture() -> None:
    """The LLM must be told about exactly the columns Suzaku really writes."""
    conn = duckdb.connect(str(FIXTURE), read_only=True)
    try:
        actual = [
            name
            for (name,) in conn.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'timeline' ORDER BY ordinal_position"
            ).fetchall()
        ]
    finally:
        conn.close()

    assert get_column_names(SUZAKU_TIMELINE_PROFILE.columns) == actual


# ---------------------------------------------------------------------------
# Filter injection (tests 13-16)
# ---------------------------------------------------------------------------


def test_date_filter_default_profile_is_unchanged() -> None:
    """Test 14: existing callers pass no profile and must see no difference."""
    sql = apply_date_filter(
        "SELECT * FROM cloudtrail_events", date(2024, 1, 1), date(2024, 1, 31)
    )
    assert "_ct_filtered" in sql
    assert "event_time >= TIMESTAMP '2024-01-01 00:00:00'" in sql
    assert "CAST" not in sql


def test_date_filter_for_suzaku_compares_the_typed_timestamp() -> None:
    """Test 13: `Timestamp` is a real TIMESTAMP, so no CAST is needed."""
    sql = apply_filters(
        'SELECT * FROM timeline ORDER BY "Timestamp" DESC',
        profile=SUZAKU_TIMELINE_PROFILE,
        start_date=date(2024, 1, 1),
        end_date=date(2024, 1, 31),
    )
    assert "_sz_filtered" in sql
    assert "\"Timestamp\" >= TIMESTAMP '2024-01-01 00:00:00'" in sql
    assert "\"Timestamp\" <= TIMESTAMP '2024-01-31 23:59:59'" in sql
    assert "CAST" not in sql
    assert "FROM timeline\n" in sql  # the CTE still reads the real table


def test_level_filter_injects_an_in_list() -> None:
    """Test 15a: the severity filter is what makes 1.9 M rows usable."""
    sql = apply_filters(
        "SELECT * FROM timeline",
        profile=SUZAKU_TIMELINE_PROFILE,
        levels=["critical", "high"],
    )
    assert "_sz_filtered" in sql
    assert "\"Level\" IN ('critical', 'high')" in sql


def test_level_and_date_filters_share_one_cte() -> None:
    """Test 15b: two filters must compose, not nest into two CTEs."""
    sql = apply_filters(
        "SELECT * FROM timeline",
        profile=SUZAKU_TIMELINE_PROFILE,
        start_date=date(2024, 1, 1),
        levels=["high"],
    )
    assert sql.count("_sz_filtered AS (") == 1
    assert "AND" in sql


def test_filters_extend_an_existing_with_chain() -> None:
    """A hunt that already uses a CTE must stay valid after injection."""
    sql = apply_filters(
        "WITH ranked AS (SELECT * FROM timeline) SELECT * FROM ranked",
        profile=SUZAKU_TIMELINE_PROFILE,
        levels=["high"],
    )
    assert sql.count("WITH") == 1
    assert "_sz_filtered AS (" in sql


def test_filters_without_arguments_return_sql_unchanged() -> None:
    """No active filter must mean no rewriting at all."""
    original = "SELECT * FROM timeline"
    assert apply_filters(original, profile=SUZAKU_TIMELINE_PROFILE) == original


def test_filters_never_rewrite_a_string_literal() -> None:
    """Test 16: a literal mentioning the table name must survive untouched."""
    sql = apply_filters(
        "SELECT * FROM timeline WHERE RuleTitle = 'timeline tampering'",
        profile=SUZAKU_TIMELINE_PROFILE,
        levels=["high"],
    )
    assert "'timeline tampering'" in sql


def test_level_filter_rejects_unknown_levels() -> None:
    """Only Suzaku's five severities may reach the SQL string."""
    with pytest.raises(ValueError):
        apply_filters(
            "SELECT * FROM timeline",
            profile=SUZAKU_TIMELINE_PROFILE,
            levels=["high'; DROP TABLE timeline; --"],
        )


def test_level_filter_requires_a_level_column() -> None:
    """The CloudTrail table has no severity, so asking for one is a bug."""
    with pytest.raises(ValueError):
        apply_filters(
            "SELECT * FROM cloudtrail_events",
            profile=CLOUDTRAIL_PROFILE,
            levels=["high"],
        )


# ---------------------------------------------------------------------------
# Prompt building (test 18)
# ---------------------------------------------------------------------------


def test_system_prompt_defaults_to_cloudtrail() -> None:
    """Existing callers of build_system_prompt() see no change."""
    from llm import build_system_prompt

    prompt = build_system_prompt()
    assert "cloudtrail_events" in prompt


def test_suzaku_system_prompt_names_the_timeline_table() -> None:
    """Test 18: the Suzaku prompt must not mention the CloudTrail table."""
    from llm import build_system_prompt

    prompt = build_system_prompt(profile=SUZAKU_TIMELINE_PROFILE)
    assert "timeline" in prompt
    assert "cloudtrail_events" not in prompt
    assert '"AwsRegion"' in prompt  # quoting rule is spelled out
    assert "suzaku_level" in prompt  # the ENUM threshold trap is spelled out
    assert "LIMIT" in prompt  # the table is huge; ordering + limit is mandatory


def test_generate_sql_sends_the_profile_system_prompt() -> None:
    """The profile must reach the API call, not just build_system_prompt()."""
    from llm import generate_sql

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content="SELECT 1"))]
    )
    with patch("llm.OpenAI", return_value=mock_client):
        generate_sql(
            "top rules",
            api_key="sk-test",
            model="gpt-5.4",
            profile=SUZAKU_TIMELINE_PROFILE,
        )

    messages = mock_client.chat.completions.create.call_args.kwargs["messages"]
    assert "timeline" in messages[0]["content"]
    assert "cloudtrail_events" not in messages[0]["content"]


def test_fix_sql_names_the_profile_table() -> None:
    """A correction request for the wrong table would send the LLM astray."""
    from llm import fix_sql_with_llm

    mock_client = MagicMock()
    mock_client.chat.completions.create.return_value = MagicMock(
        choices=[MagicMock(message=MagicMock(content="SELECT 1"))]
    )
    with patch("llm.OpenAI", return_value=mock_client):
        fix_sql_with_llm(
            "SELCT 1",
            "syntax error",
            api_key="sk-test",
            model="gpt-5.4",
            profile=SUZAKU_TIMELINE_PROFILE,
        )

    messages = mock_client.chat.completions.create.call_args.kwargs["messages"]
    assert "timeline" in messages[1]["content"]


def test_profile_is_frozen() -> None:
    """Profiles are module-level singletons; mutating one would leak globally."""
    with pytest.raises(Exception):
        SUZAKU_TIMELINE_PROFILE.table = "other"  # type: ignore[misc]


def test_dataset_profile_is_constructible_for_tests() -> None:
    """A profile must be usable standalone so future datasets need no plumbing."""
    profile = DatasetProfile(
        key="tmp",
        label="Temp",
        icon="🧪",
        table="t",
        time_column="ts",
        columns=(),
        hunts_filename="builtin_hunts.yaml",
    )
    assert profile.filter_alias == "_tmp_filtered"
    assert profile.state_key("messages") == "tmp_messages"
