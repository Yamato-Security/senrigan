"""Tests for prompt templates — system_prompt.py and analysis_prompt.py."""

from prompts.analysis_prompt import ANALYSIS_SYSTEM_PROMPT, ANALYSIS_USER_TEMPLATE
from prompts.system_prompt import SYSTEM_PROMPT

# ---------------------------------------------------------------------------
# SYSTEM_PROMPT (SQL generation)
# ---------------------------------------------------------------------------


def test_system_prompt_is_nonempty():
    """SYSTEM_PROMPT must be a non-empty string."""
    assert isinstance(SYSTEM_PROMPT, str)
    assert len(SYSTEM_PROMPT.strip()) > 0


def test_system_prompt_contains_schema_placeholder():
    """SYSTEM_PROMPT must have a {schema} placeholder for schema injection."""
    assert "{schema}" in SYSTEM_PROMPT


def test_system_prompt_contains_duckdb_rule():
    """SYSTEM_PROMPT must instruct the LLM to use DuckDB-compatible SQL."""
    assert "DuckDB" in SYSTEM_PROMPT


def test_system_prompt_contains_mitre_tactics():
    """SYSTEM_PROMPT must reference MITRE ATT&CK tactics for threat hunting context."""
    assert "MITRE" in SYSTEM_PROMPT


def test_system_prompt_contains_json_extraction_guidance():
    """SYSTEM_PROMPT must provide JSON extraction idioms for request_parameters."""
    assert "json_extract_string" in SYSTEM_PROMPT


def test_system_prompt_contains_statistical_function_guidance():
    """SYSTEM_PROMPT must guide the LLM to use statistical/aggregation functions."""
    assert "DATE_TRUNC" in SYSTEM_PROMPT
    assert "COUNT" in SYSTEM_PROMPT


def test_system_prompt_contains_no_write_rule():
    """SYSTEM_PROMPT must prohibit INSERT, UPDATE, DELETE, DROP statements."""
    upper = SYSTEM_PROMPT.upper()
    for keyword in ("INSERT", "UPDATE", "DELETE", "DROP"):
        assert keyword in upper, f"Expected '{keyword}' prohibition in SYSTEM_PROMPT"


# ---------------------------------------------------------------------------
# ANALYSIS_SYSTEM_PROMPT
# ---------------------------------------------------------------------------


def test_analysis_system_prompt_is_nonempty():
    """ANALYSIS_SYSTEM_PROMPT must be a non-empty string."""
    assert isinstance(ANALYSIS_SYSTEM_PROMPT, str)
    assert len(ANALYSIS_SYSTEM_PROMPT.strip()) > 0


def test_analysis_system_prompt_contains_findings_section():
    """ANALYSIS_SYSTEM_PROMPT must surface notable findings from the data."""
    lower = ANALYSIS_SYSTEM_PROMPT.lower()
    assert (
        "findings" in lower
        or "observations" in lower
        or "observed" in lower
        or "notable" in lower
    )


def test_analysis_system_prompt_contains_statistical_context_guidance():
    """ANALYSIS_SYSTEM_PROMPT must instruct the LLM to summarise data shape."""
    lower = ANALYSIS_SYSTEM_PROMPT.lower()
    assert (
        "statistic" in lower
        or "baseline" in lower
        or "summary" in lower
        or "count" in lower
        or "total" in lower
    )


def test_analysis_system_prompt_contains_api_explanation_guidance():
    """ANALYSIS_SYSTEM_PROMPT must instruct the LLM to explain what each AWS API does."""
    lower = ANALYSIS_SYSTEM_PROMPT.lower()
    assert "api" in lower or "event_name" in lower


def test_analysis_system_prompt_no_speculation_rule():
    """ANALYSIS_SYSTEM_PROMPT must prohibit speculation and threat assessments."""
    lower = ANALYSIS_SYSTEM_PROMPT.lower()
    assert "speculate" in lower or "speculation" in lower or "do not speculate" in lower


def test_analysis_system_prompt_fact_based_rule():
    """ANALYSIS_SYSTEM_PROMPT must require fact-based, evidence-backed findings."""
    lower = ANALYSIS_SYSTEM_PROMPT.lower()
    assert "fact" in lower or "evidence" in lower or "observed" in lower


# ---------------------------------------------------------------------------
# ANALYSIS_USER_TEMPLATE
# ---------------------------------------------------------------------------


def test_analysis_user_template_is_nonempty():
    """ANALYSIS_USER_TEMPLATE must be a non-empty string."""
    assert isinstance(ANALYSIS_USER_TEMPLATE, str)
    assert len(ANALYSIS_USER_TEMPLATE.strip()) > 0


def test_analysis_user_template_has_sql_placeholder():
    """ANALYSIS_USER_TEMPLATE must contain a {sql} placeholder."""
    assert "{sql}" in ANALYSIS_USER_TEMPLATE


def test_analysis_user_template_has_results_placeholder():
    """ANALYSIS_USER_TEMPLATE must contain a {results} placeholder."""
    assert "{results}" in ANALYSIS_USER_TEMPLATE


def test_analysis_user_template_renders_correctly():
    """ANALYSIS_USER_TEMPLATE must be renderable with sql and results values."""
    rendered = ANALYSIS_USER_TEMPLATE.format(
        sql="SELECT event_name FROM cloudtrail_events LIMIT 5",
        results="| event_name |\n| CreateUser |",
    )
    assert "SELECT event_name" in rendered
    assert "CreateUser" in rendered


# ---------------------------------------------------------------------------
# Structure sections
# ---------------------------------------------------------------------------


def test_analysis_system_prompt_contains_summary_section():
    """ANALYSIS_SYSTEM_PROMPT must include a Summary section."""
    assert "Summary" in ANALYSIS_SYSTEM_PROMPT


def test_analysis_system_prompt_contains_api_overview_section():
    """ANALYSIS_SYSTEM_PROMPT must include an API Overview section for non-experts."""
    assert "API Overview" in ANALYSIS_SYSTEM_PROMPT


def test_analysis_system_prompt_contains_legitimate_use_guidance():
    """ANALYSIS_SYSTEM_PROMPT must remind the LLM to note typical legitimate usage."""
    lower = ANALYSIS_SYSTEM_PROMPT.lower()
    assert "legitimate" in lower


def test_analysis_system_prompt_contains_observed_in_data_guidance():
    """ANALYSIS_SYSTEM_PROMPT must ask the LLM to surface notable patterns from the data."""
    lower = ANALYSIS_SYSTEM_PROMPT.lower()
    assert "observed" in lower or "pattern" in lower


def test_analysis_user_template_requests_report_sections():
    """ANALYSIS_USER_TEMPLATE must ask for the two defined report sections."""
    assert "Summary" in ANALYSIS_USER_TEMPLATE
    assert "API Overview" in ANALYSIS_USER_TEMPLATE
