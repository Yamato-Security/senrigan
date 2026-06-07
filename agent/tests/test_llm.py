"""Tests for llm.py — OpenAI API integration for SQL generation and analysis."""

import openai
import pandas as pd
from unittest.mock import MagicMock, patch

from llm import (
    MAX_CONTEXT_TURNS,
    MAX_RETRIES,
    _clear_client_cache,
    _create_client,
    _is_retryable,
    _supports_temperature,
    _user_facing_error,
    build_system_prompt,
    fix_sql_with_llm,
    generate_analysis,
    generate_sql,
)
from prompts.analysis_prompt import ANALYSIS_SYSTEM_PROMPT


def _exc(status_code: int | None = None, msg: str = "test error") -> openai.OpenAIError:
    """Create an OpenAIError with an optional status_code attribute."""
    exc = openai.OpenAIError(msg)
    if status_code is not None:
        exc.status_code = status_code
    return exc


# ---------------------------------------------------------------------------
# Client caching
# ---------------------------------------------------------------------------


def test_create_client_reuses_same_instance():
    """_create_client returns the identical object for the same api_key (cache hit)."""
    _clear_client_cache()
    with patch("llm.OpenAI") as mock_cls:
        mock_cls.return_value = MagicMock()
        client_a = _create_client("sk-cache-test")
        client_b = _create_client("sk-cache-test")

    assert client_a is client_b, "Expected the same cached instance"
    assert mock_cls.call_count == 1, "OpenAI constructor must be called only once"


def test_create_client_creates_new_instance_for_different_key():
    """_create_client creates a separate instance per unique api_key."""
    _clear_client_cache()
    with patch("llm.OpenAI") as mock_cls:
        mock_cls.side_effect = [MagicMock(), MagicMock()]
        client_a = _create_client("sk-key-1")
        client_b = _create_client("sk-key-2")

    assert client_a is not client_b
    assert mock_cls.call_count == 2


def test_build_system_prompt_includes_schema():
    """The system prompt includes the CloudTrail table schema."""
    prompt = build_system_prompt()

    assert "cloudtrail_events" in prompt
    assert "event_time" in prompt
    assert "event_name" in prompt


def test_build_system_prompt_includes_duckdb_dialect():
    """The system prompt specifies DuckDB SQL dialect."""
    prompt = build_system_prompt()

    assert "DuckDB" in prompt


def test_supports_temperature_returns_false_for_gpt55():
    """_supports_temperature() must return False for gpt-5.5."""
    assert _supports_temperature("gpt-5.5") is False


def test_supports_temperature_returns_true_for_gpt54():
    """_supports_temperature() must return True for gpt-5.4."""
    assert _supports_temperature("gpt-5.4") is True


def test_supports_temperature_returns_true_for_gpt54_mini():
    """_supports_temperature() must return True for gpt-5.4-mini."""
    assert _supports_temperature("gpt-5.4-mini") is True


def test_generate_sql_gpt55_omits_temperature(mock_openai_client):
    """generate_sql() must not pass temperature for gpt-5.5."""
    generate_sql("Show me all events", api_key="sk-test", model="gpt-5.5")

    call_kwargs = mock_openai_client.chat.completions.create.call_args.kwargs
    assert "temperature" not in call_kwargs


def test_generate_sql_gpt54_passes_temperature_zero(mock_openai_client):
    """generate_sql() must pass temperature=0 for models that support it."""
    generate_sql("Show me all events", api_key="sk-test", model="gpt-5.4")

    call_kwargs = mock_openai_client.chat.completions.create.call_args.kwargs
    assert call_kwargs.get("temperature") == 0


def test_fix_sql_gpt55_omits_temperature(mock_openai_client):
    """fix_sql_with_llm() must not pass temperature for gpt-5.5."""
    fix_sql_with_llm(
        broken_sql="bad sql", error_message="err", api_key="sk-test", model="gpt-5.5"
    )

    call_kwargs = mock_openai_client.chat.completions.create.call_args.kwargs
    assert "temperature" not in call_kwargs


def test_fix_sql_gpt54_passes_temperature_zero(mock_openai_client):
    """fix_sql_with_llm() must pass temperature=0 for models that support it."""
    fix_sql_with_llm(
        broken_sql="bad sql", error_message="err", api_key="sk-test", model="gpt-5.4"
    )

    call_kwargs = mock_openai_client.chat.completions.create.call_args.kwargs
    assert call_kwargs.get("temperature") == 0


def test_generate_analysis_gpt55_omits_temperature(mock_openai_client):
    """generate_analysis() must not pass temperature for gpt-5.5."""
    df = pd.DataFrame({"event_name": ["CreateUser"], "cnt": [1]})
    generate_analysis(sql="SELECT 1", results=df, api_key="sk-test", model="gpt-5.5")

    call_kwargs = mock_openai_client.chat.completions.create.call_args.kwargs
    assert "temperature" not in call_kwargs


def test_generate_analysis_gpt54_passes_temperature_zero(mock_openai_client):
    """generate_analysis() must pass temperature=0 for models that support it."""
    df = pd.DataFrame({"event_name": ["CreateUser"], "cnt": [1]})
    generate_analysis(sql="SELECT 1", results=df, api_key="sk-test", model="gpt-5.4")

    call_kwargs = mock_openai_client.chat.completions.create.call_args.kwargs
    assert call_kwargs.get("temperature") == 0


def test_generate_sql_default_model_is_gpt_5_5(mock_openai_client):
    """generate_sql() must use gpt-5.5 as the default model."""
    generate_sql("Show me all events", api_key="sk-test")

    call_kwargs = mock_openai_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["model"] == "gpt-5.5"


def test_fix_sql_default_model_is_gpt_5_5(mock_openai_client):
    """fix_sql_with_llm() must use gpt-5.5 as the default model."""
    fix_sql_with_llm(
        broken_sql="bad sql",
        error_message="syntax error",
        api_key="sk-test",
    )

    call_kwargs = mock_openai_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["model"] == "gpt-5.5"


def test_generate_analysis_default_model_is_gpt_5_5(mock_openai_client):
    """generate_analysis() must use gpt-5.5 as the default model."""
    df = pd.DataFrame({"event_name": ["CreateUser"], "cnt": [1]})
    generate_analysis(
        sql="SELECT event_name, COUNT(*) AS cnt FROM cloudtrail_events GROUP BY event_name",
        results=df,
        api_key="sk-test",
    )

    call_kwargs = mock_openai_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["model"] == "gpt-5.5"


def test_generate_sql_returns_sql_string(mock_openai_client):
    """Given a mocked OpenAI response, generate_sql() returns a SQL string."""
    sql = generate_sql("Show me all CreateUser events", api_key="sk-test")

    assert isinstance(sql, str)
    assert "SELECT" in sql.upper()
    assert "cloudtrail_events" in sql


def test_generate_sql_strips_markdown_fences(mock_openai_client):
    """If the LLM wraps SQL in ```sql ... ```, the fences are stripped."""
    mock_openai_client.chat.completions.create.return_value.choices[
        0
    ].message.content = "```sql\nSELECT event_name FROM cloudtrail_events LIMIT 10\n```"

    sql = generate_sql("List events", api_key="sk-test")

    assert not sql.startswith("```")
    assert not sql.endswith("```")
    assert "SELECT" in sql.upper()


def test_generate_analysis_returns_markdown(mock_openai_client):
    """Given query results, generate_analysis() returns Markdown analysis text."""
    mock_openai_client.chat.completions.create.return_value.choices[
        0
    ].message.content = "## Analysis\n\nFound 3 events."

    df = pd.DataFrame(
        {
            "event_name": ["DescribeInstances", "DescribeInstances", "CreateUser"],
            "cnt": [2, 2, 1],
        }
    )
    result = generate_analysis(
        sql="SELECT event_name, COUNT(*) as cnt FROM cloudtrail_events GROUP BY event_name",
        results=df,
        api_key="sk-test",
    )

    assert isinstance(result, str)
    assert len(result) > 0


def test_generate_analysis_uses_analysis_system_prompt(mock_openai_client):
    """generate_analysis() must use ANALYSIS_SYSTEM_PROMPT, not the SQL generation prompt."""
    df = pd.DataFrame({"event_name": ["CreateUser"], "cnt": [1]})
    generate_analysis(
        sql="SELECT event_name, COUNT(*) AS cnt FROM cloudtrail_events GROUP BY event_name",
        results=df,
        api_key="sk-test",
    )

    call_kwargs = mock_openai_client.chat.completions.create.call_args.kwargs
    messages = call_kwargs["messages"]
    system_content = messages[0]["content"]

    # Must use the dedicated analysis prompt, not the SQL generation prompt
    assert system_content == ANALYSIS_SYSTEM_PROMPT


def test_generate_analysis_user_message_contains_sql(mock_openai_client):
    """generate_analysis() user message must embed the executed SQL query."""
    sql = "SELECT event_name FROM cloudtrail_events LIMIT 5"
    df = pd.DataFrame({"event_name": ["ConsoleLogin"]})
    generate_analysis(sql=sql, results=df, api_key="sk-test")

    call_kwargs = mock_openai_client.chat.completions.create.call_args.kwargs
    messages = call_kwargs["messages"]
    user_content = messages[1]["content"]

    assert sql in user_content


def test_generate_sql_handles_api_error(mock_openai_client):
    """OpenAI API errors are caught and surfaced as user-friendly messages."""
    mock_openai_client.chat.completions.create.side_effect = openai.OpenAIError(
        "connection error"
    )

    with patch("llm.time.sleep"):
        result = generate_sql("Show me all events", api_key="sk-test")

    assert isinstance(result, str)
    assert "error" in result.lower()


# ---------------------------------------------------------------------------
# Proposal 1 — conversation context injection
# ---------------------------------------------------------------------------


def test_generate_sql_with_context_injects_messages(mock_openai_client):
    """generate_sql() injects context entries as user/assistant message pairs."""
    context = [
        {
            "user_query": "Show me root events",
            "sql": "SELECT * FROM cloudtrail_events WHERE user_identity_type = 'Root'",
            "summary": "3 root events found",
        }
    ]

    generate_sql("Drill down further", api_key="sk-test", context=context)

    call_kwargs = mock_openai_client.chat.completions.create.call_args.kwargs
    messages = call_kwargs["messages"]
    # system + user(context) + assistant(context) + user(new query)
    assert len(messages) == 4
    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    assert messages[1]["content"] == "Show me root events"
    assert messages[2]["role"] == "assistant"
    assert messages[3]["role"] == "user"
    assert messages[3]["content"] == "Drill down further"


def test_generate_sql_context_none_is_backward_compatible(mock_openai_client):
    """generate_sql() with context=None sends exactly system + user messages."""
    generate_sql("Show me all events", api_key="sk-test", context=None)

    call_kwargs = mock_openai_client.chat.completions.create.call_args.kwargs
    messages = call_kwargs["messages"]
    assert len(messages) == 2
    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    assert messages[1]["content"] == "Show me all events"


def test_generate_sql_context_max_items_truncated(mock_openai_client):
    """generate_sql() only includes the last MAX_CONTEXT_TURNS context entries."""
    context = [
        {"user_query": f"Query {i}", "sql": f"SELECT {i}", "summary": f"Summary {i}"}
        for i in range(MAX_CONTEXT_TURNS + 3)  # 3 extra entries beyond the limit
    ]

    generate_sql("Latest query", api_key="sk-test", context=context)

    call_kwargs = mock_openai_client.chat.completions.create.call_args.kwargs
    messages = call_kwargs["messages"]
    # Expected: 1 system + 2 * MAX_CONTEXT_TURNS (user+assistant pairs) + 1 user
    expected_count = 1 + 2 * MAX_CONTEXT_TURNS + 1
    assert len(messages) == expected_count
    # The oldest entries should have been excluded
    message_contents = " ".join(m["content"] for m in messages)
    assert "Query 0" not in message_contents


# ---------------------------------------------------------------------------
# Proposal 2 — fix_sql_with_llm
# ---------------------------------------------------------------------------


def test_fix_sql_with_llm_returns_corrected_sql(mock_openai_client):
    """fix_sql_with_llm() returns the corrected SQL string from the LLM."""
    mock_openai_client.chat.completions.create.return_value.choices[
        0
    ].message.content = "SELECT event_name FROM cloudtrail_events LIMIT 10"

    result = fix_sql_with_llm(
        broken_sql="SELECT * FROM wrong_table",
        error_message="Table 'wrong_table' does not exist",
        api_key="sk-test",
        model="gpt-5.4",
    )

    assert "SELECT" in result.upper()
    assert "cloudtrail_events" in result


def test_fix_sql_with_llm_strips_markdown_fences(mock_openai_client):
    """fix_sql_with_llm() strips ```sql ... ``` wrappers from the LLM response."""
    mock_openai_client.chat.completions.create.return_value.choices[
        0
    ].message.content = "```sql\nSELECT event_name FROM cloudtrail_events LIMIT 10\n```"

    result = fix_sql_with_llm(
        broken_sql="bad sql",
        error_message="syntax error",
        api_key="sk-test",
    )

    assert not result.startswith("```")
    assert not result.endswith("```")


def test_fix_sql_with_llm_handles_api_error(mock_openai_client):
    """fix_sql_with_llm() returns an [error] string when the OpenAI API fails."""
    mock_openai_client.chat.completions.create.side_effect = openai.OpenAIError(
        "API down"
    )

    with patch("llm.time.sleep"):
        result = fix_sql_with_llm(
            broken_sql="bad sql",
            error_message="syntax error",
            api_key="sk-test",
        )

    assert result.startswith("[error]")


# ---------------------------------------------------------------------------
# _is_retryable
# ---------------------------------------------------------------------------


def test_is_retryable_rate_limit():
    """status_code 429 must be retryable."""
    assert _is_retryable(_exc(429)) is True


def test_is_retryable_server_error_500():
    """status_code 500 must be retryable."""
    assert _is_retryable(_exc(500)) is True


def test_is_retryable_server_error_503():
    """status_code 503 must be retryable."""
    assert _is_retryable(_exc(503)) is True


def test_is_retryable_no_status_code():
    """Errors without status_code (network/connection) must be retryable."""
    assert _is_retryable(_exc(None)) is True


def test_is_retryable_auth_error_not_retryable():
    """status_code 401 must NOT be retryable."""
    assert _is_retryable(_exc(401)) is False


def test_is_retryable_bad_request_not_retryable():
    """status_code 400 must NOT be retryable."""
    assert _is_retryable(_exc(400)) is False


def test_is_retryable_not_found_not_retryable():
    """status_code 404 must NOT be retryable."""
    assert _is_retryable(_exc(404)) is False


def test_is_retryable_permission_denied_not_retryable():
    """status_code 403 must NOT be retryable."""
    assert _is_retryable(_exc(403)) is False


# ---------------------------------------------------------------------------
# _user_facing_error
# ---------------------------------------------------------------------------


def test_user_facing_error_auth():
    """status_code 401 must produce an authentication error message."""
    msg = _user_facing_error(_exc(401))
    assert msg.startswith("[error]")
    assert "key" in msg.lower() or "auth" in msg.lower()


def test_user_facing_error_permission():
    """status_code 403 must produce a permission-denied error message."""
    msg = _user_facing_error(_exc(403))
    assert msg.startswith("[error]")
    assert "permission" in msg.lower() or "denied" in msg.lower()


def test_user_facing_error_not_found():
    """status_code 404 must mention model not found."""
    msg = _user_facing_error(_exc(404))
    assert msg.startswith("[error]")
    assert "model" in msg.lower() or "not found" in msg.lower()


def test_user_facing_error_rate_limit():
    """status_code 429 must produce a rate-limit message."""
    msg = _user_facing_error(_exc(429))
    assert msg.startswith("[error]")
    assert "rate" in msg.lower() or "limit" in msg.lower()


def test_user_facing_error_bad_request():
    """status_code 400 must include the original exception text."""
    exc = _exc(400, msg="temperature not supported")
    msg = _user_facing_error(exc)
    assert msg.startswith("[error]")
    assert "temperature not supported" in msg


def test_user_facing_error_server_error():
    """status_code 500 must produce a service-error message."""
    msg = _user_facing_error(_exc(500))
    assert msg.startswith("[error]")
    assert "service" in msg.lower() or "server" in msg.lower()


def test_user_facing_error_no_status_connection():
    """Errors without status_code must produce a connection-error message."""
    msg = _user_facing_error(_exc(None, msg="name resolution failed"))
    assert msg.startswith("[error]")
    assert "connection" in msg.lower() or "network" in msg.lower()


# ---------------------------------------------------------------------------
# Retry behaviour
# ---------------------------------------------------------------------------


def test_generate_sql_retries_on_rate_limit_then_succeeds(mock_openai_client):
    """generate_sql() must retry on 429 and return the result on success."""
    rate_exc = _exc(429)
    success = MagicMock()
    success.choices[0].message.content = "SELECT 1 FROM cloudtrail_events"
    mock_openai_client.chat.completions.create.side_effect = [rate_exc, success]

    with patch("llm.time.sleep") as mock_sleep:
        result = generate_sql("test query", api_key="sk-test")

    assert "SELECT" in result.upper()
    mock_sleep.assert_called_once_with(1.0)


def test_generate_sql_no_retry_on_auth_error(mock_openai_client):
    """generate_sql() must NOT retry on 401 — only one API call must be made."""
    mock_openai_client.chat.completions.create.side_effect = _exc(401)

    with patch("llm.time.sleep") as mock_sleep:
        result = generate_sql("test query", api_key="sk-bad-key")

    assert result.startswith("[error]")
    mock_sleep.assert_not_called()
    assert mock_openai_client.chat.completions.create.call_count == 1


def test_generate_sql_exhausted_retries_returns_error(mock_openai_client):
    """generate_sql() must return an error string after exhausting all retries."""
    mock_openai_client.chat.completions.create.side_effect = _exc(429)

    with patch("llm.time.sleep") as mock_sleep:
        result = generate_sql("test query", api_key="sk-test")

    assert result.startswith("[error]")
    assert mock_openai_client.chat.completions.create.call_count == MAX_RETRIES + 1
    assert mock_sleep.call_count == MAX_RETRIES


def test_generate_sql_retry_uses_exponential_backoff(mock_openai_client):
    """generate_sql() retry delays must follow exponential backoff (1s, 2s, …)."""
    mock_openai_client.chat.completions.create.side_effect = _exc(500)

    with patch("llm.time.sleep") as mock_sleep:
        generate_sql("test query", api_key="sk-test")

    delays = [call.args[0] for call in mock_sleep.call_args_list]
    assert delays == [1.0 * (2**i) for i in range(MAX_RETRIES)]


def test_fix_sql_retries_on_connection_error(mock_openai_client):
    """fix_sql_with_llm() must retry on connection errors (no status_code)."""
    conn_exc = _exc(None, msg="connection reset")
    success = MagicMock()
    success.choices[0].message.content = "SELECT event_name FROM cloudtrail_events"
    mock_openai_client.chat.completions.create.side_effect = [conn_exc, success]

    with patch("llm.time.sleep") as mock_sleep:
        result = fix_sql_with_llm("bad sql", "error", api_key="sk-test")

    assert "SELECT" in result.upper()
    mock_sleep.assert_called_once_with(1.0)


def test_generate_analysis_retries_on_server_error(mock_openai_client):
    """generate_analysis() must retry on 500 server errors."""
    server_exc = _exc(500)
    success = MagicMock()
    success.choices[0].message.content = "## Analysis"
    mock_openai_client.chat.completions.create.side_effect = [server_exc, success]
    df = pd.DataFrame({"event_name": ["CreateUser"]})

    with patch("llm.time.sleep") as mock_sleep:
        result = generate_analysis("SELECT 1", df, api_key="sk-test")

    assert "Analysis" in result
    mock_sleep.assert_called_once_with(1.0)
