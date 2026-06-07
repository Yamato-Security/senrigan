"""OpenAI API integration for SQL generation and result analysis.

Generates DuckDB SQL from natural language queries and produces
Markdown analysis of query results using the OpenAI chat API.
"""

import logging
import os
import re
import time

import httpx
import pandas as pd
from openai import OpenAI, OpenAIError

from prompts.analysis_prompt import ANALYSIS_SYSTEM_PROMPT, ANALYSIS_USER_TEMPLATE
from prompts.system_prompt import SYSTEM_PROMPT
from schema import get_schema_description

logger = logging.getLogger(__name__)

# Maximum number of prior conversation turns to inject into the SQL generation prompt.
MAX_CONTEXT_TURNS: int = 5

# Retry configuration for transient OpenAI API errors.
MAX_RETRIES: int = 2
_RETRY_BASE_DELAY: float = 1.0  # seconds; doubled on each subsequent attempt

# Models that do not support a custom temperature value (only the API default is accepted).
_NO_TEMPERATURE_MODELS: frozenset[str] = frozenset({"gpt-5.5"})

# Module-level OpenAI client cache keyed by api_key.
# Avoids creating a new httpx connection pool on every LLM call within a
# single Streamlit request (generate_sql → fix_sql_with_llm → generate_analysis).
_client_cache: dict[str, OpenAI] = {}


def _supports_temperature(model: str) -> bool:
    """Return True when *model* accepts a custom temperature parameter.

    Some newer models (e.g. gpt-5.5) only accept the API default and reject
    any explicit temperature value, including 0.
    """
    return model not in _NO_TEMPERATURE_MODELS


def _is_retryable(exc: OpenAIError) -> bool:
    """Return True when *exc* represents a transient failure worth retrying.

    Retryable conditions:
    - HTTP 429 (rate limit)
    - HTTP 5xx (server-side error)
    - No status_code attribute (network/connection-level failure such as DNS
      resolution failure, TCP reset, or read timeout)
    """
    status = getattr(exc, "status_code", None)
    if status is None:
        return True
    return status == 429 or status >= 500


def _user_facing_error(exc: OpenAIError) -> str:
    """Return a concise, user-friendly error string for *exc*.

    Maps HTTP status codes to actionable messages so analysts see something
    more helpful than a raw exception repr in the chat area.
    """
    status = getattr(exc, "status_code", None)
    if status == 400:
        return f"[error] Invalid request: {exc}"
    if status == 401:
        return "[error] Authentication failed — verify your API key in the sidebar."
    if status == 403:
        return "[error] Permission denied — your API key may lack access to this model."
    if status == 404:
        return "[error] Model not found — verify the selected model name is correct."
    if status == 429:
        return "[error] Rate limit exceeded — please wait a moment and try again."
    if status is not None and status >= 500:
        return "[error] OpenAI service error — please try again later."
    # No status code: network / connection-level failure.
    return f"[error] Connection error — {exc}"


def _call_with_retry(client: OpenAI, context: str, **create_kwargs) -> str:
    """Call ``client.chat.completions.create`` with exponential-backoff retries.

    Retries up to MAX_RETRIES times for transient errors (429, 5xx, or no
    status code).  Non-retryable errors (4xx other than 429) are re-raised
    immediately so the caller can convert them to user-facing messages.

    Args:
        client:          The OpenAI client instance.
        context:         Short label for log messages (e.g. "SQL generation").
        **create_kwargs: Arguments forwarded verbatim to ``create()``.

    Returns:
        The message content string from the API response.

    Raises:
        OpenAIError: On non-retryable errors or after exhausting all retries.
    """
    last_exc: OpenAIError | None = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            response = client.chat.completions.create(**create_kwargs)
            return response.choices[0].message.content or ""
        except OpenAIError as exc:
            if not _is_retryable(exc) or attempt >= MAX_RETRIES:
                raise
            last_exc = exc
            delay = _RETRY_BASE_DELAY * (2**attempt)
            logger.warning(
                "Transient OpenAI error during %s (attempt %d/%d), retrying in %.1fs: %s",
                context,
                attempt + 1,
                MAX_RETRIES + 1,
                delay,
                exc,
            )
            time.sleep(delay)
    # Unreachable; satisfies type checker.
    assert last_exc is not None
    raise last_exc


def _clear_client_cache() -> None:
    """Clear the module-level OpenAI client cache.

    Intended for use in tests only.  Calling this between tests prevents a
    cached mock client from leaking into subsequent test cases.
    """
    _client_cache.clear()


def build_system_prompt() -> str:
    """Build the system prompt including the CloudTrail schema description.

    Returns:
        A formatted system prompt string that instructs the LLM to generate
        DuckDB-compatible SQL for the cloudtrail_events table.
    """
    return SYSTEM_PROMPT.format(schema=get_schema_description())


def _strip_markdown_fences(text: str) -> str:
    """Remove ```sql ... ``` or ``` ... ``` wrappers from LLM output.

    Args:
        text: Raw text returned by the LLM.

    Returns:
        The text with Markdown code fences removed.
    """
    text = re.sub(r"^```(?:sql)?\s*\n?", "", text.strip(), flags=re.IGNORECASE)
    text = re.sub(r"\n?```\s*$", "", text.strip())
    return text.strip()


def _create_client(api_key: str) -> OpenAI:
    """Return a cached OpenAI client for *api_key*, creating one if necessary.

    Caching avoids opening a new httpx connection pool on every LLM call.
    The cache is keyed solely on *api_key*; the CA bundle (if any) is baked
    in at first-creation time and stable for the lifetime of the process.

    When running behind a corporate proxy that performs TLS inspection,
    set the ``SSL_CERT_FILE`` or ``REQUESTS_CA_BUNDLE`` environment
    variable to point to a CA bundle that includes the proxy's root CA.
    """
    if api_key not in _client_cache:
        ca_bundle = os.environ.get("SSL_CERT_FILE") or os.environ.get(
            "REQUESTS_CA_BUNDLE"
        )
        if ca_bundle:
            http_client = httpx.Client(verify=False)
            _client_cache[api_key] = OpenAI(api_key=api_key, http_client=http_client)
        else:
            _client_cache[api_key] = OpenAI(api_key=api_key)
    return _client_cache[api_key]


def _build_context_messages(context: list[dict], max_turns: int) -> list[dict]:
    """Convert conversation context entries to OpenAI message pairs.

    Takes the most recent *max_turns* entries from *context* and formats
    each as a user/assistant message pair so the LLM understands prior
    exchanges when generating the next SQL query.

    Args:
        context:   List of dicts with 'user_query', 'sql', and 'summary' keys.
        max_turns: Maximum number of prior turns to include.

    Returns:
        A flat list of OpenAI message dicts (role + content), alternating
        user and assistant entries.
    """
    recent = context[-max_turns:] if len(context) > max_turns else context
    messages: list[dict] = []
    for turn in recent:
        messages.append({"role": "user", "content": turn.get("user_query", "")})
        sql_text = turn.get("sql", "")
        summary_text = turn.get("summary", "(no summary)") or "(no summary)"
        messages.append(
            {
                "role": "assistant",
                "content": f"```sql\n{sql_text}\n```\n\n{summary_text}",
            }
        )
    return messages


def generate_sql(
    user_query: str,
    api_key: str,
    model: str = "gpt-5.5",
    context: list[dict] | None = None,
) -> str:
    """Generate a DuckDB SQL query from a natural language question.

    Args:
        user_query: The natural language threat hunting question.
        api_key:    OpenAI API key.
        model:      Model name to use for generation (default: gpt-5.5).
        context:    Optional list of prior conversation turns. Each entry
                    must contain 'user_query', 'sql', and 'summary' keys.
                    When provided, the most recent MAX_CONTEXT_TURNS entries
                    are injected as user/assistant message pairs before the
                    current query, enabling follow-up questions.

    Returns:
        A DuckDB SQL string. On API error, returns a user-friendly error message.
    """
    client = _create_client(api_key)
    messages: list[dict] = [{"role": "system", "content": build_system_prompt()}]
    if context:
        messages.extend(_build_context_messages(context, MAX_CONTEXT_TURNS))
    messages.append({"role": "user", "content": user_query})
    kwargs: dict = {"model": model, "messages": messages}
    if _supports_temperature(model):
        kwargs["temperature"] = 0
    try:
        raw = _call_with_retry(client, "SQL generation", **kwargs)
        return _strip_markdown_fences(raw)
    except OpenAIError as exc:
        logger.error("OpenAI API error during SQL generation: %s", exc)
        return _user_facing_error(exc)


def fix_sql_with_llm(
    broken_sql: str,
    error_message: str,
    api_key: str,
    model: str = "gpt-5.5",
) -> str:
    """Attempt to fix a SQL query that failed validation using the LLM.

    Sends the broken SQL along with the validation error message to the LLM
    and asks it to return a corrected DuckDB-compatible SQL string.

    Args:
        broken_sql:    The SQL query that failed validation.
        error_message: The error message produced by the validation failure.
        api_key:       OpenAI API key.
        model:         Model name to use (default: gpt-5.5).

    Returns:
        A corrected DuckDB SQL string. On API error, returns a string
        starting with '[error]'.
    """
    client = _create_client(api_key)
    user_message = (
        f"The following SQL query failed validation:\n\n"
        f"```sql\n{broken_sql}\n```\n\n"
        f"Error: {error_message}\n\n"
        f"Please fix the SQL so it is valid DuckDB SQL for the cloudtrail_events table. "
        f"Return only the corrected SQL, with no explanation."
    )
    messages = [
        {"role": "system", "content": build_system_prompt()},
        {"role": "user", "content": user_message},
    ]
    kwargs: dict = {"model": model, "messages": messages}
    if _supports_temperature(model):
        kwargs["temperature"] = 0
    try:
        raw = _call_with_retry(client, "SQL fix", **kwargs)
        return _strip_markdown_fences(raw)
    except OpenAIError as exc:
        logger.error("OpenAI API error during SQL fix: %s", exc)
        return _user_facing_error(exc)


def generate_analysis(
    sql: str,
    results: pd.DataFrame,
    api_key: str,
    model: str = "gpt-5.5",
) -> str:
    """Generate a fact-based summary for SQL query results.

    Serialises up to 50 rows of the DataFrame as a Markdown table and asks
    the LLM to list only observed facts — counts, top values, and anomalies
    present in the data. Speculative threat assessments are explicitly excluded.

    Args:
        sql:     The SQL query that produced the results.
        results: The query result as a pandas DataFrame.
        api_key: OpenAI API key.
        model:   Model name to use (default: gpt-5.5).

    Returns:
        Markdown bullet-point summary. On API error, returns a user-friendly
        error message.
    """
    sample = (
        results.head(50).to_markdown(index=False)
        if not results.empty
        else "(no results)"
    )
    user_message = ANALYSIS_USER_TEMPLATE.format(sql=sql, results=sample)
    client = _create_client(api_key)
    messages = [
        {"role": "system", "content": ANALYSIS_SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ]
    kwargs: dict = {"model": model, "messages": messages}
    if _supports_temperature(model):
        kwargs["temperature"] = 0
    try:
        return _call_with_retry(client, "analysis", **kwargs)
    except OpenAIError as exc:
        logger.error("OpenAI API error during analysis: %s", exc)
        return _user_facing_error(exc)
