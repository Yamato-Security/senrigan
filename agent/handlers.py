"""Business-logic handlers for the Senrigan Streamlit agent.

This module contains the three stateful handler functions that were previously
defined directly in ``app.py``.  Extracting them here:

- Keeps ``app.py`` focused on UI layout and Streamlit wiring.
- Makes handlers independently testable without rendering the full page.
- Ensures all DuckDB connections are guarded by the ``duckdb_connection``
  context manager so they are always closed, even on exception.

All handlers read and write ``st.session_state`` directly — they are designed
to be called from within a running Streamlit application.

Every handler takes a ``profile`` (see ``profiles.py``) that selects the table to
query, the filters to inject, and the session-state namespace to read and write.
It defaults to :data:`~profiles.CLOUDTRAIL_PROFILE`, whose namespace is
un-prefixed, so the CloudTrail hunting page behaves exactly as before.
"""

import logging

import duckdb
import pandas as pd
import streamlit as st

from geo import enrich_with_geo
from llm import MAX_CONTEXT_TURNS, generate_analysis, generate_sql
from profiles import CLOUDTRAIL_PROFILE, DatasetProfile
from query import (
    QueryValidationError,
    apply_filters,
    apply_row_limit,
    duckdb_connection,
    execute_query,
    execute_with_retry,
)
from report import ReportEntry

logger = logging.getLogger(__name__)


def _get(profile: DatasetProfile, name: str, default=None):
    """Read *name* from this profile's session-state namespace."""
    return st.session_state.get(profile.state_key(name), default)


def _set(profile: DatasetProfile, name: str, value) -> None:
    """Write *value* to *name* in this profile's session-state namespace."""
    st.session_state[profile.state_key(name)] = value


def _active_filters(profile: DatasetProfile, sql: str) -> str:
    """Apply the profile's active UI filters (date range, severity) to *sql*."""
    return apply_filters(
        sql,
        profile=profile,
        start_date=_get(profile, "date_start"),
        end_date=_get(profile, "date_end"),
        levels=_get(profile, "levels") or (),
    )


def _format_row_info(
    results: pd.DataFrame, row_limit: int, extended: bool = False
) -> str:
    """Format a row-count summary string for a query result.

    Args:
        results:   The query result DataFrame.
        row_limit: The effective row cap applied to the query.
        extended:  When True, append a hint to add LIMIT for more control.

    Returns:
        A human-readable string such as ``"42 row(s)"`` or
        ``"500 row(s) _(truncated to 500)_"``.
    """
    truncated = len(results) >= row_limit
    suffix = ""
    if truncated:
        if extended:
            suffix = f" _(truncated to {row_limit:,} — add LIMIT to your SQL for more control)_"
        else:
            suffix = f" _(truncated to {row_limit:,})_"
    return f"{len(results)} row(s){suffix}"


def _maybe_enrich_geo(
    conn: duckdb.DuckDBPyConnection,
    results: pd.DataFrame,
    profile: DatasetProfile = CLOUDTRAIL_PROFILE,
) -> pd.DataFrame:
    """Geo-enrich *results* when the sidebar toggle is on.

    Enrichment is best-effort: any failure is logged and the original
    results are returned unchanged — it must never fail the query itself.

    Profiles whose table carries no ``geo_*`` columns (Suzaku's ``timeline``)
    skip enrichment entirely: the lookup joins against ``cloudtrail_events``,
    which is not in that database at all.

    Args:
        conn:    The open DuckDB connection the query ran on.
        results: The query result DataFrame.
        profile: Dataset profile the query ran against.

    Returns:
        The (possibly) enriched DataFrame.
    """
    if not profile.supports_geo_enrich:
        return results
    if not st.session_state.get("geo_enrich", True):
        return results
    try:
        return enrich_with_geo(conn, results)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Geo enrichment failed, returning raw results: %s", exc)
        return results


def _execute_sql_safely(
    db_path: str,
    sql: str,
    row_limit: int,
    profile: DatasetProfile = CLOUDTRAIL_PROFILE,
) -> tuple[pd.DataFrame, str | None]:
    """Execute *sql* read-only, converting known failures to a user message.

    Successful results are geo-enriched via :func:`_maybe_enrich_geo`.

    Args:
        db_path:   Path to the DuckDB database file.
        sql:       The SQL query to execute.
        row_limit: Maximum number of rows to return.
        profile:   Dataset profile the query targets.

    Returns:
        A tuple ``(results, error_message)`` — *error_message* is ``None`` on
        success, otherwise a display-ready string and *results* is empty.
    """
    try:
        with duckdb_connection(db_path) as conn:
            results = execute_query(conn, sql, row_limit=row_limit)
            return _maybe_enrich_geo(conn, results, profile), None
    except QueryValidationError as exc:
        return pd.DataFrame(), f"🚫 SQL validation error: {exc}"
    except TimeoutError:
        return pd.DataFrame(), "⏱ Query timed out (30 s limit exceeded)."
    except Exception as exc:  # noqa: BLE001
        return pd.DataFrame(), f"❌ Query execution error: {exc}"


def _handle_direct_sql(
    sql: str,
    db_path: str,
    description: str = "",
    chart_config: dict | None = None,
    bulk_mode: bool = False,
    label: str = "",
    category: str = "",
    techniques: list[dict] | None = None,
    severity: str = "",
    playbook: dict | None = None,
    next_steps: str = "",
    profile: DatasetProfile = CLOUDTRAIL_PROFILE,
) -> None:
    """Execute a pre-built SQL query directly without requiring an API key.

    Runs the SQL against the DuckDB database in read-only mode, stores results
    in session state, and appends a message to the chat history (unless
    ``bulk_mode=True``, in which case no chat message is added).

    The DuckDB connection is opened inside a ``duckdb_connection`` context
    manager so it is always closed, even when an exception occurs.

    Args:
        sql:          Validated DuckDB SQL from a built-in preset entry.
        db_path:      Path to the DuckDB database file.
        description:  Optional human-readable description of the preset query.
        chart_config: Optional chart configuration dict (type, x, y, bucket).
        bulk_mode:    When True, skip appending a chat message. Use for bulk
                      execution so results appear in the dedicated bulk section.
        label:        Display name for the query (e.g. "🔑 Root Account Activity").
        category:     Category group (e.g. "🔑 Identity & Access").
        techniques:   Threat Technique Catalog mappings for the preset
                      (list of dicts with tid / name / summary / url keys).
        severity:     Triage severity P1..P4 from the preset entry.
        playbook:     AWS incident response playbook mapping (name / url).
        next_steps:   Containment guidance shown alongside the results.
        profile:      Dataset profile selecting the table, filters and state.
    """
    # Apply the active UI filters (date range, severity) as a scoped CTE.
    sql = _active_filters(profile, sql)
    # Pre-compute the effective SQL (with row_limit applied) so that last_sql
    # and the chat message always reflect what was actually executed.
    row_limit = st.session_state.row_limit
    effective_sql = apply_row_limit(sql, row_limit)

    with st.spinner("⚡ Running direct SQL…"):
        results, error_message = _execute_sql_safely(db_path, sql, row_limit, profile)

    _set(profile, "last_sql", effective_sql)
    _set(profile, "last_results", results if error_message is None else None)
    _set(profile, "last_summary", "")

    # Append a chat message only in non-bulk (chat) mode.
    if not bulk_mode:
        if error_message:
            assistant_content = error_message
        else:
            row_info = _format_row_info(results, row_limit)
            assistant_content = (
                f"**Direct SQL query executed.** **Results:** {row_info}"
            )

        _get(profile, "messages").append(
            {"role": "assistant", "content": assistant_content}
        )

    if error_message is None:
        source = "bulk" if bulk_mode else "chat"
        _get(profile, "query_history").append(
            ReportEntry(
                sql=effective_sql,
                results=results,
                analysis="",
                description=description,
                chart_config=chart_config,
                label=label,
                category=category,
                source=source,
                techniques=techniques or [],
                severity=severity,
                playbook=playbook or {},
                next_steps=next_steps,
            )
        )
        if not bulk_mode:
            # Link this message to its query_history entry for interleaved rendering.
            _get(profile, "messages")[-1]["query_index"] = (
                len(_get(profile, "query_history")) - 1
            )


def _handle_edit_rerun_sql(
    sql: str, db_path: str, profile: DatasetProfile = CLOUDTRAIL_PROFILE
) -> None:
    """Execute a manually edited SQL query, with optional AI analysis.

    Runs the edited SQL against the DuckDB database in read-only mode without
    requiring an API key.  When an API key is present an AI summary is generated;
    otherwise the query executes and returns results immediately.

    The DuckDB connection is opened inside a ``duckdb_connection`` context
    manager so it is always closed, even when an exception occurs.

    Args:
        sql:     The edited SQL query string from the SQL editor text area.
        db_path: Path to the DuckDB database file.
        profile: Dataset profile selecting the table, prompt and state.
    """
    api_key = st.session_state.api_key
    model = st.session_state.model
    row_limit = st.session_state.row_limit
    effective_sql = apply_row_limit(sql, row_limit)

    with st.spinner("▶ Running SQL…"):
        results, error_message = _execute_sql_safely(db_path, sql, row_limit, profile)

    _set(profile, "last_sql", effective_sql)
    _set(profile, "last_results", results if error_message is None else None)

    if error_message:
        _set(profile, "last_summary", "")
        _get(profile, "messages").append(
            {"role": "assistant", "content": error_message}
        )
        return

    row_info = _format_row_info(results, row_limit, extended=True)

    summary = ""
    if api_key:
        with st.spinner("📋 Summarising results…"):
            summary = generate_analysis(
                effective_sql, results, api_key=api_key, model=model
            )

    # Clear last_summary — the analysis is shown in the AI Analysis section via query_history.
    _set(profile, "last_summary", "")

    assistant_content = f"**Re-run SQL executed.** **Results:** {row_info}"
    _get(profile, "messages").append(
        {"role": "assistant", "content": assistant_content}
    )
    _get(profile, "query_history").append(
        ReportEntry(sql=effective_sql, results=results, analysis=summary)
    )
    # Link this message to its query_history entry for interleaved rendering.
    _get(profile, "messages")[-1]["query_index"] = (
        len(_get(profile, "query_history")) - 1
    )


def _analyze_entry_results(
    entry_idx: int, profile: DatasetProfile = CLOUDTRAIL_PROFILE
) -> None:
    """Analyze a specific query_history entry by index using AI.

    Reads the entry's sql and results, calls generate_analysis(), and stores
    the result back in entry.analysis.  Updates last_summary only when
    entry_idx refers to the last entry (backward compatibility).

    Args:
        entry_idx: 0-based index into the profile's query_history.
        profile:   Dataset profile whose history holds the entry.
    """
    api_key = st.session_state.api_key
    model = st.session_state.model

    if not api_key:
        _get(profile, "messages").append(
            {
                "role": "assistant",
                "content": "⚠️ Please enter your OpenAI API key in the sidebar first.",
            }
        )
        return

    entry = _get(profile, "query_history")[entry_idx]
    if entry.results is None or (
        hasattr(entry.results, "empty") and entry.results.empty
    ):
        return

    with st.spinner("🤖 Analyzing results…"):
        summary = generate_analysis(
            entry.sql, entry.results, api_key=api_key, model=model
        )

    entry.analysis = summary

    if entry_idx == len(_get(profile, "query_history")) - 1:
        _set(profile, "last_summary", summary)


def _handle_user_query(
    user_input: str, db_path: str, profile: DatasetProfile = CLOUDTRAIL_PROFILE
) -> None:
    """Process a user query: generate SQL, execute, summarise, and update state.

    Implements the AGT-01 → AGT-02 → AGT-03 → AGT-04 → AGT-05 pipeline.
    The summary step (AGT-05) produces only fact-based bullet points;
    speculative threat assessments are excluded by the LLM prompt.

    Conversation context from previous turns is forwarded to generate_sql()
    so that follow-up questions such as "drill down on that" work naturally.

    If the generated SQL fails validation, execute_with_retry() asks the LLM
    to correct it (up to 2 attempts) before surfacing the error to the user.

    The DuckDB connection is opened inside a ``duckdb_connection`` context
    manager so it is always closed, even when an exception occurs.

    Args:
        user_input: The natural language question from the user.
        db_path:    Path to the DuckDB database file.
        profile:    Dataset profile selecting the table, prompt and state.
    """
    api_key = st.session_state.api_key
    model = st.session_state.model

    if not api_key:
        _get(profile, "messages").append(
            {
                "role": "assistant",
                "content": "⚠️ Please enter your OpenAI API key in the sidebar first.",
            }
        )
        return

    # Step 1: Generate SQL (AGT-02), injecting prior conversation context.
    # Take a snapshot so that the context passed to the LLM is not mutated
    # by the append at the end of this function.
    context = list(_get(profile, "conversation_context", []))
    with st.spinner("🤖 Generating SQL…"):
        sql = generate_sql(
            user_input,
            api_key=api_key,
            model=model,
            context=context,
            profile=profile,
        )

    # Apply the active UI filters to the AI-generated SQL (CTE when active).
    sql = _active_filters(profile, sql)

    original_sql = sql  # preserve to detect LLM corrections later
    final_sql = sql
    _set(profile, "last_sql", sql)

    # Step 2: Execute query with automatic SQL correction on validation failure (AGT-03/04).
    results = pd.DataFrame()
    error_message: str | None = None
    effective_sql = sql  # updated to effective SQL (row_limit applied) on success
    try:
        with duckdb_connection(db_path) as conn:
            results, final_sql = execute_with_retry(
                conn,
                sql,
                api_key=api_key,
                model=model,
                row_limit=st.session_state.row_limit,
                profile=profile,
            )
            results = _maybe_enrich_geo(conn, results, profile)
        if final_sql != original_sql:
            sql = final_sql
        # Store the effective SQL (with row_limit applied) so the SQL editor
        # shows exactly what was executed, not the pre-limit original.
        effective_sql = apply_row_limit(sql, st.session_state.row_limit)
        _set(profile, "last_sql", effective_sql)
    except QueryValidationError as exc:
        error_message = f"🚫 SQL validation error: {exc}"
    except TimeoutError:
        error_message = "⏱ Query timed out (30 s limit exceeded)."
    except Exception as exc:  # noqa: BLE001
        error_message = f"❌ Query execution error: {exc}"

    _set(profile, "last_results", results if error_message is None else None)

    # Step 3: Generate fact-based analysis (AGT-05) — stored in query_history only.
    summary = ""
    if error_message is None:
        with st.spinner("📋 Summarising results…"):
            summary = generate_analysis(
                effective_sql, results, api_key=api_key, model=model
            )
    # Clear last_summary — the analysis is displayed via query_history in the AI Analysis section.
    _set(profile, "last_summary", "")

    # Step 4: Append to chat history and query history.
    if error_message:
        assistant_content = error_message
    else:
        row_info = _format_row_info(results, st.session_state.row_limit, extended=True)
        retry_notice = (
            "\n\n⚠️ _SQL was auto-corrected by the AI assistant._"
            if final_sql != original_sql
            else ""
        )
        assistant_content = f"**Results:** {row_info}" + retry_notice

    _get(profile, "messages").append(
        {"role": "assistant", "content": assistant_content}
    )

    if error_message is None:
        _get(profile, "query_history").append(
            ReportEntry(sql=effective_sql, results=results, analysis=summary)
        )
        # Link this message to its query_history entry for interleaved rendering.
        _get(profile, "messages")[-1]["query_index"] = (
            len(_get(profile, "query_history")) - 1
        )
        # Update conversation context for follow-up queries.
        summary_text = summary if summary else "(no summary)"
        context_entries = _get(profile, "conversation_context")
        context_entries.append(
            {"user_query": user_input, "sql": effective_sql, "summary": summary_text}
        )
        # Keep only the most recent MAX_CONTEXT_TURNS entries.
        if len(context_entries) > MAX_CONTEXT_TURNS:
            _set(profile, "conversation_context", context_entries[-MAX_CONTEXT_TURNS:])
