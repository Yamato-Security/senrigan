"""Business-logic handlers for the Senrigan Streamlit agent.

This module contains the three stateful handler functions that were previously
defined directly in ``app.py``.  Extracting them here:

- Keeps ``app.py`` focused on UI layout and Streamlit wiring.
- Makes handlers independently testable without rendering the full page.
- Ensures all DuckDB connections are guarded by the ``duckdb_connection``
  context manager so they are always closed, even on exception.

All handlers read and write ``st.session_state`` directly — they are designed
to be called from within a running Streamlit application.
"""

import logging

import duckdb
import pandas as pd
import streamlit as st

from geo import enrich_with_geo
from llm import MAX_CONTEXT_TURNS, generate_analysis, generate_sql
from query import (
    QueryValidationError,
    apply_date_filter,
    apply_row_limit,
    duckdb_connection,
    execute_query,
    execute_with_retry,
)
from report import ReportEntry

logger = logging.getLogger(__name__)


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
    conn: duckdb.DuckDBPyConnection, results: pd.DataFrame
) -> pd.DataFrame:
    """Geo-enrich *results* when the sidebar toggle is on.

    Enrichment is best-effort: any failure is logged and the original
    results are returned unchanged — it must never fail the query itself.

    Args:
        conn:    The open DuckDB connection the query ran on.
        results: The query result DataFrame.

    Returns:
        The (possibly) enriched DataFrame.
    """
    if not st.session_state.get("geo_enrich", True):
        return results
    try:
        return enrich_with_geo(conn, results)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Geo enrichment failed, returning raw results: %s", exc)
        return results


def _execute_sql_safely(
    db_path: str, sql: str, row_limit: int
) -> tuple[pd.DataFrame, str | None]:
    """Execute *sql* read-only, converting known failures to a user message.

    Successful results are geo-enriched via :func:`_maybe_enrich_geo`.

    Args:
        db_path:   Path to the DuckDB database file.
        sql:       The SQL query to execute.
        row_limit: Maximum number of rows to return.

    Returns:
        A tuple ``(results, error_message)`` — *error_message* is ``None`` on
        success, otherwise a display-ready string and *results* is empty.
    """
    try:
        with duckdb_connection(db_path) as conn:
            results = execute_query(conn, sql, row_limit=row_limit)
            return _maybe_enrich_geo(conn, results), None
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
    """
    # Apply date range filter (wraps sql in a date-scoped CTE when active).
    sql = apply_date_filter(sql, st.session_state.date_start, st.session_state.date_end)
    # Pre-compute the effective SQL (with row_limit applied) so that last_sql
    # and the chat message always reflect what was actually executed.
    effective_sql = apply_row_limit(sql, st.session_state.row_limit)

    with st.spinner("⚡ Running direct SQL…"):
        results, error_message = _execute_sql_safely(
            db_path, sql, st.session_state.row_limit
        )

    st.session_state.last_sql = effective_sql
    st.session_state.last_results = results if error_message is None else None
    st.session_state.last_summary = ""

    # Append a chat message only in non-bulk (chat) mode.
    if not bulk_mode:
        if error_message:
            assistant_content = error_message
        else:
            row_info = _format_row_info(results, st.session_state.row_limit)
            assistant_content = (
                f"**Direct SQL query executed.** **Results:** {row_info}"
            )

        st.session_state.messages.append(
            {"role": "assistant", "content": assistant_content}
        )

    if error_message is None:
        source = "bulk" if bulk_mode else "chat"
        st.session_state.query_history.append(
            ReportEntry(
                sql=effective_sql,
                results=results,
                analysis="",
                description=description,
                chart_config=chart_config,
                label=label,
                category=category,
                source=source,
            )
        )
        if not bulk_mode:
            # Link this message to its query_history entry for interleaved rendering.
            st.session_state.messages[-1]["query_index"] = (
                len(st.session_state.query_history) - 1
            )


def _handle_edit_rerun_sql(sql: str, db_path: str) -> None:
    """Execute a manually edited SQL query, with optional AI analysis.

    Runs the edited SQL against the DuckDB database in read-only mode without
    requiring an API key.  When an API key is present an AI summary is generated;
    otherwise the query executes and returns results immediately.

    The DuckDB connection is opened inside a ``duckdb_connection`` context
    manager so it is always closed, even when an exception occurs.

    Args:
        sql:     The edited SQL query string from the SQL editor text area.
        db_path: Path to the DuckDB database file.
    """
    api_key = st.session_state.api_key
    model = st.session_state.model
    row_limit = st.session_state.row_limit
    effective_sql = apply_row_limit(sql, row_limit)

    with st.spinner("▶ Running SQL…"):
        results, error_message = _execute_sql_safely(db_path, sql, row_limit)

    st.session_state.last_sql = effective_sql
    st.session_state.last_results = results if error_message is None else None

    if error_message:
        st.session_state.last_summary = ""
        st.session_state.messages.append(
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
    st.session_state.last_summary = ""

    assistant_content = f"**Re-run SQL executed.** **Results:** {row_info}"
    st.session_state.messages.append(
        {"role": "assistant", "content": assistant_content}
    )
    st.session_state.query_history.append(
        ReportEntry(sql=effective_sql, results=results, analysis=summary)
    )
    # Link this message to its query_history entry for interleaved rendering.
    st.session_state.messages[-1]["query_index"] = (
        len(st.session_state.query_history) - 1
    )


def _analyze_entry_results(entry_idx: int) -> None:
    """Analyze a specific query_history entry by index using AI.

    Reads the entry's sql and results, calls generate_analysis(), and stores
    the result back in entry.analysis.  Updates last_summary only when
    entry_idx refers to the last entry (backward compatibility).

    Args:
        entry_idx: 0-based index into st.session_state.query_history.
    """
    api_key = st.session_state.api_key
    model = st.session_state.model

    if not api_key:
        st.session_state.messages.append(
            {
                "role": "assistant",
                "content": "⚠️ Please enter your OpenAI API key in the sidebar first.",
            }
        )
        return

    entry = st.session_state.query_history[entry_idx]
    if entry.results is None or (
        hasattr(entry.results, "empty") and entry.results.empty
    ):
        return

    with st.spinner("🤖 Analyzing results…"):
        summary = generate_analysis(
            entry.sql, entry.results, api_key=api_key, model=model
        )

    entry.analysis = summary

    if entry_idx == len(st.session_state.query_history) - 1:
        st.session_state.last_summary = summary


def _handle_user_query(user_input: str, db_path: str) -> None:
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
    """
    api_key = st.session_state.api_key
    model = st.session_state.model

    if not api_key:
        st.session_state.messages.append(
            {
                "role": "assistant",
                "content": "⚠️ Please enter your OpenAI API key in the sidebar first.",
            }
        )
        return

    # Step 1: Generate SQL (AGT-02), injecting prior conversation context.
    # Take a snapshot so that the context passed to the LLM is not mutated
    # by the append at the end of this function.
    context = list(st.session_state.conversation_context)
    with st.spinner("🤖 Generating SQL…"):
        sql = generate_sql(user_input, api_key=api_key, model=model, context=context)

    # Apply date range filter to the AI-generated SQL (wraps in CTE when active).
    sql = apply_date_filter(sql, st.session_state.date_start, st.session_state.date_end)

    original_sql = sql  # preserve to detect LLM corrections later
    final_sql = sql
    st.session_state.last_sql = sql

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
            )
            results = _maybe_enrich_geo(conn, results)
        if final_sql != original_sql:
            sql = final_sql
        # Store the effective SQL (with row_limit applied) so the SQL editor
        # shows exactly what was executed, not the pre-limit original.
        effective_sql = apply_row_limit(sql, st.session_state.row_limit)
        st.session_state.last_sql = effective_sql
    except QueryValidationError as exc:
        error_message = f"🚫 SQL validation error: {exc}"
    except TimeoutError:
        error_message = "⏱ Query timed out (30 s limit exceeded)."
    except Exception as exc:  # noqa: BLE001
        error_message = f"❌ Query execution error: {exc}"

    st.session_state.last_results = results if error_message is None else None

    # Step 3: Generate fact-based analysis (AGT-05) — stored in query_history only.
    summary = ""
    if error_message is None:
        with st.spinner("📋 Summarising results…"):
            summary = generate_analysis(
                effective_sql, results, api_key=api_key, model=model
            )
    # Clear last_summary — the analysis is displayed via query_history in the AI Analysis section.
    st.session_state.last_summary = ""

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

    st.session_state.messages.append(
        {"role": "assistant", "content": assistant_content}
    )

    if error_message is None:
        st.session_state.query_history.append(
            ReportEntry(sql=effective_sql, results=results, analysis=summary)
        )
        # Link this message to its query_history entry for interleaved rendering.
        st.session_state.messages[-1]["query_index"] = (
            len(st.session_state.query_history) - 1
        )
        # Update conversation context for follow-up queries.
        summary_text = summary if summary else "(no summary)"
        st.session_state.conversation_context.append(
            {"user_query": user_input, "sql": effective_sql, "summary": summary_text}
        )
        # Keep only the most recent MAX_CONTEXT_TURNS entries.
        if len(st.session_state.conversation_context) > MAX_CONTEXT_TURNS:
            st.session_state.conversation_context = (
                st.session_state.conversation_context[-MAX_CONTEXT_TURNS:]
            )
