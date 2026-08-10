"""Session-state lifecycle and hunt loading for the two chat pages.

Everything a page needs *before* it renders anything: the per-profile
``st.session_state`` namespace (create, clear, export) and the built-in hunts
read off disk. ``profiles.py`` owns the namespacing rule — every key here is
written through :meth:`DatasetProfile.state_key`, which is what keeps the four
pages from sharing history, filters and reports while still sharing the API key,
the model and the row cap.

Layout lives in ``app.py``; this module renders nothing. It touches
``st.session_state`` and no other part of Streamlit, so its tests need no
Streamlit runtime.
"""

import copy
import json
import logging

import streamlit as st
import yaml

from config import DB_VARIANT_FULL
from profiles import CLOUDTRAIL_PROFILE, DatasetProfile
from query import DEFAULT_ROW_LIMIT
from report import ReportEntry

logger = logging.getLogger(__name__)

# Session state keys and their default values. The mutable ones are templates,
# never the value stored: :func:`_init_session_state` copies them per profile —
# see the note there.
SESSION_STATE_DEFAULTS: dict = {
    "messages": [],  # chat history: list of {role, content}
    "query_history": [],  # list of ReportEntry for report generation
    "last_sql": "",  # most recently generated SQL (editable)
    "last_results": None,  # pandas DataFrame or None
    "last_summary": "",  # fact-based summary from the last query
    "api_key": "",  # entered in sidebar (AGT-09)
    "model": "gpt-5.5",  # selected model
    "date_start": None,  # date | None — lower bound for event_time filter
    "date_end": None,  # date | None — upper bound for event_time filter
    "row_limit": DEFAULT_ROW_LIMIT,  # maximum rows returned per query
    "geo_enrich": True,  # auto-join geo columns next to IP columns in results
    "conversation_context": [],  # recent (user_query, sql, summary) turns for LLM context
    "db_variant": DB_VARIANT_FULL,  # active DB variant; "Lite" only available when DUCKDB_PATH_LITE is set
    "analyst_notes": {},  # UI-01: dict[int, str] — query_index → analyst note text
    "bulk_progress": None,  # UI-04: None | {"current": int, "total": int, "label": str}
    "levels": [],  # severity filter (Suzaku only; empty = no filter)
    "suzaku_db": "",  # path of the selected Suzaku DuckDB file
}


def _init_session_state(profile: DatasetProfile = CLOUDTRAIL_PROFILE) -> None:
    """Initialize this profile's session-state namespace with default values.

    Idempotent: only sets keys that are not already present, so existing
    session data is never overwritten on page reload. Per-page keys are
    prefixed by the profile (see ``profiles.py``), so the two pages keep
    independent history, filters and reports while sharing the API key,
    model and row cap.

    Mutable defaults are deep-copied. Storing the object from
    :data:`SESSION_STATE_DEFAULTS` directly gave every profile the *same* list
    or dict, so a hunt run on one page appended to the other page's history
    too — and, because that table outlives the session, to the next session's.

    Args:
        profile: Dataset profile whose namespace to initialize.
    """
    for key, default in SESSION_STATE_DEFAULTS.items():
        namespaced = profile.state_key(key)
        if namespaced not in st.session_state:
            if key == "levels":
                default = list(profile.default_levels)
            elif key == "row_limit":
                default = profile.default_row_limit
            st.session_state[namespaced] = copy.deepcopy(default)


def _format_technique_caption(technique: dict) -> str:
    """Format one Threat Technique Catalog mapping as a caption line.

    Args:
        technique: Dict with tid / name / summary / url keys (all optional
            except tid).

    Returns:
        A Markdown caption like
        ``🎯 [T1562.008 — Impair Defenses: Disable Cloud Logs](url): summary``.
        The link is omitted when no url is present; the summary suffix is
        omitted when no summary is present.
    """
    tid = str(technique.get("tid", ""))
    name = str(technique.get("name", ""))
    url = str(technique.get("url", ""))
    summary = str(technique.get("summary", ""))

    title = f"{tid} — {name}" if name else tid
    if url:
        title = f"[{title}]({url})"
    caption = f"🎯 {title}"
    if summary:
        caption = f"{caption}: {summary}"
    return caption


# Response-time expectations from the AWS incident response playbooks'
# TRIAGE_GUIDE severity matrix. Showing the clock next to the level is what makes
# the level actionable — "P1" alone is just a colour.
_SEVERITY_LABELS: dict[str, str] = {
    "P1": "Critical — respond within 15 minutes",
    "P2": "High — respond within 1 hour",
    "P3": "Medium — respond within 4 hours",
    "P4": "Low — respond within 24 hours",
}


def _format_severity_caption(severity: str) -> str:
    """Format a triage severity as a caption line.

    Args:
        severity: One of P1..P4. Anything else renders as an empty string so an
            unannotated hunt simply shows nothing.

    Returns:
        A Markdown caption like ``🚨 **P1** — Critical — respond within 15
        minutes``, or ``""`` when *severity* is not a known level.
    """
    label = _SEVERITY_LABELS.get(str(severity or ""))
    if not label:
        return ""
    icon = "🚨" if severity == "P1" else "⚠️" if severity == "P2" else "ℹ️"
    return f"{icon} **{severity}** — {label}"


def _format_playbook_caption(playbook: dict | None) -> str:
    """Format the AWS incident response playbook mapping as a caption line.

    Args:
        playbook: Dict with ``name`` and optional ``url``. Falsy input renders
            as an empty string.

    Returns:
        A Markdown caption like ``📕 Response playbook: [IRP-Ransomware](url)``,
        with the link omitted when no url is present.
    """
    if not playbook:
        return ""
    name = str(playbook.get("name", "")).strip()
    if not name:
        return ""
    url = str(playbook.get("url", "")).strip()
    target = f"[{name}]({url})" if url else name
    return f"📕 Response playbook: {target}"


def _build_all_hunt_queries(prompts: list[dict]) -> list[dict]:
    """Return a flat list of bulk-query dicts for every entry that has a sql field.

    Args:
        prompts: All prompt entries loaded from builtin_hunts.yaml.

    Returns:
        List of dicts with keys sql, description, chart_config, label, category,
        techniques, severity, playbook and next_steps, covering every entry whose
        sql field is non-empty.  sql values are stripped of leading/trailing
        whitespace.
    """
    return [
        {
            "sql": p["sql"].strip(),
            "description": p.get("description", ""),
            "chart_config": p.get("chart"),
            "label": p["label"],
            "category": p.get("category", ""),
            "techniques": p.get("techniques") or [],
            "severity": p.get("severity", ""),
            "playbook": p.get("playbook") or {},
            "next_steps": p.get("next_steps", ""),
        }
        for p in prompts
        if p.get("sql", "").strip()
    ]


def _load_builtin_prompts(
    profile: DatasetProfile = CLOUDTRAIL_PROFILE,
) -> list[dict]:
    """Load built-in hunt prompts for *profile* from its YAML file.

    Args:
        profile: Dataset profile whose ``hunts_path`` to read.

    Returns:
        A list of dicts, each containing 'label' and 'prompt' keys.
        Falls back to a minimal built-in list if the file is not found.
    """
    path = profile.hunts_path
    try:
        with open(path, encoding="utf-8") as f:
            prompts = yaml.safe_load(f)
        if isinstance(prompts, list):
            return prompts
    except FileNotFoundError:
        logger.warning("hunts YAML not found at %s", path)
    except yaml.YAMLError as exc:
        logger.error("Failed to parse %s: %s", path, exc)

    # Fallback minimal list
    return [
        {
            "label": "🔑 Root Account Activity",
            "prompt": (
                "List all API calls made by the root account. Include event_time, "
                "event_name, source_ip_address, and aws_region. Order by most recent first."
            ),
        },
        {
            "label": "🚫 Access Denied Errors",
            "prompt": (
                "Show all AccessDenied and UnauthorizedAccess errors in the logs. "
                "Group by user identity and event_name to find the top offenders."
            ),
        },
    ]


def _clear_session(profile: DatasetProfile = CLOUDTRAIL_PROFILE) -> None:
    """Reset one page's chat, results, notes and context.

    Only the profile's own namespace is touched, so clearing the Suzaku page
    leaves a CloudTrail investigation — and the shared API key — intact.

    Args:
        profile: Dataset profile whose session state to clear.
    """
    for key, value in (
        ("messages", []),
        ("query_history", []),
        ("last_sql", ""),
        ("last_results", None),
        ("last_summary", ""),
        ("conversation_context", []),
        ("analyst_notes", {}),
    ):
        st.session_state[profile.state_key(key)] = value


def _export_session(
    entries: list[ReportEntry], title: str = "Threat Hunting Session"
) -> str:
    """Export the current session as a JSON string.

    Serialises all ReportEntry objects to a JSON payload for download
    or later re-import (AGT-08).  Includes analyst_note for each query.

    Args:
        entries: List of ReportEntry objects from the current session.
        title:   Human-readable session title.

    Returns:
        A JSON-formatted string representing the session.
    """
    queries = [
        {
            "sql": entry.sql,
            "row_count": len(entry.results) if entry.results is not None else 0,
            "analyst_note": entry.analyst_note,
        }
        for entry in entries
    ]
    payload = {
        "title": title,
        "queries": queries,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
