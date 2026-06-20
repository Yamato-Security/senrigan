"""Markdown / HTML report generation for Suzaku ``aws-ct-summary`` data.

Mirrors the chat-side :mod:`report` module, but for the identity-centric Suzaku
summary: one section per ``user_arn`` with its abused APIs, source IPs, regions,
user agents, access keys, and source countries.

Unlike the chat report, access-key IDs and source IPs are **not** redacted —
in this view they are the indicators of compromise the analyst is reporting on.
The summary never contains secret access keys.

All functions are pure (parsed data in, string out): no Streamlit, no I/O.
"""

from __future__ import annotations

import html as _html
import re
from datetime import datetime, timezone

import pandas as pd

from suzaku_summary import (
    api_entries_df,
    build_triage_table,
    country_counts,
    top_n,
    value_entries_df,
)

DEFAULT_TITLE = "Suzaku CloudTrail Summary Report"

# High-cardinality lists (source IPs, user agents, …) can be huge; cap how many
# rows the report includes per identity so the document stays readable.
REPORT_TOP_N = 20


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _identity_heading(summary: dict) -> str:
    """Heading text for one identity, e.g. ``user/backup (IAMUser)``."""
    arn = summary.get("user_arn", "")
    user_type = summary.get("user_types", "")
    return f"{arn} ({user_type})" if user_type else arn


def _anchor(text: str) -> str:
    """GitHub-flavored Markdown anchor fragment for a heading (no leading ``#``)."""
    anchor = text.lower()
    anchor = re.sub(r"[^\w\s-]", "", anchor)
    anchor = re.sub(r"\s+", "-", anchor.strip())
    return anchor


def _identity_breakdowns(summary: dict) -> list[tuple[str, pd.DataFrame, str]]:
    """Return ``(title, dataframe, label_column)`` triples for the value lists.

    Centralizes the set of per-identity breakdown tables so the Markdown and
    HTML renderers stay in sync.
    """
    return [
        ("Source IPs", value_entries_df(summary.get("src_ips")), "value"),
        ("Source Countries", country_counts(summary.get("src_ips")), "country"),
        ("AWS Regions", value_entries_df(summary.get("aws_regions")), "value"),
        ("User Agents", value_entries_df(summary.get("user_agents")), "value"),
        (
            "Access Key IDs",
            value_entries_df(summary.get("user_access_key_ids")),
            "value",
        ),
    ]


def _capped(df: pd.DataFrame, n: int = REPORT_TOP_N) -> tuple[pd.DataFrame, str]:
    """Return the top-``n`` rows of ``df`` and a note when it was truncated."""
    total = len(df)
    if total > n:
        return top_n(df, n), f" (top {n} of {total:,})"
    return df, ""


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def _md_table(df: pd.DataFrame) -> str:
    if df is None or df.empty:
        return "_(none)_"
    return df.to_markdown(index=False)


def _identity_section_md(summary: dict) -> str:
    heading = _identity_heading(summary)
    lines = [
        f"## {heading}",
        "",
        f"- **Total events:** {summary.get('num_of_events', 0):,}",
        f"- **Active:** {summary.get('first_timestamp', '-')} "
        f"→ {summary.get('last_timestamp', '-')}",
        "",
        "### 🔴 Abused APIs — Succeeded",
        "",
        _md_table(api_entries_df(summary.get("abused_apis_success"))),
        "",
        "### 🔴 Abused APIs — Failed",
        "",
        _md_table(api_entries_df(summary.get("abused_apis_failed"))),
        "",
    ]

    for title, df, _label in _identity_breakdowns(summary):
        shown, note = _capped(df)
        lines += [f"### {title}{note}", "", _md_table(shown), ""]

    lines.append("---")
    return "\n".join(lines)


def generate_markdown_report(summaries: list[dict], title: str = DEFAULT_TITLE) -> str:
    """Generate a Markdown report from parsed ``aws-ct-summary`` data.

    Args:
        summaries: Parsed identity summaries (see ``suzaku_summary.parse_summary``).
        title:     Report title used in the top-level heading.

    Returns:
        A complete Markdown document as a string.
    """
    triage = build_triage_table(summaries)
    # Render in triage order (most suspicious first).
    ordered = [
        next(s for s in summaries if s.get("user_arn") == arn)
        for arn in triage["user_arn"]
    ]

    header = (
        f"# {title}\n\n"
        f"**Generated:** {_now_iso()}  ·  **Identities:** {len(summaries)}\n\n---\n"
    )

    toc_lines = ["## Table of Contents", ""]
    for i, summary in enumerate(ordered, 1):
        heading = _identity_heading(summary)
        toc_lines.append(f"{i}. [{heading}](#{_anchor(heading)})")
    toc = "\n".join(toc_lines)

    overview = "## Overview\n\n" + _md_table(triage)
    sections = [_identity_section_md(s) for s in ordered]

    return "\n\n".join([header, toc, "---", overview, "---"] + sections) + "\n"


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------


def _html_table(df: pd.DataFrame) -> str:
    if df is None or df.empty:
        return '<p class="no-results">(none)</p>'
    return f'<div class="table-wrap">{df.to_html(index=False, border=1)}</div>'


def _identity_section_html(summary: dict) -> str:
    heading = _identity_heading(summary)
    anchor = _anchor(heading)

    blocks = [
        f'<section id="{anchor}">',
        f"  <h2>{_html.escape(heading)}</h2>",
        f"  <p><strong>Total events:</strong> {summary.get('num_of_events', 0):,}"
        f" &nbsp;&middot;&nbsp; <strong>Active:</strong> "
        f"{_html.escape(str(summary.get('first_timestamp', '-')))} → "
        f"{_html.escape(str(summary.get('last_timestamp', '-')))}</p>",
        "  <h3>🔴 Abused APIs — Succeeded</h3>",
        _html_table(api_entries_df(summary.get("abused_apis_success"))),
        "  <h3>🔴 Abused APIs — Failed</h3>",
        _html_table(api_entries_df(summary.get("abused_apis_failed"))),
    ]

    for title, df, _label in _identity_breakdowns(summary):
        shown, note = _capped(df)
        blocks.append(f"  <h3>{_html.escape(title)}{_html.escape(note)}</h3>")
        blocks.append(_html_table(shown))

    blocks.append("</section>")
    blocks.append("<hr>")
    return "\n".join(blocks)


_HTML_CSS = """
* { box-sizing: border-box; }
body { font-family: sans-serif; margin: 0; line-height: 1.6; color: #000; background: #fff; }
#page-header { padding: 0.8em 1.5em; border-bottom: 1px solid #ccc; }
#page-header h1 { margin: 0 0 0.1em; font-size: 1.3em; }
#page-header p { margin: 0; font-size: 0.85em; color: #555; }
#layout { display: grid; grid-template-columns: 320px 1fr; min-height: calc(100vh - 60px); }
#toc { position: sticky; top: 0; height: 100vh; overflow: auto; border-right: 1px solid #ccc; padding: 1em 0.8em; font-size: 0.85em; }
#toc h2 { font-size: 0.95em; margin: 0 0 0.5em; border-bottom: 1px solid #ccc; padding-bottom: 0.3em; }
#toc ol { margin: 0; padding-left: 1.4em; }
#toc li { margin: 0.3em 0; }
#toc a { color: #000; text-decoration: none; }
#toc a:hover { text-decoration: underline; }
#content { padding: 1.5em 2em 4em; min-width: 0; }
h2 { border-bottom: 1px solid #ccc; padding-bottom: 0.2em; margin-top: 2em; font-size: 1.1em; word-break: break-all; }
h3 { margin-top: 1.2em; font-size: 0.95em; }
table { border-collapse: collapse; width: 100%; font-size: 0.85em; }
th, td { border: 1px solid #999; padding: 0.3em 0.6em; text-align: left; }
th { background: #eee; position: sticky; top: 0; }
.table-wrap { overflow: auto; max-height: 480px; }
.no-results { color: #666; font-style: italic; }
hr { border: none; border-top: 1px solid #ccc; margin: 2em 0; }
"""


def generate_html_report(summaries: list[dict], title: str = DEFAULT_TITLE) -> str:
    """Generate a self-contained HTML report from parsed ``aws-ct-summary`` data.

    Renders a sticky table-of-contents sidebar (identities in triage order)
    alongside an overview table and one section per identity.

    Args:
        summaries: Parsed identity summaries.
        title:     Report title shown in the page title and top heading.

    Returns:
        A complete self-contained HTML document as a string.
    """
    triage = build_triage_table(summaries)
    ordered = [
        next(s for s in summaries if s.get("user_arn") == arn)
        for arn in triage["user_arn"]
    ]

    toc_items = "\n".join(
        f'    <li><a href="#{_anchor(_identity_heading(s))}">'
        f"{_html.escape(_identity_heading(s))}</a></li>"
        for s in ordered
    )
    overview_html = _html_table(triage)
    sections_html = "\n".join(_identity_section_html(s) for s in ordered)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{_html.escape(title)}</title>
  <style>{_HTML_CSS}</style>
</head>
<body>
<div id="page-header">
  <h1>{_html.escape(title)}</h1>
  <p>Generated: {_now_iso()} &nbsp;&middot;&nbsp; {len(summaries)} identities</p>
</div>
<div id="layout">
<nav id="toc">
  <h2>Identities</h2>
  <ol>
{toc_items}
  </ol>
</nav>
<div id="content">
  <h2 id="overview">Overview</h2>
  {overview_html}
  <hr>
  {sections_html}
</div>
</div>
</body>
</html>
"""
