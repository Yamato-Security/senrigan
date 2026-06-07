"""Threat hunting report generation.

Generates structured Markdown reports from investigation sessions,
including queries, results, analysis, and sensitive data redaction.
"""

import html as _html
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

import pandas as pd

# ---------------------------------------------------------------------------
# SQL syntax highlighting
# ---------------------------------------------------------------------------

# SQL keywords to highlight (case-insensitive match, case-preserving output).
_SQL_KEYWORDS: frozenset[str] = frozenset(
    {
        "SELECT",
        "FROM",
        "WHERE",
        "GROUP",
        "ORDER",
        "HAVING",
        "BY",
        "JOIN",
        "LEFT",
        "RIGHT",
        "INNER",
        "OUTER",
        "CROSS",
        "FULL",
        "ON",
        "AS",
        "WITH",
        "UNION",
        "ALL",
        "INTERSECT",
        "EXCEPT",
        "AND",
        "OR",
        "NOT",
        "IN",
        "LIKE",
        "ILIKE",
        "BETWEEN",
        "IS",
        "NULL",
        "TRUE",
        "FALSE",
        "ASC",
        "DESC",
        "CASE",
        "WHEN",
        "THEN",
        "ELSE",
        "END",
        "LIMIT",
        "OFFSET",
        "DISTINCT",
        "INSERT",
        "INTO",
        "UPDATE",
        "SET",
        "DELETE",
        "CREATE",
        "DROP",
        "ALTER",
        "TABLE",
        "VIEW",
        "INDEX",
        "COUNT",
        "SUM",
        "AVG",
        "MIN",
        "MAX",
        "COALESCE",
        "CAST",
        "OVER",
        "PARTITION",
        "ROWS",
        "RANGE",
        "UNBOUNDED",
        "PRECEDING",
        "FOLLOWING",
        "CURRENT",
        "ROW",
        "FILTER",
        "WITHIN",
        "TIMESTAMP",
        "DATE",
        "INTERVAL",
        "IF",
        "EXISTS",
        "EXPLAIN",
        "USING",
        "VALUES",
    }
)

# Tokeniser: order matters — longer/more specific patterns must come first.
_SQL_TOKEN_RE = re.compile(
    r"(--[^\n]*)"  # line comment
    r"|(\/\*.*?\*\/)"  # block comment
    r"|('(?:[^'\\]|\\.)*')"  # single-quoted string
    r"|(\b\d+(?:\.\d+)?\b)"  # numeric literal
    r"|([A-Za-z_]\w*)",  # identifier or keyword
    re.DOTALL,
)


def _highlight_sql(sql: str) -> str:
    """Apply simple syntax highlighting to a SQL string for HTML display.

    Tokenises the SQL and wraps keywords, string literals, comments, and
    numeric literals in ``<span>`` elements with distinct CSS classes.
    All text content is HTML-escaped before being included in the output.

    Args:
        sql: Plain SQL text (already sanitized of secrets).

    Returns:
        HTML string with ``<span class="sql-*">`` tags applied.
    """
    parts: list[str] = []
    pos = 0

    for m in _SQL_TOKEN_RE.finditer(sql):
        # Append any unmatched gap (operators, punctuation, whitespace, etc.)
        if m.start() > pos:
            parts.append(_html.escape(sql[pos : m.start()]))
        pos = m.end()

        comment_line, comment_block, string, number, word = m.groups()

        if comment_line is not None or comment_block is not None:
            token = comment_line if comment_line is not None else comment_block
            parts.append(f'<span class="sql-comment">{_html.escape(token)}</span>')
        elif string is not None:
            parts.append(f'<span class="sql-string">{_html.escape(string)}</span>')
        elif number is not None:
            parts.append(f'<span class="sql-number">{_html.escape(number)}</span>')
        elif word is not None:
            if word.upper() in _SQL_KEYWORDS:
                parts.append(f'<span class="sql-keyword">{_html.escape(word)}</span>')
            else:
                parts.append(_html.escape(word))
        else:
            parts.append(_html.escape(m.group()))

    # Append any trailing unmatched text
    if pos < len(sql):
        parts.append(_html.escape(sql[pos:]))

    return "".join(parts)


# ---------------------------------------------------------------------------
# Sensitive data redaction patterns
# ---------------------------------------------------------------------------
# Each entry is (compiled_pattern, replacement_string).
_SENSITIVE_PATTERNS: list[tuple[re.Pattern, str]] = [
    # AWS Access Key ID: AKIA/ASIA/AROA/AIDA followed by 16 uppercase alphanumerics
    (re.compile(r"(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}"), "[REDACTED_KEY_ID]"),
    # AWS Secret Access Key: 40-character base64-like string (must come AFTER key ID
    # pattern so key IDs are not partially matched by this broader rule)
    (
        re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
        "[REDACTED_SECRET]",
    ),
]


def _sanitize(text: str) -> str:
    """Redact sensitive credential-like strings from a text block.

    Args:
        text: Arbitrary string that may contain AWS credentials.

    Returns:
        The input string with sensitive patterns replaced by redaction markers.
    """
    for pattern, replacement in _SENSITIVE_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ReportEntry:
    """A single query-result-summary triple in an investigation session."""

    sql: str
    results: pd.DataFrame
    analysis: str = ""
    description: str = ""
    chart_config: dict | None = None
    analyst_note: str = ""  # UI-01: freeform Markdown note by the analyst
    label: str = ""  # UI-02: display name (e.g. "🔑 Root Account Activity")
    category: str = ""  # UI-02: category group (e.g. "🔑 Identity & Access")
    source: str = "chat"  # UI-03: "chat" | "bulk"
    # Prevent pandas DataFrame equality issues in dataclass comparisons
    _results_placeholder: None = field(default=None, init=False, repr=False)


# ---------------------------------------------------------------------------
# Report renderer
# ---------------------------------------------------------------------------


def _result_count(entry: ReportEntry) -> int:
    """Return the number of rows in the entry's result DataFrame (0 if empty).

    Args:
        entry: The ReportEntry to inspect.

    Returns:
        Row count as an integer.
    """
    if entry.results is not None and not entry.results.empty:
        return len(entry.results)
    return 0


def _build_heading(index: int, entry: ReportEntry) -> str:
    """Build the ``##`` level heading text including result count badge.

    Args:
        index: 1-based query number.
        entry: The ReportEntry whose label/category/row count are used.

    Returns:
        Heading string without the leading ``## `` prefix.
    """
    count = _result_count(entry)
    count_badge = f"({count:,} rows)"

    if entry.label:
        if entry.category:
            return f"Query {index} — {entry.category}  ›  {entry.label}  {count_badge}"
        return f"Query {index} — {entry.label}  {count_badge}"
    return f"Query {index}  {count_badge}"


def _heading_anchor(heading_text: str) -> str:
    """Convert a heading text to a GitHub-flavored Markdown anchor fragment.

    Lowercases the text, replaces spaces with hyphens, and strips characters
    that are not alphanumeric, hyphens, or underscores.

    Args:
        heading_text: Plain heading text (without ``##`` prefix).

    Returns:
        Anchor fragment string (without leading ``#``).
    """
    anchor = heading_text.lower()
    anchor = re.sub(r"[^\w\s-]", "", anchor)
    anchor = re.sub(r"\s+", "-", anchor.strip())
    return anchor


def _render_toc(entries: list[ReportEntry]) -> str:
    """Render a Markdown table of contents for all report entries.

    Each line is a numbered list item linking to the corresponding section
    anchor, including the result count.

    Args:
        entries: Ordered list of ReportEntry objects.

    Returns:
        A Markdown string containing the TOC block.
    """
    lines = ["## Table of Contents", ""]
    for i, entry in enumerate(entries, 1):
        heading_text = _build_heading(i, entry)
        anchor = _heading_anchor(heading_text)
        lines.append(f"{i}. [{heading_text}](#{anchor})")
    return "\n".join(lines)


def _render_entry(index: int, entry: ReportEntry) -> str:
    """Render one ReportEntry as a Markdown section.

    Outputs the SQL query, results table, and a fact-based summary.
    When label and/or category are set they appear prominently in the heading.
    Result count is appended to the heading.
    When analyst_note is non-empty it is included under its own heading.
    Sensitive credential-like strings are automatically redacted throughout.

    Args:
        index: 1-based query number used for the section heading.
        entry: The ReportEntry to render.

    Returns:
        A Markdown string for the given entry.
    """
    # Results table: render up to 1000 rows; fall back to "(no results)"
    if entry.results is not None and not entry.results.empty:
        results_md = entry.results.head(1000).to_markdown(index=False)
    else:
        results_md = "(no results)"

    sql_block = _sanitize(entry.sql)
    results_block = _sanitize(results_md)
    summary_block = _sanitize(entry.analysis) if entry.analysis else "(no summary)"

    heading = f"## {_build_heading(index, entry)}"

    # Analyst note section (only when non-empty)
    analyst_note_section = ""
    if entry.analyst_note:
        analyst_note_block = _sanitize(entry.analyst_note)
        analyst_note_section = f"\n### Analyst Note\n\n{analyst_note_block}\n"

    return (
        f"{heading}\n\n"
        f"### SQL\n\n"
        f"```sql\n{sql_block}\n```\n\n"
        f"### Results\n\n"
        f"{results_block}\n\n"
        f"### Summary\n\n"
        f"{summary_block}\n"
        f"{analyst_note_section}"
        f"\n---"
    )


def generate_report(
    entries: list[ReportEntry],
    title: str = "Threat Hunting Report",
) -> str:
    """Generate a Markdown threat hunting report from a list of ReportEntries.

    Each entry is rendered as a numbered section containing the SQL query,
    a results table, and a fact-based summary. A table of contents with
    result counts is inserted after the header. The summary lists only
    observed facts (counts, top values) without speculative threat assessments.
    Sensitive credential-like strings are automatically redacted throughout.

    Args:
        entries: Ordered list of query-result-summary triples.
        title:   Report title shown in the top-level heading.

    Returns:
        A complete Markdown document as a string.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    header = f"# {title}\n\n**Generated:** {timestamp}\n\n---\n"
    toc = _render_toc(entries)
    sections = [_render_entry(i + 1, entry) for i, entry in enumerate(entries)]

    return "\n\n".join([header, toc, "---"] + sections) + "\n"


def _render_toc_html(entries: list[ReportEntry]) -> str:
    """Render the table of contents as an HTML ``<nav>`` element.

    Entries are grouped by category using ``<details>``/``<summary>`` elements
    so each category can be expanded or collapsed.  Entries without a category
    are placed under an "Other" group.

    Args:
        entries: Ordered list of ReportEntry objects.

    Returns:
        HTML string for the collapsible category navigation.
    """
    # Group entries by category, preserving insertion order.
    from collections import OrderedDict

    groups: OrderedDict[str, list[tuple[int, ReportEntry]]] = OrderedDict()
    for i, entry in enumerate(entries, 1):
        cat = entry.category if entry.category else "Other"
        groups.setdefault(cat, []).append((i, entry))

    blocks = []
    for cat, group_entries in groups.items():
        items = []
        for i, entry in group_entries:
            heading_text = _build_heading(i, entry)
            anchor = _heading_anchor(heading_text)
            count = _result_count(entry)
            short_label = entry.label if entry.label else f"Query {i}"
            items.append(
                f'<li><a href="#{anchor}">{short_label} ({count:,} rows)</a></li>'
            )
        items_html = "\n".join(items)
        blocks.append(
            f"<details>\n"
            f"  <summary>{cat}</summary>\n"
            f"  <ul>{items_html}</ul>\n"
            f"</details>"
        )

    groups_html = "\n".join(blocks)
    return f"""<nav id="toc">
  <div id="toc-controls">
    <button onclick="document.querySelectorAll('#toc details').forEach(d=>d.open=true)">Expand all</button>
    <button onclick="document.querySelectorAll('#toc details').forEach(d=>d.open=false)">Collapse all</button>
  </div>
  {groups_html}
</nav>"""


def _render_entry_html(index: int, entry: ReportEntry) -> str:
    """Render one ReportEntry as an HTML ``<section>`` block.

    Args:
        index: 1-based query number.
        entry: The ReportEntry to render.

    Returns:
        HTML string for the section.
    """
    heading_text = _build_heading(index, entry)
    anchor = _heading_anchor(heading_text)

    # Results table
    if entry.results is not None and not entry.results.empty:
        results_html = entry.results.head(1000).to_html(index=False, border=1)
        results_html = f'<div class="table-wrap">{results_html}</div>'
    else:
        results_html = '<p class="no-results">No results returned.</p>'

    sql_raw = _sanitize(entry.sql)
    sql_highlighted = _highlight_sql(sql_raw)
    results_html_sanitized = _sanitize(results_html)
    summary_block = (
        f"<p>{_sanitize(entry.analysis)}</p>"
        if entry.analysis
        else '<p class="no-results">(no summary)</p>'
    )

    analyst_section = ""
    if entry.analyst_note:
        note = _sanitize(entry.analyst_note)
        analyst_section = f'<h3>Analyst Note</h3><pre class="analyst-note">{note}</pre>'

    return f"""<section id="{anchor}">
  <h2>{heading_text}</h2>
  <h3>SQL</h3>
  <pre><code class="sql">{sql_highlighted}</code></pre>
  <h3>Results</h3>
  {results_html_sanitized}
  <h3>Summary</h3>
  {summary_block}
  {analyst_section}
</section>
<hr>"""


def generate_html_report(
    entries: list[ReportEntry],
    title: str = "Threat Hunting Report",
) -> str:
    """Generate a self-contained HTML threat hunting report.

    Renders a simple single-column layout with a table of contents,
    followed by each query section containing SQL, results, and summary.
    Minimal styling only — no decorative colors or complex layout.

    Args:
        entries: Ordered list of query-result-summary triples.
        title:   Report title shown in the page title and top heading.

    Returns:
        A complete self-contained HTML document as a string.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    toc_html = _render_toc_html(entries)
    sections_html = "\n".join(
        _render_entry_html(i + 1, entry) for i, entry in enumerate(entries)
    )

    css = """
* { box-sizing: border-box; }
body {
    font-family: sans-serif;
    margin: 0;
    padding: 0;
    line-height: 1.6;
    color: #000;
    background: #fff;
}
#page-header {
    padding: 0.8em 1.5em;
    border-bottom: 1px solid #ccc;
}
#page-header h1 { margin: 0 0 0.1em; font-size: 1.3em; }
#page-header p  { margin: 0; font-size: 0.85em; color: #555; }
#layout {
    display: grid;
    grid-template-columns: 320px 4px 1fr;
    min-height: calc(100vh - 60px);
}
#toc {
    position: sticky;
    top: 0;
    height: 100vh;
    overflow-y: auto;
    overflow-x: auto;
    border-right: 1px solid #ccc;
    padding: 1em 0.8em;
    font-size: 0.85em;
    min-width: 120px;
}
#sidebar-resizer {
    position: sticky;
    top: 0;
    height: 100vh;
    width: 4px;
    background: #ddd;
    cursor: col-resize;
    user-select: none;
    transition: background 0.15s;
}
#sidebar-resizer:hover, #sidebar-resizer.dragging { background: #999; }
#toc h2 { font-size: 0.95em; margin: 0 0 0.5em; border-bottom: 1px solid #ccc; padding-bottom: 0.3em; }
#toc-controls { margin-bottom: 0.5em; display: flex; gap: 0.4em; }
#toc-controls button {
    font-size: 0.75em;
    padding: 0.2em 0.6em;
    cursor: pointer;
    border: 1px solid #999;
    background: #f4f4f4;
}
#toc-controls button:hover { background: #e0e0e0; }
#toc details { margin-bottom: 0.4em; }
#toc summary {
    cursor: pointer;
    font-size: 0.85em;
    font-weight: bold;
    padding: 0.2em 0.2em;
    list-style: disclosure-closed;
    user-select: none;
}
#toc details[open] > summary { list-style: disclosure-open; }
#toc ul { margin: 0.2em 0 0.4em 1em; padding-left: 0; list-style: none; }
#toc li { margin: 0.25em 0; }
#toc li a { font-size: 0.78em; }
#toc a { color: #000; text-decoration: none; }
#toc a:hover { text-decoration: underline; }
#content {
    padding: 1.5em 2em 4em;
    min-width: 0;
}
h2 { border-bottom: 1px solid #ccc; padding-bottom: 0.2em; margin-top: 2em; font-size: 1.1em; }
h3 { margin-top: 1.2em; font-size: 0.95em; }
pre {
    background: #f4f4f4;
    border: 1px solid #ccc;
    padding: 0.8em;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-word;
    font-size: 0.9em;
}
code { font-family: monospace; }
table { border-collapse: collapse; width: 100%; font-size: 0.85em; }
th, td { border: 1px solid #999; padding: 0.3em 0.6em; text-align: left; }
th { background: #eee; position: sticky; top: 0; }
.table-wrap { overflow-x: auto; overflow-y: auto; max-height: 480px; }
.no-results { color: #666; font-style: italic; }
hr { border: none; border-top: 1px solid #ccc; margin: 2em 0; }
.sql-keyword { color: #00008b; font-weight: bold; }
.sql-string  { color: #a31515; }
.sql-number  { color: #098658; }
.sql-comment { color: #6a737d; font-style: italic; }
"""

    js = """
(function () {
  var SIDEBAR_WIDTH_KEY = 'thuntcloud-sidebar-width';
  var DEFAULT_WIDTH = 320;
  var MIN_WIDTH = 120;
  var MAX_WIDTH = 640;

  var resizer = document.getElementById('sidebar-resizer');
  var layout = document.getElementById('layout');
  var toc = document.getElementById('toc');

  function applyWidth(px) {
    layout.style.gridTemplateColumns = px + 'px 4px 1fr';
  }

  // --- Restore persisted width ---
  var savedWidth = parseInt(localStorage.getItem(SIDEBAR_WIDTH_KEY), 10);
  if (savedWidth > 0) { applyWidth(savedWidth); }

  // --- Drag-to-resize ---
  resizer.addEventListener('pointerdown', function (e) {
    e.preventDefault();
    resizer.classList.add('dragging');
    var startX = e.clientX;
    var startWidth = toc.getBoundingClientRect().width;

    function onMove(ev) {
      var delta = ev.clientX - startX;
      var newWidth = Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, startWidth + delta));
      applyWidth(newWidth);
    }

    function onUp() {
      resizer.classList.remove('dragging');
      document.removeEventListener('pointermove', onMove);
      document.removeEventListener('pointerup', onUp);
      var finalWidth = toc.getBoundingClientRect().width;
      try { localStorage.setItem(SIDEBAR_WIDTH_KEY, Math.round(finalWidth)); } catch(e) {}
    }

    document.addEventListener('pointermove', onMove);
    document.addEventListener('pointerup', onUp);
  });
}());
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{title}</title>
  <style>{css}</style>
</head>
<body>
<div id="page-header">
  <h1>{title}</h1>
  <p>Generated: {timestamp} &nbsp;&middot;&nbsp; {len(entries)} queries</p>
</div>
<div id="layout">
{toc_html}
<div id="sidebar-resizer" title="Drag to resize sidebar"></div>
<div id="content">
  {sections_html}
</div>
</div>
<script>{js}</script>
</body>
</html>
"""
