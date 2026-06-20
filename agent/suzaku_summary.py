"""Parsing and aggregation for Suzaku ``aws-ct-summary`` JSON output.

The ``aws-ct-summary`` command of `Suzaku <https://github.com/Yamato-Security/suzaku>`_
emits a JSON array of per-identity (per ``user_arn``) CloudTrail threat profiles.
This module turns that raw structure into validated, table-friendly shapes so the
Streamlit page stays thin and the logic remains unit-testable.

All functions here are pure: they take parsed data and return DataFrames / plain
values. No Streamlit, no I/O.
"""

from __future__ import annotations

import json
import re

import pandas as pd

# Keys every identity object must contain to be considered a valid summary record.
REQUIRED_KEYS: tuple[str, ...] = (
    "user_arn",
    "user_types",
    "num_of_events",
    "abused_apis_success",
    "abused_apis_failed",
    "other_apis_success",
    "other_apis_failed",
    "aws_regions",
    "src_ips",
    "user_access_key_ids",
    "user_agents",
)

# Columns produced for an ``ApiEntry`` array (abused_/other_apis_*).
API_COLUMNS: tuple[str, ...] = (
    "api",
    "description",
    "count",
    "first_seen",
    "last_seen",
)
# Columns produced for a ``ValueEntry`` array (regions, src_ips, keys, user_agents).
VALUE_COLUMNS: tuple[str, ...] = ("value", "count", "first_seen", "last_seen")


class SuzakuSummaryError(ValueError):
    """Raised when the uploaded JSON is not a valid ``aws-ct-summary`` document."""


def parse_summary(raw: str | bytes) -> list[dict]:
    """Parse and validate raw ``aws-ct-summary`` JSON.

    Args:
        raw: The file contents, as bytes (from an upload) or a decoded string.

    Returns:
        The list of identity summary objects.

    Raises:
        SuzakuSummaryError: If the JSON is malformed, is not an array, is empty,
            or any element is missing a required key.
    """
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SuzakuSummaryError(f"Invalid JSON: {exc}") from exc

    if not isinstance(data, list):
        raise SuzakuSummaryError(
            "Expected a JSON array of identity summaries at the top level, "
            f"got {type(data).__name__}."
        )
    if not data:
        raise SuzakuSummaryError("The summary contains no identities.")

    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise SuzakuSummaryError(f"Element {i} is not an object.")
        missing = [k for k in REQUIRED_KEYS if k not in item]
        if missing:
            raise SuzakuSummaryError(
                f"Element {i} ({item.get('user_arn', '?')}) is missing "
                f"required keys: {', '.join(missing)}."
            )

    return data


def build_triage_table(summaries: list[dict]) -> pd.DataFrame:
    """Build the one-row-per-identity triage overview.

    Rows are sorted by total abused-API count (desc), then event count (desc),
    so the most suspicious identities surface at the top.

    Args:
        summaries: Parsed identity summaries from :func:`parse_summary`.

    Returns:
        A DataFrame with one row per identity and triage-relevant columns.
    """
    rows = []
    for s in summaries:
        abused_success = len(s.get("abused_apis_success") or [])
        abused_failed = len(s.get("abused_apis_failed") or [])
        rows.append(
            {
                "user_arn": s.get("user_arn", ""),
                "user_type": s.get("user_types", ""),
                "total_events": s.get("num_of_events", 0),
                "abused_success": abused_success,
                "abused_failed": abused_failed,
                "first_seen": s.get("first_timestamp", ""),
                "last_seen": s.get("last_timestamp", ""),
                "regions": len(s.get("aws_regions") or []),
                "src_ips": len(s.get("src_ips") or []),
                "access_keys": len(s.get("user_access_key_ids") or []),
            }
        )

    df = pd.DataFrame(rows)
    if df.empty:
        return df
    df["_abused_total"] = df["abused_success"] + df["abused_failed"]
    df = df.sort_values(
        ["_abused_total", "total_events"], ascending=[False, False]
    ).drop(columns="_abused_total")
    return df.reset_index(drop=True)


def find_identity(summaries: list[dict], user_arn: str) -> dict | None:
    """Return the summary object for ``user_arn``, or ``None`` if not present."""
    for s in summaries:
        if s.get("user_arn") == user_arn:
            return s
    return None


def api_entries_df(entries: list[dict] | None) -> pd.DataFrame:
    """Normalize an ``ApiEntry`` array into a DataFrame.

    Always returns the canonical :data:`API_COLUMNS`, even for empty input, so
    the UI can render a consistent (possibly empty) table.
    """
    df = pd.DataFrame(entries or [], columns=list(API_COLUMNS))
    return df.reindex(columns=list(API_COLUMNS))


def value_entries_df(entries: list[dict] | None) -> pd.DataFrame:
    """Normalize a ``ValueEntry`` array into a DataFrame.

    Always returns the canonical :data:`VALUE_COLUMNS`, even for empty input.
    """
    df = pd.DataFrame(entries or [], columns=list(VALUE_COLUMNS))
    return df.reindex(columns=list(VALUE_COLUMNS))


def top_n(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Return the top ``n`` rows of a normalized entry DataFrame by ``count``."""
    if df.empty or "count" not in df.columns:
        return df
    return df.sort_values("count", ascending=False).head(n).reset_index(drop=True)


# Country is the last comma-separated token inside the parenthesized GeoIP suffix
# of a src_ip value, e.g. "5.205.62.253 (Telefonica ..., Madrid, Spain)" -> "Spain".
_GEO_PAREN_RE = re.compile(r"\(([^)]*)\)\s*$")


def extract_country(value: str) -> str:
    """Extract the country from a Suzaku ``src_ips`` value string.

    Suzaku embeds GeoIP as free text: ``"<ip> (<org>, <city>, <country>)"``.
    Returns ``"Unknown"`` when no country can be determined (e.g. ``"-"`` or
    a ``(-, -, -)`` placeholder).
    """
    if not value:
        return "Unknown"
    m = _GEO_PAREN_RE.search(value)
    if not m:
        return "Unknown"
    country = m.group(1).split(",")[-1].strip()
    if not country or country == "-":
        return "Unknown"
    return country


def country_counts(src_ips: list[dict] | None) -> pd.DataFrame:
    """Aggregate ``src_ips`` event counts by country.

    Args:
        src_ips: The ``src_ips`` array of an identity summary.

    Returns:
        A DataFrame with ``country`` and ``count`` columns, sorted by count desc.
        Empty when there is no source-IP data.
    """
    rows: dict[str, int] = {}
    for entry in src_ips or []:
        country = extract_country(entry.get("value", ""))
        rows[country] = rows.get(country, 0) + int(entry.get("count", 0) or 0)

    if not rows:
        return pd.DataFrame(columns=["country", "count"])

    df = pd.DataFrame(
        sorted(rows.items(), key=lambda kv: kv[1], reverse=True),
        columns=["country", "count"],
    )
    return df


def activity_timeline(summary: dict) -> pd.DataFrame:
    """Build a Gantt-style timeline of abused-API activity for one identity.

    Combines ``abused_apis_success`` and ``abused_apis_failed`` into rows of
    ``api`` / ``status`` / ``start`` / ``end`` / ``count`` with parsed timestamps,
    suitable for ``plotly.express.timeline``.

    Args:
        summary: A single identity summary object.

    Returns:
        A DataFrame of timeline rows; empty when no abused APIs have parseable
        timestamps.
    """
    rows = []
    for status, key in (
        ("success", "abused_apis_success"),
        ("failed", "abused_apis_failed"),
    ):
        for entry in summary.get(key) or []:
            rows.append(
                {
                    "api": entry.get("api", ""),
                    "status": status,
                    "start": entry.get("first_seen"),
                    "end": entry.get("last_seen"),
                    "count": entry.get("count", 0),
                }
            )

    df = pd.DataFrame(rows)
    if df.empty:
        return df

    df["start"] = pd.to_datetime(df["start"], errors="coerce")
    df["end"] = pd.to_datetime(df["end"], errors="coerce")
    df = df.dropna(subset=["start", "end"]).reset_index(drop=True)
    return df
