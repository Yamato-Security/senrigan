#!/usr/bin/env python3
"""Generate trimmed Suzaku DuckDB fixtures for the Senrigan test suites.

Suzaku's real ``aws-ct-timeline`` output is hundreds of megabytes (the reference
run is 1,925,150 rows / 236 MiB), which must never enter git history.  This
script derives small, committed fixtures from a full-size run so that tests can
execute real SQL against real Suzaku schemas.

Usage::

    python3 sample/suzaku/generate_fixtures.py                  # default paths
    python3 sample/suzaku/generate_fixtures.py --source <dir> --out <dir>

Trimming rules:

* ``timeline`` — a per-``Level`` quota (see :data:`LEVEL_QUOTAS`) so every
  severity, including the three ``critical`` rows, survives.  Rows are picked in
  a stable order (``Timestamp``, ``RuleID``, ``EventID``) so a regenerated
  fixture holds the same rows.
* ``summary`` / ``metrics`` — copied whole; they are already small.

The output is *content*-reproducible, not byte-reproducible: DuckDB block layout
is not stable across writes, so regenerating always shows a git diff.  Only
regenerate when the fixture content must change.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

import duckdb

# Row quota per timeline Level.  Sized so every Level is represented while the
# fixture stays a few MB.  Levels absent from the source are simply skipped.
LEVEL_QUOTAS: dict[str, int] = {
    "critical": 1_000,
    "high": 2_000,
    "medium": 4_000,
    "low": 4_000,
    "informational": 2_000,
}

# Source file name -> fixture file name.
FIXTURES: dict[str, str] = {
    "sample-aws-ct-timeline.duckdb": "suzaku-aws-ct-timeline.duckdb",
    "sample-aws-ct-summary.duckdb": "suzaku-aws-ct-summary.duckdb",
    "sample-aws-ct-metrics.duckdb": "suzaku-aws-ct-metrics.duckdb",
}

DEFAULT_SOURCE = Path(__file__).resolve().parent
DEFAULT_OUT = DEFAULT_SOURCE / "fixtures"


def _quoted_columns(conn: duckdb.DuckDBPyConnection, table: str) -> str:
    """Return *table*'s columns as a quoted, comma-separated select list.

    Suzaku column names are PascalCase and one of them (``AWS-Region``)
    contains a hyphen, so every identifier must be quoted.

    Args:
        conn:  Connection with the source database attached as ``src``.
        table: Table name to describe.

    Returns:
        A select list such as ``"Timestamp", "RuleTitle", "AWS-Region"``.
    """
    rows = conn.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_catalog = 'src' AND table_name = ? "
        "ORDER BY ordinal_position",
        [table],
    ).fetchall()
    return ", ".join(f'"{name}"' for (name,) in rows)


def trim_timeline(source: Path, out: Path) -> int:
    """Write a Level-balanced subset of *source*'s ``timeline`` table to *out*.

    Args:
        source: Full-size ``aws-ct-timeline`` DuckDB file.
        out:    Fixture path to create (overwritten if present).

    Returns:
        The number of rows written.
    """
    out.unlink(missing_ok=True)
    conn = duckdb.connect(str(out))
    try:
        conn.execute(f"ATTACH '{source}' AS src (READ_ONLY)")
        columns = _quoted_columns(conn, "timeline")
        quota_rows = ", ".join(
            f"('{level}', {quota})" for level, quota in LEVEL_QUOTAS.items()
        )
        # A single CTAS keeps the row choice deterministic: rank within each
        # Level by a stable key, then keep ranks below that Level's quota.
        conn.execute(f"""
            CREATE TABLE timeline AS
            WITH quotas(quota_level, quota_rows) AS (VALUES {quota_rows}),
            ranked AS (
                SELECT t.*, row_number() OVER (
                    PARTITION BY t."Level"
                    ORDER BY t."Timestamp", t."RuleID", t."EventID"
                ) AS _rank
                FROM src.timeline t
            )
            SELECT {columns}
            FROM ranked r
            JOIN quotas q ON lower(r."Level") = q.quota_level
            WHERE r._rank <= q.quota_rows
            ORDER BY r."Timestamp", r."RuleID"
            """)
        (count,) = conn.execute("SELECT count(*) FROM timeline").fetchone()
        conn.execute("CHECKPOINT")
        return int(count)
    finally:
        conn.close()


def copy_whole(source: Path, out: Path) -> int:
    """Copy *source* to *out* unchanged and report its total row count.

    Used for ``aws-ct-summary`` and ``aws-ct-metrics``, which are already small
    because Suzaku pre-aggregates them.

    Args:
        source: Suzaku DuckDB file to copy.
        out:    Fixture path to create (overwritten if present).

    Returns:
        The total number of rows across every table in the fixture.
    """
    out.unlink(missing_ok=True)
    shutil.copyfile(source, out)
    conn = duckdb.connect(str(out), read_only=True)
    try:
        tables = [
            name
            for (name,) in conn.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'main' ORDER BY table_name"
            ).fetchall()
        ]
        total = 0
        for table in tables:
            (count,) = conn.execute(f'SELECT count(*) FROM "{table}"').fetchone()
            total += int(count)
        return total
    finally:
        conn.close()


def main() -> int:
    """Generate every fixture, reporting what was written.

    Returns:
        ``0`` on success, ``1`` when no source database was found.
    """
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--source",
        type=Path,
        default=DEFAULT_SOURCE,
        help="directory holding the full-size Suzaku DuckDB files",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="directory to write the trimmed fixtures to",
    )
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    written = 0
    for source_name, fixture_name in FIXTURES.items():
        source = args.source / source_name
        if not source.exists():
            print(f"  · {source_name} not found — skipped")
            continue
        target = args.out / fixture_name
        if "timeline" in source_name:
            rows = trim_timeline(source, target)
        else:
            rows = copy_whole(source, target)
        size_mb = target.stat().st_size / 1024 / 1024
        print(f"  ✓ {fixture_name}  {rows:,} rows  {size_mb:.1f} MiB")
        written += 1

    if not written:
        print(f"\n  No Suzaku databases found in {args.source}/")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
