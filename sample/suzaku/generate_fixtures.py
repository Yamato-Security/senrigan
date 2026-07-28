#!/usr/bin/env python3
"""Generate trimmed Suzaku DuckDB fixtures for the Senrigan test suites.

Suzaku's real ``aws-ct-timeline`` output is hundreds of megabytes (the reference
run is 1,206,049 rows / 200 MiB), which must never enter git history.  This
script derives small, committed fixtures from a full-size run so that tests can
execute real SQL against real Suzaku schemas.

Usage::

    python3 sample/suzaku/generate_fixtures.py                  # default paths
    python3 sample/suzaku/generate_fixtures.py --source <dir> --out <dir>

Trimming rules:

* ``timeline`` — a per-``Level`` quota (see :data:`LEVEL_QUOTAS`) so every
  severity, including the rare ``critical`` rows, survives.  Rows are picked in
  a stable order (``Timestamp``, ``RuleID``, ``EventID``) so a regenerated
  fixture holds the same rows.
* ``summary`` / ``metrics`` — copied whole; they are already small.
* ``suzaku_meta`` — copied from the source, with ``output_rows`` rewritten to the
  fixture's own row count so the file stays internally consistent.

Two schema details are reproduced deliberately, because the code under test
depends on them:

* ``Level`` is restored to Suzaku's **named** ``suzaku_level`` ENUM.  A plain
  ``CREATE TABLE AS SELECT`` keeps the ENUM but loses its name, and a threshold
  filter (``"Level" >= 'high'::suzaku_level``) only binds against the named type.
* ``metrics`` always carries the three GeoIP columns.  Suzaku emits them only
  when ``--geo-ip`` ran, and the Superset metrics dashboard requires them, so a
  source produced without ``--geo-ip`` gets them added as typed NULL columns and
  the script says so.

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

# Suzaku's named severity type (src/core/duckdb_out.rs: LEVEL_TYPE / LEVEL_ENUM).
LEVEL_TYPE = "suzaku_level"
LEVEL_ENUM = "ENUM('informational','low','medium','high','critical')"

# GeoIP columns Suzaku adds to `metrics` under --geo-ip, in write order.
GEO_COLUMNS: tuple[str, ...] = ("SrcASN", "SrcCity", "SrcCountry")

# Provenance table present in every Suzaku DuckDB file since schema_version 1.
META_TABLE = "suzaku_meta"

# Source file name -> fixture file name.
FIXTURES: dict[str, str] = {
    "sample-timeline.duckdb": "suzaku-aws-ct-timeline.duckdb",
    "sample-summary.duckdb": "suzaku-aws-ct-summary.duckdb",
    "sample-metrics.duckdb": "suzaku-aws-ct-metrics.duckdb",
}

DEFAULT_SOURCE = Path(__file__).resolve().parent
DEFAULT_OUT = DEFAULT_SOURCE / "fixtures"


def _quoted_columns(conn: duckdb.DuckDBPyConnection, table: str) -> str:
    """Return *table*'s columns as a quoted, comma-separated select list.

    Suzaku column names are PascalCase, so every identifier must be quoted.

    Args:
        conn:  Connection with the source database attached as ``src``.
        table: Table name to describe.

    Returns:
        A select list such as ``"Timestamp", "RuleTitle", "AwsRegion"``.
    """
    rows = conn.execute(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_catalog = 'src' AND table_name = ? "
        "ORDER BY ordinal_position",
        [table],
    ).fetchall()
    return ", ".join(f'"{name}"' for (name,) in rows)


def _copy_meta(conn: duckdb.DuckDBPyConnection, rows: int) -> None:
    """Copy ``suzaku_meta`` from the attached ``src`` database into the fixture.

    ``output_rows`` is rewritten to *rows* so the fixture does not claim the
    row count of the full-size run it was trimmed from. Everything else — the
    Suzaku version, the command, the ruleset revision, the timezone — is
    provenance of the real run and is kept verbatim.

    Args:
        conn: Connection with the source attached as ``src``.
        rows: Row count of the fixture's main table.
    """
    conn.execute(f"CREATE TABLE {META_TABLE} AS SELECT * FROM src.{META_TABLE}")
    conn.execute(f"UPDATE {META_TABLE} SET output_rows = ?", [rows])


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
            JOIN quotas q ON lower(r."Level"::VARCHAR) = q.quota_level
            WHERE r._rank <= q.quota_rows
            ORDER BY r."Timestamp", r."RuleID"
            """)
        # CTAS keeps the ENUM but not its name, and the name is what makes
        # `"Level" >= 'high'::suzaku_level` bind.
        conn.execute(f"CREATE TYPE {LEVEL_TYPE} AS {LEVEL_ENUM}")
        conn.execute(f'ALTER TABLE timeline ALTER "Level" TYPE {LEVEL_TYPE}')

        (count,) = conn.execute("SELECT count(*) FROM timeline").fetchone()
        _copy_meta(conn, int(count))
        conn.execute("CHECKPOINT")
        return int(count)
    finally:
        conn.close()


def _add_missing_geo_columns(out: Path) -> bool:
    """Add the ``--geo-ip`` columns to *out*'s ``metrics`` table when absent.

    Suzaku writes ``SrcASN`` / ``SrcCity`` / ``SrcCountry`` only when the run was
    enriched, but the Superset metrics dashboard requires them, so the fixture
    always has to model an enriched run. Adding them as typed NULL columns
    reproduces exactly the shape ``--geo-ip`` produces when enrichment finds
    nothing, which is what the reference dataset's synthetic IPs yield anyway.

    Args:
        out: Fixture to inspect and, if needed, extend in place.

    Returns:
        Whether any column had to be added.
    """
    conn = duckdb.connect(str(out))
    try:
        present = {
            name
            for (name,) in conn.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = 'main' AND table_name = 'metrics'"
            ).fetchall()
        }
        missing = [column for column in GEO_COLUMNS if column not in present]
        for column in missing:
            conn.execute(f'ALTER TABLE metrics ADD COLUMN "{column}" VARCHAR')
        if missing:
            conn.execute("CHECKPOINT")
        return bool(missing)
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
        if "metrics" in source_name and _add_missing_geo_columns(target):
            print(
                f"    ! {source_name} was produced without --geo-ip; "
                f"{', '.join(GEO_COLUMNS)} added as NULL columns so the fixture "
                "matches what the metrics dashboard requires."
            )
        written += 1

    if not written:
        print(f"\n  No Suzaku databases found in {args.source}/")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
