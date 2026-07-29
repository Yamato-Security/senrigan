"""The fitness contract must cover exactly what the bundles query.

``agent/suzaku_db.py`` refuses a Suzaku file that lacks a column the shipped
datasets select (PLAN_SUZAKU_MULTI_DB.md F-1) — a metrics run without
``--geo-ip`` is the case that motivated it. That gate is only worth anything if
``REQUIRED_COLUMNS`` and the dataset YAML cannot drift apart.

Rather than parse SQL, each test builds a **reduced** copy of the fixture
holding only the columns ``REQUIRED_COLUMNS`` promises — with the fixture's own
types, so ``unnest``, ``date_diff`` and ``FILTER (WHERE …)`` still work — and
runs the real dataset SQL against it. A column the SQL needs but the contract
omits fails to bind, which is the drift this catches.
"""

from __future__ import annotations

import sys
from pathlib import Path

import duckdb
import pytest
import yaml

ASSETS = Path(__file__).resolve().parent.parent / "assets"
REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "sample" / "suzaku" / "fixtures"

# The detection module lives in agent/ and is bind-mounted into the Superset
# init container; the Superset image cannot install the agent package, so the
# import path is set up the same way here.
AGENT_DIR = str(REPO_ROOT / "agent")
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from suzaku_db import (  # noqa: E402 — needs AGENT_DIR on sys.path
    GEO_COLUMNS,
    META_TABLE,
    REQUIRED_COLUMNS,
    SuzakuKind,
)

# Bundle directory -> (fixture file, the command it serves).
BUNDLES: dict[str, tuple[str, SuzakuKind]] = {
    "suzaku_timeline": ("suzaku-aws-ct-timeline.duckdb", SuzakuKind.TIMELINE),
    "suzaku_summary": ("suzaku-aws-ct-summary.duckdb", SuzakuKind.SUMMARY),
    "suzaku_metrics": ("suzaku-aws-ct-metrics.duckdb", SuzakuKind.METRICS),
}

ALL_BUNDLES = list(BUNDLES)


def _datasets(bundle: str) -> list[Path]:
    """Return the bundle's dataset YAML files."""
    return sorted((ASSETS / bundle / "datasets").glob("*.yaml"))


def _reduced_fixture(tmp_path: Path, bundle: str) -> Path:
    """Build a copy of the fixture holding only the promised columns.

    ``suzaku_meta`` is copied whole: it drives the provenance header, not the
    data charts, so it is deliberately outside the fitness contract.

    Args:
        tmp_path: Directory for the reduced database.
        bundle:   Bundle name, keying :data:`BUNDLES`.

    Returns:
        Path to the reduced DuckDB file.
    """
    fixture_name, kind = BUNDLES[bundle]
    reduced = tmp_path / f"{bundle}-reduced.duckdb"
    conn = duckdb.connect(str(reduced))
    try:
        conn.execute(f"ATTACH '{FIXTURE_DIR / fixture_name}' AS src (READ_ONLY)")
        for table, columns in REQUIRED_COLUMNS[kind].items():
            projection = ", ".join(f'"{column}"' for column in columns)
            conn.execute(
                f'CREATE TABLE "{table}" AS ' f'SELECT {projection} FROM src."{table}"'
            )
        conn.execute(f"CREATE TABLE {META_TABLE} AS SELECT * FROM src.{META_TABLE}")
    finally:
        conn.close()
    return reduced


@pytest.mark.parametrize("bundle", ALL_BUNDLES)
def test_required_columns_are_enough_to_run_every_dataset(
    bundle: str, tmp_path: Path
) -> None:
    """A file with exactly the promised columns must serve the whole bundle.

    Fails when a dataset starts selecting a column the fitness gate does not
    demand — the gate would then admit a file the dashboard cannot query.
    """
    reduced = _reduced_fixture(tmp_path, bundle)
    conn = duckdb.connect(str(reduced), read_only=True)
    try:
        for path in _datasets(bundle):
            sql = yaml.safe_load(path.read_text(encoding="utf-8"))["sql"]
            conn.execute(f"SELECT * FROM ({sql}) AS _t LIMIT 1")
    finally:
        conn.close()


@pytest.mark.parametrize("bundle", ALL_BUNDLES)
def test_required_columns_all_exist_in_real_output(bundle: str) -> None:
    """The contract must not demand a column Suzaku never writes."""
    fixture_name, kind = BUNDLES[bundle]
    conn = duckdb.connect(str(FIXTURE_DIR / fixture_name), read_only=True)
    try:
        for table, columns in REQUIRED_COLUMNS[kind].items():
            present = {
                row[0].lower()
                for row in conn.execute(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'main' AND table_name = ?",
                    [table],
                ).fetchall()
            }
            missing = [c for c in columns if c.lower() not in present]
            assert not missing, f"{bundle}: {table} has no {missing}"
    finally:
        conn.close()


def test_the_metrics_contract_demands_the_geo_columns() -> None:
    """The Metrics dashboard charts them, so a non-geo run cannot serve it."""
    metrics = REQUIRED_COLUMNS[SuzakuKind.METRICS]["metrics"]
    assert {"SrcASN", "SrcCity", "SrcCountry"} <= set(metrics)


@pytest.mark.parametrize("kind", [SuzakuKind.TIMELINE, SuzakuKind.SUMMARY])
def test_only_the_metrics_contract_demands_geo(kind: SuzakuKind) -> None:
    """Suzaku writes GeoIP columns to `metrics` only.

    Demanding them elsewhere would reject every file of that kind, geo run or
    not — the exact failure mode this gate exists to prevent, inverted.
    """
    demanded = {
        column for columns in REQUIRED_COLUMNS[kind].values() for column in columns
    }
    assert not demanded & set(GEO_COLUMNS)


@pytest.mark.parametrize("bundle", ALL_BUNDLES)
def test_every_contract_table_is_a_bundle_table(bundle: str) -> None:
    """A table in the contract that no dataset reads would reject files for nothing."""
    _, kind = BUNDLES[bundle]
    sql_text = " ".join(
        yaml.safe_load(path.read_text(encoding="utf-8"))["sql"]
        for path in _datasets(bundle)
    )
    for table in REQUIRED_COLUMNS[kind]:
        assert table in sql_text, f"{bundle}: no dataset reads {table}"
