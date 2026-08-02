"""Tests for the built-in Suzaku timeline hunts.

Every hunt runs for real against the committed fixture, which is what catches
the mistakes this dataset invites: an unquoted PascalCase identifier, an uncast
severity threshold, a placeholder comparison where the column is NULL-able, or
a missing LIMIT on a table that has millions of rows in production.
"""

from __future__ import annotations

import re
from pathlib import Path

import duckdb
import pytest
import yaml

from profiles import SUZAKU_TIMELINE_PROFILE

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "sample"
    / "suzaku"
    / "fixtures"
    / "suzaku-aws-ct-timeline.duckdb"
)

HUNTS: list[dict] = yaml.safe_load(
    SUZAKU_TIMELINE_PROFILE.hunts_path.read_text(encoding="utf-8")
)

# Hunts carrying SQL, as (id, hunt) pairs for readable parametrize output.
SQL_HUNTS = [(hunt["label"], hunt) for hunt in HUNTS if hunt.get("sql", "").strip()]

_TRAILING_LIMIT = re.compile(r"\bLIMIT\s+(\d+)\s*$", re.IGNORECASE)
_QUOTED_IDENTIFIER = re.compile(r'"([^"]+)"')
_VALID_TID = re.compile(r"^T\d{4}(\.[A-Z]?\d{3})?$")


@pytest.fixture(scope="module")
def conn() -> duckdb.DuckDBPyConnection:
    """A read-only connection to the timeline fixture, shared by the module."""
    connection = duckdb.connect(str(FIXTURE), read_only=True)
    yield connection
    connection.close()


@pytest.fixture(scope="module")
def timeline_columns(conn: duckdb.DuckDBPyConnection) -> set[str]:
    """Column names of the fixture's ``timeline`` table."""
    return {
        name
        for (name,) in conn.execute(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'timeline'"
        ).fetchall()
    }


def test_hunts_file_is_a_non_empty_list() -> None:
    """A malformed YAML would silently render an empty sidebar."""
    assert isinstance(HUNTS, list)
    assert len(HUNTS) >= 15


@pytest.mark.parametrize(("label", "hunt"), SQL_HUNTS, ids=[i for i, _ in SQL_HUNTS])
def test_hunt_has_required_keys(label: str, hunt: dict) -> None:
    """Test 19a: the sidebar, reports and bulk runner all read these keys."""
    for key in ("category", "label", "description", "prompt", "sql"):
        assert hunt.get(key), f"{label}: missing {key}"


def test_hunt_labels_are_unique() -> None:
    """Test 19b: duplicate labels collide as Streamlit widget keys."""
    labels = [hunt["label"] for hunt in HUNTS]
    assert len(labels) == len(set(labels))


def test_every_hunt_ships_runnable_sql() -> None:
    """The page must work without an API key, so every hunt needs SQL."""
    assert len(SQL_HUNTS) == len(HUNTS)


@pytest.mark.parametrize(("label", "hunt"), SQL_HUNTS, ids=[i for i, _ in SQL_HUNTS])
def test_hunt_sql_declares_order_by_and_limit(label: str, hunt: dict) -> None:
    """Test 22: an un-ORDERed or un-LIMITed query is never right on this table."""
    sql = hunt["sql"]
    assert "ORDER BY" in sql.upper(), f"{label}: no ORDER BY"
    assert _TRAILING_LIMIT.search(sql.strip()), f"{label}: no trailing LIMIT"


@pytest.mark.parametrize(("label", "hunt"), SQL_HUNTS, ids=[i for i, _ in SQL_HUNTS])
def test_hunt_sql_only_references_real_columns(
    label: str, hunt: dict, timeline_columns: set[str]
) -> None:
    """Test 21: every quoted identifier must be a column Suzaku really writes.

    The convention is that all columns are double-quoted, so this doubles as a
    check that no PascalCase identifier was left bare.
    """
    referenced = set(_QUOTED_IDENTIFIER.findall(hunt["sql"]))
    unknown = referenced - timeline_columns
    assert not unknown, f"{label}: unknown column(s) {sorted(unknown)}"


@pytest.mark.parametrize(("label", "hunt"), SQL_HUNTS, ids=[i for i, _ in SQL_HUNTS])
def test_hunt_sql_validates(
    label: str, hunt: dict, conn: duckdb.DuckDBPyConnection
) -> None:
    """Test 20a: EXPLAIN proves the SQL binds against the real schema."""
    conn.execute(f"EXPLAIN {hunt['sql']}")


@pytest.mark.parametrize(("label", "hunt"), SQL_HUNTS, ids=[i for i, _ in SQL_HUNTS])
def test_hunt_sql_respects_its_own_limit(
    label: str, hunt: dict, conn: duckdb.DuckDBPyConnection
) -> None:
    """Test 20b: run it for real and confirm the declared cap holds."""
    sql = hunt["sql"].strip()
    declared = int(_TRAILING_LIMIT.search(sql).group(1))
    rows = conn.execute(sql).fetchall()
    assert len(rows) <= declared, f"{label}: returned {len(rows)} rows"


@pytest.mark.parametrize(("label", "hunt"), SQL_HUNTS, ids=[i for i, _ in SQL_HUNTS])
def test_hunt_sql_never_casts_the_typed_timestamp(label: str, hunt: dict) -> None:
    """`Timestamp` is a real TIMESTAMP since schema_version 1 — a CAST is stale."""
    assert (
        'CAST("Timestamp"' not in hunt["sql"]
    ), f"{label}: casts an already-typed TIMESTAMP"


@pytest.mark.parametrize(("label", "hunt"), SQL_HUNTS, ids=[i for i, _ in SQL_HUNTS])
def test_hunt_sql_casts_every_severity_threshold(label: str, hunt: dict) -> None:
    """DuckDB compares an ENUM against a bare string literal as text.

    `"Level" >= 'high'` therefore means the alphabetical `'high' <= 'informational'`
    and silently returns the wrong rows; only the `::suzaku_level` cast compares
    by severity. Equality and IN are unaffected.
    """
    for match in re.finditer(r'"Level"\s*(>=|>|<=|<)\s*(\S+)', hunt["sql"]):
        assert "::suzaku_level" in match.group(
            2
        ), f"{label}: uncast severity threshold {match.group(0)!r}"


@pytest.mark.parametrize(("label", "hunt"), SQL_HUNTS, ids=[i for i, _ in SQL_HUNTS])
def test_hunt_sql_uses_null_not_the_dash_placeholder(label: str, hunt: dict) -> None:
    """Suzaku's DuckDB output writes NULL, so `<> '-'` never filters anything."""
    assert "'-'" not in hunt["sql"], (
        f"{label}: compares against the '-' placeholder, which the DuckDB "
        "output no longer contains"
    )


@pytest.mark.parametrize(("label", "hunt"), SQL_HUNTS, ids=[i for i, _ in SQL_HUNTS])
def test_hunt_techniques_are_well_formed(label: str, hunt: dict) -> None:
    """Test 23: a malformed tid breaks the technique caption and the report."""
    for technique in hunt.get("techniques") or []:
        tid = technique.get("tid", "")
        assert _VALID_TID.match(tid), f"{label}: invalid tid {tid!r}"
        assert technique.get("name")
        assert technique.get("summary")
        assert str(technique.get("url", "")).startswith("https://")


@pytest.mark.parametrize(("label", "hunt"), SQL_HUNTS, ids=[i for i, _ in SQL_HUNTS])
def test_hunt_chart_config_is_supported(label: str, hunt: dict) -> None:
    """An unknown chart type renders nothing, silently losing the visual."""
    chart = hunt.get("chart")
    if chart is None:
        return
    assert chart.get("type") in ("bar", "timeseries"), label
    if chart["type"] == "timeseries":
        assert chart.get("bucket") in ("hour", "day", "week", "month"), label


def test_categories_are_a_small_stable_set() -> None:
    """The sidebar groups by category; a typo would create a one-entry group."""
    categories = {hunt["category"] for hunt in HUNTS}
    assert 4 <= len(categories) <= 8, sorted(categories)


@pytest.mark.parametrize(("label", "hunt"), SQL_HUNTS, ids=[i for i, _ in SQL_HUNTS])
def test_hunt_sql_still_validates_with_ui_filters_applied(
    label: str, hunt: dict, conn: duckdb.DuckDBPyConnection
) -> None:
    """The page always injects the severity/date CTE, so validate that form too."""
    from datetime import date

    from query import apply_filters

    filtered = apply_filters(
        hunt["sql"],
        profile=SUZAKU_TIMELINE_PROFILE,
        start_date=date(2017, 1, 1),
        end_date=date(2030, 1, 1),
        levels=["critical", "high", "medium"],
    )
    conn.execute(f"EXPLAIN {filtered}")


@pytest.mark.parametrize("needle", ["Technique Coverage", "Tactic Breakdown"])
def test_attack_hunts_return_rows_from_the_fixture(
    needle: str, conn: duckdb.DuckDBPyConnection
) -> None:
    """`Tactics` / `TechniqueIDs` are lists — unnesting the wrong one is empty."""
    hunt = next(h for h in HUNTS if needle in h["label"])
    rows = conn.execute(hunt["sql"]).fetchall()
    assert rows, f"{needle}: no rows — check the list column being unnested"


def test_severity_ordering_puts_critical_first(
    conn: duckdb.DuckDBPyConnection,
) -> None:
    """`ORDER BY "Level" DESC` must be severity order, not alphabetical."""
    hunt = next(h for h in HUNTS if "Detection Volume by Severity" in h["label"])
    levels = [str(row[0]) for row in conn.execute(hunt["sql"]).fetchall()]
    assert levels[0] == "critical", levels
