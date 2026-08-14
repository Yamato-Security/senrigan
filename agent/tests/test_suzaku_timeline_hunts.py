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
from query import apply_filters
from schema import SUZAKU_TACTIC_ABBREVIATIONS

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

# `list_contains("Tactics", 'Impact')` — the literal a tactic filter compares to.
_TACTIC_LITERAL = re.compile(r'list_contains\(\s*"Tactics"\s*,\s*\'([^\']*)\'')

# `"Level" >= 'high'::suzaku_level` — a severity floor.
_LEVEL_FLOOR = re.compile(r'"Level"\s*(?:>=|>)\s*\'(\w+)\'::suzaku_level')

# `count(*) FILTER (WHERE ...)`. A floor inside one of these computes a metric
# column and leaves the row set alone, so only floors outside them are filters.
_FILTER_CLAUSE = re.compile(r"FILTER\s*\([^()]*\)", re.IGNORECASE)


def row_filter_floors(sql: str) -> set[str]:
    """Return the severity floors *sql* applies to its rows, not to its metrics."""
    return set(_LEVEL_FLOOR.findall(_FILTER_CLAUSE.sub("", sql)))


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


# ---------------------------------------------------------------------------
# Does the hunt return the right rows?
#
# Everything above proves a hunt is well-formed SQL against the real schema. A
# query can pass all of it and still be wrong in the one way that matters to an
# analyst: it binds, it runs, and it answers nothing.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("label", "hunt"), SQL_HUNTS, ids=[i for i, _ in SQL_HUNTS])
def test_hunt_returns_rows_under_the_default_severity_filter(
    label: str, hunt: dict, conn: duckdb.DuckDBPyConnection
) -> None:
    """A hunt that is always empty is indistinguishable from a clean environment.

    The page opens on the profile's default severities, so that — not the whole
    table — is the condition a hunt has to produce something under. The fixture
    carries every severity and eight of Suzaku's tactics, so an empty result
    here means the predicate never matches anything, not that the data is quiet.
    """
    sql = apply_filters(
        hunt["sql"],
        profile=SUZAKU_TIMELINE_PROFILE,
        levels=list(SUZAKU_TIMELINE_PROFILE.default_levels),
    )
    assert conn.execute(sql).fetchall(), (
        f"{label}: no rows under the default severity filter — the predicate "
        "matches nothing in a fixture that holds every severity"
    )


@pytest.mark.parametrize(("label", "hunt"), SQL_HUNTS, ids=[i for i, _ in SQL_HUNTS])
def test_hunt_tactic_literals_are_suzaku_abbreviations(label: str, hunt: dict) -> None:
    """`Tactics` holds Suzaku's abbreviations, never the full ATT&CK name.

    `list_contains("Tactics", 'Credential Access')` is valid SQL against a
    VARCHAR[], so nothing else in this file rejects it — it simply matches no
    row, forever.
    """
    for tactic in _TACTIC_LITERAL.findall(hunt["sql"]):
        assert tactic in SUZAKU_TACTIC_ABBREVIATIONS, (
            f"{label}: {tactic!r} is not a Suzaku tactic abbreviation "
            f"({sorted(SUZAKU_TACTIC_ABBREVIATIONS)})"
        )


def test_known_abbreviations_cover_every_tactic_in_the_fixture(
    conn: duckdb.DuckDBPyConnection,
) -> None:
    """The pinned vocabulary is checked against real Suzaku output, not trusted."""
    present = {
        tactic
        for (tactic,) in conn.execute(
            'SELECT DISTINCT unnest("Tactics") FROM timeline'
        ).fetchall()
    }
    unknown = present - SUZAKU_TACTIC_ABBREVIATIONS
    assert not unknown, f"fixture holds tactics the constant omits: {sorted(unknown)}"


@pytest.mark.parametrize(("label", "hunt"), SQL_HUNTS, ids=[i for i, _ in SQL_HUNTS])
def test_hunt_declares_the_severity_floor_it_hardcodes(label: str, hunt: dict) -> None:
    """Severity belongs to the sidebar unless the hunt's meaning fixes it.

    `apply_filters` has already narrowed the rows to the severities the analyst
    selected. A second, hardcoded floor is the stricter of the two, so widening
    the sidebar to `low` empties the hunt with no explanation. A hunt that is
    *defined* by its floor — "Critical & High Detections" — keeps it and says so
    in `min_level`, which is what makes the silence intentional and reviewable.
    """
    floors = row_filter_floors(hunt["sql"])
    declared = hunt.get("min_level")

    assert floors == ({declared} if declared else set()), (
        f"{label}: SQL floors {sorted(floors)} vs min_level {declared!r} — "
        "declare the floor in min_level or let the sidebar own severity"
    )
    if declared:
        assert declared in SUZAKU_TIMELINE_PROFILE.level_order, f"{label}: {declared!r}"


@pytest.mark.parametrize(("label", "hunt"), SQL_HUNTS, ids=[i for i, _ in SQL_HUNTS])
def test_row_level_hunts_project_the_event_id(label: str, hunt: dict) -> None:
    """A detection an analyst cannot cite is a detection they cannot escalate.

    `EventID` is the join back to the raw CloudTrail event on the Senrigan page,
    and the only value an IR ticket can quote. Aggregates are exempt: they
    describe a population, not an event.
    """
    if "GROUP BY" in hunt["sql"].upper():
        return
    assert '"EventID"' in hunt["sql"], f"{label}: row-level hunt without an EventID"


@pytest.mark.parametrize(("label", "hunt"), SQL_HUNTS, ids=[i for i, _ in SQL_HUNTS])
def test_bar_chart_axes_match_the_result_columns(
    label: str, hunt: dict, conn: duckdb.DuckDBPyConnection
) -> None:
    """`chart.x` is the category, `chart.y` the measure — never the reverse.

    `_render_bar_chart` draws `px.bar(x=chart.y, y=chart.x, orientation="h")`,
    mirroring its own fallback of "first non-numeric column, all numeric
    columns". Swapping the two still renders, which is why this went unnoticed:
    the bars come out plotted against a string axis and mean nothing.
    """
    chart = hunt.get("chart")
    if not chart or chart.get("type") != "bar":
        return

    frame = conn.execute(hunt["sql"]).fetchdf()
    numeric = set(frame.select_dtypes(include="number").columns)

    x_col = chart.get("x")
    y_cols = chart.get("y", [])
    y_cols = [y_cols] if isinstance(y_cols, str) else list(y_cols)

    assert x_col in frame.columns, f"{label}: chart.x {x_col!r} is not selected"
    assert (
        x_col not in numeric
    ), f"{label}: chart.x {x_col!r} is a measure, not a category"
    for y_col in y_cols:
        assert y_col in frame.columns, f"{label}: chart.y {y_col!r} is not selected"
        assert (
            y_col in numeric
        ), f"{label}: chart.y {y_col!r} is a category, not a measure"


def test_a_hunt_surfaces_detections_with_no_principal(
    conn: duckdb.DuckDBPyConnection,
) -> None:
    """Every identity hunt filters `"UserARN" IS NOT NULL`, so nothing shows these.

    AWS redacts the identity of a failed console login, and service-principal
    calls carry no ARN at all. Both are detections; without a hunt of their own
    they are invisible on this page.
    """
    expected = conn.execute(
        'SELECT count(*) FROM timeline WHERE "UserARN" IS NULL'
    ).fetchone()[0]
    assert expected, "fixture has no unattributed rows to cover"

    hunt = next((h for h in HUNTS if "Unattributed" in h["label"]), None)
    assert hunt, "no hunt covers detections that carry no principal ARN"

    rows = conn.execute(hunt["sql"]).fetchall()
    assert len(rows) >= expected, f"covers {len(rows)} of {expected} unattributed rows"
