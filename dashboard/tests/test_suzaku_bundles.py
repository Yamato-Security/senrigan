"""Structural tests for the Suzaku Superset asset bundles.

Parametrized over every Suzaku bundle, so a bundle added later is checked
automatically.

The checks that matter most here are the ones a human reviewer cannot do by
reading YAML: that each virtual dataset's SQL actually runs against real Suzaku
output, and that its declared temporal column really comes back as a timestamp.
"""

from __future__ import annotations

import re
from pathlib import Path

import duckdb
import pytest
import yaml

ASSETS = Path(__file__).resolve().parent.parent / "assets"
FIXTURE_DIR = Path(__file__).resolve().parents[2] / "sample" / "suzaku" / "fixtures"

# Bundle directory -> the Suzaku fixture its datasets must run against.
BUNDLES: dict[str, str] = {
    "suzaku_timeline": "suzaku-aws-ct-timeline.duckdb",
    "suzaku_summary": "suzaku-aws-ct-summary.duckdb",
    "suzaku_metrics": "suzaku-aws-ct-metrics.duckdb",
}

ALL_BUNDLE_DIRS = [ASSETS / name for name in BUNDLES]


def _load(path: Path) -> dict:
    """Parse a YAML file."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _charts(bundle: Path) -> list[Path]:
    """Return the bundle's chart YAML files."""
    return sorted((bundle / "charts").glob("*.yaml"))


def _datasets(bundle: Path) -> list[Path]:
    """Return the bundle's dataset YAML files."""
    return sorted((bundle / "datasets").glob("*.yaml"))


def _databases(bundle: Path) -> list[Path]:
    """Return the bundle's database YAML files."""
    return sorted((bundle / "databases").glob("*.yaml"))


def _position_chart_uuids(dashboard: dict) -> set[str]:
    """Return every chart UUID referenced by a dashboard's position tree."""
    return {
        component["meta"]["uuid"]
        for component in dashboard.get("position", {}).values()
        if isinstance(component, dict)
        and component.get("type") == "CHART"
        and "uuid" in component.get("meta", {})
    }


# ---------------------------------------------------------------------------
# Bundle layout (test 5)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bundle", ALL_BUNDLE_DIRS, ids=lambda p: p.name)
def test_bundle_has_the_required_files(bundle: Path) -> None:
    """Test 5: Superset's v1 import needs all four pieces."""
    assert (bundle / "metadata.yaml").exists()
    assert (bundle / "dashboard.yaml").exists()
    assert len(_databases(bundle)) == 1, "exactly one database per bundle"
    assert _datasets(bundle), "at least one dataset"


@pytest.mark.parametrize("bundle", ALL_BUNDLE_DIRS, ids=lambda p: p.name)
def test_metadata_declares_a_dashboard_export(bundle: Path) -> None:
    """A wrong `type` makes Superset reject the whole ZIP."""
    metadata = _load(bundle / "metadata.yaml")
    assert metadata["type"] == "Dashboard"
    assert str(metadata["version"]) == "1.0.0"


@pytest.mark.parametrize("bundle", ALL_BUNDLE_DIRS, ids=lambda p: p.name)
def test_dashboard_has_a_title_uuid_and_slug(bundle: Path) -> None:
    """Without a slug the dashboard is only reachable by numeric id."""
    dashboard = _load(bundle / "dashboard.yaml")
    for key in ("uuid", "dashboard_title", "slug", "position"):
        assert dashboard.get(key), f"{bundle.name}: missing {key}"
    assert dashboard["published"] is True


# ---------------------------------------------------------------------------
# Database connection contract (test 6)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bundle", ALL_BUNDLE_DIRS, ids=lambda p: p.name)
def test_database_yaml_is_read_only_and_uses_the_explicit_driver(
    bundle: Path,
) -> None:
    """Test 6: DU-13/DU-14 plus the read-only rule for third-party files."""
    database = _load(_databases(bundle)[0])
    assert database["sqlalchemy_uri"].startswith("duckdb+duckdb_engine:///")
    assert "?read_only" not in database["sqlalchemy_uri"]
    assert database["extra"]["engine_params"]["connect_args"]["read_only"] is True
    assert database["allow_dml"] is False
    # DU-06: async execution needs a Celery worker that is not deployed.
    assert database.get("allow_run_async") is not True


@pytest.mark.parametrize("bundle", ALL_BUNDLE_DIRS, ids=lambda p: p.name)
def test_database_uuid_matches_the_registration_script(bundle: Path) -> None:
    """The bundle and the bootstrap script must agree on the database UUID."""
    import importlib.util
    import sys

    path = Path(__file__).resolve().parent.parent / "init" / "register_suzaku_dbs.py"
    spec = importlib.util.spec_from_file_location("_szdb_for_bundles", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["_szdb_for_bundles"] = module
    spec.loader.exec_module(module)

    database = _load(_databases(bundle)[0])
    assert database["uuid"] in module.DATABASE_UUIDS.values()
    assert database["database_name"] in module.DATABASE_NAMES.values()


# ---------------------------------------------------------------------------
# UUID uniqueness across every bundle (test 7)
# ---------------------------------------------------------------------------


def test_uuids_are_unique_across_all_bundles() -> None:
    """Test 7: a duplicate UUID silently overwrites another bundle's object."""
    seen: dict[str, Path] = {}
    bundles = ALL_BUNDLE_DIRS + [ASSETS / "cloudtrail_default"]
    for bundle in bundles:
        if not bundle.exists():
            continue
        files = (
            [bundle / "dashboard.yaml"]
            + _databases(bundle)
            + _datasets(bundle)
            + _charts(bundle)
        )
        for path in files:
            uuid = _load(path).get("uuid")
            if uuid is None:
                continue
            # cloudtrail_default and cloudtrail_rare deliberately share database
            # and dataset objects; only collisions with a Suzaku bundle matter.
            assert (
                uuid not in seen or seen[uuid] == path
            ), f"UUID {uuid} used by both {seen.get(uuid)} and {path}"
            seen[uuid] = path


# ---------------------------------------------------------------------------
# Chart wiring (tests 8-10)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bundle", ALL_BUNDLE_DIRS, ids=lambda p: p.name)
def test_charts_reference_a_dataset_in_the_same_bundle(bundle: Path) -> None:
    """Test 8: a dangling dataset_uuid imports as a chart that cannot query."""
    dataset_uuids = {_load(path)["uuid"] for path in _datasets(bundle)}
    for chart in _charts(bundle):
        assert _load(chart)["dataset_uuid"] in dataset_uuids, chart.name


@pytest.mark.parametrize("bundle", ALL_BUNDLE_DIRS, ids=lambda p: p.name)
def test_every_chart_is_placed_and_every_placement_exists(bundle: Path) -> None:
    """Test 9: an unplaced chart is invisible; a stale placement is an error."""
    dashboard = _load(bundle / "dashboard.yaml")
    placed = _position_chart_uuids(dashboard)
    defined = {_load(path)["uuid"] for path in _charts(bundle)}
    assert defined == placed, (
        f"{bundle.name}: defined-but-unplaced={sorted(defined - placed)}, "
        f"placed-but-undefined={sorted(placed - defined)}"
    )


@pytest.mark.parametrize("bundle", ALL_BUNDLE_DIRS, ids=lambda p: p.name)
def test_every_bundle_ships_charts(bundle: Path) -> None:
    """Test 10 (inverted): every bundle now has charts.

    This replaces the empty-template contract the timeline bundle used to be
    held to — a bundle that imports as a chartless shell is a regression now,
    not a milestone.
    """
    assert _charts(bundle), f"{bundle.name}: no charts"


@pytest.mark.parametrize("bundle", ALL_BUNDLE_DIRS, ids=lambda p: p.name)
def test_chart_slice_names_are_unique(bundle: Path) -> None:
    """Duplicate slice names make a dashboard impossible to read."""
    names = [_load(path)["slice_name"] for path in _charts(bundle)]
    assert len(names) == len(set(names))


# ---------------------------------------------------------------------------
# Datasets run for real (test 11)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bundle", ALL_BUNDLE_DIRS, ids=lambda p: p.name)
def test_every_virtual_dataset_runs_against_the_fixture(bundle: Path) -> None:
    """Test 11: the dataset SQL must bind against real Suzaku output."""
    fixture = FIXTURE_DIR / BUNDLES[bundle.name]
    conn = duckdb.connect(str(fixture), read_only=True)
    try:
        for path in _datasets(bundle):
            dataset = _load(path)
            sql = dataset.get("sql")
            assert sql, f"{path.name}: Suzaku datasets must be virtual (sql:)"
            conn.execute(f"SELECT * FROM ({sql}) AS _t LIMIT 1")
    finally:
        conn.close()


@pytest.mark.parametrize("bundle", ALL_BUNDLE_DIRS, ids=lambda p: p.name)
def test_declared_columns_match_the_dataset_sql(bundle: Path) -> None:
    """A column declared but not selected renders as an empty chart axis."""
    fixture = FIXTURE_DIR / BUNDLES[bundle.name]
    conn = duckdb.connect(str(fixture), read_only=True)
    try:
        for path in _datasets(bundle):
            dataset = _load(path)
            produced = {
                description[0]
                for description in conn.execute(
                    f"SELECT * FROM ({dataset['sql']}) AS _t LIMIT 0"
                ).description
            }
            declared = {column["column_name"] for column in dataset["columns"]}
            assert declared <= produced, (
                f"{path.name}: declared but not produced: "
                f"{sorted(declared - produced)}"
            )
    finally:
        conn.close()


@pytest.mark.parametrize("bundle", ALL_BUNDLE_DIRS, ids=lambda p: p.name)
def test_main_dttm_col_is_really_temporal(bundle: Path) -> None:
    """Superset needs a real timestamp; Suzaku stores its time as VARCHAR."""
    fixture = FIXTURE_DIR / BUNDLES[bundle.name]
    conn = duckdb.connect(str(fixture), read_only=True)
    try:
        for path in _datasets(bundle):
            dataset = _load(path)
            dttm = dataset.get("main_dttm_col")
            if not dttm:
                continue
            (value,) = conn.execute(
                f'SELECT typeof("{dttm}") FROM ({dataset["sql"]}) AS _t LIMIT 1'
            ).fetchone()
            assert (
                "TIMESTAMP" in value.upper() or "DATE" in value.upper()
            ), f"{path.name}: main_dttm_col {dttm} is {value}"
            declared = {column["column_name"]: column for column in dataset["columns"]}
            assert declared[dttm]["is_dttm"] is True
    finally:
        conn.close()


@pytest.mark.parametrize("bundle", ALL_BUNDLE_DIRS, ids=lambda p: p.name)
def test_dataset_metrics_are_computable(bundle: Path) -> None:
    """A metric with a typo silently renders every chart using it as empty."""
    fixture = FIXTURE_DIR / BUNDLES[bundle.name]
    conn = duckdb.connect(str(fixture), read_only=True)
    try:
        for path in _datasets(bundle):
            dataset = _load(path)
            for metric in dataset.get("metrics") or []:
                expression = metric["expression"]
                conn.execute(f"SELECT {expression} FROM ({dataset['sql']}) AS _t")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Field-agnostic metrics dashboard (test 12)
# ---------------------------------------------------------------------------


def test_metrics_bundle_never_hardcodes_a_field_name() -> None:
    """Test 12: `Field` is whatever the analyst passed to `suzaku -f`."""
    bundle = ASSETS / "suzaku_metrics"
    if not bundle.exists():
        pytest.skip("suzaku_metrics bundle not present")
    for path in _charts(bundle) + _datasets(bundle):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue  # comments may name eventName as an example
            assert (
                "'eventName'" not in stripped
            ), f"{path.name}: hard-codes the eventName field"


# ---------------------------------------------------------------------------
# Chart expressions run for real
# ---------------------------------------------------------------------------


def _chart_sql_expressions(chart: dict) -> list[str]:
    """Return every raw SQL expression a chart embeds.

    Covers ``metric``, ``metrics``, ``timeseries_limit_metric``,
    ``adhoc_filters`` and ad-hoc ``groupby`` / ``x_axis`` columns — every place a
    typo can hide and produce an empty chart rather than an error.
    """
    params = chart.get("params") or {}
    expressions: list[str] = []

    candidates = []
    if isinstance(params.get("metric"), dict):
        candidates.append(params["metric"])
    if isinstance(params.get("x_axis"), dict):
        candidates.append(params["x_axis"])
    for column in params.get("groupby") or []:
        if isinstance(column, dict):
            candidates.append(column)
    if isinstance(params.get("timeseries_limit_metric"), dict):
        candidates.append(params["timeseries_limit_metric"])
    for metric in params.get("metrics") or []:
        if isinstance(metric, dict):
            candidates.append(metric)
    for candidate in candidates:
        if candidate.get("expressionType") == "SQL" and candidate.get("sqlExpression"):
            expressions.append(candidate["sqlExpression"])

    for filter_spec in params.get("adhoc_filters") or []:
        if isinstance(filter_spec, dict) and filter_spec.get("sqlExpression"):
            expressions.append(f"CASE WHEN {filter_spec['sqlExpression']} THEN 1 END")

    return expressions


@pytest.mark.parametrize("bundle", ALL_BUNDLE_DIRS, ids=lambda p: p.name)
def test_chart_expressions_execute_against_the_fixture(bundle: Path) -> None:
    """Every chart metric and filter must be valid SQL for its dataset.

    Superset renders an unparseable expression as an empty chart with an error
    badge, which is easy to miss in a 18-chart dashboard, so they are executed
    here against real Suzaku output.
    """
    datasets = {_load(path)["uuid"]: _load(path) for path in _datasets(bundle)}
    fixture = FIXTURE_DIR / BUNDLES[bundle.name]
    conn = duckdb.connect(str(fixture), read_only=True)
    try:
        for path in _charts(bundle):
            chart = _load(path)
            dataset = datasets[chart["dataset_uuid"]]
            for expression in _chart_sql_expressions(chart):
                conn.execute(f"SELECT {expression} FROM ({dataset['sql']}) AS _t")
    finally:
        conn.close()


@pytest.mark.parametrize("bundle", ALL_BUNDLE_DIRS, ids=lambda p: p.name)
def test_chart_groupby_columns_exist(bundle: Path) -> None:
    """A groupby naming a column the dataset does not select renders nothing."""
    datasets = {_load(path)["uuid"]: _load(path) for path in _datasets(bundle)}
    for path in _charts(bundle):
        chart = _load(path)
        dataset = datasets[chart["dataset_uuid"]]
        declared = {column["column_name"] for column in dataset["columns"]}
        params = chart.get("params") or {}
        for key in ("groupby", "columns"):
            for column in params.get(key) or []:
                if isinstance(column, dict):
                    # Ad-hoc SQL column (e.g. EXTRACT(HOUR FROM ...)); its
                    # expression is executed against the fixture instead.
                    continue
                assert column in declared, f"{path.name}: unknown column {column}"
        granularity = params.get("granularity_sqla")
        if granularity:
            assert granularity in declared, f"{path.name}: unknown time column"


@pytest.mark.parametrize("bundle", ALL_BUNDLE_DIRS, ids=lambda p: p.name)
def test_charts_declare_a_row_limit(bundle: Path) -> None:
    """Suzaku's attribute table has 18 k rows; an unlimited chart is unreadable."""
    for path in _charts(bundle):
        chart = _load(path)
        if chart["viz_type"] == "big_number_total":
            continue  # a single aggregate, no rows to cap
        assert (chart.get("params") or {}).get("row_limit"), path.name


@pytest.mark.parametrize("bundle", ALL_BUNDLE_DIRS, ids=lambda p: p.name)
def test_database_uri_is_an_obvious_placeholder(bundle: Path) -> None:
    """The bundle's URI must never look like a real Suzaku file name.

    Superset re-applies this YAML onto the existing connection on every import,
    so the path here is overwritten by `register_suzaku_dbs.py` afterwards. A
    plausible-looking placeholder hides that: it works exactly as long as the
    analyst happens to name their file the same way, which is how the original
    bug went unnoticed.
    """
    uri = _load(_databases(bundle)[0])["sqlalchemy_uri"]
    assert (
        "_placeholder_rewritten_at_bootstrap" in uri
    ), f"{bundle.name}: placeholder URI must be obviously fake, got {uri}"


# ---------------------------------------------------------------------------
# Timeline bundle: the constraints that come from Suzaku's `timeline` table
# ---------------------------------------------------------------------------

TIMELINE = ASSETS / "suzaku_timeline"

# Suzaku writes SrcASN / SrcCity / SrcCountry into `metrics` only, and never into
# `timeline` — not even for a --geo-ip run.
GEO_COLUMNS = ("src_country", "src_city", "src_asn")

# The tag kinds the suzaku_timeline_tags dataset derives from Suzaku's three
# VARCHAR[] columns.
TAG_TYPES = {"tactic", "technique", "group", "other"}


def _timeline_dataset(table_name: str) -> dict:
    """Return the timeline bundle dataset with the given table_name."""
    for path in _datasets(TIMELINE):
        dataset = _load(path)
        if dataset["table_name"] == table_name:
            return dataset
    raise AssertionError(f"suzaku_timeline: no dataset named {table_name}")


def _timeline_fixture() -> duckdb.DuckDBPyConnection:
    """Open the aws-ct-timeline fixture read-only."""
    return duckdb.connect(str(FIXTURE_DIR / BUNDLES["suzaku_timeline"]), read_only=True)


def test_timeline_bundle_never_references_a_geo_column() -> None:
    """`timeline` has no geo columns, so one reference breaks the whole bundle.

    A dataset is a single SQL string: naming a column Suzaku never writes does
    not blank one chart, it makes every chart in the bundle fail. The draft
    charts in the design notes were written against a geo-carrying schema, so
    this guards against a later copy-paste from them.
    """
    for path in _datasets(TIMELINE) + _charts(TIMELINE):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue  # comments may explain why geo is absent
            for column in GEO_COLUMNS:
                assert column not in stripped, f"{path.name}:{number} names {column}"


def test_timeline_outcome_is_success_or_failed() -> None:
    """`outcome` is derived from ErrorCode, and charts filter on both literals."""
    dataset = _timeline_dataset("suzaku_timeline")
    conn = _timeline_fixture()
    try:
        values = {
            row[0]
            for row in conn.execute(
                f"SELECT DISTINCT outcome FROM ({dataset['sql']}) AS _t"
            ).fetchall()
        }
    finally:
        conn.close()
    assert values == {"Success", "Failed"}


def test_timeline_tags_dataset_emits_only_known_tag_types() -> None:
    """The UNNEST dataset must not invent a tag_type no chart filters on."""
    dataset = _timeline_dataset("suzaku_timeline_tags")
    conn = _timeline_fixture()
    try:
        produced = {
            row[0]
            for row in conn.execute(
                f"SELECT DISTINCT tag_type FROM ({dataset['sql']}) AS _t"
            ).fetchall()
        }
        # The fixture carries tactics and techniques; group/other need a rule
        # set that ships attack.gNNNN tags, so only assert the domain.
        assert produced <= TAG_TYPES, f"unexpected tag_type(s): {produced - TAG_TYPES}"
        assert {"tactic", "technique"} <= produced
    finally:
        conn.close()


def test_tag_charts_filter_on_a_known_tag_type() -> None:
    """A typo'd tag_type renders an empty chart rather than an error."""
    tags_uuid = _timeline_dataset("suzaku_timeline_tags")["uuid"]
    pattern = re.compile(r"tag_type\s*=\s*'([^']+)'")
    for path in _charts(TIMELINE):
        chart = _load(path)
        if chart["dataset_uuid"] != tags_uuid:
            continue
        for filter_spec in (chart.get("params") or {}).get("adhoc_filters") or []:
            for value in pattern.findall(filter_spec.get("sqlExpression") or ""):
                assert value in TAG_TYPES, f"{path.name}: unknown tag_type {value}"


def test_tag_charts_count_detections_distinctly() -> None:
    """One detection with three tactics is three rows in the tags dataset.

    So a metric labelled "detections" there must count distinct events; COUNT(*)
    would silently inflate every ATT&CK chart.
    """
    tags_uuid = _timeline_dataset("suzaku_timeline_tags")["uuid"]
    for path in _charts(TIMELINE):
        chart = _load(path)
        if chart["dataset_uuid"] != tags_uuid:
            continue
        params = chart.get("params") or {}
        candidates = (
            [params["metric"]] if isinstance(params.get("metric"), dict) else []
        )
        candidates += [m for m in (params.get("metrics") or []) if isinstance(m, dict)]
        for metric in candidates:
            if "detection" in str(metric.get("label", "")).lower():
                assert "COUNT(DISTINCT event_id)" in metric.get("sqlExpression", ""), (
                    f"{path.name}: metric {metric.get('label')} counts tag rows, "
                    "not detections"
                )


def test_run_info_chart_is_outside_the_date_range_filter() -> None:
    """`generated_at` is when Suzaku ran, not when anything was detected.

    A dashboard-wide time filter targeting each chart's main temporal column
    would therefore blank the provenance chart for any range that excludes the
    moment Suzaku was run — which is exactly when an analyst goes looking for it.
    """
    dashboard = _load(TIMELINE / "dashboard.yaml")
    run_info_uuid = _load(TIMELINE / "charts" / "run_info.yaml")["uuid"]
    chart_ids = {
        component["meta"]["uuid"]: component["meta"]["chartId"]
        for component in dashboard["position"].values()
        if isinstance(component, dict) and component.get("type") == "CHART"
    }
    time_filters = [
        entry
        for entry in dashboard["metadata"]["native_filter_configuration"]
        if entry["filterType"] == "filter_time"
    ]
    assert time_filters, "the dashboard has no Date Range filter"
    for entry in time_filters:
        assert (
            chart_ids[run_info_uuid] in entry["scope"]["excluded"]
        ), f"{entry['name']}: Suzaku Run Info must be excluded"
