"""Tests for the Suzaku Detections dashboard asset bundle.

The bundle lives in assets/suzaku_detections/ and is packaged into
suzaku_detections.zip by assets/rebuild_suzaku_zip.py.  Its charts read two
datasets written by `ingester suzaku-import`:

  * suzaku_detections      — one row per Suzaku Sigma-rule hit
  * suzaku_detection_tags  — one row per ATT&CK tag on a hit (MITRE tab)

Superset reports most mistakes in these files only at render time, as a red
chart in the browser, so they are checked structurally here instead: required
fields, unique identifiers, and — most importantly — that every column a chart
groups by or filters on is actually declared on the dataset it reads.
"""

import importlib
import os
import re
import subprocess
import sys
import zipfile

import pytest
import yaml

ASSETS = os.path.join(os.path.dirname(__file__), "..", "assets")
BUNDLE = os.path.join(ASSETS, "suzaku_detections")
CHARTS_DIR = os.path.join(BUNDLE, "charts")
DASHBOARD_YAML = os.path.join(BUNDLE, "dashboard.yaml")
DATASETS_DIR = os.path.join(BUNDLE, "datasets")
OUTPUT_ZIP = os.path.join(ASSETS, "suzaku_detections.zip")
REBUILD_SCRIPT = os.path.join(ASSETS, "rebuild_suzaku_zip.py")
INIT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "init"))
BOOTSTRAP = os.path.join(INIT_DIR, "bootstrap.sh")

DETECTIONS_UUID = "7c1f9d2a-6b35-4e88-9a10-0d5f3b7e4c21"
TAGS_UUID = "3e8a5c47-91d2-4fb6-8c03-6a7e2d914b58"
DASHBOARD_UUID = "9b4d7e21-5c68-4a3f-b0d9-1e6c8f2a3457"
# Both Suzaku tables live in the same DuckDB file as cloudtrail_events, so the
# bundle deliberately reuses that connection rather than defining a second one.
DATABASE_UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
TEMPORAL_COLUMN = "detected_at"

REQUIRED_CHART_FIELDS = {
    "uuid",
    "version",
    "dataset_uuid",
    "slice_name",
    "viz_type",
    "params",
}
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
# Visualisation types already proven to render in this Superset build — the
# cloudtrail_default dashboard uses exactly these.
SUPPORTED_VIZ_TYPES = {
    "big_number_total",
    "bar",
    "dist_bar",
    "echarts_timeseries_bar",
    "heatmap",
    "table",
    "world_map",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def load_all_charts() -> list[tuple[str, dict]]:
    """Return (filename, parsed_yaml) for every .yaml in the bundle's charts/."""
    results = []
    for fname in sorted(os.listdir(CHARTS_DIR)):
        if fname.endswith(".yaml"):
            with open(os.path.join(CHARTS_DIR, fname), encoding="utf-8") as fh:
                results.append((fname, yaml.safe_load(fh)))
    return results


def load_dashboard() -> dict:
    with open(DASHBOARD_YAML, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_dataset(fname: str) -> dict:
    with open(os.path.join(DATASETS_DIR, fname), encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def dataset_columns() -> dict[str, set[str]]:
    """Column names declared per dataset uuid."""
    out = {}
    for fname in os.listdir(DATASETS_DIR):
        dataset = load_dataset(fname)
        out[dataset["uuid"]] = {c["column_name"] for c in dataset["columns"]}
    return out


def referenced_columns(chart: dict) -> set[str]:
    """Plain column names a chart groups or plots by.

    Adhoc (SQL expression) entries are skipped — their columns are validated by
    executing the SQL, not by name.
    """
    params = chart.get("params") or {}
    names = set()
    entries = list(params.get("groupby") or [])
    for key in ("x_axis", "entity"):
        value = params.get(key)
        if value is not None:
            entries.append(value)
    for entry in entries:
        if isinstance(entry, str):
            names.add(entry)
    return names


def chart_uuids_from_dashboard(dashboard: dict) -> set[str]:
    return {
        value["meta"]["uuid"]
        for value in dashboard.get("position", {}).values()
        if isinstance(value, dict) and value.get("type") == "CHART"
    }


# ---------------------------------------------------------------------------
# Per-chart structure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fname, chart", load_all_charts())
def test_chart_has_required_fields(fname: str, chart: dict) -> None:
    """Every chart must declare all required top-level fields."""
    missing = REQUIRED_CHART_FIELDS - set(chart.keys())
    assert not missing, f"{fname} is missing fields: {missing}"


@pytest.mark.parametrize("fname, chart", load_all_charts())
def test_chart_uuid_format(fname: str, chart: dict) -> None:
    """Chart UUID must be a valid UUID string."""
    uuid = chart.get("uuid", "")
    assert UUID_RE.match(uuid), f"{fname}: '{uuid}' is not a valid UUID"


@pytest.mark.parametrize("fname, chart", load_all_charts())
def test_chart_targets_a_suzaku_dataset(fname: str, chart: dict) -> None:
    """Charts may only reference the two Suzaku datasets."""
    assert chart.get("dataset_uuid") in (DETECTIONS_UUID, TAGS_UUID), (
        f"{fname}: dataset_uuid '{chart.get('dataset_uuid')}' is neither "
        f"suzaku_detections nor suzaku_detection_tags"
    )


@pytest.mark.parametrize("fname, chart", load_all_charts())
def test_chart_params_not_empty(fname: str, chart: dict) -> None:
    """params must be a non-empty mapping."""
    assert chart.get("params"), f"{fname}: params must not be empty"


@pytest.mark.parametrize("fname, chart", load_all_charts())
def test_chart_uses_a_supported_viz_type(fname: str, chart: dict) -> None:
    """Only visualisation types already proven in this Superset build.

    A viz_type the build does not ship renders as an empty box with no error
    message, which is far harder to diagnose than a failing test.
    """
    assert chart["viz_type"] in SUPPORTED_VIZ_TYPES, (
        f"{fname}: viz_type '{chart['viz_type']}' is not among the types used "
        f"by the existing dashboards: {sorted(SUPPORTED_VIZ_TYPES)}"
    )


@pytest.mark.parametrize("fname, chart", load_all_charts())
def test_chart_declares_the_temporal_column(fname: str, chart: dict) -> None:
    """Every chart must set granularity_sqla to the Suzaku temporal column.

    import_dashboard.py fills in a missing granularity_sqla from the chart's
    dataset, but declaring it here keeps the YAML self-describing and makes a
    copy-paste of `event_time` from the CloudTrail charts fail loudly.
    """
    assert chart["params"].get("granularity_sqla") == TEMPORAL_COLUMN, (
        f"{fname}: granularity_sqla must be '{TEMPORAL_COLUMN}', got "
        f"'{chart['params'].get('granularity_sqla')}'"
    )


@pytest.mark.parametrize("fname, chart", load_all_charts())
def test_chart_metric_option_names_unique(fname: str, chart: dict) -> None:
    """Adhoc metrics need distinct optionName values within a chart.

    Superset keys its metric controls by optionName; duplicates silently
    collapse into one series.
    """
    params = chart["params"]
    metrics = params.get("metrics") or (
        [params["metric"]] if params.get("metric") else []
    )
    names = [
        m["optionName"] for m in metrics if isinstance(m, dict) and "optionName" in m
    ]
    assert len(names) == len(
        set(names)
    ), f"{fname}: duplicate metric optionName in {names}"


@pytest.mark.parametrize("fname, chart", load_all_charts())
def test_chart_columns_exist_in_its_dataset(fname: str, chart: dict) -> None:
    """Every column a chart groups by must be declared on its own dataset.

    This is the mistake that breaks a dashboard import outright: Superset
    raises "Columns missing in dataset" and nothing is imported at all.
    """
    declared = dataset_columns()[chart["dataset_uuid"]]
    missing = referenced_columns(chart) - declared
    assert (
        not missing
    ), f"{fname}: columns not declared on its dataset: {sorted(missing)}"


@pytest.mark.parametrize("fname, chart", load_all_charts())
def test_ip_table_includes_geo_columns(fname: str, chart: dict) -> None:
    """A table listing source_ip must also show its geographic context.

    Mirrors the same rule on the CloudTrail dashboard: a bare IP address gives
    an analyst nothing to act on, and the geo columns are functionally
    dependent on it, so adding them never changes the grouping granularity.
    """
    if chart["viz_type"] != "table":
        return
    groupby = chart["params"].get("groupby") or []
    if "source_ip" not in groupby:
        return
    assert (
        "src_country" in groupby
    ), f"{fname}: table showing source_ip must include src_country"
    assert (
        "src_city" in groupby or "src_asn" in groupby
    ), f"{fname}: table showing source_ip must include src_city or src_asn"


# ---------------------------------------------------------------------------
# Bundle-wide identity
# ---------------------------------------------------------------------------


def test_all_chart_uuids_unique() -> None:
    """No two Suzaku charts may share a UUID."""
    uuids = [c["uuid"] for _, c in load_all_charts()]
    duplicates = {u for u in uuids if uuids.count(u) > 1}
    assert not duplicates, f"Duplicate chart UUIDs detected: {duplicates}"


def test_chart_uuids_do_not_collide_with_cloudtrail() -> None:
    """Suzaku chart UUIDs must not clash with the CloudTrail dashboard's.

    Both bundles are imported into the same Superset metadata database, and
    the assets importer overwrites by UUID — a collision would silently
    replace a CloudTrail chart with a Suzaku one.
    """
    other_dir = os.path.join(ASSETS, "cloudtrail_default", "charts")
    other = set()
    for fname in os.listdir(other_dir):
        if fname.endswith(".yaml"):
            with open(os.path.join(other_dir, fname), encoding="utf-8") as fh:
                other.add(yaml.safe_load(fh)["uuid"])
    mine = {c["uuid"] for _, c in load_all_charts()}
    assert not (
        mine & other
    ), f"UUIDs shared with the CloudTrail dashboard: {mine & other}"


def test_datasets_declare_expected_identity() -> None:
    """Both datasets must carry their fixed UUIDs, table names and time column."""
    detections = load_dataset("suzaku_detections.yaml")
    tags = load_dataset("suzaku_detection_tags.yaml")
    assert detections["uuid"] == DETECTIONS_UUID
    assert detections["table_name"] == "suzaku_detections"
    assert tags["uuid"] == TAGS_UUID
    assert tags["table_name"] == "suzaku_detection_tags"
    for dataset in (detections, tags):
        assert dataset["main_dttm_col"] == TEMPORAL_COLUMN
        assert dataset["database_uuid"] == DATABASE_UUID


def test_dataset_temporal_column_is_marked_dttm() -> None:
    """detected_at must be flagged is_dttm, or time filters silently do nothing."""
    for fname in ("suzaku_detections.yaml", "suzaku_detection_tags.yaml"):
        columns = {c["column_name"]: c for c in load_dataset(fname)["columns"]}
        assert (
            columns[TEMPORAL_COLUMN]["is_dttm"] is True
        ), f"{fname}: {TEMPORAL_COLUMN} not is_dttm"


# ---------------------------------------------------------------------------
# dashboard.yaml
# ---------------------------------------------------------------------------


def test_dashboard_has_required_keys() -> None:
    dashboard = load_dashboard()
    required = {"uuid", "version", "dashboard_title", "position", "metadata", "slug"}
    missing = required - set(dashboard.keys())
    assert not missing, f"dashboard.yaml missing fields: {missing}"
    assert dashboard["uuid"] == DASHBOARD_UUID
    assert dashboard["dashboard_title"] == "Suzaku Detections"
    assert dashboard["slug"] == "suzaku-detections"


def test_all_chart_components_have_children_list() -> None:
    """Every CHART in position needs children: [] so Superset can call .forEach().

    Without it the Superset frontend throws:
      TypeError: Cannot read properties of undefined (reading 'forEach')
    """
    dashboard = load_dashboard()
    offenders = [
        key
        for key, val in dashboard["position"].items()
        if isinstance(val, dict)
        and val.get("type") == "CHART"
        and not isinstance(val.get("children"), list)
    ]
    assert not offenders, f"CHART components missing 'children: []': {offenders}"


def test_dashboard_has_seven_tabs() -> None:
    """The layout is a 7-tab walk through the analyst's questions."""
    dashboard = load_dashboard()
    tabs = [
        v
        for v in dashboard["position"].values()
        if isinstance(v, dict) and v.get("type") == "TAB"
    ]
    assert len(tabs) == 7, f"Expected 7 TAB entries, found {len(tabs)}"


def test_dashboard_chart_uuids_have_matching_yaml() -> None:
    """Every chart UUID in the layout must have a chart YAML on disk."""
    file_uuids = {c["uuid"] for _, c in load_all_charts()}
    missing = chart_uuids_from_dashboard(load_dashboard()) - file_uuids
    assert not missing, f"Chart UUIDs in dashboard.yaml with no YAML file: {missing}"


def test_all_chart_yamls_referenced_in_dashboard() -> None:
    """Every chart YAML must be placed somewhere in the layout."""
    by_uuid = {c["uuid"]: fname for fname, c in load_all_charts()}
    unreferenced = set(by_uuid) - chart_uuids_from_dashboard(load_dashboard())
    assert not unreferenced, (
        f"Chart YAMLs not referenced in dashboard.yaml: "
        f"{sorted(by_uuid[u] for u in unreferenced)}"
    )


def test_every_row_and_tab_is_reachable() -> None:
    """Each ROW must be a child of a TAB, and each TAB a child of TABS_ID.

    An orphaned row renders nowhere, so its charts vanish without any error.
    """
    position = load_dashboard()["position"]
    tab_ids = {
        k for k, v in position.items() if isinstance(v, dict) and v.get("type") == "TAB"
    }
    row_ids = {
        k for k, v in position.items() if isinstance(v, dict) and v.get("type") == "ROW"
    }
    assert tab_ids == set(position["TABS_ID"]["children"])
    referenced_rows = {child for tab in tab_ids for child in position[tab]["children"]}
    assert row_ids == referenced_rows, (
        f"Orphaned rows: {sorted(row_ids - referenced_rows)}; "
        f"dangling row references: {sorted(referenced_rows - row_ids)}"
    )


def test_dashboard_filter_ids_unique() -> None:
    dashboard = load_dashboard()
    ids = [f["id"] for f in dashboard["metadata"]["native_filter_configuration"]]
    assert len(ids) == len(
        set(ids)
    ), "Duplicate filter IDs in native_filter_configuration"


def test_dashboard_filter_columns_exist_in_target_dataset() -> None:
    """A native filter's column must exist on the dataset it targets."""
    columns = dataset_columns()
    offenders = []
    for spec in load_dashboard()["metadata"]["native_filter_configuration"]:
        for target in spec["targets"]:
            if not target:
                continue  # the time-range filter targets no specific column
            column = target["column"]["name"]
            if column not in columns.get(target["datasetUuid"], set()):
                offenders.append((spec["id"], column))
    assert not offenders, f"Native filters targeting unknown columns: {offenders}"


def test_tag_dataset_filters_are_scoped_to_the_mitre_tab() -> None:
    """Filters bound to suzaku_detection_tags must be scoped to that tab.

    A native filter targets exactly one dataset, so a tag-side filter can only
    ever affect the ATT&CK charts.  Leaving it at ROOT_ID would present it as a
    dashboard-wide control that silently does nothing on the other six tabs.
    """
    for spec in load_dashboard()["metadata"]["native_filter_configuration"]:
        targets = [t for t in spec["targets"] if t]
        if not targets or targets[0]["datasetUuid"] != TAGS_UUID:
            continue
        assert spec["scope"]["rootPath"] == ["TAB-mitre"], (
            f"{spec['id']}: filters on suzaku_detection_tags must be scoped to "
            f"TAB-mitre, got {spec['scope']['rootPath']}"
        )


def test_severity_and_rule_filters_exist() -> None:
    """The two filters an analyst reaches for first must be present."""
    ids = {f["id"] for f in load_dashboard()["metadata"]["native_filter_configuration"]}
    for required in (
        "NATIVE_FILTER-szk-timerange",
        "NATIVE_FILTER-szk-level",
        "NATIVE_FILTER-szk-level-not",
        "NATIVE_FILTER-szk-rule",
        "NATIVE_FILTER-szk-rule-not",
    ):
        assert required in ids, f"missing native filter {required}"


# ---------------------------------------------------------------------------
# ZIP packaging
# ---------------------------------------------------------------------------


def test_rebuild_suzaku_zip_importable_without_side_effects() -> None:
    """Importing the rebuild script must not touch the committed ZIP."""
    with open(OUTPUT_ZIP, "rb") as fh:
        before = fh.read()

    assets_dir = os.path.dirname(os.path.abspath(REBUILD_SCRIPT))
    sys.path.insert(0, assets_dir)
    try:
        module = importlib.reload(importlib.import_module("rebuild_suzaku_zip"))
    finally:
        sys.path.remove(assets_dir)

    with open(OUTPUT_ZIP, "rb") as fh:
        after = fh.read()
    assert after == before, (
        "Importing rebuild_suzaku_zip rebuilt the ZIP — keep the build code in "
        "main() behind an __main__ guard."
    )
    assert isinstance(module.FILE_MAP, dict)


def test_rebuild_suzaku_zip_runs_cleanly() -> None:
    """rebuild_suzaku_zip.py must exit 0 with no missing or unmapped sources."""
    result = subprocess.run(
        [sys.executable, REBUILD_SCRIPT], capture_output=True, text=True
    )
    assert result.returncode == 0, f"rebuild failed:\n{result.stderr}\n{result.stdout}"
    assert "MISSING:" not in result.stdout, f"missing sources:\n{result.stdout}"
    assert "WARNING:" not in result.stdout, f"unmapped chart YAMLs:\n{result.stdout}"


def test_committed_zip_is_up_to_date_and_reproducible() -> None:
    """Rebuilding must reproduce the committed ZIP byte for byte.

    Two things at once: the ZIP on disk really is built from the YAML next to
    it (an edit that was never repackaged would never reach Superset), and the
    build is deterministic — entries carry a fixed timestamp, so running the
    test suite does not leave a diff made entirely of file times.
    """
    with open(OUTPUT_ZIP, "rb") as fh:
        before = fh.read()
    subprocess.run([sys.executable, REBUILD_SCRIPT], capture_output=True, check=True)
    with open(OUTPUT_ZIP, "rb") as fh:
        after = fh.read()
    assert after == before, (
        "suzaku_detections.zip does not match its sources — re-run "
        "assets/rebuild_suzaku_zip.py and commit the result."
    )


def test_zip_contains_required_files() -> None:
    with zipfile.ZipFile(OUTPUT_ZIP) as zf:
        names = set(zf.namelist())
    for required in (
        "metadata.yaml",
        "dashboards/suzaku_detections.yaml",
        "databases/CloudTrail_DuckDB.yaml",
        "datasets/CloudTrail_DuckDB/suzaku_detections.yaml",
        "datasets/CloudTrail_DuckDB/suzaku_detection_tags.yaml",
    ):
        assert required in names, f"ZIP missing required file: {required}"


def test_zip_contains_every_chart_yaml() -> None:
    """A chart added to charts/ without a FILE_MAP entry drops out of the ZIP.

    Superset then renders "There is no chart definition associated with this
    component" wherever the dashboard references it.
    """
    with zipfile.ZipFile(OUTPUT_ZIP) as zf:
        zip_uuids = {
            yaml.safe_load(zf.read(name))["uuid"]
            for name in zf.namelist()
            if name.startswith("charts/") and name.endswith(".yaml")
        }
    missing = [
        fname for fname, chart in load_all_charts() if chart["uuid"] not in zip_uuids
    ]
    assert not missing, (
        f"Chart YAMLs missing from the ZIP (add them to FILE_MAP in "
        f"rebuild_suzaku_zip.py and re-run it): {missing}"
    )


def test_zip_dashboard_chart_refs_resolve() -> None:
    """Every CHART uuid in the packaged dashboard must have a packaged chart."""
    with zipfile.ZipFile(OUTPUT_ZIP) as zf:
        zip_uuids = {
            yaml.safe_load(zf.read(name))["uuid"]
            for name in zf.namelist()
            if name.startswith("charts/") and name.endswith(".yaml")
        }
        dashboard = yaml.safe_load(zf.read("dashboards/suzaku_detections.yaml"))
    dangling = {
        key: value["meta"]["uuid"]
        for key, value in dashboard["position"].items()
        if isinstance(value, dict)
        and value.get("type") == "CHART"
        and value["meta"]["uuid"] not in zip_uuids
    }
    assert (
        not dangling
    ), f"Dashboard references chart uuids absent from the ZIP: {dangling}"


# ---------------------------------------------------------------------------
# Superset init wiring
# ---------------------------------------------------------------------------


def _register_dataset():
    if INIT_DIR not in sys.path:
        sys.path.insert(0, INIT_DIR)
    return importlib.import_module("register_dataset")


def test_register_dataset_covers_every_dataset() -> None:
    """register_dataset.py must register both Suzaku datasets.

    A dataset that exists in the ZIP but not here fails the dashboard import
    with "Columns missing in dataset" whenever the DuckDB table is absent —
    which is the normal state before `suzaku-import` has been run.
    """
    module = _register_dataset()
    by_table = {spec["table_name"]: spec for spec in module.DATASETS}
    assert set(by_table) == {
        "cloudtrail_events",
        "suzaku_detections",
        "suzaku_detection_tags",
    }
    assert by_table["suzaku_detections"]["uuid"] == DETECTIONS_UUID
    assert by_table["suzaku_detection_tags"]["uuid"] == TAGS_UUID
    for table in ("suzaku_detections", "suzaku_detection_tags"):
        assert by_table[table]["main_dttm_col"] == TEMPORAL_COLUMN


@pytest.mark.parametrize(
    "yaml_name, table",
    [
        ("suzaku_detections.yaml", "suzaku_detections"),
        ("suzaku_detection_tags.yaml", "suzaku_detection_tags"),
    ],
)
def test_register_dataset_columns_match_the_dataset_yaml(
    yaml_name: str, table: str
) -> None:
    """The fallback column list must match the dataset YAML exactly.

    The two are separate declarations of the same schema: the YAML is what the
    ZIP import checks chart params against, the Python list is what Superset
    falls back to when the DuckDB table cannot be introspected.  If they drift,
    the dashboard imports in one situation and fails in the other.
    """
    module = _register_dataset()
    spec = next(s for s in module.DATASETS if s["table_name"] == table)
    declared = {c[0] for c in spec["columns"]}
    from_yaml = {c["column_name"] for c in load_dataset(yaml_name)["columns"]}
    assert declared == from_yaml, (
        f"{table}: register_dataset.py and {yaml_name} disagree — "
        f"only in Python: {sorted(declared - from_yaml)}; "
        f"only in YAML: {sorted(from_yaml - declared)}"
    )


# ---------------------------------------------------------------------------
# Executable SQL — the strongest check available without a running Superset.
#
# Superset assembles each chart's SQL from its params, so a column typo or an
# expression DuckDB will not accept shows up only as a red chart in the
# browser.  Rebuilding that SQL and running it against empty tables built from
# the dataset definitions catches both at test time.
#
# Skipped when duckdb is not installed (the dashboard CI job installs only
# PyYAML); it runs in any environment that has the ingester's dependencies.
# ---------------------------------------------------------------------------

TABLE_FOR_DATASET = {
    DETECTIONS_UUID: "suzaku_detections",
    TAGS_UUID: "suzaku_detection_tags",
}


def _empty_suzaku_db(duckdb):
    """An in-memory DuckDB holding both Suzaku tables, built from the YAML."""
    conn = duckdb.connect(":memory:")
    for fname in ("suzaku_detections.yaml", "suzaku_detection_tags.yaml"):
        dataset = load_dataset(fname)
        ddl = ", ".join(f'"{c["column_name"]}" {c["type"]}' for c in dataset["columns"])
        conn.execute(f'CREATE TABLE {dataset["table_name"]} ({ddl})')
    return conn


def _chart_sql(chart: dict) -> str:
    """Reconstruct the query Superset builds from a chart's params."""
    params = chart["params"]
    dimensions = []
    for key in ("x_axis", "entity"):
        if params.get(key) is not None:
            dimensions.append(params[key])
    dimensions += params.get("groupby") or []

    select, group = [], []
    for i, dim in enumerate(dimensions, start=1):
        if isinstance(dim, str):
            expr, label = dim, dim
        else:
            expr, label = dim["sqlExpression"], dim["label"]
        select.append(f'{expr} AS "{label}"')
        group.append(str(i))

    metrics = params.get("metrics") or (
        [params["metric"]] if params.get("metric") else []
    )
    select += [f'{mt["sqlExpression"]} AS "{mt["label"]}"' for mt in metrics]

    sql = f'SELECT {", ".join(select)} FROM {TABLE_FOR_DATASET[chart["dataset_uuid"]]}'
    where = [af["sqlExpression"] for af in params.get("adhoc_filters") or []]
    if where:
        sql += " WHERE " + " AND ".join(f"({w})" for w in where)
    if group:
        sql += " GROUP BY " + ", ".join(group)
    return sql


@pytest.mark.parametrize("fname, chart", load_all_charts())
def test_chart_sql_is_valid_duckdb(fname: str, chart: dict) -> None:
    """Every chart's reconstructed query must run against the real schema."""
    duckdb = pytest.importorskip("duckdb")
    conn = _empty_suzaku_db(duckdb)
    sql = _chart_sql(chart)
    try:
        conn.execute(sql).fetchall()
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"{fname}: chart SQL is invalid:\n  {sql}\n  {exc}")


@pytest.mark.parametrize(
    "yaml_name", ["suzaku_detections.yaml", "suzaku_detection_tags.yaml"]
)
def test_dataset_metric_expressions_are_valid_duckdb(yaml_name: str) -> None:
    """Dataset-level metrics must be valid against their own table."""
    duckdb = pytest.importorskip("duckdb")
    conn = _empty_suzaku_db(duckdb)
    dataset = load_dataset(yaml_name)
    for metric in dataset["metrics"]:
        sql = f'SELECT {metric["expression"]} FROM {dataset["table_name"]}'
        try:
            conn.execute(sql).fetchall()
        except Exception as exc:  # noqa: BLE001
            pytest.fail(
                f"{yaml_name}: metric {metric['metric_name']} is invalid: {exc}"
            )


def test_bootstrap_imports_the_suzaku_dashboard() -> None:
    """bootstrap.sh must import suzaku_detections.zip on superset-init."""
    with open(BOOTSTRAP, encoding="utf-8") as fh:
        source = fh.read()
    assert "suzaku_detections.zip" in source, (
        "bootstrap.sh does not import suzaku_detections.zip — the dashboard "
        "would never appear in Superset."
    )
