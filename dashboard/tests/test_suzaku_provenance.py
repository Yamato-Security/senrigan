"""Every Suzaku dashboard must name the file it is reading.

With several runs in the mounted directory, "which file is this?" is the first
question a number that looks wrong raises — and before this the answer was not
on the page anywhere.

The file path is not a column in the data: it comes from DuckDB's own
``duckdb_databases()``, so the header reports the connection Superset actually
opened and cannot be made to lie by editing YAML.
"""

from __future__ import annotations

from pathlib import Path

import duckdb
import pytest
import yaml

ASSETS = Path(__file__).resolve().parent.parent / "assets"
FIXTURE_DIR = Path(__file__).resolve().parents[2] / "sample" / "suzaku" / "fixtures"

# Bundle -> the fixture its provenance dataset must run against.
BUNDLES: dict[str, str] = {
    "suzaku_timeline": "suzaku-aws-ct-timeline.duckdb",
    "suzaku_summary": "suzaku-aws-ct-summary.duckdb",
    "suzaku_metrics": "suzaku-aws-ct-metrics.duckdb",
}

ALL_BUNDLES = list(BUNDLES)


def _load(path: Path) -> dict:
    """Parse a YAML file."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _meta_datasets(bundle: str) -> list[dict]:
    """Return the bundle's datasets that read the provenance table."""
    return [
        _load(path)
        for path in sorted((ASSETS / bundle / "datasets").glob("*.yaml"))
        if "suzaku_meta" in (_load(path).get("sql") or "")
    ]


def _charts(bundle: str) -> list[dict]:
    """Return the bundle's chart definitions."""
    return [_load(path) for path in sorted((ASSETS / bundle / "charts").glob("*.yaml"))]


@pytest.mark.parametrize("bundle", ALL_BUNDLES)
def test_every_bundle_has_one_provenance_dataset(bundle: str) -> None:
    """One per bundle: two would let two charts disagree about the same file."""
    assert len(_meta_datasets(bundle)) == 1


@pytest.mark.parametrize("bundle", ALL_BUNDLES)
def test_the_provenance_dataset_reports_the_source_file(bundle: str) -> None:
    """The path must come from the connection, not from anything editable."""
    dataset = _meta_datasets(bundle)[0]
    assert "source_file" in dataset["sql"]
    assert "duckdb_databases()" in dataset["sql"]
    declared = {column["column_name"] for column in dataset["columns"]}
    assert "source_file" in declared


@pytest.mark.parametrize("bundle", ALL_BUNDLES)
def test_the_source_file_is_the_file_actually_opened(bundle: str) -> None:
    """Run it: the column must equal the fixture's own path, not a placeholder."""
    fixture = FIXTURE_DIR / BUNDLES[bundle]
    dataset = _meta_datasets(bundle)[0]
    conn = duckdb.connect(str(fixture), read_only=True)
    try:
        rows = conn.execute(
            f"SELECT source_file FROM ({dataset['sql']}) AS _t"
        ).fetchall()
    finally:
        conn.close()

    assert len(rows) == 1, "suzaku_meta holds exactly one row"
    assert rows[0][0] == str(fixture)


@pytest.mark.parametrize("bundle", ALL_BUNDLES)
def test_every_bundle_charts_its_provenance(bundle: str) -> None:
    """A dataset nothing charts is invisible to the analyst."""
    dataset_uuid = _meta_datasets(bundle)[0]["uuid"]
    users = [
        chart for chart in _charts(bundle) if chart["dataset_uuid"] == dataset_uuid
    ]
    assert users, f"{bundle} has a provenance dataset but no chart on it"


@pytest.mark.parametrize("bundle", ALL_BUNDLES)
def test_the_provenance_chart_shows_the_source_file(bundle: str) -> None:
    """Naming the run is not enough when two runs sit in one directory."""
    dataset_uuid = _meta_datasets(bundle)[0]["uuid"]
    charts = [
        chart for chart in _charts(bundle) if chart["dataset_uuid"] == dataset_uuid
    ]
    grouped = {
        column for chart in charts for column in chart["params"].get("groupby", [])
    }
    assert "source_file" in grouped


@pytest.mark.parametrize("bundle", ALL_BUNDLES)
def test_the_provenance_chart_is_placed_on_the_dashboard(bundle: str) -> None:
    """An unplaced chart ships in the ZIP and appears nowhere."""
    dataset_uuid = _meta_datasets(bundle)[0]["uuid"]
    chart_uuids = {
        chart["uuid"]
        for chart in _charts(bundle)
        if chart["dataset_uuid"] == dataset_uuid
    }
    dashboard = _load(ASSETS / bundle / "dashboard.yaml")
    placed = {
        component["meta"]["uuid"]
        for component in dashboard.get("position", {}).values()
        if isinstance(component, dict)
        and component.get("type") == "CHART"
        and "uuid" in component.get("meta", {})
    }
    assert chart_uuids & placed, f"{bundle}: the provenance chart is not placed"
