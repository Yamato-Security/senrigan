"""Tests for the generated cloudtrail_rare.zip (Rare Events dashboard).

Mirrors test_rebuild_zip.py: runs the generator script and validates the
resulting ZIP structure, the ascending-order semantics, and byte-level
determinism (rebuilding without source changes must be a zero git diff).
"""

import os
import subprocess
import sys
import zipfile

import yaml

REBUILD_RARE_SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "assets", "rebuild_rare_zip.py"
)
OUTPUT_ZIP = os.path.join(
    os.path.dirname(__file__), "..", "assets", "cloudtrail_rare.zip"
)
REQUIRED_ZIP_PATHS = [
    "metadata.yaml",
    "dashboards/cloudtrail_rare_events.yaml",
    "databases/CloudTrail_DuckDB.yaml",
    "datasets/CloudTrail_DuckDB/cloudtrail_events.yaml",
]


def _run_script() -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, REBUILD_RARE_SCRIPT],
        capture_output=True,
        text=True,
    )


def test_rebuild_rare_zip_runs_without_error() -> None:
    """rebuild_rare_zip.py must exit 0 and produce the ZIP."""
    result = _run_script()
    assert result.returncode == 0, (
        f"rebuild_rare_zip.py failed (rc={result.returncode}):\n"
        f"{result.stderr}\n{result.stdout}"
    )
    assert os.path.exists(OUTPUT_ZIP)


def test_rare_zip_contains_required_files() -> None:
    """ZIP must contain metadata, rare dashboard, database, dataset, and
    all 115 chart files."""
    with zipfile.ZipFile(OUTPUT_ZIP) as zf:
        names = set(zf.namelist())
    for required in REQUIRED_ZIP_PATHS:
        assert required in names, f"ZIP missing required file: {required}"
    chart_names = [n for n in names if n.startswith("charts/")]
    assert len(chart_names) == 115


def test_rare_zip_charts_are_ascending() -> None:
    """Every chart in the ZIP that has order_desc must have it False, and
    every slice_name must carry the ' (Rare)' suffix."""
    with zipfile.ZipFile(OUTPUT_ZIP) as zf:
        for name in zf.namelist():
            if not name.startswith("charts/"):
                continue
            doc = yaml.safe_load(zf.read(name))
            assert doc["slice_name"].endswith(" (Rare)"), name
            if "order_desc" in doc.get("params", {}):
                assert doc["params"]["order_desc"] is False, name


def test_rare_zip_dashboard_refs_resolve() -> None:
    """Every CHART uuid in the rare dashboard position must have a chart
    file in the ZIP (dangling refs render as broken components)."""
    with zipfile.ZipFile(OUTPUT_ZIP) as zf:
        chart_uuids = {
            yaml.safe_load(zf.read(n))["uuid"]
            for n in zf.namelist()
            if n.startswith("charts/")
        }
        dashboard = yaml.safe_load(zf.read("dashboards/cloudtrail_rare_events.yaml"))
    dangling = {
        key: node["meta"]["uuid"]
        for key, node in dashboard["position"].items()
        if isinstance(node, dict)
        and node.get("type") == "CHART"
        and node["meta"]["uuid"] not in chart_uuids
    }
    assert not dangling


def test_rare_zip_build_is_deterministic() -> None:
    """Two consecutive builds must be byte-identical (fixed timestamps),
    so rebuilding without source changes never dirties git."""
    result_first = _run_script()
    assert result_first.returncode == 0
    with open(OUTPUT_ZIP, "rb") as fh:
        first = fh.read()
    result_second = _run_script()
    assert result_second.returncode == 0
    with open(OUTPUT_ZIP, "rb") as fh:
        second = fh.read()
    assert first == second
