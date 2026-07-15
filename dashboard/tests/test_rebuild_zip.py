"""Tests for rebuild_zip.py — verifies that the output ZIP has correct structure
and contains all chart YAML files listed in FILE_MAP."""

import importlib
import os
import subprocess
import sys
import zipfile

import pytest
import yaml

REBUILD_ZIP_SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "assets", "rebuild_zip.py"
)
OUTPUT_ZIP = os.path.join(
    os.path.dirname(__file__), "..", "assets", "cloudtrail_default.zip"
)
REQUIRED_ZIP_PATHS = [
    "metadata.yaml",
    "dashboards/cloudtrail_threat_hunting.yaml",
    "databases/CloudTrail_DuckDB.yaml",
    "datasets/CloudTrail_DuckDB/cloudtrail_events.yaml",
]
# Chart arc-name fragments that must appear in the ZIP (Sprint 1–4 new charts)
NEW_CHART_FRAGMENTS = [
    "Security_Monitoring_Control_Changes",
    "MFA_Less_Login_Trend",
    "Login_Activity_Heatmap",
    "Write_Read_Ratio_Trend",
    "Throttling_Exception_Spikes",
    "Secrets_Access_Anomaly",
    "Organizations_SCP_Changes",
    "S3_Protection_Config_Changes",
    "First_Last_Seen_Service_Source",
    "AssumedRole_External_IP",
    "IAM_Privilege_Change_Event_Timeline",
    "Route53_DNS_Changes",
]


def test_rebuild_zip_importable_without_side_effects() -> None:
    """Importing rebuild_zip as a module must not rebuild the ZIP.

    rebuild_rare_zip.py imports FILE_MAP from rebuild_zip, so the module's
    top-level build code must live behind an ``if __name__ == "__main__"``
    guard.  Rebuilding on import would silently touch the committed ZIP.
    """
    with open(OUTPUT_ZIP, "rb") as fh:
        bytes_before = fh.read()

    assets_dir = os.path.dirname(os.path.abspath(REBUILD_ZIP_SCRIPT))
    sys.path.insert(0, assets_dir)
    try:
        module = importlib.import_module("rebuild_zip")
        # Reload so the module top-level runs even if already imported.
        module = importlib.reload(module)
    finally:
        sys.path.remove(assets_dir)

    with open(OUTPUT_ZIP, "rb") as fh:
        bytes_after = fh.read()
    assert bytes_after == bytes_before, (
        "Importing rebuild_zip rebuilt the ZIP — move the build code into "
        "main() behind an __main__ guard."
    )
    assert isinstance(module.FILE_MAP, dict) and len(module.FILE_MAP) >= 95, (
        "rebuild_zip.FILE_MAP must stay importable (4 core entries + " "91 charts)."
    )


def test_rebuild_zip_runs_without_error() -> None:
    """rebuild_zip.py must exit with code 0."""
    result = subprocess.run(
        [sys.executable, REBUILD_ZIP_SCRIPT],
        capture_output=True,
        text=True,
    )
    assert (
        result.returncode == 0
    ), f"rebuild_zip.py failed (rc={result.returncode}):\n{result.stderr}\n{result.stdout}"


def test_zip_contains_required_files() -> None:
    """ZIP must always contain the metadata, dashboard, database, and dataset files."""
    with zipfile.ZipFile(OUTPUT_ZIP) as zf:
        names = set(zf.namelist())
    for required in REQUIRED_ZIP_PATHS:
        assert required in names, f"ZIP missing required file: {required}"


def test_zip_has_no_missing_sources() -> None:
    """rebuild_zip.py must not report any MISSING source files."""
    result = subprocess.run(
        [sys.executable, REBUILD_ZIP_SCRIPT],
        capture_output=True,
        text=True,
    )
    assert (
        "MISSING:" not in result.stdout
    ), f"rebuild_zip.py reports missing source files:\n{result.stdout}"


@pytest.mark.parametrize("fragment", NEW_CHART_FRAGMENTS)
def test_zip_contains_new_chart(fragment: str) -> None:
    """Each new DSH-19–30 chart must appear in the ZIP under charts/."""
    with zipfile.ZipFile(OUTPUT_ZIP) as zf:
        names = set(zf.namelist())
    chart_names = {n for n in names if n.startswith("charts/")}
    assert any(fragment in n for n in chart_names), (
        f"New chart '{fragment}' not found in ZIP charts/ entries.\n"
        f"Available: {sorted(chart_names)}"
    )


# ---------------------------------------------------------------------------
# Completeness — FILE_MAP is an explicit list, so a chart YAML added to
# charts/ without a matching FILE_MAP entry silently drops out of the ZIP.
# Superset then shows "There is no chart definition associated with this
# component" for every dashboard reference to the missing chart.
# ---------------------------------------------------------------------------

CHARTS_DIR = os.path.join(
    os.path.dirname(__file__), "..", "assets", "cloudtrail_default", "charts"
)


def _zip_chart_uuids() -> set[str]:
    """Return the uuid of every charts/*.yaml entry inside the ZIP."""
    uuids: set[str] = set()
    with zipfile.ZipFile(OUTPUT_ZIP) as zf:
        for name in zf.namelist():
            if name.startswith("charts/") and name.endswith(".yaml"):
                uuids.add(yaml.safe_load(zf.read(name))["uuid"])
    return uuids


def test_zip_contains_every_chart_yaml() -> None:
    """Every YAML in the charts/ source dir must be packaged into the ZIP."""
    zip_uuids = _zip_chart_uuids()
    missing = []
    for fname in sorted(os.listdir(CHARTS_DIR)):
        if not fname.endswith(".yaml"):
            continue
        with open(os.path.join(CHARTS_DIR, fname), encoding="utf-8") as fh:
            uuid = yaml.safe_load(fh)["uuid"]
        if uuid not in zip_uuids:
            missing.append(fname)
    assert not missing, (
        f"Chart YAMLs missing from the ZIP (add them to FILE_MAP in "
        f"rebuild_zip.py and re-run it): {missing}"
    )


def test_zip_dashboard_chart_refs_resolve() -> None:
    """Every CHART uuid in the ZIP's dashboard position must have a chart file.

    A dangling reference makes Superset render 'There is no chart definition
    associated with this component' in place of the chart.
    """
    zip_uuids = _zip_chart_uuids()
    with zipfile.ZipFile(OUTPUT_ZIP) as zf:
        dashboard = yaml.safe_load(zf.read("dashboards/cloudtrail_threat_hunting.yaml"))
    dangling = {
        key: value["meta"]["uuid"]
        for key, value in dashboard["position"].items()
        if isinstance(value, dict)
        and value.get("type") == "CHART"
        and value["meta"]["uuid"] not in zip_uuids
    }
    assert not dangling, (
        f"Dashboard position references chart uuids with no chart file in the "
        f"ZIP: {dangling}"
    )
