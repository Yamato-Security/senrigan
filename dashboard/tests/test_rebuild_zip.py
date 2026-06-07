"""Tests for rebuild_zip.py — verifies that the output ZIP has correct structure
and contains all chart YAML files listed in FILE_MAP."""

import os
import subprocess
import sys
import zipfile

import pytest

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
    "Defense_Evasion",
    "MFA_Less_Login_Trend",
    "Login_Activity_Heatmap",
    "Write_Read_Ratio_Trend",
    "Throttling_Exception_Spikes",
    "Secrets_Access_Anomaly",
    "Organizations_SCP_Changes",
    "S3_Protection_Config_Changes",
    "First_Time_Service_Sources",
    "AssumedRole_External_IP",
    "Privilege_Escalation_Timeline",
    "Route53_DNS_Changes",
]


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
