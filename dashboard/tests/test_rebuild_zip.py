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
        "rebuild_zip.FILE_MAP must stay importable (4 core entries + " "101 charts)."
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


ASSETS_DIR = os.path.join(os.path.dirname(__file__), "..", "assets")


def _rebuild_zip_module():
    """Import rebuild_zip with assets/ importable, for FILE_MAP and SOURCE_DIR."""
    sys.path.insert(0, os.path.abspath(ASSETS_DIR))
    try:
        return importlib.import_module("rebuild_zip")
    finally:
        sys.path.remove(os.path.abspath(ASSETS_DIR))


def _build_zip():
    """Return ``zip_builder.build_zip``, the shared deterministic packager."""
    sys.path.insert(0, os.path.abspath(ASSETS_DIR))
    try:
        from zip_builder import build_zip

        return build_zip
    finally:
        sys.path.remove(os.path.abspath(ASSETS_DIR))


def test_committed_zip_uses_the_fixed_timestamp() -> None:
    """Every entry must carry the pinned timestamp, not its source's mtime.

    `zf.write()` stamps each entry with the mtime of the file on disk, which
    is the checkout time on a fresh clone. That made every rebuild of this
    bundle a diff: running the dashboard suite rewrote the committed ZIP and
    left the working tree dirty, and it made "is this ZIP stale?" unanswerable
    by comparing bytes — which is exactly how the Suzaku bundles answer it.
    """
    sys.path.insert(0, os.path.abspath(ASSETS_DIR))
    try:
        from zip_builder import FIXED_DATE_TIME
    finally:
        sys.path.remove(os.path.abspath(ASSETS_DIR))

    with zipfile.ZipFile(OUTPUT_ZIP) as zf:
        stamped = {info.filename: info.date_time for info in zf.infolist()}
        modes = {info.filename: info.external_attr for info in zf.infolist()}

    drifting = {n: t for n, t in stamped.items() if t != FIXED_DATE_TIME}
    assert not drifting, f"entries carry a filesystem mtime: {sorted(drifting)[:5]}"

    wrong_mode = {n: m for n, m in modes.items() if m != 0o644 << 16}
    assert not wrong_mode, f"entries carry a source file mode: {sorted(wrong_mode)[:5]}"


def test_shipped_zip_is_up_to_date(tmp_path) -> None:
    """The committed ZIP must match the current sources, byte for byte.

    Superset applies the ZIP, not the YAML, so editing the bundle without
    rebuilding leaves the running dashboard silently out of date.
    """
    module = _rebuild_zip_module()
    rebuilt = tmp_path / "rebuilt.zip"
    _build_zip()(module.SOURCE_DIR, str(rebuilt), module.FILE_MAP, verbose=False)

    with open(OUTPUT_ZIP, "rb") as fh:
        committed = fh.read()
    assert (
        committed == rebuilt.read_bytes()
    ), "cloudtrail_default.zip is stale — run: python3 assets/rebuild_zip.py"


def test_rebuild_is_byte_deterministic(tmp_path) -> None:
    """Two rebuilds of unchanged sources must produce the same bytes."""
    module = _rebuild_zip_module()
    build_zip = _build_zip()

    first, second = tmp_path / "a.zip", tmp_path / "b.zip"
    build_zip(module.SOURCE_DIR, str(first), module.FILE_MAP, verbose=False)
    build_zip(module.SOURCE_DIR, str(second), module.FILE_MAP, verbose=False)

    assert first.read_bytes() == second.read_bytes()


def test_missing_source_file_fails_loudly(tmp_path) -> None:
    """A mapped file that does not exist must stop the build, not be skipped.

    The old builder printed `MISSING:` and carried on, which ships a dashboard
    referencing a chart that is not in the bundle — Superset renders "There is
    no chart definition associated with this component" for every reference.
    """
    module = _rebuild_zip_module()

    with pytest.raises(FileNotFoundError):
        _build_zip()(
            module.SOURCE_DIR,
            str(tmp_path / "x.zip"),
            {**module.FILE_MAP, "charts/does_not_exist.yaml": "charts/x.yaml"},
            verbose=False,
        )


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
