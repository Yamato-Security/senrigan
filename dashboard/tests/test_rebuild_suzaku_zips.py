"""Tests for the Suzaku bundle ZIP builders.

Covers PLAN_SUZAKU_VIEWS.md §5.5 (tests 13-15). Superset never reads the bundle
YAML directly — it only applies the compiled ZIP — so a ZIP that is stale, is
missing a chart, or changes on every rebuild all lead to the same failure mode: a
dashboard that does not match the files under review.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ASSETS = Path(__file__).resolve().parent.parent / "assets"

# Rebuild script -> bundle directory, for every Suzaku bundle that has one.
REBUILD_SCRIPTS: dict[str, str] = {
    "rebuild_suzaku_timeline_zip.py": "suzaku_timeline",
    "rebuild_suzaku_summary_zip.py": "suzaku_summary",
    "rebuild_suzaku_metrics_zip.py": "suzaku_metrics",
}

EXISTING_SCRIPTS = [name for name in REBUILD_SCRIPTS if (ASSETS / name).exists()]


def _load_script(name: str):
    """Import a rebuild script by path, with assets/ importable for zip_builder."""
    sys.path.insert(0, str(ASSETS))
    try:
        spec = importlib.util.spec_from_file_location(
            name.removesuffix(".py"), ASSETS / name
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(ASSETS))


def test_every_bundle_has_a_rebuild_script() -> None:
    """A bundle without a builder can never reach Superset."""
    for bundle in sorted(p.name for p in ASSETS.glob("suzaku_*") if p.is_dir()):
        matching = [
            name for name, target in REBUILD_SCRIPTS.items() if target == bundle
        ]
        assert matching, f"{bundle}: no rebuild script mapped"
        assert (ASSETS / matching[0]).exists(), f"{bundle}: {matching[0]} missing"


@pytest.mark.parametrize("script_name", EXISTING_SCRIPTS)
def test_zip_matches_its_file_map(script_name: str, tmp_path: Path) -> None:
    """Test 13: the shipped ZIP holds exactly the mapped arc names."""
    import zipfile

    module = _load_script(script_name)
    output = tmp_path / "bundle.zip"
    from zip_builder import build_zip  # noqa: PLC0415 — needs assets/ on sys.path

    sys.path.insert(0, str(ASSETS))
    try:
        build_zip(module.SOURCE_DIR, str(output), module.FILE_MAP, verbose=False)
    finally:
        sys.path.remove(str(ASSETS))

    with zipfile.ZipFile(output) as zf:
        assert sorted(zf.namelist()) == sorted(module.FILE_MAP.values())


@pytest.mark.parametrize("script_name", EXISTING_SCRIPTS)
def test_rebuild_is_byte_deterministic(script_name: str, tmp_path: Path) -> None:
    """Test 14: two rebuilds must be identical, or `git diff` cries wolf."""
    module = _load_script(script_name)
    sys.path.insert(0, str(ASSETS))
    try:
        from zip_builder import build_zip  # noqa: PLC0415

        first = tmp_path / "a.zip"
        second = tmp_path / "b.zip"
        build_zip(module.SOURCE_DIR, str(first), module.FILE_MAP, verbose=False)
        build_zip(module.SOURCE_DIR, str(second), module.FILE_MAP, verbose=False)
    finally:
        sys.path.remove(str(ASSETS))

    assert first.read_bytes() == second.read_bytes()


@pytest.mark.parametrize("script_name", EXISTING_SCRIPTS)
def test_every_source_yaml_is_shipped(script_name: str) -> None:
    """Test 15: a chart YAML absent from FILE_MAP is invisible to Superset."""
    module = _load_script(script_name)
    source = Path(module.SOURCE_DIR)
    mapped = {(source / relative).resolve() for relative in module.FILE_MAP}
    on_disk = {path.resolve() for path in source.rglob("*.yaml")}
    assert on_disk == mapped, (
        f"{script_name}: unshipped={sorted(p.name for p in on_disk - mapped)}, "
        f"mapped-but-missing={sorted(p.name for p in mapped - on_disk)}"
    )


@pytest.mark.parametrize("script_name", EXISTING_SCRIPTS)
def test_shipped_zip_is_up_to_date(script_name: str, tmp_path: Path) -> None:
    """The committed ZIP must match the current sources.

    Superset applies the ZIP, not the YAML, so editing a bundle without
    rebuilding leaves the running dashboard silently out of date.
    """
    module = _load_script(script_name)
    committed = Path(module.OUTPUT_ZIP)
    if not committed.exists():
        pytest.fail(f"{committed.name} not committed — run {script_name}")

    sys.path.insert(0, str(ASSETS))
    try:
        from zip_builder import build_zip  # noqa: PLC0415

        rebuilt = tmp_path / "rebuilt.zip"
        build_zip(module.SOURCE_DIR, str(rebuilt), module.FILE_MAP, verbose=False)
    finally:
        sys.path.remove(str(ASSETS))

    assert (
        committed.read_bytes() == rebuilt.read_bytes()
    ), f"{committed.name} is stale — run: python3 assets/{script_name}"


@pytest.mark.parametrize("script_name", EXISTING_SCRIPTS)
def test_missing_source_file_fails_loudly(script_name: str, tmp_path: Path) -> None:
    """A silently dropped file would import a dashboard with broken references."""
    module = _load_script(script_name)
    sys.path.insert(0, str(ASSETS))
    try:
        from zip_builder import build_zip  # noqa: PLC0415

        with pytest.raises(FileNotFoundError):
            build_zip(
                module.SOURCE_DIR,
                str(tmp_path / "x.zip"),
                {**module.FILE_MAP, "charts/does_not_exist.yaml": "charts/x.yaml"},
                verbose=False,
            )
    finally:
        sys.path.remove(str(ASSETS))
