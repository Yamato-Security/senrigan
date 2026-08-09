"""Invariants every chart in the CloudTrail bundle must hold.

The chart directory grew one file at a time, and nothing checked the set as a
whole — so a chart could reach the ZIP without ever being placed on a tab, and
two of them could quietly encode one team's timezone into a product shipped in
fifteen locales. These tests state the rules once and apply them to the whole
bundle.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest
import yaml

ASSETS_DIR = pathlib.Path(__file__).parent.parent / "assets"
BUNDLE_DIR = ASSETS_DIR / "cloudtrail_default"
CHARTS_DIR = BUNDLE_DIR / "charts"


def _charts() -> list[tuple[str, dict]]:
    """Return ``(filename, parsed chart)`` for every chart in the bundle."""
    return [
        (path.name, yaml.safe_load(path.read_text(encoding="utf-8")))
        for path in sorted(CHARTS_DIR.glob("*.yaml"))
    ]


CHARTS = _charts()
CHART_IDS = [name for name, _ in CHARTS]


def _chart_text(chart: dict) -> str:
    """Return every SQL-bearing string in a chart as one searchable blob.

    ``params`` and ``query_context`` are sometimes YAML mappings and sometimes
    JSON strings, so both are normalised to text rather than walked.
    """
    return json.dumps(chart, ensure_ascii=False, default=str)


# ``AT TIME ZONE 'Asia/Tokyo'`` and friends. UTC is the only zone a chart may
# name: the dashboard is shipped in fifteen locales and read in all of them.
_NAMED_TIMEZONE_RE = re.compile(
    r"AT TIME ZONE\\?'(?!UTC)[^'\\]+|"
    r"(?:Asia|Europe|America|Africa|Australia|Pacific)/[A-Za-z_]+",
)

# ``read_only`` is NULL on the majority of real CloudTrail records, so an
# equality test silently drops the write events the chart exists to show.
_UNSAFE_READ_ONLY_RE = re.compile(r"read_only\s*(?:=|!=|<>)\s*(?:true|false)", re.I)


@pytest.mark.parametrize("name,chart", CHARTS, ids=CHART_IDS)
def test_chart_never_hardcodes_a_local_timezone(name: str, chart: dict):
    """No chart may bucket time in a named zone.

    An hour-of-day heatmap rendered in ``Asia/Tokyo`` is off by up to a day for
    every reader outside that zone, and nothing on the chart says so. The
    dashboard reports in UTC, which every CloudTrail timestamp already is.
    """
    found = _NAMED_TIMEZONE_RE.findall(_chart_text(chart))
    assert (
        not found
    ), f"{name} hardcodes the timezone {found!r}; charts bucket time in UTC"


@pytest.mark.parametrize("name,chart", CHARTS, ids=CHART_IDS)
def test_chart_treats_a_missing_read_only_flag_as_a_write(name: str, chart: dict):
    """``read_only`` comparisons in chart SQL must be NULL-safe.

    Same defect as in the hunt catalogue: CloudTrail omits ``readOnly`` from
    most records, so ``read_only = false`` matches a small fraction of the
    writes it claims to count. ``IS NOT TRUE`` classes the unknowns as writes.
    """
    found = _UNSAFE_READ_ONLY_RE.findall(_chart_text(chart))
    assert not found, (
        f"{name} compares read_only with = / != ; NULL rows are dropped. "
        f"Use `read_only IS TRUE` / `read_only IS NOT TRUE`"
    )


def _dashboard() -> dict:
    """Return the parsed dashboard definition for the CloudTrail bundle."""
    return yaml.safe_load((BUNDLE_DIR / "dashboard.yaml").read_text(encoding="utf-8"))


def _placed_by_uuid() -> dict[str, str | None]:
    """Return ``{chart uuid: sliceName}`` for every chart the layout positions.

    Superset resolves a positioned chart by its uuid, so the uuid is what
    decides whether a chart is reachable; the ``sliceName`` beside it is
    display metadata that can — and did — drift.
    """
    position = _dashboard().get("position") or _dashboard().get("position_json")
    if isinstance(position, str):
        position = json.loads(position)

    placed: dict[str, str | None] = {}

    def walk(node) -> None:
        if isinstance(node, dict):
            meta = node.get("meta") or {}
            if isinstance(meta, dict) and "uuid" in meta:
                placed[str(meta["uuid"])] = meta.get("sliceName")
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(position)
    return placed


def test_every_chart_is_placed_on_a_dashboard_tab():
    """A chart that no tab positions ships in the ZIP and is never seen.

    Superset imports it, it occupies a uuid, ``make resync`` maintains it, and
    no user can reach it. Either the layout positions it or it should not be
    in the bundle.
    """
    placed = _placed_by_uuid()
    orphans = sorted(
        f"{name} ({chart['slice_name']})"
        for name, chart in CHARTS
        if chart["uuid"] not in placed
    )
    assert not orphans, f"charts in the bundle but on no dashboard tab: {orphans}"


def test_layout_slice_names_match_the_chart_they_position():
    """The ``sliceName`` beside a positioned uuid must be the chart's real name.

    Superset renders by uuid, so a stale name here is invisible in the running
    dashboard and survives indefinitely — while every reader of the layout, and
    every grep for a chart by name, is misled.
    """
    placed = _placed_by_uuid()
    by_uuid = {chart["uuid"]: chart["slice_name"].strip() for _, chart in CHARTS}

    mismatched = sorted(
        f"{by_uuid[uuid]!r} positioned as {name!r}"
        for uuid, name in placed.items()
        if uuid in by_uuid and (name or "").strip() != by_uuid[uuid]
    )
    assert not mismatched, f"stale sliceName in the layout: {mismatched}"


def test_dashboard_chart_inventory_describes_charts_that_exist():
    """``metadata.charts`` may only name charts the bundle actually ships.

    The inventory is hand-maintained prose about a subset of the charts. When a
    chart is renamed or retired the entry stays behind, so the list accumulates
    descriptions of charts that no longer exist and viz types that no longer
    match — documentation that reads as authoritative and is not.
    """
    by_name = {chart["slice_name"].strip(): chart["viz_type"] for _, chart in CHARTS}

    unknown = sorted(
        entry["slice_name"]
        for entry in _dashboard()["metadata"]["charts"]
        if entry["slice_name"] not in by_name
    )
    assert not unknown, f"inventory names charts that do not exist: {unknown}"

    wrong_viz = sorted(
        f"{entry['slice_name']}: inventory={entry.get('viz_type')} "
        f"actual={by_name[entry['slice_name']]}"
        for entry in _dashboard()["metadata"]["charts"]
        if entry["slice_name"] in by_name
        and entry.get("viz_type") != by_name[entry["slice_name"]]
    )
    assert not wrong_viz, f"inventory states the wrong viz_type: {wrong_viz}"
