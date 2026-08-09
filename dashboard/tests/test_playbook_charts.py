"""Charts added to close the gaps the AWS incident response playbooks exposed.

Fourteen charts, five of which are only expressible because the extended columns
(``session_issuer_arn``, ``user_identity_access_key_id``,
``session_mfa_authenticated``) were promoted into the Superset dataset — a chart
grouping by a column the dataset does not declare renders as an error, not as an
empty panel.

Each chart must exist as YAML, carry a unique UUID, and be placed in the tab an
analyst would look in; ``test_dashboard_yaml.py`` separately enforces that no
chart YAML is left unreferenced.
"""

from __future__ import annotations

import pathlib

import pytest
import yaml

ASSETS = pathlib.Path(__file__).parent.parent / "assets" / "cloudtrail_default"
CHARTS = ASSETS / "charts"
DASHBOARD = ASSETS / "dashboard.yaml"
DATASET = ASSETS / "datasets" / "cloudtrail_events.yaml"

# file stem -> (tab id, viz_type)
NEW_CHARTS: dict[str, tuple[str, str]] = {
    "role_chain_depth": ("TAB-identity", "table"),
    "session_key_activity": ("TAB-identity", "table"),
    "kpi_non_mfa_api_calls": ("TAB-identity", "big_number_total"),
    "federated_login_origin": ("TAB-identity", "table"),
    "permission_set_grants": ("TAB-identity", "echarts_timeseries_bar"),
    "kpi_p1_indicators": ("TAB-threat", "big_number_total"),
    "kpi_p2_indicators": ("TAB-threat", "big_number_total"),
    "off_hours_heatmap": ("TAB-temporal", "heatmap"),
    "principal_daily_volume": ("TAB-temporal", "echarts_timeseries_bar"),
    "data_access_scope": ("TAB-s3-rds", "table"),
    "cross_account_object_copy": ("TAB-s3-rds", "table"),
    "ransom_note_placement": ("TAB-s3-rds", "table"),
    "agentcore_token_issuance": ("TAB-ai", "echarts_timeseries_bar"),
    "agentcore_gateway_changes": ("TAB-ai", "table"),
}

# Charts that exist only because an extended column was promoted.
EXTENDED_COLUMN_CHARTS = {
    "role_chain_depth": "session_issuer_arn",
    "session_key_activity": "user_identity_access_key_id",
    "kpi_non_mfa_api_calls": "session_mfa_authenticated",
    "federated_login_origin": "additional_event_data",
    "permission_set_grants": "event_source",
}

TOTAL_CHARTS = 115


def load(path: pathlib.Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def dashboard_position() -> dict:
    return load(DASHBOARD)["position"]


def chart_nodes() -> dict[str, dict]:
    return {
        key: node
        for key, node in dashboard_position().items()
        if isinstance(node, dict) and node.get("type") == "CHART"
    }


def tab_of(uuid: str) -> str | None:
    """Walk up from the chart node to the TAB that ultimately contains it."""
    position = dashboard_position()
    node_id = next(
        (
            key
            for key, node in position.items()
            if isinstance(node, dict)
            and node.get("type") == "CHART"
            and node["meta"]["uuid"] == uuid
        ),
        None,
    )
    if node_id is None:
        return None

    parent_of = {
        child: key
        for key, node in position.items()
        if isinstance(node, dict)
        for child in node.get("children", [])
    }
    while node_id in parent_of:
        node_id = parent_of[node_id]
        if node_id.startswith("TAB-"):
            return node_id
    return None


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("stem", sorted(NEW_CHARTS))
def test_chart_yaml_exists(stem: str) -> None:
    assert (CHARTS / f"{stem}.yaml").exists()


@pytest.mark.parametrize("stem", sorted(NEW_CHARTS))
def test_chart_has_required_keys(stem: str) -> None:
    chart = load(CHARTS / f"{stem}.yaml")
    for key in ("uuid", "version", "dataset_uuid", "slice_name", "viz_type", "params"):
        assert chart.get(key), f"{stem}.yaml is missing {key}"
    assert chart["description"].strip(), f"{stem}.yaml has no description"


@pytest.mark.parametrize("stem", sorted(NEW_CHARTS))
def test_chart_viz_type_matches_spec(stem: str) -> None:
    assert load(CHARTS / f"{stem}.yaml")["viz_type"] == NEW_CHARTS[stem][1]


@pytest.mark.parametrize("stem", sorted(NEW_CHARTS))
def test_chart_uses_the_shared_dataset(stem: str) -> None:
    expected = load(CHARTS / "kpi_total_events.yaml")["dataset_uuid"]
    assert load(CHARTS / f"{stem}.yaml")["dataset_uuid"] == expected


def test_chart_uuids_are_unique() -> None:
    uuids = [load(path)["uuid"] for path in CHARTS.glob("*.yaml")]
    assert len(uuids) == len(set(uuids)), "duplicate chart UUID in the bundle"


def test_chart_ids_are_unique_per_chart() -> None:
    """One chart may appear on two tabs, but two charts may not share an id.

    ``CloudTrail Events Over Time`` is deliberately placed twice, so the
    invariant is a 1:1 mapping between chartId and UUID, not distinct ids per
    node.
    """
    by_id: dict[int, set[str]] = {}
    for node in chart_nodes().values():
        by_id.setdefault(node["meta"]["chartId"], set()).add(node["meta"]["uuid"])

    collisions = {cid: uuids for cid, uuids in by_id.items() if len(uuids) > 1}
    assert not collisions, f"chartId reused by different charts: {collisions}"


# ---------------------------------------------------------------------------
# Placement
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("stem", sorted(NEW_CHARTS))
def test_chart_is_placed_in_the_expected_tab(stem: str) -> None:
    chart = load(CHARTS / f"{stem}.yaml")
    assert (
        tab_of(chart["uuid"]) == NEW_CHARTS[stem][0]
    ), f"{chart['slice_name']!r} is not in {NEW_CHARTS[stem][0]}"


@pytest.mark.parametrize("stem", sorted(NEW_CHARTS))
def test_dashboard_node_names_match_the_chart(stem: str) -> None:
    chart = load(CHARTS / f"{stem}.yaml")
    node = next(
        node for node in chart_nodes().values() if node["meta"]["uuid"] == chart["uuid"]
    )
    assert node["meta"]["sliceName"] == chart["slice_name"]


# ---------------------------------------------------------------------------
# Extended columns
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("stem,column", sorted(EXTENDED_COLUMN_CHARTS.items()))
def test_chart_references_its_extended_column(stem: str, column: str) -> None:
    assert column in (CHARTS / f"{stem}.yaml").read_text(encoding="utf-8")


@pytest.mark.parametrize("column", sorted(set(EXTENDED_COLUMN_CHARTS.values())))
def test_extended_columns_are_declared_in_the_dataset(column: str) -> None:
    """A chart grouping by an undeclared column renders an error, not a blank."""
    names = {c["column_name"] for c in load(DATASET)["columns"]}
    assert column in names


# ---------------------------------------------------------------------------
# Bundle totals
# ---------------------------------------------------------------------------


def test_bundle_chart_count() -> None:
    assert len(list(CHARTS.glob("*.yaml"))) == TOTAL_CHARTS


def test_playbook_panel_is_present() -> None:
    """The Overview tab carries the hunt-finding → playbook routing table."""
    position = dashboard_position()
    markdown = [
        node
        for node in position.values()
        if isinstance(node, dict) and node.get("type") == "MARKDOWN"
    ]
    codes = " ".join(node["meta"].get("code", "") for node in markdown)
    assert (
        "aws-incident-response-playbooks" in codes
    ), "no Overview panel routes findings to a response playbook"
