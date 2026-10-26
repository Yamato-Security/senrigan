"""Tests for the built-in VPC Flow Logs hunts (``vpc_flow_hunts.yaml``).

Every hunt runs against the VPC Flow Logs fixture, which the real ingester built
from planted scenarios (``sample/vpc_flow/generate_fixtures.py``). A hunt is
trusted only when it returns its planted positive *and* leaves out the near-miss
planted beside it — a query that returns everything passes the first check and
fails the second (PRD_VPC_FLOW_LOGS §7).

The rules shared with the other catalogues (chart configs, wall-clock filters,
shipping SQL) run through ``hunt_catalogue.py``.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from datetime import date
from pathlib import Path

import duckdb
import pytest
import yaml

from profiles import VPC_FLOW_PROFILE
from query import apply_filters

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "sample" / "vpc_flow" / "fixtures" / "vpc-flow-fixture.duckdb"


def _scenarios() -> dict:
    path = REPO / "sample" / "vpc_flow" / "generate_fixtures.py"
    spec = importlib.util.spec_from_file_location("vpc_flow_fixtures", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.SCENARIOS


S = _scenarios()

HUNTS: list[dict] = yaml.safe_load(
    VPC_FLOW_PROFILE.hunts_path.read_text(encoding="utf-8")
)
BY_LABEL = {hunt["label"]: hunt for hunt in HUNTS}
PARAMS = [pytest.param(hunt, id=hunt["label"]) for hunt in HUNTS]

CONTRACT_KEYS = ("requires", "protocols", "ip_versions", "min_span", "limitations")
_VALID_TID = re.compile(r"^T\d{4}(\.\d{3})?$")

# Label -> (result column, values that must appear, values that must not).
CONTROLS: dict[str, tuple[str, set, set]] = {
    "🔍 Vertical Port Scans": (
        "remote_addr",
        {S["vertical_scan"]["remote"]},
        {S["vertical_near_miss"]["remote"], S["horizontal_scan"]["remote"]},
    ),
    "🔍 Horizontal Sweeps": (
        "remote_addr",
        {S["horizontal_scan"]["remote"]},
        {S["vertical_scan"]["remote"]},
    ),
    "🚪 Internet Access to Admin / DB Ports": (
        "remote_addr",
        {S["admin_rdp_accepted"]["remote"], S["admin_ssh_accepted"]["remote"]},
        {S["vertical_near_miss"]["remote"], S["vertical_scan"]["remote"]},
    ),
    "🚪 Rejected, Then Accepted": (
        "remote_addr",
        {S["reject_then_accept"]["remote"]},
        {S["horizontal_scan"]["remote"], S["vertical_near_miss"]["remote"]},
    ),
    "📤 Egress Spike vs Host Baseline": (
        "local_addr",
        {S["exfil"]["local"]},
        {S["beacon"]["local"]},
    ),
    "📤 Unusual Destination Ports": (
        "local_addr",
        {S["c2_port"]["local"], S["mining_port"]["local"]},
        {S["beacon"]["local"], S["exfil"]["local"]},
    ),
    "📤 DNS to Non-Amazon Resolvers": (
        "remote_addr",
        {S["dns_custom_resolver"]["remote"]},
        {S["smtp_out"]["remote"]},
    ),
    "📤 Outbound SMTP": (
        "local_addr",
        {S["smtp_out"]["local"]},
        {S["exfil"]["local"]},
    ),
    "⏱️ Periodic Observations to External Peers": (
        "remote_addr",
        {S["beacon"]["remote"], S["beacon_with_skipdata"]["remote"]},
        {S["cadence_near_miss"]["remote"], S["lateral_near_miss"]["dst"]},
    ),
    "↔️ New Internal Admin-Port Pairs": (
        "flow_src",
        {S["lateral_smb"]["src"]},
        {S["lateral_near_miss"]["src"]},
    ),
    "↔️ Internal Inbound, Then External Egress": (
        "host",
        {S["exfil"]["local"]},
        {S["beacon"]["local"], S["staging_source"]["local"]},
    ),
    "🧪 Unusual IP Protocols": (
        "flow_src",
        {S["gre"]["local"]},
        {S["beacon"]["local"]},
    ),
    "🧪 UDP Fan-Out to External Hosts": (
        "flow_src",
        {S["udp_fanout"]["local"]},
        {S["dns_custom_resolver"]["local"]},
    ),
    "🧪 ICMP and ICMPv6 Peers": (
        "flow_src",
        {S["icmp"]["remote"], S["icmpv6"]["remote"]},
        {S["vertical_scan"]["remote"]},
    ),
    "🌍 Accepted Inbound by Country": (
        "country_code",
        {"GB"},
        {"PRIVATE", None},
    ),
    "🛡️ BPA and Encryption-Control Rejections": (
        "reject_reason",
        {"BPA", "EC"},
        {None},
    ),
    "🧭 Flow Log Sources and Field Coverage": (
        "flow_log_id",
        {"fl-0a1b2c3d4e5f60001", "fl-0f1e2d3c4b5a60002"},
        {None},
    ),
    "🧭 SKIPDATA Gaps by Interface": (
        "local_addresses",
        {S["beacon_with_skipdata"]["local"]},
        {None},
    ),
}


@pytest.fixture(scope="module")
def conn():
    connection = duckdb.connect(str(FIXTURE), read_only=True)
    yield connection
    connection.close()


def _run(conn, sql: str) -> list[dict]:
    cursor = conn.execute(sql)
    names = [d[0] for d in cursor.description]
    return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]


def test_catalogue_is_non_empty_and_labels_unique() -> None:
    assert HUNTS
    labels = [hunt["label"] for hunt in HUNTS]
    assert len(labels) == len(set(labels))


def test_every_hunt_has_a_control() -> None:
    """A hunt without a planted positive and near-miss is not reviewed."""
    assert set(BY_LABEL) == set(CONTROLS)


@pytest.mark.parametrize("hunt", PARAMS)
def test_hunt_declares_its_contract(hunt: dict) -> None:
    for key in (
        "category",
        "label",
        "description",
        "severity",
        "prompt",
        "sql",
        *CONTRACT_KEYS,
    ):
        assert hunt.get(key), key
    assert hunt["severity"] in {"P1", "P2", "P3", "P4"}
    assert set(hunt["ip_versions"]) <= {4, 6}


@pytest.mark.parametrize("hunt", PARAMS)
def test_required_columns_exist(conn, hunt: dict) -> None:
    columns = {row[0] for row in conn.execute("DESCRIBE vpc_flow_logs").fetchall()}
    assert set(hunt["requires"]) <= columns
    assert set(hunt.get("optional") or []) <= columns


@pytest.mark.parametrize("hunt", PARAMS)
def test_hunt_sql_shape(hunt: dict) -> None:
    sql = hunt["sql"]
    assert re.search(r"\bORDER BY\b", sql, re.I)
    assert re.search(r"\bLIMIT\s+\d+\s*$", sql.strip(), re.I)
    assert "vpc_flow_logs_geo" not in sql, "the date filter does not reach the view"
    assert not re.search(r"sum\(\s*bytes\s*\)", sql, re.I), "BPA records carry no bytes"
    assert not re.search(r"traffic_path\s*(=|IN)\s*\(?\s*2\b", sql, re.I)


@pytest.mark.parametrize("hunt", PARAMS)
def test_direction_dependent_hunts_use_recorded_direction(hunt: dict) -> None:
    if re.search(r"\b(local_addr|remote_addr|flow_direction)\b", hunt["sql"]):
        assert "direction_source = 'record'" in hunt["sql"]


@pytest.mark.parametrize("hunt", PARAMS)
def test_hunt_techniques_are_well_formed(hunt: dict) -> None:
    for technique in hunt.get("techniques") or []:
        assert _VALID_TID.match(technique["tid"]), technique
        assert technique["name"] and technique["url"].startswith("https://")


@pytest.mark.parametrize("hunt", PARAMS)
def test_hunt_validates_with_the_date_filter(conn, hunt: dict) -> None:
    sql = apply_filters(
        hunt["sql"],
        profile=VPC_FLOW_PROFILE,
        start_date=date(2024, 1, 14),
        end_date=date(2024, 1, 15),
    )
    conn.execute(f"EXPLAIN {sql}")


@pytest.mark.parametrize("hunt", PARAMS)
def test_positive_and_near_miss_controls(conn, hunt: dict) -> None:
    column, positives, negatives = CONTROLS[hunt["label"]]
    rows = _run(conn, hunt["sql"])
    values = {row[column] for row in rows}
    assert positives <= values, f"missing planted positive: {positives - values}"
    assert not (negatives & values), f"near-miss reported: {negatives & values}"
