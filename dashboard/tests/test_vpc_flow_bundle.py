"""Tests for the VPC Flow Logs Superset bundle (``assets/vpc_flow_default/``).

Every dataset and every chart is executed against the VPC Flow Logs fixture —
a database produced by the real ingester from planted scenarios
(``sample/vpc_flow/generate_fixtures.py``). Structural checks catch a chart
that cannot render; the scenario checks catch one that renders the wrong thing:
each derived dataset must surface its planted positive and ignore the near-miss
beside it (PRD_VPC_FLOW_LOGS §7–§8).
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import duckdb
import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
ASSETS = REPO / "dashboard" / "assets"
BUNDLE = ASSETS / "vpc_flow_default"
FIXTURE = REPO / "sample" / "vpc_flow" / "fixtures" / "vpc-flow-fixture.duckdb"


def _scenarios() -> dict:
    """The scenario catalogue the fixture was generated from."""
    path = REPO / "sample" / "vpc_flow" / "generate_fixtures.py"
    spec = importlib.util.spec_from_file_location("vpc_flow_fixtures", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.SCENARIOS


SCENARIOS = _scenarios()


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _charts() -> list[Path]:
    return sorted((BUNDLE / "charts").glob("*.yaml"))


def _datasets() -> dict[str, dict]:
    return {
        _load(p)["uuid"]: _load(p) for p in sorted((BUNDLE / "datasets").glob("*.yaml"))
    }


def _dataset_by_table(table: str) -> dict:
    matches = [d for d in _datasets().values() if d["table_name"] == table]
    assert len(matches) == 1, f"no single dataset named {table}"
    return matches[0]


@pytest.fixture(scope="module")
def conn():
    connection = duckdb.connect(str(FIXTURE), read_only=True)
    yield connection
    connection.close()


def _rows(conn, dataset: dict, select: str = "*", where: str = "TRUE") -> list[dict]:
    cursor = conn.execute(
        f"SELECT {select} FROM ({dataset['sql']}) AS _t WHERE {where}"
    )
    names = [d[0] for d in cursor.description]
    return [dict(zip(names, row, strict=True)) for row in cursor.fetchall()]


# ── Chart → SQL, the way Superset aggregates it ─────────────────────────────


def _sql_of(item, dataset_metrics: dict[str, str]) -> str:
    """A groupby/metric entry as SQL: a column name, an ad-hoc expression or a saved metric."""
    if isinstance(item, dict):
        return item["sqlExpression"]
    return dataset_metrics.get(item, f'"{item}"')


def chart_query(chart: dict, dataset: dict) -> str:
    """The aggregate query a chart issues: dimensions, metrics, WHERE, row limit."""
    params = chart["params"]
    saved = {m["metric_name"]: m["expression"] for m in dataset.get("metrics") or []}

    dimensions = []
    for key in ("x_axis", "entity"):
        if params.get(key):
            dimensions.append(params[key])
    dimensions += list(params.get("groupby") or []) + list(params.get("columns") or [])
    metrics = [params["metric"]] if params.get("metric") else list(params["metrics"])

    select = [_sql_of(d, saved) for d in dimensions] + [
        _sql_of(m, saved) for m in metrics
    ]
    where = [f["sqlExpression"] for f in params.get("adhoc_filters") or []]
    sql = f"SELECT {', '.join(select)} FROM ({dataset['sql']}) AS _t"
    if where:
        sql += " WHERE " + " AND ".join(f"({w})" for w in where)
    if dimensions:
        sql += " GROUP BY ALL"
    order = len(dimensions) + 1
    sql += (
        f" ORDER BY {order} DESC"
        if params.get("order_desc", True)
        else f" ORDER BY {order}"
    )
    return sql + f" LIMIT {params.get('row_limit', 10000)}"


def _chart(slice_name: str) -> dict:
    for path in _charts():
        chart = _load(path)
        if chart["slice_name"] == slice_name:
            return chart
    raise AssertionError(f"no chart named {slice_name!r}")


def _chart_rows(conn, slice_name: str) -> list[tuple]:
    chart = _chart(slice_name)
    return conn.execute(
        chart_query(chart, _datasets()[chart["dataset_uuid"]])
    ).fetchall()


# ── Bundle structure ────────────────────────────────────────────────────────


def test_bundle_has_the_required_files() -> None:
    for name in ("metadata.yaml", "dashboard.yaml"):
        assert (BUNDLE / name).is_file(), name
    assert _charts(), "no charts"
    assert _datasets(), "no datasets"


def test_database_is_the_shared_cloudtrail_connection() -> None:
    """Flow logs live in threat_hunting.db, so the bundle reuses that connection verbatim."""
    ours = (BUNDLE / "databases" / "CloudTrail_DuckDB.yaml").read_text(encoding="utf-8")
    theirs = (
        ASSETS / "cloudtrail_default" / "databases" / "CloudTrail_DuckDB.yaml"
    ).read_text(encoding="utf-8")
    assert ours == theirs
    for dataset in _datasets().values():
        assert (
            dataset["database_uuid"]
            == _load(BUNDLE / "databases" / "CloudTrail_DuckDB.yaml")["uuid"]
        )


def test_uuids_are_unique_across_every_bundle() -> None:
    seen: dict[str, Path] = {}
    for path in ASSETS.glob("*/**/*.yaml"):
        uuid = (_load(path) or {}).get("uuid")
        if not uuid or path.name == "CloudTrail_DuckDB.yaml":
            continue
        assert uuid not in seen, f"{path} reuses the uuid of {seen[uuid]}"
        seen[uuid] = path


def test_every_dataset_is_virtual_and_runs(conn) -> None:
    for dataset in _datasets().values():
        assert dataset.get("sql"), f"{dataset['table_name']}: must be virtual"
        conn.execute(f"SELECT * FROM ({dataset['sql']}) AS _t LIMIT 1")


def test_declared_columns_match_the_dataset_sql(conn) -> None:
    for dataset in _datasets().values():
        produced = {
            d[0]
            for d in conn.execute(
                f"SELECT * FROM ({dataset['sql']}) AS _t LIMIT 0"
            ).description
        }
        declared = {c["column_name"] for c in dataset["columns"]}
        assert declared == produced, (
            f"{dataset['table_name']}: declared-only {sorted(declared - produced)}, "
            f"undeclared {sorted(produced - declared)}"
        )


def test_main_dttm_col_is_really_temporal(conn) -> None:
    for dataset in _datasets().values():
        dttm = dataset["main_dttm_col"]
        (kind,) = conn.execute(
            f'SELECT typeof("{dttm}") FROM ({dataset["sql"]}) AS _t LIMIT 1'
        ).fetchone()
        assert "TIMESTAMP" in kind.upper(), f"{dataset['table_name']}: {dttm} is {kind}"
        declared = {c["column_name"]: c for c in dataset["columns"]}
        assert declared[dttm]["is_dttm"] is True


def test_every_chart_query_runs_and_returns_rows(conn) -> None:
    """Every chart renders something on a database that holds its scenario."""
    datasets = _datasets()
    for path in _charts():
        chart = _load(path)
        rows = conn.execute(
            chart_query(chart, datasets[chart["dataset_uuid"]])
        ).fetchall()
        assert rows, f"{path.name}: empty on the fixture"


def test_chart_columns_exist_in_their_dataset() -> None:
    datasets = _datasets()
    for path in _charts():
        chart = _load(path)
        declared = {
            c["column_name"] for c in datasets[chart["dataset_uuid"]]["columns"]
        }
        params = chart["params"]
        names = [
            params.get("entity"),
            params.get("x_axis"),
            params.get("granularity_sqla"),
        ]
        names += list(params.get("groupby") or []) + list(params.get("columns") or [])
        for name in names:
            if isinstance(name, str):
                assert name in declared, f"{path.name}: unknown column {name}"


def test_every_chart_is_placed_and_every_placement_exists() -> None:
    dashboard = _load(BUNDLE / "dashboard.yaml")
    placed = {
        c["meta"]["uuid"]: c["meta"]["sliceName"]
        for c in dashboard["position"].values()
        if isinstance(c, dict) and c.get("type") == "CHART"
    }
    charts = {_load(p)["uuid"]: _load(p)["slice_name"] for p in _charts()}
    assert placed == charts


def test_slice_names_unique_and_row_limits_declared() -> None:
    names = [_load(p)["slice_name"] for p in _charts()]
    assert len(names) == len(set(names))
    for path in _charts():
        chart = _load(path)
        if chart["viz_type"] != "big_number_total":
            assert chart["params"].get("row_limit"), path.name


def test_native_filters_target_declared_columns() -> None:
    dashboard = _load(BUNDLE / "dashboard.yaml")
    datasets = _datasets()
    for native in dashboard["metadata"]["native_filter_configuration"]:
        for target in native["targets"]:
            if not target:
                continue
            declared = {
                c["column_name"] for c in datasets[target["datasetUuid"]]["columns"]
            }
            assert target["column"]["name"] in declared, native["name"]


# ── Wording and evidence rules (PRD §6) ─────────────────────────────────────


def _expressions(chart: dict) -> list[str]:
    params = chart["params"]
    items = [params.get("metric"), params.get("x_axis"), params.get("entity")]
    items += list(params.get("metrics") or []) + list(params.get("groupby") or [])
    items += list(params.get("columns") or []) + list(params.get("adhoc_filters") or [])
    return [
        i["sqlExpression"]
        for i in items
        if isinstance(i, dict) and "sqlExpression" in i
    ]


def test_charts_never_count_connections() -> None:
    """A row is an observation; the word "connection" would overstate it (D7)."""
    for path in _charts():
        chart = _load(path)
        labels = [chart["slice_name"]] + [
            m.get("label", "")
            for m in chart["params"].get("metrics") or []
            if isinstance(m, dict)
        ]
        metric = chart["params"].get("metric")
        if isinstance(metric, dict):
            labels.append(metric.get("label", ""))
        for label in labels:
            assert not re.search(r"connection", label, re.I), f"{path.name}: {label!r}"


def test_byte_metrics_exclude_bpa_rows() -> None:
    """BPA records carry no bytes; summing raw `bytes` would read them as zero."""
    for path in _charts():
        for expression in _expressions(_load(path)):
            assert not re.search(
                r"\bbytes\b", expression
            ), f"{path.name}: use bytes_measured"


def test_traffic_path_is_only_read_through_its_label() -> None:
    """Value 2 is IGW *or* gateway endpoint; only the label keeps that ambiguity visible."""
    for path in _charts():
        chart = _load(path)
        columns = [
            c for c in chart["params"].get("groupby") or [] if isinstance(c, str)
        ]
        assert "traffic_path" not in columns, path.name
        for expression in _expressions(chart):
            assert not re.search(r"\btraffic_path\b(?!_label)", expression), path.name


def test_direction_dependent_charts_use_recorded_direction() -> None:
    """local/remote/flow_direction are definitive only when direction_source = 'record'.

    Applies to charts on the raw records dataset; the derived datasets filter on
    the recorded direction inside their own SQL.
    """
    records_uuid = _dataset_by_table("vpc_flow_records")["uuid"]
    for path in _charts():
        chart = _load(path)
        if chart["dataset_uuid"] != records_uuid:
            continue
        text = (
            " ".join(_expressions(chart))
            + " "
            + " ".join(
                c for c in chart["params"].get("groupby") or [] if isinstance(c, str)
            )
        )
        if re.search(r"\b(local_addr|remote_addr|flow_direction)\b", text):
            filters = " ".join(
                f["sqlExpression"] for f in chart["params"]["adhoc_filters"]
            )
            assert "direction_source = 'record'" in filters, path.name


def test_derived_datasets_use_recorded_direction() -> None:
    for dataset in _datasets().values():
        sql = dataset["sql"]
        if dataset["table_name"] == "vpc_flow_records":
            continue
        if re.search(r"\b(local_addr|remote_addr|flow_direction)\b", sql):
            assert "direction_source = 'record'" in sql, dataset["table_name"]


def test_traffic_path_two_is_labelled_ambiguous(conn) -> None:
    rows = dict(_chart_rows(conn, "Egress Bytes by Traffic Path"))
    assert "IGW or gateway endpoint (ambiguous)" in rows
    assert "Internet gateway" in rows and "Gateway endpoint" in rows


# ── Scenario checks: planted positive in, near-miss out ─────────────────────


def test_vertical_scan_ranks_the_scanner_first(conn) -> None:
    top = _chart_rows(conn, "Vertical Scan Candidates")[0]
    assert top[0] == SCENARIOS["vertical_scan"]["remote"]


def test_horizontal_scan_ranks_the_scanner_first(conn) -> None:
    top = _chart_rows(conn, "Horizontal Scan Candidates")[0]
    assert top[0] == SCENARIOS["horizontal_scan"]["remote"]


def test_internet_admin_ports_accepted(conn) -> None:
    remotes = {
        row[0] for row in _chart_rows(conn, "Internet to Admin / DB Ports — Accepted")
    }
    assert SCENARIOS["admin_rdp_accepted"]["remote"] in remotes
    assert SCENARIOS["admin_ssh_accepted"]["remote"] in remotes
    assert SCENARIOS["vertical_near_miss"]["remote"] not in remotes


def test_reject_then_accept(conn) -> None:
    rows = _rows(conn, _dataset_by_table("vpc_flow_reject_accept"))
    remotes = {r["remote_addr"] for r in rows}
    assert SCENARIOS["reject_then_accept"]["remote"] in remotes
    assert SCENARIOS["horizontal_scan"]["remote"] not in remotes, "only rejected"
    assert SCENARIOS["vertical_near_miss"]["remote"] not in remotes, "only accepted"


def test_periodicity_finds_the_beacon_and_not_the_logging_cadence(conn) -> None:
    rows = {
        (r["local_addr"], r["remote_addr"]): r
        for r in _rows(conn, _dataset_by_table("vpc_flow_periodicity"))
    }
    beacon = rows[(SCENARIOS["beacon"]["local"], SCENARIOS["beacon"]["remote"])]
    assert beacon["confidence"] == "high"
    assert beacon["period_secs"] == 300
    skipped = rows[
        (
            SCENARIOS["beacon_with_skipdata"]["local"],
            SCENARIOS["beacon_with_skipdata"]["remote"],
        )
    ]
    assert skipped["skipdata_overlaps"] > 0
    assert skipped["confidence"] != "high"
    cadence = SCENARIOS["cadence_near_miss"]
    assert (cadence["local"], cadence["remote"]) not in rows
    assert all(
        r["remote_addr"] != SCENARIOS["lateral_near_miss"]["dst"] for r in rows.values()
    )


def test_egress_outlier_flags_the_exfil_host(conn) -> None:
    rows = _rows(
        conn,
        _dataset_by_table("vpc_flow_egress_daily"),
        where="ratio_to_baseline IS NOT NULL ORDER BY ratio_to_baseline DESC",
    )
    assert rows[0]["local_addr"] == SCENARIOS["exfil"]["local"]
    assert rows[0]["ratio_to_baseline"] > 100


def test_staging_then_egress(conn) -> None:
    hosts = {r["host"] for r in _rows(conn, _dataset_by_table("vpc_flow_staging"))}
    assert hosts == {SCENARIOS["exfil"]["local"]}


def test_new_internal_pairs(conn) -> None:
    rows = _rows(
        conn, _dataset_by_table("vpc_flow_internal_pairs"), where="is_new_pair"
    )
    pairs = {(r["flow_src"], r["dstport"]) for r in rows}
    assert (SCENARIOS["lateral_smb"]["src"], 445) in pairs
    near = SCENARIOS["lateral_near_miss"]
    assert (near["src"], near["port"]) not in pairs


def test_unusual_ports_and_dns(conn) -> None:
    ports = {row[2] for row in _chart_rows(conn, "Unusual Destination Ports")}
    assert {SCENARIOS["c2_port"]["port"], SCENARIOS["mining_port"]["port"]} <= ports
    assert 443 not in ports
    resolvers = {row[1] for row in _chart_rows(conn, "DNS to Non-Amazon Resolvers")}
    assert resolvers == {SCENARIOS["dns_custom_resolver"]["remote"]}


def test_coverage_lists_both_subscriptions_and_their_scope(conn) -> None:
    sources = _rows(conn, _dataset_by_table("vpc_flow_sources"))
    assert len(sources) == 2
    configs = _rows(conn, _dataset_by_table("vpc_flow_log_configs"))
    assert {c["traffic_type"] for c in configs} == {"ALL"}


def test_inbound_accepted_map_has_countries(conn) -> None:
    countries = {row[0] for row in _chart_rows(conn, "Inbound Accepted — Origin Map")}
    assert "GB" in countries
    assert "PRIVATE" not in countries


def test_every_chart_declares_its_time_column() -> None:
    """Without one, the date-range filter falls back to a column the dataset may not have."""
    datasets = _datasets()
    for path in _charts():
        chart = _load(path)
        dataset = datasets[chart["dataset_uuid"]]
        temporal = {c["column_name"] for c in dataset["columns"] if c["is_dttm"]}
        assert chart["params"].get("granularity_sqla") in temporal, path.name
