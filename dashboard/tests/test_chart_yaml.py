"""Tests for Superset chart YAML files.

Validates that every chart YAML in cloudtrail_default/charts/ conforms to
the structure required by the Superset v1 dashboard import format.
"""

import os
import re
import sys

import pytest
import yaml

CHARTS_DIR = os.path.join(
    os.path.dirname(__file__), "..", "assets", "cloudtrail_default", "charts"
)
DATASET_YAML_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "assets",
    "cloudtrail_default",
    "datasets",
    "cloudtrail_events.yaml",
)
REGISTER_DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "init")
REQUIRED_CHART_FIELDS = {
    "uuid",
    "version",
    "dataset_uuid",
    "slice_name",
    "viz_type",
    "params",
}
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I
)
DATASET_UUID = "d8444b4a-ac55-4710-a777-a5b940bebabe"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def load_all_charts() -> list[tuple[str, dict]]:
    """Return (filename, parsed_yaml) for every .yaml in charts/."""
    results = []
    for fname in sorted(os.listdir(CHARTS_DIR)):
        if fname.endswith(".yaml"):
            path = os.path.join(CHARTS_DIR, fname)
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            results.append((fname, data))
    return results


# ---------------------------------------------------------------------------
# Parametric tests — run once per chart file
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fname, chart", load_all_charts())
def test_chart_has_required_fields(fname: str, chart: dict) -> None:
    """Every chart must declare all required top-level fields."""
    missing = REQUIRED_CHART_FIELDS - set(chart.keys())
    assert not missing, f"{fname} is missing fields: {missing}"


@pytest.mark.parametrize("fname, chart", load_all_charts())
def test_chart_dataset_uuid(fname: str, chart: dict) -> None:
    """Every chart must reference the canonical cloudtrail_events dataset."""
    assert chart.get("dataset_uuid") == DATASET_UUID, (
        f"{fname}: dataset_uuid mismatch — got '{chart.get('dataset_uuid')}', "
        f"expected '{DATASET_UUID}'"
    )


@pytest.mark.parametrize("fname, chart", load_all_charts())
def test_chart_uuid_format(fname: str, chart: dict) -> None:
    """Chart UUID must be a valid lowercase UUID v4 string."""
    uuid = chart.get("uuid", "")
    assert UUID_RE.match(uuid), f"{fname}: '{uuid}' is not a valid UUID"


@pytest.mark.parametrize("fname, chart", load_all_charts())
def test_chart_params_not_empty(fname: str, chart: dict) -> None:
    """params must be a non-empty mapping."""
    assert chart.get("params"), f"{fname}: params must not be empty"


# ---------------------------------------------------------------------------
# Global tests
# ---------------------------------------------------------------------------

# Valid aggregator names accepted by React Pivottable (used in Superset pivot_table_v2).
# Superset throws "this.props.aggregatorsFactory(...)[this.props.aggregatorName] is not a
# function" when this value is not an exact case-sensitive match.
_VALID_AGGREGATE_FUNCTIONS: frozenset[str] = frozenset(
    {
        "Count",
        "Count Unique Values",
        "List Unique Values",
        "Sum",
        "Integer Sum",
        "Average",
        "Median",
        "Sample Variance",
        "Sample Standard Deviation",
        "Minimum",
        "Maximum",
        "First",
        "Last",
        "Sum as Fraction of Total",
        "Sum as Fraction of Rows",
        "Sum as Fraction of Columns",
        "Count as Fraction of Total",
        "Count as Fraction of Rows",
        "Count as Fraction of Columns",
    }
)


def test_pivot_table_aggregate_function_valid() -> None:
    """pivot_table_v2 charts must use a valid React Pivottable aggregator name.

    Using an invalid name (e.g. 'SUM' instead of 'Sum') causes:
      TypeError: this.props.aggregatorsFactory(...)[this.props.aggregatorName]
                 is not a function
    """
    offenders = []
    for fname, chart in load_all_charts():
        if chart.get("viz_type") != "pivot_table_v2":
            continue
        agg = chart.get("params", {}).get("aggregateFunction")
        if agg is not None and agg not in _VALID_AGGREGATE_FUNCTIONS:
            offenders.append((fname, agg))
    assert not offenders, (
        f"pivot_table_v2 charts have invalid aggregateFunction: {offenders}\n"
        f"Valid values: {sorted(_VALID_AGGREGATE_FUNCTIONS)}"
    )


def test_all_chart_uuids_unique() -> None:
    """No two chart files may share the same UUID."""
    charts = load_all_charts()
    uuids = [c["uuid"] for _, c in charts]
    duplicates = {u for u in uuids if uuids.count(u) > 1}
    assert not duplicates, f"Duplicate chart UUIDs detected: {duplicates}"


# ---------------------------------------------------------------------------
# Sprint-1 mandatory charts
# ---------------------------------------------------------------------------


def _find_chart_by_filename(fragment: str) -> tuple[str, dict] | None:
    for fname, chart in load_all_charts():
        if fragment in fname.lower():
            return fname, chart
    return None


def test_dsh22_defense_evasion_exists() -> None:
    """DSH-22: security_monitoring_changes.yaml (defense-evasion catch-all) must exist."""
    result = _find_chart_by_filename("security_monitoring_changes")
    assert result is not None, "charts/security_monitoring_changes.yaml not found"
    _, chart = result
    assert chart["viz_type"] == "table"
    assert "Security Monitoring" in chart["slice_name"]


def test_dsh28_mfa_less_login_trend_exists() -> None:
    """DSH-28: mfa_less_login_trend.yaml must exist with correct metadata."""
    result = _find_chart_by_filename("mfa_less_login_trend")
    assert result is not None, "charts/mfa_less_login_trend.yaml not found"
    _, chart = result
    assert chart["viz_type"] == "echarts_timeseries_bar"
    assert "MFA" in chart["slice_name"]


# ---------------------------------------------------------------------------
# Sprint-2 charts
# ---------------------------------------------------------------------------


def test_dsh19_login_heatmap_exists() -> None:
    """DSH-19: login_heatmap.yaml must exist."""
    result = _find_chart_by_filename("login_heatmap")
    assert result is not None, "charts/login_heatmap.yaml not found"
    _, chart = result
    assert chart["viz_type"] in ("heatmap", "pivot_table_v2", "table")


def test_dsh20_write_read_ratio_exists() -> None:
    """DSH-20: write_read_ratio.yaml must exist."""
    result = _find_chart_by_filename("write_read_ratio")
    assert result is not None, "charts/write_read_ratio.yaml not found"
    _, chart = result
    assert chart["viz_type"] == "echarts_timeseries_bar"


def test_dsh21_throttling_spikes_exists() -> None:
    """DSH-21: throttling_spikes.yaml must exist."""
    result = _find_chart_by_filename("throttling_spikes")
    assert result is not None, "charts/throttling_spikes.yaml not found"
    _, chart = result
    assert chart["viz_type"] == "echarts_timeseries_bar"


# ---------------------------------------------------------------------------
# Sprint-3 charts
# ---------------------------------------------------------------------------


def test_dsh23_secrets_access_anomaly_exists() -> None:
    """DSH-23: secrets_access_anomaly.yaml must exist."""
    assert _find_chart_by_filename("secrets_access_anomaly") is not None


def test_dsh24_org_scp_changes_exists() -> None:
    """DSH-24: org_scp_changes.yaml must exist."""
    assert _find_chart_by_filename("org_scp_changes") is not None


def test_dsh27_assumed_role_external_ip_exists() -> None:
    """DSH-27: assumed_role_external_ip.yaml must exist."""
    assert _find_chart_by_filename("assumed_role_external_ip") is not None


def test_dsh30_priv_esc_timeline_exists() -> None:
    """DSH-30: iam_privilege_change_timeline.yaml must exist."""
    assert _find_chart_by_filename("iam_privilege_change_timeline") is not None


# ---------------------------------------------------------------------------
# Sprint-4 charts
# ---------------------------------------------------------------------------


def test_dsh25_s3_protection_changes_exists() -> None:
    """DSH-25: s3_protection_changes.yaml must exist."""
    assert _find_chart_by_filename("s3_protection_changes") is not None


def test_dsh26_first_time_services_exists() -> None:
    """DSH-26: first_time_services.yaml must exist."""
    assert _find_chart_by_filename("first_time_services") is not None


def test_dsh29_route53_dns_changes_exists() -> None:
    """DSH-29: route53_dns_changes.yaml must exist."""
    assert _find_chart_by_filename("route53_dns_changes") is not None


# ---------------------------------------------------------------------------
# Sprint-5 charts — High-Risk API Monitor (Tab 6)
# ---------------------------------------------------------------------------


def test_hrm_timeseries_exists() -> None:
    """HRM-39: hrm_timeseries.yaml must exist with echarts_timeseries_bar."""
    result = _find_chart_by_filename("hrm_timeseries")
    assert result is not None, "charts/hrm_timeseries.yaml not found"
    _, chart = result
    assert chart["viz_type"] == "echarts_timeseries_bar"
    assert "High-Risk" in chart["slice_name"]


def test_hrm_top_calls_exists() -> None:
    """HRM-40: hrm_top_calls.yaml must exist with bar viz."""
    result = _find_chart_by_filename("hrm_top_calls")
    assert result is not None, "charts/hrm_top_calls.yaml not found"
    _, chart = result
    assert chart["viz_type"] == "bar"


def test_hrm_top_actors_exists() -> None:
    """HRM-42: hrm_top_actors.yaml must exist with bar viz."""
    result = _find_chart_by_filename("hrm_top_actors")
    assert result is not None, "charts/hrm_top_actors.yaml not found"
    _, chart = result
    assert chart["viz_type"] == "bar"


def test_hrm_defense_evasion_table_exists() -> None:
    """HRM-44: hrm_security_service_mods.yaml must exist with table viz."""
    result = _find_chart_by_filename("hrm_security_service_mods")
    assert result is not None, "charts/hrm_security_service_mods.yaml not found"
    _, chart = result
    assert chart["viz_type"] == "table"


def test_hrm_credential_access_table_exists() -> None:
    """HRM-45: hrm_credential_retrieval_table.yaml must exist with table viz."""
    result = _find_chart_by_filename("hrm_credential_retrieval_table")
    assert result is not None, "charts/hrm_credential_retrieval_table.yaml not found"
    _, chart = result
    assert chart["viz_type"] == "table"


# ---------------------------------------------------------------------------
# LLMjacking charts (DSH-98 to DSH-101)
# ---------------------------------------------------------------------------


def test_dsh98_bedrock_invocation_trend_exists() -> None:
    """DSH-98: bedrock_invocation_trend.yaml must exist as a time series."""
    result = _find_chart_by_filename("bedrock_invocation_trend")
    assert result is not None, "charts/bedrock_invocation_trend.yaml not found"
    _, chart = result
    assert chart["viz_type"] == "echarts_timeseries_bar"
    assert "Bedrock" in chart["slice_name"]


def test_dsh99_bedrock_model_access_changes_exists() -> None:
    """DSH-99: bedrock_model_access_changes.yaml must exist as a table."""
    result = _find_chart_by_filename("bedrock_model_access_changes")
    assert result is not None, "charts/bedrock_model_access_changes.yaml not found"
    _, chart = result
    assert chart["viz_type"] == "table"
    assert "Bedrock" in chart["slice_name"]


def test_dsh100_bedrock_failed_invocations_exists() -> None:
    """DSH-100: bedrock_failed_invocations.yaml must exist as a table."""
    result = _find_chart_by_filename("bedrock_failed_invocations")
    assert result is not None, "charts/bedrock_failed_invocations.yaml not found"
    _, chart = result
    assert chart["viz_type"] == "table"
    assert "Bedrock" in chart["slice_name"]


def test_dsh101_bedrock_callers_geo_exists() -> None:
    """DSH-101: bedrock_callers_geo.yaml must exist as a table."""
    result = _find_chart_by_filename("bedrock_callers_geo")
    assert result is not None, "charts/bedrock_callers_geo.yaml not found"
    _, chart = result
    assert chart["viz_type"] == "table"
    assert "Bedrock" in chart["slice_name"]


def test_all_groupby_columns_exist_in_dataset() -> None:
    """All groupby columns used in charts must exist in the dataset YAML.

    Prevents 'Columns missing in dataset' errors during Superset dashboard
    import caused by charts referencing columns absent from the dataset YAML.
    """
    with open(DATASET_YAML_PATH, encoding="utf-8") as fh:
        dataset_yaml = yaml.safe_load(fh)
    # Dataset YAML uses 'column_name' as the key (not 'name').
    dataset_columns = {c["column_name"] for c in dataset_yaml["columns"]}

    offenders = []
    for fname, chart in load_all_charts():
        params = chart.get("params", {})
        groupby = params.get("groupby", [])
        for col in groupby:
            # Skip adhoc column definitions (dicts); only validate plain column name strings.
            if not isinstance(col, str):
                continue
            if col not in dataset_columns:
                offenders.append((fname, col))

    assert not offenders, (
        "The following charts reference groupby columns not found in the dataset YAML: "
        f"{offenders}"
    )


def test_register_dataset_has_core_columns() -> None:
    """register_dataset.py must define CORE_COLUMNS covering user_identity_arn and source_ip_address.

    When fetch_metadata() fails (e.g. DuckDB is empty at init time), Superset will
    not have any columns in the dataset metadata.  ImportDashboardsCommand then raises
    'Columns missing in dataset' for every column referenced in chart params.
    CORE_COLUMNS provides an explicit fallback so all 17 core columns are always
    registered regardless of whether DuckDB is populated.
    """
    sys.path.insert(0, REGISTER_DATASET_PATH)  # type: ignore
    from register_dataset import CORE_COLUMNS  # noqa: PLC0415

    # CORE_COLUMNS is a list of tuples: (col_name, col_type, verbose_name, groupby, filterable, is_dttm)
    core_col_names = {c[0] for c in CORE_COLUMNS}
    assert (
        "user_identity_arn" in core_col_names
    ), "CORE_COLUMNS is missing user_identity_arn"
    assert (
        "source_ip_address" in core_col_names
    ), "CORE_COLUMNS is missing source_ip_address"


# ---------------------------------------------------------------------------
# GeoIP context — tables showing an IP must show geo columns
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fname, chart", load_all_charts())
def test_ip_table_includes_geo_columns(fname: str, chart: dict) -> None:
    """Every table chart showing source_ip_address must also show geo columns.

    Applies to both event-level listings (event_time in groupby) and
    per-IP aggregation tables (e.g. Top Source IP Addresses). Raw IPs alone
    give analysts no location context, so a country column (geo_country_code
    or geo_country_name) plus at least one of geo_city / geo_org must also
    be listed. Geo columns are functionally dependent on the IP, so adding
    them never changes the grouping granularity.
    """
    if chart.get("viz_type") != "table":
        return
    groupby = (chart.get("params") or {}).get("groupby") or []
    if "source_ip_address" not in groupby:
        return

    assert (
        "geo_country_code" in groupby or "geo_country_name" in groupby
    ), f"{fname}: table showing source_ip_address must include a geo country column"
    assert (
        "geo_city" in groupby or "geo_org" in groupby
    ), f"{fname}: table showing source_ip_address must include geo_city or geo_org"


# ---------------------------------------------------------------------------
# Event-name hygiene — a filter naming a non-existent API can never match
# ---------------------------------------------------------------------------

# CloudTrail records an ``eventName`` per API action actually invoked. These
# names look plausible but are never emitted, so a filter listing one is dead
# weight that silently shrinks the chart's coverage:
#
#   DisableDetector  GuardDuty has no such API. A detector is disabled with
#                    UpdateDetector and enable=false — the form the agent's
#                    "GuardDuty Detector Tampering" hunt already looks for.
#   PassRole         iam:PassRole is an IAM *permission*, authorised inside
#                    RunInstances / CreateFunction / CreateDevEndpoint. It is
#                    never an event of its own; the passed role shows up in the
#                    caller's requestParameters instead.
_NON_EVENT_NAMES: frozenset[str] = frozenset({"DisableDetector", "PassRole"})

_EVENT_NAME_IN_RE = re.compile(r"event_name\s+IN\s*\(([^)]*)\)", re.I)
_EVENT_NAME_EQ_RE = re.compile(r"event_name\s*=\s*'([^']+)'", re.I)
_QUOTED_RE = re.compile(r"'([^']+)'")


def _filtered_event_names(chart: dict) -> set[str]:
    """Return every literal event_name a chart restricts itself to.

    Charts express the same restriction three ways: a SIMPLE adhoc filter
    carrying a ``comparator`` list, a SQL adhoc filter carrying an
    ``event_name IN (...)`` clause, and — on the KPI cards, which have no
    filters — a ``COUNT(*) FILTER (WHERE event_name IN (...))`` metric. All
    three have to be read or the check only covers part of the deck.
    """
    params = chart.get("params") or {}
    names: set[str] = set()
    expressions: list[str] = []

    for flt in params.get("adhoc_filters") or []:
        if not isinstance(flt, dict):
            continue
        if flt.get("subject") == "event_name":
            comparator = flt.get("comparator")
            if isinstance(comparator, list):
                names.update(str(value) for value in comparator)
        expressions.append(flt.get("sqlExpression") or "")

    metrics = params.get("metrics") or []
    if not isinstance(metrics, list):
        metrics = [metrics]
    for metric in [params.get("metric"), *metrics]:
        if isinstance(metric, dict):
            expressions.append(metric.get("sqlExpression") or "")

    for expression in expressions:
        for clause in _EVENT_NAME_IN_RE.findall(expression):
            names.update(_QUOTED_RE.findall(clause))
        # A name singled out for an extra condition — the KPI card qualifies
        # UpdateDetector with enable=false — is still part of the chart's set.
        names.update(_EVENT_NAME_EQ_RE.findall(expression))
    return names


@pytest.mark.parametrize("fname, chart", load_all_charts())
def test_chart_filters_no_non_existent_event_names(fname: str, chart: dict) -> None:
    """No chart may filter on an eventName CloudTrail never emits."""
    dead = _filtered_event_names(chart) & _NON_EVENT_NAMES
    assert not dead, (
        f"{fname}: filters on event names AWS never emits: {sorted(dead)} — "
        "the filter can never match, so the chart under-reports"
    )


# ---------------------------------------------------------------------------
# Duplicated watchlists — Superset has no shared list, so agreement is asserted
# ---------------------------------------------------------------------------

# Superset chart YAML cannot reference a shared constant: each chart repeats the
# event list it filters on. Two groups are meant to stay identical, and nothing
# in the import pipeline notices when one drifts, so the agreement is pinned
# here. Editing one member of a group and running the suite names the rest.
_MIRRORED_EVENT_LISTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "defense-evasion watchlist",
        (
            "kpi_audit_tampering.yaml",
            "security_monitoring_changes.yaml",
        ),
    ),
    (
        "high-risk API watchlist (HRM)",
        (
            "hrm_top_calls.yaml",
            "hrm_top_actors.yaml",
            "hrm_timeseries.yaml",
        ),
    ),
)


@pytest.mark.parametrize("group, filenames", _MIRRORED_EVENT_LISTS)
def test_mirrored_event_lists_agree(group: str, filenames: tuple[str, ...]) -> None:
    """Charts sharing a watchlist must filter on exactly the same event names."""
    charts = dict(load_all_charts())
    reference = filenames[0]
    expected = _filtered_event_names(charts[reference])
    assert expected, f"{reference}: no event_name filter found — helper is stale"

    for fname in filenames[1:]:
        actual = _filtered_event_names(charts[fname])
        assert actual == expected, (
            f"{group}: {fname} has drifted from {reference} — "
            f"only in {fname}: {sorted(actual - expected)}; "
            f"only in {reference}: {sorted(expected - actual)}"
        )


def test_hrm_top_calls_row_limit_covers_the_whole_watchlist() -> None:
    """HRM-40 ranks the watchlist, so its row_limit must not truncate it.

    The limit was sized to the list by hand; adding an API without raising it
    silently drops the least-called entry off the bottom of the chart.
    """
    charts = dict(load_all_charts())
    chart = charts["hrm_top_calls.yaml"]
    watchlist = _filtered_event_names(chart)
    row_limit = chart["params"]["row_limit"]
    assert row_limit >= len(watchlist), (
        f"hrm_top_calls.yaml: row_limit {row_limit} is below the "
        f"{len(watchlist)}-entry watchlist — the chart truncates itself"
    )


def _charts_filtering_on(event_name: str) -> list[tuple[str, dict]]:
    """Return every chart whose event_name filter includes ``event_name``."""
    return [
        (fname, chart)
        for fname, chart in load_all_charts()
        if event_name in _filtered_event_names(chart)
    ]


@pytest.mark.parametrize("fname, chart", _charts_filtering_on("DeleteDetector"))
def test_guardduty_disable_path_accompanies_deletion(fname: str, chart: dict) -> None:
    """A chart counting DeleteDetector must also cover the disable path.

    Deleting a detector and setting ``enable=false`` on it end the same way —
    GuardDuty stops producing findings — and an adversary reaches for whichever
    the credential permits. Listing only the deletion leaves the quieter half
    of the technique uncounted.
    """
    assert "UpdateDetector" in _filtered_event_names(chart), (
        f"{fname}: counts DeleteDetector but not UpdateDetector — a detector "
        "disabled with enable=false goes unnoticed"
    )


# The defense-evasion watchlist has to cover the quiet forms of each control's
# removal, not just the loud one. Each entry here is a technique whose obvious
# API was already listed while the subtler sibling was not, which left the
# card reading zero through the very actions an adversary prefers.
_DEFENSE_EVASION_REQUIRED: frozenset[str] = frozenset(
    {
        # GuardDuty keeps running; the findings it names are archived on arrival.
        "CreateFilter",
        "UpdateFilter",
        # The log group survives; its retention is cut to the shortest window.
        "PutRetentionPolicy",
        # The trail survives; Insights stop being recorded.
        "PutInsightSelectors",
    }
)


@pytest.mark.parametrize(
    "fname",
    ["kpi_audit_tampering.yaml", "security_monitoring_changes.yaml"],
)
def test_defense_evasion_watchlist_covers_the_quiet_forms(fname: str) -> None:
    """Suppressing, shortening and narrowing are evasion as much as deleting."""
    charts = dict(load_all_charts())
    missing = _DEFENSE_EVASION_REQUIRED - _filtered_event_names(charts[fname])
    assert not missing, (
        f"{fname}: defense-evasion watchlist misses {sorted(missing)} — "
        "each leaves the control in place while ending its effect"
    )


def test_s3_protection_chart_covers_public_access_block_removal() -> None:
    """Deleting the block and setting it false expose the bucket alike."""
    charts = dict(load_all_charts())
    names = _filtered_event_names(charts["s3_protection_changes.yaml"])
    assert "DeletePublicAccessBlock" in names, (
        "s3_protection_changes.yaml tracks PutPublicAccessBlock but not "
        "DeletePublicAccessBlock, which removes the guardrail outright"
    )


def test_hrm_watchlist_covers_permission_enumeration() -> None:
    """A stolen credential asks what it may do before it does anything."""
    charts = dict(load_all_charts())
    names = _filtered_event_names(charts["hrm_top_calls.yaml"])
    missing = {"ListAttachedUserPolicies", "GetAccountAuthorizationDetails"} - names
    assert (
        not missing
    ), f"HRM watchlist misses permission enumeration: {sorted(missing)}"
