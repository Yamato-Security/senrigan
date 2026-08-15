"""Invariants every built-in hunt must hold, whatever it detects.

The catalogue grew hunt by hunt, each one reviewed against the playbook it came
from and against nothing else. That is how two hunts ended up filtering on the
wall clock while a third filtered on the dataset, and how the same "write event"
predicate acquired two incompatible spellings. These tests state the rules once
and apply them to every entry, so the next hunt cannot reintroduce a defect the
catalogue has already been cleaned of.

The rules that never mention a column run over **both** catalogues (see
``hunt_catalogue.py``); the ones that name a CloudTrail column stay on
``builtin_hunts.yaml``, which is the only catalogue that has them.
"""

from __future__ import annotations

import pathlib
import re

import pytest
import yaml

from tests.hunt_catalogue import (
    CATALOGUES,
    NAMED_TIMEZONE_RE,
    WALL_CLOCK_RE,
    Catalogue,
    hunt_params,
)

AGENT_DIR = pathlib.Path(__file__).parent.parent
YAML_PATH = AGENT_DIR / "builtin_hunts.yaml"

HUNTS: list[dict] = yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))

# ``(label, sql)`` for every CloudTrail hunt that ships pre-built SQL, with the
# label doubling as the test id so a failure names the hunt rather than echoing
# the whole query.
SQL_HUNTS = [(hunt["label"], hunt["sql"]) for hunt in HUNTS if hunt.get("sql")]
SQL_HUNT_IDS = [label for label, _ in SQL_HUNTS]

# The same, across every catalogue, for the rules that are not CloudTrail's.
ALL_SQL_HUNTS, ALL_SQL_IDS = hunt_params("sql")

# ``read_only`` is NULL on every event whose CloudTrail record omitted the
# field — the overwhelming majority in real data — so ``= false`` drops the
# rows it is meant to return. ``IS NOT TRUE`` is the NULL-safe spelling.
_UNSAFE_READ_ONLY_RE = re.compile(
    r"read_only\s*(=|!=|<>)\s*(true|false)", re.IGNORECASE
)


@pytest.mark.parametrize(("catalogue", "hunt"), ALL_SQL_HUNTS, ids=ALL_SQL_IDS)
def test_hunt_sql_never_filters_on_the_wall_clock(catalogue: Catalogue, hunt: dict):
    """No hunt may bound its time column with the machine's current time.

    A hunt written as ``event_time >= NOW() - INTERVAL '7 days'`` returns
    nothing at all unless the logs happen to have been generated this week,
    which for an incident investigation is precisely when they are not. The
    dataset's own ``MAX(event_time)`` is the only defensible "recent" anchor.
    """
    found = WALL_CLOCK_RE.findall(hunt["sql"])
    assert not found, (
        f"{hunt['label']!r} bounds time with {found!r}; anchor the window on the "
        f"dataset's own MAX() so it follows the ingested data, not the clock"
    )


@pytest.mark.parametrize("label,sql", SQL_HUNTS, ids=SQL_HUNT_IDS)
def test_hunt_sql_treats_a_missing_read_only_flag_as_a_write(label: str, sql: str):
    """``read_only`` comparisons must be NULL-safe.

    CloudTrail omits ``readOnly`` from most event records, so the column is
    NULL far more often than it is populated. ``read_only = false`` therefore
    matches a small fraction of the write events it claims to find, while
    ``read_only IS NOT TRUE`` classes the unknowns as writes — the safe
    direction for a hunt whose job is to surface mutations.
    """
    found = _UNSAFE_READ_ONLY_RE.findall(sql)
    assert not found, (
        f"{label!r} compares read_only with = / != ; NULL rows are dropped. "
        f"Use `read_only IS TRUE` / `read_only IS NOT TRUE`"
    )


@pytest.mark.parametrize(("catalogue", "hunt"), ALL_SQL_HUNTS, ids=ALL_SQL_IDS)
def test_hunt_sql_never_hardcodes_a_local_timezone(catalogue: Catalogue, hunt: dict):
    """Hunts report in UTC; a named zone bakes in one team's calendar."""
    found = NAMED_TIMEZONE_RE.findall(hunt["sql"])
    assert not found, (
        f"{hunt['label']!r} hardcodes the timezone {found!r}. Hunts report in "
        f"UTC and name their hour columns accordingly"
    )


@pytest.mark.parametrize("catalogue", CATALOGUES, ids=[c.key for c in CATALOGUES])
def test_every_hunt_runs_without_an_api_key(catalogue: Catalogue):
    """Every hunt ships SQL, so the catalogue works with no OpenAI key.

    A hunt with only a ``prompt`` is invisible to anyone running Senrigan
    offline — which is the mode the README leads with.
    """
    missing = [hunt["label"] for hunt in catalogue.hunts() if not hunt.get("sql")]
    assert not missing, f"{catalogue.key} hunts with no `sql` field: {missing}"


def test_console_origin_hunt_reads_the_ingested_column():
    """The console-origin hunt uses ``session_credential_from_console``.

    The ingester writes that column (``ingester/src/db.rs``), so inferring
    console origin from ``user_agent`` alone both misses events and contradicts
    the schema. The user-agent match stays as a fallback for records that
    predate the field.
    """
    hunt = next(h for h in HUNTS if "Management Console" in h["label"])
    assert (
        "session_credential_from_console" in hunt["sql"]
    ), "the console-origin hunt ignores the column the ingester populates"
    assert (
        "not a standard CloudTrail column" not in hunt["sql"]
    ), "stale comment: session_credential_from_console is ingested and queryable"


def test_off_hours_hunt_documents_its_window_in_utc():
    """The off-hours hunt states the UTC window it applies.

    The hours were chosen for one timezone and named ``event_hour_utc``, which
    reads as though no conversion was involved. Whatever window ships, the
    description has to say which hours it covers so a reader in another
    timezone can tell whether it means anything for them.
    """
    hunt = next(h for h in HUNTS if "Off-Hours" in h["label"])
    assert (
        "UTC" in hunt["description"]
    ), "the off-hours window is timezone-specific; the description must name UTC"


# ---------------------------------------------------------------------------
# Consolidation — hunts folded into a neighbour that already answered them
# ---------------------------------------------------------------------------

BY_LABEL = {hunt["label"]: hunt for hunt in HUNTS}


def _sql(label_fragment: str) -> str:
    """Return the SQL of the one hunt whose label contains *label_fragment*."""
    matches = [h for h in HUNTS if label_fragment in h["label"]]
    assert len(matches) == 1, f"{label_fragment!r} matched {len(matches)} hunts"
    return matches[0]["sql"]


# Retired hunt -> the hunt that now answers the same question. Every entry was
# a strict subset of its successor: same events, fewer columns, or a filter the
# successor expresses as a column.
RETIRED_HUNTS: dict[str, str] = {
    "🔐 AssumeRole Cross-Account": "🌐 AssumeRole Target Account (roleArn)",
    "🌍 Security Group Opened to Internet": "🔥 Security Group Modifications",
    "🚧 VPC Endpoint Access Denied": "🚫 Access Denied Errors",
    "🛡 Network Firewall / Shield Tampering": "🛡 DDoS Protection Weakening",
    "🗺 Console Logins by Country": "🌐 Console Logins",
    "🛠 Data Pipeline / CodeStar Privilege Escalation": "🎯 IAM PassRole Abuse",
    "🧩 Step Functions Privilege Escalation": "🎯 IAM PassRole Abuse",
    "🌍 Bedrock Callers & Origins": "🧭 Bedrock Reconnaissance Sweep",
    # Descriptive Top-N by GeoIP dimension: the Superset GeoIP tab renders the
    # same GROUP BY with sorting, paging and a map, so the agent no longer
    # carries a second copy of each.
    "🔍 Write Events by Country": "🌍 Top Countries by Request Volume (dashboard)",
    "🌐 Private / Internal IP Summary": "🌍 Top Countries by Request Volume (dashboard)",
    "🌍 Top Source Countries": "🌍 Top Countries by Request Volume (dashboard)",
    "🏢 Top ASN / Organizations": "🏢 Top ASN Organizations by Request Volume (dashboard)",
    "📍 Top Source Cities": "📍 Top Cities by Request Volume (dashboard)",
    "📋 API Calls by Country (Event Name)": "📋 API Calls by Country (dashboard)",
    "👤 Identities by Country (user_identity_arn)": "📋 API Calls by Country (dashboard)",
}


@pytest.mark.parametrize("retired", sorted(RETIRED_HUNTS))
def test_retired_hunt_is_gone_from_the_catalogue(retired: str):
    """A hunt folded into a neighbour must not still ship.

    Leaving both means the operator runs two queries to learn one thing and
    has to work out which of the two answers is the fuller one.
    """
    assert (
        retired not in BY_LABEL
    ), f"{retired!r} was folded into {RETIRED_HUNTS[retired]!r} but still ships"


def test_geoip_category_keeps_only_the_anomaly_hunts():
    """GeoIP keeps the hunts that judge; the dashboard keeps the ones that count.

    Ranking countries, cities and ASNs by volume is a reporting question the
    Superset GeoIP tab answers better. What belongs in the hunt catalogue is
    the pair that says something is *wrong*: a rare country/identity pairing
    and a concentration of denials.
    """
    geoip = {h["label"] for h in HUNTS if "GeoIP" in h["category"]}
    assert geoip == {"🚨 Unusual Country Access", "🚫 Access Denied by Country"}


def test_access_denied_hunt_carries_the_vpc_endpoint():
    """Absorbing the VPC-endpoint hunt means keeping its one extra column."""
    assert "vpc_endpoint_id" in _sql("🚫 Access Denied Errors")


def test_security_group_hunt_flags_rules_open_to_the_internet():
    """The 0.0.0.0/0 filter survives as a column, not as a second hunt."""
    sql = _sql("🔥 Security Group Modifications")
    assert "0.0.0.0/0" in sql
    assert "open_to_internet" in sql


def test_console_login_hunt_carries_the_geoip_origin():
    """Absorbing the by-country hunt means keeping its geo columns."""
    sql = _sql("🌐 Console Logins")
    for column in ("geo_country_code", "geo_country_name", "geo_city"):
        assert column in sql, f"{column} was lost when the geo hunt was folded in"


def test_ddos_hunt_covers_network_firewall_and_shield():
    """The absorbed hunt's own event sources have to survive the merge."""
    sql = _sql("🛡 DDoS Protection Weakening")
    assert "network-firewall.amazonaws.com" in sql
    assert "DeleteFirewall" in sql


def test_passrole_hunt_covers_the_services_its_variants_owned():
    """Step Functions and Data Pipeline / CodeStar fold into PassRole abuse."""
    sql = _sql("🎯 IAM PassRole Abuse")
    for event in ("CreateStateMachine", "CreatePipeline", "CreateProjectFromTemplate"):
        assert event in sql, f"{event} was lost when its own hunt was retired"


# Event names that two hunts both claimed. The second hunt in each pair is the
# one the triage guide points at, so the first stops firing on them.
DEOVERLAPPED: list[tuple[str, str, tuple[str, ...]]] = [
    (
        "📰 AWS Organizations Account Creation",
        "👑 Delegated Administrator Registration",
        ("RegisterDelegatedAdministrator", "DeregisterDelegatedAdministrator"),
    ),
    (
        "🛑 CloudTrail Tampering",
        "📜 CloudWatch Logs Subscription Changes",
        ("DeleteLogGroup", "PutRetentionPolicy", "DeleteRetentionPolicy"),
    ),
]


@pytest.mark.parametrize("broad,owner,events", DEOVERLAPPED, ids=lambda v: str(v)[:40])
def test_shared_events_belong_to_exactly_one_hunt(
    broad: str, owner: str, events: tuple[str, ...]
):
    """Two hunts firing on one event double-count it in every triage.

    The narrower, higher-severity hunt owns the event; the broad one drops it.
    """
    broad_sql, owner_sql = _sql(broad), _sql(owner)
    for event in events:
        assert event in owner_sql, f"{owner!r} must own {event}"
        assert event not in broad_sql, f"{broad!r} still fires on {event}"
