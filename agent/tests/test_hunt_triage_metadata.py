"""Triage metadata on built-in hunts, and the extended columns three hunts need.

Senrigan answers "what happened"; the AWS incident response playbooks answer
"what to do next".  Until a hunt names its playbook, the responder builds that
bridge from memory at 3am.  Three fields close the gap, mirroring the existing
``techniques`` mechanism:

  H-Q1: ``severity`` — P1..P4 from the playbooks' TRIAGE_GUIDE severity matrix,
        so the hunt list can be ordered by response urgency rather than topic.
  H-Q2: ``playbook`` — name + URL of the upstream playbook that owns the
        response procedure for this finding.
  H-Q3: ``next_steps`` — one or two lines drawn from the playbook's containment
        step, shown under the results.
  H-Q4: rendering — captions in the sidebar and result card, sections in the
        Markdown and HTML reports.
  H-Q5: extended columns — ``session_issuer_arn``, ``user_identity_access_key_id``
        and friends already exist in DuckDB but are hidden from the LLM and from
        Superset, which is why role-chain and session-trace hunts cannot be
        written against them.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
import yaml

AGENT_DIR = pathlib.Path(__file__).parent.parent
REPO_ROOT = AGENT_DIR.parent
YAML_PATH = AGENT_DIR / "builtin_hunts.yaml"
SUZAKU_YAML_PATH = AGENT_DIR / "suzaku_timeline_hunts.yaml"
DATASET_YAML = (
    REPO_ROOT
    / "dashboard"
    / "assets"
    / "cloudtrail_default"
    / "datasets"
    / "cloudtrail_events.yaml"
)

VALID_SEVERITIES = {"P1", "P2", "P3", "P4"}

PLAYBOOK_BASE = "https://github.com/aws-samples/aws-incident-response-playbooks"

# The playbook files that actually exist in the upstream repository.  The README
# advertises several more (IRP-EC2Compromise, IRP-S3DataExfiltration, …) that are
# not in the tree; pointing a hunt at one of those would ship a dead link.
KNOWN_PLAYBOOKS = {
    "IRP-CredCompromise",
    "IRP-DataAccess",
    "IRP-DoS",
    "IRP-FederatedAccessAbuse",
    "IRP-IdentityCenterCompromise",
    "IRP-InsiderThreat",
    "IRP-PersonalDataBreach",
    "IRP-Ransomware",
    "IRP-SatelliteOperations",
    "IRP-STSTokenAbuse",
    "IRP-AgentCoreAgentIntegrity",
    "IRP-AgentCoreAuthorizationBypass",
    "IRP-AgentCoreIdentityCompromise",
    "IRP-AgentCoreObservabilityTampering",
    "IRP-AgentCoreToolAbuse",
}

# Extended columns promoted out of hiding.  Each one unlocks a hunt that cannot
# be expressed without it; the other 18 extended columns stay hidden so the
# system prompt does not grow for no reason.
PROMOTED_COLUMNS = [
    "user_identity_access_key_id",
    "session_issuer_arn",
    "session_mfa_authenticated",
    "additional_event_data",
    "event_id",
    "vpc_endpoint_id",
]


def _load(path: pathlib.Path = YAML_PATH) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def get_hunt(label: str, path: pathlib.Path = YAML_PATH) -> dict[str, Any]:
    for hunt in _load(path):
        if hunt.get("label") == label:
            return hunt
    raise ValueError(f"No hunt found with label: {label!r}")


# ---------------------------------------------------------------------------
# H-Q1 — severity
# ---------------------------------------------------------------------------


def test_q1_every_cloudtrail_hunt_has_a_severity() -> None:
    missing = [h["label"] for h in _load() if not h.get("severity")]
    assert not missing, f"Hunts without a severity: {missing}"


def test_q1_every_suzaku_hunt_has_a_severity() -> None:
    missing = [h["label"] for h in _load(SUZAKU_YAML_PATH) if not h.get("severity")]
    assert not missing, f"Suzaku hunts without a severity: {missing}"


@pytest.mark.parametrize("path", [YAML_PATH, SUZAKU_YAML_PATH])
def test_q1_severities_are_valid_triage_levels(path: pathlib.Path) -> None:
    bad = {
        h["label"]: h.get("severity")
        for h in _load(path)
        if h.get("severity") not in VALID_SEVERITIES
    }
    assert not bad, f"Severity must be one of {sorted(VALID_SEVERITIES)}: {bad}"


def test_q1_all_four_levels_are_used() -> None:
    used = {h["severity"] for h in _load()}
    assert (
        used == VALID_SEVERITIES
    ), f"Unused severity levels: {VALID_SEVERITIES - used}"


def test_q1_p1_stays_a_minority() -> None:
    """If everything is critical nothing is — keep P1 a genuine shortlist."""
    hunts = _load()
    p1_share = sum(1 for h in hunts if h["severity"] == "P1") / len(hunts)
    assert p1_share <= 0.35, f"P1 covers {p1_share:.0%} of hunts, which dilutes it"


def test_q1_defense_evasion_hunts_are_p1() -> None:
    """Log tampering is the playbooks' canonical immediate-response trigger."""
    for label in ("🛑 CloudTrail Tampering", "🛡️ GuardDuty Detector Tampering"):
        assert get_hunt(label)["severity"] == "P1"


def test_q1_baseline_hunts_are_not_p1() -> None:
    """Volume/baseline views are context, not alerts."""
    for label in (
        "🖥 Write Events from Management Console",
        "🔍 Events with Errors (24h)",
    ):
        assert get_hunt(label)["severity"] in {"P3", "P4"}


# ---------------------------------------------------------------------------
# H-Q2 — playbook mapping
# ---------------------------------------------------------------------------


def _hunts_with_playbook(path: pathlib.Path = YAML_PATH) -> list[dict[str, Any]]:
    return [h for h in _load(path) if h.get("playbook")]


def test_q2_playbook_entries_have_name_and_url() -> None:
    for hunt in _hunts_with_playbook():
        playbook = hunt["playbook"]
        assert isinstance(
            playbook, dict
        ), f"{hunt['label']}: playbook must be a mapping"
        assert playbook.get("name"), f"{hunt['label']}: playbook.name missing"
        assert playbook.get("url"), f"{hunt['label']}: playbook.url missing"


def test_q2_playbook_names_exist_upstream() -> None:
    unknown = {
        h["label"]: h["playbook"]["name"]
        for h in _hunts_with_playbook()
        if h["playbook"]["name"] not in KNOWN_PLAYBOOKS
    }
    assert not unknown, f"These playbooks are not in the upstream repository: {unknown}"


def test_q2_playbook_urls_point_at_the_upstream_repo() -> None:
    for hunt in _hunts_with_playbook():
        url = hunt["playbook"]["url"]
        assert url.startswith(PLAYBOOK_BASE), f"{hunt['label']}: {url}"
        assert url.endswith(".md"), f"{hunt['label']}: {url}"
        assert (
            hunt["playbook"]["name"] in url
        ), f"{hunt['label']}: url does not reference {hunt['playbook']['name']}"


def test_q2_signature_hunts_name_their_playbook() -> None:
    expected = {
        "📝 Ransom Note Placement": "IRP-Ransomware",
        "🌐 AssumeRole Target Account (roleArn)": "IRP-STSTokenAbuse",
        "🔗 SAML / OIDC Provider Updates": "IRP-FederatedAccessAbuse",
        "🆔 IAM Identity Center (SSO) Events": "IRP-IdentityCenterCompromise",
        "👤 New IAM Users / Keys": "IRP-CredCompromise",
    }
    for label, playbook in expected.items():
        assert (
            get_hunt(label).get("playbook", {}).get("name") == playbook
        ), f"{label} should map to {playbook}"


def test_q2_every_known_playbook_is_reachable_from_some_hunt() -> None:
    """A playbook nobody links to is a response procedure nobody will find."""
    linked = {h["playbook"]["name"] for h in _hunts_with_playbook()}
    # Satellite operations has no CloudTrail signature to hunt for.
    expected = KNOWN_PLAYBOOKS - {"IRP-SatelliteOperations"}
    assert (
        expected <= linked
    ), f"Playbooks no hunt links to: {sorted(expected - linked)}"


# ---------------------------------------------------------------------------
# H-Q3 — next steps
# ---------------------------------------------------------------------------


def test_q3_next_steps_is_a_non_empty_string_when_present() -> None:
    for hunt in _load():
        if "next_steps" in hunt:
            assert isinstance(hunt["next_steps"], str)
            assert hunt["next_steps"].strip(), f"{hunt['label']}: empty next_steps"


def test_q3_p1_hunts_all_carry_next_steps() -> None:
    """A P1 finding demands action inside 15 minutes; say what that action is."""
    missing = [
        h["label"]
        for h in _load()
        if h["severity"] == "P1" and not (h.get("next_steps") or "").strip()
    ]
    assert not missing, f"P1 hunts without next_steps: {missing}"


# ---------------------------------------------------------------------------
# H-Q4 — rendering
# ---------------------------------------------------------------------------


def test_q4_severity_caption_covers_every_level() -> None:
    from session import _format_severity_caption

    for level in sorted(VALID_SEVERITIES):
        caption = _format_severity_caption(level)
        assert level in caption
        assert caption.strip()


def test_q4_severity_caption_states_the_response_time() -> None:
    from session import _format_severity_caption

    assert "15" in _format_severity_caption("P1")
    assert "24" in _format_severity_caption("P4")


def test_q4_unknown_severity_renders_empty() -> None:
    from session import _format_severity_caption

    assert _format_severity_caption("") == ""
    assert _format_severity_caption("P9") == ""


def test_q4_playbook_caption_is_a_markdown_link() -> None:
    from session import _format_playbook_caption

    caption = _format_playbook_caption(
        {
            "name": "IRP-Ransomware",
            "url": f"{PLAYBOOK_BASE}/blob/main/x/IRP-Ransomware.md",
        }
    )
    assert "[IRP-Ransomware](" in caption
    assert PLAYBOOK_BASE in caption


def test_q4_playbook_caption_without_url_is_plain_text() -> None:
    from session import _format_playbook_caption

    caption = _format_playbook_caption({"name": "IRP-Ransomware"})
    assert "IRP-Ransomware" in caption
    assert "](" not in caption


def test_q4_empty_playbook_renders_empty() -> None:
    from session import _format_playbook_caption

    assert _format_playbook_caption({}) == ""
    assert _format_playbook_caption(None) == ""


def test_q4_bulk_queries_carry_the_triage_metadata() -> None:
    from session import _build_all_hunt_queries

    queries = _build_all_hunt_queries(_load())
    assert queries
    for query in queries:
        assert query["severity"] in VALID_SEVERITIES
        assert "playbook" in query
        assert "next_steps" in query


def test_q4_report_entry_accepts_the_triage_metadata() -> None:
    import pandas as pd
    from report import ReportEntry

    entry = ReportEntry(
        sql="SELECT 1",
        results=pd.DataFrame(),
        severity="P1",
        playbook={
            "name": "IRP-Ransomware",
            "url": f"{PLAYBOOK_BASE}/x/IRP-Ransomware.md",
        },
        next_steps="Revoke the session and preserve snapshots before eradication.",
    )
    assert entry.severity == "P1"
    assert entry.playbook["name"] == "IRP-Ransomware"


def test_q4_markdown_report_includes_playbook_and_next_steps() -> None:
    import pandas as pd
    from report import ReportEntry, generate_report

    entry = ReportEntry(
        sql="SELECT 1",
        results=pd.DataFrame({"a": [1]}),
        label="📝 Ransom Note Placement",
        severity="P1",
        playbook={
            "name": "IRP-Ransomware",
            "url": f"{PLAYBOOK_BASE}/blob/main/playbooks/IRP-Ransomware.md",
        },
        next_steps="Isolate the bucket and confirm backup integrity before restoring.",
    )
    markdown = generate_report([entry])
    assert "IRP-Ransomware" in markdown
    assert "P1" in markdown
    assert "Isolate the bucket" in markdown


def test_q4_html_report_includes_playbook_link() -> None:
    import pandas as pd
    from report import ReportEntry, generate_html_report

    entry = ReportEntry(
        sql="SELECT 1",
        results=pd.DataFrame({"a": [1]}),
        label="📝 Ransom Note Placement",
        severity="P1",
        playbook={
            "name": "IRP-Ransomware",
            "url": f"{PLAYBOOK_BASE}/blob/main/playbooks/IRP-Ransomware.md",
        },
        next_steps="Isolate the bucket.",
    )
    html = generate_html_report([entry])
    assert "IRP-Ransomware" in html
    assert "Isolate the bucket." in html


# ---------------------------------------------------------------------------
# H-Q5 — extended columns
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("column", PROMOTED_COLUMNS)
def test_q5_promoted_columns_are_exposed_to_the_llm(column: str) -> None:
    from schema import get_column_names

    assert column in get_column_names()


@pytest.mark.parametrize("column", PROMOTED_COLUMNS)
def test_q5_promoted_columns_are_described(column: str) -> None:
    from schema import get_schema_description

    assert column in get_schema_description()


def test_q5_deliberately_hidden_columns_stay_hidden() -> None:
    """Only the six columns that unlock a hunt are promoted."""
    from schema import get_column_names

    columns = set(get_column_names())
    for hidden in (
        "shared_event_id",
        "tls_version",
        "api_version",
        "session_creation_date",
    ):
        assert hidden not in columns


@pytest.mark.parametrize("column", PROMOTED_COLUMNS)
def test_q5_promoted_columns_reach_superset(column: str) -> None:
    with open(DATASET_YAML, encoding="utf-8") as fh:
        dataset = yaml.safe_load(fh)
    names = {c["column_name"] for c in dataset["columns"]}
    assert column in names
