"""Phase 7 — event-name corrections driven by the AWS incident response playbooks.

Cross-checking ``builtin_hunts.yaml`` against
``aws-samples/aws-incident-response-playbooks`` surfaced hunts that reference AWS
API names which do not exist.  Such a hunt runs without error and returns zero
rows, which an analyst reads as "no attack" — a silent false negative.

  P7-Q1: the OIDC provider hunt used five abbreviated names
         (``CreateOIDCProvider`` …); IAM spells them ``…OpenIDConnectProvider``.
  P7-Q2: ``DisableDetector`` is not a GuardDuty API.  Disabling a detector is
         ``UpdateDetector`` with ``enable=false``; removal is ``DeleteDetector``.
  P7-Q3: CloudTrail/CWL anti-forensics missed ``PutInsightSelectors``,
         ``PutRetentionPolicy``, ``DeleteDelivery`` and ``DisassociateKmsKey``.
  P7-Q4: ``AssumeRoleWithSAML`` appeared in no hunt SQL at all, although both
         IRP-STSTokenAbuse and IRP-FederatedAccessAbuse name it first.
  P7-Q5: the KMS hunt omitted ``CreateKey`` / ``Encrypt`` / ``ReEncrypt*`` /
         ``RevokeGrant`` / ``RetireGrant`` — the ransomware operator's toolkit.
  P7-Q6: S3 read hunts covered only ``GetObject``; IRP-PersonalDataBreach adds
         ``SelectObjectContent``, and ``PutObjectAcl`` exposes single objects.
  P7-Q7: a new hunt for ransom-note ``PutObject`` keys (IRP-Ransomware).
  P7-Q8: every ``event_name`` literal in either hunt file must appear in
         ``agent/known_event_names.txt``, so a new hunt cannot introduce an
         unverified API name without a deliberate edit to that file.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any

import duckdb
import pytest
import yaml

AGENT_DIR = pathlib.Path(__file__).parent.parent
YAML_PATH = AGENT_DIR / "builtin_hunts.yaml"
SUZAKU_YAML_PATH = AGENT_DIR / "suzaku_timeline_hunts.yaml"
ALLOWLIST_PATH = AGENT_DIR / "known_event_names.txt"

CLOUDTRAIL_LABEL = "🛑 CloudTrail Tampering"
GUARDDUTY_LABEL = "🛡️ GuardDuty Detector Tampering"
OIDC_LABEL = "🔗 SAML / OIDC Provider Updates"
KMS_LABEL = "🔓 KMS Key Operations"
S3_ACCESS_LABEL = "🪣 S3 Data Access Anomalies"
RANSOM_NOTE_LABEL = "📝 Ransom Note Placement"

DATA_CATEGORY = "🪣 Data & Storage"


def _load_hunts(path: pathlib.Path = YAML_PATH) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def get_hunt(label: str) -> dict[str, Any]:
    for hunt in _load_hunts():
        if hunt.get("label") == label:
            return hunt
    raise ValueError(f"No builtin hunt found with label: {label!r}")


def get_builtin_sql(label: str) -> str:
    hunt = get_hunt(label)
    sql = hunt.get("sql")
    assert sql, f"Hunt '{label}' found but has no 'sql' field"
    return sql


def _run_sql(db_path: str, sql: str) -> list[dict]:
    conn = duckdb.connect(db_path, read_only=True)
    try:
        return conn.execute(sql).fetchdf().to_dict(orient="records")
    finally:
        conn.close()


def event_name_literals(hunt: dict[str, Any]) -> set[str]:
    """Every string compared against ``event_name`` in one hunt's SQL."""
    sql = hunt.get("sql") or ""
    names: set[str] = set()
    for match in re.finditer(
        r"event_name\s+(?:NOT\s+)?IN\s*\(([^)]*)\)", sql, re.S | re.I
    ):
        names |= set(re.findall(r"'([A-Za-z0-9_*]+)'", match.group(1)))
    for match in re.finditer(r"event_name\s*=\s*'([A-Za-z0-9_*]+)'", sql):
        names.add(match.group(1))
    return names


def all_event_name_literals() -> set[str]:
    names: set[str] = set()
    for hunt in _load_hunts():
        names |= event_name_literals(hunt)
    return names


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def phase7_db(tmp_path: pathlib.Path) -> str:
    """A database whose rows only match if the corrected API names are used."""
    db_path = tmp_path / "phase7_test.db"
    conn = duckdb.connect(str(db_path))
    conn.execute("""
        CREATE TABLE cloudtrail_events (
            event_time               TIMESTAMP,
            event_name               VARCHAR,
            event_source             VARCHAR,
            aws_region               VARCHAR,
            source_ip_address        VARCHAR,
            user_agent               VARCHAR,
            user_identity_type       VARCHAR,
            user_identity_arn        VARCHAR,
            user_identity_account_id VARCHAR,
            request_parameters       VARCHAR,
            response_elements        VARCHAR,
            additional_event_data    VARCHAR,
            recipient_account_id     VARCHAR,
            error_code               VARCHAR,
            read_only                BOOLEAN,
            geo_country_code         VARCHAR,
            geo_org                  VARCHAR
        )
    """)

    def insert(
        event_name: str,
        event_source: str,
        request_parameters: str = "{}",
        when: str = "2024-06-10 10:00:00",
        arn: str = "arn:aws:iam::111111111111:user/attacker",
    ) -> None:
        conn.execute(
            """
            INSERT INTO cloudtrail_events
                (event_time, event_name, event_source, aws_region,
                 source_ip_address, user_agent, user_identity_type,
                 user_identity_arn, user_identity_account_id,
                 request_parameters, response_elements, additional_event_data,
                 recipient_account_id, error_code, read_only,
                 geo_country_code, geo_org)
            VALUES (?, ?, ?, 'us-east-1', '203.0.113.50', 'aws-cli/2.0',
                    'IAMUser', ?, '111111111111', ?, NULL, NULL,
                    '111111111111', NULL, FALSE, 'NL', 'Example Hosting BV')
            """,
            [when, event_name, event_source, arn, request_parameters],
        )

    # P7-Q1 — real IAM OIDC provider API names
    insert(
        "CreateOpenIDConnectProvider",
        "iam.amazonaws.com",
        '{"url":"https://token.actions.githubusercontent.com"}',
    )
    insert(
        "UpdateOpenIDConnectProviderThumbprint",
        "iam.amazonaws.com",
        '{"openIDConnectProviderArn":"arn:aws:iam::111111111111:oidc-provider/x"}',
    )
    insert(
        "AddClientIDToOpenIDConnectProvider",
        "iam.amazonaws.com",
        '{"clientID":"attacker-client"}',
    )
    # P7-Q2 — GuardDuty detector disabled the way the API actually spells it
    insert(
        "UpdateDetector",
        "guardduty.amazonaws.com",
        '{"detectorId":"det-1","enable":false}',
    )
    insert("DeleteDetector", "guardduty.amazonaws.com", '{"detectorId":"det-1"}')
    # P7-Q3 — CloudTrail / CWL anti-forensics
    insert("PutInsightSelectors", "cloudtrail.amazonaws.com", '{"trailName":"org"}')
    insert(
        "PutRetentionPolicy",
        "logs.amazonaws.com",
        '{"logGroupName":"/aws/cloudtrail","retentionInDays":1}',
    )
    # P7-Q4 — SAML federation
    insert(
        "AssumeRoleWithSAML",
        "sts.amazonaws.com",
        '{"roleArn":"arn:aws:iam::222222222222:role/Federated"}',
    )
    # P7-Q5 — KMS ransomware toolkit
    insert("CreateKey", "kms.amazonaws.com", '{"origin":"AWS_KMS"}')
    insert("ReEncrypt", "kms.amazonaws.com", '{"keyId":"key-1"}')
    insert("RevokeGrant", "kms.amazonaws.com", '{"keyId":"key-1","grantId":"g-1"}')
    # P7-Q6 — S3 Select and per-object ACL
    insert(
        "SelectObjectContent",
        "s3.amazonaws.com",
        '{"bucketName":"pii-archive","key":"customers.csv"}',
    )
    insert(
        "PutObjectAcl",
        "s3.amazonaws.com",
        '{"bucketName":"pii-archive","key":"customers.csv","x-amz-acl":"public-read"}',
    )
    # P7-Q7 — ransom notes, plus a benign PutObject that must not match
    insert(
        "PutObject",
        "s3.amazonaws.com",
        '{"bucketName":"prod-data","key":"reports/RANSOM_NOTE.txt"}',
    )
    insert(
        "PutObject",
        "s3.amazonaws.com",
        '{"bucketName":"prod-data","key":"HOW_TO_DECRYPT.html"}',
    )
    insert(
        "PutObject",
        "s3.amazonaws.com",
        '{"bucketName":"prod-data","key":"reports/quarterly-summary.pdf"}',
    )

    conn.close()
    return str(db_path)


# ---------------------------------------------------------------------------
# P7-Q1 — OIDC provider API names
# ---------------------------------------------------------------------------

WRONG_OIDC_NAMES = [
    "CreateOIDCProvider",
    "UpdateOIDCProviderThumbprint",
    "DeleteOIDCProvider",
    "AddClientIDToOIDCProvider",
    "RemoveClientIDFromOIDCProvider",
]

CORRECT_OIDC_NAMES = [
    "CreateOpenIDConnectProvider",
    "UpdateOpenIDConnectProviderThumbprint",
    "DeleteOpenIDConnectProvider",
    "AddClientIDToOpenIDConnectProvider",
    "RemoveClientIDFromOpenIDConnectProvider",
]


@pytest.mark.parametrize("wrong", WRONG_OIDC_NAMES)
def test_q1_abbreviated_oidc_names_are_gone(wrong: str) -> None:
    """No hunt may reference the abbreviated OIDC names — they do not exist."""
    for hunt in _load_hunts():
        assert wrong not in event_name_literals(
            hunt
        ), f"Hunt {hunt['label']!r} matches on {wrong!r}, which is not an IAM API"


@pytest.mark.parametrize("correct", CORRECT_OIDC_NAMES)
def test_q1_oidc_hunt_uses_real_names(correct: str) -> None:
    assert correct in event_name_literals(get_hunt(OIDC_LABEL))


def test_q1_oidc_hunt_matches_real_events(phase7_db: str) -> None:
    rows = _run_sql(phase7_db, get_builtin_sql(OIDC_LABEL))
    names = {row["event_name"] for row in rows}
    assert "CreateOpenIDConnectProvider" in names
    assert "UpdateOpenIDConnectProviderThumbprint" in names
    assert "AddClientIDToOpenIDConnectProvider" in names


# ---------------------------------------------------------------------------
# P7-Q2 — GuardDuty detector disable
# ---------------------------------------------------------------------------


def test_q2_disable_detector_is_gone_everywhere() -> None:
    """``DisableDetector`` is not a GuardDuty API and must not be matched on."""
    for hunt in _load_hunts():
        assert "DisableDetector" not in event_name_literals(
            hunt
        ), f"Hunt {hunt['label']!r} matches on DisableDetector, which does not exist"


def test_q2_guardduty_hunt_uses_update_detector() -> None:
    assert "UpdateDetector" in event_name_literals(get_hunt(GUARDDUTY_LABEL))


def test_q2_guardduty_hunt_matches_disable_via_update(phase7_db: str) -> None:
    rows = _run_sql(phase7_db, get_builtin_sql(GUARDDUTY_LABEL))
    names = {row["event_name"] for row in rows}
    assert "UpdateDetector" in names
    assert "DeleteDetector" in names


def test_q2_guardduty_hunt_surfaces_the_enable_flag(phase7_db: str) -> None:
    """An UpdateDetector row is only actionable if the enable flag is shown."""
    sql = get_builtin_sql(GUARDDUTY_LABEL)
    rows = _run_sql(phase7_db, sql)
    update_rows = [r for r in rows if r["event_name"] == "UpdateDetector"]
    assert update_rows, "UpdateDetector row missing"
    assert any(
        str(value).lower() == "false"
        for value in update_rows[0].values()
        if value is not None
    ), "UpdateDetector result does not expose requestParameters.enable"


# ---------------------------------------------------------------------------
# P7-Q3 — CloudTrail / CloudWatch Logs anti-forensics
# ---------------------------------------------------------------------------

CLOUDTRAIL_ADDITIONS = ["PutInsightSelectors"]
LOGS_ADDITIONS = ["PutRetentionPolicy", "DeleteDelivery", "DisassociateKmsKey"]


@pytest.mark.parametrize("event", CLOUDTRAIL_ADDITIONS)
def test_q3_cloudtrail_hunt_covers_insight_selectors(event: str) -> None:
    assert event in event_name_literals(get_hunt(CLOUDTRAIL_LABEL))


@pytest.mark.parametrize("event", LOGS_ADDITIONS)
def test_q3_log_retention_tampering_is_covered(event: str) -> None:
    """Retention/delivery/KMS tampering must be matched by at least one hunt."""
    assert any(
        event in event_name_literals(h) for h in _load_hunts()
    ), f"No hunt matches on {event!r}"


def test_q3_cloudtrail_hunt_matches_insight_selectors(phase7_db: str) -> None:
    rows = _run_sql(phase7_db, get_builtin_sql(CLOUDTRAIL_LABEL))
    assert "PutInsightSelectors" in {row["event_name"] for row in rows}


# ---------------------------------------------------------------------------
# P7-Q4 — AssumeRoleWithSAML
# ---------------------------------------------------------------------------


def test_q4_assume_role_with_saml_is_covered() -> None:
    assert "AssumeRoleWithSAML" in all_event_name_literals(), (
        "AssumeRoleWithSAML appears in no hunt SQL — the primary federated "
        "access path is unmonitored"
    )


# ---------------------------------------------------------------------------
# P7-Q5 — KMS ransomware toolkit
# ---------------------------------------------------------------------------

KMS_ADDITIONS = ["CreateKey", "Encrypt", "ReEncrypt", "RevokeGrant", "RetireGrant"]


@pytest.mark.parametrize("event", KMS_ADDITIONS)
def test_q5_kms_hunt_covers_ransomware_operations(event: str) -> None:
    assert event in event_name_literals(get_hunt(KMS_LABEL))


def test_q5_kms_hunt_matches_key_creation(phase7_db: str) -> None:
    rows = _run_sql(phase7_db, get_builtin_sql(KMS_LABEL))
    names = {row["event_name"] for row in rows}
    assert {"CreateKey", "ReEncrypt", "RevokeGrant"} <= names


# ---------------------------------------------------------------------------
# P7-Q6 — S3 Select and per-object ACL
# ---------------------------------------------------------------------------


def test_q6_select_object_content_is_covered() -> None:
    assert "SelectObjectContent" in all_event_name_literals()


def test_q6_put_object_acl_is_covered() -> None:
    assert "PutObjectAcl" in all_event_name_literals()


def test_q6_s3_access_hunt_counts_select_object_content(phase7_db: str) -> None:
    """S3 Select reads objects just as GetObject does, so it must be counted."""
    assert "SelectObjectContent" in event_name_literals(get_hunt(S3_ACCESS_LABEL))


# ---------------------------------------------------------------------------
# P7-Q7 — ransom note placement
# ---------------------------------------------------------------------------


def test_q7_ransom_note_hunt_exists() -> None:
    hunt = get_hunt(RANSOM_NOTE_LABEL)
    assert hunt["category"] == DATA_CATEGORY
    assert hunt.get("sql")
    assert hunt.get("prompt")


def test_q7_ransom_note_hunt_matches_notes_only(phase7_db: str) -> None:
    rows = _run_sql(phase7_db, get_builtin_sql(RANSOM_NOTE_LABEL))
    keys = {str(value) for row in rows for value in row.values()}
    joined = " ".join(keys)
    assert "RANSOM_NOTE.txt" in joined
    assert "HOW_TO_DECRYPT.html" in joined
    assert (
        "quarterly-summary.pdf" not in joined
    ), "benign PutObject matched the ransom-note pattern"


# ---------------------------------------------------------------------------
# P7-Q8 — every event name is a verified AWS API name
# ---------------------------------------------------------------------------


def _load_allowlist() -> set[str]:
    names: set[str] = set()
    with open(ALLOWLIST_PATH, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                names.add(line)
    return names


def test_q8_allowlist_exists() -> None:
    assert ALLOWLIST_PATH.exists(), (
        f"{ALLOWLIST_PATH.name} is missing — without it a typo'd API name "
        "silently returns zero rows"
    )


def test_q8_every_event_name_is_allowlisted() -> None:
    unknown = sorted(all_event_name_literals() - _load_allowlist())
    assert not unknown, (
        "These event_name literals are not in known_event_names.txt. Verify each "
        f"against the AWS API reference before adding it: {unknown}"
    )


def test_q8_allowlist_has_no_unused_entries() -> None:
    unused = sorted(_load_allowlist() - all_event_name_literals())
    assert (
        not unused
    ), f"known_event_names.txt lists names no hunt uses any more: {unused}"


def test_q8_allowlist_is_sorted_and_unique() -> None:
    lines = [
        line.strip()
        for line in ALLOWLIST_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert lines == sorted(lines), "known_event_names.txt must be sorted"
    assert len(lines) == len(set(lines)), "known_event_names.txt has duplicates"


def test_q8_suzaku_hunts_need_no_event_name_literals() -> None:
    """Suzaku hunts filter on rule metadata, not raw API names."""
    for hunt in _load_hunts(SUZAKU_YAML_PATH):
        assert not event_name_literals(hunt)
