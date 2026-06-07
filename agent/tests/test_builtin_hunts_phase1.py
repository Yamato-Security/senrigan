"""Phase 1 — Critical DFIR gap tests for builtin_hunts.yaml.

Tests G-01 through G-08 in the Red-Green-Refactor cycle:
  G-01: SSM Session / Run Command
  G-02: RDS Snapshot Cross-Account Share
  G-03: GuardDuty Detector Tampering
  G-04: EC2 Public Snapshot / AMI Sharing
  G-05: VPC Flow Log Changes
  G-06: STS Federation Token Issuance
  G-07: IAM Role Trust Policy Changes
  G-08: AWS Config Tampering

Each test:
1. Loads the SQL from builtin_hunts.yaml by label (fails if missing → Red).
2. Inserts targeted test data into a fresh DuckDB.
3. Executes the SQL and asserts detection.
"""

from __future__ import annotations

import pathlib
from typing import Any

import duckdb
import pytest
import yaml

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

YAML_PATH = pathlib.Path(__file__).parent.parent / "builtin_hunts.yaml"


def _load_hunts() -> list[dict[str, Any]]:
    with open(YAML_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def get_builtin_sql(label: str) -> str:
    """Return the ``sql`` field for the given hunt label.

    Raises ValueError when the entry is absent (Red state).
    Raises AssertionError when the entry exists but has no inline SQL.
    """
    hunts = _load_hunts()
    for hunt in hunts:
        if hunt.get("label") == label:
            sql = hunt.get("sql")
            assert sql, f"Hunt '{label}' found but has no 'sql' field"
            return sql
    raise ValueError(f"No builtin hunt found with label: {label!r}")


# ---------------------------------------------------------------------------
# Fixture — extended tmp DuckDB with all Phase-1 relevant columns
# ---------------------------------------------------------------------------


@pytest.fixture()
def phase1_db(tmp_path: pathlib.Path) -> str:
    """Temporary DuckDB pre-loaded with Phase-1 test events."""
    db_path = tmp_path / "phase1_test.db"
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
            error_code               VARCHAR,
            error_message            VARCHAR,
            read_only                BOOLEAN,
            event_type               VARCHAR,
            recipient_account_id     VARCHAR,
            raw_event                VARCHAR,
            geo_country_code         VARCHAR,
            geo_country_name         VARCHAR,
            geo_city                 VARCHAR,
            geo_latitude             DOUBLE,
            geo_longitude            DOUBLE,
            geo_asn                  VARCHAR,
            geo_org                  VARCHAR
        )
    """)

    conn.execute("""
        INSERT INTO cloudtrail_events
            (event_time, event_name, event_source, aws_region,
             user_identity_arn, source_ip_address, request_parameters,
             response_elements, error_code, read_only, recipient_account_id,
             user_identity_account_id)
        VALUES
        -- G-01: SSM StartSession (attacker lateral movement)
        ('2024-03-01 02:00:00', 'StartSession',   'ssm.amazonaws.com', 'ap-northeast-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.5',
         '{"target":"i-0123456789abcdef0"}',
         NULL, NULL, false, '111111111111', '111111111111'),
        ('2024-03-01 02:05:00', 'SendCommand',    'ssm.amazonaws.com', 'ap-northeast-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.5',
         '{"instanceIds":["i-0123456789abcdef0"],"documentName":"AWS-RunShellScript"}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-02: RDS snapshot shared to external account
        ('2024-03-02 03:00:00', 'ModifyDBSnapshotAttribute', 'rds.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.10',
         '{"dBSnapshotIdentifier":"prod-snapshot-20240302","attributeName":"restore","valuesToAdd":["999999999999"]}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-03: GuardDuty detector disabled
        ('2024-03-03 04:00:00', 'DisableDetector', 'guardduty.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '10.0.0.1',
         '{"detectorId":"abc123def456"}',
         NULL, NULL, false, '111111111111', '111111111111'),
        ('2024-03-03 04:10:00', 'DeletePublishingDestination', 'guardduty.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '10.0.0.1',
         '{"detectorId":"abc123def456","destinationId":"dest-abc"}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-04: EBS snapshot shared publicly
        ('2024-03-04 05:00:00', 'ModifySnapshotAttribute', 'ec2.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.20',
         '{"snapshotId":"snap-0abc123","createVolumePermission":{"add":{"items":[{"group":"all"}]}}}',
         NULL, NULL, false, '111111111111', '111111111111'),
        ('2024-03-04 05:30:00', 'ModifyImageAttribute',      'ec2.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.20',
         '{"imageId":"ami-0123abc","launchPermission":{"add":[{"group":"all"}]}}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-05: VPC Flow Log deleted
        ('2024-03-05 06:00:00', 'DeleteFlowLogs', 'ec2.amazonaws.com', 'eu-west-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.30',
         '{"DeleteFlowLogsRequest":{"FlowLogId":{"content":["fl-0abc12345"]}}}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-06: STS GetFederationToken by IAM user
        ('2024-03-06 07:00:00', 'GetFederationToken', 'sts.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/dev-user', '198.51.100.5',
         '{"name":"federated-session","durationSeconds":"43200"}',
         NULL, NULL, false, '111111111111', '111111111111'),
        ('2024-03-06 07:05:00', 'GetSessionToken',    'sts.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/dev-user', '198.51.100.5',
         '{"durationSeconds":"3600"}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-07: IAM role trust policy updated (backdoor trust)
        -- policyDocument is stored as an escaped JSON string (as CloudTrail does)
        ('2024-03-07 08:00:00', 'UpdateAssumeRolePolicy', 'iam.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.40',
         '{"roleName":"AdminRole","policyDocument":"<trust-policy-with-external-account-999999999999>"}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-08: AWS Config recorder stopped
        ('2024-03-08 09:00:00', 'StopConfigurationRecorder', 'config.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.50',
         '{"configurationRecorderName":"default"}',
         NULL, NULL, false, '111111111111', '111111111111'),
        ('2024-03-08 09:15:00', 'DeleteConfigRule',          'config.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.50',
         '{"configRuleName":"required-tags"}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- Benign baseline events (should NOT appear in threat queries)
        ('2024-03-01 10:00:00', 'DescribeInstances', 'ec2.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/jenkins', '10.0.0.100',
         '{}', NULL, NULL, true, '111111111111', '111111111111')
    """)
    conn.close()
    return str(db_path)


def _run_sql(db_path: str, sql: str) -> list[dict]:
    """Execute SQL against a read-only DuckDB and return rows as list-of-dicts."""
    conn = duckdb.connect(db_path, read_only=True)
    try:
        result = conn.execute(sql).fetchdf()
        return result.to_dict(orient="records")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# G-01: SSM Session / Run Command
# ---------------------------------------------------------------------------


def test_g01_ssm_session_label_exists_in_yaml():
    """G-01: The builtin hunt entry for SSM Session / Run Command must exist."""
    sql = get_builtin_sql("\U0001f5a5\ufe0f SSM Session / Run Command")
    assert len(sql) > 10


def test_g01_ssm_session_detects_start_session(phase1_db: str):
    """G-01: SQL must detect StartSession event from SSM."""
    sql = get_builtin_sql("\U0001f5a5\ufe0f SSM Session / Run Command")
    rows = _run_sql(phase1_db, sql)
    names = [r["event_name"] for r in rows]
    assert "StartSession" in names, f"StartSession not detected. Got: {names}"


def test_g01_ssm_session_detects_send_command(phase1_db: str):
    """G-01: SQL must detect SendCommand event from SSM."""
    sql = get_builtin_sql("\U0001f5a5\ufe0f SSM Session / Run Command")
    rows = _run_sql(phase1_db, sql)
    names = [r["event_name"] for r in rows]
    assert "SendCommand" in names, f"SendCommand not detected. Got: {names}"


def test_g01_ssm_does_not_include_benign_ec2(phase1_db: str):
    """G-01: Benign DescribeInstances must not appear in SSM results."""
    sql = get_builtin_sql("\U0001f5a5\ufe0f SSM Session / Run Command")
    rows = _run_sql(phase1_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DescribeInstances" not in names


# ---------------------------------------------------------------------------
# G-02: RDS Snapshot Cross-Account Share
# ---------------------------------------------------------------------------


def test_g02_rds_snapshot_share_label_exists_in_yaml():
    """G-02: The builtin hunt entry for RDS snapshot sharing must exist."""
    sql = get_builtin_sql("\U0001f4be RDS Snapshot Cross-Account Share")
    assert len(sql) > 10


def test_g02_rds_snapshot_share_detects_modify_attribute(phase1_db: str):
    """G-02: SQL must detect ModifyDBSnapshotAttribute with external account ID."""
    sql = get_builtin_sql("\U0001f4be RDS Snapshot Cross-Account Share")
    rows = _run_sql(phase1_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "ModifyDBSnapshotAttribute" in names
    ), f"ModifyDBSnapshotAttribute not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-03: GuardDuty Detector Tampering
# ---------------------------------------------------------------------------


def test_g03_guardduty_tampering_label_exists_in_yaml():
    """G-03: The builtin hunt entry for GuardDuty tampering must exist."""
    sql = get_builtin_sql("\U0001f6e1\ufe0f GuardDuty Detector Tampering")
    assert len(sql) > 10


def test_g03_guardduty_detects_disable_detector(phase1_db: str):
    """G-03: SQL must detect DisableDetector event."""
    sql = get_builtin_sql("\U0001f6e1\ufe0f GuardDuty Detector Tampering")
    rows = _run_sql(phase1_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DisableDetector" in names, f"DisableDetector not detected. Got: {names}"


def test_g03_guardduty_detects_delete_publishing_destination(phase1_db: str):
    """G-03: SQL must detect DeletePublishingDestination event."""
    sql = get_builtin_sql("\U0001f6e1\ufe0f GuardDuty Detector Tampering")
    rows = _run_sql(phase1_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DeletePublishingDestination" in names


# ---------------------------------------------------------------------------
# G-04: EC2 Public Snapshot / AMI Sharing
# ---------------------------------------------------------------------------


def test_g04_ec2_public_snapshot_label_exists_in_yaml():
    """G-04: The builtin hunt for EC2 public snapshot/AMI sharing must exist."""
    sql = get_builtin_sql("\U0001f4f8 EC2 Public Snapshot / AMI Sharing")
    assert len(sql) > 10


def test_g04_ec2_snapshot_detects_modify_snapshot_attribute(phase1_db: str):
    """G-04: SQL must detect ModifySnapshotAttribute with group=all."""
    sql = get_builtin_sql("\U0001f4f8 EC2 Public Snapshot / AMI Sharing")
    rows = _run_sql(phase1_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "ModifySnapshotAttribute" in names
    ), f"ModifySnapshotAttribute not detected. Got: {names}"


def test_g04_ec2_snapshot_detects_modify_image_attribute(phase1_db: str):
    """G-04: SQL must detect ModifyImageAttribute (AMI public share)."""
    sql = get_builtin_sql("\U0001f4f8 EC2 Public Snapshot / AMI Sharing")
    rows = _run_sql(phase1_db, sql)
    names = [r["event_name"] for r in rows]
    assert "ModifyImageAttribute" in names


# ---------------------------------------------------------------------------
# G-05: VPC Flow Log Changes
# ---------------------------------------------------------------------------


def test_g05_vpc_flowlog_label_exists_in_yaml():
    """G-05: The builtin hunt for VPC Flow Log changes must exist."""
    sql = get_builtin_sql("\U0001f30a VPC Flow Log Changes")
    assert len(sql) > 10


def test_g05_vpc_flowlog_detects_delete(phase1_db: str):
    """G-05: SQL must detect DeleteFlowLogs (defense evasion)."""
    sql = get_builtin_sql("\U0001f30a VPC Flow Log Changes")
    rows = _run_sql(phase1_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DeleteFlowLogs" in names, f"DeleteFlowLogs not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-06: STS Federation Token Issuance
# ---------------------------------------------------------------------------


def test_g06_sts_federation_label_exists_in_yaml():
    """G-06: The builtin hunt for STS federation token issuance must exist."""
    sql = get_builtin_sql("\U0001f511 STS Federation Token Issuance")
    assert len(sql) > 10


def test_g06_sts_detects_get_federation_token(phase1_db: str):
    """G-06: SQL must detect GetFederationToken from STS."""
    sql = get_builtin_sql("\U0001f511 STS Federation Token Issuance")
    rows = _run_sql(phase1_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "GetFederationToken" in names
    ), f"GetFederationToken not detected. Got: {names}"


def test_g06_sts_detects_get_session_token(phase1_db: str):
    """G-06: SQL must detect GetSessionToken from STS."""
    sql = get_builtin_sql("\U0001f511 STS Federation Token Issuance")
    rows = _run_sql(phase1_db, sql)
    names = [r["event_name"] for r in rows]
    assert "GetSessionToken" in names, f"GetSessionToken not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-07: IAM Role Trust Policy Changes
# ---------------------------------------------------------------------------


def test_g07_iam_trust_policy_label_exists_in_yaml():
    """G-07: The builtin hunt for IAM role trust policy changes must exist."""
    sql = get_builtin_sql("\U0001f504 IAM Role Trust Policy Changes")
    assert len(sql) > 10


def test_g07_iam_trust_policy_detects_update_assume_role(phase1_db: str):
    """G-07: SQL must detect UpdateAssumeRolePolicy (backdoor trust)."""
    sql = get_builtin_sql("\U0001f504 IAM Role Trust Policy Changes")
    rows = _run_sql(phase1_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "UpdateAssumeRolePolicy" in names
    ), f"UpdateAssumeRolePolicy not detected. Got: {names}"


def test_g07_iam_trust_policy_shows_role_name(phase1_db: str):
    """G-07: Result must include role_name extracted from request_parameters."""
    sql = get_builtin_sql("\U0001f504 IAM Role Trust Policy Changes")
    rows = _run_sql(phase1_db, sql)
    assert len(rows) >= 1
    assert (
        "role_name" in rows[0]
    ), f"Expected 'role_name' column. Got: {list(rows[0].keys())}"
    assert rows[0]["role_name"] == "AdminRole"


# ---------------------------------------------------------------------------
# G-08: AWS Config Tampering
# ---------------------------------------------------------------------------


def test_g08_config_tampering_label_exists_in_yaml():
    """G-08: The builtin hunt for AWS Config tampering must exist."""
    sql = get_builtin_sql("\u2699\ufe0f AWS Config Tampering")
    assert len(sql) > 10


def test_g08_config_detects_stop_configuration_recorder(phase1_db: str):
    """G-08: SQL must detect StopConfigurationRecorder."""
    sql = get_builtin_sql("\u2699\ufe0f AWS Config Tampering")
    rows = _run_sql(phase1_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "StopConfigurationRecorder" in names
    ), f"StopConfigurationRecorder not detected. Got: {names}"


def test_g08_config_detects_delete_config_rule(phase1_db: str):
    """G-08: SQL must detect DeleteConfigRule."""
    sql = get_builtin_sql("\u2699\ufe0f AWS Config Tampering")
    rows = _run_sql(phase1_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DeleteConfigRule" in names, f"DeleteConfigRule not detected. Got: {names}"


def test_g08_config_does_not_include_benign_ec2(phase1_db: str):
    """G-08: Benign DescribeInstances must not appear in Config tampering results."""
    sql = get_builtin_sql("\u2699\ufe0f AWS Config Tampering")
    rows = _run_sql(phase1_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DescribeInstances" not in names


# ---------------------------------------------------------------------------
# Cross-cutting: all Phase-1 SQL must pass DuckDB EXPLAIN
# ---------------------------------------------------------------------------

PHASE1_LABELS = [
    "\U0001f5a5\ufe0f SSM Session / Run Command",
    "\U0001f4be RDS Snapshot Cross-Account Share",
    "\U0001f6e1\ufe0f GuardDuty Detector Tampering",
    "\U0001f4f8 EC2 Public Snapshot / AMI Sharing",
    "\U0001f30a VPC Flow Log Changes",
    "\U0001f511 STS Federation Token Issuance",
    "\U0001f504 IAM Role Trust Policy Changes",
    "\u2699\ufe0f AWS Config Tampering",
]


@pytest.mark.parametrize("label", PHASE1_LABELS)
def test_phase1_sql_is_valid_duckdb_syntax(phase1_db: str, label: str):
    """All Phase-1 SQL queries must pass DuckDB EXPLAIN without errors."""
    sql = get_builtin_sql(label)
    conn = duckdb.connect(phase1_db, read_only=True)
    try:
        conn.execute(f"EXPLAIN {sql}")
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"EXPLAIN failed for '{label}': {exc}")
    finally:
        conn.close()
