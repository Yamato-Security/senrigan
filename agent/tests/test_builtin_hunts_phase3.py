"""Phase 3 — Medium-priority DFIR gap tests for builtin_hunts.yaml.

Tests G-19 through G-33 in the Red-Green-Refactor cycle:
  G-19: EventBridge / CloudWatch Rule Changes
  G-20: CloudWatch Logs Subscription Changes
  G-21: EKS Cluster API Calls
  G-22: ECR Repository / Image Changes
  G-23: RDS Public Accessibility Enabled
  G-24: Elastic IP Allocation / Association
  G-25: AWS Organizations Account Creation
  G-26: WAF WebACL Changes
  G-27: Cognito Unauthenticated Access
  G-28: Budget / Cost Anomaly Changes
  G-29: Lambda Layer Addition
  G-30: EC2 User Data Modification
  G-31: IAM Access Analyzer Calls
  G-32: STS AssumeRoleWithWebIdentity
  G-33: Security Hub Tampering
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
    """Return the ``sql`` field for the given hunt label."""
    hunts = _load_hunts()
    for hunt in hunts:
        if hunt.get("label") == label:
            sql = hunt.get("sql")
            assert sql, f"Hunt '{label}' found but has no 'sql' field"
            return sql
    raise ValueError(f"No builtin hunt found with label: {label!r}")


# ---------------------------------------------------------------------------
# Fixture — DuckDB pre-loaded with Phase-3 test events
# ---------------------------------------------------------------------------


@pytest.fixture()
def phase3_db(tmp_path: pathlib.Path) -> str:
    """Temporary DuckDB pre-loaded with Phase-3 test events."""
    db_path = tmp_path / "phase3_test.db"
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
        -- G-19: EventBridge rule deleted (attacker silencing scheduled detection)
        ('2024-05-01 01:00:00', 'DeleteRule', 'events.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.1',
         '{"name":"SecurityAlertsRule"}',
         NULL, NULL, false, '111111111111', '111111111111'),
        ('2024-05-01 01:05:00', 'DisableRule', 'events.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.1',
         '{"name":"ComplianceCheckRule"}',
         NULL, NULL, false, '111111111111', '111111111111'),
        ('2024-05-01 01:10:00', 'CreateSchedule', 'scheduler.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.1',
         '{"name":"AttackerCronJob","scheduleExpression":"rate(1 minute)"}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-20: CloudWatch Logs subscription filter changed (log exfil)
        ('2024-05-02 02:00:00', 'PutSubscriptionFilter', 'logs.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.2',
         '{"logGroupName":"/aws/cloudtrail","filterName":"ExfilFilter","destinationArn":"arn:aws:kinesis:us-east-1:999999999999:stream/attacker-stream"}',
         NULL, NULL, false, '111111111111', '111111111111'),
        ('2024-05-02 02:15:00', 'DeleteLogGroup', 'logs.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.2',
         '{"logGroupName":"/aws/vpc/flowlogs"}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-21: EKS cluster modified (container platform compromise)
        ('2024-05-03 03:00:00', 'UpdateClusterConfig', 'eks.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.3',
         '{"name":"prod-cluster","resourcesVpcConfig":{"endpointPublicAccess":true}}',
         NULL, NULL, false, '111111111111', '111111111111'),
        ('2024-05-03 03:20:00', 'CreateFargateProfile', 'eks.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.3',
         '{"clusterName":"prod-cluster","fargateProfileName":"malicious-profile"}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-22: ECR image pushed (malicious image supply chain)
        ('2024-05-04 04:00:00', 'PutImage', 'ecr.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.4',
         '{"repositoryName":"prod-api","imageTag":"latest"}',
         NULL, NULL, false, '111111111111', '111111111111'),
        ('2024-05-04 04:15:00', 'SetRepositoryPolicy', 'ecr.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.4',
         '{"repositoryName":"prod-api","policyText":"<cross-account-policy>"}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-23: RDS made publicly accessible
        ('2024-05-05 05:00:00', 'ModifyDBInstance', 'rds.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.5',
         '{"dBInstanceIdentifier":"prod-db","publiclyAccessible":true}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-24: Elastic IP allocated and associated (C2 infrastructure)
        ('2024-05-06 06:00:00', 'AllocateAddress', 'ec2.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.6',
         '{"domain":"vpc"}',
         '{"publicIp":"198.51.100.99","allocationId":"eipalloc-0abc123"}',
         NULL, false, '111111111111', '111111111111'),
        ('2024-05-06 06:10:00', 'AssociateAddress', 'ec2.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.6',
         '{"allocationId":"eipalloc-0abc123","instanceId":"i-0malicious"}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-25: New AWS Organization account created (shadow account persistence)
        ('2024-05-07 07:00:00', 'CreateAccount', 'organizations.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:root', '203.0.113.7',
         '{"accountName":"attacker-shadow-account","email":"attacker@evil.example.com"}',
         NULL, NULL, false, '111111111111', '111111111111'),
        ('2024-05-07 07:30:00', 'RegisterDelegatedAdministrator', 'organizations.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.7',
         '{"accountId":"999999999999","servicePrincipal":"guardduty.amazonaws.com"}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-26: WAF WebACL deleted (disabling web protection)
        ('2024-05-08 08:00:00', 'DeleteWebACL', 'wafv2.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.8',
         '{"name":"prod-waf-acl","id":"waf-id-abc123","scope":"REGIONAL"}',
         NULL, NULL, false, '111111111111', '111111111111'),
        ('2024-05-08 08:20:00', 'UpdateWebACL', 'wafv2.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.8',
         '{"name":"prod-waf-acl","id":"waf-id-abc123","scope":"REGIONAL"}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-27: Cognito identity pool allows unauthenticated access
        ('2024-05-09 09:00:00', 'UpdateIdentityPool', 'cognito-identity.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.9',
         '{"identityPoolId":"us-east-1:pool-abc123","identityPoolName":"prod-pool","allowUnauthenticatedIdentities":true}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-28: Budget deleted (hiding cryptomining costs)
        ('2024-05-10 10:00:00', 'DeleteBudget', 'budgets.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.10',
         '{"accountId":"111111111111","budgetName":"monthly-cost-alert"}',
         NULL, NULL, false, '111111111111', '111111111111'),
        ('2024-05-10 10:15:00', 'DeleteAnomalyMonitor', 'ce.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.10',
         '{"monitorArn":"arn:aws:ce::111111111111:anomalymonitor/abc123"}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-29: Lambda layer added (dependency injection)
        ('2024-05-11 11:00:00', 'PublishLayerVersion', 'lambda.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.11',
         '{"layerName":"malicious-shared-layer","description":"utility"}',
         NULL, NULL, false, '111111111111', '111111111111'),
        ('2024-05-11 11:15:00', 'AddLayerVersionPermission', 'lambda.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.11',
         '{"layerName":"malicious-shared-layer","versionNumber":"1","principal":"*"}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-30: EC2 user data modified (code injection at next boot)
        ('2024-05-12 12:00:00', 'ModifyInstanceAttribute', 'ec2.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.12',
         '{"instanceId":"i-0abc123","userData":{"value":"IyEvYmluL2Jhc2gKY3VybCBodHRwOi8vZXZpbC5leGFtcGxlLmNvbS9iYWNrZG9vci5zaHxiYXNo"}}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-31: IAM Access Analyzer used as reconnaissance tool
        ('2024-05-13 13:00:00', 'ListFindings', 'access-analyzer.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.13',
         '{"analyzerArn":"arn:aws:access-analyzer:us-east-1:111111111111:analyzer/default"}',
         NULL, NULL, true, '111111111111', '111111111111'),
        ('2024-05-13 13:05:00', 'GetFinding', 'access-analyzer.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.13',
         '{"analyzerArn":"arn:aws:access-analyzer:us-east-1:111111111111:analyzer/default","id":"finding-abc"}',
         NULL, NULL, true, '111111111111', '111111111111'),

        -- G-32: STS AssumeRoleWithWebIdentity (OIDC token abuse)
        ('2024-05-14 14:00:00', 'AssumeRoleWithWebIdentity', 'sts.amazonaws.com', 'us-east-1',
         'arn:aws:sts::111111111111:assumed-role/GitHubActionsRole/session1', '203.0.113.14',
         '{"roleArn":"arn:aws:iam::111111111111:role/AdminRole","roleSessionName":"attacker-session","webIdentityToken":"eyJhbGc..."}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- G-33: Security Hub disabled (silencing security findings)
        ('2024-05-15 15:00:00', 'DisableSecurityHub', 'securityhub.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.15',
         '{}',
         NULL, NULL, false, '111111111111', '111111111111'),
        ('2024-05-15 15:10:00', 'BatchDisableStandards', 'securityhub.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.15',
         '{"standardsSubscriptionArns":["arn:aws:securityhub:us-east-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0"]}',
         NULL, NULL, false, '111111111111', '111111111111'),

        -- Benign baseline
        ('2024-05-01 20:00:00', 'DescribeInstances', 'ec2.amazonaws.com', 'us-east-1',
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
# G-19: EventBridge / CloudWatch Rule Changes
# ---------------------------------------------------------------------------


def test_g19_eventbridge_label_exists():
    """G-19: The builtin hunt entry for EventBridge rule changes must exist."""
    sql = get_builtin_sql("\U0001f4c5 EventBridge / CloudWatch Rule Changes")
    assert len(sql) > 10


def test_g19_eventbridge_detects_delete_rule(phase3_db: str):
    """G-19: SQL must detect DeleteRule (silencing scheduled detection)."""
    sql = get_builtin_sql("\U0001f4c5 EventBridge / CloudWatch Rule Changes")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DeleteRule" in names, f"DeleteRule not detected. Got: {names}"


def test_g19_eventbridge_detects_disable_rule(phase3_db: str):
    """G-19: SQL must detect DisableRule."""
    sql = get_builtin_sql("\U0001f4c5 EventBridge / CloudWatch Rule Changes")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DisableRule" in names, f"DisableRule not detected. Got: {names}"


def test_g19_eventbridge_detects_create_schedule(phase3_db: str):
    """G-19: SQL must detect CreateSchedule (attacker cron job)."""
    sql = get_builtin_sql("\U0001f4c5 EventBridge / CloudWatch Rule Changes")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert "CreateSchedule" in names, f"CreateSchedule not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-20: CloudWatch Logs Subscription Changes
# ---------------------------------------------------------------------------


def test_g20_cwlogs_subscription_label_exists():
    """G-20: The builtin hunt for CW Logs subscription changes must exist."""
    sql = get_builtin_sql("\U0001f4dc CloudWatch Logs Subscription Changes")
    assert len(sql) > 10


def test_g20_cwlogs_detects_put_subscription_filter(phase3_db: str):
    """G-20: SQL must detect PutSubscriptionFilter (log exfiltration)."""
    sql = get_builtin_sql("\U0001f4dc CloudWatch Logs Subscription Changes")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "PutSubscriptionFilter" in names
    ), f"PutSubscriptionFilter not detected. Got: {names}"


def test_g20_cwlogs_detects_delete_log_group(phase3_db: str):
    """G-20: SQL must detect DeleteLogGroup (evidence destruction)."""
    sql = get_builtin_sql("\U0001f4dc CloudWatch Logs Subscription Changes")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DeleteLogGroup" in names, f"DeleteLogGroup not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-21: EKS Cluster API Calls
# ---------------------------------------------------------------------------


def test_g21_eks_label_exists():
    """G-21: The builtin hunt for EKS cluster API calls must exist."""
    sql = get_builtin_sql("\u2638\ufe0f EKS Cluster API Calls")
    assert len(sql) > 10


def test_g21_eks_detects_update_cluster_config(phase3_db: str):
    """G-21: SQL must detect UpdateClusterConfig (public API server)."""
    sql = get_builtin_sql("\u2638\ufe0f EKS Cluster API Calls")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "UpdateClusterConfig" in names
    ), f"UpdateClusterConfig not detected. Got: {names}"


def test_g21_eks_detects_create_fargate_profile(phase3_db: str):
    """G-21: SQL must detect CreateFargateProfile."""
    sql = get_builtin_sql("\u2638\ufe0f EKS Cluster API Calls")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "CreateFargateProfile" in names
    ), f"CreateFargateProfile not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-22: ECR Repository / Image Changes
# ---------------------------------------------------------------------------


def test_g22_ecr_label_exists():
    """G-22: The builtin hunt for ECR repository/image changes must exist."""
    sql = get_builtin_sql("\U0001f433 ECR Repository / Image Changes")
    assert len(sql) > 10


def test_g22_ecr_detects_put_image(phase3_db: str):
    """G-22: SQL must detect PutImage (malicious image push)."""
    sql = get_builtin_sql("\U0001f433 ECR Repository / Image Changes")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert "PutImage" in names, f"PutImage not detected. Got: {names}"


def test_g22_ecr_detects_set_repository_policy(phase3_db: str):
    """G-22: SQL must detect SetRepositoryPolicy (cross-account access)."""
    sql = get_builtin_sql("\U0001f433 ECR Repository / Image Changes")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "SetRepositoryPolicy" in names
    ), f"SetRepositoryPolicy not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-23: RDS Public Accessibility Enabled
# ---------------------------------------------------------------------------


def test_g23_rds_public_access_label_exists():
    """G-23: The builtin hunt for RDS public accessibility must exist."""
    sql = get_builtin_sql("\U0001f4bd RDS Public Accessibility Enabled")
    assert len(sql) > 10


def test_g23_rds_detects_modify_db_instance_public(phase3_db: str):
    """G-23: SQL must detect ModifyDBInstance with publiclyAccessible=true."""
    sql = get_builtin_sql("\U0001f4bd RDS Public Accessibility Enabled")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "ModifyDBInstance" in names
    ), f"ModifyDBInstance not detected for public accessibility. Got: {names}"


def test_g23_rds_excludes_private_modify(phase3_db: str):
    """G-23: Benign DescribeInstances must not appear in RDS public results."""
    sql = get_builtin_sql("\U0001f4bd RDS Public Accessibility Enabled")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DescribeInstances" not in names


# ---------------------------------------------------------------------------
# G-24: Elastic IP Allocation / Association
# ---------------------------------------------------------------------------


def test_g24_eip_label_exists():
    """G-24: The builtin hunt for Elastic IP allocation must exist."""
    sql = get_builtin_sql("\U0001f4e1 Elastic IP Allocation / Association")
    assert len(sql) > 10


def test_g24_eip_detects_allocate_address(phase3_db: str):
    """G-24: SQL must detect AllocateAddress (new public IP for C2)."""
    sql = get_builtin_sql("\U0001f4e1 Elastic IP Allocation / Association")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert "AllocateAddress" in names, f"AllocateAddress not detected. Got: {names}"


def test_g24_eip_detects_associate_address(phase3_db: str):
    """G-24: SQL must detect AssociateAddress (attaching EIP to instance)."""
    sql = get_builtin_sql("\U0001f4e1 Elastic IP Allocation / Association")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert "AssociateAddress" in names, f"AssociateAddress not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-25: AWS Organizations Account Creation
# ---------------------------------------------------------------------------


def test_g25_org_account_creation_label_exists():
    """G-25: The builtin hunt for Organizations account creation must exist."""
    sql = get_builtin_sql("\U0001f4f0 AWS Organizations Account Creation")
    assert len(sql) > 10


def test_g25_org_detects_create_account(phase3_db: str):
    """G-25: SQL must detect CreateAccount (shadow account persistence)."""
    sql = get_builtin_sql("\U0001f4f0 AWS Organizations Account Creation")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert "CreateAccount" in names, f"CreateAccount not detected. Got: {names}"


def test_g25_org_detects_register_delegated_admin(phase3_db: str):
    """G-25: SQL must detect RegisterDelegatedAdministrator."""
    sql = get_builtin_sql("\U0001f4f0 AWS Organizations Account Creation")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "RegisterDelegatedAdministrator" in names
    ), f"RegisterDelegatedAdministrator not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-26: WAF WebACL Changes
# ---------------------------------------------------------------------------


def test_g26_waf_label_exists():
    """G-26: The builtin hunt for WAF WebACL changes must exist."""
    sql = get_builtin_sql("\U0001f3f9 WAF WebACL Changes")
    assert len(sql) > 10


def test_g26_waf_detects_delete_web_acl(phase3_db: str):
    """G-26: SQL must detect DeleteWebACL (disabling web protection)."""
    sql = get_builtin_sql("\U0001f3f9 WAF WebACL Changes")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DeleteWebACL" in names, f"DeleteWebACL not detected. Got: {names}"


def test_g26_waf_detects_update_web_acl(phase3_db: str):
    """G-26: SQL must detect UpdateWebACL (weakening WAF rules)."""
    sql = get_builtin_sql("\U0001f3f9 WAF WebACL Changes")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert "UpdateWebACL" in names, f"UpdateWebACL not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-27: Cognito Unauthenticated Access
# ---------------------------------------------------------------------------


def test_g27_cognito_unauth_label_exists():
    """G-27: The builtin hunt for Cognito unauthenticated access must exist."""
    sql = get_builtin_sql("\U0001f465 Cognito Unauthenticated Access")
    assert len(sql) > 10


def test_g27_cognito_detects_update_identity_pool(phase3_db: str):
    """G-27: SQL must detect UpdateIdentityPool with allowUnauthenticated=true."""
    sql = get_builtin_sql("\U0001f465 Cognito Unauthenticated Access")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "UpdateIdentityPool" in names
    ), f"UpdateIdentityPool not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-28: Budget / Cost Anomaly Changes
# ---------------------------------------------------------------------------


def test_g28_budget_label_exists():
    """G-28: The builtin hunt for budget/cost anomaly changes must exist."""
    sql = get_builtin_sql("\U0001f4b0 Budget / Cost Anomaly Changes")
    assert len(sql) > 10


def test_g28_budget_detects_delete_budget(phase3_db: str):
    """G-28: SQL must detect DeleteBudget (hiding cryptomining costs)."""
    sql = get_builtin_sql("\U0001f4b0 Budget / Cost Anomaly Changes")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DeleteBudget" in names, f"DeleteBudget not detected. Got: {names}"


def test_g28_budget_detects_delete_anomaly_monitor(phase3_db: str):
    """G-28: SQL must detect DeleteAnomalyMonitor."""
    sql = get_builtin_sql("\U0001f4b0 Budget / Cost Anomaly Changes")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "DeleteAnomalyMonitor" in names
    ), f"DeleteAnomalyMonitor not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-29: Lambda Layer Addition
# ---------------------------------------------------------------------------


def test_g29_lambda_layer_label_exists():
    """G-29: The builtin hunt for Lambda layer addition must exist."""
    sql = get_builtin_sql("\U0001f4e6 Lambda Layer Addition")
    assert len(sql) > 10


def test_g29_lambda_detects_publish_layer_version(phase3_db: str):
    """G-29: SQL must detect PublishLayerVersion (malicious shared layer)."""
    sql = get_builtin_sql("\U0001f4e6 Lambda Layer Addition")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "PublishLayerVersion" in names
    ), f"PublishLayerVersion not detected. Got: {names}"


def test_g29_lambda_detects_add_layer_version_permission(phase3_db: str):
    """G-29: SQL must detect AddLayerVersionPermission with principal=*."""
    sql = get_builtin_sql("\U0001f4e6 Lambda Layer Addition")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "AddLayerVersionPermission" in names
    ), f"AddLayerVersionPermission not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-30: EC2 User Data Modification
# ---------------------------------------------------------------------------


def test_g30_ec2_userdata_label_exists():
    """G-30: The builtin hunt for EC2 user data modification must exist."""
    sql = get_builtin_sql("\U0001f4dd EC2 User Data Modification")
    assert len(sql) > 10


def test_g30_ec2_userdata_detects_modify_instance_attribute(phase3_db: str):
    """G-30: SQL must detect ModifyInstanceAttribute with userData (code injection)."""
    sql = get_builtin_sql("\U0001f4dd EC2 User Data Modification")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "ModifyInstanceAttribute" in names
    ), f"ModifyInstanceAttribute not detected. Got: {names}"


def test_g30_ec2_userdata_excludes_benign_describe(phase3_db: str):
    """G-30: Benign DescribeInstances must not appear in user data results."""
    sql = get_builtin_sql("\U0001f4dd EC2 User Data Modification")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DescribeInstances" not in names


# ---------------------------------------------------------------------------
# G-31: IAM Access Analyzer Calls
# ---------------------------------------------------------------------------


def test_g31_access_analyzer_label_exists():
    """G-31: The builtin hunt for IAM Access Analyzer calls must exist."""
    sql = get_builtin_sql("\U0001f9d0 IAM Access Analyzer Calls")
    assert len(sql) > 10


def test_g31_access_analyzer_detects_list_findings(phase3_db: str):
    """G-31: SQL must detect ListFindings (attacker recon via Access Analyzer)."""
    sql = get_builtin_sql("\U0001f9d0 IAM Access Analyzer Calls")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert "ListFindings" in names, f"ListFindings not detected. Got: {names}"


def test_g31_access_analyzer_detects_get_finding(phase3_db: str):
    """G-31: SQL must detect GetFinding."""
    sql = get_builtin_sql("\U0001f9d0 IAM Access Analyzer Calls")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert "GetFinding" in names, f"GetFinding not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-32: STS AssumeRoleWithWebIdentity
# ---------------------------------------------------------------------------


def test_g32_assume_role_web_identity_label_exists():
    """G-32: The builtin hunt for STS AssumeRoleWithWebIdentity must exist."""
    sql = get_builtin_sql("\U0001f9e9 STS AssumeRoleWithWebIdentity")
    assert len(sql) > 10


def test_g32_detect_assume_role_with_web_identity(phase3_db: str):
    """G-32: SQL must detect AssumeRoleWithWebIdentity (OIDC token abuse)."""
    sql = get_builtin_sql("\U0001f9e9 STS AssumeRoleWithWebIdentity")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "AssumeRoleWithWebIdentity" in names
    ), f"AssumeRoleWithWebIdentity not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-33: Security Hub Tampering
# ---------------------------------------------------------------------------


def test_g33_securityhub_tampering_label_exists():
    """G-33: The builtin hunt for Security Hub tampering must exist."""
    sql = get_builtin_sql("\u26d4 Security Hub Tampering")
    assert len(sql) > 10


def test_g33_securityhub_detects_disable(phase3_db: str):
    """G-33: SQL must detect DisableSecurityHub."""
    sql = get_builtin_sql("\u26d4 Security Hub Tampering")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "DisableSecurityHub" in names
    ), f"DisableSecurityHub not detected. Got: {names}"


def test_g33_securityhub_detects_batch_disable_standards(phase3_db: str):
    """G-33: SQL must detect BatchDisableStandards (disabling CIS benchmarks)."""
    sql = get_builtin_sql("\u26d4 Security Hub Tampering")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "BatchDisableStandards" in names
    ), f"BatchDisableStandards not detected. Got: {names}"


def test_g33_securityhub_excludes_benign(phase3_db: str):
    """G-33: Benign DescribeInstances must not appear in Security Hub results."""
    sql = get_builtin_sql("\u26d4 Security Hub Tampering")
    rows = _run_sql(phase3_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DescribeInstances" not in names


# ---------------------------------------------------------------------------
# Cross-cutting: all Phase-3 SQL must pass DuckDB EXPLAIN
# ---------------------------------------------------------------------------

PHASE3_LABELS = [
    "\U0001f4c5 EventBridge / CloudWatch Rule Changes",
    "\U0001f4dc CloudWatch Logs Subscription Changes",
    "\u2638\ufe0f EKS Cluster API Calls",
    "\U0001f433 ECR Repository / Image Changes",
    "\U0001f4bd RDS Public Accessibility Enabled",
    "\U0001f4e1 Elastic IP Allocation / Association",
    "\U0001f4f0 AWS Organizations Account Creation",
    "\U0001f3f9 WAF WebACL Changes",
    "\U0001f465 Cognito Unauthenticated Access",
    "\U0001f4b0 Budget / Cost Anomaly Changes",
    "\U0001f4e6 Lambda Layer Addition",
    "\U0001f4dd EC2 User Data Modification",
    "\U0001f9d0 IAM Access Analyzer Calls",
    "\U0001f9e9 STS AssumeRoleWithWebIdentity",
    "\u26d4 Security Hub Tampering",
]


@pytest.mark.parametrize("label", PHASE3_LABELS)
def test_phase3_sql_is_valid_duckdb_syntax(phase3_db: str, label: str):
    """All Phase-3 SQL queries must pass DuckDB EXPLAIN without errors."""
    sql = get_builtin_sql(label)
    conn = duckdb.connect(phase3_db, read_only=True)
    try:
        conn.execute(f"EXPLAIN {sql}")
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"EXPLAIN failed for '{label}': {exc}")
    finally:
        conn.close()
