"""Phase 2 — High-priority DFIR gap tests for builtin_hunts.yaml.

Tests G-09 through G-18 in the Red-Green-Refactor cycle:
  G-09: EC2 Key Pair Creation
  G-10: S3 Bucket Policy / ACL Changes
  G-11: S3 Versioning / Logging Disabled
  G-12: IAM Permission Boundary Changes
  G-13: IAM Identity Center (SSO) Events
  G-14: SAML / OIDC Provider Updates
  G-15: Network ACL Changes
  G-16: Route Table Changes
  G-17: S3 Cross-Account Replication
  G-18: EC2 Instance Profile Changes

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
# Helpers (same as Phase 1)
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
# Fixture — extended tmp DuckDB with Phase-2 relevant test events
# ---------------------------------------------------------------------------


@pytest.fixture()
def phase2_db(tmp_path: pathlib.Path) -> str:
    """Temporary DuckDB pre-loaded with Phase-2 test events."""
    db_path = tmp_path / "phase2_test.db"
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
             user_identity_account_id, user_agent)
        VALUES
        -- G-09: EC2 key pair created (SSH backdoor)
        ('2024-04-01 01:00:00', 'CreateKeyPair', 'ec2.amazonaws.com', 'ap-northeast-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.5',
         '{"keyName":"attacker-backdoor-key"}',
         '{"keyFingerprint":"aa:bb:cc:dd"}', NULL, false, '111111111111', '111111111111',
         'aws-cli/2.0'),
        ('2024-04-01 01:05:00', 'ImportKeyPair', 'ec2.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.5',
         '{"keyName":"imported-key","publicKeyMaterial":"c3NoLXJzYQ=="}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),

        -- G-10: S3 bucket policy changed (makes bucket public or cross-account)
        -- bucketPolicy stored as escaped string (as CloudTrail records it)
        ('2024-04-02 02:00:00', 'PutBucketPolicy', 's3.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.10',
         '{"bucketName":"prod-data-bucket","bucketPolicy":"<policy-with-principal-star>"}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),
        ('2024-04-02 02:30:00', 'PutBucketAcl',    's3.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.10',
         '{"bucketName":"prod-data-bucket","AccessControlPolicy":"public-read"}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),

        -- G-11: S3 versioning disabled / logging disabled
        ('2024-04-03 03:00:00', 'PutBucketVersioning', 's3.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.15',
         '{"bucketName":"backup-bucket","VersioningConfiguration":{"Status":"Suspended"}}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),
        ('2024-04-03 03:30:00', 'PutBucketLogging',  's3.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.15',
         '{"bucketName":"backup-bucket","BucketLoggingStatus":{}}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),

        -- G-12: IAM permission boundary removed (privilege escalation path)
        ('2024-04-04 04:00:00', 'DeleteUserPermissionsBoundary', 'iam.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.20',
         '{"userName":"dev-user"}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),
        ('2024-04-04 04:10:00', 'DeleteRolePermissionsBoundary', 'iam.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.20',
         '{"roleName":"LambdaExecutionRole"}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),

        -- G-13: IAM Identity Center (SSO) events
        ('2024-04-05 05:00:00', 'CreateAccountAssignment', 'sso.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.25',
         '{"instanceArn":"arn:aws:sso:::instance/ssoins-abc","targetId":"222222222222","permissionSetArn":"arn:aws:sso:::permissionSet/ssoins-abc/ps-xyz"}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),
        ('2024-04-05 05:15:00', 'CreatePermissionSet',    'sso.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.25',
         '{"instanceArn":"arn:aws:sso:::instance/ssoins-abc","name":"BackdoorAdmin"}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),

        -- G-14: SAML provider updated (backdoor identity provider)
        ('2024-04-06 06:00:00', 'UpdateSAMLProvider', 'iam.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.30',
         '{"sAMLProviderArn":"arn:aws:iam::111111111111:saml-provider/CorpSSO"}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),
        ('2024-04-06 06:15:00', 'CreateOIDCProvider', 'iam.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.30',
         '{"url":"https://attacker-idp.example.com","thumbprintList":["abc123"]}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),

        -- G-15: Network ACL entry added (bypasses security groups)
        ('2024-04-07 07:00:00', 'CreateNetworkAclEntry', 'ec2.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.35',
         '{"networkAclId":"acl-0123abc","ruleNumber":"99","protocol":"-1","ruleAction":"allow","cidrBlock":"0.0.0.0/0"}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),
        ('2024-04-07 07:30:00', 'DeleteNetworkAclEntry', 'ec2.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.35',
         '{"networkAclId":"acl-0123abc","ruleNumber":"100","egress":"false"}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),

        -- G-16: Route table modified (traffic redirection)
        ('2024-04-08 08:00:00', 'CreateRoute',  'ec2.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.40',
         '{"routeTableId":"rtb-0abc123","destinationCidrBlock":"0.0.0.0/0","gatewayId":"igw-0xyz"}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),
        ('2024-04-08 08:15:00', 'ReplaceRoute', 'ec2.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.40',
         '{"routeTableId":"rtb-0abc123","destinationCidrBlock":"10.0.0.0/8","networkInterfaceId":"eni-0xyz"}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),

        -- G-17: S3 cross-account replication configured
        ('2024-04-09 09:00:00', 'PutBucketReplication', 's3.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.45',
         '{"bucketName":"source-bucket","replicationConfiguration":{"role":"arn:aws:iam::111111111111:role/s3-replication","rules":[{"destination":{"bucket":"arn:aws:s3:::attacker-bucket-999999999999"}}]}}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),

        -- G-18: EC2 instance profile replaced (malicious role attached)
        ('2024-04-10 10:00:00', 'AssociateIamInstanceProfile', 'ec2.amazonaws.com', 'ap-northeast-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.50',
         '{"instanceId":"i-0abc123def456","iamInstanceProfile":{"arn":"arn:aws:iam::111111111111:instance-profile/MaliciousProfile"}}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),
        ('2024-04-10 10:15:00', 'ReplaceIamInstanceProfileAssociation', 'ec2.amazonaws.com', 'ap-northeast-1',
         'arn:aws:iam::111111111111:user/attacker', '203.0.113.50',
         '{"associationId":"iip-assoc-0abc","iamInstanceProfile":{"arn":"arn:aws:iam::111111111111:instance-profile/AdminProfile"}}',
         NULL, NULL, false, '111111111111', '111111111111', 'aws-cli/2.0'),

        -- Benign baseline
        ('2024-04-01 12:00:00', 'DescribeInstances', 'ec2.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/jenkins', '10.0.0.100',
         '{}', NULL, NULL, true, '111111111111', '111111111111', 'aws-cli/2.0')
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
# G-09: EC2 Key Pair Creation
# ---------------------------------------------------------------------------


def test_g09_ec2_keypair_label_exists():
    """G-09: The builtin hunt entry for EC2 key pair creation must exist."""
    sql = get_builtin_sql("\U0001f5dd\ufe0f EC2 Key Pair Creation")
    assert len(sql) > 10


def test_g09_ec2_keypair_detects_create_key_pair(phase2_db: str):
    """G-09: SQL must detect CreateKeyPair (new SSH backdoor key)."""
    sql = get_builtin_sql("\U0001f5dd\ufe0f EC2 Key Pair Creation")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert "CreateKeyPair" in names, f"CreateKeyPair not detected. Got: {names}"


def test_g09_ec2_keypair_detects_import_key_pair(phase2_db: str):
    """G-09: SQL must detect ImportKeyPair (attacker-uploaded public key)."""
    sql = get_builtin_sql("\U0001f5dd\ufe0f EC2 Key Pair Creation")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert "ImportKeyPair" in names, f"ImportKeyPair not detected. Got: {names}"


def test_g09_ec2_keypair_excludes_benign(phase2_db: str):
    """G-09: Benign DescribeInstances must not appear."""
    sql = get_builtin_sql("\U0001f5dd\ufe0f EC2 Key Pair Creation")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DescribeInstances" not in names


# ---------------------------------------------------------------------------
# G-10: S3 Bucket Policy / ACL Changes
# ---------------------------------------------------------------------------


def test_g10_s3_policy_acl_label_exists():
    """G-10: The builtin hunt for S3 bucket policy/ACL changes must exist."""
    sql = get_builtin_sql("\U0001faa3 S3 Bucket Policy / ACL Changes")
    assert len(sql) > 10


def test_g10_s3_policy_detects_put_bucket_policy(phase2_db: str):
    """G-10: SQL must detect PutBucketPolicy."""
    sql = get_builtin_sql("\U0001faa3 S3 Bucket Policy / ACL Changes")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert "PutBucketPolicy" in names, f"PutBucketPolicy not detected. Got: {names}"


def test_g10_s3_policy_detects_put_bucket_acl(phase2_db: str):
    """G-10: SQL must detect PutBucketAcl."""
    sql = get_builtin_sql("\U0001faa3 S3 Bucket Policy / ACL Changes")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert "PutBucketAcl" in names, f"PutBucketAcl not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-11: S3 Versioning / Logging Disabled
# ---------------------------------------------------------------------------


def test_g11_s3_versioning_logging_label_exists():
    """G-11: The builtin hunt for S3 versioning/logging disabled must exist."""
    sql = get_builtin_sql("\U0001f4c2 S3 Versioning / Logging Disabled")
    assert len(sql) > 10


def test_g11_s3_detects_versioning_suspended(phase2_db: str):
    """G-11: SQL must detect PutBucketVersioning with Status=Suspended."""
    sql = get_builtin_sql("\U0001f4c2 S3 Versioning / Logging Disabled")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "PutBucketVersioning" in names
    ), f"PutBucketVersioning not detected. Got: {names}"


def test_g11_s3_detects_logging_disabled(phase2_db: str):
    """G-11: SQL must detect PutBucketLogging with empty BucketLoggingStatus."""
    sql = get_builtin_sql("\U0001f4c2 S3 Versioning / Logging Disabled")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert "PutBucketLogging" in names, f"PutBucketLogging not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-12: IAM Permission Boundary Changes
# ---------------------------------------------------------------------------


def test_g12_iam_permission_boundary_label_exists():
    """G-12: The builtin hunt for IAM permission boundary changes must exist."""
    sql = get_builtin_sql("\U0001f6a7 IAM Permission Boundary Changes")
    assert len(sql) > 10


def test_g12_detects_delete_user_permissions_boundary(phase2_db: str):
    """G-12: SQL must detect DeleteUserPermissionsBoundary."""
    sql = get_builtin_sql("\U0001f6a7 IAM Permission Boundary Changes")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "DeleteUserPermissionsBoundary" in names
    ), f"DeleteUserPermissionsBoundary not detected. Got: {names}"


def test_g12_detects_delete_role_permissions_boundary(phase2_db: str):
    """G-12: SQL must detect DeleteRolePermissionsBoundary."""
    sql = get_builtin_sql("\U0001f6a7 IAM Permission Boundary Changes")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "DeleteRolePermissionsBoundary" in names
    ), f"DeleteRolePermissionsBoundary not detected. Got: {names}"


def test_g12_excludes_benign(phase2_db: str):
    """G-12: Benign DescribeInstances must not appear."""
    sql = get_builtin_sql("\U0001f6a7 IAM Permission Boundary Changes")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DescribeInstances" not in names


# ---------------------------------------------------------------------------
# G-13: IAM Identity Center (SSO) Events
# ---------------------------------------------------------------------------


def test_g13_sso_events_label_exists():
    """G-13: The builtin hunt for IAM Identity Center SSO events must exist."""
    sql = get_builtin_sql("\U0001f194 IAM Identity Center (SSO) Events")
    assert len(sql) > 10


def test_g13_sso_detects_create_account_assignment(phase2_db: str):
    """G-13: SQL must detect CreateAccountAssignment (backdoor account access)."""
    sql = get_builtin_sql("\U0001f194 IAM Identity Center (SSO) Events")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "CreateAccountAssignment" in names
    ), f"CreateAccountAssignment not detected. Got: {names}"


def test_g13_sso_detects_create_permission_set(phase2_db: str):
    """G-13: SQL must detect CreatePermissionSet (new admin permission set)."""
    sql = get_builtin_sql("\U0001f194 IAM Identity Center (SSO) Events")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "CreatePermissionSet" in names
    ), f"CreatePermissionSet not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-14: SAML / OIDC Provider Updates
# ---------------------------------------------------------------------------


def test_g14_saml_oidc_label_exists():
    """G-14: The builtin hunt for SAML/OIDC provider updates must exist."""
    sql = get_builtin_sql("\U0001f517 SAML / OIDC Provider Updates")
    assert len(sql) > 10


def test_g14_detects_update_saml_provider(phase2_db: str):
    """G-14: SQL must detect UpdateSAMLProvider (backdoor IdP)."""
    sql = get_builtin_sql("\U0001f517 SAML / OIDC Provider Updates")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "UpdateSAMLProvider" in names
    ), f"UpdateSAMLProvider not detected. Got: {names}"


def test_g14_detects_create_oidc_provider(phase2_db: str):
    """G-14: SQL must detect CreateOIDCProvider (rogue OIDC IdP)."""
    sql = get_builtin_sql("\U0001f517 SAML / OIDC Provider Updates")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "CreateOIDCProvider" in names
    ), f"CreateOIDCProvider not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-15: Network ACL Changes
# ---------------------------------------------------------------------------


def test_g15_nacl_label_exists():
    """G-15: The builtin hunt for Network ACL changes must exist."""
    sql = get_builtin_sql("\U0001f9f1 Network ACL Changes")
    assert len(sql) > 10


def test_g15_nacl_detects_create_entry(phase2_db: str):
    """G-15: SQL must detect CreateNetworkAclEntry (new allow-all rule)."""
    sql = get_builtin_sql("\U0001f9f1 Network ACL Changes")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "CreateNetworkAclEntry" in names
    ), f"CreateNetworkAclEntry not detected. Got: {names}"


def test_g15_nacl_detects_delete_entry(phase2_db: str):
    """G-15: SQL must detect DeleteNetworkAclEntry (removing deny rules)."""
    sql = get_builtin_sql("\U0001f9f1 Network ACL Changes")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "DeleteNetworkAclEntry" in names
    ), f"DeleteNetworkAclEntry not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-16: Route Table Changes
# ---------------------------------------------------------------------------


def test_g16_route_table_label_exists():
    """G-16: The builtin hunt for route table changes must exist."""
    sql = get_builtin_sql("\U0001f6e3\ufe0f Route Table Changes")
    assert len(sql) > 10


def test_g16_detects_create_route(phase2_db: str):
    """G-16: SQL must detect CreateRoute (traffic redirection)."""
    sql = get_builtin_sql("\U0001f6e3\ufe0f Route Table Changes")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert "CreateRoute" in names, f"CreateRoute not detected. Got: {names}"


def test_g16_detects_replace_route(phase2_db: str):
    """G-16: SQL must detect ReplaceRoute (MitM / traffic hijacking)."""
    sql = get_builtin_sql("\U0001f6e3\ufe0f Route Table Changes")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert "ReplaceRoute" in names, f"ReplaceRoute not detected. Got: {names}"


def test_g16_excludes_read_only(phase2_db: str):
    """G-16: Benign DescribeInstances must not appear in route table results."""
    sql = get_builtin_sql("\U0001f6e3\ufe0f Route Table Changes")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DescribeInstances" not in names


# ---------------------------------------------------------------------------
# G-17: S3 Cross-Account Replication
# ---------------------------------------------------------------------------


def test_g17_s3_replication_label_exists():
    """G-17: The builtin hunt for S3 cross-account replication must exist."""
    sql = get_builtin_sql("\U0001f501 S3 Cross-Account Replication")
    assert len(sql) > 10


def test_g17_s3_replication_detects_put_bucket_replication(phase2_db: str):
    """G-17: SQL must detect PutBucketReplication (data staging for exfiltration)."""
    sql = get_builtin_sql("\U0001f501 S3 Cross-Account Replication")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "PutBucketReplication" in names
    ), f"PutBucketReplication not detected. Got: {names}"


# ---------------------------------------------------------------------------
# G-18: EC2 Instance Profile Changes
# ---------------------------------------------------------------------------


def test_g18_instance_profile_label_exists():
    """G-18: The builtin hunt for EC2 instance profile changes must exist."""
    sql = get_builtin_sql("\U0001f464 EC2 Instance Profile Changes")
    assert len(sql) > 10


def test_g18_detects_associate_iam_instance_profile(phase2_db: str):
    """G-18: SQL must detect AssociateIamInstanceProfile (malicious role attach)."""
    sql = get_builtin_sql("\U0001f464 EC2 Instance Profile Changes")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "AssociateIamInstanceProfile" in names
    ), f"AssociateIamInstanceProfile not detected. Got: {names}"


def test_g18_detects_replace_instance_profile(phase2_db: str):
    """G-18: SQL must detect ReplaceIamInstanceProfileAssociation."""
    sql = get_builtin_sql("\U0001f464 EC2 Instance Profile Changes")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert (
        "ReplaceIamInstanceProfileAssociation" in names
    ), f"ReplaceIamInstanceProfileAssociation not detected. Got: {names}"


def test_g18_excludes_benign(phase2_db: str):
    """G-18: Benign DescribeInstances must not appear."""
    sql = get_builtin_sql("\U0001f464 EC2 Instance Profile Changes")
    rows = _run_sql(phase2_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DescribeInstances" not in names


# ---------------------------------------------------------------------------
# Cross-cutting: all Phase-2 SQL must pass DuckDB EXPLAIN
# ---------------------------------------------------------------------------

PHASE2_LABELS = [
    "\U0001f5dd\ufe0f EC2 Key Pair Creation",
    "\U0001faa3 S3 Bucket Policy / ACL Changes",
    "\U0001f4c2 S3 Versioning / Logging Disabled",
    "\U0001f6a7 IAM Permission Boundary Changes",
    "\U0001f194 IAM Identity Center (SSO) Events",
    "\U0001f517 SAML / OIDC Provider Updates",
    "\U0001f9f1 Network ACL Changes",
    "\U0001f6e3\ufe0f Route Table Changes",
    "\U0001f501 S3 Cross-Account Replication",
    "\U0001f464 EC2 Instance Profile Changes",
]


@pytest.mark.parametrize("label", PHASE2_LABELS)
def test_phase2_sql_is_valid_duckdb_syntax(phase2_db: str, label: str):
    """All Phase-2 SQL queries must pass DuckDB EXPLAIN without errors."""
    sql = get_builtin_sql(label)
    conn = duckdb.connect(phase2_db, read_only=True)
    try:
        conn.execute(f"EXPLAIN {sql}")
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"EXPLAIN failed for '{label}': {exc}")
    finally:
        conn.close()
