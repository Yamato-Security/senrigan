"""Phase 5 — Threat Technique Catalog gap-closing hunts for builtin_hunts.yaml.

Tests TC-P1 through TC-P10 in the Red-Green-Refactor cycle (see
doc/PLAN_THREAT_CATALOG.md §3, Priority 1):
  TC-P1:  IAM Entity Deletion               (T1070.A001)
  TC-P2:  AssumeRoot Usage                  (AT1669)
  TC-P3:  S3 SSE-C Encryption (Ransomware)  (T1486.A001)
  TC-P4:  S3 Lifecycle-Triggered Deletion   (T1485.001)
  TC-P5:  RDS Query & Instance Manipulation (AT1023.001 / T1213.A013)
  TC-P6:  IMDS Options Weakening            (T1552.005)
  TC-P7:  Route 53 & Domain Changes         (T1583.001 / T1491.A001)
  TC-P8:  S3 Bucket Enumeration             (T1619.A001)
  TC-P9:  AMI & Snapshot Deletion           (T1485.A002)
  TC-P10: Storage Re-Encryption for Impact  (T1486.A002 / T1486.A003)
"""

from __future__ import annotations

import pathlib
from typing import Any

import duckdb
import pytest
import yaml

YAML_PATH = pathlib.Path(__file__).parent.parent / "builtin_hunts.yaml"

P1_LABEL = "\U0001fa93 IAM Entity Deletion"
P2_LABEL = "\U0001f451 AssumeRoot Usage"
P3_LABEL = "\U0001f510 S3 SSE-C Encryption (Ransomware)"
P4_LABEL = "⏳ S3 Lifecycle-Triggered Deletion"
P5_LABEL = "\U0001f5c3 RDS Query & Instance Manipulation"
P6_LABEL = "\U0001f6f0 IMDS Options Weakening"
P7_LABEL = "\U0001f310 Route 53 & Domain Changes"
P8_LABEL = "\U0001f50e S3 Bucket Enumeration"
P9_LABEL = "\U0001f4a5 AMI & Snapshot Deletion"
P10_LABEL = "\U0001f511 Storage Re-Encryption for Impact"

IDENTITY_CATEGORY = "\U0001f511 Identity & Access"
DATA_CATEGORY = "\U0001faa3 Data & Storage"
COMPUTE_CATEGORY = "⚡ Compute & Serverless"
NETWORK_CATEGORY = "\U0001f310 Network & Infrastructure"

EXPECTED = {
    P1_LABEL: (IDENTITY_CATEGORY, ["T1070.A001"]),
    P2_LABEL: (IDENTITY_CATEGORY, ["AT1669"]),
    P3_LABEL: (DATA_CATEGORY, ["T1486.A001"]),
    P4_LABEL: (DATA_CATEGORY, ["T1485.001"]),
    P5_LABEL: (DATA_CATEGORY, ["AT1023.001", "T1213.A013"]),
    P6_LABEL: (COMPUTE_CATEGORY, ["T1552.005"]),
    P7_LABEL: (NETWORK_CATEGORY, ["T1583.001", "T1491.A001"]),
    P8_LABEL: (DATA_CATEGORY, ["T1619.A001"]),
    P9_LABEL: (COMPUTE_CATEGORY, ["T1485.A002"]),
    P10_LABEL: (DATA_CATEGORY, ["T1486.A002", "T1486.A003"]),
}


def _load_hunts() -> list[dict[str, Any]]:
    with open(YAML_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def get_hunt(label: str) -> dict[str, Any]:
    """Return the full hunt entry for the given label."""
    for hunt in _load_hunts():
        if hunt.get("label") == label:
            return hunt
    raise ValueError(f"No builtin hunt found with label: {label!r}")


def get_builtin_sql(label: str) -> str:
    """Return the ``sql`` field for the given hunt label."""
    hunt = get_hunt(label)
    sql = hunt.get("sql")
    assert sql, f"Hunt '{label}' found but has no 'sql' field"
    return sql


def _run_sql(db_path: str, sql: str) -> list[dict]:
    """Execute SQL against a read-only DuckDB and return rows as list-of-dicts."""
    conn = duckdb.connect(db_path, read_only=True)
    try:
        result = conn.execute(sql).fetchdf()
        return result.to_dict(orient="records")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Fixture — DuckDB pre-loaded with Phase-5 test events
# ---------------------------------------------------------------------------


@pytest.fixture()
def phase5_db(tmp_path: pathlib.Path) -> str:
    """Temporary DuckDB pre-loaded with one positive event per hunt plus noise."""
    db_path = tmp_path / "phase5_test.db"
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
            error_code               VARCHAR,
            error_message            VARCHAR,
            read_only                BOOLEAN,
            event_type               VARCHAR,
            recipient_account_id     VARCHAR,
            raw_event                VARCHAR
        )
    """)

    def insert(
        event_name: str,
        event_source: str,
        request_parameters: str = "{}",
        additional_event_data: str | None = None,
        arn: str = "arn:aws:iam::111111111111:user/attacker",
        when: str = "2024-06-01 10:00:00",
        read_only: bool = False,
    ) -> None:
        conn.execute(
            """
            INSERT INTO cloudtrail_events
                (event_time, event_name, event_source, aws_region,
                 source_ip_address, user_identity_arn, request_parameters,
                 additional_event_data, read_only)
            VALUES (?, ?, ?, 'us-east-1', '203.0.113.50', ?, ?, ?, ?)
            """,
            [
                when,
                event_name,
                event_source,
                arn,
                request_parameters,
                additional_event_data,
                read_only,
            ],
        )

    # TC-P1: IAM entity deletion
    insert("DeleteUser", "iam.amazonaws.com", '{"userName":"victim-user"}')
    insert("DeleteRole", "iam.amazonaws.com", '{"roleName":"victim-role"}')
    # TC-P2: AssumeRoot
    insert(
        "AssumeRoot",
        "sts.amazonaws.com",
        '{"targetPrincipal":"222222222222",'
        '"taskPolicyArn":{"arn":"arn:aws:iam::aws:policy/root-task/'
        'IAMDeleteRootUserCredentials"}}',
    )
    # TC-P3: SSE-C copy + bucket encryption change
    insert(
        "CopyObject",
        "s3.amazonaws.com",
        '{"bucketName":"victim-bucket","x-amz-server-side-encryption-customer-algorithm":"AES256"}',
        additional_event_data='{"SSEApplied":"SSE_C","bytesTransferredIn":0}',
    )
    insert("PutBucketEncryption", "s3.amazonaws.com", '{"bucketName":"victim-bucket"}')
    # negative for TC-P3: normal SSE-KMS copy must NOT match
    insert(
        "CopyObject",
        "s3.amazonaws.com",
        '{"bucketName":"ok-bucket"}',
        additional_event_data='{"SSEApplied":"Default_SSE_S3"}',
        arn="arn:aws:iam::111111111111:user/normal",
    )
    # TC-P4: lifecycle deletion rule
    insert(
        "PutBucketLifecycle",
        "s3.amazonaws.com",
        '{"bucketName":"victim-bucket","LifecycleConfiguration":'
        '{"Rule":{"Expiration":{"Days":1},"Status":"Enabled","ID":"nuke"}}}',
    )
    # TC-P5: RDS Data API query + master password reset
    insert(
        "ExecuteStatement",
        "rds-data.amazonaws.com",
        '{"resourceArn":"arn:aws:rds:us-east-1:111111111111:cluster:prod",'
        '"sql":"SELECT * FROM users"}',
    )
    insert(
        "ModifyDBInstance",
        "rds.amazonaws.com",
        '{"dBInstanceIdentifier":"prod-db","masterUserPassword":"****"}',
    )
    # negative for TC-P5: ModifyDBInstance without password change must NOT match
    insert(
        "ModifyDBInstance",
        "rds.amazonaws.com",
        '{"dBInstanceIdentifier":"prod-db","allocatedStorage":100}',
        arn="arn:aws:iam::111111111111:user/normal",
    )
    # TC-P6: IMDSv2 requirement dropped
    insert(
        "ModifyInstanceMetadataOptions",
        "ec2.amazonaws.com",
        '{"ModifyInstanceMetadataOptionsRequest":'
        '{"InstanceId":"i-0abc123","HttpTokens":"optional"}}',
    )
    # TC-P7: DNS record change
    insert(
        "ChangeResourceRecordSets",
        "route53.amazonaws.com",
        '{"hostedZoneId":"Z123","changeBatch":{"changes":[{"action":"UPSERT",'
        '"resourceRecordSet":{"name":"www.example.com.","type":"CNAME"}}]}}',
    )
    insert(
        "RegisterDomain", "route53domains.amazonaws.com", '{"domainName":"evil.com"}'
    )
    # TC-P8: S3 enumeration sweep — 12 read calls in one hour by one caller
    for i in range(12):
        insert(
            "GetBucketAcl" if i % 2 else "ListBuckets",
            "s3.amazonaws.com",
            f'{{"bucketName":"bucket-{i}"}}',
            arn="arn:aws:iam::111111111111:user/enumerator",
            when=f"2024-06-01 10:{i:02d}:00",
            read_only=True,
        )
    # negative for TC-P8: 3 calls only — below threshold
    for i in range(3):
        insert(
            "ListBuckets",
            "s3.amazonaws.com",
            "{}",
            arn="arn:aws:iam::111111111111:user/normal",
            when=f"2024-06-01 11:{i:02d}:00",
            read_only=True,
        )
    # TC-P9: bulk AMI/snapshot deletion — 6 deletions in one hour
    for i in range(6):
        insert(
            "DeleteSnapshot" if i % 2 else "DeregisterImage",
            "ec2.amazonaws.com",
            f'{{"snapshotId":"snap-{i}"}}',
            arn="arn:aws:iam::111111111111:user/destroyer",
            when=f"2024-06-01 10:{i:02d}:30",
        )
    # negative for TC-P9: single deletion — below threshold
    insert(
        "DeleteSnapshot",
        "ec2.amazonaws.com",
        '{"snapshotId":"snap-ok"}',
        arn="arn:aws:iam::111111111111:user/normal",
        when="2024-06-01 12:00:00",
    )
    # TC-P10: snapshot re-encryption with explicit KMS key + RDS copy
    insert(
        "CopySnapshot",
        "ec2.amazonaws.com",
        '{"sourceSnapshotId":"snap-1","encrypted":true,'
        '"kmsKeyId":"arn:aws:kms:us-east-1:999999999999:key/attacker-key"}',
    )
    insert(
        "CopyDBSnapshot",
        "rds.amazonaws.com",
        '{"sourceDBSnapshotIdentifier":"prod-snap","kmsKeyId":"attacker-key"}',
    )
    insert("DisableEbsEncryptionByDefault", "ec2.amazonaws.com", "{}")
    # negative for TC-P10: CopySnapshot without kmsKeyId must NOT match
    insert(
        "CopySnapshot",
        "ec2.amazonaws.com",
        '{"sourceSnapshotId":"snap-2","encrypted":false}',
        arn="arn:aws:iam::111111111111:user/normal",
    )
    # generic noise
    insert("DescribeInstances", "ec2.amazonaws.com", "{}", read_only=True)

    conn.close()
    return str(db_path)


# ---------------------------------------------------------------------------
# Schema tests — every hunt exists with the expected category / techniques
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("label", list(EXPECTED))
def test_hunt_exists_with_category_sql_and_techniques(label):
    hunt = get_hunt(label)
    category, tids = EXPECTED[label]
    assert hunt["category"] == category
    assert hunt.get("sql", "").strip(), f"{label} must ship a direct-SQL query"
    assert hunt.get("prompt", "").strip(), f"{label} must ship an AI prompt"
    assert hunt.get("description", "").strip()
    got_tids = [t["tid"] for t in hunt.get("techniques", [])]
    assert got_tids == tids


# ---------------------------------------------------------------------------
# Detection tests — positive and negative
# ---------------------------------------------------------------------------


def test_iam_entity_deletion_detects_delete_events(phase5_db):
    rows = _run_sql(phase5_db, get_builtin_sql(P1_LABEL))
    names = {r["event_name"] for r in rows}
    assert {"DeleteUser", "DeleteRole"} <= names
    entities = {r["deleted_entity"] for r in rows}
    assert {"victim-user", "victim-role"} <= entities


def test_assume_root_detects_event_and_target(phase5_db):
    rows = _run_sql(phase5_db, get_builtin_sql(P2_LABEL))
    assert len(rows) == 1
    assert rows[0]["event_name"] == "AssumeRoot"
    assert rows[0]["target_principal"] == "222222222222"


def test_s3_ssec_detects_ssec_copy_and_encryption_change(phase5_db):
    rows = _run_sql(phase5_db, get_builtin_sql(P3_LABEL))
    names = [r["event_name"] for r in rows]
    assert "CopyObject" in names
    assert "PutBucketEncryption" in names
    # the SSE-KMS CopyObject on ok-bucket must not match
    buckets = {r.get("bucket_name") for r in rows}
    assert "ok-bucket" not in buckets


def test_s3_lifecycle_deletion_detects_rule_with_expiration(phase5_db):
    rows = _run_sql(phase5_db, get_builtin_sql(P4_LABEL))
    assert len(rows) == 1
    assert rows[0]["event_name"] == "PutBucketLifecycle"
    assert str(rows[0]["expiration_days"]) == "1"


def test_rds_manipulation_detects_data_api_and_password_reset(phase5_db):
    rows = _run_sql(phase5_db, get_builtin_sql(P5_LABEL))
    names = [r["event_name"] for r in rows]
    assert "ExecuteStatement" in names
    assert "ModifyDBInstance" in names
    # exactly one ModifyDBInstance (the password reset) — the storage-only
    # modification must not match
    assert names.count("ModifyDBInstance") == 1


def test_imds_weakening_detects_http_tokens_optional(phase5_db):
    rows = _run_sql(phase5_db, get_builtin_sql(P6_LABEL))
    assert len(rows) == 1
    assert rows[0]["http_tokens"] == "optional"
    assert rows[0]["instance_id"] == "i-0abc123"


def test_route53_detects_record_and_domain_changes(phase5_db):
    rows = _run_sql(phase5_db, get_builtin_sql(P7_LABEL))
    names = {r["event_name"] for r in rows}
    assert {"ChangeResourceRecordSets", "RegisterDomain"} <= names


def test_s3_enumeration_detects_sweep_above_threshold(phase5_db):
    rows = _run_sql(phase5_db, get_builtin_sql(P8_LABEL))
    assert len(rows) == 1
    assert rows[0]["user_identity_arn"].endswith("user/enumerator")
    assert rows[0]["enum_calls"] == 12


def test_ami_snapshot_deletion_detects_bulk_only(phase5_db):
    rows = _run_sql(phase5_db, get_builtin_sql(P9_LABEL))
    assert len(rows) == 1
    assert rows[0]["user_identity_arn"].endswith("user/destroyer")
    assert rows[0]["delete_count"] == 6


def test_storage_reencryption_detects_kms_copies(phase5_db):
    rows = _run_sql(phase5_db, get_builtin_sql(P10_LABEL))
    names = [r["event_name"] for r in rows]
    assert "CopySnapshot" in names
    assert "CopyDBSnapshot" in names
    assert "DisableEbsEncryptionByDefault" in names
    # the unencrypted CopySnapshot must not match
    assert names.count("CopySnapshot") == 1


def test_phase5_hunts_pass_query_validation(phase5_db):
    """SQL-safety guard: every new hunt passes blocklist + EXPLAIN validation."""
    from query import validate_query

    conn = duckdb.connect(phase5_db, read_only=True)
    try:
        for label in EXPECTED:
            validate_query(conn, get_builtin_sql(label))
    finally:
        conn.close()
