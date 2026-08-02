"""Phase 6 — Priority-2 catalog hunts and extensions for builtin_hunts.yaml.

Priority-2 entries of the Threat Technique Catalog:
  New hunts:
    TC-Q1: WorkSpaces Hijacking          (T1496.A009)
    TC-Q2: Support Case Manipulation     (T1098.A001)
    TC-Q3: Cognito User Pool Manipulation (T1098.A006)
    TC-Q4: First-Seen Region Activity    (T1535)
  Extensions:
    TC-Q5: Organizations hunt also flags LeaveOrganization / handshake events
           and declares T1666.A002 / T1666.A003.
    TC-Q6: Lambda hunt also flags CreateFunctionUrlConfig and declares
           T1648.A001.
"""

from __future__ import annotations

import pathlib
from typing import Any

import duckdb
import pytest
import yaml

YAML_PATH = pathlib.Path(__file__).parent.parent / "builtin_hunts.yaml"

Q1_LABEL = "\U0001f5a5 WorkSpaces Hijacking"
Q2_LABEL = "\U0001f3ab Support Case Manipulation"
Q3_LABEL = "\U0001faaa Cognito User Pool Manipulation"
Q4_LABEL = "\U0001f5fa First-Seen Region Activity"
ORG_LABEL = "\U0001f4f0 AWS Organizations Account Creation"
LAMBDA_LABEL = "⚡ Lambda Function Tampering"

COMPUTE_CATEGORY = "⚡ Compute & Serverless"
IDENTITY_CATEGORY = "\U0001f511 Identity & Access"
THREAT_CATEGORY = "\U0001f575 Threat Patterns"

NEW_HUNTS = {
    Q1_LABEL: (COMPUTE_CATEGORY, ["T1496.A009"]),
    Q2_LABEL: (IDENTITY_CATEGORY, ["T1098.A001"]),
    Q3_LABEL: (IDENTITY_CATEGORY, ["T1098.A006"]),
    Q4_LABEL: (THREAT_CATEGORY, ["T1535"]),
}


def _load_hunts() -> list[dict[str, Any]]:
    with open(YAML_PATH, encoding="utf-8") as fh:
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


@pytest.fixture()
def phase6_db(tmp_path: pathlib.Path) -> str:
    db_path = tmp_path / "phase6_test.db"
    conn = duckdb.connect(str(db_path))
    conn.execute("""
        CREATE TABLE cloudtrail_events (
            event_time               TIMESTAMP,
            event_name               VARCHAR,
            event_source             VARCHAR,
            aws_region               VARCHAR,
            source_ip_address        VARCHAR,
            user_identity_arn        VARCHAR,
            request_parameters       VARCHAR,
            additional_event_data    VARCHAR,
            error_code               VARCHAR,
            read_only                BOOLEAN
        )
    """)

    def insert(
        event_name: str,
        event_source: str,
        request_parameters: str = "{}",
        aws_region: str = "us-east-1",
        when: str = "2024-06-10 10:00:00",
        arn: str = "arn:aws:iam::111111111111:user/attacker",
        read_only: bool = False,
    ) -> None:
        conn.execute(
            """
            INSERT INTO cloudtrail_events
                (event_time, event_name, event_source, aws_region,
                 source_ip_address, user_identity_arn, request_parameters,
                 additional_event_data, error_code, read_only)
            VALUES (?, ?, ?, ?, '203.0.113.50', ?, ?, NULL, NULL, ?)
            """,
            [
                when,
                event_name,
                event_source,
                aws_region,
                arn,
                request_parameters,
                read_only,
            ],
        )

    # TC-Q1: WorkSpaces provisioning
    insert(
        "CreateWorkspaces",
        "workspaces.amazonaws.com",
        '{"workspaces":[{"directoryId":"d-123"}]}',
    )
    insert("CreateWorkspacesPool", "workspaces.amazonaws.com", "{}")
    # TC-Q2: support case closure
    insert("ResolveCase", "support.amazonaws.com", '{"caseId":"case-123"}')
    insert("AddCommunicationToCase", "support.amazonaws.com", '{"caseId":"case-123"}')
    # TC-Q3: cognito user pool manipulation
    insert(
        "UpdateUserPoolClient",
        "cognito-idp.amazonaws.com",
        '{"userPoolId":"us-east-1_abc","refreshTokenValidity":3650}',
    )
    insert(
        "AdminCreateUser",
        "cognito-idp.amazonaws.com",
        '{"userPoolId":"us-east-1_abc","username":"backdoor"}',
    )
    # TC-Q4: region history — us-east-1/us-west-2 have old activity;
    # ap-south-1 first appears only in the last day (the anomaly).
    insert(
        "RunInstances",
        "ec2.amazonaws.com",
        when="2024-01-01 09:00:00",
        aws_region="us-east-1",
    )
    insert(
        "RunInstances",
        "ec2.amazonaws.com",
        when="2024-01-02 09:00:00",
        aws_region="us-west-2",
    )
    insert(
        "CreateFunction",
        "lambda.amazonaws.com",
        when="2024-06-10 12:00:00",
        aws_region="ap-south-1",
    )
    # a second recent event in an already-seen region must NOT be flagged
    insert(
        "RunInstances",
        "ec2.amazonaws.com",
        when="2024-06-10 12:30:00",
        aws_region="us-east-1",
    )
    # TC-Q5: Organizations extension
    insert("LeaveOrganization", "organizations.amazonaws.com", "{}")
    insert("AcceptHandshake", "organizations.amazonaws.com", '{"handshakeId":"h-123"}')
    # TC-Q6: Lambda Function URL exposure
    insert(
        "CreateFunctionUrlConfig",
        "lambda.amazonaws.com",
        '{"functionName":"backdoor","authType":"NONE"}',
    )

    conn.close()
    return str(db_path)


# ---------------------------------------------------------------------------
# Schema — new hunts exist with expected category / techniques
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("label", list(NEW_HUNTS))
def test_new_hunt_schema(label):
    hunt = get_hunt(label)
    category, tids = NEW_HUNTS[label]
    assert hunt["category"] == category
    assert hunt.get("sql", "").strip()
    assert hunt.get("prompt", "").strip()
    assert hunt.get("description", "").strip()
    assert [t["tid"] for t in hunt.get("techniques", [])] == tids


# ---------------------------------------------------------------------------
# Detection — new hunts
# ---------------------------------------------------------------------------


def test_workspaces_hijacking_detects_creation(phase6_db):
    rows = _run_sql(phase6_db, get_builtin_sql(Q1_LABEL))
    names = {r["event_name"] for r in rows}
    assert {"CreateWorkspaces", "CreateWorkspacesPool"} <= names


def test_support_case_manipulation_detects_resolve(phase6_db):
    rows = _run_sql(phase6_db, get_builtin_sql(Q2_LABEL))
    names = {r["event_name"] for r in rows}
    assert "ResolveCase" in names
    assert "AddCommunicationToCase" in names


def test_cognito_user_pool_manipulation_detects_client_update(phase6_db):
    rows = _run_sql(phase6_db, get_builtin_sql(Q3_LABEL))
    names = {r["event_name"] for r in rows}
    assert {"UpdateUserPoolClient", "AdminCreateUser"} <= names


def test_first_seen_region_flags_only_new_region(phase6_db):
    rows = _run_sql(phase6_db, get_builtin_sql(Q4_LABEL))
    regions = {r["aws_region"] for r in rows}
    assert regions == {"ap-south-1"}


# ---------------------------------------------------------------------------
# Extensions
# ---------------------------------------------------------------------------


def test_org_hunt_declares_leave_and_invite_techniques():
    tids = [t["tid"] for t in get_hunt(ORG_LABEL).get("techniques", [])]
    assert "T1666.A002" in tids
    assert "T1666.A003" in tids


def test_org_hunt_detects_leave_and_handshake(phase6_db):
    rows = _run_sql(phase6_db, get_builtin_sql(ORG_LABEL))
    names = {r["event_name"] for r in rows}
    assert "LeaveOrganization" in names
    assert "AcceptHandshake" in names


def test_lambda_hunt_declares_invoke_technique():
    tids = [t["tid"] for t in get_hunt(LAMBDA_LABEL).get("techniques", [])]
    assert "T1648.A001" in tids


def test_lambda_hunt_detects_function_url(phase6_db):
    rows = _run_sql(phase6_db, get_builtin_sql(LAMBDA_LABEL))
    names = {r["event_name"] for r in rows}
    assert "CreateFunctionUrlConfig" in names


def test_phase6_new_hunts_pass_query_validation(phase6_db):
    from query import validate_query

    conn = duckdb.connect(phase6_db, read_only=True)
    try:
        for label in list(NEW_HUNTS) + [ORG_LABEL, LAMBDA_LABEL]:
            validate_query(conn, get_builtin_sql(label))
    finally:
        conn.close()
