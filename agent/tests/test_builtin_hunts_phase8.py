"""Phase 8 — hunts for the gaps the AWS incident response playbooks exposed.

Twenty-four hunts covering what ``builtin_hunts.yaml`` could not answer:

  Identity (9)  role chaining, session-credential tracing, AssumeRole target
                accounts and fan-in, GetCallerIdentity recon, federated console
                logins, and the three Identity Center paths the playbook grades
                HIGH/CRITICAL.
  Insider (5)   off-hours activity, self-service privilege escalation, per-
                principal daily volume deviation, resource creation outside the
                normal regions, and high-volume API use — IRP-InsiderThreat is
                the most concrete playbook upstream and had no coverage at all.
  Data (3)      access-scope quantification for breach notification, cross-
                account object copies, presigned-URL generation.
  AgentCore (5) token vault, gateway authorization, memory integrity, sandbox
                network-mode drift, observability tampering.  Every API name
                below was confirmed against the AgentCore control-plane and
                data-plane API references; both surfaces log under the single
                event source ``bedrock-agentcore.amazonaws.com``.
  Other (2)     the ransomware kill-chain correlation and DDoS-protection
                weakening.
"""

from __future__ import annotations

import pathlib
from typing import Any

import duckdb
import pytest
import yaml

AGENT_DIR = pathlib.Path(__file__).parent.parent
YAML_PATH = AGENT_DIR / "builtin_hunts.yaml"

IDENTITY = "🔑 Identity & Access"
THREAT = "🕵 Threat Patterns"
DATA = "🪣 Data & Storage"
AI = "🤖 AI & LLM Abuse"
DETECTION = "🛡 Detection & Response"
NETWORK = "🌐 Network & Infrastructure"

# label -> (category, severity, playbook name or None)
NEW_HUNTS: dict[str, tuple[str, str, str | None]] = {
    "🔗 Role Chaining (Session → Role)": (IDENTITY, "P2", "IRP-STSTokenAbuse"),
    "🎫 Session Credential Trace": (IDENTITY, "P2", "IRP-STSTokenAbuse"),
    "🌐 AssumeRole Target Account (roleArn)": (IDENTITY, "P2", "IRP-STSTokenAbuse"),
    "📊 AssumeRole Fan-In by Target Role": (IDENTITY, "P3", "IRP-STSTokenAbuse"),
    "🔍 GetCallerIdentity Reconnaissance": (IDENTITY, "P3", "IRP-CredCompromise"),
    "🪪 Federated Console Logins": (IDENTITY, "P2", "IRP-FederatedAccessAbuse"),
    "🎟 Identity Center Permission Set Grants": (
        IDENTITY,
        "P1",
        "IRP-IdentityCenterCompromise",
    ),
    "🧑 Identity Store User & Group Creation": (
        IDENTITY,
        "P2",
        "IRP-IdentityCenterCompromise",
    ),
    "👑 Delegated Administrator Registration": (
        IDENTITY,
        "P1",
        "IRP-IdentityCenterCompromise",
    ),
    "🌙 Off-Hours Activity": (THREAT, "P3", "IRP-InsiderThreat"),
    "🪞 Self-Service Privilege Escalation": (THREAT, "P1", "IRP-InsiderThreat"),
    "📈 Principal Daily Volume Deviation": (THREAT, "P3", "IRP-InsiderThreat"),
    "🗺 Resource Creation Outside Normal Regions": (THREAT, "P3", "IRP-InsiderThreat"),
    "📞 High-Volume API Calls per Principal": (THREAT, "P3", "IRP-InsiderThreat"),
    "📐 Data Access Scope (Breach Notification)": (
        DATA,
        "P2",
        "IRP-PersonalDataBreach",
    ),
    "📤 Cross-Account Object Copy": (DATA, "P2", "IRP-PersonalDataBreach"),
    "🔗 Presigned URL Generation": (DATA, "P3", "IRP-InsiderThreat"),
    "🔑 AgentCore Token Vault Abuse": (AI, "P1", "IRP-AgentCoreIdentityCompromise"),
    "🚪 AgentCore Gateway Authorization Bypass": (
        AI,
        "P1",
        "IRP-AgentCoreAuthorizationBypass",
    ),
    "🧠 AgentCore Memory Integrity": (AI, "P2", "IRP-AgentCoreAgentIntegrity"),
    "📦 AgentCore Sandbox Network Mode Drift": (AI, "P2", "IRP-AgentCoreToolAbuse"),
    "🙈 AgentCore Observability Tampering": (
        AI,
        "P1",
        "IRP-AgentCoreObservabilityTampering",
    ),
    "⛓ Ransomware Kill-Chain Sequence": (DETECTION, "P1", "IRP-Ransomware"),
    "🛡 DDoS Protection Weakening": (NETWORK, "P2", "IRP-DoS"),
}


def _load() -> list[dict[str, Any]]:
    with open(YAML_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def get_hunt(label: str) -> dict[str, Any]:
    for hunt in _load():
        if hunt.get("label") == label:
            return hunt
    raise ValueError(f"No builtin hunt found with label: {label!r}")


def get_builtin_sql(label: str) -> str:
    sql = get_hunt(label).get("sql")
    assert sql, f"Hunt '{label}' found but has no 'sql' field"
    return sql


def _run(db_path: str, sql: str) -> list[dict]:
    conn = duckdb.connect(db_path, read_only=True)
    try:
        return conn.execute(sql).fetchdf().to_dict(orient="records")
    finally:
        conn.close()


def _values(rows: list[dict]) -> str:
    """All cell values of a result set flattened into one searchable string."""
    return " ".join(str(v) for row in rows for v in row.values())


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture()
def phase8_db(tmp_path: pathlib.Path) -> str:
    db_path = tmp_path / "phase8_test.db"
    conn = duckdb.connect(str(db_path))
    conn.execute("""
        CREATE TABLE cloudtrail_events (
            event_time                  TIMESTAMP,
            event_name                  VARCHAR,
            event_source                VARCHAR,
            aws_region                  VARCHAR,
            source_ip_address           VARCHAR,
            user_agent                  VARCHAR,
            user_identity_type          VARCHAR,
            user_identity_arn           VARCHAR,
            user_identity_account_id    VARCHAR,
            user_identity_access_key_id VARCHAR,
            user_identity_user_name     VARCHAR,
            session_issuer_arn          VARCHAR,
            session_mfa_authenticated   VARCHAR,
            request_parameters          VARCHAR,
            response_elements           VARCHAR,
            additional_event_data       VARCHAR,
            recipient_account_id        VARCHAR,
            error_code                  VARCHAR,
            read_only                   BOOLEAN,
            geo_country_code            VARCHAR,
            geo_city                    VARCHAR,
            geo_org                     VARCHAR
        )
    """)

    def insert(
        event_name: str,
        event_source: str,
        *,
        when: str = "2024-06-10 10:00:00",
        arn: str = "arn:aws:iam::111111111111:user/alice",
        identity_type: str = "IAMUser",
        region: str = "us-east-1",
        params: str = "{}",
        access_key: str = "AKIAEXAMPLE1",
        issuer: str | None = None,
        user_name: str | None = None,
        account: str = "111111111111",
        recipient: str = "111111111111",
        ip: str = "203.0.113.50",
        aed: str | None = None,
        read_only: bool = False,
        error: str | None = None,
        mfa: str = "false",
    ) -> None:
        conn.execute(
            """
            INSERT INTO cloudtrail_events VALUES
                (?, ?, ?, ?, ?, 'aws-cli/2.0', ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?,
                 ?, ?, ?, 'NL', 'Amsterdam', 'Example Hosting BV')
            """,
            [
                when,
                event_name,
                event_source,
                region,
                ip,
                identity_type,
                arn,
                account,
                access_key,
                user_name,
                issuer,
                mfa,
                params,
                aed,
                recipient,
                error,
                read_only,
            ],
        )

    # --- role chaining: an assumed-role session assuming a further role -----
    insert(
        "AssumeRole",
        "sts.amazonaws.com",
        identity_type="AssumedRole",
        arn="arn:aws:sts::111111111111:assumed-role/AppRole/i-0abc",
        issuer="arn:aws:iam::111111111111:role/AppRole",
        access_key="ASIACHAIN0001",
        params='{"roleArn":"arn:aws:iam::222222222222:role/DataRole",'
        '"roleSessionName":"pivot","durationSeconds":3600}',
        when="2024-06-10 01:00:00",
    )
    # A plain user assuming a role — same event, not a chain hop.
    insert(
        "AssumeRole",
        "sts.amazonaws.com",
        params='{"roleArn":"arn:aws:iam::111111111111:role/DeployRole"}',
        when="2024-06-10 01:05:00",
    )
    # --- session credential trace: one ASIA key doing several things -------
    for i, name in enumerate(("ListBuckets", "GetObject", "PutBucketPolicy")):
        insert(
            name,
            "s3.amazonaws.com",
            identity_type="AssumedRole",
            arn="arn:aws:sts::111111111111:assumed-role/DataRole/pivot",
            access_key="ASIATRACE0001",
            when=f"2024-06-10 02:{i:02d}:00",
            params='{"bucketName":"pii-archive"}',
        )
    # --- GetCallerIdentity recon -------------------------------------------
    insert(
        "GetCallerIdentity",
        "sts.amazonaws.com",
        arn="arn:aws:iam::111111111111:user/stolen",
        ip="198.51.100.9",
        when="2024-06-10 03:00:00",
        read_only=True,
    )
    insert(
        "GetCallerIdentity",
        "sts.amazonaws.com",
        ip="AWS Internal",
        when="2024-06-10 03:01:00",
        read_only=True,
    )
    # --- federated console login -------------------------------------------
    insert(
        "ConsoleLogin",
        "signin.amazonaws.com",
        arn="arn:aws:sts::111111111111:federated-user/bob",
        identity_type="FederatedUser",
        aed='{"MFAUsed":"No","federatedProvider":"CorpSSO"}',
        when="2024-06-10 04:00:00",
    )
    insert(
        "ConsoleLogin",
        "signin.amazonaws.com",
        aed='{"MFAUsed":"Yes"}',
        when="2024-06-10 04:05:00",
    )
    # --- Identity Center ----------------------------------------------------
    insert(
        "CreatePermissionSet",
        "sso.amazonaws.com",
        params='{"name":"BackdoorAdmin","instanceArn":"arn:aws:sso:::instance/ssoins-1"}',
        when="2024-06-10 05:00:00",
    )
    insert(
        "AttachManagedPolicyToPermissionSet",
        "sso.amazonaws.com",
        params='{"managedPolicyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}',
        when="2024-06-10 05:01:00",
    )
    insert(
        "CreateAccountAssignment",
        "sso.amazonaws.com",
        params='{"targetId":"333333333333","principalId":"user-1"}',
        when="2024-06-10 05:02:00",
    )
    insert(
        "CreateGroupMembership",
        "identitystore.amazonaws.com",
        params='{"identityStoreId":"d-1","groupId":"g-1"}',
        when="2024-06-10 05:03:00",
    )
    insert(
        "CreateUser",
        "identitystore.amazonaws.com",
        params='{"identityStoreId":"d-1","userName":"ghost"}',
        when="2024-06-10 05:04:00",
    )
    insert(
        "RegisterDelegatedAdministrator",
        "organizations.amazonaws.com",
        params='{"accountId":"444444444444","servicePrincipal":"sso.amazonaws.com"}',
        when="2024-06-10 05:05:00",
    )
    # --- insider: off-hours + self-service escalation ------------------------
    insert(
        "GetObject",
        "s3.amazonaws.com",
        arn="arn:aws:iam::111111111111:user/mallory",
        when="2024-06-11 23:30:00",
        read_only=True,
        params='{"bucketName":"hr-records","key":"salaries.csv"}',
    )
    insert(
        "AttachUserPolicy",
        "iam.amazonaws.com",
        arn="arn:aws:iam::111111111111:user/mallory",
        user_name="mallory",
        params='{"userName":"mallory",'
        '"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess"}',
        when="2024-06-11 23:35:00",
    )
    # An admin granting someone *else* rights — not self-service.
    insert(
        "AttachUserPolicy",
        "iam.amazonaws.com",
        arn="arn:aws:iam::111111111111:user/admin",
        user_name="admin",
        params='{"userName":"newhire",'
        '"policyArn":"arn:aws:iam::aws:policy/ReadOnlyAccess"}',
        when="2024-06-11 09:00:00",
    )
    # --- insider: unusual region + volume ------------------------------------
    for i in range(60):
        insert(
            "DescribeInstances",
            "ec2.amazonaws.com",
            arn="arn:aws:iam::111111111111:user/mallory",
            when=f"2024-06-12 09:{i % 60:02d}:00",
            read_only=True,
        )
    insert(
        "RunInstances",
        "ec2.amazonaws.com",
        arn="arn:aws:iam::111111111111:user/mallory",
        region="ap-south-1",
        when="2024-06-12 10:00:00",
        params='{"instanceType":"p4d.24xlarge"}',
    )
    # --- data: scope, cross-account copy, presigned URL ----------------------
    for i in range(5):
        insert(
            "GetObject",
            "s3.amazonaws.com",
            arn="arn:aws:iam::111111111111:user/mallory",
            when=f"2024-06-13 08:{i:02d}:00",
            read_only=True,
            params=f'{{"bucketName":"pii-archive","key":"customers/{i}.csv"}}',
        )
    insert(
        "CopyObject",
        "s3.amazonaws.com",
        arn="arn:aws:iam::111111111111:user/mallory",
        params='{"bucketName":"external-drop","key":"copy.csv",'
        '"x-amz-copy-source":"/pii-archive/customers/0.csv"}',
        recipient="999999999999",
        when="2024-06-13 08:30:00",
    )
    insert(
        "CreatePresignedNotebookInstanceUrl",
        "sagemaker.amazonaws.com",
        arn="arn:aws:iam::111111111111:user/mallory",
        params='{"notebookInstanceName":"research"}',
        when="2024-06-13 08:40:00",
    )
    # --- AgentCore -----------------------------------------------------------
    for i in range(3):
        insert(
            "GetResourceOauth2Token",
            "bedrock-agentcore.amazonaws.com",
            arn="arn:aws:iam::111111111111:role/AgentRuntime",
            params='{"workloadName":"invoice-agent"}',
            when=f"2024-06-14 07:{i:02d}:00",
        )
    insert(
        "GetWorkloadAccessTokenForUserId",
        "bedrock-agentcore.amazonaws.com",
        params='{"workloadName":"invoice-agent","userId":"u-1"}',
        when="2024-06-14 07:10:00",
    )
    insert(
        "SetTokenVaultCMK",
        "bedrock-agentcore.amazonaws.com",
        params='{"tokenVaultId":"default","kmsConfiguration":{"keyType":"CustomerManagedKey"}}',
        when="2024-06-14 07:15:00",
    )
    insert(
        "UpdateGateway",
        "bedrock-agentcore.amazonaws.com",
        params='{"gatewayIdentifier":"gw-1","policyEngineConfiguration":'
        '{"cedarConfiguration":{"mode":"LOG_ONLY"}}}',
        when="2024-06-14 08:00:00",
    )
    insert(
        "CreateGatewayTarget",
        "bedrock-agentcore.amazonaws.com",
        params='{"gatewayIdentifier":"gw-1","targetConfiguration":'
        '{"mcp":{"lambda":{"lambdaArn":"arn:aws:lambda:us-east-1:999999999999:function:evil"}}}}',
        when="2024-06-14 08:05:00",
    )
    insert(
        "UpdateMemory",
        "bedrock-agentcore.amazonaws.com",
        params='{"memoryId":"mem-1","streamDeliveryResources":'
        '["arn:aws:kinesis:us-east-1:999999999999:stream/exfil"]}',
        when="2024-06-14 09:00:00",
    )
    insert(
        "DeleteCodeInterpreter",
        "bedrock-agentcore.amazonaws.com",
        params='{"codeInterpreterId":"ci-1"}',
        when="2024-06-14 10:00:00",
    )
    insert(
        "CreateCodeInterpreter",
        "bedrock-agentcore.amazonaws.com",
        params='{"name":"ci-1","networkConfiguration":{"networkMode":"PUBLIC"}}',
        when="2024-06-14 10:02:00",
    )
    insert(
        "CreateEvaluator",
        "bedrock-agentcore.amazonaws.com",
        params='{"name":"leak-evaluator"}',
        when="2024-06-14 11:00:00",
    )
    insert(
        "UpdateSamplingRule",
        "xray.amazonaws.com",
        params='{"samplingRuleUpdate":{"FixedRate":0}}',
        when="2024-06-14 11:05:00",
    )
    # --- ransomware kill chain (one principal, one day) ----------------------
    insert(
        "DeleteBackupVault",
        "backup.amazonaws.com",
        arn="arn:aws:iam::111111111111:user/ransom",
        params='{"backupVaultName":"prod-vault"}',
        when="2024-06-15 01:00:00",
    )
    insert(
        "PutBucketVersioning",
        "s3.amazonaws.com",
        arn="arn:aws:iam::111111111111:user/ransom",
        params='{"bucketName":"prod-data","VersioningConfiguration":{"Status":"Suspended"}}',
        when="2024-06-15 01:30:00",
    )
    insert(
        "DeleteObjects",
        "s3.amazonaws.com",
        arn="arn:aws:iam::111111111111:user/ransom",
        params='{"bucketName":"prod-data"}',
        when="2024-06-15 02:00:00",
    )
    # A principal that only did one of the three — must not be reported.
    insert(
        "DeleteObjects",
        "s3.amazonaws.com",
        arn="arn:aws:iam::111111111111:user/janitor",
        params='{"bucketName":"tmp-data"}',
        when="2024-06-15 03:00:00",
    )
    # --- DDoS protection weakening -------------------------------------------
    insert(
        "UpdateWebACL",
        "wafv2.amazonaws.com",
        params='{"name":"prod-acl","defaultAction":{"Allow":{}}}',
        when="2024-06-16 01:00:00",
    )
    insert(
        "DeleteProtection",
        "shield.amazonaws.com",
        params='{"protectionId":"p-1"}',
        when="2024-06-16 01:05:00",
    )

    conn.close()
    return str(db_path)


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("label", sorted(NEW_HUNTS))
def test_hunt_exists_with_sql_and_prompt(label: str) -> None:
    hunt = get_hunt(label)
    assert hunt.get("sql", "").strip(), f"{label} has no SQL"
    assert hunt.get("prompt", "").strip(), f"{label} has no prompt"
    assert hunt.get("description", "").strip(), f"{label} has no description"


@pytest.mark.parametrize("label", sorted(NEW_HUNTS))
def test_hunt_metadata_matches_spec(label: str) -> None:
    category, severity, playbook = NEW_HUNTS[label]
    hunt = get_hunt(label)
    assert hunt["category"] == category
    assert hunt["severity"] == severity
    if playbook:
        assert hunt.get("playbook", {}).get("name") == playbook


@pytest.mark.parametrize("label", sorted(NEW_HUNTS))
def test_hunt_sql_runs(label: str, phase8_db: str) -> None:
    """Every hunt must at least bind and execute against the real schema."""
    _run(phase8_db, get_builtin_sql(label))


def test_total_hunt_count() -> None:
    """151 after phase 8, less the 15 folded into a neighbouring hunt.

    Phase 9 adds three more; see test_builtin_hunts_phase9.py.
    """
    assert len(_load()) == 139


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def test_role_chaining_reports_only_chained_hops(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("🔗 Role Chaining (Session → Role)"))
    joined = _values(rows)
    assert "arn:aws:iam::111111111111:role/AppRole" in joined
    assert "arn:aws:iam::222222222222:role/DataRole" in joined
    assert "DeployRole" not in joined, "a plain user's AssumeRole is not a chain hop"


def test_session_trace_groups_by_access_key(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("🎫 Session Credential Trace"))
    traced = [r for r in rows if "ASIATRACE0001" in _values([r])]
    assert traced, "the ASIA session was not traced"
    assert "3" in _values(traced), "the session's three calls were not counted"
    assert not any(
        "AKIAEXAMPLE1" in _values([r]) for r in rows
    ), "long-lived AKIA keys are not sessions"


def test_assume_role_target_account_is_extracted(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("🌐 AssumeRole Target Account (roleArn)"))
    joined = _values(rows)
    assert "222222222222" in joined, "target account not extracted from roleArn"
    assert "DeployRole" not in joined, "same-account assume is not cross-account"


def test_assume_role_fan_in_aggregates(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("📊 AssumeRole Fan-In by Target Role"))
    assert rows
    assert "DataRole" in _values(rows)


def test_get_caller_identity_excludes_aws_internal(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("🔍 GetCallerIdentity Reconnaissance"))
    joined = _values(rows)
    assert "198.51.100.9" in joined
    assert "AWS Internal" not in joined


def test_federated_console_login_shows_provider(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("🪪 Federated Console Logins"))
    joined = _values(rows)
    assert "CorpSSO" in joined
    assert len(rows) == 1, "a non-federated ConsoleLogin was included"


def test_permission_set_grants_are_isolated(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("🎟 Identity Center Permission Set Grants"))
    names = {r["event_name"] for r in rows}
    assert {
        "CreatePermissionSet",
        "AttachManagedPolicyToPermissionSet",
        "CreateAccountAssignment",
    } <= names
    assert "CreateUser" not in names, "identity-store events belong to their own hunt"


def test_identity_store_creation_hunt(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("🧑 Identity Store User & Group Creation"))
    names = {r["event_name"] for r in rows}
    assert {"CreateUser", "CreateGroupMembership"} <= names


def test_delegated_administrator_hunt(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("👑 Delegated Administrator Registration"))
    assert "RegisterDelegatedAdministrator" in _values(rows)
    assert "444444444444" in _values(rows)


# ---------------------------------------------------------------------------
# Insider threat
# ---------------------------------------------------------------------------


def test_off_hours_activity_uses_the_utc_night_window(phase8_db: str) -> None:
    """The window is 22:00-06:00 UTC — mallory reads HR records at 23:30."""
    sql = get_builtin_sql("🌙 Off-Hours Activity")
    assert "hour" in sql.lower(), "the hunt must filter on hour of day"
    rows = _run(phase8_db, sql)
    assert "mallory" in _values(rows)


def test_self_service_escalation_requires_caller_equals_target(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("🪞 Self-Service Privilege Escalation"))
    joined = _values(rows)
    assert "mallory" in joined
    assert (
        "newhire" not in joined
    ), "granting rights to someone else is not self-service"


def test_daily_volume_deviation_reports_per_day_counts(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("📈 Principal Daily Volume Deviation"))
    assert rows
    assert "mallory" in _values(rows)


def test_unusual_region_creation(phase8_db: str) -> None:
    rows = _run(
        phase8_db, get_builtin_sql("🗺 Resource Creation Outside Normal Regions")
    )
    joined = _values(rows)
    assert "ap-south-1" in joined
    assert "RunInstances" in joined


def test_high_volume_api_calls(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("📞 High-Volume API Calls per Principal"))
    joined = _values(rows)
    assert "DescribeInstances" in joined
    assert "RunInstances" not in joined, "a single call is not high volume"


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


def test_data_access_scope_counts_objects_and_buckets(phase8_db: str) -> None:
    sql = get_builtin_sql("📐 Data Access Scope (Breach Notification)")
    rows = _run(phase8_db, sql)
    assert rows
    joined = _values(rows)
    assert "pii-archive" in joined or "1" in joined
    assert "approx_count_distinct" in sql.lower() or "count(distinct" in sql.lower()


def test_cross_account_object_copy(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("📤 Cross-Account Object Copy"))
    joined = _values(rows)
    assert "external-drop" in joined
    assert "pii-archive" in joined, "the copy source must be shown"


def test_presigned_url_generation(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("🔗 Presigned URL Generation"))
    assert "CreatePresignedNotebookInstanceUrl" in _values(rows)


# ---------------------------------------------------------------------------
# AgentCore
# ---------------------------------------------------------------------------


def test_token_vault_abuse_aggregates_issuance(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("🔑 AgentCore Token Vault Abuse"))
    joined = _values(rows)
    assert "GetResourceOauth2Token" in joined or "3" in joined
    assert "AgentRuntime" in joined


def test_gateway_authorization_bypass_flags_log_only(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("🚪 AgentCore Gateway Authorization Bypass"))
    joined = _values(rows)
    assert "LOG_ONLY" in joined, "the Cedar mode downgrade must be surfaced"
    assert "999999999999" in joined, "the foreign target ARN must be surfaced"


def test_memory_integrity_flags_foreign_stream(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("🧠 AgentCore Memory Integrity"))
    joined = _values(rows)
    assert "UpdateMemory" in joined
    assert "999999999999" in joined


def test_sandbox_network_mode_drift(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("📦 AgentCore Sandbox Network Mode Drift"))
    joined = _values(rows)
    assert "CreateCodeInterpreter" in joined
    assert "PUBLIC" in joined


def test_agentcore_observability_tampering(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("🙈 AgentCore Observability Tampering"))
    names = {r["event_name"] for r in rows}
    assert "CreateEvaluator" in names
    assert "UpdateSamplingRule" in names


# ---------------------------------------------------------------------------
# Correlation hunts
# ---------------------------------------------------------------------------


def test_ransomware_kill_chain_needs_all_three_stages(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("⛓ Ransomware Kill-Chain Sequence"))
    joined = _values(rows)
    assert "ransom" in joined, "the principal that did all three stages is missing"
    assert "janitor" not in joined, "one stage alone is not a kill chain"


def test_ddos_protection_weakening(phase8_db: str) -> None:
    rows = _run(phase8_db, get_builtin_sql("🛡 DDoS Protection Weakening"))
    names = {r["event_name"] for r in rows}
    assert {"UpdateWebACL", "DeleteProtection"} <= names
