"""Phase 4 — LLMjacking detection tests for builtin_hunts.yaml.

Tests LJ-1 through LJ-6 in the Red-Green-Refactor cycle:
  LJ-1: Bedrock Model Invocation Spike
  LJ-2: Bedrock Model Access Enablement
  LJ-3: Bedrock Invocation Logging Tampering
  LJ-4: Bedrock Reconnaissance Sweep
  LJ-5: Failed Bedrock Invocations
  LJ-6: Bedrock Callers & Origins

LLMjacking = attackers using stolen AWS credentials to run LLM inference
on Amazon Bedrock at the victim's expense, typically resold through
OAI-style reverse proxies.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any

import duckdb
import pytest
import yaml

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

YAML_PATH = pathlib.Path(__file__).parent.parent / "builtin_hunts.yaml"

LJ1_LABEL = "\U0001f916 Bedrock Model Invocation Spike"
LJ2_LABEL = "\U0001f513 Bedrock Model Access Enablement"
LJ3_LABEL = "\U0001f648 Bedrock Invocation Logging Tampering"
LJ4_LABEL = "\U0001f9ed Bedrock Reconnaissance Sweep"
LJ5_LABEL = "⛔ Failed Bedrock Invocations"
LJ6_LABEL = "\U0001f30d Bedrock Callers & Origins"

PHASE4_LABELS = [
    LJ1_LABEL,
    LJ2_LABEL,
    LJ3_LABEL,
    LJ4_LABEL,
    LJ5_LABEL,
    LJ6_LABEL,
]

AI_CATEGORY = "\U0001f916 AI & LLM Abuse"


def _load_hunts() -> list[dict[str, Any]]:
    with open(YAML_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def get_hunt(label: str) -> dict[str, Any]:
    """Return the full hunt entry for the given label."""
    hunts = _load_hunts()
    for hunt in hunts:
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
# Fixture — DuckDB pre-loaded with Phase-4 (LLMjacking) test events
# ---------------------------------------------------------------------------


@pytest.fixture()
def phase4_db(tmp_path: pathlib.Path) -> str:
    """Temporary DuckDB pre-loaded with LLMjacking test events."""
    db_path = tmp_path / "phase4_test.db"
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

    # LJ-1: invocation spike — 60 InvokeModel calls in one hour by one caller.
    # Real CloudTrail marks InvokeModel as readOnly=true, so hunts must NOT
    # rely on read_only=false for invocation events.
    conn.execute("""
        INSERT INTO cloudtrail_events
            (event_time, event_name, event_source, aws_region,
             user_identity_arn, source_ip_address, user_agent,
             request_parameters, error_code, read_only,
             recipient_account_id, user_identity_account_id,
             geo_country_code, geo_org)
        SELECT
            TIMESTAMP '2024-06-01 10:00:00' + INTERVAL (t.i) SECOND,
            'InvokeModel', 'bedrock.amazonaws.com', 'us-east-1',
            'arn:aws:iam::111111111111:user/llmjacker', '203.0.113.50',
            'Boto3/1.34.0 Python/3.11',
            '{"modelId":"anthropic.claude-3-5-sonnet-20241022-v2:0"}',
            NULL, true, '111111111111', '111111111111',
            'RU', 'EVIL-HOSTING-ASN'
        FROM range(60) AS t(i)
    """)

    conn.execute("""
        INSERT INTO cloudtrail_events
            (event_time, event_name, event_source, aws_region,
             user_identity_arn, source_ip_address, user_agent,
             request_parameters, response_elements, error_code, read_only,
             recipient_account_id, user_identity_account_id,
             geo_country_code, geo_org)
        VALUES
        -- Benign baseline: 5 low-volume invocations by a legitimate user
        ('2024-06-01 09:00:00', 'InvokeModel', 'bedrock.amazonaws.com', 'ap-northeast-1',
         'arn:aws:iam::111111111111:user/data-scientist', '10.0.0.20', 'Boto3/1.34.0',
         '{"modelId":"amazon.titan-text-express-v1"}', NULL, NULL, true,
         '111111111111', '111111111111', 'JP', 'AMAZON-02'),
        ('2024-06-01 09:05:00', 'InvokeModel', 'bedrock.amazonaws.com', 'ap-northeast-1',
         'arn:aws:iam::111111111111:user/data-scientist', '10.0.0.20', 'Boto3/1.34.0',
         '{"modelId":"amazon.titan-text-express-v1"}', NULL, NULL, true,
         '111111111111', '111111111111', 'JP', 'AMAZON-02'),
        ('2024-06-01 09:10:00', 'InvokeModel', 'bedrock.amazonaws.com', 'ap-northeast-1',
         'arn:aws:iam::111111111111:user/data-scientist', '10.0.0.20', 'Boto3/1.34.0',
         '{"modelId":"amazon.titan-text-express-v1"}', NULL, NULL, true,
         '111111111111', '111111111111', 'JP', 'AMAZON-02'),
        ('2024-06-01 09:15:00', 'InvokeModel', 'bedrock.amazonaws.com', 'ap-northeast-1',
         'arn:aws:iam::111111111111:user/data-scientist', '10.0.0.20', 'Boto3/1.34.0',
         '{"modelId":"amazon.titan-text-express-v1"}', NULL, NULL, true,
         '111111111111', '111111111111', 'JP', 'AMAZON-02'),
        ('2024-06-01 09:20:00', 'InvokeModel', 'bedrock.amazonaws.com', 'ap-northeast-1',
         'arn:aws:iam::111111111111:user/data-scientist', '10.0.0.20', 'Boto3/1.34.0',
         '{"modelId":"amazon.titan-text-express-v1"}', NULL, NULL, true,
         '111111111111', '111111111111', 'JP', 'AMAZON-02'),

        -- LJ-2: model access enablement (canonical first write of LLMjacking)
        ('2024-06-02 02:00:00', 'PutUseCaseForModelAccess', 'bedrock.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/llmjacker', '203.0.113.50', 'Boto3/1.34.0',
         '{"formData":"<use-case-blob>"}', NULL, NULL, false,
         '111111111111', '111111111111', 'RU', 'EVIL-HOSTING-ASN'),
        ('2024-06-02 02:05:00', 'CreateFoundationModelAgreement', 'bedrock.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/llmjacker', '203.0.113.50', 'Boto3/1.34.0',
         '{"modelId":"anthropic.claude-3-5-sonnet-20241022-v2:0","offerToken":"<token>"}',
         NULL, NULL, false, '111111111111', '111111111111', 'RU', 'EVIL-HOSTING-ASN'),
        ('2024-06-02 02:10:00', 'PutFoundationModelEntitlement', 'bedrock.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/llmjacker', '203.0.113.50', 'Boto3/1.34.0',
         '{"modelId":"anthropic.claude-3-5-sonnet-20241022-v2:0"}', NULL, NULL, false,
         '111111111111', '111111111111', 'RU', 'EVIL-HOSTING-ASN'),

        -- LJ-3: invocation logging tampering + logging recon
        ('2024-06-03 03:00:00', 'GetModelInvocationLoggingConfiguration', 'bedrock.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/llmjacker', '203.0.113.50', 'Boto3/1.34.0',
         '{}', NULL, NULL, true,
         '111111111111', '111111111111', 'RU', 'EVIL-HOSTING-ASN'),
        ('2024-06-03 03:05:00', 'DeleteModelInvocationLoggingConfiguration', 'bedrock.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/llmjacker', '203.0.113.50', 'Boto3/1.34.0',
         '{}', NULL, NULL, false,
         '111111111111', '111111111111', 'RU', 'EVIL-HOSTING-ASN'),

        -- LJ-5: access-denied probing — 6 failed invokes by a key prober
        ('2024-06-04 04:00:00', 'InvokeModel', 'bedrock.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/key-prober', '198.51.100.77', 'python-requests/2.31',
         '{"modelId":"anthropic.claude-3-opus-20240229-v1:0"}', NULL, 'AccessDenied', true,
         '111111111111', '111111111111', 'US', 'PROXY-ASN'),
        ('2024-06-04 04:01:00', 'InvokeModel', 'bedrock.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/key-prober', '198.51.100.77', 'python-requests/2.31',
         '{"modelId":"anthropic.claude-3-5-sonnet-20241022-v2:0"}', NULL, 'AccessDenied', true,
         '111111111111', '111111111111', 'US', 'PROXY-ASN'),
        ('2024-06-04 04:02:00', 'InvokeModel', 'bedrock.amazonaws.com', 'us-west-2',
         'arn:aws:iam::111111111111:user/key-prober', '198.51.100.77', 'python-requests/2.31',
         '{"modelId":"anthropic.claude-3-opus-20240229-v1:0"}', NULL, 'AccessDenied', true,
         '111111111111', '111111111111', 'US', 'PROXY-ASN'),
        ('2024-06-04 04:03:00', 'InvokeModelWithResponseStream', 'bedrock.amazonaws.com', 'us-west-2',
         'arn:aws:iam::111111111111:user/key-prober', '198.51.100.77', 'python-requests/2.31',
         '{"modelId":"meta.llama3-70b-instruct-v1:0"}', NULL, 'AccessDenied', true,
         '111111111111', '111111111111', 'US', 'PROXY-ASN'),
        ('2024-06-04 04:04:00', 'Converse', 'bedrock.amazonaws.com', 'eu-west-1',
         'arn:aws:iam::111111111111:user/key-prober', '198.51.100.77', 'python-requests/2.31',
         '{"modelId":"anthropic.claude-3-haiku-20240307-v1:0"}', NULL, 'AccessDenied', true,
         '111111111111', '111111111111', 'US', 'PROXY-ASN'),
        ('2024-06-04 04:05:00', 'ConverseStream', 'bedrock.amazonaws.com', 'eu-west-1',
         'arn:aws:iam::111111111111:user/key-prober', '198.51.100.77', 'python-requests/2.31',
         '{"modelId":"mistral.mistral-large-2402-v1:0"}', NULL, 'ValidationException', true,
         '111111111111', '111111111111', 'US', 'PROXY-ASN'),

        -- Benign non-Bedrock baseline
        ('2024-06-01 20:00:00', 'DescribeInstances', 'ec2.amazonaws.com', 'us-east-1',
         'arn:aws:iam::111111111111:user/jenkins', '10.0.0.100', 'aws-cli/2.15',
         '{}', NULL, NULL, true,
         '111111111111', '111111111111', 'JP', 'AMAZON-02')
    """)

    # LJ-4: reconnaissance sweep — 12 read-only enumeration calls across
    # 3 regions within one hour by a single caller.
    conn.execute("""
        INSERT INTO cloudtrail_events
            (event_time, event_name, event_source, aws_region,
             user_identity_arn, source_ip_address, user_agent,
             request_parameters, error_code, read_only,
             recipient_account_id, user_identity_account_id,
             geo_country_code, geo_org)
        SELECT
            TIMESTAMP '2024-06-05 05:00:00' + INTERVAL (t.i) MINUTE,
            CASE t.i % 3
                WHEN 0 THEN 'ListFoundationModels'
                WHEN 1 THEN 'GetFoundationModelAvailability'
                ELSE        'ListProvisionedModelThroughputs'
            END,
            'bedrock.amazonaws.com',
            CASE t.i % 3
                WHEN 0 THEN 'us-east-1'
                WHEN 1 THEN 'us-west-2'
                ELSE        'eu-west-1'
            END,
            'arn:aws:iam::111111111111:user/llmjacker-recon', '203.0.113.60',
            'python-requests/2.31',
            '{}', NULL, true, '111111111111', '111111111111',
            'NL', 'VPN-EXIT-ASN'
        FROM range(12) AS t(i)
    """)

    # LJ-4 negative: 3 single-region ListFoundationModels calls by a
    # legitimate user must NOT be flagged.
    conn.execute("""
        INSERT INTO cloudtrail_events
            (event_time, event_name, event_source, aws_region,
             user_identity_arn, source_ip_address, user_agent,
             request_parameters, error_code, read_only,
             recipient_account_id, user_identity_account_id,
             geo_country_code, geo_org)
        SELECT
            TIMESTAMP '2024-06-05 08:00:00' + INTERVAL (t.i) MINUTE,
            'ListFoundationModels', 'bedrock.amazonaws.com', 'ap-northeast-1',
            'arn:aws:iam::111111111111:user/data-scientist', '10.0.0.20',
            'Boto3/1.34.0',
            '{}', NULL, true, '111111111111', '111111111111',
            'JP', 'AMAZON-02'
        FROM range(3) AS t(i)
    """)

    conn.close()
    return str(db_path)


# ---------------------------------------------------------------------------
# Structure: all LJ hunts exist under the AI & LLM Abuse category
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("label", PHASE4_LABELS)
def test_phase4_hunt_has_required_fields(label: str):
    """Every LJ hunt must have category, description, prompt, and sql."""
    hunt = get_hunt(label)
    assert hunt.get("category") == AI_CATEGORY
    assert len(hunt.get("description", "")) > 20
    assert len(hunt.get("prompt", "")) > 20
    assert len(hunt.get("sql", "")) > 10


def test_phase4_chart_hints():
    """LJ-1 is a time series; LJ-4/LJ-5 are bar charts over callers."""
    assert get_hunt(LJ1_LABEL)["chart"]["type"] == "timeseries"
    assert get_hunt(LJ4_LABEL)["chart"]["type"] == "bar"
    assert get_hunt(LJ5_LABEL)["chart"]["type"] == "bar"


# ---------------------------------------------------------------------------
# LJ-1: Bedrock Model Invocation Spike
# ---------------------------------------------------------------------------


def test_lj1_detects_invocation_spike(phase4_db: str):
    """LJ-1: 60 InvokeModel calls in one hour must be flagged with model id."""
    sql = get_builtin_sql(LJ1_LABEL)
    rows = _run_sql(phase4_db, sql)
    arns = [r["user_identity_arn"] for r in rows]
    assert "arn:aws:iam::111111111111:user/llmjacker" in arns
    spike = next(r for r in rows if r["user_identity_arn"].endswith("user/llmjacker"))
    assert spike["invocation_count"] >= 60
    assert "claude" in spike["model_id"]


def test_lj1_ignores_low_volume(phase4_db: str):
    """LJ-1: 5 invocations/hour by a legitimate user must not be flagged."""
    sql = get_builtin_sql(LJ1_LABEL)
    rows = _run_sql(phase4_db, sql)
    arns = [r["user_identity_arn"] for r in rows]
    assert "arn:aws:iam::111111111111:user/data-scientist" not in arns


# ---------------------------------------------------------------------------
# LJ-2: Bedrock Model Access Enablement
# ---------------------------------------------------------------------------


def test_lj2_detects_model_access_enablement(phase4_db: str):
    """LJ-2: self-enablement of foundation-model access must be detected."""
    sql = get_builtin_sql(LJ2_LABEL)
    rows = _run_sql(phase4_db, sql)
    names = [r["event_name"] for r in rows]
    assert "PutUseCaseForModelAccess" in names
    assert "CreateFoundationModelAgreement" in names
    assert "PutFoundationModelEntitlement" in names


def test_lj2_excludes_benign_events(phase4_db: str):
    """LJ-2: unrelated events (DescribeInstances, InvokeModel) are excluded."""
    sql = get_builtin_sql(LJ2_LABEL)
    rows = _run_sql(phase4_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DescribeInstances" not in names
    assert "InvokeModel" not in names


# ---------------------------------------------------------------------------
# LJ-3: Bedrock Invocation Logging Tampering
# ---------------------------------------------------------------------------


def test_lj3_detects_logging_tampering(phase4_db: str):
    """LJ-3: deleting the invocation logging configuration must be detected."""
    sql = get_builtin_sql(LJ3_LABEL)
    rows = _run_sql(phase4_db, sql)
    names = [r["event_name"] for r in rows]
    assert "DeleteModelInvocationLoggingConfiguration" in names


def test_lj3_detects_logging_recon(phase4_db: str):
    """LJ-3: attackers checking whether logging is enabled must be visible."""
    sql = get_builtin_sql(LJ3_LABEL)
    rows = _run_sql(phase4_db, sql)
    names = [r["event_name"] for r in rows]
    assert "GetModelInvocationLoggingConfiguration" in names


# ---------------------------------------------------------------------------
# LJ-4: Bedrock Reconnaissance Sweep
# ---------------------------------------------------------------------------


def test_lj4_detects_multi_region_recon(phase4_db: str):
    """LJ-4: 12 enumeration calls across 3 regions in 1h must be flagged."""
    sql = get_builtin_sql(LJ4_LABEL)
    rows = _run_sql(phase4_db, sql)
    arns = [r["user_identity_arn"] for r in rows]
    assert "arn:aws:iam::111111111111:user/llmjacker-recon" in arns
    recon = next(
        r for r in rows if r["user_identity_arn"].endswith("user/llmjacker-recon")
    )
    assert recon["recon_calls"] >= 12
    assert recon["distinct_regions"] >= 3


def test_lj4_ignores_single_region_low_volume(phase4_db: str):
    """LJ-4: 3 single-region ListFoundationModels calls are not flagged."""
    sql = get_builtin_sql(LJ4_LABEL)
    rows = _run_sql(phase4_db, sql)
    arns = [r["user_identity_arn"] for r in rows]
    assert "arn:aws:iam::111111111111:user/data-scientist" not in arns


# ---------------------------------------------------------------------------
# LJ-5: Failed Bedrock Invocations
# ---------------------------------------------------------------------------


def test_lj5_detects_access_denied_probing(phase4_db: str):
    """LJ-5: bursts of failed invokes (stolen-key testing) must be flagged."""
    sql = get_builtin_sql(LJ5_LABEL)
    rows = _run_sql(phase4_db, sql)
    arns = [r["user_identity_arn"] for r in rows]
    assert "arn:aws:iam::111111111111:user/key-prober" in arns
    prober = next(r for r in rows if r["user_identity_arn"].endswith("user/key-prober"))
    assert prober["failed_calls"] >= 6


def test_lj5_excludes_successful_invocations(phase4_db: str):
    """LJ-5: high-volume but successful invocations are not failures."""
    sql = get_builtin_sql(LJ5_LABEL)
    rows = _run_sql(phase4_db, sql)
    arns = [r["user_identity_arn"] for r in rows]
    assert "arn:aws:iam::111111111111:user/llmjacker" not in arns


# ---------------------------------------------------------------------------
# LJ-6: Bedrock Callers & Origins
# ---------------------------------------------------------------------------


def test_lj6_inventories_callers_with_geo(phase4_db: str):
    """LJ-6: every Bedrock caller appears with origin and model diversity."""
    sql = get_builtin_sql(LJ6_LABEL)
    rows = _run_sql(phase4_db, sql)
    arns = {r["user_identity_arn"] for r in rows}
    assert "arn:aws:iam::111111111111:user/llmjacker" in arns
    assert "arn:aws:iam::111111111111:user/data-scientist" in arns
    jacker = next(r for r in rows if r["user_identity_arn"].endswith("user/llmjacker"))
    assert jacker["geo_country_code"] == "RU"
    assert jacker["first_seen"] is not None
    assert jacker["last_seen"] is not None
    assert jacker["distinct_models"] >= 1


def test_lj6_excludes_non_bedrock_callers(phase4_db: str):
    """LJ-6: callers who never touched Bedrock must not appear."""
    sql = get_builtin_sql(LJ6_LABEL)
    rows = _run_sql(phase4_db, sql)
    arns = {r["user_identity_arn"] for r in rows}
    assert "arn:aws:iam::111111111111:user/jenkins" not in arns


# ---------------------------------------------------------------------------
# Cross-cutting: SQL safety + DuckDB EXPLAIN validity
# ---------------------------------------------------------------------------

FORBIDDEN_SQL = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b", re.IGNORECASE
)


@pytest.mark.parametrize("label", PHASE4_LABELS)
def test_phase4_sql_is_read_only(label: str):
    """All LJ SQL must pass the write-keyword blocklist."""
    sql = get_builtin_sql(label)
    match = FORBIDDEN_SQL.search(sql)
    assert match is None, f"Forbidden keyword {match.group(0)!r} in '{label}'"


@pytest.mark.parametrize("label", PHASE4_LABELS)
def test_phase4_sql_is_valid_duckdb_syntax(phase4_db: str, label: str):
    """All Phase-4 SQL queries must pass DuckDB EXPLAIN without errors."""
    sql = get_builtin_sql(label)
    conn = duckdb.connect(phase4_db, read_only=True)
    try:
        conn.execute(f"EXPLAIN {sql}")
    except Exception as exc:  # noqa: BLE001
        pytest.fail(f"EXPLAIN failed for '{label}': {exc}")
    finally:
        conn.close()


@pytest.mark.parametrize("label", PHASE4_LABELS)
def test_phase4_sql_has_limit(label: str):
    """All LJ SQL must carry an explicit LIMIT clause."""
    sql = get_builtin_sql(label)
    assert re.search(r"\bLIMIT\s+\d+", sql, re.IGNORECASE)
