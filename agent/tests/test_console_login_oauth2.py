"""Console Login hunts must also detect the OAuth2-based sign-in flow.

Some AWS accounts no longer emit the classic ``ConsoleLogin`` event for
signin.amazonaws.com; instead they emit ``CreateOAuth2Token`` /
``AuthorizeOAuth2Access`` with a ``success`` flag in ``additional_event_data``
(no ``MFAUsed``/``LoginTo`` fields). Hunts that hard-filter on
``event_name = 'ConsoleLogin'`` silently return zero rows for such accounts.

Red -> Green -> Refactor:
1. Assert the "Console Logins" / "Console Logins by Country" SQL detects
   CreateOAuth2Token / AuthorizeOAuth2Access events (fails before the fix).
2. Widen the ``event_name`` filter and login_result extraction in
   builtin_hunts.yaml.
3. Re-run to confirm green.
"""

from __future__ import annotations

import pathlib
from typing import Any

import duckdb
import pytest
import yaml

YAML_PATH = pathlib.Path(__file__).parent.parent / "builtin_hunts.yaml"

CONSOLE_LOGINS_LABEL = "\U0001f310 Console Logins"
CONSOLE_LOGINS_BY_COUNTRY_LABEL = "\U0001f5fa Console Logins by Country"


def _load_hunts() -> list[dict[str, Any]]:
    with open(YAML_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def get_builtin_sql(label: str) -> str:
    hunts = _load_hunts()
    for hunt in hunts:
        if hunt.get("label") == label:
            sql = hunt.get("sql")
            assert sql, f"Hunt '{label}' found but has no 'sql' field"
            return sql
    raise ValueError(f"No builtin hunt found with label: {label!r}")


def _run_sql(db_path: str, sql: str) -> list[dict]:
    conn = duckdb.connect(db_path, read_only=True)
    try:
        return conn.execute(sql).fetchdf().to_dict(orient="records")
    finally:
        conn.close()


@pytest.fixture()
def oauth2_login_db(tmp_path: pathlib.Path) -> str:
    """Temp DuckDB with OAuth2-flow sign-in events (no classic ConsoleLogin)."""
    db_path = tmp_path / "oauth2_login_test.db"
    conn = duckdb.connect(str(db_path))
    conn.execute("""
        CREATE TABLE cloudtrail_events (
            event_time               TIMESTAMP,
            event_name               VARCHAR,
            event_source             VARCHAR,
            aws_region               VARCHAR,
            source_ip_address        VARCHAR,
            user_agent               VARCHAR,
            user_identity_arn        VARCHAR,
            user_identity_account_id VARCHAR,
            request_parameters       VARCHAR,
            response_elements        VARCHAR,
            additional_event_data    VARCHAR,
            error_code               VARCHAR,
            error_message            VARCHAR,
            read_only                BOOLEAN,
            recipient_account_id     VARCHAR,
            geo_country_code         VARCHAR,
            geo_country_name         VARCHAR,
            geo_city                 VARCHAR
        )
    """)
    conn.execute("""
        INSERT INTO cloudtrail_events
            (event_time, event_name, event_source, aws_region,
             user_identity_arn, source_ip_address, additional_event_data,
             recipient_account_id, geo_country_code, geo_country_name, geo_city)
        VALUES
        ('2026-06-28 11:53:47', 'CreateOAuth2Token', 'signin.amazonaws.com',
         'ap-northeast-1', 'arn:aws:iam::015043439996:root', '59.147.205.157',
         '{"signInSessionArn":"arn:aws:signin:ap-northeast-1:015043439996:session/abc",
           "grant_type":"authorization_code","success":"true"}',
         '015043439996', 'JP', 'Japan', 'Tokyo'),
        ('2026-06-28 11:53:50', 'AuthorizeOAuth2Access', 'signin.amazonaws.com',
         'ap-northeast-1', 'arn:aws:iam::015043439996:root', '59.147.205.157',
         '{"success":"true"}',
         '015043439996', 'JP', 'Japan', 'Tokyo'),
        -- benign, unrelated event that must not leak into results
        ('2026-06-28 12:00:00', 'DescribeInstances', 'ec2.amazonaws.com',
         'ap-northeast-1', 'arn:aws:iam::015043439996:user/ops', '10.0.0.1',
         NULL, '015043439996', NULL, NULL, NULL)
    """)
    conn.close()
    return str(db_path)


def test_console_logins_detects_oauth2_token_events(oauth2_login_db: str):
    sql = get_builtin_sql(CONSOLE_LOGINS_LABEL)
    rows = _run_sql(oauth2_login_db, sql)
    assert len(rows) == 2, f"Expected both OAuth2 sign-in events, got: {rows}"
    assert all(r["login_result"] == "true" for r in rows), (
        f"login_result should be extracted from additional_event_data.success. Got: {rows}"
    )


def test_console_logins_by_country_detects_oauth2_token_events(
    oauth2_login_db: str,
):
    sql = get_builtin_sql(CONSOLE_LOGINS_BY_COUNTRY_LABEL)
    rows = _run_sql(oauth2_login_db, sql)
    assert len(rows) >= 2, f"Expected OAuth2 sign-ins by country, got: {rows}"
