"""Console-login dashboard charts must also detect the OAuth2 sign-in flow.

Some AWS accounts no longer emit the classic ``ConsoleLogin`` event for
signin.amazonaws.com; instead they emit ``CreateOAuth2Token`` /
``AuthorizeOAuth2Access`` with a ``success`` flag in ``additional_event_data``
(no ``responseElements.ConsoleLogin`` / ``MFAUsed`` fields). Chart YAMLs that
hard-filter on ``event_name = 'ConsoleLogin'`` silently show zero rows for
such accounts.

Each test assembles the real adhoc_filters / metrics sqlExpression fragments
from the chart YAML into a full query and runs it against a temp DuckDB
seeded with OAuth2-flow events, so a regression in the YAML fails here
before it ships.
"""

from __future__ import annotations

import os
import pathlib

import duckdb
import pytest
import yaml

CHARTS_DIR = pathlib.Path(__file__).parent.parent / "assets" / "cloudtrail_default" / "charts"


def _load_chart(filename: str) -> dict:
    path = CHARTS_DIR / f"{filename}.yaml"
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _adhoc_where(chart: dict, filter_option_name: str) -> str:
    for f in chart["params"]["adhoc_filters"]:
        if f.get("filterOptionName") == filter_option_name:
            return f["sqlExpression"]
    raise AssertionError(f"adhoc filter {filter_option_name!r} not found")


def _metric_sql(chart: dict, option_name: str) -> str:
    for m in chart["params"]["metrics"]:
        if m.get("optionName") == option_name:
            return m["sqlExpression"]
    raise AssertionError(f"metric {option_name!r} not found")


@pytest.fixture()
def login_db(tmp_path: pathlib.Path) -> str:
    """Temp DuckDB with both classic ConsoleLogin and OAuth2-flow sign-ins."""
    db_path = tmp_path / "login_test.db"
    conn = duckdb.connect(str(db_path))
    conn.execute("""
        CREATE TABLE cloudtrail_events (
            event_time               TIMESTAMP,
            event_name               VARCHAR,
            event_source             VARCHAR,
            user_identity_arn        VARCHAR,
            source_ip_address        VARCHAR,
            error_code               VARCHAR,
            response_elements        VARCHAR,
            raw_event                VARCHAR,
            additional_event_data    VARCHAR,
            geo_country_code         VARCHAR
        )
    """)
    conn.execute("""
        INSERT INTO cloudtrail_events
            (event_time, event_name, event_source, user_identity_arn,
             source_ip_address, response_elements, raw_event, additional_event_data)
        VALUES
        -- classic ConsoleLogin, one success one failure
        ('2026-06-01 09:00:00', 'ConsoleLogin', 'signin.amazonaws.com',
         'arn:aws:iam::111111111111:user/alice', '198.51.100.1',
         '{"ConsoleLogin":"Success"}',
         '{"responseElements":{"ConsoleLogin":"Success"}}', NULL),
        ('2026-06-01 08:00:00', 'ConsoleLogin', 'signin.amazonaws.com',
         'arn:aws:iam::111111111111:user/alice', '198.51.100.1',
         '{"ConsoleLogin":"Failure"}',
         '{"responseElements":{"ConsoleLogin":"Failure"}}', NULL),

        -- OAuth2-flow sign-in, one success one failure
        ('2026-06-28 11:53:47', 'CreateOAuth2Token', 'signin.amazonaws.com',
         'arn:aws:iam::015043439996:root', '59.147.205.157',
         NULL, NULL, '{"grant_type":"authorization_code","success":"true"}'),
        ('2026-06-29 11:53:47', 'AuthorizeOAuth2Access', 'signin.amazonaws.com',
         'arn:aws:iam::015043439996:root', '59.147.205.157',
         NULL, NULL, '{"success":"false"}'),

        -- benign, unrelated event that must not leak into results
        ('2026-06-28 12:00:00', 'DescribeInstances', 'ec2.amazonaws.com',
         'arn:aws:iam::015043439996:user/ops', '10.0.0.1', NULL, NULL, NULL)
    """)
    conn.close()
    return str(db_path)


def _run_scalar(db_path: str, sql: str):
    conn = duckdb.connect(db_path, read_only=True)
    try:
        return conn.execute(sql).fetchone()[0]
    finally:
        conn.close()


def _run_count(db_path: str, where_sql: str) -> int:
    return _run_scalar(
        db_path, f"SELECT COUNT(*) FROM cloudtrail_events WHERE {where_sql}"
    )


# ---------------------------------------------------------------------------
# console_login_activity.yaml
# ---------------------------------------------------------------------------


def test_console_login_activity_filter_includes_oauth2(login_db: str):
    chart = _load_chart("console_login_activity")
    where_sql = _adhoc_where(chart, "filter_event_type")
    assert _run_count(login_db, where_sql) == 4, (
        "filter should match 2 ConsoleLogin + 2 OAuth2 sign-in events"
    )


def test_console_login_activity_success_failure_counts_oauth2(login_db: str):
    chart = _load_chart("console_login_activity")
    where_sql = _adhoc_where(chart, "filter_event_type")
    failed_sql = _metric_sql(chart, "metric_failed_logins")
    success_sql = _metric_sql(chart, "metric_success_logins")
    sql = (
        f"SELECT {failed_sql} AS failed, {success_sql} AS success "
        f"FROM cloudtrail_events WHERE {where_sql}"
    )
    conn = duckdb.connect(login_db, read_only=True)
    try:
        failed, success = conn.execute(sql).fetchone()
    finally:
        conn.close()
    assert failed == 2, f"expected 2 failures (1 ConsoleLogin + 1 OAuth2), got {failed}"
    assert success == 2, f"expected 2 successes (1 ConsoleLogin + 1 OAuth2), got {success}"


# ---------------------------------------------------------------------------
# login_heatmap.yaml
# ---------------------------------------------------------------------------


def test_login_heatmap_filter_includes_oauth2(login_db: str):
    chart = _load_chart("login_heatmap")
    where_sql = _adhoc_where(chart, "filter_heatmap_login")
    assert _run_count(login_db, where_sql) == 4


# ---------------------------------------------------------------------------
# auth_failure_success.yaml
# ---------------------------------------------------------------------------


def test_auth_failure_success_filter_includes_oauth2(login_db: str):
    chart = _load_chart("auth_failure_success")
    where_sql = _adhoc_where(chart, "filter_auth_console_login")
    assert _run_count(login_db, where_sql) == 4


def test_auth_failure_success_counts_oauth2(login_db: str):
    chart = _load_chart("auth_failure_success")
    where_sql = _adhoc_where(chart, "filter_auth_console_login")
    failure_sql = _metric_sql(chart, "metric_auth_failures")
    success_sql = _metric_sql(chart, "metric_auth_successes")
    sql = (
        f"SELECT {failure_sql} AS failure, {success_sql} AS success "
        f"FROM cloudtrail_events WHERE {where_sql}"
    )
    conn = duckdb.connect(login_db, read_only=True)
    try:
        failure, success = conn.execute(sql).fetchone()
    finally:
        conn.close()
    assert failure == 2, f"expected 2 failures (1 ConsoleLogin + 1 OAuth2), got {failure}"
    assert success == 2, f"expected 2 successes (1 ConsoleLogin + 1 OAuth2), got {success}"


# ---------------------------------------------------------------------------
# security_relevant_api_calls.yaml
# ---------------------------------------------------------------------------


def test_security_relevant_api_calls_includes_oauth2_events(login_db: str):
    chart = _load_chart("security_relevant_api_calls")
    where_sql = chart["params"]["adhoc_filters"][0]["sqlExpression"]
    assert _run_count(login_db, where_sql) == 4, (
        "sensitive-API allowlist should match ConsoleLogin and OAuth2 sign-in events"
    )
