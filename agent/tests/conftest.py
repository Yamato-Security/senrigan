"""Shared pytest fixtures for the agent test suite."""

import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture(autouse=True)
def clear_llm_client_cache():
    """Clear the OpenAI client cache before and after every test.

    Prevents a cached mock (or real) client from leaking between test cases
    when tests call functions that invoke ``_create_client``.
    """
    import llm

    llm._clear_client_cache()
    yield
    llm._clear_client_cache()


class MockSessionState(dict):
    """Dict subclass that supports attribute-style access.

    Mimics Streamlit's ``st.session_state`` which supports both
    ``session_state["key"]`` and ``session_state.key`` syntax.
    Used in tests that need to inspect state after production code runs.

    Pre-populates keys that have session-wide defaults so tests that do not
    explicitly set them do not raise ``AttributeError`` when production code
    accesses them.  Explicit keyword arguments always override the defaults.
    """

    def __init__(self, **kwargs) -> None:
        from query import DEFAULT_ROW_LIMIT

        # Apply defaults first so explicit kwargs take precedence.
        defaults = {"row_limit": DEFAULT_ROW_LIMIT}
        defaults.update(kwargs)
        super().__init__(defaults)

    def __getattr__(self, key: str):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)

    def __setattr__(self, key: str, value) -> None:  # type: ignore[override]
        self[key] = value

    def pop(self, key, *args):  # type: ignore[override]
        return super().pop(key, *args)


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client that returns a predefined SQL response."""
    with patch("llm.OpenAI") as mock_cls:
        client = MagicMock()
        mock_cls.return_value = client

        response = MagicMock()
        response.choices = [MagicMock()]
        response.choices[0].message.content = (
            "SELECT event_name, COUNT(*) as cnt "
            "FROM cloudtrail_events "
            "GROUP BY event_name ORDER BY cnt DESC LIMIT 10"
        )
        client.chat.completions.create.return_value = response

        yield client


@pytest.fixture
def tmp_duckdb(tmp_path):
    """Create a temporary DuckDB with cloudtrail_events table and sample rows."""
    import duckdb

    db_path = tmp_path / "test.db"
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
        INSERT INTO cloudtrail_events (event_time, event_name, event_source, aws_region)
        VALUES
            ('2024-01-15 10:30:00', 'DescribeInstances', 'ec2.amazonaws.com', 'us-east-1'),
            ('2024-01-15 10:31:00', 'DescribeInstances', 'ec2.amazonaws.com', 'us-east-1'),
            ('2024-01-15 10:32:00', 'CreateUser',        'iam.amazonaws.com', 'us-east-1')
    """)
    conn.close()
    yield str(db_path)
