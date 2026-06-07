"""Tests for schema.py — CloudTrail table schema definitions."""

from schema import get_column_names, get_schema_description


def test_get_schema_description_returns_string():
    """Returns a human-readable description of the cloudtrail_events table."""
    description = get_schema_description()

    assert isinstance(description, str)
    assert len(description) > 0
    # Must mention the table name and key columns
    assert "cloudtrail_events" in description
    assert "event_time" in description
    assert "event_name" in description


def test_get_column_names_returns_list():
    """Returns the expected list of column names for cloudtrail_events."""
    expected = [
        "event_time",
        "event_name",
        "event_source",
        "aws_region",
        "source_ip_address",
        "user_agent",
        "user_identity_type",
        "user_identity_arn",
        "user_identity_account_id",
        "request_parameters",
        "response_elements",
        "error_code",
        "error_message",
        "read_only",
        "event_type",
        "recipient_account_id",
        "raw_event",
        "geo_country_code",
        "geo_country_name",
        "geo_city",
        "geo_latitude",
        "geo_longitude",
        "geo_asn",
        "geo_org",
    ]

    columns = get_column_names()

    assert isinstance(columns, list)
    assert columns == expected
