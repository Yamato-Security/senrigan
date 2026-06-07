"""CloudTrail table schema definitions.

Provides human-readable schema descriptions and column name lists
for use in system prompts and SQL validation.
"""

CLOUDTRAIL_COLUMNS: list[dict] = [
    {
        "name": "event_time",
        "type": "TIMESTAMP",
        "nullable": True,
        "description": "Timestamp of the API call",
    },
    {
        "name": "event_name",
        "type": "VARCHAR",
        "nullable": False,
        "description": "Name of the AWS API action (e.g. DescribeInstances)",
    },
    {
        "name": "event_source",
        "type": "VARCHAR",
        "nullable": False,
        "description": "AWS service that processed the request (e.g. ec2.amazonaws.com)",
    },
    {
        "name": "aws_region",
        "type": "VARCHAR",
        "nullable": False,
        "description": "AWS region where the request was made",
    },
    {
        "name": "source_ip_address",
        "type": "VARCHAR",
        "nullable": True,
        "description": "IP address of the requester",
    },
    {
        "name": "user_agent",
        "type": "VARCHAR",
        "nullable": True,
        "description": "User agent string of the requester",
    },
    {
        "name": "user_identity_type",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Type of the IAM identity (e.g. IAMUser, AssumedRole, Root)",
    },
    {
        "name": "user_identity_arn",
        "type": "VARCHAR",
        "nullable": True,
        "description": "ARN of the IAM identity",
    },
    {
        "name": "user_identity_account_id",
        "type": "VARCHAR",
        "nullable": True,
        "description": "AWS account ID of the identity",
    },
    {
        "name": "request_parameters",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Parameters sent with the API request (JSON string)",
    },
    {
        "name": "response_elements",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Response elements returned by the API (JSON string)",
    },
    {
        "name": "error_code",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Error code if the request failed",
    },
    {
        "name": "error_message",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Error message if the request failed",
    },
    {
        "name": "read_only",
        "type": "BOOLEAN",
        "nullable": True,
        "description": "Whether the API call is read-only",
    },
    {
        "name": "event_type",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Type of event (e.g. AwsApiCall, AwsConsoleSignIn)",
    },
    {
        "name": "recipient_account_id",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Account ID that received the event",
    },
    {
        "name": "raw_event",
        "type": "VARCHAR",
        "nullable": False,
        "description": "Full original CloudTrail event as JSON string",
    },
    {
        "name": "geo_country_code",
        "type": "VARCHAR",
        "nullable": True,
        "description": "GeoIP country code (e.g. US, JP) or PRIVATE/LOOPBACK/LINK-LOCAL for special IPs",
    },
    {
        "name": "geo_country_name",
        "type": "VARCHAR",
        "nullable": True,
        "description": "GeoIP country name (e.g. United States, Japan)",
    },
    {
        "name": "geo_city",
        "type": "VARCHAR",
        "nullable": True,
        "description": "GeoIP city name (e.g. Tokyo, London)",
    },
    {
        "name": "geo_latitude",
        "type": "DOUBLE",
        "nullable": True,
        "description": "GeoIP latitude coordinate",
    },
    {
        "name": "geo_longitude",
        "type": "DOUBLE",
        "nullable": True,
        "description": "GeoIP longitude coordinate",
    },
    {
        "name": "geo_asn",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Autonomous System Number (e.g. AS15169)",
    },
    {
        "name": "geo_org",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Organization name associated with the ASN (e.g. Google LLC)",
    },
]


def get_column_names() -> list[str]:
    """Return the list of column names for cloudtrail_events.

    Returns:
        A list of column name strings in schema-definition order.
    """
    return [col["name"] for col in CLOUDTRAIL_COLUMNS]


def get_schema_description() -> str:
    """Return a human-readable Markdown table description of cloudtrail_events.

    The output is intended for use in LLM system prompts so the model
    understands the available columns, their types, and their meaning.

    Returns:
        A multi-line string containing the table name and a Markdown column table.
    """
    header = (
        "Table: cloudtrail_events\n\n"
        "| Column | Type | Nullable | Description |\n"
        "| ------ | ---- | -------- | ----------- |"
    )
    rows = [
        f"| {col['name']} | {col['type']} | {'YES' if col['nullable'] else 'NO'} | {col['description']} |"
        for col in CLOUDTRAIL_COLUMNS
    ]
    return "\n".join([header] + rows)
