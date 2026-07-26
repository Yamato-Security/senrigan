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


# Columns of Suzaku's ``aws-ct-timeline`` table, in the order Suzaku writes them.
#
# Everything is VARCHAR in the file (see doc/PLAN_SUZAKU_SCHEMA.md P3), including
# the timestamp and the severity, so the descriptions carry the handling rules
# the LLM would otherwise have to guess: the ``-`` placeholder Suzaku writes
# instead of NULL (P2) and the " ¦ "-separated Tags string (P5).
SUZAKU_TIMELINE_COLUMNS: list[dict] = [
    {
        "name": "Timestamp",
        "type": "VARCHAR",
        "nullable": False,
        "description": (
            "Detection time as 'YYYY-MM-DD HH:MM:SS' text — CAST to TIMESTAMP for "
            "any date arithmetic or bucketing"
        ),
    },
    {
        "name": "RuleTitle",
        "type": "VARCHAR",
        "nullable": False,
        "description": "Title of the Suzaku rule that matched",
    },
    {
        "name": "RuleAuthor",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Author of the matched rule",
    },
    {
        "name": "Level",
        "type": "VARCHAR",
        "nullable": False,
        "description": (
            "Severity: critical, high, medium, low, informational — text, so order "
            "it with a CASE rank, never alphabetically"
        ),
    },
    {
        "name": "EventName",
        "type": "VARCHAR",
        "nullable": False,
        "description": "CloudTrail API action that triggered the detection",
    },
    {
        "name": "ErrorCode",
        "type": "VARCHAR",
        "nullable": False,
        "description": (
            "AWS error code, or '-' when the call succeeded (Suzaku writes '-', "
            "not NULL — use ErrorCode <> '-' to find failures)"
        ),
    },
    {
        "name": "ErrorMessage",
        "type": "VARCHAR",
        "nullable": False,
        "description": "AWS error message, or '-' when the call succeeded",
    },
    {
        "name": "EventSource",
        "type": "VARCHAR",
        "nullable": False,
        "description": "AWS service that processed the request (e.g. ec2.amazonaws.com)",
    },
    {
        "name": "AWS-Region",
        "type": "VARCHAR",
        "nullable": True,
        "description": (
            "Region of the request — the hyphen means it MUST be written as "
            '"AWS-Region"'
        ),
    },
    {
        "name": "SrcIP",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Source IP address of the request (no GeoIP columns in this table)",
    },
    {
        "name": "UserAgent",
        "type": "VARCHAR",
        "nullable": True,
        "description": "User agent string of the caller",
    },
    {
        "name": "UserName",
        "type": "VARCHAR",
        "nullable": False,
        "description": "IAM user or role name, or '-' when absent",
    },
    {
        "name": "UserType",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Identity type (e.g. IAMUser, AssumedRole, Root)",
    },
    {
        "name": "UserAccountID",
        "type": "VARCHAR",
        "nullable": True,
        "description": "AWS account ID of the identity",
    },
    {
        "name": "UserARN",
        "type": "VARCHAR",
        "nullable": True,
        "description": "ARN of the identity that triggered the detection",
    },
    {
        "name": "UserPrincipalID",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Principal ID of the identity",
    },
    {
        "name": "UserAccessKeyID",
        "type": "VARCHAR",
        "nullable": False,
        "description": "Access key used, or '-' when the call was not key-based",
    },
    {
        "name": "EventID",
        "type": "VARCHAR",
        "nullable": False,
        "description": (
            "CloudTrail event ID — NOT unique: one event matching several rules "
            "produces one row per match"
        ),
    },
    {
        "name": "Tags",
        "type": "VARCHAR",
        "nullable": False,
        "description": (
            "Tactic short names and ATT&CK technique IDs joined by ' ¦ ' "
            "(e.g. 'PrivEsc ¦ Persis ¦ T1078.004') — split with "
            "string_split(\"Tags\", ' ¦ ') and unnest to analyse them"
        ),
    },
    {
        "name": "RuleID",
        "type": "VARCHAR",
        "nullable": False,
        "description": "UUID of the matched rule",
    },
]


def get_column_names(columns: list[dict] | tuple[dict, ...] | None = None) -> list[str]:
    """Return the column names of a table's schema definition.

    Args:
        columns: Column metadata to read, defaulting to
                 :data:`CLOUDTRAIL_COLUMNS` so existing callers are unaffected.

    Returns:
        A list of column name strings in schema-definition order.
    """
    return [
        col["name"] for col in (columns if columns is not None else CLOUDTRAIL_COLUMNS)
    ]


def get_schema_description(
    table: str = "cloudtrail_events",
    columns: list[dict] | tuple[dict, ...] | None = None,
) -> str:
    """Return a human-readable Markdown description of *table*'s schema.

    The output is intended for use in LLM system prompts so the model
    understands the available columns, their types, and their meaning.

    Args:
        table:   Table name to describe (default: ``cloudtrail_events``).
        columns: Column metadata, defaulting to :data:`CLOUDTRAIL_COLUMNS`.

    Returns:
        A multi-line string containing the table name and a Markdown column table.
    """
    if columns is None:
        columns = CLOUDTRAIL_COLUMNS
    header = (
        f"Table: {table}\n\n"
        "| Column | Type | Nullable | Description |\n"
        "| ------ | ---- | -------- | ----------- |"
    )
    rows = [
        f"| {col['name']} | {col['type']} | {'YES' if col['nullable'] else 'NO'} | {col['description']} |"
        for col in columns
    ]
    return "\n".join([header] + rows)
