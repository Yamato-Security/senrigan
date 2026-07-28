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
# Since Suzaku's DuckDB schema_version 1 the file is typed rather than rendered:
# ``Timestamp`` is a real TIMESTAMP, ``Level`` is an ordered ENUM, absent values
# are NULL rather than the ``-`` placeholder the CSV writer still uses, and the
# packed ``Tags`` string is split into three ``VARCHAR[]`` columns. The
# descriptions below carry what remains non-obvious to the LLM.
#
# The three GeoIP columns Suzaku adds under ``--geo-ip`` are deliberately absent:
# they exist only in an enriched run, and a prompt promising a column that is not
# there produces SQL that fails to bind.
SUZAKU_TIMELINE_COLUMNS: list[dict] = [
    {
        "name": "Timestamp",
        "type": "TIMESTAMP",
        "nullable": True,
        "description": (
            "Detection time, in the timezone named by suzaku_meta.timestamp_tz "
            "(UTC unless Suzaku ran with --localtime)"
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
        "type": "ENUM (suzaku_level)",
        "nullable": True,
        "description": (
            "Severity, as an ordered ENUM: informational < low < medium < high < "
            'critical. ORDER BY "Level" DESC is already severity order — but a '
            "threshold needs the cast, \"Level\" >= 'high'::suzaku_level, because "
            "a bare string literal compares alphabetically"
        ),
    },
    {
        "name": "EventName",
        "type": "VARCHAR",
        "nullable": True,
        "description": "CloudTrail API action that triggered the detection",
    },
    {
        "name": "ErrorCode",
        "type": "VARCHAR",
        "nullable": True,
        "description": "AWS error code, NULL when the call succeeded",
    },
    {
        "name": "ErrorMessage",
        "type": "VARCHAR",
        "nullable": True,
        "description": "AWS error message, NULL when the call succeeded",
    },
    {
        "name": "EventSource",
        "type": "VARCHAR",
        "nullable": True,
        "description": "AWS service that processed the request (e.g. ec2.amazonaws.com)",
    },
    {
        "name": "AwsRegion",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Region of the request (e.g. us-east-1)",
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
        "nullable": True,
        "description": "IAM user or role name, NULL when the identity has none",
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
        "nullable": True,
        "description": "Access key used, NULL when the call was not key-based",
    },
    {
        "name": "EventID",
        "type": "VARCHAR",
        "nullable": True,
        "description": (
            "CloudTrail event ID — NOT unique: one event matching several rules "
            "produces one row per match"
        ),
    },
    {
        "name": "Tactics",
        "type": "VARCHAR[]",
        "nullable": False,
        "description": (
            "MITRE ATT&CK tactic short names (e.g. ['PrivEsc', 'Persis']) — a "
            "list, empty when the rule has none; unnest it or use list_contains"
        ),
    },
    {
        "name": "TechniqueIDs",
        "type": "VARCHAR[]",
        "nullable": False,
        "description": (
            "MITRE ATT&CK technique IDs (e.g. ['T1078.004']) — a list, empty when "
            "the rule has none"
        ),
    },
    {
        "name": "OtherTags",
        "type": "VARCHAR[]",
        "nullable": False,
        "description": "Remaining rule tags that are neither a tactic nor a technique",
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
