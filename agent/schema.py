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
    # Six of the 24 extended columns, promoted because each one unlocks a hunt
    # that cannot be written without it (role chaining, session tracing, MFA
    # truth). The remaining 18 stay hidden to keep the prompt small.
    {
        "name": "user_identity_access_key_id",
        "type": "VARCHAR",
        "nullable": True,
        "description": (
            "Access key used for the call. Keys starting with ASIA are temporary "
            "STS session credentials — group by this to trace everything one "
            "assumed-role session did"
        ),
    },
    {
        "name": "session_issuer_arn",
        "type": "VARCHAR",
        "nullable": True,
        "description": (
            "ARN of the role that issued the current session. Set only for "
            "AssumedRole calls; combined with an AssumeRole event_name it reveals "
            "role chaining (a session assuming a further role)"
        ),
    },
    {
        "name": "session_mfa_authenticated",
        "type": "VARCHAR",
        "nullable": True,
        "description": (
            "Whether the session was MFA-authenticated, as the string 'true' or "
            "'false' (not a BOOLEAN). Covers every API call, unlike the "
            "ConsoleLogin-only MFA field in additional_event_data"
        ),
    },
    {
        "name": "additional_event_data",
        "type": "VARCHAR",
        "nullable": True,
        "description": (
            "Service-specific extra fields as a JSON string. Carries MFAUsed and "
            "federatedProvider for ConsoleLogin, and SSEApplied for S3"
        ),
    },
    {
        "name": "event_id",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Unique CloudTrail event ID — use it to cite a specific event",
    },
    {
        "name": "vpc_endpoint_id",
        "type": "VARCHAR",
        "nullable": True,
        "description": (
            "VPC endpoint the request arrived through, when it did not traverse "
            "the public internet"
        ),
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
# Suzaku's ATT&CK tactic abbreviations, as mapped by ``config/mitre_tactics.txt``
# in the Suzaku repository. The ``Tactics`` column holds these strings and never
# the full ATT&CK tactic name, so a filter written as
# ``list_contains("Tactics", 'Credential Access')`` binds, runs, and silently
# returns nothing. Two full tags share one abbreviation: ``attack.stealth`` and
# ``attack.defense-evasion`` both render as ``Stealth``.
SUZAKU_TACTIC_ABBREVIATIONS: frozenset[str] = frozenset(
    {
        "Recon",  # attack.reconnaissance
        "ResDev",  # attack.resource-development
        "InitAccess",  # attack.initial-access
        "Exec",  # attack.execution
        "Persis",  # attack.persistence
        "PrivEsc",  # attack.privilege-escalation
        "Stealth",  # attack.stealth / attack.defense-evasion
        "DefImpair",  # attack.defense-impairment
        "CredAccess",  # attack.credential-access
        "Disc",  # attack.discovery
        "LatMov",  # attack.lateral-movement
        "Collect",  # attack.collection
        "C2",  # attack.command-and-control
        "Exfil",  # attack.exfiltration
        "Impact",  # attack.impact
    }
)


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


# Columns of `vpc_flow_logs` shown to the LLM. ECS, tag and next-hop columns are
# withheld to keep the prompt small; hunt SQL may still use them.
VPC_FLOW_COLUMNS: list[dict] = [
    {
        "name": "start_time",
        "type": "TIMESTAMP",
        "nullable": True,
        "description": "Start of the aggregation window that holds the first packet (UTC)",
    },
    {
        "name": "end_time",
        "type": "TIMESTAMP",
        "nullable": True,
        "description": "End of the aggregation window that holds the last packet (UTC)",
    },
    {
        "name": "account_id",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Owner account of the observing network interface",
    },
    {
        "name": "interface_id",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Network interface the flow was observed on",
    },
    {
        "name": "vpc_id",
        "type": "VARCHAR",
        "nullable": True,
        "description": "VPC of the observing interface (NULL in version-2 formats)",
    },
    {
        "name": "subnet_id",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Subnet of the observing interface (NULL in version-2 formats)",
    },
    {
        "name": "instance_id",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Instance owning the interface; NULL for NAT gateways and other requester-managed interfaces",
    },
    {
        "name": "srcaddr",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Source address as seen by the interface (may be a middlebox's own address)",
    },
    {
        "name": "dstaddr",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Destination address as seen by the interface (may be a middlebox's own address)",
    },
    {
        "name": "pkt_srcaddr",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Original packet source address",
    },
    {
        "name": "pkt_dstaddr",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Original packet destination address",
    },
    {
        "name": "srcport",
        "type": "INTEGER",
        "nullable": True,
        "description": "Source port (0 for ICMP)",
    },
    {
        "name": "dstport",
        "type": "INTEGER",
        "nullable": True,
        "description": "Destination port (0 for ICMP)",
    },
    {
        "name": "protocol",
        "type": "INTEGER",
        "nullable": True,
        "description": "IANA protocol number (6 TCP, 17 UDP, 1 ICMP, 58 ICMPv6)",
    },
    {
        "name": "protocol_name",
        "type": "VARCHAR",
        "nullable": True,
        "description": "TCP, UDP, ICMP, ICMPv6, or the number for anything else",
    },
    {
        "name": "ip_version",
        "type": "INTEGER",
        "nullable": True,
        "description": "4 or 6",
    },
    {
        "name": "packets",
        "type": "BIGINT",
        "nullable": True,
        "description": "Packets in the window",
    },
    {
        "name": "bytes",
        "type": "BIGINT",
        "nullable": True,
        "description": "Bytes in the window; NULL for BPA records, which carry none",
    },
    {
        "name": "action",
        "type": "VARCHAR",
        "nullable": True,
        "description": "ACCEPT or REJECT — what the security group / NACL decided, not whether a session was established",
    },
    {
        "name": "log_status",
        "type": "VARCHAR",
        "nullable": True,
        "description": "OK, NODATA (no traffic in the window) or SKIPDATA (records dropped)",
    },
    {
        "name": "tcp_flags",
        "type": "INTEGER",
        "nullable": True,
        "description": "TCP flags OR-ed over the window: FIN 1, SYN 2, RST 4, SYN-ACK 18",
    },
    {
        "name": "flow_direction",
        "type": "VARCHAR",
        "nullable": True,
        "description": "ingress or egress relative to the observing interface",
    },
    {
        "name": "traffic_path",
        "type": "INTEGER",
        "nullable": True,
        "description": "Egress path: 8 internet gateway, 7 gateway endpoint, 2 either (ambiguous), 1 same VPC",
    },
    {
        "name": "pkt_src_aws_service",
        "type": "VARCHAR",
        "nullable": True,
        "description": "AWS service range of the packet source (e.g. S3), else NULL",
    },
    {
        "name": "pkt_dst_aws_service",
        "type": "VARCHAR",
        "nullable": True,
        "description": "AWS service range of the packet destination, else NULL",
    },
    {
        "name": "reject_reason",
        "type": "VARCHAR",
        "nullable": True,
        "description": "BPA (Block Public Access) or EC (Encryption Controls), else NULL",
    },
    {
        "name": "local_addr",
        "type": "VARCHAR",
        "nullable": True,
        "description": "The observing side's address; definitive only when direction_source = 'record'",
    },
    {
        "name": "remote_addr",
        "type": "VARCHAR",
        "nullable": True,
        "description": "The peer's address; definitive only when direction_source = 'record'",
    },
    {
        "name": "direction_source",
        "type": "VARCHAR",
        "nullable": True,
        "description": "record (from flow-direction), heuristic (address class only) or unknown",
    },
    {
        "name": "src_scope",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Address class of the packet source: public, private, loopback, link-local, special",
    },
    {
        "name": "dst_scope",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Address class of the packet destination",
    },
    {
        "name": "remote_scope",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Address class of remote_addr; 'public' means an external peer",
    },
    {
        "name": "flow_log_id",
        "type": "VARCHAR",
        "nullable": True,
        "description": "Flow log subscription the record came from",
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
