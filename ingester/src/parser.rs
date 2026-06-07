//! CloudTrail JSON log parser.
//!
//! Parses AWS CloudTrail log files (JSON format) into typed Rust structs.
//!
//! ## Two-step parsing strategy
//!
//! Parsing uses a two-step strategy to eliminate expensive round-trip
//! JSON serialization:
//!
//! 1. **Tokenise** the outer `{"Records": [...]}` envelope with
//!    `serde_json::RawValue` to locate per-record byte ranges without
//!    building any `serde_json::Value` trees.
//! 2. **Parse** each record individually into [`RawCloudTrailEvent`],
//!    keeping `requestParameters` and `responseElements` as raw JSON
//!    (`Box<RawValue>`) so that the insert path can write them directly.
//!
//! Compared to the old single-pass approach, this eliminates:
//! - `serde_json::Value` tree allocation for req/resp objects.
//! - The per-event `serde_json::to_string(event)` call (re-serialisation).
//! - `serde_json::Value::to_string()` calls for req/resp at insert time.
//! - `serde_json::Value` tree traversal for `userIdentity` at insert time.

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::value::RawValue;

// ─── Internal serde helpers ──────────────────────────────────────────────────

/// Minimal deserialization struct for the `userIdentity` sub-object.
///
/// Captures the columns stored as dedicated DB columns; all other keys
/// are ignored. This avoids building a full `serde_json::Value` tree for
/// the identity object.
#[derive(Deserialize)]
struct UserIdentityDeser {
    #[serde(rename = "type")]
    identity_type: Option<String>,
    arn: Option<String>,
    #[serde(rename = "accountId")]
    account_id: Option<String>,
    #[serde(rename = "principalId")]
    principal_id: Option<String>,
    #[serde(rename = "accessKeyId")]
    access_key_id: Option<String>,
    #[serde(rename = "userName")]
    user_name: Option<String>,
    #[serde(rename = "invokedBy")]
    invoked_by: Option<String>,
    #[serde(rename = "sessionContext")]
    session_context: Option<SessionContextDeser>,
}

/// Sub-object of `userIdentity` carrying session attributes and the
/// session issuer (the principal that created the temporary credentials).
#[derive(Deserialize)]
struct SessionContextDeser {
    attributes: Option<SessionAttributesDeser>,
    #[serde(rename = "sessionIssuer")]
    session_issuer: Option<SessionIssuerDeser>,
}

#[derive(Deserialize)]
struct SessionAttributesDeser {
    /// CloudTrail emits this as either a JSON boolean or the string
    /// "true" / "false" depending on event version, so we keep it as a
    /// raw string and let the DB column be VARCHAR.
    #[serde(rename = "mfaAuthenticated")]
    mfa_authenticated: Option<BoolOrString>,
    #[serde(rename = "creationDate")]
    creation_date: Option<String>,
}

#[derive(Deserialize)]
struct SessionIssuerDeser {
    #[serde(rename = "type")]
    issuer_type: Option<String>,
    arn: Option<String>,
    #[serde(rename = "accountId")]
    account_id: Option<String>,
    #[serde(rename = "userName")]
    user_name: Option<String>,
    #[serde(rename = "principalId")]
    principal_id: Option<String>,
}

/// Helper for fields that AWS encodes as either a JSON boolean or a string.
/// Older CloudTrail records (e.g. `mfaAuthenticated`) use the string form;
/// newer ones use the bool form. Normalised to "true" / "false" on read.
#[derive(Deserialize)]
#[serde(untagged)]
enum BoolOrString {
    Bool(bool),
    String(String),
}

impl From<BoolOrString> for String {
    fn from(v: BoolOrString) -> Self {
        match v {
            BoolOrString::Bool(true) => "true".to_owned(),
            BoolOrString::Bool(false) => "false".to_owned(),
            BoolOrString::String(s) => s,
        }
    }
}

/// Sub-object of CloudTrail event carrying TLS connection details.
#[derive(Deserialize)]
struct TlsDetailsDeser {
    #[serde(rename = "tlsVersion")]
    tls_version: Option<String>,
    #[serde(rename = "cipherSuite")]
    cipher_suite: Option<String>,
    #[serde(rename = "clientProvidedHostHeader")]
    client_provided_host_header: Option<String>,
}

/// Internal deserialization struct for a single CloudTrail event record.
///
/// `requestParameters` and `responseElements` are deserialized as
/// `Box<RawValue>` (raw JSON byte slices) rather than `serde_json::Value`
/// trees, avoiding heap allocations for all nested objects and making the
/// later `.get().to_owned()` copy far cheaper than `Value::to_string()`.
#[derive(Deserialize)]
struct RawCloudTrailEvent {
    #[serde(rename = "eventTime", default)]
    event_time: Option<String>,
    #[serde(rename = "eventName", default)]
    event_name: Option<String>,
    #[serde(rename = "eventSource", default)]
    event_source: Option<String>,
    #[serde(rename = "awsRegion", default)]
    aws_region: Option<String>,
    #[serde(rename = "sourceIPAddress")]
    source_ip_address: Option<String>,
    #[serde(rename = "userAgent")]
    user_agent: Option<String>,
    /// Parsed into a small typed struct — no full Value tree.
    #[serde(rename = "userIdentity")]
    user_identity: Option<UserIdentityDeser>,
    /// Raw JSON — avoids `serde_json::Value` tree allocation entirely.
    #[serde(rename = "requestParameters")]
    request_parameters: Option<Box<RawValue>>,
    /// Raw JSON — avoids `serde_json::Value` tree allocation entirely.
    #[serde(rename = "responseElements")]
    response_elements: Option<Box<RawValue>>,
    #[serde(rename = "errorCode")]
    error_code: Option<String>,
    #[serde(rename = "errorMessage")]
    error_message: Option<String>,
    #[serde(rename = "readOnly")]
    read_only: Option<bool>,
    #[serde(rename = "eventType")]
    event_type: Option<String>,
    #[serde(rename = "recipientAccountId")]
    recipient_account_id: Option<String>,

    // ── Newly extracted top-level fields (Step A) ────────────────────
    /// Globally unique event identifier, used for cross-system correlation.
    #[serde(rename = "eventID")]
    event_id: Option<String>,
    /// `Management` / `Data` / `Insight`.
    #[serde(rename = "eventCategory")]
    event_category: Option<String>,
    /// Array of resources touched. Stored as raw JSON — variable structure.
    #[serde(rename = "resources")]
    resources: Option<Box<RawValue>>,
    /// Service-specific extras. Free-form object stored as raw JSON.
    #[serde(rename = "additionalEventData")]
    additional_event_data: Option<Box<RawValue>>,
    #[serde(rename = "sharedEventID")]
    shared_event_id: Option<String>,
    #[serde(rename = "vpcEndpointId")]
    vpc_endpoint_id: Option<String>,
    /// Boolean per AWS docs but accepted as string too (older logs).
    #[serde(rename = "managementEvent")]
    management_event: Option<BoolOrString>,
    #[serde(rename = "tlsDetails")]
    tls_details: Option<TlsDetailsDeser>,
    #[serde(rename = "serviceEventDetails")]
    service_event_details: Option<Box<RawValue>>,
    #[serde(rename = "sessionCredentialFromConsole")]
    session_credential_from_console: Option<BoolOrString>,
    #[serde(rename = "apiVersion")]
    api_version: Option<String>,
}

/// Fast outer envelope: locates record boundaries without parsing values.
#[derive(Deserialize)]
struct CloudTrailLogRaw {
    #[serde(rename = "Records")]
    records: Vec<Box<RawValue>>,
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Pre-extracted fields from the `userIdentity` sub-object of a CloudTrail event.
///
/// Grouping these columns into their own struct improves readability and
/// makes it clear they share a common origin.
#[derive(Debug, Clone, Default)]
pub struct UserIdentity {
    /// Value of `userIdentity.type`.
    pub identity_type: Option<String>,
    /// Value of `userIdentity.arn`.
    pub arn: Option<String>,
    /// Value of `userIdentity.accountId`.
    pub account_id: Option<String>,
    /// Value of `userIdentity.principalId`.
    pub principal_id: Option<String>,
    /// Value of `userIdentity.accessKeyId`. Critical for tracing
    /// AssumeRole-issued sessions back to subsequent API calls.
    pub access_key_id: Option<String>,
    /// Value of `userIdentity.userName`.
    pub user_name: Option<String>,
    /// Value of `userIdentity.invokedBy` (AWS-service-initiated calls).
    pub invoked_by: Option<String>,
    /// Pre-extracted from `userIdentity.sessionContext`.
    pub session: SessionContext,
}

/// Pre-extracted fields from `userIdentity.sessionContext`.
///
/// Distinguishes between `attributes` (this session's own properties)
/// and `sessionIssuer` (the principal that minted the session).
#[derive(Debug, Clone, Default)]
pub struct SessionContext {
    /// `sessionContext.attributes.mfaAuthenticated`. Stored as a string
    /// because CloudTrail emits both `true` (bool) and `"true"` (string)
    /// across event versions.
    pub mfa_authenticated: Option<String>,
    /// `sessionContext.attributes.creationDate` (ISO-8601 string).
    pub creation_date: Option<String>,
    /// `sessionContext.sessionIssuer.type`.
    pub issuer_type: Option<String>,
    /// `sessionContext.sessionIssuer.arn` — the role/user that minted
    /// the session. Critical for role-chaining investigation.
    pub issuer_arn: Option<String>,
    /// `sessionContext.sessionIssuer.accountId`.
    pub issuer_account_id: Option<String>,
    /// `sessionContext.sessionIssuer.userName`.
    pub issuer_user_name: Option<String>,
    /// `sessionContext.sessionIssuer.principalId`.
    pub issuer_principal_id: Option<String>,
}

/// Pre-extracted fields from the `tlsDetails` sub-object.
#[derive(Debug, Clone, Default)]
pub struct TlsDetails {
    /// `tlsDetails.tlsVersion` — e.g. `TLSv1.2`.
    pub tls_version: Option<String>,
    /// `tlsDetails.cipherSuite`.
    pub cipher_suite: Option<String>,
    /// `tlsDetails.clientProvidedHostHeader`.
    pub client_provided_host_header: Option<String>,
}

/// A single CloudTrail event record.
///
/// ### Performance notes
///
/// - `raw_json`: original JSON bytes of this record.  Written directly to the
///   `raw_event` DB column — eliminates the `serde_json::to_string(event)`
///   round-trip that was previously required for every event.
/// - `request_parameters` / `response_elements`: raw JSON strings captured
///   during parsing.  Written directly to the DB — eliminates
///   `serde_json::Value::to_string()` at insert time.
/// - `user_identity`: pre-extracted during parsing — eliminates
///   `serde_json::Value` tree traversal at insert time.
#[derive(Debug, Clone)]
pub struct CloudTrailEvent {
    pub event_time: Option<String>,
    pub event_name: String,
    pub event_source: String,
    pub aws_region: String,
    pub source_ip_address: Option<String>,
    pub user_agent: Option<String>,
    /// Pre-extracted from the `userIdentity` sub-object.
    pub user_identity: UserIdentity,
    /// Raw JSON string of the original `requestParameters` object.
    pub request_parameters: Option<String>,
    /// Raw JSON string of the original `responseElements` object.
    pub response_elements: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub read_only: Option<bool>,
    pub event_type: Option<String>,
    pub recipient_account_id: Option<String>,
    /// Original JSON bytes of this record — written directly to `raw_event`.
    pub raw_json: String,

    // ── Newly extracted top-level fields (Step A) ────────────────────
    /// `eventID` — globally unique correlation ID.
    pub event_id: Option<String>,
    /// `eventCategory` — Management / Data / Insight.
    pub event_category: Option<String>,
    /// `resources` — JSON array of resource objects, kept as raw JSON.
    pub resources: Option<String>,
    /// `additionalEventData` — service-specific JSON object, raw.
    pub additional_event_data: Option<String>,
    /// `sharedEventID` — cross-account correlation.
    pub shared_event_id: Option<String>,
    /// `vpcEndpointId`.
    pub vpc_endpoint_id: Option<String>,
    /// `managementEvent` — normalised to a string ("true"/"false").
    pub management_event: Option<String>,
    /// Pre-extracted from `tlsDetails`.
    pub tls: TlsDetails,
    /// `serviceEventDetails` — service-specific JSON object, raw.
    pub service_event_details: Option<String>,
    /// `sessionCredentialFromConsole` — normalised to a string.
    pub session_credential_from_console: Option<String>,
    /// `apiVersion` — service API version, when present.
    pub api_version: Option<String>,
}

/// Wrapper for the CloudTrail JSON file format.
///
/// CloudTrail log files contain a top-level `Records` array.
#[derive(Debug)]
pub struct CloudTrailLog {
    pub records: Vec<CloudTrailEvent>,
}

/// Parse a CloudTrail JSON string into a [`CloudTrailLog`].
///
/// Uses the two-step strategy described in the module documentation.
/// Returns an error if the input is not valid JSON or does not conform
/// to the expected CloudTrail log structure.
pub fn parse_cloudtrail_log(json: &str) -> Result<CloudTrailLog> {
    // Step 1: fast tokenisation — locate record boundaries without building
    // any serde_json::Value trees.
    let raw_log: CloudTrailLogRaw =
        serde_json::from_str(json).with_context(|| "Failed to parse CloudTrail log JSON")?;

    let mut records = Vec::with_capacity(raw_log.records.len());

    // Step 2: parse each record individually.
    for raw_record in raw_log.records {
        let raw_str = raw_record.get(); // &str into the original json buffer

        let ev: RawCloudTrailEvent = serde_json::from_str(raw_str)
            .with_context(|| "Failed to parse CloudTrail event record")?;

        // Destructure the userIdentity struct to avoid Value traversal at
        // insert time. Session sub-fields are pulled out separately so the
        // DB layer can bind them as flat columns.
        let user_identity = match ev.user_identity {
            Some(ui) => {
                let session = match ui.session_context {
                    Some(sc) => {
                        let (mfa, creation) = match sc.attributes {
                            Some(a) => (a.mfa_authenticated.map(String::from), a.creation_date),
                            None => (None, None),
                        };
                        let (it, ia, iacc, iun, ipid) = match sc.session_issuer {
                            Some(si) => (
                                si.issuer_type,
                                si.arn,
                                si.account_id,
                                si.user_name,
                                si.principal_id,
                            ),
                            None => (None, None, None, None, None),
                        };
                        SessionContext {
                            mfa_authenticated: mfa,
                            creation_date: creation,
                            issuer_type: it,
                            issuer_arn: ia,
                            issuer_account_id: iacc,
                            issuer_user_name: iun,
                            issuer_principal_id: ipid,
                        }
                    }
                    None => SessionContext::default(),
                };
                UserIdentity {
                    identity_type: ui.identity_type,
                    arn: ui.arn,
                    account_id: ui.account_id,
                    principal_id: ui.principal_id,
                    access_key_id: ui.access_key_id,
                    user_name: ui.user_name,
                    invoked_by: ui.invoked_by,
                    session,
                }
            }
            None => UserIdentity::default(),
        };

        let tls = match ev.tls_details {
            Some(t) => TlsDetails {
                tls_version: t.tls_version,
                cipher_suite: t.cipher_suite,
                client_provided_host_header: t.client_provided_host_header,
            },
            None => TlsDetails::default(),
        };

        records.push(CloudTrailEvent {
            event_time: ev.event_time,
            event_name: ev.event_name.unwrap_or_default(),
            event_source: ev.event_source.unwrap_or_default(),
            aws_region: ev.aws_region.unwrap_or_default(),
            source_ip_address: ev.source_ip_address,
            user_agent: ev.user_agent,
            user_identity,
            // `RawValue::get()` yields a &str pointing into the record's raw
            // bytes; `.to_owned()` copies them into an owned String — much
            // cheaper than serialising a `serde_json::Value` tree.
            request_parameters: ev.request_parameters.map(|v| v.get().to_owned()),
            response_elements: ev.response_elements.map(|v| v.get().to_owned()),
            error_code: ev.error_code,
            error_message: ev.error_message,
            read_only: ev.read_only,
            event_type: ev.event_type,
            recipient_account_id: ev.recipient_account_id,
            // Preserve the original JSON bytes so the insert path can write
            // `raw_event` without any re-serialisation.
            raw_json: raw_str.to_owned(),

            event_id: ev.event_id,
            event_category: ev.event_category,
            resources: ev.resources.map(|v| v.get().to_owned()),
            additional_event_data: ev.additional_event_data.map(|v| v.get().to_owned()),
            shared_event_id: ev.shared_event_id,
            vpc_endpoint_id: ev.vpc_endpoint_id,
            management_event: ev.management_event.map(String::from),
            tls,
            service_event_details: ev.service_event_details.map(|v| v.get().to_owned()),
            session_credential_from_console: ev.session_credential_from_console.map(String::from),
            api_version: ev.api_version,
        });
    }

    Ok(CloudTrailLog { records })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test #1: Parse a minimal CloudTrail JSON record into a struct.
    #[test]
    fn test_parse_single_cloudtrail_event() {
        let json = r#"{
            "Records": [
                {
                    "eventTime": "2024-01-15T10:30:00Z",
                    "eventName": "DescribeInstances",
                    "eventSource": "ec2.amazonaws.com",
                    "awsRegion": "us-east-1",
                    "sourceIPAddress": "198.51.100.1",
                    "userAgent": "aws-cli/2.0",
                    "readOnly": true,
                    "eventType": "AwsApiCall",
                    "recipientAccountId": "123456789012"
                }
            ]
        }"#;

        let log = parse_cloudtrail_log(json).expect("Should parse successfully");

        assert_eq!(log.records.len(), 1);
        let event = &log.records[0];
        assert_eq!(event.event_time.as_deref(), Some("2024-01-15T10:30:00Z"));
        assert_eq!(event.event_name, "DescribeInstances");
        assert_eq!(event.event_source, "ec2.amazonaws.com");
        assert_eq!(event.aws_region, "us-east-1");
        assert_eq!(event.source_ip_address.as_deref(), Some("198.51.100.1"));
        assert_eq!(event.user_agent.as_deref(), Some("aws-cli/2.0"));
        assert_eq!(event.read_only, Some(true));
    }

    // Test #2: Parse a CloudTrail file containing `{"Records": [...]}` with multiple events.
    #[test]
    fn test_parse_cloudtrail_records_array() {
        let json = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/testdata/multi_event.json"
        ))
        .expect("testdata file should exist");

        let log = parse_cloudtrail_log(&json).expect("Should parse successfully");

        assert_eq!(log.records.len(), 3);
        assert_eq!(log.records[0].event_name, "DescribeInstances");
        assert_eq!(log.records[1].event_name, "CreateBucket");
        assert_eq!(log.records[2].event_name, "AssumeRole");
    }

    // Test #3: Fields like `errorCode` may be absent; parse should not panic.
    #[test]
    fn test_parse_handles_missing_optional_fields() {
        // Minimal event with only required fields; all optional fields absent.
        let json = r#"{
            "Records": [
                {
                    "eventTime": "2024-01-15T10:30:00Z",
                    "eventName": "DescribeInstances",
                    "eventSource": "ec2.amazonaws.com",
                    "awsRegion": "us-east-1"
                }
            ]
        }"#;

        let log = parse_cloudtrail_log(json).expect("Should parse successfully");

        let event = &log.records[0];
        assert!(event.source_ip_address.is_none());
        assert!(event.user_agent.is_none());
        // userIdentity sub-fields are pre-extracted; all should be None here.
        assert!(event.user_identity.identity_type.is_none());
        assert!(event.user_identity.arn.is_none());
        assert!(event.user_identity.account_id.is_none());
        assert!(event.request_parameters.is_none());
        assert!(event.response_elements.is_none());
        assert!(event.error_code.is_none());
        assert!(event.error_message.is_none());
        assert!(event.read_only.is_none());
        assert!(event.event_type.is_none());
        assert!(event.recipient_account_id.is_none());
    }

    // Test #4: Invalid JSON input returns an appropriate error.
    #[test]
    fn test_parse_malformed_json_returns_error() {
        let json = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/testdata/malformed.json"
        ))
        .expect("testdata file should exist");

        let result = parse_cloudtrail_log(&json);

        assert!(result.is_err(), "Malformed JSON should return an error");
    }

    // Test #5: `{"Records": []}` returns an empty vec, not an error.
    #[test]
    fn test_parse_empty_records_array() {
        let json = r#"{"Records": []}"#;

        let log = parse_cloudtrail_log(json).expect("Should parse successfully");

        assert_eq!(log.records.len(), 0);
    }

    // Test A1-01: Step-A extended fields are extracted from a realistic
    // CloudTrail event with userIdentity.sessionContext, tlsDetails,
    // resources, and other top-level fields populated.
    #[test]
    fn test_parse_extracts_step_a_fields() {
        let json = r#"{
            "Records": [{
                "eventTime": "2024-01-15T10:30:00Z",
                "eventName": "AssumeRole",
                "eventSource": "sts.amazonaws.com",
                "awsRegion": "us-east-1",
                "eventID": "EID-1234",
                "eventCategory": "Management",
                "managementEvent": true,
                "vpcEndpointId": "vpce-abc",
                "sharedEventID": "SHARED-1",
                "apiVersion": "2011-06-15",
                "sessionCredentialFromConsole": "true",
                "userIdentity": {
                    "type": "AssumedRole",
                    "arn": "arn:aws:sts::1:assumed-role/r/s",
                    "accountId": "1",
                    "principalId": "AROAEXAMPLE:s",
                    "accessKeyId": "ASIAEXAMPLE",
                    "userName": "uname",
                    "invokedBy": "ec2.amazonaws.com",
                    "sessionContext": {
                        "attributes": {
                            "mfaAuthenticated": "false",
                            "creationDate": "2024-01-15T10:00:00Z"
                        },
                        "sessionIssuer": {
                            "type": "Role",
                            "arn": "arn:aws:iam::1:role/r",
                            "accountId": "1",
                            "userName": "r",
                            "principalId": "AROAEXAMPLE"
                        }
                    }
                },
                "tlsDetails": {
                    "tlsVersion": "TLSv1.3",
                    "cipherSuite": "TLS_AES_128_GCM_SHA256",
                    "clientProvidedHostHeader": "sts.amazonaws.com"
                },
                "resources": [{"ARN": "arn:aws:s3:::b", "type": "AWS::S3::Bucket"}],
                "additionalEventData": {"key": "v"},
                "serviceEventDetails": {"detail": "x"}
            }]
        }"#;

        let log = parse_cloudtrail_log(json).expect("parse should succeed");
        let ev = &log.records[0];

        // userIdentity sub-fields
        let ui = &ev.user_identity;
        assert_eq!(ui.principal_id.as_deref(), Some("AROAEXAMPLE:s"));
        assert_eq!(ui.access_key_id.as_deref(), Some("ASIAEXAMPLE"));
        assert_eq!(ui.user_name.as_deref(), Some("uname"));
        assert_eq!(ui.invoked_by.as_deref(), Some("ec2.amazonaws.com"));

        // sessionContext
        assert_eq!(ui.session.mfa_authenticated.as_deref(), Some("false"));
        assert_eq!(
            ui.session.creation_date.as_deref(),
            Some("2024-01-15T10:00:00Z")
        );
        assert_eq!(ui.session.issuer_type.as_deref(), Some("Role"));
        assert_eq!(
            ui.session.issuer_arn.as_deref(),
            Some("arn:aws:iam::1:role/r")
        );
        assert_eq!(ui.session.issuer_user_name.as_deref(), Some("r"));
        assert_eq!(
            ui.session.issuer_principal_id.as_deref(),
            Some("AROAEXAMPLE")
        );

        // top-level fields
        assert_eq!(ev.event_id.as_deref(), Some("EID-1234"));
        assert_eq!(ev.event_category.as_deref(), Some("Management"));
        assert_eq!(ev.shared_event_id.as_deref(), Some("SHARED-1"));
        assert_eq!(ev.vpc_endpoint_id.as_deref(), Some("vpce-abc"));
        assert_eq!(ev.management_event.as_deref(), Some("true"));
        assert_eq!(ev.api_version.as_deref(), Some("2011-06-15"));
        assert_eq!(ev.session_credential_from_console.as_deref(), Some("true"));

        // tlsDetails
        assert_eq!(ev.tls.tls_version.as_deref(), Some("TLSv1.3"));
        assert_eq!(
            ev.tls.cipher_suite.as_deref(),
            Some("TLS_AES_128_GCM_SHA256")
        );
        assert_eq!(
            ev.tls.client_provided_host_header.as_deref(),
            Some("sts.amazonaws.com")
        );

        // raw-JSON fields
        assert!(ev.resources.as_deref().unwrap().contains("arn:aws:s3:::b"));
        assert!(
            ev.additional_event_data
                .as_deref()
                .unwrap()
                .contains("\"v\"")
        );
        assert!(
            ev.service_event_details
                .as_deref()
                .unwrap()
                .contains("\"x\"")
        );
    }

    // Test A1-02: mfaAuthenticated may be a JSON bool *or* a string. Both
    // forms must be normalised to "true"/"false" on the Rust side.
    #[test]
    fn test_parse_mfa_authenticated_accepts_bool_and_string() {
        let json = r#"{"Records":[
            {"eventTime":"t","eventName":"e","eventSource":"s","awsRegion":"r",
             "userIdentity":{"sessionContext":{"attributes":{"mfaAuthenticated":true}}}},
            {"eventTime":"t","eventName":"e","eventSource":"s","awsRegion":"r",
             "userIdentity":{"sessionContext":{"attributes":{"mfaAuthenticated":"false"}}}}
        ]}"#;
        let log = parse_cloudtrail_log(json).expect("parse should succeed");
        assert_eq!(
            log.records[0]
                .user_identity
                .session
                .mfa_authenticated
                .as_deref(),
            Some("true")
        );
        assert_eq!(
            log.records[1]
                .user_identity
                .session
                .mfa_authenticated
                .as_deref(),
            Some("false")
        );
    }

    // Test A1-03: Missing optional sub-objects must not panic and leave
    // the corresponding fields None.
    #[test]
    fn test_parse_handles_missing_extended_fields() {
        let json = r#"{"Records":[{"eventTime":"t","eventName":"e",
            "eventSource":"s","awsRegion":"r"}]}"#;
        let log = parse_cloudtrail_log(json).expect("parse should succeed");
        let ev = &log.records[0];
        assert!(ev.event_id.is_none());
        assert!(ev.event_category.is_none());
        assert!(ev.resources.is_none());
        assert!(ev.user_identity.access_key_id.is_none());
        assert!(ev.user_identity.session.mfa_authenticated.is_none());
        assert!(ev.tls.tls_version.is_none());
    }
}
