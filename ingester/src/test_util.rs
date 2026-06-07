//! Shared test utilities for the ingester test suite.
//!
//! This module is **only compiled in test mode** (`#[cfg(test)]`).  It
//! centralises the helper functions that were previously copy-pasted into
//! each source module's `#[cfg(test)] mod tests` block, giving us a single
//! source of truth for test fixtures.
//!
//! # Usage
//!
//! In any `#[cfg(test)] mod tests` block within `ingester/src/`:
//!
//! ```rust,ignore
//! use crate::test_util::*;
//!
//! #[test]
//! fn my_test() {
//!     let conn = setup_db();
//!     let event = full_event();
//!     // ...
//! }
//! ```

use std::path::PathBuf;

use duckdb::Connection;

use crate::db::ensure_table;
use crate::geoip::{GeoipConfig, GeoipEnricher};
use crate::parser::{CloudTrailEvent, SessionContext, TlsDetails, UserIdentity};

// ── Database helpers ──────────────────────────────────────────────────────────

/// Open an in-memory DuckDB connection.
///
/// Does **not** create the schema — call [`setup_db`] when you need the
/// `cloudtrail_events` and `ingested_files` tables ready.
pub fn temp_db() -> Connection {
    Connection::open_in_memory().unwrap()
}

/// Open an in-memory DuckDB connection with the full ingester schema applied.
///
/// Equivalent to `temp_db()` followed by `ensure_table()`.
pub fn setup_db() -> Connection {
    let conn = temp_db();
    ensure_table(&conn).unwrap();
    conn
}

// ── GeoIP helpers ─────────────────────────────────────────────────────────────

/// Return the path to the bundled `GeoLite2-City-Test.mmdb` fixture.
pub fn test_city_db_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/geoip/GeoLite2-City-Test.mmdb")
}

/// Return the path to the bundled `GeoLite2-Country-Test.mmdb` fixture.
pub fn test_country_db_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/testdata/geoip/GeoLite2-Country-Test.mmdb")
}

/// Return the path to the bundled `GeoLite2-ASN-Test.mmdb` fixture.
pub fn test_asn_db_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/geoip/GeoLite2-ASN-Test.mmdb")
}

/// Open a [`GeoipEnricher`] backed by the City test mmdb.
pub fn make_enricher() -> GeoipEnricher {
    GeoipEnricher::open(&GeoipConfig {
        city_db_path: Some(test_city_db_path()),
        country_db_path: None,
        asn_db_path: None,
    })
    .expect("should open test City mmdb")
}

// ── Event helpers ─────────────────────────────────────────────────────────────

/// Build a minimal [`CloudTrailEvent`] with all required fields set and
/// all optional fields set to `None`.
pub fn minimal_event() -> CloudTrailEvent {
    CloudTrailEvent {
        event_time: Some("2024-01-15T10:30:00Z".to_string()),
        event_name: "DescribeInstances".to_string(),
        event_source: "ec2.amazonaws.com".to_string(),
        aws_region: "us-east-1".to_string(),
        source_ip_address: None,
        user_agent: None,
        user_identity: UserIdentity::default(),
        request_parameters: None,
        response_elements: None,
        error_code: None,
        error_message: None,
        read_only: None,
        event_type: None,
        recipient_account_id: None,
        raw_json: "{}".to_owned(),
        event_id: None,
        event_category: None,
        resources: None,
        additional_event_data: None,
        shared_event_id: None,
        vpc_endpoint_id: None,
        management_event: None,
        tls: TlsDetails::default(),
        service_event_details: None,
        session_credential_from_console: None,
        api_version: None,
    }
}

/// Build a fully-populated [`CloudTrailEvent`] with all optional fields set.
pub fn full_event() -> CloudTrailEvent {
    CloudTrailEvent {
        event_time: Some("2024-01-15T10:30:00Z".to_string()),
        event_name: "DescribeInstances".to_string(),
        event_source: "ec2.amazonaws.com".to_string(),
        aws_region: "us-east-1".to_string(),
        source_ip_address: Some("198.51.100.1".to_string()),
        user_agent: Some("aws-cli/2.0".to_string()),
        user_identity: UserIdentity {
            identity_type: Some("IAMUser".to_string()),
            arn: Some("arn:aws:iam::123456789012:user/testuser".to_string()),
            account_id: Some("123456789012".to_string()),
            principal_id: Some("AIDAEXAMPLE".to_string()),
            access_key_id: Some("AKIAEXAMPLE".to_string()),
            user_name: Some("testuser".to_string()),
            invoked_by: None,
            session: SessionContext {
                mfa_authenticated: Some("true".to_string()),
                creation_date: Some("2024-01-15T10:00:00Z".to_string()),
                issuer_type: Some("Role".to_string()),
                issuer_arn: Some("arn:aws:iam::123456789012:role/issuer".to_string()),
                issuer_account_id: Some("123456789012".to_string()),
                issuer_user_name: Some("issuer".to_string()),
                issuer_principal_id: Some("AROAEXAMPLE".to_string()),
            },
        },
        request_parameters: Some(r#"{"key":"value"}"#.to_owned()),
        response_elements: Some(r#"{"result":"ok"}"#.to_owned()),
        error_code: None,
        error_message: None,
        read_only: Some(true),
        event_type: Some("AwsApiCall".to_string()),
        recipient_account_id: Some("123456789012".to_string()),
        raw_json: r#"{"eventTime":"2024-01-15T10:30:00Z","eventName":"DescribeInstances"}"#
            .to_owned(),
        event_id: Some("00000000-1111-2222-3333-444444444444".to_string()),
        event_category: Some("Management".to_string()),
        resources: Some(r#"[{"ARN":"arn:aws:s3:::bucket","type":"AWS::S3::Bucket"}]"#.to_owned()),
        additional_event_data: Some(r#"{"key":"v"}"#.to_owned()),
        shared_event_id: None,
        vpc_endpoint_id: Some("vpce-12345".to_string()),
        management_event: Some("true".to_string()),
        tls: TlsDetails {
            tls_version: Some("TLSv1.2".to_string()),
            cipher_suite: Some("ECDHE-RSA-AES128-GCM-SHA256".to_string()),
            client_provided_host_header: Some("ec2.us-east-1.amazonaws.com".to_string()),
        },
        service_event_details: None,
        session_credential_from_console: Some("false".to_string()),
        api_version: None,
    }
}

/// Build a [`CloudTrailEvent`] with only `source_ip_address` set to `ip`.
///
/// All other optional fields are `None` (uses [`minimal_event`] as base).
pub fn event_with_ip(ip: &str) -> CloudTrailEvent {
    CloudTrailEvent {
        source_ip_address: Some(ip.to_string()),
        ..minimal_event()
    }
}

/// Build a [`CloudTrailEvent`] with `source_ip_address` set to `None`.
///
/// Identical to [`minimal_event`] — provided for readability at call sites.
pub fn event_with_null_ip() -> CloudTrailEvent {
    minimal_event()
}
