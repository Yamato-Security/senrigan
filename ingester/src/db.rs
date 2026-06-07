//! DuckDB connection, table schema management, and batch insert operations.
//!
//! This module is the only place that writes to DuckDB. All other modules
//! interact with the database through the public API defined here.

use std::collections::HashMap;

use anyhow::{Context, Result};
use duckdb::{Appender, Connection, ToSql};

use crate::geoip::{GeoInfo, GeoipEnricher};
use crate::parser::CloudTrailEvent;

/// Create the `cloudtrail_events` and `ingested_files` tables if they do not exist,
/// then ensure the geo-enrichment and extended-field columns are present.
///
/// This function is idempotent — calling it multiple times on the same
/// connection is safe.
pub fn ensure_table(conn: &Connection) -> Result<()> {
    // CREATE TABLE only declares the original 17 core columns.  Geo
    // columns and Step-A extended columns are added via ALTER TABLE
    // for both new and pre-existing databases — this guarantees a
    // single canonical column order on disk regardless of when the
    // database was first created:
    //   core (17)  →  geo (7)  →  extended (24)
    // The Appender writes positionally, so this ordering is the
    // contract that `append_event_row` relies on.
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS cloudtrail_events (
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
            raw_event                VARCHAR
        );

        CREATE TABLE IF NOT EXISTS ingested_files (
            file_path   VARCHAR PRIMARY KEY,
            sha256      VARCHAR NOT NULL,
            ingested_at TIMESTAMP DEFAULT current_timestamp
        );
        ",
    )
    .context("Failed to create database tables")?;

    ensure_geo_columns(conn)?;
    ensure_extended_columns(conn)?;
    ensure_indexes(conn)
}

/// Create ART indexes on high-frequency equality-filter columns.
///
/// Targets columns that are: (a) used in WHERE equality / IN clauses across
/// the built-in hunt queries, and (b) selective enough that the index prune
/// beats DuckDB's vectorised full-scan.  Range-filter columns such as
/// `event_time` are intentionally omitted — DuckDB's automatic zone maps
/// (per-row-group min/max) already handle those efficiently.
///
/// Uses `CREATE INDEX IF NOT EXISTS` so the function is idempotent.
pub fn ensure_indexes(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE INDEX IF NOT EXISTS idx_event_name
            ON cloudtrail_events (event_name);
        CREATE INDEX IF NOT EXISTS idx_event_source
            ON cloudtrail_events (event_source);
        CREATE INDEX IF NOT EXISTS idx_user_identity_type
            ON cloudtrail_events (user_identity_type);
        CREATE INDEX IF NOT EXISTS idx_error_code
            ON cloudtrail_events (error_code);
        CREATE INDEX IF NOT EXISTS idx_source_ip_address
            ON cloudtrail_events (source_ip_address);
        CREATE INDEX IF NOT EXISTS idx_user_identity_access_key_id
            ON cloudtrail_events (user_identity_access_key_id);
        CREATE INDEX IF NOT EXISTS idx_recipient_account_id
            ON cloudtrail_events (recipient_account_id);
        ",
    )
    .context("Failed to create indexes on cloudtrail_events")
}

/// Add the 7 geo-enrichment columns to `cloudtrail_events` if they do not exist.
///
/// Uses `ALTER TABLE … ADD COLUMN IF NOT EXISTS` — safe to call repeatedly.
pub fn ensure_geo_columns(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS geo_country_code VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS geo_country_name VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS geo_city         VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS geo_latitude     DOUBLE;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS geo_longitude    DOUBLE;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS geo_asn          VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS geo_org          VARCHAR;
        ",
    )
    .context("Failed to add geo columns to cloudtrail_events")
}

/// Add the Step-A extended-field columns to `cloudtrail_events` if they
/// do not exist. These hoist commonly-needed sub-fields out of the
/// `raw_event` blob so that incident-investigation queries can run as
/// regular column predicates.
///
/// Uses `ALTER TABLE … ADD COLUMN IF NOT EXISTS` so existing databases
/// are migrated transparently on the next ingest run.
pub fn ensure_extended_columns(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        -- userIdentity sub-fields (in addition to type/arn/accountId already present)
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS user_identity_principal_id      VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS user_identity_access_key_id     VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS user_identity_user_name         VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS user_identity_invoked_by        VARCHAR;
        -- userIdentity.sessionContext.attributes
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS session_mfa_authenticated       VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS session_creation_date           VARCHAR;
        -- userIdentity.sessionContext.sessionIssuer
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS session_issuer_type             VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS session_issuer_arn              VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS session_issuer_account_id       VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS session_issuer_user_name        VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS session_issuer_principal_id     VARCHAR;
        -- top-level identifiers / categorisation
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS event_id                        VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS event_category                  VARCHAR;
        -- resources / additional / shared / VPC
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS resources                       VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS additional_event_data           VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS shared_event_id                 VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS vpc_endpoint_id                 VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS management_event                VARCHAR;
        -- TLS posture
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS tls_version                     VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS tls_cipher_suite                VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS tls_client_provided_host_header VARCHAR;
        -- service-specific / misc
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS service_event_details           VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS session_credential_from_console VARCHAR;
        ALTER TABLE cloudtrail_events ADD COLUMN IF NOT EXISTS api_version                     VARCHAR;
        ",
    )
    .context("Failed to add extended columns to cloudtrail_events")
}

/// Append a single [`CloudTrailEvent`] row (with pre-resolved [`GeoInfo`]) to an open
/// [`Appender`].
///
/// This is the single source of truth for the row layout.
/// Both [`insert_events_with_geo`] and any future bulk-append callers must use
/// this helper so that schema changes only need to be made in one place.
///
/// Column order **must exactly match** [`ensure_table`]'s CREATE TABLE
/// statement, then the geo columns added by [`ensure_geo_columns`], then
/// the Step-A extended columns added by [`ensure_extended_columns`].
///
/// When `strip_raw_event` is `true`, the `raw_event` column receives
/// `NULL` instead of the original JSON. All Step-A extended columns
/// remain populated, so investigation queries continue to work — only
/// the unscoped full-text fallback via raw_event is dropped.
fn append_event_row(
    appender: &mut Appender<'_>,
    event: &CloudTrailEvent,
    geo: &GeoInfo,
    strip_raw_event: bool,
) -> Result<()> {
    let ui = &event.user_identity;
    let session = &ui.session;
    let tls = &event.tls;
    // When strip_raw_event is set, bind None for the raw_event column.
    let raw_event_param: Option<&str> = if strip_raw_event {
        None
    } else {
        Some(event.raw_json.as_str())
    };

    // All JSON fields are pre-computed strings on CloudTrailEvent —
    // no serde_json serialisation occurs in this hot path.
    //
    // Order: core (17) → geo (7) → extended (24). Matches the on-disk
    // column order produced by `ensure_table` + `ensure_geo_columns`
    // + `ensure_extended_columns`.
    let params: Vec<&dyn ToSql> = vec![
        // ── core (17) ────────────────────────────────────────────────
        &event.event_time,           // event_time
        &event.event_name,           // event_name
        &event.event_source,         // event_source
        &event.aws_region,           // aws_region
        &event.source_ip_address,    // source_ip_address
        &event.user_agent,           // user_agent
        &ui.identity_type,           // user_identity_type
        &ui.arn,                     // user_identity_arn
        &ui.account_id,              // user_identity_account_id
        &event.request_parameters,   // request_parameters
        &event.response_elements,    // response_elements
        &event.error_code,           // error_code
        &event.error_message,        // error_message
        &event.read_only,            // read_only
        &event.event_type,           // event_type
        &event.recipient_account_id, // recipient_account_id
        &raw_event_param,            // raw_event (None when stripped)
        // ── geo (7) ─────────────────────────────────────────────────
        &geo.country_code, // geo_country_code
        &geo.country_name, // geo_country_name
        &geo.city,         // geo_city
        &geo.latitude,     // geo_latitude
        &geo.longitude,    // geo_longitude
        &geo.asn,          // geo_asn
        &geo.org,          // geo_org
        // ── extended (24) ───────────────────────────────────────────
        &ui.principal_id,                       // user_identity_principal_id
        &ui.access_key_id,                      // user_identity_access_key_id
        &ui.user_name,                          // user_identity_user_name
        &ui.invoked_by,                         // user_identity_invoked_by
        &session.mfa_authenticated,             // session_mfa_authenticated
        &session.creation_date,                 // session_creation_date
        &session.issuer_type,                   // session_issuer_type
        &session.issuer_arn,                    // session_issuer_arn
        &session.issuer_account_id,             // session_issuer_account_id
        &session.issuer_user_name,              // session_issuer_user_name
        &session.issuer_principal_id,           // session_issuer_principal_id
        &event.event_id,                        // event_id
        &event.event_category,                  // event_category
        &event.resources,                       // resources (JSON)
        &event.additional_event_data,           // additional_event_data (JSON)
        &event.shared_event_id,                 // shared_event_id
        &event.vpc_endpoint_id,                 // vpc_endpoint_id
        &event.management_event,                // management_event
        &tls.tls_version,                       // tls_version
        &tls.cipher_suite,                      // tls_cipher_suite
        &tls.client_provided_host_header,       // tls_client_provided_host_header
        &event.service_event_details,           // service_event_details (JSON)
        &event.session_credential_from_console, // session_credential_from_console
        &event.api_version,                     // api_version
    ];
    appender
        .append_row(params.as_slice())
        .context("Failed to append event row")
}

/// Insert a slice of [`CloudTrailEvent`]s with optional GeoIP enrichment.
///
/// Uses [`duckdb::Appender`] for high-throughput batch inserts.
/// When `geoip` is `None`, all geo columns are written as `NULL`.
/// When `strip_raw_event` is `true`, the `raw_event` column receives
/// `NULL` (rather than the original JSON) — used by the
/// `--strip-raw-event` CLI flag to produce a much smaller DB after
/// Step-A field hoisting.
/// Returns the number of rows inserted.
pub fn insert_events_with_geo(
    conn: &Connection,
    events: &[CloudTrailEvent],
    geoip: Option<&GeoipEnricher>,
    strip_raw_event: bool,
) -> Result<usize> {
    if events.is_empty() {
        return Ok(0);
    }

    let mut appender = conn
        .appender("cloudtrail_events")
        .context("Failed to create appender for cloudtrail_events")?;

    for event in events {
        // Look up geo info for the source IP (or return all-None when no enricher).
        let geo: GeoInfo = match (geoip, &event.source_ip_address) {
            (Some(enricher), Some(ip)) => enricher.lookup(ip),
            _ => GeoInfo::all_none(),
        };
        append_event_row(&mut appender, event, &geo, strip_raw_event)?;
    }

    appender.flush().context("Failed to flush appender")?;
    Ok(events.len())
}

/// Record a batch of ingested files in a single Appender flush.
///
/// Replaces N individual `INSERT OR REPLACE` statements (one per file) with
/// a single Appender write, reducing SQL round-trip overhead from O(N) to
/// O(1) per chunk.
///
/// `ingested_at` is supplied as a formatted RFC 3339 timestamp string so the
/// appender can fill the TIMESTAMP column without relying on SQL DEFAULT.
pub fn batch_mark_ingested(conn: &Connection, files: &[(String, String)]) -> Result<()> {
    if files.is_empty() {
        return Ok(());
    }
    let now = chrono::Utc::now()
        .format("%Y-%m-%d %H:%M:%S%.6f")
        .to_string();
    let mut appender = conn
        .appender("ingested_files")
        .context("Failed to create appender for ingested_files")?;
    for (path, sha256) in files {
        appender
            .append_row([path.as_str(), sha256.as_str(), now.as_str()])
            .with_context(|| format!("Failed to append ingested_files row for {path}"))?;
    }
    appender
        .flush()
        .context("Failed to flush ingested_files appender")?;
    Ok(())
}

/// Load the entire `ingested_files` table into a `HashMap<file_path, sha256>`.
///
/// Using this function at the start of an ingestion run replaces the previous
/// pattern of one `SELECT` per file with a single bulk query, which is orders
/// of magnitude faster when tens of thousands of files are already tracked.
///
/// The caller is expected to update the map as new files are inserted so that
/// within-run duplicate detection works correctly without extra DB round-trips.
pub fn fetch_ingested_files_map(conn: &Connection) -> Result<HashMap<String, String>> {
    let mut stmt = conn
        .prepare("SELECT file_path, sha256 FROM ingested_files")
        .context("Failed to prepare ingested_files query")?;
    let rows = stmt
        .query_map([], |row| {
            let path: String = row.get(0)?;
            let sha256: String = row.get(1)?;
            Ok((path, sha256))
        })
        .context("Failed to query ingested_files")?;
    let mut map = HashMap::new();
    for row in rows {
        let (path, sha256) = row.context("Failed to read ingested_files row")?;
        map.insert(path, sha256);
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{full_event, make_enricher, minimal_event, temp_db};

    // Test #9: `ensure_table()` creates the `cloudtrail_events` table in a temp DuckDB.
    #[test]
    fn test_create_cloudtrail_table() {
        let conn = temp_db();

        ensure_table(&conn).expect("ensure_table should succeed");

        // Verify the table exists by querying its row count.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM cloudtrail_events", [], |row| {
                row.get(0)
            })
            .expect("cloudtrail_events table should exist and be queryable");
        assert_eq!(count, 0);

        // Verify the ingested_files table also exists.
        let count2: i64 = conn
            .query_row("SELECT COUNT(*) FROM ingested_files", [], |row| row.get(0))
            .expect("ingested_files table should exist and be queryable");
        assert_eq!(count2, 0);
    }

    // Test #10: Calling `ensure_table()` twice does not error.
    #[test]
    fn test_create_table_is_idempotent() {
        let conn = temp_db();

        ensure_table(&conn).expect("First call should succeed");
        ensure_table(&conn).expect("Second call should also succeed without error");
    }

    // Test #11: Insert one parsed event and verify it can be queried back.
    #[test]
    fn test_insert_single_event() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();

        let event = full_event();
        let inserted =
            insert_events_with_geo(&conn, &[event], None, false).expect("insert should succeed");

        assert_eq!(inserted, 1);

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM cloudtrail_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);

        // Spot-check a column value.
        let name: String = conn
            .query_row(
                "SELECT event_name FROM cloudtrail_events LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(name, "DescribeInstances");
    }

    // Test #12: Insert 100 events in a batch and verify the row count.
    #[test]
    fn test_insert_batch_events() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();

        let events: Vec<CloudTrailEvent> = (0..100).map(|_| full_event()).collect();
        let inserted = insert_events_with_geo(&conn, &events, None, false)
            .expect("batch insert should succeed");

        assert_eq!(inserted, 100);

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM cloudtrail_events", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 100);
    }

    // Test #13: Events with `None` optional fields are inserted without error.
    #[test]
    fn test_insert_event_with_null_fields() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();

        // minimal_event() has all optional fields set to None.
        let event = minimal_event();
        let inserted = insert_events_with_geo(&conn, &[event], None, false)
            .expect("insert with null fields should succeed");
        assert_eq!(inserted, 1);

        // Verify the NULL columns are actually NULL in the database.
        let (src_ip, error_code): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT source_ip_address, error_code FROM cloudtrail_events LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(src_ip.is_none());
        assert!(error_code.is_none());
    }

    // Test D-01: ensure_geo_columns adds 7 new columns to cloudtrail_events.
    #[test]
    fn test_ensure_geo_columns_adds_seven_columns() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();

        // Verify all 7 geo columns exist via information_schema (works on empty table).
        let geo_col_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM information_schema.columns \
                 WHERE table_name = 'cloudtrail_events' AND column_name LIKE 'geo_%'",
                [],
                |row| row.get(0),
            )
            .expect("information_schema query should succeed");
        assert_eq!(geo_col_count, 7, "should have exactly 7 geo_ columns");
    }

    // Test D-A1: ensure_extended_columns adds all Step-A columns.
    #[test]
    fn test_ensure_extended_columns_adds_all_columns() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();

        let expected = [
            "user_identity_principal_id",
            "user_identity_access_key_id",
            "user_identity_user_name",
            "user_identity_invoked_by",
            "session_mfa_authenticated",
            "session_creation_date",
            "session_issuer_type",
            "session_issuer_arn",
            "session_issuer_account_id",
            "session_issuer_user_name",
            "session_issuer_principal_id",
            "event_id",
            "event_category",
            "resources",
            "additional_event_data",
            "shared_event_id",
            "vpc_endpoint_id",
            "management_event",
            "tls_version",
            "tls_cipher_suite",
            "tls_client_provided_host_header",
            "service_event_details",
            "session_credential_from_console",
            "api_version",
        ];
        for col in expected {
            let exists: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM information_schema.columns \
                     WHERE table_name = 'cloudtrail_events' AND column_name = ?",
                    [col],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1, "extended column missing: {col}");
        }
    }

    // Test D-A2: ensure_extended_columns is idempotent.
    #[test]
    fn test_ensure_extended_columns_is_idempotent() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();
        ensure_extended_columns(&conn).expect("second call should succeed");
        ensure_extended_columns(&conn).expect("third call should also succeed");
    }

    // Test D-B1: insert_events_with_geo with strip_raw_event=true writes
    // NULL into raw_event but keeps all Step-A columns populated.
    #[test]
    fn test_insert_with_strip_raw_event_writes_null_raw() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();

        let event = full_event();
        insert_events_with_geo(&conn, &[event], None, true).expect("insert should succeed");

        let (raw, akid, ev_id): (Option<String>, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT raw_event, user_identity_access_key_id, event_id \
                 FROM cloudtrail_events LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert!(raw.is_none(), "raw_event must be NULL when stripped");
        // Step-A columns must remain populated.
        assert_eq!(akid.as_deref(), Some("AKIAEXAMPLE"));
        assert_eq!(
            ev_id.as_deref(),
            Some("00000000-1111-2222-3333-444444444444")
        );
    }

    // Test D-B2: strip_raw_event=false (default) preserves raw_event verbatim.
    #[test]
    fn test_insert_without_strip_raw_event_preserves_raw() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();
        insert_events_with_geo(&conn, &[full_event()], None, false).expect("insert should succeed");
        let raw: Option<String> = conn
            .query_row("SELECT raw_event FROM cloudtrail_events LIMIT 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(raw.is_some(), "raw_event must be preserved by default");
        assert!(raw.unwrap().contains("DescribeInstances"));
    }

    // Test D-A3: full_event() values round-trip through the appender for
    // every Step-A column (validates schema/Appender column-order pairing).
    #[test]
    fn test_insert_event_persists_extended_fields() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();
        insert_events_with_geo(&conn, &[full_event()], None, false).expect("insert should succeed");

        // Eleven Option<String> columns spelled out as a type alias to
        // satisfy clippy::type_complexity in test code.
        type ExtendedRow = (
            Option<String>, // access_key_id
            Option<String>, // mfa_authenticated
            Option<String>, // issuer_arn
            Option<String>, // event_id
            Option<String>, // event_category
            Option<String>, // resources
            Option<String>, // vpc_endpoint_id
            Option<String>, // management_event
            Option<String>, // tls_version
            Option<String>, // tls_cipher_suite
            Option<String>, // tls_client_provided_host_header
        );
        let (akid, mfa, issuer_arn, ev_id, ev_cat, res, vpc, mgmt, tls_ver, tls_suite, tls_host): ExtendedRow = conn
            .query_row(
                "SELECT user_identity_access_key_id, session_mfa_authenticated, \
                        session_issuer_arn, event_id, event_category, resources, \
                        vpc_endpoint_id, management_event, tls_version, tls_cipher_suite, \
                        tls_client_provided_host_header \
                 FROM cloudtrail_events LIMIT 1",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                        r.get(9)?,
                        r.get(10)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(akid.as_deref(), Some("AKIAEXAMPLE"));
        assert_eq!(mfa.as_deref(), Some("true"));
        assert_eq!(
            issuer_arn.as_deref(),
            Some("arn:aws:iam::123456789012:role/issuer")
        );
        assert_eq!(
            ev_id.as_deref(),
            Some("00000000-1111-2222-3333-444444444444")
        );
        assert_eq!(ev_cat.as_deref(), Some("Management"));
        assert!(res.as_deref().unwrap().contains("arn:aws:s3:::bucket"));
        assert_eq!(vpc.as_deref(), Some("vpce-12345"));
        assert_eq!(mgmt.as_deref(), Some("true"));
        assert_eq!(tls_ver.as_deref(), Some("TLSv1.2"));
        assert_eq!(tls_suite.as_deref(), Some("ECDHE-RSA-AES128-GCM-SHA256"));
        assert_eq!(tls_host.as_deref(), Some("ec2.us-east-1.amazonaws.com"));
    }

    // Test D-02: ensure_geo_columns is idempotent.
    #[test]
    fn test_ensure_geo_columns_is_idempotent() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();

        ensure_geo_columns(&conn).expect("second call to ensure_geo_columns should succeed");
        ensure_geo_columns(&conn).expect("third call to ensure_geo_columns should also succeed");
    }

    // Test D-03: insert_events_with_geo stores geo data when GeoInfo is provided.
    #[test]
    fn test_insert_events_with_geo_populates_columns() {
        let enricher = make_enricher();

        let conn = temp_db();
        ensure_table(&conn).unwrap();

        // Use a known IP from the test mmdb: 81.2.69.160 → GB / London.
        let mut event = full_event();
        event.source_ip_address = Some("81.2.69.160".to_string());

        insert_events_with_geo(&conn, &[event], Some(&enricher), false)
            .expect("insert with geo should succeed");

        let country_code: Option<String> = conn
            .query_row(
                "SELECT geo_country_code FROM cloudtrail_events LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            country_code.as_deref(),
            Some("GB"),
            "geo_country_code should be GB for 81.2.69.160"
        );
    }

    // Test D-04: insert_events_with_geo stores NULL geo columns when no enricher.
    #[test]
    fn test_insert_events_without_geo_columns_are_null() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();

        let event = full_event();
        insert_events_with_geo(&conn, &[event], None, false)
            .expect("insert without geo should succeed");

        let (cc, cn, city): (Option<String>, Option<String>, Option<String>) = conn
            .query_row(
                "SELECT geo_country_code, geo_country_name, geo_city FROM cloudtrail_events LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(
            cc.is_none(),
            "geo_country_code should be NULL without enricher"
        );
        assert!(
            cn.is_none(),
            "geo_country_name should be NULL without enricher"
        );
        assert!(city.is_none(), "geo_city should be NULL without enricher");
    }

    // Test D-05: Private IPs are stored with the "PRIVATE" marker.
    #[test]
    fn test_insert_events_private_ip_stores_marker() {
        let enricher = make_enricher();

        let conn = temp_db();
        ensure_table(&conn).unwrap();

        let mut event = full_event();
        event.source_ip_address = Some("10.0.0.1".to_string());

        insert_events_with_geo(&conn, &[event], Some(&enricher), false)
            .expect("insert with private IP should succeed");

        let country_code: Option<String> = conn
            .query_row(
                "SELECT geo_country_code FROM cloudtrail_events LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            country_code.as_deref(),
            Some("PRIVATE"),
            "geo_country_code should be PRIVATE for 10.0.0.1"
        );
    }

    // Test #37: fetch_ingested_files_map returns an empty map when no files have been ingested.
    #[test]
    fn test_fetch_ingested_files_map_empty() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();

        let map = fetch_ingested_files_map(&conn).expect("fetch should succeed on empty table");
        assert!(
            map.is_empty(),
            "map must be empty when ingested_files is empty"
        );
    }

    // Test #38: fetch_ingested_files_map returns all entries present in ingested_files.
    #[test]
    fn test_fetch_ingested_files_map_with_entries() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();

        conn.execute(
            "INSERT INTO ingested_files (file_path, sha256) VALUES (?, ?)",
            duckdb::params!["/logs/a.json", "aaaa1111"],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ingested_files (file_path, sha256) VALUES (?, ?)",
            duckdb::params!["/logs/b.json.gz", "bbbb2222"],
        )
        .unwrap();

        let map = fetch_ingested_files_map(&conn).expect("fetch should succeed");
        assert_eq!(map.len(), 2, "map must contain both entries");
        assert_eq!(
            map.get("/logs/a.json").map(String::as_str),
            Some("aaaa1111")
        );
        assert_eq!(
            map.get("/logs/b.json.gz").map(String::as_str),
            Some("bbbb2222")
        );
    }
}
