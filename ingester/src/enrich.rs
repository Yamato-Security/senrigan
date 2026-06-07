//! Enrich existing `cloudtrail_events` rows with GeoIP data.
//!
//! The `enrich` command is for back-filling geo columns in a database that
//! was ingested without a GeoIP enricher.  It queries all distinct
//! `source_ip_address` values that have `geo_country_code IS NULL`, performs
//! one mmdb lookup per unique IP, then bulk-UPDATEs all matching rows.
//!
//! Unlike `insert_events_with_geo`, UPDATE operations cannot use a DuckDB
//! `Appender` (which is INSERT-only).  Plain `conn.execute()` is used instead.

use std::time::Instant;

use anyhow::{Context, Result};
use duckdb::Connection;

use crate::db::ensure_geo_columns;
use crate::geoip::GeoipEnricher;

/// Statistics returned after a completed enrichment run.
#[derive(Debug, Default)]
pub struct EnrichStats {
    /// Number of rows updated with geo data.
    pub enriched_count: usize,
    /// Number of rows whose `source_ip_address` is NULL (skipped).
    pub skipped_count: usize,
    /// Wall-clock time for the entire run in seconds.
    pub elapsed_secs: f64,
}

/// Enrich all rows in `cloudtrail_events` that have a non-NULL
/// `source_ip_address` and a NULL `geo_country_code`.
///
/// # Algorithm
///
/// 1. `ensure_geo_columns` — adds the 7 geo columns if not present.
/// 2. Query all distinct `source_ip_address` values where `geo_country_code IS NULL`.
/// 3. For each unique IP: `GeoipEnricher::lookup()` → `GeoInfo`.
/// 4. UPDATE all rows sharing that IP in a single statement.
/// 5. Return [`EnrichStats`].
///
/// This function is idempotent: rows already having a non-NULL `geo_country_code`
/// are skipped (`WHERE geo_country_code IS NULL`).
pub fn enrich_existing(conn: &Connection, geoip: &GeoipEnricher) -> Result<EnrichStats> {
    let start = Instant::now();
    let mut stats = EnrichStats::default();

    // Ensure the geo columns exist (idempotent).
    ensure_geo_columns(conn).context("Failed to ensure geo columns before enrichment")?;

    // Collect all distinct source IPs that still need enrichment.
    // NULL source_ip rows are excluded here — they are counted as skipped.
    let pending_ips = collect_pending_ips(conn)?;

    // Also count NULL-source-ip rows for the stats.
    stats.skipped_count = count_null_source_ips(conn)?;

    // Process each unique IP: lookup → UPDATE all matching rows.
    for ip in &pending_ips {
        let geo = geoip.lookup(ip);

        let rows_affected = conn
            .execute(
                "UPDATE cloudtrail_events
                 SET geo_country_code = $1,
                     geo_country_name = $2,
                     geo_city         = $3,
                     geo_latitude     = $4,
                     geo_longitude    = $5,
                     geo_asn          = $6,
                     geo_org          = $7
                 WHERE source_ip_address = $8
                   AND geo_country_code IS NULL",
                duckdb::params![
                    geo.country_code,
                    geo.country_name,
                    geo.city,
                    geo.latitude,
                    geo.longitude,
                    geo.asn,
                    geo.org,
                    ip,
                ],
            )
            .with_context(|| format!("Failed to update geo columns for IP {ip}"))?;

        stats.enriched_count += rows_affected;
    }

    stats.elapsed_secs = start.elapsed().as_secs_f64();
    Ok(stats)
}

/// Return all distinct non-NULL `source_ip_address` values whose
/// `geo_country_code` is still NULL (i.e. not yet enriched).
fn collect_pending_ips(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT source_ip_address
             FROM cloudtrail_events
             WHERE source_ip_address IS NOT NULL
               AND geo_country_code IS NULL",
        )
        .context("Failed to prepare pending-IPs query")?;

    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .context("Failed to query pending IPs")?;

    let mut ips = Vec::new();
    for row in rows {
        ips.push(row.context("Failed to read pending IP row")?);
    }
    Ok(ips)
}

/// Count rows where `source_ip_address` is NULL.
fn count_null_source_ips(conn: &Connection) -> Result<usize> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM cloudtrail_events WHERE source_ip_address IS NULL",
            [],
            |row| row.get(0),
        )
        .context("Failed to count NULL source_ip rows")?;
    Ok(count as usize)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{ensure_table, insert_events_with_geo};
    use crate::test_util::{event_with_ip, event_with_null_ip, make_enricher, temp_db};

    // Test E-01: enrich_existing adds geo columns to an existing table.
    #[test]
    fn test_enrich_adds_geo_columns_to_existing_table() {
        let conn = temp_db();
        // Create table without geo columns (simulate legacy schema).
        conn.execute_batch(
            "CREATE TABLE cloudtrail_events (
                event_time TIMESTAMP, event_name VARCHAR, event_source VARCHAR,
                aws_region VARCHAR, source_ip_address VARCHAR, user_agent VARCHAR,
                user_identity_type VARCHAR, user_identity_arn VARCHAR,
                user_identity_account_id VARCHAR, request_parameters VARCHAR,
                response_elements VARCHAR, error_code VARCHAR, error_message VARCHAR,
                read_only BOOLEAN, event_type VARCHAR, recipient_account_id VARCHAR,
                raw_event VARCHAR
            );
            CREATE TABLE ingested_files (
                file_path VARCHAR PRIMARY KEY, sha256 VARCHAR NOT NULL,
                ingested_at TIMESTAMP DEFAULT current_timestamp
            );",
        )
        .unwrap();

        let enricher = make_enricher();
        enrich_existing(&conn, &enricher).expect("enrich_existing should succeed");

        // Verify all 7 geo columns exist via information_schema (works on empty table).
        let geo_col_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM information_schema.columns \
                 WHERE table_name = 'cloudtrail_events' AND column_name LIKE 'geo_%'",
                [],
                |row| row.get(0),
            )
            .expect("information_schema query should succeed");
        assert_eq!(
            geo_col_count, 7,
            "should have exactly 7 geo_ columns after enrich_existing"
        );
    }

    // Test E-02: enrich_existing updates a public IP with correct geo data.
    #[test]
    fn test_enrich_public_ip_writes_geo_data() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();

        // Insert without enricher so geo columns remain NULL.
        insert_events_with_geo(&conn, &[event_with_ip("81.2.69.160")], None, false).unwrap();

        let enricher = make_enricher();
        let stats = enrich_existing(&conn, &enricher).expect("enrich_existing should succeed");

        assert!(
            stats.enriched_count > 0,
            "at least one row should be updated"
        );

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

    // Test E-03: enrich_existing writes "PRIVATE" marker for private IPs.
    #[test]
    fn test_enrich_private_ip_writes_marker() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();
        insert_events_with_geo(&conn, &[event_with_ip("10.0.0.1")], None, false).unwrap();

        let enricher = make_enricher();
        enrich_existing(&conn, &enricher).expect("enrich_existing should succeed");

        let cc: Option<String> = conn
            .query_row(
                "SELECT geo_country_code FROM cloudtrail_events LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(cc.as_deref(), Some("PRIVATE"));
    }

    // Test E-04: Rows with NULL source_ip_address are not updated.
    #[test]
    fn test_enrich_skips_null_source_ip() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();
        insert_events_with_geo(&conn, &[event_with_null_ip()], None, false).unwrap();

        let enricher = make_enricher();
        let stats = enrich_existing(&conn, &enricher).expect("enrich_existing should succeed");

        assert_eq!(
            stats.skipped_count, 1,
            "one row with NULL source_ip should be skipped"
        );
        assert_eq!(stats.enriched_count, 0, "no rows should be enriched");
    }

    // Test E-05: enrich_existing is idempotent (already-enriched rows are not overwritten).
    #[test]
    fn test_enrich_is_idempotent() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();
        insert_events_with_geo(&conn, &[event_with_ip("81.2.69.160")], None, false).unwrap();

        let enricher = make_enricher();
        let stats1 = enrich_existing(&conn, &enricher).expect("first enrich should succeed");
        assert!(stats1.enriched_count > 0);

        // Second run: rows now have geo_country_code = "GB" → WHERE IS NULL excludes them.
        let stats2 = enrich_existing(&conn, &enricher).expect("second enrich should succeed");
        assert_eq!(
            stats2.enriched_count, 0,
            "no rows should be re-enriched on second run"
        );
    }

    // Test E-06: Same IP in multiple rows triggers only one mmdb lookup (dedup).
    #[test]
    fn test_enrich_deduplicates_lookups() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();

        // Insert 5 rows with the same IP.
        let events: Vec<_> = (0..5).map(|_| event_with_ip("81.2.69.160")).collect();
        insert_events_with_geo(&conn, &events, None, false).unwrap();

        let enricher = make_enricher();
        let stats = enrich_existing(&conn, &enricher).expect("enrich_existing should succeed");

        // All 5 rows should be updated in one batch UPDATE statement.
        assert_eq!(
            stats.enriched_count, 5,
            "all 5 rows with the same IP should be updated"
        );

        // Verify all rows have the correct country code.
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM cloudtrail_events WHERE geo_country_code = 'GB'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 5);
    }

    // Test E-07: enrich_existing returns an EnrichStats with meaningful values.
    #[test]
    fn test_enrich_returns_stats() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();

        // One public IP row + one NULL-ip row.
        insert_events_with_geo(&conn, &[event_with_ip("81.2.69.160")], None, false).unwrap();
        insert_events_with_geo(&conn, &[event_with_null_ip()], None, false).unwrap();

        let enricher = make_enricher();
        let stats = enrich_existing(&conn, &enricher).expect("enrich_existing should succeed");

        assert!(stats.enriched_count > 0, "enriched_count should be > 0");
        assert_eq!(
            stats.skipped_count, 1,
            "skipped_count should be 1 for NULL ip row"
        );
        assert!(
            stats.elapsed_secs >= 0.0,
            "elapsed_secs must be non-negative"
        );
    }

    // Test E-08: Non-IP strings like "AWS" result in NULL geo columns (no error).
    #[test]
    fn test_enrich_aws_service_ip_stored_as_null() {
        let conn = temp_db();
        ensure_table(&conn).unwrap();
        // CloudTrail sometimes stores "AWS" as the sourceIPAddress.
        insert_events_with_geo(&conn, &[event_with_ip("AWS")], None, false).unwrap();

        let enricher = make_enricher();
        // Should not error even though "AWS" is not an IP address.
        enrich_existing(&conn, &enricher).expect("enrich with AWS string should not error");

        // After enrichment the row was "updated" with all-NULL geo (lookup returns all_none).
        // The geo_country_code should be NULL.
        let cc: Option<String> = conn
            .query_row(
                "SELECT geo_country_code FROM cloudtrail_events LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            cc.is_none(),
            "geo_country_code should be NULL for non-IP source address like 'AWS'"
        );
    }
}
