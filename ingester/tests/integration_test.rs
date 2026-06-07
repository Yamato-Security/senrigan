//! End-to-end integration tests for the ingester pipeline.
//!
//! These tests drive the public library API directly (no subprocess) and
//! verify that the full walk → decompress → parse → insert pipeline works
//! correctly with the testdata fixtures checked into the repository.

use duckdb::Connection;
use ingester::db::ensure_table;
use ingester::ingest::{IngestOptions, ingest};
use std::path::PathBuf;

/// Returns the absolute path to `ingester/tests/testdata/`.
fn testdata_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("testdata")
}

/// Open an in-memory DuckDB connection with the schema already applied.
fn setup_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    ensure_table(&conn).unwrap();
    conn
}

// Ingest the entire testdata directory and verify the row count.
//
// testdata contains:
//   - single_event.json  → 1 record
//   - multi_event.json   → 3 records
//   - single_event.json.gz → 1 record  (same content as single_event.json but different SHA-256 path)
//   - malformed.json     → parse error → counted as errors, not inserted
//
// Expected: 5 records inserted (1 + 3 + 1), 1 error, 3 files processed successfully.
#[test]
fn test_ingest_full_testdata_pipeline() {
    let conn = setup_db();
    let dir = testdata_dir();

    let stats =
        ingest(&dir, &conn, IngestOptions::default()).expect("full pipeline should succeed");

    // malformed.json produces one error.
    assert_eq!(
        stats.errors, 1,
        "malformed.json should produce exactly 1 error"
    );
    // 3 valid files (single_event.json, multi_event.json, single_event.json.gz).
    assert_eq!(
        stats.files_processed, 3,
        "three valid files should be processed"
    );
    // 1 + 3 + 1 = 5 records.
    assert_eq!(
        stats.records_inserted, 5,
        "total inserted records should be 5"
    );

    // Verify via SQL that the rows are actually in the database.
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM cloudtrail_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 5);
}

// Ingest the testdata directory twice; the second run should insert no new records.
#[test]
fn test_ingest_testdata_idempotent() {
    let conn = setup_db();
    let dir = testdata_dir();

    let stats1 = ingest(&dir, &conn, IngestOptions::default()).expect("first run should succeed");
    let stats2 = ingest(&dir, &conn, IngestOptions::default()).expect("second run should succeed");

    // Second run: all previously ingested files are skipped.
    assert_eq!(
        stats2.records_inserted, 0,
        "second ingest should insert no new records"
    );
    // Total DB rows must not have changed.
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM cloudtrail_events", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, stats1.records_inserted as i64);
}
