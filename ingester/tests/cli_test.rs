//! CLI integration tests for the ingester binary.
//!
//! These tests exercise the command-line interface end-to-end using
//! `assert_cmd`. The binary must be built before running these tests.

use assert_cmd::cargo_bin_cmd;
use predicates::prelude::*;
use std::io::Write;
use std::path::PathBuf;
use tempfile::{NamedTempFile, TempDir};

/// Returns the path to the GeoLite2-City test mmdb fixture.
fn test_city_db_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/geoip/GeoLite2-City-Test.mmdb")
}

/// Write a minimal CloudTrail JSON file and return the temp file handle.
fn write_single_event_json() -> NamedTempFile {
    let mut tmp = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    tmp.write_all(
        br#"{
        "Records": [{
            "eventTime": "2024-01-15T10:30:00Z",
            "eventName": "DescribeInstances",
            "eventSource": "ec2.amazonaws.com",
            "awsRegion": "us-east-1"
        }]
    }"#,
    )
    .unwrap();
    tmp.flush().unwrap();
    tmp
}

// Test #20: Running `ingester ingest --path <dir>` exits successfully and
//           prints a summary that includes the records_inserted count.
#[test]
fn test_cli_ingest_command() {
    let log_file = write_single_event_json();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");

    cargo_bin_cmd!("ingester")
        .args([
            "ingest",
            "--path",
            log_file.path().to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("records_inserted"));
}

// Test #21: Running without `--path` produces a usage error (non-zero exit)
//           and the error message appears on stderr.
#[test]
fn test_cli_missing_path_shows_error() {
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");

    cargo_bin_cmd!("ingester")
        .args(["ingest", "--db", db_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

// Test #33: --from and --to options filter files by date segment in their path.
//           Only the file under yyyy/mm/dd within the range is ingested.
#[test]
fn test_cli_date_filter_from_to() {
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");

    let log_dir = TempDir::new().unwrap();

    // In-range: 2024/01/15
    let in_range = log_dir.path().join("2024").join("01").join("15");
    std::fs::create_dir_all(&in_range).unwrap();
    std::fs::write(
        in_range.join("event.json"),
        br#"{"Records":[{"eventTime":"2024-01-15T10:00:00Z","eventName":"DescribeInstances","eventSource":"ec2.amazonaws.com","awsRegion":"us-east-1"}]}"#,
    )
    .unwrap();

    // Out-of-range: 2024/02/01
    let out_of_range = log_dir.path().join("2024").join("02").join("01");
    std::fs::create_dir_all(&out_of_range).unwrap();
    std::fs::write(
        out_of_range.join("event.json"),
        br#"{"Records":[{"eventTime":"2024-02-01T10:00:00Z","eventName":"ListBuckets","eventSource":"s3.amazonaws.com","awsRegion":"us-east-1"}]}"#,
    )
    .unwrap();

    cargo_bin_cmd!("ingester")
        .args([
            "ingest",
            "--path",
            log_dir.path().to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--from",
            "20240101",
            "--to",
            "20240131",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("records_inserted=1"))
        .stdout(predicate::str::contains("files_processed=1"));
}

// Test #34: --from only excludes files before the from date.
#[test]
fn test_cli_date_filter_from_only() {
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");

    let log_dir = TempDir::new().unwrap();

    // Before from: 2024/01/09
    let before = log_dir.path().join("2024").join("01").join("09");
    std::fs::create_dir_all(&before).unwrap();
    std::fs::write(
        before.join("event.json"),
        br#"{"Records":[{"eventTime":"2024-01-09T10:00:00Z","eventName":"DescribeInstances","eventSource":"ec2.amazonaws.com","awsRegion":"us-east-1"}]}"#,
    )
    .unwrap();

    // On from: 2024/01/10
    let on_from = log_dir.path().join("2024").join("01").join("10");
    std::fs::create_dir_all(&on_from).unwrap();
    std::fs::write(
        on_from.join("event.json"),
        br#"{"Records":[{"eventTime":"2024-01-10T10:00:00Z","eventName":"ListBuckets","eventSource":"s3.amazonaws.com","awsRegion":"us-east-1"}]}"#,
    )
    .unwrap();

    cargo_bin_cmd!("ingester")
        .args([
            "ingest",
            "--path",
            log_dir.path().to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--from",
            "20240110",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("records_inserted=1"))
        .stdout(predicate::str::contains("files_processed=1"));
}

// Test #35: invalid --from format produces an error with non-zero exit.
#[test]
fn test_cli_invalid_from_date_format_shows_error() {
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");
    let log_file = write_single_event_json();

    cargo_bin_cmd!("ingester")
        .args([
            "ingest",
            "--path",
            log_file.path().to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--from",
            "2024-01-01", // YYYY-MM-DD is rejected; only YYYYMMDD is accepted
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

// Test #36: --include filters to matching service; non-matching file is skipped.
#[test]
fn test_cli_include_pattern_filters_service() {
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");
    let log_dir = TempDir::new().unwrap();

    // Simulate S3 layout: two services under the same root.
    let ct_dir = log_dir.path().join("CloudTrail").join("us-east-1");
    let cfg_dir = log_dir.path().join("Config").join("us-east-1");
    std::fs::create_dir_all(&ct_dir).unwrap();
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(
        ct_dir.join("event.json"),
        br#"{"Records":[{"eventTime":"2024-01-15T10:00:00Z","eventName":"DescribeInstances","eventSource":"ec2.amazonaws.com","awsRegion":"us-east-1"}]}"#,
    )
    .unwrap();
    std::fs::write(
        cfg_dir.join("event.json"),
        br#"{"Records":[{"eventTime":"2024-01-15T10:00:00Z","eventName":"GetResourceConfigHistory","eventSource":"config.amazonaws.com","awsRegion":"us-east-1"}]}"#,
    )
    .unwrap();

    cargo_bin_cmd!("ingester")
        .args([
            "ingest",
            "--path",
            log_dir.path().to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--include",
            "*CloudTrail*",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("records_inserted=1"))
        .stdout(predicate::str::contains("files_processed=1"));
}

// Test #37: --exclude removes matching service; other files are ingested.
#[test]
fn test_cli_exclude_pattern_removes_service() {
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");
    let log_dir = TempDir::new().unwrap();

    let ct_dir = log_dir.path().join("CloudTrail").join("us-east-1");
    let cfg_dir = log_dir.path().join("Config").join("us-east-1");
    std::fs::create_dir_all(&ct_dir).unwrap();
    std::fs::create_dir_all(&cfg_dir).unwrap();
    std::fs::write(
        ct_dir.join("event.json"),
        br#"{"Records":[{"eventTime":"2024-01-15T10:00:00Z","eventName":"DescribeInstances","eventSource":"ec2.amazonaws.com","awsRegion":"us-east-1"}]}"#,
    )
    .unwrap();
    std::fs::write(
        cfg_dir.join("event.json"),
        br#"{"Records":[{"eventTime":"2024-01-15T10:00:00Z","eventName":"GetResourceConfigHistory","eventSource":"config.amazonaws.com","awsRegion":"us-east-1"}]}"#,
    )
    .unwrap();

    cargo_bin_cmd!("ingester")
        .args([
            "ingest",
            "--path",
            log_dir.path().to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--exclude",
            "*Config*",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("records_inserted=1"))
        .stdout(predicate::str::contains("files_processed=1"));
}

// Test #38: invalid --include glob pattern produces an error with non-zero exit.
#[test]
fn test_cli_invalid_include_pattern_shows_error() {
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");
    let log_file = write_single_event_json();

    cargo_bin_cmd!("ingester")
        .args([
            "ingest",
            "--path",
            log_file.path().to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--include",
            "*CloudTrail[", // unclosed bracket = invalid glob
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

// ── GeoIP / Enrich CLI tests (C-01 ~ C-05) ───────────────────────────────────

/// Write a CloudTrail JSON file with sourceIPAddress = 81.2.69.160 (GB in test mmdb).
fn write_geoip_event_json() -> NamedTempFile {
    let mut tmp = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    tmp.write_all(
        br#"{
        "Records": [{
            "eventTime": "2024-01-15T10:30:00Z",
            "eventName": "DescribeInstances",
            "eventSource": "ec2.amazonaws.com",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "81.2.69.160"
        }]
    }"#,
    )
    .unwrap();
    tmp.flush().unwrap();
    tmp
}

// Test C-01: `ingest --geoip-city <path>` exits successfully and prints records_inserted.
#[test]
fn test_cli_ingest_with_geoip_city_flag() {
    let log_file = write_geoip_event_json();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");
    let city_db = test_city_db_path();

    cargo_bin_cmd!("ingester")
        .args([
            "ingest",
            "--path",
            log_file.path().to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--geoip-city",
            city_db.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("records_inserted=1"));
}

// Test C-02: `enrich --db <path> --geoip-city <path>` exits successfully and
//            prints enriched_count.
#[test]
fn test_cli_enrich_command_succeeds() {
    // First ingest without GeoIP so geo columns are NULL.
    let log_file = write_geoip_event_json();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");

    cargo_bin_cmd!("ingester")
        .args([
            "ingest",
            "--path",
            log_file.path().to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Now run enrich.
    let city_db = test_city_db_path();
    cargo_bin_cmd!("ingester")
        .args([
            "enrich",
            "--db",
            db_path.to_str().unwrap(),
            "--geoip-city",
            city_db.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("enriched_count"));
}

// Test C-03: `enrich` reads GEOIP_CITY_PATH environment variable when --geoip-city is omitted.
#[test]
fn test_cli_enrich_uses_geoip_city_env_var() {
    let log_file = write_geoip_event_json();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");

    cargo_bin_cmd!("ingester")
        .args([
            "ingest",
            "--path",
            log_file.path().to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let city_db = test_city_db_path();
    cargo_bin_cmd!("ingester")
        .args(["enrich", "--db", db_path.to_str().unwrap()])
        // Provide GEOIP_CITY_PATH env var instead of --geoip-city flag.
        .env("GEOIP_CITY_PATH", city_db.to_str().unwrap())
        .assert()
        .success()
        .stdout(predicate::str::contains("enriched_count"));
}

// Test C-04: `enrich` with a non-existent mmdb path exits with error.
#[test]
fn test_cli_enrich_nonexistent_mmdb_shows_error() {
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");

    // Create an empty DB so the DB open itself does not fail.
    cargo_bin_cmd!("ingester")
        .args([
            "ingest",
            "--path",
            db_dir.path().to_str().unwrap(), // empty dir → 0 files
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    cargo_bin_cmd!("ingester")
        .args([
            "enrich",
            "--db",
            db_path.to_str().unwrap(),
            "--geoip-city",
            "/nonexistent/GeoLite2-City.mmdb",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

// Test C-05: `enrich` stdout contains enriched_count=N after successful run.
#[test]
fn test_cli_enrich_prints_enriched_count() {
    let log_file = write_geoip_event_json();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");

    cargo_bin_cmd!("ingester")
        .args([
            "ingest",
            "--path",
            log_file.path().to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let city_db = test_city_db_path();
    cargo_bin_cmd!("ingester")
        .args([
            "enrich",
            "--db",
            db_path.to_str().unwrap(),
            "--geoip-city",
            city_db.to_str().unwrap(),
        ])
        .assert()
        .success()
        // Output must contain "enriched_count=1" for the one ingested row.
        .stdout(predicate::str::contains("enriched_count=1"));
}
