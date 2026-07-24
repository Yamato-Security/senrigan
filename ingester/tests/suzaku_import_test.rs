//! CLI integration tests for the `suzaku-import` subcommand.

use assert_cmd::cargo_bin_cmd;
use duckdb::Connection;
use predicates::prelude::*;
use std::path::Path;
use tempfile::TempDir;

/// Columns of Suzaku's `config/aws_profile.yaml` (with the `--geo-ip` additions).
const AWS_COLUMNS: &[&str] = &[
    "Timestamp",
    "RuleTitle",
    "RuleAuthor",
    "Level",
    "EventName",
    "ErrorCode",
    "ErrorMessage",
    "EventSource",
    "AWS-Region",
    "SrcIP",
    "SrcASN",
    "SrcCity",
    "SrcCountry",
    "UserAgent",
    "UserName",
    "UserType",
    "UserAccountID",
    "UserARN",
    "UserPrincipalID",
    "UserAccessKeyID",
    "EventID",
    "Tags",
    "RuleID",
];

/// Write a Suzaku-shaped `.duckdb` output: one all-VARCHAR `timeline` table,
/// matching what `DuckDbSink` in Suzaku's `timeline_writer.rs` produces.
fn write_suzaku_output(path: &Path) {
    let conn = Connection::open(path).expect("create suzaku output");
    let ddl = AWS_COLUMNS
        .iter()
        .map(|c| format!("\"{c}\" VARCHAR"))
        .collect::<Vec<_>>()
        .join(", ");
    conn.execute_batch(&format!("CREATE OR REPLACE TABLE timeline ({ddl});"))
        .expect("create timeline table");
    let values = [
        "2024-08-18 10:07:56",
        "AWS CloudTrail Important Change",
        "vitaliy0x1",
        "high",
        "StopLogging",
        "-",
        "-",
        "cloudtrail.amazonaws.com",
        "us-east-1",
        "203.0.113.7",
        "-",
        "-",
        "-",
        "aws-cli/2.17.32",
        "TrailDiscover",
        "IAMUser",
        "111111111111",
        "arn:aws:iam::111111111111:user/TrailDiscover",
        "AROA1234:User",
        "AKIA1234",
        "1d8eaf44-b4ac-41b7-b40e-377ba7e11a82",
        "Stealth ¦ T1562.008",
        "4d50ab30-a04d-11ee-8c90-0242ac120002",
    ];
    let placeholders = vec!["?"; AWS_COLUMNS.len()].join(", ");
    conn.execute(
        &format!("INSERT INTO timeline VALUES ({placeholders})"),
        duckdb::params_from_iter(values.iter()),
    )
    .expect("insert timeline row");
}

// Test CLI-SI-01: `ingester suzaku-import --path <file>` succeeds and prints a summary.
#[test]
fn test_cli_suzaku_import_succeeds_and_prints_summary() {
    let dir = TempDir::new().unwrap();
    let src = dir.path().join("aws_detections.duckdb");
    write_suzaku_output(&src);
    let db_path = dir.path().join("test.db");

    cargo_bin_cmd!("ingester")
        .args([
            "suzaku-import",
            "--path",
            src.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--no-progress",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("detections_inserted=1"))
        .stdout(predicate::str::contains("tags_inserted=2"));
}

// Test CLI-SI-02: the imported rows are queryable in the normalised schema.
#[test]
fn test_cli_suzaku_import_writes_normalised_rows() {
    let dir = TempDir::new().unwrap();
    let src = dir.path().join("aws_detections.duckdb");
    write_suzaku_output(&src);
    let db_path = dir.path().join("test.db");

    cargo_bin_cmd!("ingester")
        .args([
            "suzaku-import",
            "--path",
            src.to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--no-progress",
        ])
        .assert()
        .success();

    let conn = Connection::open(&db_path).unwrap();
    let (rule, level, rank, technique): (String, String, i32, String) = conn
        .query_row(
            "SELECT d.rule_title, d.level, d.level_rank, t.tag_value
             FROM suzaku_detections d
             JOIN suzaku_detection_tags t USING (detection_id)
             WHERE t.tag_type = 'technique'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .expect("the detection and its ATT&CK technique must both be queryable");
    assert_eq!(rule, "AWS CloudTrail Important Change");
    assert_eq!(level, "high");
    assert_eq!(rank, 4);
    assert_eq!(technique, "T1562.008");
}

// Test CLI-SI-03: missing --path flag produces a usage error.
#[test]
fn test_cli_suzaku_import_missing_path_shows_error() {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");

    cargo_bin_cmd!("ingester")
        .args(["suzaku-import", "--db", db_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}

// Test CLI-SI-04: the subcommand is advertised in `--help`.
#[test]
fn test_cli_help_lists_suzaku_import() {
    cargo_bin_cmd!("ingester")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("suzaku-import"));
}
