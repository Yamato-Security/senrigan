//! CLI integration tests for the `config-import` subcommand.

use assert_cmd::cargo_bin_cmd;
use predicates::prelude::*;
use std::io::Write;
use tempfile::{NamedTempFile, TempDir};

/// Write the mini Config snapshot JSON to a temp file and return the handle.
fn write_mini_snapshot() -> NamedTempFile {
    let mut tmp = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    tmp.write_all(include_bytes!("testdata_config/config_snapshot_mini.json"))
        .unwrap();
    tmp.flush().unwrap();
    tmp
}

// Test CLI-CI-01: `ingester config-import --path <file>` succeeds and prints summary.
#[test]
fn test_cli_config_import_succeeds_and_prints_summary() {
    let snap_file = write_mini_snapshot();
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");

    cargo_bin_cmd!("ingester")
        .args([
            "config-import",
            "--path",
            snap_file.path().to_str().unwrap(),
            "--db",
            db_path.to_str().unwrap(),
            "--no-progress",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("resources_inserted"));
}

// Test CLI-CI-02: missing --path flag produces a usage error.
#[test]
fn test_cli_config_import_missing_path_shows_error() {
    let db_dir = TempDir::new().unwrap();
    let db_path = db_dir.path().join("test.db");

    cargo_bin_cmd!("ingester")
        .args(["config-import", "--db", db_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("error"));
}
