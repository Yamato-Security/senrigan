//! Pipeline for `ingester config-import`.
//!
//! Walks a directory tree (or a single file), finds AWS Config snapshot JSON
//! files, parses them, and writes records to DuckDB.
//!
//! SHA-256 deduplication via the shared `ingested_files` table prevents
//! re-ingesting unchanged files across runs.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use duckdb::Connection;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::config_db::{
    ConfigEdge, ConfigResource, ConfigSnapshot, ensure_config_tables, insert_config_edges,
    insert_config_resources, insert_config_snapshot,
};
use crate::config_parser::{ParsedSnapshot, parse_config_snapshot};
use crate::db::{batch_mark_ingested, ensure_table, fetch_ingested_files_map};
use crate::progress::ProgressReporter;

// ── Public types ──────────────────────────────────────────────────────────────

/// Statistics returned by a completed [`import_config`] run.
#[derive(Debug, Default)]
pub struct ImportStats {
    /// Files successfully parsed and inserted.
    pub files_processed: usize,
    /// Files skipped because their SHA-256 matched a previous ingestion.
    pub files_skipped: usize,
    /// Resources inserted across all processed files.
    pub resources_inserted: usize,
    /// Edges inserted (dangling edges whose target is absent are excluded).
    pub edges_inserted: usize,
    /// Files or rows that produced a non-fatal error.
    pub errors: usize,
    /// Wall-clock time for the entire run.
    pub elapsed_secs: f64,
}

/// Options for the `config-import` pipeline.
pub struct ImportOptions {
    pub show_progress: bool,
}

// ── Pipeline entry point ──────────────────────────────────────────────────────

/// Import all Config snapshot JSON files found under `path` into `conn`.
///
/// Files are discovered by walking the directory tree and selecting entries
/// with a `.json` extension.  When `path` is a file, it is processed directly
/// (only if its extension is `.json`).
///
/// Already-ingested files (matched by SHA-256 in `ingested_files`) are
/// skipped without re-parsing.  Errors for individual files are logged to
/// stderr and counted in [`ImportStats::errors`]; they do not abort the run.
pub fn import_config(path: &Path, conn: &Connection, opts: ImportOptions) -> Result<ImportStats> {
    // Ensure both the CloudTrail tables (for ingested_files) and Config tables exist.
    ensure_table(conn).context("Failed to ensure ingested_files table")?;
    ensure_config_tables(conn).context("Failed to ensure Config tables")?;

    let ingested_map = fetch_ingested_files_map(conn).context("Failed to load ingested_files")?;

    let files = collect_json_files(path);
    let total = files.len() as u64;

    let reporter = if opts.show_progress {
        ProgressReporter::new(total)
    } else {
        ProgressReporter::hidden()
    };

    let start = Instant::now();
    let mut stats = ImportStats::default();
    let mut newly_ingested: Vec<(String, String)> = Vec::new();

    for file_path in &files {
        let path_str = file_path.to_string_lossy().to_string();

        // ── SHA-256 deduplication ─────────────────────────────────────────
        let sha = match compute_sha256(file_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("warn: sha256 failed for {path_str}: {e:#}");
                stats.errors += 1;
                reporter.inc(0);
                continue;
            }
        };

        if ingested_map.get(&path_str).map(String::as_str) == Some(sha.as_str()) {
            stats.files_skipped += 1;
            reporter.inc(0);
            continue;
        }

        // ── Read & parse ──────────────────────────────────────────────────
        let data = match std::fs::read(file_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("warn: cannot read {path_str}: {e:#}");
                stats.errors += 1;
                reporter.inc(0);
                continue;
            }
        };

        let parsed: ParsedSnapshot = match parse_config_snapshot(&data) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("warn: parse failed for {path_str}: {e:#}");
                stats.errors += 1;
                reporter.inc(0);
                continue;
            }
        };

        // ── Insert snapshot metadata ──────────────────────────────────────
        let account_id = parsed.resources.first().and_then(|r| r.account_id.clone());
        let aws_region = parsed.resources.first().and_then(|r| r.aws_region.clone());
        let captured_at = parsed
            .resources
            .iter()
            .filter_map(|r| r.captured_at.as_deref())
            .max()
            .map(str::to_string);
        let record_count = parsed.resources.len() as i64;

        let snap = ConfigSnapshot {
            snapshot_id: parsed.snapshot_id.clone(),
            account_id,
            aws_region,
            captured_at,
            source_path: path_str.clone(),
            record_count,
        };
        let snapshot_inserted = match insert_config_snapshot(conn, &snap) {
            Ok(inserted) => inserted,
            Err(e) => {
                eprintln!("warn: insert snapshot failed for {path_str}: {e:#}");
                stats.errors += 1;
                reporter.inc(0);
                continue;
            }
        };

        // When the snapshot_id already existed (INSERT OR IGNORE skipped the row),
        // check whether resources are already present for this snapshot.
        // If they are, the import is complete — skip to avoid a PRIMARY KEY violation
        // and mark the file as ingested so future runs skip it via SHA-256.
        // If resources are absent (partial prior failure), fall through and insert them.
        if !snapshot_inserted {
            let resource_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM config_resources WHERE snapshot_id = ?",
                    [&parsed.snapshot_id],
                    |r| r.get(0),
                )
                .unwrap_or(0);

            if resource_count > 0 {
                reporter.inc(0);
                stats.files_processed += 1;
                newly_ingested.push((path_str, sha));
                continue;
            }
            // Resources are missing despite snapshot existing (partial prior failure).
            // Fall through to re-insert resources and edges.
        }

        // ── Insert resources ──────────────────────────────────────────────
        let resources: Vec<ConfigResource> = parsed
            .resources
            .iter()
            .map(|r| ConfigResource {
                resource_id: r.resource_id.clone(),
                snapshot_id: parsed.snapshot_id.clone(),
                resource_type: r.resource_type.clone(),
                aws_region: r.aws_region.clone(),
                resource_name: r.resource_name.clone(),
                configuration: r.configuration.clone(),
                tags: r.tags.clone(),
            })
            .collect();

        if let Err(e) = insert_config_resources(conn, &resources) {
            eprintln!("warn: insert resources failed for {path_str}: {e:#}");
            stats.errors += 1;
            reporter.inc(0);
            continue;
        }
        stats.resources_inserted += resources.len();

        // ── Insert edges (filter dangling: target must exist in snapshot) ─
        let resource_ids: HashSet<&str> = parsed
            .resources
            .iter()
            .map(|r| r.resource_id.as_str())
            .collect();

        let edges: Vec<ConfigEdge> = parsed
            .edges
            .iter()
            .filter(|e| resource_ids.contains(e.target_id.as_str()))
            .map(|e| ConfigEdge {
                snapshot_id: parsed.snapshot_id.clone(),
                source_id: e.source_id.clone(),
                target_id: e.target_id.clone(),
                edge_type: e.edge_type.clone(),
            })
            .collect();

        if let Err(e) = insert_config_edges(conn, &edges) {
            eprintln!("warn: insert edges failed for {path_str}: {e:#}");
            stats.errors += 1;
            reporter.inc(0);
            continue;
        }
        stats.edges_inserted += edges.len();

        reporter.inc(resources.len());
        stats.files_processed += 1;
        newly_ingested.push((path_str, sha));
    }

    // Flush all newly-ingested file records in one batch.
    batch_mark_ingested(conn, &newly_ingested).context("Failed to record ingested files")?;

    reporter.finish();
    stats.elapsed_secs = start.elapsed().as_secs_f64();
    Ok(stats)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Collect all `.json` files reachable under `root`.
///
/// When `root` is a file with a `.json` extension, it is returned directly.
fn collect_json_files(root: &Path) -> Vec<PathBuf> {
    if root.is_file() {
        return if root.extension().and_then(|e| e.to_str()) == Some("json") {
            vec![root.to_path_buf()]
        } else {
            vec![]
        };
    }
    WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
        .map(|e| e.path().to_path_buf())
        .collect()
}

/// Compute the hex-encoded SHA-256 digest of a file on disk.
fn compute_sha256(path: &Path) -> Result<String> {
    let data = std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let digest = Sha256::digest(&data);
    Ok(hex::encode(digest))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::temp_db;
    use std::io::Write;
    use tempfile::TempDir;

    /// Minimal two-resource Config snapshot used across pipeline tests.
    const MINI_JSON: &[u8] = br#"{
        "fileVersion": "1.0",
        "configSnapshotId": "snap-001",
        "configurationItems": [
            {
                "relationships": [
                    {"resourceId": "sg-aaaa", "resourceType": "AWS::EC2::SecurityGroup", "name": "Is associated with "}
                ],
                "configuration": {"instanceType": "t3.micro"},
                "tags": {"Name": "web-server"},
                "configurationItemCaptureTime": "2026-01-01T00:00:00.000Z",
                "awsAccountId": "123456789012",
                "resourceType": "AWS::EC2::Instance",
                "resourceId":   "i-12345",
                "resourceName": "web-server",
                "awsRegion":    "ap-northeast-1"
            },
            {
                "relationships": [],
                "configuration": {"groupId": "sg-aaaa"},
                "tags": {},
                "configurationItemCaptureTime": "2026-01-01T00:00:00.000Z",
                "awsAccountId": "123456789012",
                "resourceType": "AWS::EC2::SecurityGroup",
                "resourceId":   "sg-aaaa",
                "resourceName": "web-sg",
                "awsRegion":    "ap-northeast-1"
            }
        ]
    }"#;

    fn write_file(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
        path
    }

    fn opts() -> ImportOptions {
        ImportOptions {
            show_progress: false,
        }
    }

    // Test CI-01: import_config inserts resources and edges from a single JSON file.
    #[test]
    fn test_import_config_inserts_resources_and_edges() {
        let dir = TempDir::new().unwrap();
        write_file(&dir, "snap.json", MINI_JSON);

        let conn = temp_db();
        let stats = import_config(dir.path(), &conn, opts()).unwrap();

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.resources_inserted, 2);
        assert_eq!(
            stats.edges_inserted, 1,
            "only the intra-snapshot edge should be kept"
        );
        assert_eq!(stats.errors, 0);
    }

    // Test CI-02: a file already tracked in ingested_files (same SHA-256) is skipped.
    #[test]
    fn test_import_config_skips_duplicate_file() {
        let dir = TempDir::new().unwrap();
        write_file(&dir, "snap.json", MINI_JSON);

        let conn = temp_db();
        // First run ingests the file.
        import_config(dir.path(), &conn, opts()).unwrap();
        // Second run should skip it.
        let stats2 = import_config(dir.path(), &conn, opts()).unwrap();

        assert_eq!(stats2.files_processed, 0);
        assert_eq!(stats2.files_skipped, 1);
    }

    // Test CI-03: malformed JSON is counted as an error; the run still succeeds.
    #[test]
    fn test_import_config_handles_malformed_json() {
        let dir = TempDir::new().unwrap();
        write_file(&dir, "bad.json", b"not json {{{");

        let conn = temp_db();
        let stats = import_config(dir.path(), &conn, opts()).unwrap();

        assert_eq!(stats.files_processed, 0);
        assert_eq!(stats.errors, 1, "malformed JSON must increment error count");
    }

    // Test CI-04: non-JSON files in the directory are silently ignored.
    #[test]
    fn test_import_config_ignores_non_json_files() {
        let dir = TempDir::new().unwrap();
        write_file(&dir, "snap.json", MINI_JSON);
        std::fs::write(dir.path().join("readme.txt"), "not json").unwrap();

        let conn = temp_db();
        let stats = import_config(dir.path(), &conn, opts()).unwrap();

        assert_eq!(
            stats.files_processed, 1,
            "only the .json file should be processed"
        );
    }

    // Test CI-05: edges whose target is absent from the snapshot are dropped (dangling edge filter).
    #[test]
    fn test_import_config_drops_dangling_edges() {
        let json = br#"{
            "configSnapshotId": "snap-dangling",
            "configurationItems": [
                {
                    "relationships": [
                        {"resourceId": "i-9999", "name": "Is associated with "}
                    ],
                    "configuration": null,
                    "tags": null,
                    "awsAccountId": "123456789012",
                    "resourceType": "AWS::EC2::Instance",
                    "resourceId":   "i-12345",
                    "awsRegion":    "ap-northeast-1"
                }
            ]
        }"#;
        let dir = TempDir::new().unwrap();
        write_file(&dir, "snap.json", json);

        let conn = temp_db();
        let stats = import_config(dir.path(), &conn, opts()).unwrap();

        assert_eq!(
            stats.edges_inserted, 0,
            "dangling edge (target i-9999 not in snapshot) must be filtered"
        );
        assert_eq!(stats.resources_inserted, 1);
    }

    // Test CI-06: when snapshot_id already exists in config_snapshots but the file
    // is not yet tracked in ingested_files (e.g. partial prior import), the second
    // run completes without error and marks the file as ingested.
    #[test]
    fn test_import_config_handles_existing_snapshot_id_gracefully() {
        let dir = TempDir::new().unwrap();
        write_file(&dir, "snap.json", MINI_JSON);

        let conn = temp_db();
        // First run: ingest normally.
        let stats1 = import_config(dir.path(), &conn, opts()).unwrap();
        assert_eq!(stats1.files_processed, 1);
        assert_eq!(stats1.errors, 0);

        // Simulate a subsequent run where ingested_files was cleared but config_snapshots
        // still has the data. Remove the ingested_files record to force reprocessing.
        conn.execute_batch("DELETE FROM ingested_files").unwrap();

        // Second run: snapshot_id already in config_snapshots — must NOT produce a PK error.
        let stats2 = import_config(dir.path(), &conn, opts()).unwrap();
        assert_eq!(
            stats2.errors, 0,
            "re-processing a file whose snapshot_id already exists must not error"
        );
        assert_eq!(
            stats2.files_processed, 1,
            "file should be counted as processed (idempotent re-entry)"
        );

        // Verify the file is now tracked so the next run skips it.
        let stats3 = import_config(dir.path(), &conn, opts()).unwrap();
        assert_eq!(stats3.files_skipped, 1);
    }

    // Test CI-07: snapshot exists in config_snapshots but resources are absent
    // (partial-failure state from a prior run).  import_config must re-insert
    // the resources without erroring out.
    #[test]
    fn test_import_config_recovers_missing_resources_after_partial_failure() {
        let dir = TempDir::new().unwrap();
        write_file(&dir, "snap.json", MINI_JSON);

        let conn = temp_db();

        // Simulate partial-failure state: snapshot row exists but no resources.
        import_config(dir.path(), &conn, opts()).unwrap(); // normal first run
        // Manually wipe resources and ingested_files to reproduce partial-failure state.
        conn.execute_batch(
            "DELETE FROM config_resources; DELETE FROM config_edges; DELETE FROM ingested_files;",
        )
        .unwrap();

        // Counts after simulated partial failure.
        let res_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM config_resources", [], |r| r.get(0))
            .unwrap();
        assert_eq!(res_count, 0, "setup: resources must be empty");

        // Recovery run: should re-insert resources without any error.
        let stats = import_config(dir.path(), &conn, opts()).unwrap();
        assert_eq!(stats.errors, 0, "recovery run must not produce any errors");
        assert_eq!(
            stats.resources_inserted, 2,
            "both resources must be re-inserted"
        );
        assert_eq!(stats.edges_inserted, 1, "edge must be re-inserted");

        // Next run should skip (file now tracked in ingested_files).
        let stats2 = import_config(dir.path(), &conn, opts()).unwrap();
        assert_eq!(stats2.files_skipped, 1);
    }
}
