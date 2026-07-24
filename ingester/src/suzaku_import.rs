//! Pipeline for `ingester suzaku-import`.
//!
//! Walks a directory tree (or takes a single file), finds Suzaku `.duckdb`
//! timeline outputs, and normalises their rows into the `suzaku_detections`
//! and `suzaku_detection_tags` tables of the Senrigan database.
//!
//! Suzaku is run separately — `suzaku aws-ct-timeline -d <logs> -o result
//! -t duckdb` — and writes a `result.duckdb` file holding one `timeline`
//! table.  That file is opened **read-only** here; Senrigan never writes to
//! Suzaku's output, and the ingester remains the sole writer of its own
//! database.
//!
//! Two layers of idempotency:
//!
//! * SHA-256 deduplication through the shared `ingested_files` table skips a
//!   file whose content has not changed since the last run.
//! * When a file *has* changed (or is re-imported from a new path), every row
//!   previously loaded from that SHA is deleted before the new rows are
//!   appended, so a re-import replaces rather than duplicates.

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use duckdb::{AccessMode, Config, Connection};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::db::{batch_mark_ingested, ensure_table, fetch_ingested_files_map};
use crate::progress::ProgressReporter;
use crate::suzaku_db::{
    SuzakuDetection, SuzakuDetectionTag, delete_detections_for_source, ensure_suzaku_tables,
    insert_suzaku_detection_tags, insert_suzaku_detections,
};
use crate::suzaku_parser::{SuzakuProfile, tag_rows};

/// Name of the single table Suzaku writes into its DuckDB output.
const SUZAKU_TABLE: &str = "timeline";

// ── Public types ──────────────────────────────────────────────────────────────

/// Statistics returned by a completed [`import_suzaku`] run.
#[derive(Debug, Default)]
pub struct SuzakuImportStats {
    /// Files successfully read and imported.
    pub files_processed: usize,
    /// Files skipped because their SHA-256 matched a previous import.
    pub files_skipped: usize,
    /// Detection rows written to `suzaku_detections`.
    pub detections_inserted: usize,
    /// Tag rows written to `suzaku_detection_tags`.
    pub tags_inserted: usize,
    /// Rows removed because a changed file replaced an earlier import.
    pub detections_replaced: usize,
    /// Files that produced a non-fatal error.
    pub errors: usize,
    /// Wall-clock time for the entire run.
    pub elapsed_secs: f64,
}

/// Options for the `suzaku-import` pipeline.
pub struct SuzakuImportOptions {
    pub show_progress: bool,
}

// ── Pipeline entry point ──────────────────────────────────────────────────────

/// Import every Suzaku `.duckdb` timeline found under `path` into `conn`.
///
/// When `path` is a file it is imported directly (regardless of extension, so
/// an output saved under another name still works).  Errors for individual
/// files — an unreadable database, a file with no `timeline` table — are
/// reported on stderr and counted in [`SuzakuImportStats::errors`]; they never
/// abort the run.
pub fn import_suzaku(
    path: &Path,
    conn: &Connection,
    opts: SuzakuImportOptions,
) -> Result<SuzakuImportStats> {
    // `ingested_files` lives with the CloudTrail tables and is shared by every
    // importer, so both schemas have to exist before the first lookup.
    ensure_table(conn).context("Failed to ensure ingested_files table")?;
    ensure_suzaku_tables(conn).context("Failed to ensure Suzaku detection tables")?;

    let ingested_map = fetch_ingested_files_map(conn).context("Failed to load ingested_files")?;

    let files = collect_suzaku_files(path);
    let reporter = if opts.show_progress {
        ProgressReporter::new(files.len() as u64)
    } else {
        ProgressReporter::hidden()
    };

    let start = Instant::now();
    let mut stats = SuzakuImportStats::default();
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

        // ── Read the Suzaku timeline ──────────────────────────────────────
        let (detections, tags) = match read_timeline(file_path, &path_str, &sha) {
            Ok(rows) => rows,
            Err(e) => {
                eprintln!("warn: cannot read Suzaku timeline {path_str}: {e:#}");
                stats.errors += 1;
                reporter.inc(0);
                continue;
            }
        };

        // ── Replace anything previously loaded from this file ─────────────
        match delete_detections_for_source(conn, &path_str, &sha) {
            Ok(removed) => stats.detections_replaced += removed,
            Err(e) => {
                eprintln!("warn: cannot clear previous rows for {path_str}: {e:#}");
                stats.errors += 1;
                reporter.inc(0);
                continue;
            }
        }

        if let Err(e) = insert_suzaku_detections(conn, &detections) {
            eprintln!("warn: insert detections failed for {path_str}: {e:#}");
            stats.errors += 1;
            reporter.inc(0);
            continue;
        }
        if let Err(e) = insert_suzaku_detection_tags(conn, &tags) {
            eprintln!("warn: insert detection tags failed for {path_str}: {e:#}");
            stats.errors += 1;
            reporter.inc(0);
            continue;
        }

        stats.detections_inserted += detections.len();
        stats.tags_inserted += tags.len();
        stats.files_processed += 1;
        newly_ingested.push((path_str, sha));
        reporter.inc(detections.len());
    }

    batch_mark_ingested(conn, &newly_ingested).context("Failed to record imported files")?;

    reporter.finish();
    stats.elapsed_secs = start.elapsed().as_secs_f64();
    Ok(stats)
}

// ── Reading ───────────────────────────────────────────────────────────────────

/// Read and normalise every row of one Suzaku `.duckdb` file.
///
/// Returns the detection rows together with their exploded tag rows.
fn read_timeline(
    file_path: &Path,
    path_str: &str,
    sha: &str,
) -> Result<(Vec<SuzakuDetection>, Vec<SuzakuDetectionTag>)> {
    // Read-only: Suzaku's output is an input to Senrigan, never a target.
    let config = Config::default()
        .access_mode(AccessMode::ReadOnly)
        .context("Failed to build read-only DuckDB config")?;
    let src = Connection::open_with_flags(file_path, config)
        .with_context(|| format!("Failed to open {}", file_path.display()))?;

    let columns = timeline_columns(&src)?;
    let profile = SuzakuProfile::new(columns);

    // Every Suzaku column is already VARCHAR, but the CAST makes that explicit
    // so a future profile carrying a typed column still reads as a string
    // instead of failing the whole file.
    let projection = profile
        .columns()
        .iter()
        .map(|c| format!("CAST({} AS VARCHAR)", quote_ident(c)))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!("SELECT {projection} FROM {SUZAKU_TABLE}");

    let mut stmt = src
        .prepare(&sql)
        .with_context(|| format!("Failed to query {SUZAKU_TABLE} in {path_str}"))?;
    let column_count = profile.columns().len();
    let mut rows = stmt
        .query([])
        .with_context(|| format!("Failed to read {SUZAKU_TABLE} in {path_str}"))?;

    let mut detections = Vec::new();
    let mut tags = Vec::new();
    let mut row_index = 0usize;
    while let Some(row) = rows.next().context("Failed to advance timeline cursor")? {
        let mut values: Vec<Option<String>> = Vec::with_capacity(column_count);
        for i in 0..column_count {
            values.push(row.get::<_, Option<String>>(i).unwrap_or(None));
        }
        let detection = profile.map_row(&values, path_str, sha, row_index);
        tags.extend(tag_rows(&detection));
        detections.push(detection);
        row_index += 1;
    }

    Ok((detections, tags))
}

/// Column names of the `timeline` table, in profile order.
///
/// Errors when the file holds no such table — that is the signal that it is
/// not a Suzaku output (or was produced by a future version using a different
/// layout), and it is reported per file rather than aborting the run.
fn timeline_columns(src: &Connection) -> Result<Vec<String>> {
    let mut stmt = src
        .prepare(
            "SELECT column_name FROM information_schema.columns
             WHERE table_name = ? ORDER BY ordinal_position",
        )
        .context("Failed to prepare column lookup")?;
    let columns: Vec<String> = stmt
        .query_map([SUZAKU_TABLE], |row| row.get::<_, String>(0))
        .context("Failed to read column metadata")?
        .collect::<std::result::Result<Vec<String>, duckdb::Error>>()
        .context("Failed to collect column metadata")?;

    if columns.is_empty() {
        anyhow::bail!(
            "no '{SUZAKU_TABLE}' table found — is this a Suzaku '-t duckdb' output file?"
        );
    }
    Ok(columns)
}

/// Quote an identifier for use in SQL, doubling any embedded quote.
///
/// Suzaku column names come from a user-editable output profile, so they can
/// legitimately contain characters that need quoting (`AWS-Region` already
/// does).
fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Collect Suzaku output databases reachable under `root`.
///
/// A directory is walked for `.duckdb` files; a path that is itself a file is
/// taken as-is, so an output saved under a different extension can still be
/// imported by naming it explicitly.
fn collect_suzaku_files(root: &Path) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    let mut files: Vec<PathBuf> = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("duckdb"))
        .map(|e| e.path().to_path_buf())
        .collect();
    // WalkDir order is filesystem-dependent; sort so row indices — and thus
    // detection IDs — are reproducible across runs and platforms.
    files.sort();
    files
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
    use tempfile::TempDir;

    /// Column list of Suzaku's `config/aws_profile.yaml`, plus the GeoIP
    /// columns `--geo-ip` appends.
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

    const AZURE_COLUMNS: &[&str] = &[
        "Timestamp",
        "RuleTitle",
        "Level",
        "Workload",
        "Operation",
        "RecordType",
        "Result",
        "User",
        "SrcIP",
        "TargetObject",
        "UserAgent",
        "AppId",
        "LogonError",
        "Details",
        "Category",
        "CorrelationId",
        "RuleAuthor",
        "Tags",
        "RuleID",
    ];

    /// Build a Suzaku-shaped `.duckdb` file: one all-VARCHAR `timeline` table,
    /// exactly what `DuckDbSink` in Suzaku's `timeline_writer.rs` produces.
    fn write_suzaku_db(path: &Path, columns: &[&str], rows: &[Vec<String>]) {
        let conn = Connection::open(path).expect("create suzaku db");
        let ddl = columns
            .iter()
            .map(|c| format!("\"{c}\" VARCHAR"))
            .collect::<Vec<_>>()
            .join(", ");
        conn.execute_batch(&format!("CREATE OR REPLACE TABLE timeline ({ddl});"))
            .expect("create timeline table");
        let placeholders = vec!["?"; columns.len()].join(", ");
        for row in rows {
            conn.execute(
                &format!("INSERT INTO timeline VALUES ({placeholders})"),
                duckdb::params_from_iter(row.iter()),
            )
            .expect("insert timeline row");
        }
    }

    fn row(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    /// One AWS-profile detection row, varying only the fields the tests assert on.
    fn aws_row(timestamp: &str, level: &str, rule: &str, tags: &str) -> Vec<String> {
        row(&[
            timestamp,
            rule,
            "Yamato Security",
            level,
            "DeleteTrail",
            "AccessDenied",
            "not authorized",
            "cloudtrail.amazonaws.com",
            "us-east-1",
            "203.0.113.7",
            "AS64500",
            "Tokyo",
            "Japan",
            "aws-cli/2.17.32",
            "TrailDiscover",
            "IAMUser",
            "111111111111",
            "arn:aws:iam::111111111111:user/TrailDiscover",
            "AROA1234:User",
            "AKIA1234",
            "1d8eaf44-b4ac-41b7-b40e-377ba7e11a82",
            tags,
            "25cb1ba1-8a19-4a23-a198-d252664c8cef",
        ])
    }

    fn opts() -> SuzakuImportOptions {
        SuzakuImportOptions {
            show_progress: false,
        }
    }

    fn count(conn: &Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    // Test SI-01: a Suzaku AWS timeline imports into both normalised tables.
    #[test]
    fn test_import_suzaku_loads_detections_and_tags() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("aws.duckdb");
        write_suzaku_db(
            &src,
            AWS_COLUMNS,
            &[
                aws_row(
                    "2024-08-18 10:07:56",
                    "critical",
                    "Rule A",
                    "Impact ¦ T1485",
                ),
                aws_row("2024-08-18 11:00:00", "medium", "Rule B", "Disc"),
            ],
        );

        let conn = temp_db();
        let stats = import_suzaku(&src, &conn, opts()).expect("import should succeed");

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.detections_inserted, 2);
        assert_eq!(stats.tags_inserted, 3, "2 tags on Rule A + 1 on Rule B");
        assert_eq!(stats.errors, 0);
        assert_eq!(count(&conn, "suzaku_detections"), 2);
        assert_eq!(count(&conn, "suzaku_detection_tags"), 3);

        let (level, rank, provider, country): (String, i32, String, String) = conn
            .query_row(
                "SELECT level, level_rank, cloud_provider, src_country
                 FROM suzaku_detections ORDER BY detected_at LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(level, "critical");
        assert_eq!(rank, 5);
        assert_eq!(provider, "aws");
        assert_eq!(country, "Japan");
    }

    // Test SI-02: re-importing an unchanged file is skipped via SHA-256 and
    // does not duplicate rows.
    #[test]
    fn test_reimport_of_unchanged_file_is_skipped() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("aws.duckdb");
        write_suzaku_db(
            &src,
            AWS_COLUMNS,
            &[aws_row("2024-08-18 10:07:56", "high", "Rule A", "Impact")],
        );

        let conn = temp_db();
        import_suzaku(&src, &conn, opts()).unwrap();
        let second = import_suzaku(&src, &conn, opts()).expect("second import should succeed");

        assert_eq!(second.files_skipped, 1);
        assert_eq!(second.detections_inserted, 0);
        assert_eq!(count(&conn, "suzaku_detections"), 1);
    }

    // Test SI-03: a re-run of Suzaku over more logs replaces the earlier rows
    // for that file instead of duplicating them.
    #[test]
    fn test_changed_file_replaces_previous_rows() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("aws.duckdb");
        write_suzaku_db(
            &src,
            AWS_COLUMNS,
            &[aws_row("2024-08-18 10:07:56", "high", "Rule A", "Impact")],
        );

        let conn = temp_db();
        import_suzaku(&src, &conn, opts()).unwrap();

        // Suzaku re-run: same output path, one extra detection.
        write_suzaku_db(
            &src,
            AWS_COLUMNS,
            &[
                aws_row("2024-08-18 10:07:56", "high", "Rule A", "Impact"),
                aws_row("2024-08-19 09:00:00", "low", "Rule C", "Disc"),
            ],
        );
        let second = import_suzaku(&src, &conn, opts()).expect("re-import should succeed");

        assert_eq!(second.files_skipped, 0, "content changed, so not skipped");
        assert_eq!(second.detections_inserted, 2);
        assert_eq!(
            count(&conn, "suzaku_detections"),
            2,
            "rows must be replaced, not appended twice"
        );
        assert_eq!(count(&conn, "suzaku_detection_tags"), 2);
    }

    // Test SI-04: the same Suzaku output imported from a second path (a copy
    // or a backup directory) must not collide on the detection_id PRIMARY KEY.
    #[test]
    fn test_same_output_imported_from_two_paths_is_deduplicated() {
        let dir = TempDir::new().unwrap();
        let first = dir.path().join("aws.duckdb");
        write_suzaku_db(
            &first,
            AWS_COLUMNS,
            &[aws_row("2024-08-18 10:07:56", "high", "Rule A", "Impact")],
        );
        let second = dir.path().join("backup").join("aws.duckdb");
        std::fs::create_dir_all(second.parent().unwrap()).unwrap();
        std::fs::copy(&first, &second).unwrap();

        let conn = temp_db();
        let stats = import_suzaku(dir.path(), &conn, opts()).expect("import must not fail");

        assert_eq!(
            stats.errors, 0,
            "identical content must not raise a PK error"
        );
        assert_eq!(
            count(&conn, "suzaku_detections"),
            1,
            "the same detection must be stored once, not twice"
        );
    }

    // Test SI-05: a file that is not a Suzaku output is a per-file error, not
    // a fatal one — the rest of the run continues.
    #[test]
    fn test_non_suzaku_database_is_reported_as_an_error() {
        let dir = TempDir::new().unwrap();
        let bad = dir.path().join("other.duckdb");
        {
            let other = Connection::open(&bad).unwrap();
            other
                .execute_batch("CREATE TABLE something_else (x VARCHAR);")
                .unwrap();
        }
        let good = dir.path().join("aws.duckdb");
        write_suzaku_db(
            &good,
            AWS_COLUMNS,
            &[aws_row("2024-08-18 10:07:56", "high", "Rule A", "Impact")],
        );

        let conn = temp_db();
        let stats = import_suzaku(dir.path(), &conn, opts()).expect("run must not abort");

        assert_eq!(stats.errors, 1);
        assert_eq!(stats.files_processed, 1, "the valid file still imported");
        assert_eq!(count(&conn, "suzaku_detections"), 1);
    }

    // Test SI-05: directory walking finds .duckdb files in nested directories.
    #[test]
    fn test_directory_walk_finds_nested_outputs() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("run-2024-08-18");
        std::fs::create_dir_all(&nested).unwrap();
        write_suzaku_db(
            &dir.path().join("a.duckdb"),
            AWS_COLUMNS,
            &[aws_row("2024-08-18 10:07:56", "high", "Rule A", "Impact")],
        );
        write_suzaku_db(
            &nested.join("b.duckdb"),
            AWS_COLUMNS,
            &[aws_row("2024-08-19 10:07:56", "low", "Rule B", "Disc")],
        );
        // A non-Suzaku file in the tree must be ignored, not read.
        std::fs::write(dir.path().join("notes.txt"), b"ignore me").unwrap();

        let conn = temp_db();
        let stats = import_suzaku(dir.path(), &conn, opts()).unwrap();

        assert_eq!(stats.files_processed, 2);
        assert_eq!(stats.errors, 0);
        assert_eq!(count(&conn, "suzaku_detections"), 2);
    }

    // Test SI-06: an Azure/M365 timeline imports through the same path and is
    // labelled with its own provider.
    #[test]
    fn test_azure_timeline_imports_with_azure_provider() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("azure.duckdb");
        write_suzaku_db(
            &src,
            AZURE_COLUMNS,
            &[row(&[
                "2024-03-01 05:00:00",
                "Add member to role.",
                "high",
                "AzureActiveDirectory",
                "Add member to role.",
                "8",
                "Success",
                "attacker@contoso.com",
                "198.51.100.9",
                "Global Administrator",
                "azurehound/v2",
                "1b730954-1685-4b74-9bfd-dac224a7b894",
                "-",
                "role assignment",
                "AzureActiveDirectory",
                "0f1b2c3d-4e5f-6789-abcd-ef0123456789",
                "Yamato Security",
                "PrivEsc ¦ T1098.003",
                "aa11bb22-cc33-dd44-ee55-ff6677889900",
            ])],
        );

        let conn = temp_db();
        import_suzaku(&src, &conn, opts()).unwrap();

        let (provider, event_name, outcome): (String, String, String) = conn
            .query_row(
                "SELECT cloud_provider, event_name, outcome FROM suzaku_detections",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(provider, "azure");
        assert_eq!(event_name, "Add member to role.");
        assert_eq!(outcome, "Success");

        let tag_types: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM suzaku_detection_tags WHERE tag_type = 'technique'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tag_types, 1);
    }

    // Test SI-07: a Suzaku run with no hits (empty timeline) imports cleanly.
    #[test]
    fn test_empty_timeline_imports_without_error() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("empty.duckdb");
        write_suzaku_db(&src, AWS_COLUMNS, &[]);

        let conn = temp_db();
        let stats = import_suzaku(&src, &conn, opts()).expect("import should succeed");

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.detections_inserted, 0);
        assert_eq!(stats.errors, 0);
    }

    // Test SI-08: importing does not modify the Suzaku output file — it is
    // opened read-only, so its SHA-256 is unchanged afterwards.
    #[test]
    fn test_source_file_is_not_modified() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("aws.duckdb");
        write_suzaku_db(
            &src,
            AWS_COLUMNS,
            &[aws_row("2024-08-18 10:07:56", "high", "Rule A", "Impact")],
        );
        let before = compute_sha256(&src).unwrap();

        let conn = temp_db();
        import_suzaku(&src, &conn, opts()).unwrap();

        assert_eq!(
            compute_sha256(&src).unwrap(),
            before,
            "Suzaku output must be treated as read-only input"
        );
    }

    // Test SI-09: an empty directory is a no-op rather than an error.
    #[test]
    fn test_empty_directory_is_a_noop() {
        let dir = TempDir::new().unwrap();
        let conn = temp_db();
        let stats = import_suzaku(dir.path(), &conn, opts()).unwrap();
        assert_eq!(stats.files_processed, 0);
        assert_eq!(stats.errors, 0);
        assert_eq!(count(&conn, "suzaku_detections"), 0);
    }

    // Test SI-10: collect_suzaku_files sorts, so detection IDs are stable
    // regardless of the order the filesystem hands back directory entries.
    #[test]
    fn test_collect_suzaku_files_is_sorted() {
        let dir = TempDir::new().unwrap();
        for name in ["c.duckdb", "a.duckdb", "b.duckdb"] {
            std::fs::write(dir.path().join(name), b"").unwrap();
        }
        let files = collect_suzaku_files(dir.path());
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(names, vec!["a.duckdb", "b.duckdb", "c.duckdb"]);
    }
}
