//! Ingestion orchestration: walk a path → decompress → parse → insert into DuckDB.
//!
//! This is the top-level entry point for the ingestion pipeline.
//! It ties together [`crate::parser`] and [`crate::db`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

use anyhow::{Context, Result};
use duckdb::Connection;
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::date_filter::DateFilter;
use crate::db::{
    batch_mark_ingested, ensure_table, fetch_ingested_files_map, insert_events_with_geo,
};
use crate::field_filter::FieldFilter;
use crate::geoip::GeoipEnricher;
use crate::parser::{CloudTrailEvent, parse_cloudtrail_log};
use crate::path_filter::PathFilter;
use crate::progress::ProgressReporter;

/// Number of files parsed in parallel per chunk.
///
/// Tuning guide:
/// - Larger values → higher throughput (more parallelism) but more peak memory.
/// - Smaller values → lower peak memory but less parallelism.
///
/// At 256, worst-case peak memory per chunk is approximately
/// 256 × 1 MB (uncompressed CloudTrail file) = 256 MB — acceptable on
/// modern hardware. For memory-constrained environments set
/// `RAYON_NUM_THREADS=1` or use `--workers 1` to disable parallelism.
const PARSE_CHUNK_SIZE: usize = 256;

/// Number of pre-parsed chunks the parser thread may buffer ahead of the
/// main thread's insertion loop.
///
/// The bounded `sync_channel` capacity caps peak in-flight memory to
/// `PARSE_CHUNK_SIZE × avg_uncompressed_file_size × (1 + PIPELINE_BUFFER_DEPTH)`.
/// A value of 2 allows the parser to stay up to 2 chunks ahead of insertion
/// without wasting memory.
const PIPELINE_BUFFER_DEPTH: usize = 2;

/// Result of parsing a single file: the file's path paired with either a
/// `(sha256_hex, events)` tuple or an error.
///
/// Extracted as a type alias to avoid triggering `clippy::type_complexity` on
/// the `Vec` collected from the parallel phase.
type ParseOutcome = (PathBuf, Result<(String, Vec<CloudTrailEvent>)>);

/// Statistics returned after a completed ingestion run.
#[derive(Debug, Default)]
pub struct IngestStats {
    /// Number of files successfully processed.
    pub files_processed: usize,
    /// Total number of event records inserted into DuckDB.
    pub records_inserted: usize,
    /// Number of files that produced an error (skipped, not inserted).
    pub errors: usize,
    /// Wall-clock time for the entire run in seconds.
    pub elapsed_secs: f64,
}

/// Options controlling the ingestion pipeline.
///
/// All fields have sensible defaults — use struct-update syntax to set only
/// what you need:
///
/// ```rust,ignore
/// let stats = ingest(&path, &conn, IngestOptions {
///     show_progress: true,
///     ..Default::default()
/// })?;
/// ```
#[derive(Debug, Default)]
pub struct IngestOptions<'a> {
    /// Show a progress bar during ingestion.  Defaults to `false`.
    pub show_progress: bool,
    /// Date-range filter applied to CloudTrail log file paths.
    /// Defaults to no filter (all dates accepted).
    pub date_filter: DateFilter,
    /// Glob-pattern filter applied to CloudTrail log file paths.
    /// Defaults to no filter (all files accepted).
    pub path_filter: PathFilter,
    /// Optional GeoIP enricher for source-IP geo-enrichment.
    /// When `None`, geo columns are stored as `NULL`.
    pub geoip: Option<&'a GeoipEnricher>,
    /// Strip a fixed list of low-signal keys from
    /// `requestParameters` / `responseElements` before insert.
    /// Empty (default) → JSON is written verbatim. `raw_event` is never
    /// modified by this filter.
    pub field_filter: FieldFilter,
    /// Drop the `raw_event` column entirely (write `NULL` instead of the
    /// original JSON). Use only after Step-A field hoisting has made the
    /// raw blob unnecessary for routine investigation. Default `false`.
    pub strip_raw_event: bool,
}

/// Ingest CloudTrail log files from `path` into `conn` using the given `options`.
///
/// This is the **primary entry point** for the ingestion pipeline.
///
/// # Example
///
/// ```rust,ignore
/// let stats = ingest(&log_dir, &conn, IngestOptions::default())?;
/// ```
pub fn ingest(path: &Path, conn: &Connection, options: IngestOptions<'_>) -> Result<IngestStats> {
    ingest_core(
        path,
        conn,
        options.show_progress,
        &options.date_filter,
        &options.path_filter,
        options.geoip,
        &options.field_filter,
        options.strip_raw_event,
    )
}

/// Read a file, compute its SHA-256 digest, and parse the CloudTrail records.
///
/// Returns `(sha256_hex, records)`. This function is CPU/IO-bound and is
/// designed to be called from a `rayon` parallel iterator.
///
/// When `field_filter` is non-empty, the configured keys are stripped from
/// each record's `request_parameters` and `response_elements` JSON in this
/// function — keeping the work on the parser thread so the DuckDB writer
/// thread is never blocked on JSON re-serialisation. `raw_json` is left
/// untouched so the original event is always preserved in `raw_event`.
pub fn parse_file_content(
    path: &Path,
    field_filter: &FieldFilter,
) -> Result<(String, Vec<CloudTrailEvent>)> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let sha256 = hex::encode(Sha256::digest(&bytes));

    let content = if path.extension().and_then(|e| e.to_str()) == Some("gz") {
        use flate2::read::GzDecoder;
        use std::io::Read;
        // Pre-allocate ~5× the compressed size to minimise reallocation.
        // Typical CloudTrail gz compression ratio is 4–8×.
        // BufReader is not needed here because the source is already an
        // in-memory slice, not a system call per byte.
        let mut s = String::with_capacity(bytes.len() * 5);
        GzDecoder::new(bytes.as_slice())
            .read_to_string(&mut s)
            .with_context(|| format!("Failed to decompress {}", path.display()))?;
        s
    } else {
        String::from_utf8(bytes)
            .with_context(|| format!("File is not valid UTF-8: {}", path.display()))?
    };

    let log = parse_cloudtrail_log(&content)
        .with_context(|| format!("Failed to parse {}", path.display()))?;

    let mut records = log.records;
    if !field_filter.is_empty() {
        for ev in &mut records {
            if let Some(s) = ev.request_parameters.as_deref() {
                ev.request_parameters = Some(field_filter.apply(s));
            }
            if let Some(s) = ev.response_elements.as_deref() {
                ev.response_elements = Some(field_filter.apply(s));
            }
        }
    }
    Ok((sha256, records))
}

/// Core ingestion routine shared by all public entry points.
///
/// # Pipeline
///
/// ```text
/// Phase 0  Single DB query → HashMap<file_path, sha256>
///
/// Parser thread (OS thread)            Main thread (sole DuckDB writer)
/// ─────────────────────────            ────────────────────────────────
/// chunk[0..256]  → par_iter ──→ tx ──→ rx → dedup → INSERT(events) → batch-mark
/// chunk[256..512]→ par_iter ──→ tx        (parser blocked if buffer full)
///                                    → rx → dedup → INSERT(events) → batch-mark
/// ...
/// ```
///
/// Parse and insertion **overlap**: while the main thread inserts chunk N,
/// the parser thread is already reading and hashing files for chunk N+1.
/// The bounded channel (`PIPELINE_BUFFER_DEPTH`) caps peak memory to
/// `PARSE_CHUNK_SIZE × avg_uncompressed_file_size × (1 + PIPELINE_BUFFER_DEPTH)`.
///
/// Each chunk's `ingested_files` marks are written in a single
/// [`batch_mark_ingested`] call (one Appender flush) instead of one SQL
/// `INSERT` per file, reducing per-file SQL overhead from O(N) to O(N/chunk).
///
/// # Error handling
///
/// - Parse errors per file increment `stats.errors`; processing continues.
/// - A DuckDB insertion error causes the insertion loop to break, `rx` is
///   dropped (signalling the parser thread to exit), the parser thread is
///   joined, and then the error is propagated via `?`.
//
// Each parameter maps 1:1 to a logically distinct knob exposed via
// `IngestOptions`. Bundling them into a struct here would just push the
// same fan-out one level down without simplifying anything.
#[allow(clippy::too_many_arguments)]
fn ingest_core(
    path: &Path,
    conn: &Connection,
    show_progress: bool,
    date_filter: &DateFilter,
    path_filter: &PathFilter,
    geoip: Option<&GeoipEnricher>,
    field_filter: &FieldFilter,
    strip_raw_event: bool,
) -> Result<IngestStats> {
    ensure_table(conn)?;

    let start = Instant::now();
    let mut stats = IngestStats::default();

    // Collect candidate file paths, applying filters before any I/O.
    let files: Vec<PathBuf> = WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| is_cloudtrail_file(e.path()))
        .filter(|e| date_filter.matches(e.path()))
        .filter(|e| path_filter.matches(e.path()))
        .map(|e| e.path().to_path_buf())
        .collect();

    let reporter = if show_progress {
        ProgressReporter::new(files.len() as u64)
    } else {
        ProgressReporter::hidden()
    };

    // ── Phase 0: single bulk query instead of N per-file SELECT statements ─
    // Loading the entire ingested_files table into memory is cheap (VARCHAR
    // pairs) and eliminates the dominant per-file DB round-trip latency.
    let mut ingested_map: HashMap<String, String> = fetch_ingested_files_map(conn)?;

    // ── Pipelined parse/insert ─────────────────────────────────────────────
    // A bounded sync_channel provides backpressure: the parser thread blocks
    // when PIPELINE_BUFFER_DEPTH chunks are awaiting insertion, preventing
    // unbounded memory growth.
    let (tx, rx) = mpsc::sync_channel::<Vec<ParseOutcome>>(PIPELINE_BUFFER_DEPTH);

    // Parser thread: owns `files`, chunks it, runs par_iter() per chunk, and
    // sends Vec<ParseOutcome> through the channel.  It never touches DuckDB
    // (Connection is !Send), so the !Send constraint is satisfied.
    //
    // The field filter is cloned into the parser thread so that JSON
    // stripping (when enabled) runs in parallel with the file-read /
    // decompression / parse phases. When the filter is empty
    // (`is_empty()` is true) the call is a zero-cost no-op.
    let parser_filter = field_filter.clone();
    let parser_handle = thread::spawn(move || {
        for chunk in files.chunks(PARSE_CHUNK_SIZE) {
            // Parallel phase: read bytes → SHA-256 → decompress → parse JSON.
            let results: Vec<ParseOutcome> = chunk
                .par_iter()
                .map(|p| (p.clone(), parse_file_content(p, &parser_filter)))
                .collect();
            if tx.send(results).is_err() {
                // Receiver dropped (main thread error-exited) — stop silently.
                break;
            }
        }
        // tx dropped here → rx.recv() returns Err → insertion loop exits.
    });

    // Main thread: receive parsed chunks and insert into DuckDB serially.
    // A labelled loop allows an insertion error to break both the inner
    // (per-file) and outer (per-chunk) loops cleanly before cleanup.
    let mut insert_result: Result<()> = Ok(());
    'recv: while let Ok(parse_results) = rx.recv() {
        // Accumulate (file_path, sha256) pairs for chunk-level batch marking.
        // Replacing N individual `INSERT OR REPLACE` SQL statements (one per
        // file) with a single Appender flush at the end of the chunk.
        let mut chunk_new_files: Vec<(String, String)> = Vec::new();

        for (file_path, result) in parse_results {
            let path_key = file_path.to_string_lossy().to_string();
            // Capture any insertion error separately so that reporter.inc()
            // is always called — even for the file that triggers a DB error.
            let insert_error: Option<anyhow::Error> = match result {
                Err(_e) => {
                    stats.errors += 1;
                    None
                }
                Ok((sha256, records)) => {
                    if ingested_map.get(&path_key).map(String::as_str) == Some(sha256.as_str()) {
                        // Already ingested with the same checksum — skip.
                        stats.files_processed += 1;
                        None
                    } else {
                        match insert_events_with_geo(conn, &records, geoip, strip_raw_event) {
                            Ok(inserted) => {
                                stats.files_processed += 1;
                                stats.records_inserted += inserted;
                                // Keep the in-memory map current so within-run
                                // duplicates are caught without extra DB queries.
                                ingested_map.insert(path_key.clone(), sha256.clone());
                                // Queue for chunk-level batch marking.
                                chunk_new_files.push((path_key, sha256));
                                None
                            }
                            Err(e) => Some(e),
                        }
                    }
                }
            };
            // Always advance the bar — regardless of whether the file
            // succeeded, was a dedup-skip, or triggered a DB error.
            reporter.inc(stats.records_inserted);
            if let Some(e) = insert_error {
                insert_result = Err(e);
                break 'recv;
            }
        }

        // Batch-mark all new files in this chunk with a single Appender flush
        // instead of N individual `INSERT OR REPLACE` SQL statements.
        if let Err(e) = batch_mark_ingested(conn, &chunk_new_files) {
            insert_result = Err(e);
            break 'recv;
        }
    }

    // Drop rx before joining to unblock a parser thread that may be blocked
    // on tx.send() with a full buffer (e.g. when the insert loop error-exited).
    // Without this explicit drop, join() would deadlock forever.
    drop(rx);

    // Propagate any parser thread panic (logic bugs, not parse errors).
    parser_handle.join().expect("parser thread must not panic");

    // Always finalize the progress bar BEFORE propagating a potential insertion
    // error.  Previously `insert_result?` came first, so `reporter.finish()` was
    // never reached on the error path, leaving the bar visually incomplete.
    if insert_result.is_err() {
        reporter.abandon("error");
    } else {
        reporter.finish();
    }

    insert_result?; // propagate DB insertion error after the bar is finalized

    stats.elapsed_secs = start.elapsed().as_secs_f64();
    Ok(stats)
}

/// Returns `true` if `path` has an extension that indicates a CloudTrail log.
fn is_cloudtrail_file(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some("json") => true,
        Some("gz") => path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.ends_with(".json.gz"))
            .unwrap_or(false),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use duckdb::Connection;
    use std::io::Write;
    use tempfile::{NamedTempFile, TempDir};

    /// Shared CloudTrail JSON content used across multiple tests.
    /// sourceIPAddress is 81.2.69.160 — present in GeoLite2-City-Test.mmdb as GB/London.
    const SINGLE_EVENT_JSON: &str = r#"{
        "Records": [{
            "eventTime": "2024-01-15T10:30:00Z",
            "eventName": "DescribeInstances",
            "eventSource": "ec2.amazonaws.com",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "81.2.69.160",
            "userAgent": "aws-cli/2.0",
            "readOnly": true,
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012"
        }]
    }"#;

    const THREE_EVENT_JSON: &str = r#"{
        "Records": [
            {
                "eventTime": "2024-01-15T10:30:00Z",
                "eventName": "DescribeInstances",
                "eventSource": "ec2.amazonaws.com",
                "awsRegion": "us-east-1"
            },
            {
                "eventTime": "2024-01-15T11:00:00Z",
                "eventName": "CreateBucket",
                "eventSource": "s3.amazonaws.com",
                "awsRegion": "us-west-2"
            },
            {
                "eventTime": "2024-01-15T12:00:00Z",
                "eventName": "AssumeRole",
                "eventSource": "sts.amazonaws.com",
                "awsRegion": "us-east-1"
            }
        ]
    }"#;

    /// Write `content` to a temporary `.json` file and return the handle.
    fn write_json_file(content: &str) -> NamedTempFile {
        let mut tmp = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
        tmp.write_all(content.as_bytes()).unwrap();
        tmp.flush().unwrap();
        tmp
    }

    /// Write `content` as a gzip-compressed `.json.gz` file and return the handle.
    fn write_gz_file(content: &str) -> NamedTempFile {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        let tmp = tempfile::Builder::new()
            .suffix(".json.gz")
            .tempfile()
            .unwrap();
        let file = std::fs::File::create(tmp.path()).unwrap();
        let mut enc = GzEncoder::new(file, Compression::default());
        enc.write_all(content.as_bytes()).unwrap();
        enc.finish().unwrap();
        tmp
    }

    /// Open an in-memory DuckDB and ensure the schema exists.
    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        ensure_table(&conn).unwrap();
        conn
    }

    // ── Helper: count rows in cloudtrail_events ───────────────────────────────
    fn row_count(conn: &Connection) -> i64 {
        conn.query_row("SELECT COUNT(*) FROM cloudtrail_events", [], |r| r.get(0))
            .unwrap()
    }

    // Test #14: Ingest one `.json` file into a temp DuckDB; verify row count.
    #[test]
    fn test_ingest_single_json_file() {
        let tmp = write_json_file(SINGLE_EVENT_JSON);
        let conn = setup_db();

        let stats =
            ingest(tmp.path(), &conn, IngestOptions::default()).expect("ingest should succeed");

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.records_inserted, 1);
        assert_eq!(stats.errors, 0);
        assert_eq!(row_count(&conn), 1);
    }

    // Test #15: Ingest one `.json.gz` file; verify row count.
    #[test]
    fn test_ingest_single_gz_file() {
        let tmp = write_gz_file(SINGLE_EVENT_JSON);
        let conn = setup_db();

        let stats =
            ingest(tmp.path(), &conn, IngestOptions::default()).expect("ingest should succeed");

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.records_inserted, 1);
        assert_eq!(stats.errors, 0);
        assert_eq!(row_count(&conn), 1);
    }

    // Test #16: Ingest a directory with multiple files; verify total row count.
    #[test]
    fn test_ingest_directory() {
        let dir = TempDir::new().unwrap();

        // Write two JSON files: 1 event + 3 events = 4 total.
        std::fs::write(dir.path().join("a.json"), SINGLE_EVENT_JSON).unwrap();
        std::fs::write(dir.path().join("b.json"), THREE_EVENT_JSON).unwrap();

        let conn = setup_db();
        let stats =
            ingest(dir.path(), &conn, IngestOptions::default()).expect("ingest should succeed");

        assert_eq!(stats.files_processed, 2);
        assert_eq!(stats.records_inserted, 4);
        assert_eq!(stats.errors, 0);
        assert_eq!(row_count(&conn), 4);
    }

    // Test #17: Non-JSON files in the directory are silently skipped.
    #[test]
    fn test_ingest_skips_non_json_files() {
        let dir = TempDir::new().unwrap();

        std::fs::write(dir.path().join("log.txt"), "not a json file").unwrap();
        std::fs::write(dir.path().join("data.csv"), "col1,col2\n1,2").unwrap();
        std::fs::write(dir.path().join("event.json"), SINGLE_EVENT_JSON).unwrap();

        let conn = setup_db();
        let stats =
            ingest(dir.path(), &conn, IngestOptions::default()).expect("ingest should succeed");

        // Only event.json should have been processed.
        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.records_inserted, 1);
        assert_eq!(stats.errors, 0);
    }

    // Test #18: Ingesting the same file twice does not duplicate records.
    #[test]
    fn test_ingest_duplicate_prevention() {
        let tmp = write_json_file(SINGLE_EVENT_JSON);
        let conn = setup_db();

        // First ingest — should insert 1 record.
        let stats1 = ingest(tmp.path(), &conn, IngestOptions::default())
            .expect("first ingest should succeed");
        assert_eq!(stats1.records_inserted, 1);

        // Second ingest — file is already tracked in ingested_files; should be skipped.
        let stats2 = ingest(tmp.path(), &conn, IngestOptions::default())
            .expect("second ingest should succeed");
        assert_eq!(stats2.records_inserted, 0);
        assert_eq!(
            stats2.files_processed, 1,
            "file should still count as processed"
        );

        // Row count must not have doubled.
        assert_eq!(row_count(&conn), 1);
    }

    // Test #19: The ingest function returns IngestStats with meaningful values.
    #[test]
    fn test_ingest_returns_stats() {
        let tmp = write_json_file(SINGLE_EVENT_JSON);
        let conn = setup_db();

        let stats =
            ingest(tmp.path(), &conn, IngestOptions::default()).expect("ingest should succeed");

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.records_inserted, 1);
        assert_eq!(stats.errors, 0);
        assert!(
            stats.elapsed_secs >= 0.0,
            "elapsed_secs should be non-negative"
        );
    }

    // Test #22: show_progress=true exercises the visible ProgressReporter code path.
    #[test]
    fn test_ingest_with_progress_show_true() {
        let tmp = write_json_file(SINGLE_EVENT_JSON);
        let conn = setup_db();

        // show_progress=true should not panic and should return correct stats.
        let stats = ingest(
            tmp.path(),
            &conn,
            IngestOptions {
                show_progress: true,
                ..Default::default()
            },
        )
        .expect("ingest with visible progress should succeed");

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.records_inserted, 1);
        assert_eq!(stats.errors, 0);
    }

    // Test #23: show_progress=false uses a hidden reporter.
    #[test]
    fn test_ingest_with_progress_show_false() {
        let tmp = write_json_file(SINGLE_EVENT_JSON);
        let conn = setup_db();

        let stats = ingest(tmp.path(), &conn, IngestOptions::default())
            .expect("ingest with hidden progress should succeed");

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.records_inserted, 1);
        assert_eq!(stats.errors, 0);
    }

    // Test #24: Parallel ingestion of 10 files produces correct aggregate stats.
    // This is the primary correctness guard for the parallel implementation.
    #[test]
    fn test_ingest_parallel_correctness_10_files() {
        let dir = TempDir::new().unwrap();

        // Write 10 single-event JSON files.
        for i in 0..10 {
            std::fs::write(
                dir.path().join(format!("event_{i:02}.json")),
                SINGLE_EVENT_JSON,
            )
            .unwrap();
        }

        let conn = setup_db();
        let stats = ingest(dir.path(), &conn, IngestOptions::default())
            .expect("parallel ingest should succeed");

        assert_eq!(
            stats.files_processed, 10,
            "all 10 files should be processed"
        );
        assert_eq!(stats.records_inserted, 10, "10 records total (1 per file)");
        assert_eq!(stats.errors, 0, "no errors expected");
        assert_eq!(row_count(&conn), 10, "10 rows in DB");
    }

    // Test #25: parse_file_content correctly reads and parses a plain JSON file.
    #[test]
    fn test_parse_file_content_json() {
        let tmp = write_json_file(SINGLE_EVENT_JSON);

        let (sha256, records) = parse_file_content(tmp.path(), &FieldFilter::default())
            .expect("parse_file_content should succeed");

        assert!(!sha256.is_empty(), "sha256 must not be empty");
        assert_eq!(sha256.len(), 64, "SHA-256 hex digest is 64 chars");
        assert_eq!(records.len(), 1, "one record in the file");
        assert_eq!(records[0].event_name, "DescribeInstances");
    }

    // Test #26: parse_file_content correctly reads and parses a .json.gz file.
    #[test]
    fn test_parse_file_content_gz() {
        let tmp = write_gz_file(SINGLE_EVENT_JSON);

        let (sha256, records) = parse_file_content(tmp.path(), &FieldFilter::default())
            .expect("parse_file_content should handle .gz");

        assert_eq!(sha256.len(), 64);
        assert_eq!(records.len(), 1);
    }

    // Test FF-01: parse_file_content with a non-empty FieldFilter strips
    // matching keys from request_parameters / response_elements while leaving
    // raw_json untouched (raw_event must always preserve the original record).
    #[test]
    fn test_parse_file_content_strips_request_parameters_when_filter_set() {
        let json = r#"{
            "Records": [{
                "eventTime": "2024-01-15T10:30:00Z",
                "eventName": "ListBuckets",
                "eventSource": "s3.amazonaws.com",
                "awsRegion": "us-east-1",
                "requestParameters": {"maxResults": 50, "bucketName": "x"},
                "responseElements": {"nextToken": "tok", "result": "ok"}
            }]
        }"#;
        let tmp = write_json_file(json);
        let filter = FieldFilter::default_strip();

        let (_sha, records) =
            parse_file_content(tmp.path(), &filter).expect("parse should succeed");
        let ev = &records[0];

        let req: serde_json::Value =
            serde_json::from_str(ev.request_parameters.as_deref().unwrap()).unwrap();
        assert!(!req.as_object().unwrap().contains_key("maxResults"));
        assert_eq!(
            req.get("bucketName").and_then(serde_json::Value::as_str),
            Some("x")
        );

        let res: serde_json::Value =
            serde_json::from_str(ev.response_elements.as_deref().unwrap()).unwrap();
        assert!(!res.as_object().unwrap().contains_key("nextToken"));
        assert_eq!(
            res.get("result").and_then(serde_json::Value::as_str),
            Some("ok")
        );

        // raw_json must always preserve the original event byte-for-byte.
        assert!(
            ev.raw_json.contains("\"maxResults\""),
            "raw_event must preserve maxResults; raw_json={}",
            ev.raw_json
        );
        assert!(
            ev.raw_json.contains("\"nextToken\""),
            "raw_event must preserve nextToken; raw_json={}",
            ev.raw_json
        );
    }

    // Test #37: Ingest 100 files spanning multiple chunks (PARSE_CHUNK_SIZE=64) correctly.
    // Verifies that chunking does not lose records and aggregate stats are exact.
    #[test]
    fn test_ingest_chunked_100_files() {
        let dir = TempDir::new().unwrap();

        for i in 0..100 {
            std::fs::write(
                dir.path().join(format!("event_{i:03}.json")),
                SINGLE_EVENT_JSON,
            )
            .unwrap();
        }

        let conn = setup_db();
        let stats = ingest(dir.path(), &conn, IngestOptions::default())
            .expect("chunked ingest of 100 files should succeed");

        assert_eq!(stats.files_processed, 100, "all 100 files must be counted");
        assert_eq!(stats.records_inserted, 100, "100 records total, 1 per file");
        assert_eq!(stats.errors, 0, "no errors expected");
        assert_eq!(row_count(&conn), 100, "100 rows in DB");
    }

    // Test #38: Batch dedup (in-memory HashMap) prevents re-insertion on a second run.
    // This is the correctness guard for the fetch_ingested_files_map optimisation.
    #[test]
    fn test_ingest_batch_dedup_prevents_double_insert() {
        let dir = TempDir::new().unwrap();

        for i in 0..5 {
            std::fs::write(
                dir.path().join(format!("event_{i}.json")),
                SINGLE_EVENT_JSON,
            )
            .unwrap();
        }

        let conn = setup_db();

        // First run — should insert 5 records.
        let stats1 =
            ingest(dir.path(), &conn, IngestOptions::default()).expect("first run should succeed");
        assert_eq!(stats1.records_inserted, 5, "first run inserts 5 records");

        // Second run — all files already tracked via ingested_files.
        let stats2 =
            ingest(dir.path(), &conn, IngestOptions::default()).expect("second run should succeed");
        assert_eq!(
            stats2.records_inserted, 0,
            "second run must insert nothing (all already ingested)"
        );
        assert_eq!(
            stats2.files_processed, 5,
            "second run still counts all files as processed"
        );

        // Row count must not have doubled.
        assert_eq!(row_count(&conn), 5, "DB must still contain exactly 5 rows");
    }

    // ── Date filter integration tests ─────────────────────────────────────

    /// Build a `yyyy/mm/dd/` sub-directory under `base` and return the path.
    fn make_date_dir(base: &std::path::Path, y: u32, m: u32, d: u32) -> std::path::PathBuf {
        let dir = base
            .join(format!("{y:04}"))
            .join(format!("{m:02}"))
            .join(format!("{d:02}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // Test #27: date_filter processes only files within the date range.
    #[test]
    fn test_ingest_with_date_filter_only_processes_files_in_range() {
        use crate::date_filter::DateFilter;
        use chrono::NaiveDate;

        let root = TempDir::new().unwrap();

        // 2024-01-15 → within [2024-01-01, 2024-01-31]
        let in_range = make_date_dir(root.path(), 2024, 1, 15);
        // 2024-02-01 → outside range
        let out_of_range = make_date_dir(root.path(), 2024, 2, 1);

        std::fs::write(in_range.join("event.json"), SINGLE_EVENT_JSON).unwrap();
        std::fs::write(out_of_range.join("event.json"), SINGLE_EVENT_JSON).unwrap();

        let conn = setup_db();
        let filter = DateFilter::new(
            Some(NaiveDate::from_ymd_opt(2024, 1, 1).unwrap()),
            Some(NaiveDate::from_ymd_opt(2024, 1, 31).unwrap()),
        );

        let stats = ingest(
            root.path(),
            &conn,
            IngestOptions {
                date_filter: filter,
                ..Default::default()
            },
        )
        .expect("ingest with date filter should succeed");

        assert_eq!(
            stats.files_processed, 1,
            "only the in-range file should be processed"
        );
        assert_eq!(
            stats.records_inserted, 1,
            "only 1 record from the in-range file"
        );
        assert_eq!(stats.errors, 0);
        assert_eq!(row_count(&conn), 1, "only 1 row in DB");
    }

    // Test #28: default date filter processes all files.
    #[test]
    fn test_ingest_with_default_filter_processes_all_files() {
        let root = TempDir::new().unwrap();

        let dir1 = make_date_dir(root.path(), 2024, 1, 15);
        let dir2 = make_date_dir(root.path(), 2024, 2, 1);

        std::fs::write(dir1.join("event.json"), SINGLE_EVENT_JSON).unwrap();
        std::fs::write(dir2.join("event.json"), SINGLE_EVENT_JSON).unwrap();

        let conn = setup_db();
        let stats = ingest(root.path(), &conn, IngestOptions::default())
            .expect("ingest with no filter should process all files");

        assert_eq!(stats.files_processed, 2, "both files should be processed");
        assert_eq!(stats.records_inserted, 2);
        assert_eq!(row_count(&conn), 2);
    }

    // Test #29: from-only filter excludes files before `from`.
    #[test]
    fn test_ingest_with_from_only_filter_excludes_before_from() {
        use crate::date_filter::DateFilter;
        use chrono::NaiveDate;

        let root = TempDir::new().unwrap();

        let before = make_date_dir(root.path(), 2024, 1, 9);
        let on_from = make_date_dir(root.path(), 2024, 1, 10);

        std::fs::write(before.join("event.json"), SINGLE_EVENT_JSON).unwrap();
        std::fs::write(on_from.join("event.json"), SINGLE_EVENT_JSON).unwrap();

        let conn = setup_db();
        let filter = DateFilter::new(Some(NaiveDate::from_ymd_opt(2024, 1, 10).unwrap()), None);

        let stats = ingest(
            root.path(),
            &conn,
            IngestOptions {
                date_filter: filter,
                ..Default::default()
            },
        )
        .expect("from-only filter should succeed");

        assert_eq!(
            stats.files_processed, 1,
            "only file on/after from date should be processed"
        );
        assert_eq!(stats.records_inserted, 1);
        assert_eq!(row_count(&conn), 1);
    }

    // Test #30: to-only filter excludes files after `to`.
    #[test]
    fn test_ingest_with_to_only_filter_excludes_after_to() {
        use crate::date_filter::DateFilter;
        use chrono::NaiveDate;

        let root = TempDir::new().unwrap();

        let on_to = make_date_dir(root.path(), 2024, 1, 20);
        let after = make_date_dir(root.path(), 2024, 1, 21);

        std::fs::write(on_to.join("event.json"), SINGLE_EVENT_JSON).unwrap();
        std::fs::write(after.join("event.json"), SINGLE_EVENT_JSON).unwrap();

        let conn = setup_db();
        let filter = DateFilter::new(None, Some(NaiveDate::from_ymd_opt(2024, 1, 20).unwrap()));

        let stats = ingest(
            root.path(),
            &conn,
            IngestOptions {
                date_filter: filter,
                ..Default::default()
            },
        )
        .expect("to-only filter should succeed");

        assert_eq!(
            stats.files_processed, 1,
            "only file on/before to date should be processed"
        );
        assert_eq!(stats.records_inserted, 1);
        assert_eq!(row_count(&conn), 1);
    }

    // Test #31: files without a date in their path are always included by the filter.
    #[test]
    fn test_ingest_with_date_filter_includes_undated_files() {
        use crate::date_filter::DateFilter;
        use chrono::NaiveDate;

        let root = TempDir::new().unwrap();

        // A file in a non-date directory (no yyyy/mm/dd pattern).
        std::fs::write(root.path().join("event.json"), SINGLE_EVENT_JSON).unwrap();

        let conn = setup_db();
        // Very narrow range that would exclude any actual date.
        let filter = DateFilter::new(
            Some(NaiveDate::from_ymd_opt(2020, 1, 1).unwrap()),
            Some(NaiveDate::from_ymd_opt(2020, 1, 1).unwrap()),
        );

        let stats = ingest(
            root.path(),
            &conn,
            IngestOptions {
                date_filter: filter,
                ..Default::default()
            },
        )
        .expect("undated file should be included");

        assert_eq!(
            stats.files_processed, 1,
            "undated file should be included regardless of filter"
        );
        assert_eq!(stats.records_inserted, 1);
    }

    // Test #32: multiple date directories, only the range boundary files match.
    #[test]
    fn test_ingest_with_date_filter_boundary_dates_inclusive() {
        use crate::date_filter::DateFilter;
        use chrono::NaiveDate;

        let root = TempDir::new().unwrap();

        // Exactly on the boundary dates.
        let on_from = make_date_dir(root.path(), 2024, 3, 1);
        let middle = make_date_dir(root.path(), 2024, 3, 15);
        let on_to = make_date_dir(root.path(), 2024, 3, 31);
        // Outside.
        let before = make_date_dir(root.path(), 2024, 2, 28);
        let after = make_date_dir(root.path(), 2024, 4, 1);

        for dir in &[&on_from, &middle, &on_to, &before, &after] {
            std::fs::write(dir.join("event.json"), SINGLE_EVENT_JSON).unwrap();
        }

        let conn = setup_db();
        let filter = DateFilter::new(
            Some(NaiveDate::from_ymd_opt(2024, 3, 1).unwrap()),
            Some(NaiveDate::from_ymd_opt(2024, 3, 31).unwrap()),
        );

        let stats = ingest(
            root.path(),
            &conn,
            IngestOptions {
                date_filter: filter,
                ..Default::default()
            },
        )
        .expect("boundary inclusive test should succeed");

        assert_eq!(
            stats.files_processed, 3,
            "on_from, middle, on_to should all be processed (boundaries inclusive)"
        );
        assert_eq!(stats.records_inserted, 3);
        assert_eq!(row_count(&conn), 3);
    }

    // ── Path filter integration tests ─────────────────────────────────────

    /// Write a JSON file into a simulated S3 path: `<root>/<service>/<region>/event.json`.
    fn write_service_file(
        root: &std::path::Path,
        service: &str,
        region: &str,
    ) -> std::path::PathBuf {
        let dir = root.join(service).join(region);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("event.json");
        std::fs::write(&p, SINGLE_EVENT_JSON).unwrap();
        p
    }

    // Test #33: include pattern filters to matching service only.
    #[test]
    fn test_ingest_with_filters_include_pattern() {
        use crate::path_filter::PathFilter;

        let root = TempDir::new().unwrap();
        write_service_file(root.path(), "CloudTrail", "us-east-1");
        write_service_file(root.path(), "Config", "us-east-1");
        write_service_file(root.path(), "vpcflowlogs", "us-east-1");

        let conn = setup_db();
        let pf = PathFilter::from_strs(Some("*CloudTrail*"), None).unwrap();
        let stats = ingest(
            root.path(),
            &conn,
            IngestOptions {
                path_filter: pf,
                ..Default::default()
            },
        )
        .expect("include filter should succeed");

        assert_eq!(stats.files_processed, 1, "only CloudTrail file included");
        assert_eq!(stats.records_inserted, 1);
        assert_eq!(row_count(&conn), 1);
    }

    // Test #34: exclude pattern removes matching service.
    #[test]
    fn test_ingest_with_filters_exclude_pattern() {
        use crate::path_filter::PathFilter;

        let root = TempDir::new().unwrap();
        write_service_file(root.path(), "CloudTrail", "us-east-1");
        write_service_file(root.path(), "Config", "us-east-1");
        write_service_file(root.path(), "vpcflowlogs", "us-east-1");

        let conn = setup_db();
        let pf = PathFilter::from_strs(None, Some("*Config*,*vpcflowlogs*")).unwrap();
        let stats = ingest(
            root.path(),
            &conn,
            IngestOptions {
                path_filter: pf,
                ..Default::default()
            },
        )
        .expect("exclude filter should succeed");

        assert_eq!(stats.files_processed, 1, "only CloudTrail file remains");
        assert_eq!(stats.records_inserted, 1);
        assert_eq!(row_count(&conn), 1);
    }

    // Test #35: no path filter + date filter still works correctly.
    #[test]
    fn test_ingest_with_filters_default_path_filter_passes_all() {
        use crate::date_filter::DateFilter;
        use chrono::NaiveDate;

        let root = TempDir::new().unwrap();
        let dir = make_date_dir(root.path(), 2024, 1, 15);
        std::fs::write(dir.join("event.json"), SINGLE_EVENT_JSON).unwrap();

        let conn = setup_db();
        let df = DateFilter::new(
            Some(NaiveDate::from_ymd_opt(2024, 1, 1).unwrap()),
            Some(NaiveDate::from_ymd_opt(2024, 1, 31).unwrap()),
        );
        let stats = ingest(
            root.path(),
            &conn,
            IngestOptions {
                date_filter: df,
                ..Default::default()
            },
        )
        .expect("default path filter should pass all");

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.records_inserted, 1);
    }

    // Test #36: include multiple services with comma-separated pattern.
    #[test]
    fn test_ingest_with_filters_include_multiple_services() {
        use crate::path_filter::PathFilter;

        let root = TempDir::new().unwrap();
        write_service_file(root.path(), "CloudTrail", "us-east-1");
        write_service_file(root.path(), "Config", "us-east-1");
        write_service_file(root.path(), "vpcflowlogs", "us-east-1");

        let conn = setup_db();
        let pf = PathFilter::from_strs(Some("*CloudTrail*,*Config*"), None).unwrap();
        let stats = ingest(
            root.path(),
            &conn,
            IngestOptions {
                path_filter: pf,
                ..Default::default()
            },
        )
        .expect("multi-include filter should succeed");

        assert_eq!(
            stats.files_processed, 2,
            "CloudTrail and Config files should be included"
        );
        assert_eq!(stats.records_inserted, 2);
        assert_eq!(row_count(&conn), 2);
    }

    // Test I-01: GeoIP enrichment populates geo columns for known IPs.
    #[test]
    fn test_ingest_with_geoip_populates_geo_columns() {
        use crate::geoip::{GeoipConfig, GeoipEnricher};
        use std::path::PathBuf;

        let city_db = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/testdata/geoip/GeoLite2-City-Test.mmdb");
        let enricher = GeoipEnricher::open(&GeoipConfig {
            city_db_path: Some(city_db),
            country_db_path: None,
            asn_db_path: None,
        })
        .expect("should open test City mmdb");

        // SINGLE_EVENT_JSON has sourceIPAddress = 81.2.69.160 (GB in the test mmdb).
        let tmp = write_json_file(SINGLE_EVENT_JSON);
        let conn = setup_db();

        let stats = ingest(
            tmp.path(),
            &conn,
            IngestOptions {
                geoip: Some(&enricher),
                ..Default::default()
            },
        )
        .expect("ingest with geoip should succeed");

        assert_eq!(stats.records_inserted, 1);

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

    // Test I-02: ingest without GeoIP leaves geo columns NULL.
    #[test]
    fn test_ingest_without_geoip_geo_columns_are_null() {
        let tmp = write_json_file(SINGLE_EVENT_JSON);
        let conn = setup_db();

        let stats =
            ingest(tmp.path(), &conn, IngestOptions::default()).expect("ingest should succeed");
        assert_eq!(stats.records_inserted, 1);

        let cc: Option<String> = conn
            .query_row(
                "SELECT geo_country_code FROM cloudtrail_events LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            cc.is_none(),
            "geo_country_code should be NULL without enricher"
        );
    }

    // Test P-01: Pipelined ingest of a single file produces correct stats.
    #[test]
    fn test_pipeline_single_file_correctness() {
        let tmp = write_json_file(SINGLE_EVENT_JSON);
        let conn = setup_db();

        let stats = ingest(tmp.path(), &conn, IngestOptions::default())
            .expect("pipeline single-file ingest must succeed");

        assert_eq!(stats.files_processed, 1, "one file must be processed");
        assert_eq!(stats.records_inserted, 1, "one record must be inserted");
        assert_eq!(stats.errors, 0, "no errors expected");
        assert_eq!(row_count(&conn), 1, "one row in DB");
    }

    // Test P-02: Pipelined ingest of more than one chunk (> PARSE_CHUNK_SIZE files)
    // produces exact aggregate stats with no lost records across chunk boundaries.
    #[test]
    fn test_pipeline_multi_chunk_correctness() {
        // 130 files spans two full chunks (64 + 64) plus a partial third chunk (2).
        const FILE_COUNT: usize = 130;
        let dir = TempDir::new().unwrap();

        for i in 0..FILE_COUNT {
            std::fs::write(
                dir.path().join(format!("event_{i:03}.json")),
                SINGLE_EVENT_JSON,
            )
            .unwrap();
        }

        let conn = setup_db();
        let stats = ingest(dir.path(), &conn, IngestOptions::default())
            .expect("pipeline multi-chunk ingest must succeed");

        assert_eq!(
            stats.files_processed, FILE_COUNT,
            "all {FILE_COUNT} files must be processed"
        );
        assert_eq!(
            stats.records_inserted, FILE_COUNT,
            "{FILE_COUNT} records must be inserted (1 per file)"
        );
        assert_eq!(stats.errors, 0, "no errors expected");
        assert_eq!(
            row_count(&conn),
            FILE_COUNT as i64,
            "DB must contain exactly {FILE_COUNT} rows"
        );
    }

    // Test P-03: Pipelined ingest of an empty directory returns zeroed stats
    // with a non-negative elapsed time.
    #[test]
    fn test_pipeline_empty_directory_returns_zero_stats() {
        let dir = TempDir::new().unwrap();
        let conn = setup_db();

        let stats = ingest(dir.path(), &conn, IngestOptions::default())
            .expect("pipeline ingest of empty directory must succeed");

        assert_eq!(stats.files_processed, 0, "no files processed in empty dir");
        assert_eq!(stats.records_inserted, 0, "no records inserted");
        assert_eq!(stats.errors, 0, "no errors");
        assert!(
            stats.elapsed_secs >= 0.0,
            "elapsed_secs must be non-negative"
        );
        assert_eq!(row_count(&conn), 0, "DB must remain empty");
    }

    // Test P-04: A second pipelined run on the same files inserts nothing
    // (dedup via in-memory HashMap still works through the channel pipeline).
    #[test]
    fn test_pipeline_second_run_dedup_works() {
        let dir = TempDir::new().unwrap();

        for i in 0..10 {
            std::fs::write(
                dir.path().join(format!("event_{i}.json")),
                SINGLE_EVENT_JSON,
            )
            .unwrap();
        }

        let conn = setup_db();

        let stats1 = ingest(dir.path(), &conn, IngestOptions::default())
            .expect("first pipeline run must succeed");
        assert_eq!(stats1.records_inserted, 10, "first run inserts 10 records");

        let stats2 = ingest(dir.path(), &conn, IngestOptions::default())
            .expect("second pipeline run must succeed");
        assert_eq!(
            stats2.records_inserted, 0,
            "second run must insert nothing (all already ingested)"
        );
        assert_eq!(
            stats2.files_processed, 10,
            "all 10 files still counted as processed"
        );
        assert_eq!(
            row_count(&conn),
            10,
            "DB must contain exactly 10 rows after both runs"
        );
    }

    // Test P-06: When a DuckDB insertion error occurs, ingest returns an error
    // and the progress bar is abandoned cleanly.
    #[test]
    fn test_progress_bar_abandoned_on_db_insertion_error() {
        let tmp = write_json_file(SINGLE_EVENT_JSON);

        // Create a DB whose cloudtrail_events table has only a single wrong column.
        // ensure_table() will add the 7 geo columns via ALTER TABLE, but the 17 core
        // columns will be missing, causing the Appender to fail when it tries to write
        // 24 values to a table that does not have the expected column layout.
        let conn = Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE cloudtrail_events (wrong_col TEXT)", [])
            .unwrap();
        conn.execute(
            "CREATE TABLE ingested_files \
             (file_path TEXT PRIMARY KEY, sha256 TEXT, ingested_at TIMESTAMP DEFAULT now())",
            [],
        )
        .unwrap();

        // show_progress=true exercises the visible ProgressReporter code path.
        // reporter.abandon("error") is called before the error is returned,
        // so the terminal is left in a clean state.
        let result = ingest(
            tmp.path(),
            &conn,
            IngestOptions {
                show_progress: true,
                ..Default::default()
            },
        );

        assert!(
            result.is_err(),
            "ingest must return an error when the DB schema is incompatible"
        );
    }

    // Test P-05: A malformed JSON file in a directory is counted as an error
    // and does not prevent valid files from being inserted.
    #[test]
    fn test_pipeline_parse_error_counted_and_other_files_inserted() {
        let dir = TempDir::new().unwrap();

        // Two valid files + one intentionally malformed JSON file.
        std::fs::write(dir.path().join("valid1.json"), SINGLE_EVENT_JSON).unwrap();
        std::fs::write(dir.path().join("malformed.json"), r#"{ not: valid json }"#).unwrap();
        std::fs::write(dir.path().join("valid2.json"), THREE_EVENT_JSON).unwrap();

        let conn = setup_db();
        let stats = ingest(dir.path(), &conn, IngestOptions::default())
            .expect("ingest must succeed even when one file is malformed");

        assert_eq!(
            stats.errors, 1,
            "malformed file must be counted as an error"
        );
        assert_eq!(
            stats.files_processed, 2,
            "two valid files must be processed"
        );
        assert_eq!(
            stats.records_inserted, 4,
            "1 record from valid1 + 3 records from valid2"
        );
        assert_eq!(row_count(&conn), 4, "four rows must be in DB");
    }

    // ── IngestOptions / ingest() ──────────────────────────────────────────────

    // Test IO-01: ingest() with default IngestOptions processes a JSON file.
    #[test]
    fn test_ingest_with_options_default_processes_json_file() {
        let tmp = write_json_file(SINGLE_EVENT_JSON);
        let conn = setup_db();

        let stats = ingest(
            tmp.path(),
            &conn,
            IngestOptions {
                show_progress: false,
                ..Default::default()
            },
        )
        .expect("ingest() with default options should succeed");

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.records_inserted, 1);
        assert_eq!(stats.errors, 0);
    }

    // Test IO-02: ingest() with default IngestOptions processes a directory.
    #[test]
    fn test_ingest_with_options_processes_directory() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.json"), SINGLE_EVENT_JSON).unwrap();
        std::fs::write(dir.path().join("b.json"), THREE_EVENT_JSON).unwrap();

        let conn = setup_db();
        let stats = ingest(dir.path(), &conn, IngestOptions::default())
            .expect("ingest() with default options should succeed on directory");

        assert_eq!(stats.files_processed, 2);
        assert_eq!(stats.records_inserted, 4);
        assert_eq!(stats.errors, 0);
    }

    // Test IO-03: ingest() with show_progress = true does not error.
    #[test]
    fn test_ingest_with_options_show_progress_does_not_error() {
        let tmp = write_json_file(SINGLE_EVENT_JSON);
        let conn = setup_db();

        // show_progress = true would normally display a bar; in tests the
        // output is suppressed by indicatif when not connected to a tty.
        let stats = ingest(
            tmp.path(),
            &conn,
            IngestOptions {
                show_progress: true,
                ..Default::default()
            },
        )
        .expect("ingest() with show_progress=true should not error");

        assert_eq!(stats.records_inserted, 1);
    }
}
