//! VPC Flow Logs ingestion: parallel parse → one transaction per chunk → `ip_geo`.
//!
//! Mirrors the CloudTrail pipeline in [`crate::ingest`] — rayon-parallel
//! parsing on a parser thread, a bounded channel, and this thread as the sole
//! DuckDB writer — with one difference that matters for evidence: a chunk's
//! records, file rows, parse issues and `ingested_files` marks commit together
//! or not at all, so a failed run can be retried without appending twice.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;

use anyhow::{Context, Result};
use duckdb::Connection;
use rayon::prelude::*;

use crate::db::batch_mark_ingested;
use crate::flow_db::{FlowFileMeta, append_flow_file, delete_flow_file, ensure_flow_tables};
use crate::flow_parser::{ParsedFlowFile, parse_flow_log};
use crate::geoip::GeoipEnricher;
use crate::ingest::read_log_file;
use crate::progress::ProgressReporter;

/// A file whose rejected-row share exceeds this fraction is named in a warning.
pub const REJECTED_ROW_WARNING_RATIO: f64 = 0.01;

/// Statistics for the flow log part of an ingestion run.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct FlowStats {
    /// Files whose rows were written in this run.
    pub files_ingested: usize,
    /// Files skipped because the same content was already ingested.
    pub files_unchanged: usize,
    /// Files that could not be read or parsed as a flow log, with the reason.
    pub failed_files: Vec<(String, String)>,
    /// Records written (including rows with field issues).
    pub records_inserted: usize,
    /// Rows written with at least one malformed field.
    pub rows_with_issues: usize,
    /// Rows rejected for a wrong token count.
    pub rows_rejected: usize,
    /// Files whose rejected rows exceed [`REJECTED_ROW_WARNING_RATIO`].
    pub files_over_reject_threshold: Vec<String>,
    /// Addresses added to `ip_geo` by the post-pass.
    pub geo_addresses_added: usize,
}

/// Options for [`ingest_flow_files`].
#[derive(Debug, Default)]
pub struct FlowIngestOptions<'a> {
    pub show_progress: bool,
    /// When set, `ip_geo` is filled for every new address after the chunks commit.
    pub geoip: Option<&'a GeoipEnricher>,
}

/// Compressed bytes parsed in parallel per chunk; the chunk is also the
/// transaction unit.
///
/// Chunks are capped by size, not file count: flow log objects range from a
/// few kilobytes to many megabytes per 5-minute window, so a fixed file count
/// has no memory bound. A parsed record costs roughly 70× its compressed size
/// in memory, so 8 MiB compressed is a few hundred megabytes per chunk.
const FLOW_CHUNK_BYTES: u64 = 8 * 1024 * 1024;

/// Parsed chunks the parser thread may buffer ahead of the writer. One keeps
/// parsing and inserting overlapped while holding at most three chunks.
const PIPELINE_BUFFER_DEPTH: usize = 1;

/// Addresses resolved per `ip_geo` page.
const GEO_PAGE_SIZE: usize = 50_000;

type ParseOutcome = (PathBuf, Result<(String, ParsedFlowFile)>);

/// Read and parse one flow log file. Returns `(sha256, parsed)`.
pub fn parse_flow_file(path: &Path) -> Result<(String, ParsedFlowFile)> {
    let (sha256, content) = read_log_file(path)?;
    let parsed = parse_flow_log(&content)
        .with_context(|| format!("Failed to parse flow log {}", path.display()))?;
    Ok((sha256, parsed))
}

impl FlowStats {
    fn absorb(&mut self, other: FlowStats) {
        self.files_ingested += other.files_ingested;
        self.files_unchanged += other.files_unchanged;
        self.failed_files.extend(other.failed_files);
        self.records_inserted += other.records_inserted;
        self.rows_with_issues += other.rows_with_issues;
        self.rows_rejected += other.rows_rejected;
        self.files_over_reject_threshold
            .extend(other.files_over_reject_threshold);
        self.geo_addresses_added += other.geo_addresses_added;
    }
}

/// Ingest `files` (already classified as flow logs) into `conn`.
///
/// `ingested` is the run's `ingested_files` map, shared with the CloudTrail
/// pipeline; it is updated only for chunks that committed.
pub fn ingest_flow_files(
    conn: &Connection,
    files: Vec<PathBuf>,
    ingested: &mut HashMap<String, String>,
    options: FlowIngestOptions<'_>,
) -> Result<FlowStats> {
    ensure_flow_tables(conn)?;
    let mut stats = FlowStats::default();
    if files.is_empty() {
        return Ok(stats);
    }

    let reporter = if options.show_progress {
        ProgressReporter::new(files.len() as u64)
    } else {
        ProgressReporter::hidden()
    };

    let sized: Vec<(PathBuf, u64)> = files
        .into_iter()
        .map(|p| {
            let len = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            (p, len)
        })
        .collect();
    let chunks = chunk_by_size(sized, FLOW_CHUNK_BYTES);

    let (tx, rx) = mpsc::sync_channel::<Vec<ParseOutcome>>(PIPELINE_BUFFER_DEPTH);
    let parser = thread::spawn(move || {
        for chunk in &chunks {
            let parsed: Vec<ParseOutcome> = chunk
                .par_iter()
                .map(|p| (p.clone(), parse_flow_file(p)))
                .collect();
            if tx.send(parsed).is_err() {
                break;
            }
        }
    });

    let mut result = Ok(());
    while let Ok(chunk) = rx.recv() {
        let files_in_chunk = chunk.len();
        if let Err(e) = write_chunk(conn, chunk, ingested, &mut stats, batch_mark_ingested) {
            result = Err(e);
            break;
        }
        for _ in 0..files_in_chunk {
            reporter.inc(stats.records_inserted);
        }
    }
    // Unblock a parser waiting on a full channel before joining it.
    drop(rx);
    parser.join().expect("flow parser thread must not panic");

    if let Err(e) = result {
        reporter.abandon("error");
        return Err(e);
    }
    reporter.finish();

    if let Some(geoip) = options.geoip {
        stats.geo_addresses_added = populate_ip_geo(conn, geoip)?;
    }
    Ok(stats)
}

/// Group files, in order, into chunks of at most `budget` bytes. A file larger
/// than the budget forms a chunk of its own; no chunk is empty.
fn chunk_by_size(files: Vec<(PathBuf, u64)>, budget: u64) -> Vec<Vec<PathBuf>> {
    let mut chunks: Vec<Vec<PathBuf>> = Vec::new();
    let mut current: Vec<PathBuf> = Vec::new();
    let mut current_bytes = 0;
    for (path, len) in files {
        if !current.is_empty() && current_bytes + len > budget {
            chunks.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current_bytes += len;
        current.push(path);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// Write one parsed chunk inside a single transaction.
///
/// Records, file rows, parse issues and the `ingested_files` marks (written by
/// `mark`, injectable for tests) commit together. On any error the chunk rolls
/// back and neither `ingested` nor `stats` change, so a retry starts clean.
fn write_chunk<M>(
    conn: &Connection,
    chunk: Vec<ParseOutcome>,
    ingested: &mut HashMap<String, String>,
    stats: &mut FlowStats,
    mark: M,
) -> Result<()>
where
    M: Fn(&Connection, &[(String, String)]) -> Result<()>,
{
    let mut local = FlowStats::default();
    let mut marks: Vec<(String, String)> = Vec::new();

    conn.execute_batch("BEGIN TRANSACTION")
        .context("Failed to begin flow chunk transaction")?;
    let written = (|| -> Result<()> {
        for (path, outcome) in chunk {
            let key = path.to_string_lossy().into_owned();
            let (sha256, parsed) = match outcome {
                Ok(ok) => ok,
                Err(e) => {
                    local.failed_files.push((key, format!("{e:#}")));
                    continue;
                }
            };
            match ingested.get(&key) {
                Some(previous) if *previous == sha256 => {
                    local.files_unchanged += 1;
                    continue;
                }
                Some(_) => delete_flow_file(conn, &key)?,
                None => {}
            }
            local.records_inserted +=
                append_flow_file(conn, &FlowFileMeta::from_path(&path), &parsed)?;
            local.rows_with_issues += parsed.rows_with_issues;
            local.rows_rejected += parsed.rows_rejected;
            if parsed.rows_total > 0
                && parsed.rows_rejected as f64 / parsed.rows_total as f64
                    > REJECTED_ROW_WARNING_RATIO
            {
                local.files_over_reject_threshold.push(key.clone());
            }
            local.files_ingested += 1;
            marks.push((key, sha256));
        }
        mark(conn, &marks)
    })();

    match written {
        Ok(()) => {
            conn.execute_batch("COMMIT")
                .context("Failed to commit flow chunk")?;
            ingested.extend(marks);
            stats.absorb(local);
            Ok(())
        }
        Err(e) => {
            conn.execute_batch("ROLLBACK")
                .context("Failed to roll back flow chunk")?;
            Err(e)
        }
    }
}

/// Fill `ip_geo` for every flow address not yet in it. Returns the number added.
///
/// Memory stays bounded however many distinct peers the logs hold: DuckDB
/// computes the pending set, and Rust holds one page of it at a time.
pub fn populate_ip_geo(conn: &Connection, geoip: &GeoipEnricher) -> Result<usize> {
    ensure_flow_tables(conn)?;
    conn.execute_batch(
        "
        CREATE OR REPLACE TEMP TABLE _pending_ip AS
        SELECT addr FROM (
            SELECT srcaddr     AS addr FROM vpc_flow_logs
            UNION SELECT dstaddr     FROM vpc_flow_logs
            UNION SELECT pkt_srcaddr FROM vpc_flow_logs
            UNION SELECT pkt_dstaddr FROM vpc_flow_logs
        ) a
        WHERE addr IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM ip_geo g WHERE g.ip = a.addr);
        ",
    )
    .context("Failed to collect pending flow addresses")?;

    let mut added = 0;
    let mut after = String::new();
    loop {
        let page: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT addr FROM _pending_ip WHERE addr > ? ORDER BY addr LIMIT ?")
                .context("Failed to page pending flow addresses")?;
            stmt.query_map(duckdb::params![after, GEO_PAGE_SIZE as i64], |r| r.get(0))?
                .collect::<duckdb::Result<_>>()?
        };
        let Some(last) = page.last() else { break };
        after = last.clone();

        let mut appender = conn
            .appender("ip_geo")
            .context("Failed to create appender for ip_geo")?;
        for ip in &page {
            let g = geoip.lookup(ip);
            appender.append_row(duckdb::params![
                ip,
                g.country_code,
                g.country_name,
                g.city,
                g.latitude,
                g.longitude,
                g.asn,
                g.org,
            ])?;
        }
        appender
            .flush()
            .context("Failed to flush ip_geo appender")?;
        added += page.len();
    }

    conn.execute_batch("DROP TABLE IF EXISTS _pending_ip")
        .context("Failed to drop pending flow addresses")?;
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{make_enricher, setup_db};
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    use tempfile::TempDir;

    const V2_HEADER: &str = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status";

    fn row(src: &str, dst: &str) -> String {
        format!(
            "2 123456789012 eni-1 {src} {dst} 40000 443 6 10 900 1705276800 1705276860 ACCEPT OK"
        )
    }

    fn flow_name(n: u32) -> String {
        format!("123456789012_vpcflowlogs_us-east-1_fl-0abc_20240115T00{n:02}Z_h{n}.log.gz")
    }

    fn write_gz(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        let mut enc = GzEncoder::new(std::fs::File::create(&path).unwrap(), Compression::fast());
        enc.write_all(body.as_bytes()).unwrap();
        enc.finish().unwrap();
        path
    }

    fn flow_file(dir: &Path, n: u32, rows: &[String]) -> PathBuf {
        let mut body = vec![V2_HEADER.to_string()];
        body.extend(rows.iter().cloned());
        write_gz(dir, &flow_name(n), &body.join("\n"))
    }

    fn db() -> Connection {
        let conn = setup_db();
        ensure_flow_tables(&conn).unwrap();
        conn
    }

    fn count(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn run(conn: &Connection, files: &[PathBuf]) -> FlowStats {
        let mut map = crate::db::fetch_ingested_files_map(conn).unwrap();
        ingest_flow_files(conn, files.to_vec(), &mut map, FlowIngestOptions::default()).unwrap()
    }

    // FI-01: flow files are parsed, written and marked.
    #[test]
    fn test_ingest_writes_records_files_and_marks() {
        let dir = TempDir::new().unwrap();
        let a = flow_file(
            dir.path(),
            1,
            &[row("10.0.0.1", "10.0.0.2"), row("10.0.0.1", "10.0.0.3")],
        );
        let b = flow_file(dir.path(), 2, &[row("10.0.0.1", "10.0.0.4")]);
        let conn = db();
        let stats = run(&conn, &[a, b]);
        assert_eq!(stats.files_ingested, 2);
        assert_eq!(stats.records_inserted, 3);
        assert_eq!(count(&conn, "SELECT count(*) FROM vpc_flow_logs"), 3);
        assert_eq!(count(&conn, "SELECT count(*) FROM vpc_flow_files"), 2);
        assert_eq!(count(&conn, "SELECT count(*) FROM ingested_files"), 2);
        assert_eq!(
            count(
                &conn,
                "SELECT count(*) FROM vpc_flow_logs WHERE flow_log_id = 'fl-0abc'"
            ),
            3
        );
    }

    // FI-02: an unchanged re-run writes nothing.
    #[test]
    fn test_rerun_is_deduplicated() {
        let dir = TempDir::new().unwrap();
        let a = flow_file(dir.path(), 1, &[row("10.0.0.1", "10.0.0.2")]);
        let conn = db();
        run(&conn, std::slice::from_ref(&a));
        let stats = run(&conn, &[a]);
        assert_eq!(stats.files_unchanged, 1);
        assert_eq!(stats.files_ingested, 0);
        assert_eq!(count(&conn, "SELECT count(*) FROM vpc_flow_logs"), 1);
    }

    // FI-03: a changed file under the same path replaces its old rows.
    #[test]
    fn test_changed_file_replaces_rows() {
        let dir = TempDir::new().unwrap();
        let a = flow_file(dir.path(), 1, &[row("10.0.0.1", "10.0.0.2")]);
        let conn = db();
        run(&conn, std::slice::from_ref(&a));
        flow_file(
            dir.path(),
            1,
            &[row("10.0.0.9", "10.0.0.2"), row("10.0.0.9", "10.0.0.3")],
        );
        let stats = run(&conn, &[a]);
        assert_eq!(stats.files_ingested, 1);
        assert_eq!(count(&conn, "SELECT count(*) FROM vpc_flow_logs"), 2);
        assert_eq!(
            count(
                &conn,
                "SELECT count(*) FROM vpc_flow_logs WHERE srcaddr = '10.0.0.1'"
            ),
            0
        );
        assert_eq!(count(&conn, "SELECT count(*) FROM vpc_flow_files"), 1);
    }

    // FI-04: unreadable or unrecognisable files fail individually and are not marked.
    #[test]
    fn test_failed_files_are_counted_and_not_marked() {
        let dir = TempDir::new().unwrap();
        let good = flow_file(dir.path(), 1, &[row("10.0.0.1", "10.0.0.2")]);
        let corrupt = dir.path().join(flow_name(2));
        std::fs::write(&corrupt, b"\x1f\x8b not really gzip").unwrap();
        let empty = write_gz(dir.path(), &flow_name(3), "");
        let elb = write_gz(
            dir.path(),
            &flow_name(4),
            "https 2024-01-15T00:00:00.000000Z app/lb/1 1.2.3.4:5 10.0.0.1:80 0.1 0.1 0.1 200 200 1 1 \"GET / HTTP/1.1\"",
        );
        let conn = db();
        let stats = run(&conn, &[good, corrupt, empty, elb]);
        assert_eq!(stats.files_ingested, 1);
        assert_eq!(stats.failed_files.len(), 3);
        assert_eq!(count(&conn, "SELECT count(*) FROM ingested_files"), 1);
    }

    // FI-05: a failing dedup mark rolls back the chunk; the retry writes exactly once.
    #[test]
    fn test_chunk_rolls_back_when_marking_fails() {
        let dir = TempDir::new().unwrap();
        let a = flow_file(
            dir.path(),
            1,
            &[row("10.0.0.1", "10.0.0.2"), "short".into()],
        );
        let conn = db();
        let parsed = vec![(a.clone(), parse_flow_file(&a))];
        let mut map = HashMap::new();
        let mut stats = FlowStats::default();

        let failing = |_: &Connection, _: &[(String, String)]| -> Result<()> {
            anyhow::bail!("injected mark failure")
        };
        assert!(write_chunk(&conn, parsed, &mut map, &mut stats, failing).is_err());
        for table in [
            "vpc_flow_logs",
            "vpc_flow_files",
            "vpc_flow_parse_issues",
            "ingested_files",
        ] {
            assert_eq!(
                count(&conn, &format!("SELECT count(*) FROM {table}")),
                0,
                "{table}"
            );
        }
        assert!(map.is_empty());
        assert_eq!(stats, FlowStats::default());

        let parsed = vec![(a.clone(), parse_flow_file(&a))];
        write_chunk(&conn, parsed, &mut map, &mut stats, batch_mark_ingested).unwrap();
        assert_eq!(count(&conn, "SELECT count(*) FROM vpc_flow_logs"), 1);
        assert_eq!(
            count(&conn, "SELECT count(*) FROM vpc_flow_parse_issues"),
            1
        );
        assert_eq!(stats.records_inserted, 1);
        assert_eq!(stats.rows_rejected, 1);
    }

    // FI-06: a file above the rejected-row threshold is named in a warning.
    #[test]
    fn test_reject_threshold_warning() {
        let dir = TempDir::new().unwrap();
        let mut rows: Vec<String> = (0..10).map(|_| row("10.0.0.1", "10.0.0.2")).collect();
        rows.push("broken".into());
        let noisy = flow_file(dir.path(), 1, &rows);
        let clean = flow_file(dir.path(), 2, &[row("10.0.0.1", "10.0.0.2")]);
        let conn = db();
        let stats = run(&conn, &[noisy.clone(), clean]);
        assert_eq!(
            stats.files_over_reject_threshold,
            vec![noisy.to_string_lossy().into_owned()]
        );
    }

    // FI-09: chunks are capped by compressed bytes, never split a file, never come out empty.
    #[test]
    fn test_chunk_by_size() {
        let f = |name: &str, len: u64| (PathBuf::from(name), len);
        let chunks = chunk_by_size(
            vec![f("a", 4), f("b", 4), f("c", 4), f("huge", 100), f("d", 1)],
            10,
        );
        let names: Vec<Vec<&str>> = chunks
            .iter()
            .map(|c| c.iter().map(|p| p.to_str().unwrap()).collect())
            .collect();
        assert_eq!(
            names,
            vec![vec!["a", "b"], vec!["c"], vec!["huge"], vec!["d"]]
        );
        assert!(chunk_by_size(Vec::new(), 10).is_empty());
    }

    // FI-07: ip_geo gets every distinct address from all four address columns, once.
    #[test]
    fn test_populate_ip_geo_is_distinct_and_idempotent() {
        let conn = db();
        let parsed = crate::flow_parser::parse_flow_log(
            "srcaddr dstaddr pkt-srcaddr pkt-dstaddr flow-direction log-status\n\
             10.0.0.1 10.0.0.220 10.0.0.1 81.2.69.160 egress OK\n\
             81.2.69.160 10.0.0.1 81.2.69.160 10.0.0.1 ingress OK",
        )
        .unwrap();
        let meta = crate::flow_db::FlowFileMeta::from_path(Path::new("/f"));
        crate::flow_db::append_flow_file(&conn, &meta, &parsed).unwrap();

        let enricher = make_enricher();
        assert_eq!(populate_ip_geo(&conn, &enricher).unwrap(), 3);
        assert_eq!(populate_ip_geo(&conn, &enricher).unwrap(), 0);
        let gb: String = conn
            .query_row(
                "SELECT country_code FROM ip_geo WHERE ip = '81.2.69.160'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(gb, "GB");
        let private: String = conn
            .query_row(
                "SELECT country_code FROM ip_geo WHERE ip = '10.0.0.220'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(private, "PRIVATE");
        let remote_geo: String = conn
            .query_row(
                "SELECT remote_geo_country_code FROM vpc_flow_logs_geo WHERE flow_direction = 'egress'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(remote_geo, "GB");
    }

    // FI-08: with an enricher, ingestion runs the post-pass and reports it.
    #[test]
    fn test_ingest_runs_geo_post_pass() {
        let dir = TempDir::new().unwrap();
        let a = flow_file(dir.path(), 1, &[row("10.0.0.1", "81.2.69.160")]);
        let conn = db();
        let enricher = make_enricher();
        let mut map = HashMap::new();
        let stats = ingest_flow_files(
            &conn,
            vec![a],
            &mut map,
            FlowIngestOptions {
                geoip: Some(&enricher),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(stats.geo_addresses_added, 2);
    }
}
