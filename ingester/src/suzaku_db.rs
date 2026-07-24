//! DuckDB schema management and batch writes for the Suzaku detection tables.
//!
//! Only `ingester` opens DuckDB in `READ_WRITE` mode.  Both Suzaku tables —
//! `suzaku_detections` (one row per rule hit) and `suzaku_detection_tags`
//! (one row per ATT&CK tag on a hit) — are created here and written via
//! `duckdb::Appender`.
//!
//! `suzaku_detection_tags` exists because Suzaku folds a rule's whole `tags`
//! list into a single ` ¦ `-separated string.  Grouping a chart by that string
//! produces meaningless combination buckets (`"CredAccess ¦ Disc"`), so the
//! list is exploded into a tidy long table that the ATT&CK dashboard charts
//! group by directly — no joins, since Superset datasets are single-table.

use anyhow::{Context, Result};
use duckdb::{Appender, Connection, ToSql};

// ── Schema ────────────────────────────────────────────────────────────────────

/// Create `suzaku_detections` and `suzaku_detection_tags` if they do not exist.
///
/// Idempotent — safe to call on every `suzaku-import` run.  It is also called
/// by `ingest` so that the Suzaku dashboard renders empty charts rather than
/// "table does not exist" errors on a database where no detections have been
/// imported yet.
///
/// The Appender writes positionally, so the column order declared here is the
/// contract that [`insert_suzaku_detections`] and
/// [`insert_suzaku_detection_tags`] rely on.
pub fn ensure_suzaku_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS suzaku_detections (
            detection_id     VARCHAR PRIMARY KEY,
            detected_at      TIMESTAMP,
            rule_title       VARCHAR,
            rule_id          VARCHAR,
            rule_author      VARCHAR,
            level            VARCHAR,
            level_rank       INTEGER,
            tags             VARCHAR,
            mitre_tactics    VARCHAR,
            mitre_techniques VARCHAR,
            cloud_provider   VARCHAR,
            event_name       VARCHAR,
            event_source     VARCHAR,
            aws_region       VARCHAR,
            source_ip        VARCHAR,
            src_country      VARCHAR,
            src_city         VARCHAR,
            src_asn          VARCHAR,
            user_name        VARCHAR,
            user_type        VARCHAR,
            user_arn         VARCHAR,
            account_id       VARCHAR,
            principal_id     VARCHAR,
            access_key_id    VARCHAR,
            user_agent       VARCHAR,
            error_code       VARCHAR,
            error_message    VARCHAR,
            outcome          VARCHAR,
            event_id         VARCHAR,
            target_object    VARCHAR,
            record_type      VARCHAR,
            app_id           VARCHAR,
            category         VARCHAR,
            details          VARCHAR,
            source_path      VARCHAR,
            source_sha       VARCHAR,
            raw_row          VARCHAR
        );

        CREATE TABLE IF NOT EXISTS suzaku_detection_tags (
            detection_id   VARCHAR,
            detected_at    TIMESTAMP,
            level          VARCHAR,
            level_rank     INTEGER,
            rule_title     VARCHAR,
            cloud_provider VARCHAR,
            user_name      VARCHAR,
            source_ip      VARCHAR,
            src_country    VARCHAR,
            tag_type       VARCHAR,
            tag_value      VARCHAR,
            source_sha     VARCHAR,
            PRIMARY KEY (detection_id, tag_type, tag_value)
        );
        ",
    )
    .context("Failed to create Suzaku detection tables")?;

    ensure_suzaku_indexes(conn)
}

/// Create ART indexes on the columns the dashboard filters on most.
///
/// Mirrors `db::ensure_indexes`: equality/`IN` filter columns only.
/// `detected_at` is deliberately omitted — DuckDB's per-row-group zone maps
/// already handle range filters efficiently.
fn ensure_suzaku_indexes(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE INDEX IF NOT EXISTS idx_suzaku_detections_level
            ON suzaku_detections (level);
        CREATE INDEX IF NOT EXISTS idx_suzaku_detections_rule_title
            ON suzaku_detections (rule_title);
        CREATE INDEX IF NOT EXISTS idx_suzaku_detections_source_ip
            ON suzaku_detections (source_ip);
        CREATE INDEX IF NOT EXISTS idx_suzaku_detection_tags_value
            ON suzaku_detection_tags (tag_value);
        ",
    )
    .context("Failed to create Suzaku detection indexes")
}

// ── Row types ─────────────────────────────────────────────────────────────────

/// One normalised Suzaku rule hit, ready for `suzaku_detections`.
///
/// Every optional field is `None` when the source profile has no such column,
/// or when Suzaku wrote its `"-"` placeholder for the event.  Field order
/// matches the `CREATE TABLE` in [`ensure_suzaku_tables`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuzakuDetection {
    /// Deterministic `sha256(source_sha:row_index)` identifier.
    pub detection_id: String,
    /// Event timestamp normalised to UTC (`"YYYY-MM-DD HH:MM:SS.mmm"`).
    pub detected_at: Option<String>,
    pub rule_title: Option<String>,
    pub rule_id: Option<String>,
    pub rule_author: Option<String>,
    /// Sigma level, lower-cased (`critical` … `informational`).
    pub level: Option<String>,
    /// Sortable severity: critical=5 … informational=1, unknown=0.
    pub level_rank: i32,
    /// The raw ` ¦ `-separated Suzaku tag string.
    pub tags: Option<String>,
    /// ATT&CK tactic abbreviations from `tags`, ` ¦ `-separated.
    pub mitre_tactics: Option<String>,
    /// ATT&CK technique IDs from `tags`, ` ¦ `-separated.
    pub mitre_techniques: Option<String>,
    /// `aws`, `azure`, or `unknown` — inferred from the profile columns.
    pub cloud_provider: String,
    pub event_name: Option<String>,
    pub event_source: Option<String>,
    pub aws_region: Option<String>,
    pub source_ip: Option<String>,
    pub src_country: Option<String>,
    pub src_city: Option<String>,
    pub src_asn: Option<String>,
    pub user_name: Option<String>,
    pub user_type: Option<String>,
    pub user_arn: Option<String>,
    pub account_id: Option<String>,
    pub principal_id: Option<String>,
    pub access_key_id: Option<String>,
    pub user_agent: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    /// `Success` / `Failure` (or the raw Azure result when it is neither).
    pub outcome: Option<String>,
    pub event_id: Option<String>,
    pub target_object: Option<String>,
    pub record_type: Option<String>,
    pub app_id: Option<String>,
    pub category: Option<String>,
    pub details: Option<String>,
    /// Path of the Suzaku `.duckdb` file this row came from.
    pub source_path: String,
    /// SHA-256 of that file — the delete-then-append idempotency key.
    pub source_sha: String,
    /// The original Suzaku row as a JSON object, verbatim (placeholders
    /// included), so a custom output profile never loses data.
    pub raw_row: String,
}

/// One ATT&CK (or other) tag attached to a detection.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuzakuDetectionTag {
    pub detection_id: String,
    pub detected_at: Option<String>,
    pub level: Option<String>,
    pub level_rank: i32,
    pub rule_title: Option<String>,
    pub cloud_provider: String,
    pub user_name: Option<String>,
    pub source_ip: Option<String>,
    pub src_country: Option<String>,
    /// `tactic`, `technique`, `group`, or `other`.
    pub tag_type: String,
    pub tag_value: String,
    pub source_sha: String,
}

// ── Writers ───────────────────────────────────────────────────────────────────

/// Bulk-insert detection rows via `duckdb::Appender`.
///
/// Returns immediately when `detections` is empty.
pub fn insert_suzaku_detections(conn: &Connection, detections: &[SuzakuDetection]) -> Result<()> {
    if detections.is_empty() {
        return Ok(());
    }
    let mut app: Appender<'_> = conn
        .appender("suzaku_detections")
        .context("Failed to create appender for suzaku_detections")?;

    for d in detections {
        let params: Vec<&dyn ToSql> = vec![
            &d.detection_id,
            &d.detected_at,
            &d.rule_title,
            &d.rule_id,
            &d.rule_author,
            &d.level,
            &d.level_rank,
            &d.tags,
            &d.mitre_tactics,
            &d.mitre_techniques,
            &d.cloud_provider,
            &d.event_name,
            &d.event_source,
            &d.aws_region,
            &d.source_ip,
            &d.src_country,
            &d.src_city,
            &d.src_asn,
            &d.user_name,
            &d.user_type,
            &d.user_arn,
            &d.account_id,
            &d.principal_id,
            &d.access_key_id,
            &d.user_agent,
            &d.error_code,
            &d.error_message,
            &d.outcome,
            &d.event_id,
            &d.target_object,
            &d.record_type,
            &d.app_id,
            &d.category,
            &d.details,
            &d.source_path,
            &d.source_sha,
            &d.raw_row,
        ];
        app.append_row(params.as_slice())
            .context("Failed to append suzaku_detections row")?;
    }
    app.flush()
        .context("Failed to flush suzaku_detections appender")
}

/// Bulk-insert tag rows via `duckdb::Appender`.
///
/// Returns immediately when `tags` is empty.
pub fn insert_suzaku_detection_tags(conn: &Connection, tags: &[SuzakuDetectionTag]) -> Result<()> {
    if tags.is_empty() {
        return Ok(());
    }
    let mut app: Appender<'_> = conn
        .appender("suzaku_detection_tags")
        .context("Failed to create appender for suzaku_detection_tags")?;

    for t in tags {
        let params: Vec<&dyn ToSql> = vec![
            &t.detection_id,
            &t.detected_at,
            &t.level,
            &t.level_rank,
            &t.rule_title,
            &t.cloud_provider,
            &t.user_name,
            &t.source_ip,
            &t.src_country,
            &t.tag_type,
            &t.tag_value,
            &t.source_sha,
        ];
        app.append_row(params.as_slice())
            .context("Failed to append suzaku_detection_tags row")?;
    }
    app.flush()
        .context("Failed to flush suzaku_detection_tags appender")
}

/// Delete every row previously imported from this Suzaku output.
///
/// Called immediately before re-appending a file's rows, which is what makes
/// an import idempotent.  Both keys are needed, for two different re-runs:
///
/// * **`source_path`** — Suzaku was re-run over more logs and overwrote its
///   output file.  The content (and therefore the SHA) changed, so only the
///   path identifies the superseded rows.
/// * **`source_sha`** — the same output is imported again from a second path
///   (a copy, a rename, a backup directory).  Detection IDs are derived from
///   the content hash, so without this the re-import would collide with the
///   existing rows' `detection_id` PRIMARY KEY.
///
/// The `Appender` cannot express `ON CONFLICT`, so replacement is done with
/// this one bulk `DELETE` instead — the same documented exception
/// `batch_mark_ingested` makes for its upsert.
///
/// Returns the number of detection rows removed.
pub fn delete_detections_for_source(
    conn: &Connection,
    source_path: &str,
    source_sha: &str,
) -> Result<usize> {
    conn.execute(
        "DELETE FROM suzaku_detection_tags
         WHERE source_sha = ?
            OR detection_id IN (SELECT detection_id FROM suzaku_detections WHERE source_path = ?)",
        [source_sha, source_path],
    )
    .context("Failed to delete previous suzaku_detection_tags rows")?;
    let removed = conn
        .execute(
            "DELETE FROM suzaku_detections WHERE source_sha = ? OR source_path = ?",
            [source_sha, source_path],
        )
        .context("Failed to delete previous suzaku_detections rows")?;
    Ok(removed)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::temp_db;

    fn setup() -> Connection {
        let conn = temp_db();
        ensure_suzaku_tables(&conn).expect("ensure_suzaku_tables should succeed");
        conn
    }

    fn sample_detection(id: &str, sha: &str) -> SuzakuDetection {
        SuzakuDetection {
            detection_id: id.to_string(),
            detected_at: Some("2024-08-18 10:07:56.000".to_string()),
            rule_title: Some("AWS EFS Fileshare Modified or Deleted".to_string()),
            rule_id: Some("25cb1ba1-8a19-4a23-a198-d252664c8cef".to_string()),
            rule_author: Some("Austin Songer".to_string()),
            level: Some("medium".to_string()),
            level_rank: 3,
            tags: Some("Impact".to_string()),
            mitre_tactics: Some("Impact".to_string()),
            mitre_techniques: None,
            cloud_provider: "aws".to_string(),
            event_name: Some("DeleteFileSystem".to_string()),
            event_source: Some("elasticfilesystem.amazonaws.com".to_string()),
            aws_region: Some("us-east-1".to_string()),
            source_ip: Some("203.0.113.7".to_string()),
            src_country: None,
            src_city: None,
            src_asn: None,
            user_name: Some("TrailDiscover".to_string()),
            user_type: Some("IAMUser".to_string()),
            user_arn: Some("arn:aws:iam::111111111111:user/TrailDiscover".to_string()),
            account_id: Some("111111111111".to_string()),
            principal_id: None,
            access_key_id: None,
            user_agent: Some("aws-cli/2.17.32".to_string()),
            error_code: Some("AccessDenied".to_string()),
            error_message: Some("not authorized".to_string()),
            outcome: Some("Failure".to_string()),
            event_id: Some("1d8eaf44-b4ac-41b7-b40e-377ba7e11a82".to_string()),
            target_object: None,
            record_type: None,
            app_id: None,
            category: None,
            details: None,
            // One path per SHA, so the scoping test exercises both delete keys.
            source_path: format!("/data/suzaku/{sha}.duckdb"),
            source_sha: sha.to_string(),
            raw_row: r#"{"Level":"medium"}"#.to_string(),
        }
    }

    fn sample_tag(
        detection_id: &str,
        sha: &str,
        tag_type: &str,
        tag_value: &str,
    ) -> SuzakuDetectionTag {
        SuzakuDetectionTag {
            detection_id: detection_id.to_string(),
            detected_at: Some("2024-08-18 10:07:56.000".to_string()),
            level: Some("medium".to_string()),
            level_rank: 3,
            rule_title: Some("AWS EFS Fileshare Modified or Deleted".to_string()),
            cloud_provider: "aws".to_string(),
            user_name: Some("TrailDiscover".to_string()),
            source_ip: Some("203.0.113.7".to_string()),
            src_country: None,
            tag_type: tag_type.to_string(),
            tag_value: tag_value.to_string(),
            source_sha: sha.to_string(),
        }
    }

    // Test SDB-01: ensure_suzaku_tables creates both tables.
    #[test]
    fn test_ensure_suzaku_tables_creates_tables() {
        let conn = setup();
        for table in ["suzaku_detections", "suzaku_detection_tags"] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap_or_else(|_| panic!("table {table} should exist and be queryable"));
            assert_eq!(count, 0, "table {table} should be empty after creation");
        }
    }

    // Test SDB-02: ensure_suzaku_tables is idempotent.
    #[test]
    fn test_ensure_suzaku_tables_is_idempotent() {
        let conn = setup();
        ensure_suzaku_tables(&conn).expect("second call should not error");
    }

    // Test SDB-03: insert_suzaku_detections stores values and NULLs correctly.
    #[test]
    fn test_insert_suzaku_detections_stores_row() {
        let conn = setup();
        insert_suzaku_detections(&conn, &[sample_detection("det-1", "sha-1")])
            .expect("insert should succeed");

        let (title, rank, city): (String, i32, Option<String>) = conn
            .query_row(
                "SELECT rule_title, level_rank, src_city FROM suzaku_detections",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(title, "AWS EFS Fileshare Modified or Deleted");
        assert_eq!(rank, 3);
        assert!(city.is_none(), "absent profile columns must be stored NULL");
    }

    // Test SDB-04: detected_at is stored as a real TIMESTAMP, not a string.
    #[test]
    fn test_detected_at_is_a_timestamp_column() {
        let conn = setup();
        insert_suzaku_detections(&conn, &[sample_detection("det-1", "sha-1")]).unwrap();

        // date_trunc() only accepts a TIMESTAMP, so this fails on a VARCHAR column.
        let day: String = conn
            .query_row(
                "SELECT strftime(date_trunc('day', detected_at), '%Y-%m-%d') FROM suzaku_detections",
                [],
                |r| r.get(0),
            )
            .expect("detected_at must be a TIMESTAMP");
        assert_eq!(day, "2024-08-18");
    }

    // Test SDB-05: an empty slice is a no-op for both writers.
    #[test]
    fn test_insert_empty_slice_is_noop() {
        let conn = setup();
        insert_suzaku_detections(&conn, &[]).expect("empty detection insert should not error");
        insert_suzaku_detection_tags(&conn, &[]).expect("empty tag insert should not error");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM suzaku_detections", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    // Test SDB-06: insert_suzaku_detection_tags inserts one row per tag.
    #[test]
    fn test_insert_suzaku_detection_tags_inserts_rows() {
        let conn = setup();
        insert_suzaku_detection_tags(
            &conn,
            &[
                sample_tag("det-1", "sha-1", "tactic", "CredAccess"),
                sample_tag("det-1", "sha-1", "technique", "T1110"),
            ],
        )
        .expect("insert should succeed");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM suzaku_detection_tags", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 2);
    }

    // Test SDB-07: delete_detections_for_source clears both tables for that
    // SHA only, leaving rows imported from other files untouched.
    #[test]
    fn test_delete_detections_for_source_is_scoped_to_one_file() {
        let conn = setup();
        insert_suzaku_detections(
            &conn,
            &[
                sample_detection("det-1", "sha-1"),
                sample_detection("det-2", "sha-2"),
            ],
        )
        .unwrap();
        insert_suzaku_detection_tags(
            &conn,
            &[
                sample_tag("det-1", "sha-1", "tactic", "Impact"),
                sample_tag("det-2", "sha-2", "tactic", "Impact"),
            ],
        )
        .unwrap();

        let removed = delete_detections_for_source(&conn, "/data/suzaku/sha-1.duckdb", "sha-1")
            .expect("delete should succeed");
        assert_eq!(removed, 1, "exactly one detection row should be removed");

        let detections: i64 = conn
            .query_row("SELECT COUNT(*) FROM suzaku_detections", [], |r| r.get(0))
            .unwrap();
        let tags: i64 = conn
            .query_row("SELECT COUNT(*) FROM suzaku_detection_tags", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(detections, 1, "the other file's detection must survive");
        assert_eq!(tags, 1, "the other file's tag must survive");
    }

    // Test SDB-08: re-appending after delete_detections_for_source does not
    // violate the detection_id PRIMARY KEY (the re-import path).
    #[test]
    fn test_reimport_after_delete_does_not_violate_primary_key() {
        let conn = setup();
        insert_suzaku_detections(&conn, &[sample_detection("det-1", "sha-1")]).unwrap();
        delete_detections_for_source(&conn, "/data/suzaku/sha-1.duckdb", "sha-1").unwrap();
        insert_suzaku_detections(&conn, &[sample_detection("det-1", "sha-1")])
            .expect("re-append after delete must succeed");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM suzaku_detections", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "the row must be replaced, not duplicated");
    }
}
