//! DuckDB schema management and batch writes for AWS Config snapshot tables.
//!
//! Only `ingester` opens DuckDB in `READ_WRITE` mode. All three Config tables
//! (`config_snapshots`, `config_resources`, `config_edges`) are created here
//! and written via `duckdb::Appender` for high-throughput batch inserts.

use anyhow::{Context, Result};
use duckdb::{Appender, Connection, ToSql};

// ── Schema ────────────────────────────────────────────────────────────────────

/// Create `config_snapshots`, `config_resources`, and `config_edges` if they
/// do not exist.
///
/// Idempotent — safe to call on every `config-import` run.
/// Also applies a schema migration if `config_resources` was created with the
/// old 2-column PRIMARY KEY `(resource_id, snapshot_id)` rather than the
/// correct 3-column key `(resource_id, resource_type, snapshot_id)`.
pub fn ensure_config_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS config_snapshots (
            snapshot_id  VARCHAR PRIMARY KEY,
            account_id   VARCHAR,
            aws_region   VARCHAR,
            captured_at  TIMESTAMP,
            source_path  VARCHAR,
            record_count INTEGER
        );

        CREATE TABLE IF NOT EXISTS config_resources (
            resource_id   VARCHAR,
            snapshot_id   VARCHAR,
            resource_type VARCHAR,
            aws_region    VARCHAR,
            resource_name VARCHAR,
            configuration VARCHAR,
            tags          VARCHAR,
            PRIMARY KEY (resource_id, resource_type, snapshot_id)
        );

        CREATE TABLE IF NOT EXISTS config_edges (
            snapshot_id VARCHAR,
            source_id   VARCHAR,
            target_id   VARCHAR,
            edge_type   VARCHAR,
            PRIMARY KEY (snapshot_id, source_id, target_id, edge_type)
        );
        ",
    )
    .context("Failed to create Config snapshot tables")?;

    // Migration: if config_resources was created with the old 2-column PK
    // (resource_id, snapshot_id) it can fail when a snapshot contains multiple
    // resources that share a resourceId but differ in resourceType (which is
    // valid in AWS Config, e.g. "default" for EventBus, Glue Database, etc.).
    // Drop and recreate the table when the new key column is absent and no
    // rows exist (safe because the prior import would have failed anyway).
    migrate_config_resources_pk(conn)?;

    Ok(())
}

/// Check whether `config_resources` has the correct 3-column PRIMARY KEY.
///
/// If the table still carries the old 2-column key and has zero rows, drops
/// and recreates both `config_resources` and `config_edges` with the correct
/// schema.  When rows are present the migration is skipped and a warning is
/// printed — the caller should truncate the tables manually before re-running.
fn migrate_config_resources_pk(conn: &Connection) -> Result<()> {
    // Query duckdb_constraints() to check whether 'resource_type' appears in
    // the PRIMARY KEY of config_resources.  Returns 0 rows if the table does
    // not exist yet (handled safely by unwrap_or(0)).
    let pk_col_count: i64 = conn
        .query_row(
            "SELECT CASE
                 WHEN list_contains(constraint_column_names, 'resource_type') THEN 1
                 ELSE 0
             END
             FROM duckdb_constraints()
             WHERE table_name = 'config_resources'
               AND constraint_type = 'PRIMARY KEY'
             LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    if pk_col_count == 1 {
        return Ok(()); // Schema is already correct.
    }

    // Old schema detected.  Check whether any rows exist.
    let row_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM config_resources", [], |r| r.get(0))
        .unwrap_or(0);

    if row_count > 0 {
        eprintln!(
            "warn: config_resources has the old 2-column PRIMARY KEY with {row_count} rows. \
             Clear and re-run config-import to apply the schema migration."
        );
        return Ok(());
    }

    // Safe to drop and recreate — 0 rows, so no data loss.
    conn.execute_batch(
        "DROP TABLE IF EXISTS config_edges;
         DROP TABLE IF EXISTS config_resources;
         CREATE TABLE config_resources (
             resource_id   VARCHAR,
             snapshot_id   VARCHAR,
             resource_type VARCHAR,
             aws_region    VARCHAR,
             resource_name VARCHAR,
             configuration VARCHAR,
             tags          VARCHAR,
             PRIMARY KEY (resource_id, resource_type, snapshot_id)
         );
         CREATE TABLE config_edges (
             snapshot_id VARCHAR,
             source_id   VARCHAR,
             target_id   VARCHAR,
             edge_type   VARCHAR,
             PRIMARY KEY (snapshot_id, source_id, target_id, edge_type)
         );",
    )
    .context("Failed to migrate config_resources to 3-column PRIMARY KEY")?;

    Ok(())
}

// ── Row types ─────────────────────────────────────────────────────────────────

/// A Config snapshot metadata row for `config_snapshots`.
pub struct ConfigSnapshot {
    pub snapshot_id: String,
    pub account_id: Option<String>,
    pub aws_region: Option<String>,
    /// DuckDB-compatible timestamp string: `"YYYY-MM-DD HH:MM:SS.mmm"`.
    pub captured_at: Option<String>,
    pub source_path: String,
    pub record_count: i64,
}

/// A single resource row for `config_resources`.
pub struct ConfigResource {
    pub resource_id: String,
    pub snapshot_id: String,
    pub resource_type: String,
    pub aws_region: Option<String>,
    pub resource_name: Option<String>,
    /// Compact JSON string serialised from the `configuration` sub-object.
    pub configuration: Option<String>,
    /// Compact JSON string serialised from the `tags` map, or `None` when empty.
    pub tags: Option<String>,
}

/// A single directed edge row for `config_edges`.
pub struct ConfigEdge {
    pub snapshot_id: String,
    pub source_id: String,
    pub target_id: String,
    pub edge_type: String,
}

// ── Writers ───────────────────────────────────────────────────────────────────

/// Insert one snapshot metadata row, ignoring the row if `snapshot_id` already
/// exists (`ON CONFLICT DO NOTHING`).
///
/// Returns `true` when a new row was inserted, `false` when the `snapshot_id`
/// was already present and the insert was silently skipped.
pub fn insert_config_snapshot(conn: &Connection, snap: &ConfigSnapshot) -> Result<bool> {
    let rows_changed = conn
        .execute(
            "INSERT OR IGNORE INTO config_snapshots
             (snapshot_id, account_id, aws_region, captured_at, source_path, record_count)
         VALUES (?, ?, ?, ?, ?, ?)",
            duckdb::params![
                snap.snapshot_id,
                snap.account_id,
                snap.aws_region,
                snap.captured_at,
                snap.source_path,
                snap.record_count,
            ],
        )
        .context("Failed to insert config_snapshots row")?;
    Ok(rows_changed > 0)
}

/// Bulk-insert resource rows into `config_resources` via `duckdb::Appender`.
///
/// Returns immediately when `resources` is empty.
pub fn insert_config_resources(conn: &Connection, resources: &[ConfigResource]) -> Result<()> {
    if resources.is_empty() {
        return Ok(());
    }
    let mut app: Appender<'_> = conn
        .appender("config_resources")
        .context("Failed to create appender for config_resources")?;

    for r in resources {
        let params: Vec<&dyn ToSql> = vec![
            &r.resource_id,
            &r.snapshot_id,
            &r.resource_type,
            &r.aws_region,
            &r.resource_name,
            &r.configuration,
            &r.tags,
        ];
        app.append_row(params.as_slice())
            .context("Failed to append config_resources row")?;
    }
    app.flush()
        .context("Failed to flush config_resources appender")
}

/// Bulk-insert edge rows into `config_edges` via `duckdb::Appender`.
///
/// Returns immediately when `edges` is empty.
pub fn insert_config_edges(conn: &Connection, edges: &[ConfigEdge]) -> Result<()> {
    if edges.is_empty() {
        return Ok(());
    }
    let mut app: Appender<'_> = conn
        .appender("config_edges")
        .context("Failed to create appender for config_edges")?;

    for e in edges {
        let params: Vec<&dyn ToSql> =
            vec![&e.snapshot_id, &e.source_id, &e.target_id, &e.edge_type];
        app.append_row(params.as_slice())
            .context("Failed to append config_edges row")?;
    }
    app.flush().context("Failed to flush config_edges appender")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::temp_db;

    fn setup() -> Connection {
        let conn = temp_db();
        ensure_config_tables(&conn).expect("ensure_config_tables should succeed");
        conn
    }

    // Test CDB-01: ensure_config_tables creates all three tables.
    #[test]
    fn test_ensure_config_tables_creates_tables() {
        let conn = setup();
        for table in ["config_snapshots", "config_resources", "config_edges"] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap_or_else(|_| panic!("table {table} should exist and be queryable"));
            assert_eq!(count, 0, "table {table} should be empty after creation");
        }
    }

    // Test CDB-02: ensure_config_tables is idempotent (called twice without error).
    #[test]
    fn test_ensure_config_tables_is_idempotent() {
        let conn = setup();
        ensure_config_tables(&conn).expect("second call should not error");
    }

    // Test CDB-03: insert_config_snapshot inserts exactly one row.
    #[test]
    fn test_insert_config_snapshot_inserts_row() {
        let conn = setup();
        let snap = ConfigSnapshot {
            snapshot_id: "snap-001".to_string(),
            account_id: Some("123456789012".to_string()),
            aws_region: Some("ap-northeast-1".to_string()),
            captured_at: Some("2026-01-01 00:00:00".to_string()),
            source_path: "/data/snap.json".to_string(),
            record_count: 10,
        };
        let inserted = insert_config_snapshot(&conn, &snap).expect("insert should succeed");
        assert!(inserted, "first insert should return true (new row)");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM config_snapshots", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    // Test CDB-04: insert_config_snapshot is idempotent (INSERT OR IGNORE).
    #[test]
    fn test_insert_config_snapshot_is_idempotent() {
        let conn = setup();
        let snap = ConfigSnapshot {
            snapshot_id: "snap-001".to_string(),
            account_id: None,
            aws_region: None,
            captured_at: None,
            source_path: "/data/snap.json".to_string(),
            record_count: 0,
        };
        let inserted1 = insert_config_snapshot(&conn, &snap).expect("first insert should succeed");
        assert!(inserted1, "first insert should return true");
        let inserted2 =
            insert_config_snapshot(&conn, &snap).expect("second insert should not error");
        assert!(
            !inserted2,
            "second insert should return false (already existed)"
        );

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM config_snapshots", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "duplicate insert should be silently ignored");
    }

    // Test CDB-05: insert_config_resources stores configuration JSON correctly.
    #[test]
    fn test_insert_config_resources_stores_configuration() {
        let conn = setup();
        let res = ConfigResource {
            resource_id: "i-12345".to_string(),
            snapshot_id: "snap-001".to_string(),
            resource_type: "AWS::EC2::Instance".to_string(),
            aws_region: Some("ap-northeast-1".to_string()),
            resource_name: Some("web-server".to_string()),
            configuration: Some(r#"{"instanceType":"t3.micro"}"#.to_string()),
            tags: Some(r#"{"Name":"web-server"}"#.to_string()),
        };
        insert_config_resources(&conn, &[res]).expect("insert should succeed");

        let (rid, cfg): (String, Option<String>) = conn
            .query_row(
                "SELECT resource_id, configuration FROM config_resources LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(rid, "i-12345");
        assert!(
            cfg.as_deref().unwrap().contains("t3.micro"),
            "configuration JSON should contain instanceType value"
        );
    }

    // Test CDB-06: insert_config_resources writes NULL for None tags.
    #[test]
    fn test_insert_config_resources_null_tags_written_as_null() {
        let conn = setup();
        let res = ConfigResource {
            resource_id: "sg-aaaa".to_string(),
            snapshot_id: "snap-001".to_string(),
            resource_type: "AWS::EC2::SecurityGroup".to_string(),
            aws_region: None,
            resource_name: None,
            configuration: None,
            tags: None,
        };
        insert_config_resources(&conn, &[res]).expect("insert with null tags should succeed");

        let tags: Option<String> = conn
            .query_row("SELECT tags FROM config_resources LIMIT 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(
            tags.is_none(),
            "tags column should be NULL when None is passed"
        );
    }

    // Test CDB-07: insert_config_edges inserts the correct number of rows.
    #[test]
    fn test_insert_config_edges_inserts_rows() {
        let conn = setup();
        let edges = vec![ConfigEdge {
            snapshot_id: "snap-001".to_string(),
            source_id: "i-12345".to_string(),
            target_id: "sg-aaaa".to_string(),
            edge_type: "Is associated with".to_string(),
        }];
        insert_config_edges(&conn, &edges).expect("insert should succeed");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM config_edges", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    // Test CDB-08: insert_config_edges with empty slice is a no-op.
    #[test]
    fn test_insert_config_edges_empty_slice_is_noop() {
        let conn = setup();
        insert_config_edges(&conn, &[]).expect("empty insert should not error");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM config_edges", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "no rows should be inserted for an empty slice");
    }

    // Test CDB-09: two resources that share resource_id but differ in resource_type
    // must both be insertable without a PRIMARY KEY violation.
    // This covers the real-world case where AWS Config uses "default" as the
    // resourceId for multiple resource types (EventBus, Glue Database, etc.).
    #[test]
    fn test_insert_config_resources_same_id_different_type_allowed() {
        let conn = setup();
        let resources = vec![
            ConfigResource {
                resource_id: "default".to_string(),
                snapshot_id: "snap-001".to_string(),
                resource_type: "AWS::Events::EventBus".to_string(),
                aws_region: None,
                resource_name: Some("default".to_string()),
                configuration: None,
                tags: None,
            },
            ConfigResource {
                resource_id: "default".to_string(),
                snapshot_id: "snap-001".to_string(),
                resource_type: "AWS::Glue::Database".to_string(),
                aws_region: None,
                resource_name: Some("default".to_string()),
                configuration: None,
                tags: None,
            },
        ];
        insert_config_resources(&conn, &resources).expect(
            "two resources sharing resource_id but differing in resource_type must not conflict",
        );

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM config_resources", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2, "both rows must be present");
    }

    // Test CDB-10: ensure_config_tables migrates an old 2-column PK to the
    // correct 3-column PK when the table is empty.
    #[test]
    fn test_ensure_config_tables_migrates_old_pk() {
        let conn = temp_db();

        // Create config_resources with the old 2-column PK directly.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS config_snapshots (
                 snapshot_id VARCHAR PRIMARY KEY,
                 account_id VARCHAR, aws_region VARCHAR,
                 captured_at TIMESTAMP, source_path VARCHAR, record_count INTEGER
             );
             CREATE TABLE IF NOT EXISTS config_resources (
                 resource_id VARCHAR, snapshot_id VARCHAR,
                 resource_type VARCHAR, aws_region VARCHAR,
                 resource_name VARCHAR, configuration VARCHAR, tags VARCHAR,
                 PRIMARY KEY (resource_id, snapshot_id)
             );
             CREATE TABLE IF NOT EXISTS config_edges (
                 snapshot_id VARCHAR, source_id VARCHAR,
                 target_id VARCHAR, edge_type VARCHAR,
                 PRIMARY KEY (snapshot_id, source_id, target_id, edge_type)
             );",
        )
        .unwrap();

        // Calling ensure_config_tables should silently migrate the schema.
        ensure_config_tables(&conn).expect("migration must not error");

        // After migration, two resources with the same id but different types must coexist.
        let resources = vec![
            ConfigResource {
                resource_id: "default".to_string(),
                snapshot_id: "snap-001".to_string(),
                resource_type: "AWS::Events::EventBus".to_string(),
                aws_region: None,
                resource_name: None,
                configuration: None,
                tags: None,
            },
            ConfigResource {
                resource_id: "default".to_string(),
                snapshot_id: "snap-001".to_string(),
                resource_type: "AWS::Glue::Database".to_string(),
                aws_region: None,
                resource_name: None,
                configuration: None,
                tags: None,
            },
        ];
        insert_config_resources(&conn, &resources).expect("insert after migration must succeed");

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM config_resources", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }
}
