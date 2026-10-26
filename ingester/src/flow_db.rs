//! DuckDB schema and writes for VPC Flow Logs.
//!
//! Tables: `vpc_flow_logs` (one row per observation), `vpc_flow_files` (one
//! row per ingested file), `vpc_flow_parse_issues` (bounded raw text of parse
//! problems) and `ip_geo` (one row per distinct address). Views:
//! `vpc_flow_sources`, `vpc_flow_unique`, `vpc_flow_logs_geo` and
//! `vpc_flow_log_configs`. Readers stay read-only: every view is created here.
//!
//! All row writes go through `appender_with_columns`, so the on-disk column
//! order never matters and `ADD COLUMN IF NOT EXISTS` migrations stay safe.
//! Callers own the transaction boundary (see `flow_ingest`).

use std::path::Path;

use anyhow::{Context, Result};
use duckdb::types::{TimeUnit, Value};
use duckdb::{Connection, ToSql, params};

use crate::flow_parser::{FLOW_FIELDS, ParsedFlowFile};

/// Provenance of one flow log file, taken from its AWS object name
/// `{account}_vpcflowlogs_{region}_{flow-log-id}_{timestamp}_{hash}.log.gz`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowFileMeta {
    pub file_path: String,
    pub flow_log_id: Option<String>,
    pub account_id: Option<String>,
    pub region: Option<String>,
}

impl FlowFileMeta {
    /// Read provenance from the object name; fields stay `None` for other names.
    pub fn from_path(path: &Path) -> Self {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let tokens: Vec<&str> = name.split('_').collect();
        let aws_named = tokens.len() >= 4
            && tokens[1] == "vpcflowlogs"
            && tokens[0].len() == 12
            && tokens[0].bytes().all(|b| b.is_ascii_digit())
            && tokens[3].starts_with("fl-");
        let token = |i: usize| aws_named.then(|| tokens[i].to_string());
        FlowFileMeta {
            file_path: path.to_string_lossy().into_owned(),
            account_id: token(0),
            region: token(2),
            flow_log_id: token(3),
        }
    }
}

/// Columns Senrigan computes, in the order [`append_flow_file`] binds them.
const DERIVED_COLUMNS: &[(&str, &str)] = &[
    ("start_time", "TIMESTAMP"),
    ("end_time", "TIMESTAMP"),
    ("duration_secs", "INTEGER"),
    ("protocol_name", "VARCHAR"),
    ("ip_version", "INTEGER"),
    ("local_addr", "VARCHAR"),
    ("remote_addr", "VARCHAR"),
    ("direction_source", "VARCHAR"),
    ("src_scope", "VARCHAR"),
    ("dst_scope", "VARCHAR"),
    ("remote_scope", "VARCHAR"),
    ("flow_log_id", "VARCHAR"),
    ("source_file", "VARCHAR"),
    ("line_no", "BIGINT"),
    ("has_parse_issue", "BOOLEAN"),
    ("extra", "VARCHAR"),
];

const FILE_COLUMNS: &[&str] = &[
    "file_path",
    "flow_log_id",
    "account_id",
    "region",
    "header",
    "header_known",
    "header_unknown",
    "rows_total",
    "rows_valid",
    "rows_with_issues",
    "rows_rejected",
    "nodata_rows",
    "skipdata_rows",
    "min_start_time",
    "max_end_time",
];

const ISSUE_COLUMNS: &[&str] = &[
    "file_path",
    "line_no",
    "kind",
    "field",
    "raw_value",
    "raw_line",
];

/// Create the flow tables and views, migrating an older layout in place.
///
/// `vpc_flow_logs` is created with a single column and grown with
/// `ADD COLUMN IF NOT EXISTS`, so a new database and an old one converge on
/// the same columns through the same statements. Requires `cloudtrail_events`
/// (for `vpc_flow_log_configs`), which [`crate::db::ensure_table`] creates.
pub fn ensure_flow_tables(conn: &Connection) -> Result<()> {
    let mut ddl =
        String::from("CREATE TABLE IF NOT EXISTS vpc_flow_logs (start_time TIMESTAMP);\n");
    let flow_columns = FLOW_FIELDS.iter().map(|f| (f.column, f.ty.sql()));
    for (column, ty) in DERIVED_COLUMNS.iter().copied().chain(flow_columns) {
        ddl.push_str(&format!(
            "ALTER TABLE vpc_flow_logs ADD COLUMN IF NOT EXISTS {column} {ty};\n"
        ));
    }
    ddl.push_str(
        "
        CREATE TABLE IF NOT EXISTS vpc_flow_files (
            file_path        VARCHAR PRIMARY KEY,
            flow_log_id      VARCHAR,
            account_id       VARCHAR,
            region           VARCHAR,
            header           VARCHAR,
            header_known     VARCHAR,
            header_unknown   VARCHAR,
            rows_total       BIGINT,
            rows_valid       BIGINT,
            rows_with_issues BIGINT,
            rows_rejected    BIGINT,
            nodata_rows      BIGINT,
            skipdata_rows    BIGINT,
            min_start_time   TIMESTAMP,
            max_end_time     TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS vpc_flow_parse_issues (
            file_path VARCHAR,
            line_no   BIGINT,
            kind      VARCHAR,
            field     VARCHAR,
            raw_value VARCHAR,
            raw_line  VARCHAR
        );

        CREATE TABLE IF NOT EXISTS ip_geo (
            ip           VARCHAR PRIMARY KEY,
            country_code VARCHAR,
            country_name VARCHAR,
            city         VARCHAR,
            latitude     DOUBLE,
            longitude    DOUBLE,
            asn          VARCHAR,
            org          VARCHAR
        );
        ",
    );
    ddl.push_str(VIEWS_SQL);
    conn.execute_batch(&ddl)
        .context("Failed to create VPC Flow Logs tables")
}

/// Views over the flow tables. Recreated on every run so a release can change them.
const VIEWS_SQL: &str = r#"
-- One row per flow log subscription: what it captures and how healthy its files are.
CREATE OR REPLACE VIEW vpc_flow_sources AS
SELECT
    flow_log_id,
    string_agg(DISTINCT account_id, ',') AS account_ids,
    string_agg(DISTINCT region, ',')     AS regions,
    count(DISTINCT header)               AS header_variants,
    any_value(header)                    AS header,
    count(*)                             AS files,
    sum(rows_total)                      AS rows_total,
    sum(rows_valid)                      AS rows_valid,
    sum(rows_with_issues)                AS rows_with_issues,
    sum(rows_rejected)                   AS rows_rejected,
    sum(nodata_rows)                     AS nodata_rows,
    sum(skipdata_rows)                   AS skipdata_rows,
    min(min_start_time)                  AS first_observation,
    max(max_end_time)                    AS last_observation
FROM vpc_flow_files
GROUP BY flow_log_id;

-- Observations of the same packet flow on several interfaces collapsed to one row.
-- Bytes/packets take the max across observations, so totals are not double-counted.
CREATE OR REPLACE VIEW vpc_flow_unique AS
SELECT
    coalesce(pkt_srcaddr, srcaddr)                AS flow_src,
    coalesce(pkt_dstaddr, dstaddr)                AS flow_dst,
    srcport,
    dstport,
    protocol,
    time_bucket(INTERVAL 1 minute, start_time)    AS window_start,
    count(*)                                      AS observation_count,
    max(bytes)                                    AS bytes,
    max(packets)                                  AS packets,
    min(start_time)                               AS start_time,
    max(end_time)                                 AS end_time,
    string_agg(DISTINCT interface_id, ',')        AS interface_ids
FROM vpc_flow_logs
WHERE coalesce(log_status, 'OK') = 'OK'
  AND coalesce(pkt_srcaddr, srcaddr) IS NOT NULL
GROUP BY ALL;

-- Flow records with geo for the remote endpoint (dataset for the GeoIP tab).
CREATE OR REPLACE VIEW vpc_flow_logs_geo AS
SELECT
    f.*,
    g.country_code AS remote_geo_country_code,
    g.country_name AS remote_geo_country_name,
    g.city         AS remote_geo_city,
    g.latitude     AS remote_geo_latitude,
    g.longitude    AS remote_geo_longitude,
    g.asn          AS remote_geo_asn,
    g.org          AS remote_geo_org
FROM vpc_flow_logs f
LEFT JOIN ip_geo g ON g.ip = f.remote_addr;

-- Flow log subscriptions created or deleted, as recorded by CloudTrail. The
-- request nesting varies, so values are matched by pattern rather than path.
CREATE OR REPLACE VIEW vpc_flow_log_configs AS
SELECT
    event_time,
    event_name,
    recipient_account_id AS account_id,
    aws_region           AS region,
    user_identity_arn,
    nullif(regexp_extract(coalesce(response_elements, '') || ' ' || coalesce(request_parameters, ''),
                          'fl-[0-9a-f]+'), '')                                          AS flow_log_id,
    nullif(regexp_extract(request_parameters,
                          '"[Tt]raffic[Tt]ype"\s*:\s*"(ALL|ACCEPT|REJECT)"', 1), '')   AS traffic_type,
    regexp_extract_all(request_parameters, '(?:vpc|subnet|eni)-[0-9a-f]+')             AS resource_ids,
    nullif(regexp_extract(request_parameters, '"[Ll]og[Ff]ormat"\s*:\s*"([^"]*)"', 1), '') AS log_format,
    error_code,
    request_parameters,
    response_elements
FROM cloudtrail_events
WHERE event_source = 'ec2.amazonaws.com'
  AND event_name IN ('CreateFlowLogs', 'DeleteFlowLogs');
"#;

fn timestamp(secs: Option<i64>) -> Value {
    secs.map_or(Value::Null, |s| Value::Timestamp(TimeUnit::Second, s))
}

/// Append one parsed file: its records, its `vpc_flow_files` row and its issues.
///
/// Returns the number of records written. Must run inside the caller's transaction.
pub fn append_flow_file(
    conn: &Connection,
    meta: &FlowFileMeta,
    parsed: &ParsedFlowFile,
) -> Result<usize> {
    let columns: Vec<&str> = DERIVED_COLUMNS
        .iter()
        .map(|(c, _)| *c)
        .chain(FLOW_FIELDS.iter().map(|f| f.column))
        .collect();
    let mut rows = conn
        .appender_with_columns("vpc_flow_logs", &columns)
        .context("Failed to create appender for vpc_flow_logs")?;
    for r in &parsed.records {
        let (start, end) = (r.start_unix(), r.end_unix());
        let duration: Option<i32> = start.zip(end).map(|(s, e)| (e - s) as i32);
        let (start_ts, end_ts) = (timestamp(start), timestamp(end));
        let direction = r.direction_source.as_str();
        let mut params: Vec<&dyn ToSql> = vec![
            &start_ts,
            &end_ts,
            &duration,
            &r.protocol_name,
            &r.ip_version,
            &r.local_addr,
            &r.remote_addr,
            &direction,
            &r.src_scope,
            &r.dst_scope,
            &r.remote_scope,
            &meta.flow_log_id,
            &meta.file_path,
            &r.line_no,
            &r.has_parse_issue,
            &r.extra,
        ];
        params.extend(r.values.iter().map(|v| v as &dyn ToSql));
        rows.append_row(params.as_slice())
            .context("Failed to append flow record")?;
    }
    rows.flush()
        .context("Failed to flush vpc_flow_logs appender")?;

    let known: Vec<&str> = parsed
        .header
        .iter()
        .filter(|h| !parsed.header_unknown.contains(h))
        .map(String::as_str)
        .collect();
    let (header, header_known, header_unknown) = (
        parsed.header.join(" "),
        known.join(" "),
        parsed.header_unknown.join(" "),
    );
    let counts = [
        parsed.rows_total,
        parsed.rows_valid,
        parsed.rows_with_issues,
        parsed.rows_rejected,
        parsed.nodata_rows,
        parsed.skipdata_rows,
    ]
    .map(|n| n as i64);
    let (min_start, max_end) = (timestamp(parsed.min_start), timestamp(parsed.max_end));
    let mut files = conn
        .appender_with_columns("vpc_flow_files", FILE_COLUMNS)
        .context("Failed to create appender for vpc_flow_files")?;
    files
        .append_row(params![
            meta.file_path,
            meta.flow_log_id,
            meta.account_id,
            meta.region,
            header,
            header_known,
            header_unknown,
            counts[0],
            counts[1],
            counts[2],
            counts[3],
            counts[4],
            counts[5],
            min_start,
            max_end,
        ])
        .context("Failed to append vpc_flow_files row")?;
    files
        .flush()
        .context("Failed to flush vpc_flow_files appender")?;

    if !parsed.issues.is_empty() {
        let mut issues = conn
            .appender_with_columns("vpc_flow_parse_issues", ISSUE_COLUMNS)
            .context("Failed to create appender for vpc_flow_parse_issues")?;
        for i in &parsed.issues {
            issues
                .append_row(params![
                    meta.file_path,
                    i.line_no,
                    i.kind.as_str(),
                    i.field,
                    i.raw_value,
                    i.raw_line,
                ])
                .context("Failed to append parse issue")?;
        }
        issues
            .flush()
            .context("Failed to flush parse issue appender")?;
    }
    Ok(parsed.records.len())
}

/// Remove everything previously written for `file_path` (a changed file being re-ingested).
pub fn delete_flow_file(conn: &Connection, file_path: &str) -> Result<()> {
    for table in ["vpc_flow_logs", "vpc_flow_files", "vpc_flow_parse_issues"] {
        let column = if table == "vpc_flow_logs" {
            "source_file"
        } else {
            "file_path"
        };
        conn.execute(
            &format!("DELETE FROM {table} WHERE {column} = ?"),
            [file_path],
        )
        .with_context(|| format!("Failed to delete {file_path} from {table}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow_parser::parse_flow_log;
    use crate::test_util::setup_db;
    use std::path::PathBuf;

    const V2_HEADER: &str = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status";

    fn flow_db() -> Connection {
        let conn = setup_db();
        ensure_flow_tables(&conn).unwrap();
        conn
    }

    fn meta(path: &str, flow_log_id: &str) -> FlowFileMeta {
        FlowFileMeta {
            file_path: path.into(),
            flow_log_id: Some(flow_log_id.into()),
            account_id: Some("123456789012".into()),
            region: Some("us-east-1".into()),
        }
    }

    fn count(conn: &Connection, sql: &str) -> i64 {
        conn.query_row(sql, [], |r| r.get(0)).unwrap()
    }

    fn columns(conn: &Connection, table: &str) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT column_name FROM information_schema.columns WHERE table_name = ?")
            .unwrap();
        stmt.query_map([table], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    // FD-01: object names yield flow log ID, account and region; other names yield None.
    #[test]
    fn test_meta_from_aws_object_name() {
        let m = FlowFileMeta::from_path(&PathBuf::from(
            "/data/logs/AWSLogs/123456789012/vpcflowlogs/us-east-1/2024/01/15/123456789012_vpcflowlogs_us-east-1_fl-1234abcd_20240115T1620Z_fe123456.log.gz",
        ));
        assert_eq!(m.flow_log_id.as_deref(), Some("fl-1234abcd"));
        assert_eq!(m.account_id.as_deref(), Some("123456789012"));
        assert_eq!(m.region.as_deref(), Some("us-east-1"));

        let m = FlowFileMeta::from_path(&PathBuf::from("/x/renamed.log.gz"));
        assert_eq!(m.flow_log_id, None);
        assert_eq!(m.file_path, "/x/renamed.log.gz");
    }

    // FD-02: every AWS field and every derived column exists; creation is idempotent.
    #[test]
    fn test_ensure_flow_tables_creates_all_columns_idempotently() {
        let conn = flow_db();
        ensure_flow_tables(&conn).unwrap();
        let cols = columns(&conn, "vpc_flow_logs");
        for f in FLOW_FIELDS {
            assert!(cols.contains(&f.column.to_string()), "missing {}", f.column);
        }
        for derived in [
            "start_time",
            "end_time",
            "duration_secs",
            "protocol_name",
            "ip_version",
            "local_addr",
            "remote_addr",
            "direction_source",
            "src_scope",
            "dst_scope",
            "remote_scope",
            "flow_log_id",
            "source_file",
            "line_no",
            "has_parse_issue",
            "extra",
        ] {
            assert!(cols.contains(&derived.to_string()), "missing {derived}");
        }
    }

    // FD-03: an older table missing columns is migrated in place.
    #[test]
    fn test_ensure_flow_tables_migrates_older_layout() {
        let conn = setup_db();
        conn.execute_batch("CREATE TABLE vpc_flow_logs (start_time TIMESTAMP, srcaddr VARCHAR)")
            .unwrap();
        ensure_flow_tables(&conn).unwrap();
        assert!(columns(&conn, "vpc_flow_logs").contains(&"next_hop_interface_type".to_string()));
    }

    // FD-04: every view exists and is queryable on an empty database.
    #[test]
    fn test_views_exist() {
        let conn = flow_db();
        for view in [
            "vpc_flow_sources",
            "vpc_flow_unique",
            "vpc_flow_logs_geo",
            "vpc_flow_log_configs",
        ] {
            assert_eq!(
                count(&conn, &format!("SELECT count(*) FROM {view}")),
                0,
                "{view}"
            );
        }
    }

    fn sample() -> ParsedFlowFile {
        parse_flow_log(&[
            "version srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status flow-direction interface-id future-field",
            "5 10.0.0.71 52.95.128.179 34210 443 6 7 471 1616729292 1616729349 ACCEPT OK egress eni-1 x",
            "5 10.0.0.71 52.95.128.179 34210 443 6 7 bad 1616729292 1616729349 ACCEPT OK egress eni-1 y",
            "short row",
        ]
        .join("\n"))
        .unwrap()
    }

    // FD-05: records round-trip with typed, derived and provenance columns.
    #[test]
    fn test_append_round_trip() {
        let conn = flow_db();
        let n = append_flow_file(&conn, &meta("/f1.log.gz", "fl-1"), &sample()).unwrap();
        assert_eq!(n, 2);

        let (start, duration, bytes, remote, dir, proto, src_file, fl, extra): (
            String,
            i32,
            Option<i64>,
            String,
            String,
            String,
            String,
            String,
            String,
        ) = conn
            .query_row(
                "SELECT strftime(start_time, '%Y-%m-%d %H:%M:%S'), duration_secs, bytes, remote_addr,
                        direction_source, protocol_name, source_file, flow_log_id, extra
                 FROM vpc_flow_logs WHERE line_no = 2",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(start, "2021-03-26 03:28:12");
        assert_eq!(duration, 57);
        assert_eq!(bytes, Some(471));
        assert_eq!(remote, "52.95.128.179");
        assert_eq!(dir, "record");
        assert_eq!(proto, "TCP");
        assert_eq!(src_file, "/f1.log.gz");
        assert_eq!(fl, "fl-1");
        assert_eq!(extra, r#"{"future-field":"x"}"#);

        let issue_row: bool = conn
            .query_row(
                "SELECT has_parse_issue FROM vpc_flow_logs WHERE line_no = 3",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(issue_row);
    }

    // FD-06: the file row carries complete counts; issues carry raw text.
    #[test]
    fn test_append_writes_file_row_and_issues() {
        let conn = flow_db();
        append_flow_file(&conn, &meta("/f1.log.gz", "fl-1"), &sample()).unwrap();
        let (total, valid, issues, rejected, unknown): (i64, i64, i64, i64, String) = conn
            .query_row(
                "SELECT rows_total, rows_valid, rows_with_issues, rows_rejected, header_unknown
                 FROM vpc_flow_files WHERE file_path = '/f1.log.gz'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!((total, valid, issues, rejected), (3, 1, 1, 1));
        assert_eq!(unknown, "future-field");
        assert_eq!(
            count(
                &conn,
                "SELECT count(*) FROM vpc_flow_parse_issues WHERE kind = 'field' AND field = 'bytes' AND raw_value = 'bad'"
            ),
            1
        );
        assert_eq!(
            count(
                &conn,
                "SELECT count(*) FROM vpc_flow_parse_issues WHERE kind = 'row' AND raw_line = 'short row'"
            ),
            1
        );
    }

    // FD-07: deleting a file removes its rows from every flow table.
    #[test]
    fn test_delete_flow_file() {
        let conn = flow_db();
        append_flow_file(&conn, &meta("/f1.log.gz", "fl-1"), &sample()).unwrap();
        append_flow_file(&conn, &meta("/f2.log.gz", "fl-1"), &sample()).unwrap();
        delete_flow_file(&conn, "/f1.log.gz").unwrap();
        assert_eq!(count(&conn, "SELECT count(*) FROM vpc_flow_logs"), 2);
        assert_eq!(count(&conn, "SELECT count(*) FROM vpc_flow_files"), 1);
        assert_eq!(
            count(&conn, "SELECT count(*) FROM vpc_flow_parse_issues"),
            2
        );
    }

    // FD-08: a subscription whose files disagree on the header is flagged.
    #[test]
    fn test_sources_view_flags_header_variants() {
        let conn = flow_db();
        let a = parse_flow_log(&format!(
            "{V2_HEADER}\n2 1 eni-1 10.0.0.1 10.0.0.2 1 22 6 1 1 100 160 ACCEPT OK"
        ))
        .unwrap();
        let b = parse_flow_log("srcaddr dstaddr action log-status\n10.0.0.1 10.0.0.2 ACCEPT OK")
            .unwrap();
        append_flow_file(&conn, &meta("/a", "fl-1"), &a).unwrap();
        append_flow_file(&conn, &meta("/b", "fl-1"), &b).unwrap();
        append_flow_file(&conn, &meta("/c", "fl-2"), &a).unwrap();
        let variants: i64 = conn
            .query_row(
                "SELECT header_variants FROM vpc_flow_sources WHERE flow_log_id = 'fl-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(variants, 2);
        let files: i64 = conn
            .query_row(
                "SELECT files FROM vpc_flow_sources WHERE flow_log_id = 'fl-2'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(files, 1);
    }

    // FD-09: the same flow seen on two ENIs collapses to one observation pair.
    #[test]
    fn test_unique_view_collapses_two_interface_observations() {
        let conn = flow_db();
        let p = parse_flow_log(&format!(
            "{V2_HEADER}\n\
             2 1 eni-a 10.0.0.1 10.0.0.2 40000 445 6 10 900 100 160 ACCEPT OK\n\
             2 1 eni-b 10.0.0.1 10.0.0.2 40000 445 6 10 900 100 160 ACCEPT OK"
        ))
        .unwrap();
        append_flow_file(&conn, &meta("/a", "fl-1"), &p).unwrap();
        let (rows, obs, bytes): (i64, i64, i64) = conn
            .query_row(
                "SELECT count(*), max(observation_count), sum(bytes) FROM vpc_flow_unique",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!((rows, obs, bytes), (1, 2, 900));
    }

    // FD-10: CreateFlowLogs in CloudTrail yields the capture scope the records lack.
    #[test]
    fn test_configs_view_extracts_capture_scope() {
        let conn = flow_db();
        conn.execute_batch(
            r#"INSERT INTO cloudtrail_events (event_time, event_name, event_source, aws_region,
                                              recipient_account_id, request_parameters, response_elements)
               VALUES ('2024-01-15 00:00:00', 'CreateFlowLogs', 'ec2.amazonaws.com', 'us-east-1', '123456789012',
                       '{"CreateFlowLogsRequest":{"ResourceId":{"tag":1,"content":"vpc-0abc123"},"ResourceType":"VPC","TrafficType":"REJECT","LogFormat":"${version} ${srcaddr}"}}',
                       '{"CreateFlowLogsResponse":{"flowLogIdSet":{"item":"fl-0def456"}}}')"#,
        )
        .unwrap();
        let (fl, traffic, resources, format): (String, String, String, String) = conn
            .query_row(
                "SELECT flow_log_id, traffic_type, array_to_string(resource_ids, ','), log_format
                 FROM vpc_flow_log_configs",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(fl, "fl-0def456");
        assert_eq!(traffic, "REJECT");
        assert_eq!(resources, "vpc-0abc123");
        assert_eq!(format, "${version} ${srcaddr}");
    }

    // FD-11: address scopes reach the table.
    #[test]
    fn test_scopes_round_trip() {
        let conn = flow_db();
        append_flow_file(&conn, &meta("/f1.log.gz", "fl-1"), &sample()).unwrap();
        let scopes: (String, String, String) = conn
            .query_row(
                "SELECT src_scope, dst_scope, remote_scope FROM vpc_flow_logs WHERE line_no = 2",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(scopes, ("private".into(), "public".into(), "public".into()));
    }
}
