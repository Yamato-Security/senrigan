//! VPC Flow Logs plain-text parser.
//!
//! A flow log file is a header line naming the fields, then one
//! space-delimited record per line. Custom formats choose any subset of fields
//! in any order, so every record is mapped through the header — never through
//! a fixed column position.
//!
//! Evidence is never silently rewritten: AWS's own `-` ("not applicable")
//! becomes `NULL`, while a value that fails to parse also becomes `NULL` but
//! flags the row and leaves a [`ParseIssue`] carrying the raw text.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

use anyhow::{Result, bail};
use duckdb::ToSql;
use duckdb::types::{ToSqlOutput, Value};

use crate::geoip::classify_special_ip;

/// Storage type of a flow log field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    /// `INTEGER`
    Int,
    /// `BIGINT`
    BigInt,
    /// `VARCHAR`
    Text,
}

impl FieldType {
    /// DuckDB type name.
    pub fn sql(self) -> &'static str {
        match self {
            FieldType::Int => "INTEGER",
            FieldType::BigInt => "BIGINT",
            FieldType::Text => "VARCHAR",
        }
    }
}

/// One AWS flow log field and the column it is stored in.
#[derive(Debug, Clone, Copy)]
pub struct FlowField {
    /// Field name as AWS writes it in the header (`pkt-srcaddr`).
    pub aws: &'static str,
    /// Column name in `vpc_flow_logs` (`pkt_srcaddr`).
    pub column: &'static str,
    /// Storage type.
    pub ty: FieldType,
}

const fn f(aws: &'static str, column: &'static str, ty: FieldType) -> FlowField {
    FlowField { aws, column, ty }
}

use FieldType::{BigInt, Int, Text};

/// Every field AWS documents, in version order. This is the single source of
/// truth for both the parser and the `vpc_flow_logs` column layout; three
/// fields are renamed because the AWS name is a SQL keyword or ambiguous.
pub const FLOW_FIELDS: &[FlowField] = &[
    // v2 — the default format, in this exact order
    f("version", "version", Int),
    f("account-id", "account_id", Text),
    f("interface-id", "interface_id", Text),
    f("srcaddr", "srcaddr", Text),
    f("dstaddr", "dstaddr", Text),
    f("srcport", "srcport", Int),
    f("dstport", "dstport", Int),
    f("protocol", "protocol", Int),
    f("packets", "packets", BigInt),
    f("bytes", "bytes", BigInt),
    f("start", "start_unix", BigInt),
    f("end", "end_unix", BigInt),
    f("action", "action", Text),
    f("log-status", "log_status", Text),
    // v3
    f("vpc-id", "vpc_id", Text),
    f("subnet-id", "subnet_id", Text),
    f("instance-id", "instance_id", Text),
    f("tcp-flags", "tcp_flags", Int),
    f("type", "traffic_type", Text),
    f("pkt-srcaddr", "pkt_srcaddr", Text),
    f("pkt-dstaddr", "pkt_dstaddr", Text),
    // v4
    f("region", "region", Text),
    f("az-id", "az_id", Text),
    f("sublocation-type", "sublocation_type", Text),
    f("sublocation-id", "sublocation_id", Text),
    // v5
    f("pkt-src-aws-service", "pkt_src_aws_service", Text),
    f("pkt-dst-aws-service", "pkt_dst_aws_service", Text),
    f("flow-direction", "flow_direction", Text),
    f("traffic-path", "traffic_path", Int),
    // v7
    f("ecs-cluster-arn", "ecs_cluster_arn", Text),
    f("ecs-cluster-name", "ecs_cluster_name", Text),
    f(
        "ecs-container-instance-arn",
        "ecs_container_instance_arn",
        Text,
    ),
    f(
        "ecs-container-instance-id",
        "ecs_container_instance_id",
        Text,
    ),
    f("ecs-container-id", "ecs_container_id", Text),
    f("ecs-second-container-id", "ecs_second_container_id", Text),
    f("ecs-service-name", "ecs_service_name", Text),
    f("ecs-task-definition-arn", "ecs_task_definition_arn", Text),
    f("ecs-task-arn", "ecs_task_arn", Text),
    f("ecs-task-id", "ecs_task_id", Text),
    // v8 – v10
    f("reject-reason", "reject_reason", Text),
    f("resource-id", "resource_id", Text),
    f("encryption-status", "encryption_status", Int),
    // v11
    f("instance-tag", "instance_tag", Text),
    f("instance-tag-2", "instance_tag_2", Text),
    f("interface-tag", "interface_tag", Text),
    f("interface-tag-2", "interface_tag_2", Text),
    f("asg-tag", "asg_tag", Text),
    f("asg-tag-2", "asg_tag_2", Text),
    f("interface-type", "interface_type", Text),
    f("next-hop-interface-id", "next_hop_interface_id", Text),
    f("next-hop-subnet-id", "next_hop_subnet_id", Text),
    f("next-hop-az-id", "next_hop_az_id", Text),
    f("next-hop-vpc-id", "next_hop_vpc_id", Text),
    f("next-hop-interface-type", "next_hop_interface_type", Text),
];

/// Number of v2 fields — the headerless default format.
const V2_FIELD_COUNT: usize = 14;

// Positions in FLOW_FIELDS used on the per-row hot path (asserted by a test).
const I_SRCADDR: usize = 3;
const I_DSTADDR: usize = 4;
const I_PROTOCOL: usize = 7;
const I_START: usize = 10;
const I_END: usize = 11;
const I_LOG_STATUS: usize = 13;
const I_PKT_SRCADDR: usize = 19;
const I_PKT_DSTADDR: usize = 20;
const I_FLOW_DIRECTION: usize = 27;

/// Raw text of at most this many issues is kept per file; counts stay complete.
pub const MAX_ISSUES_PER_FILE: usize = 100;

/// A parsed field value.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    Null,
    Int(i32),
    BigInt(i64),
    Text(String),
}

impl FieldValue {
    fn as_str(&self) -> Option<&str> {
        match self {
            FieldValue::Text(s) => Some(s),
            _ => None,
        }
    }

    fn as_i64(&self) -> Option<i64> {
        match self {
            FieldValue::Int(v) => Some(i64::from(*v)),
            FieldValue::BigInt(v) => Some(*v),
            _ => None,
        }
    }
}

impl ToSql for FieldValue {
    fn to_sql(&self) -> duckdb::Result<ToSqlOutput<'_>> {
        Ok(match self {
            FieldValue::Null => ToSqlOutput::Owned(Value::Null),
            FieldValue::Int(v) => ToSqlOutput::Owned(Value::Int(*v)),
            FieldValue::BigInt(v) => ToSqlOutput::Owned(Value::BigInt(*v)),
            FieldValue::Text(s) => ToSqlOutput::Owned(Value::Text(s.clone())),
        })
    }
}

/// How `local_addr` / `remote_addr` were determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectionSource {
    /// From the record's own `flow-direction`.
    Record,
    /// No direction; exactly one IPv4 endpoint is private/special.
    Heuristic,
    /// Not determinable; both endpoints are `NULL`.
    Unknown,
}

impl DirectionSource {
    pub fn as_str(self) -> &'static str {
        match self {
            DirectionSource::Record => "record",
            DirectionSource::Heuristic => "heuristic",
            DirectionSource::Unknown => "unknown",
        }
    }
}

/// One flow log record — one observation.
#[derive(Debug, Clone)]
pub struct FlowRecord {
    /// Values aligned with [`FLOW_FIELDS`]; fields absent from the header are `Null`.
    pub values: Vec<FieldValue>,
    /// 1-based line number in the decompressed file.
    pub line_no: i64,
    /// A typed field held a malformed value (stored as `NULL`).
    pub has_parse_issue: bool,
    /// Values of header fields Senrigan does not know, as a JSON object.
    pub extra: Option<String>,
    pub protocol_name: Option<String>,
    pub ip_version: Option<i32>,
    pub local_addr: Option<String>,
    pub remote_addr: Option<String>,
    pub direction_source: DirectionSource,
    /// Address class of the packet-level source: `private`, `public`, `loopback`,
    /// `link-local` or `special`. Needs no GeoIP database.
    pub src_scope: Option<&'static str>,
    /// Address class of the packet-level destination.
    pub dst_scope: Option<&'static str>,
    /// Address class of `remote_addr`; `None` when the remote is unknown.
    pub remote_scope: Option<&'static str>,
}

impl FlowRecord {
    /// Value of the field with AWS name `aws` (test and diagnostics helper).
    pub fn get(&self, aws: &str) -> &FieldValue {
        let i = FLOW_FIELDS
            .iter()
            .position(|f| f.aws == aws)
            .unwrap_or_else(|| panic!("unknown flow field {aws}"));
        &self.values[i]
    }

    /// `start` in Unix seconds.
    pub fn start_unix(&self) -> Option<i64> {
        self.values[I_START].as_i64()
    }

    /// `end` in Unix seconds.
    pub fn end_unix(&self) -> Option<i64> {
        self.values[I_END].as_i64()
    }
}

/// Whether an issue concerns one field or a whole row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueKind {
    /// A malformed value in a typed field; the row was kept.
    Field,
    /// The token count did not match the header; the row was rejected.
    Row,
}

impl IssueKind {
    pub fn as_str(self) -> &'static str {
        match self {
            IssueKind::Field => "field",
            IssueKind::Row => "row",
        }
    }
}

/// A recorded parse problem.
#[derive(Debug, Clone, PartialEq)]
pub struct ParseIssue {
    pub line_no: i64,
    pub kind: IssueKind,
    pub field: Option<String>,
    pub raw_value: Option<String>,
    pub raw_line: Option<String>,
}

/// Everything parsed from one flow log file.
#[derive(Debug, Default)]
pub struct ParsedFlowFile {
    /// The field list as written (the v2 list for a headerless file).
    pub header: Vec<String>,
    /// Header fields Senrigan does not know.
    pub header_unknown: Vec<String>,
    pub records: Vec<FlowRecord>,
    /// At most [`MAX_ISSUES_PER_FILE`] issues.
    pub issues: Vec<ParseIssue>,
    pub rows_total: usize,
    pub rows_valid: usize,
    pub rows_with_issues: usize,
    pub rows_rejected: usize,
    pub nodata_rows: usize,
    pub skipdata_rows: usize,
    pub min_start: Option<i64>,
    pub max_end: Option<i64>,
}

/// Parse the decompressed text of one flow log file.
///
/// Fails only when the file as a whole is unrecognisable: empty, or a first
/// line that is neither a header nor a version-2 default record. Problems
/// inside individual rows are counted and recorded, never fatal.
pub fn parse_flow_log(content: &str) -> Result<ParsedFlowFile> {
    let mut lines = content
        .lines()
        .enumerate()
        .map(|(i, l)| (i as i64 + 1, l.trim_end_matches('\r')))
        .filter(|(_, l)| !l.trim().is_empty());

    let Some((first_no, first)) = lines.next() else {
        bail!("empty flow log file");
    };

    let first_tokens: Vec<&str> = first.split_ascii_whitespace().collect();
    let (header, first_is_data): (Vec<String>, bool) = if is_header(&first_tokens) {
        (first_tokens.iter().map(|t| t.to_string()).collect(), false)
    } else if is_v2_record(&first_tokens) {
        let v2 = FLOW_FIELDS[..V2_FIELD_COUNT].iter();
        (v2.map(|f| f.aws.to_string()).collect(), true)
    } else {
        bail!("first line is neither a flow log header nor a version-2 record");
    };

    // Header position → FLOW_FIELDS index, or None for an unknown field.
    let mapping: Vec<Option<usize>> = header
        .iter()
        .map(|h| FLOW_FIELDS.iter().position(|f| f.aws == h))
        .collect();

    let mut out = ParsedFlowFile {
        header_unknown: header
            .iter()
            .zip(&mapping)
            .filter(|(_, m)| m.is_none())
            .map(|(h, _)| h.clone())
            .collect(),
        header,
        ..Default::default()
    };

    let data = first_is_data
        .then_some((first_no, first))
        .into_iter()
        .chain(lines);
    for (line_no, line) in data {
        parse_row(line_no, line, &mapping, &mut out);
    }
    Ok(out)
}

fn record_issue(out: &mut ParsedFlowFile, issue: ParseIssue) {
    if out.issues.len() < MAX_ISSUES_PER_FILE {
        out.issues.push(issue);
    }
}

fn parse_row(line_no: i64, line: &str, mapping: &[Option<usize>], out: &mut ParsedFlowFile) {
    out.rows_total += 1;
    let tokens: Vec<&str> = line.split_ascii_whitespace().collect();
    if tokens.len() != mapping.len() {
        out.rows_rejected += 1;
        record_issue(
            out,
            ParseIssue {
                line_no,
                kind: IssueKind::Row,
                field: None,
                raw_value: None,
                raw_line: Some(line.to_string()),
            },
        );
        return;
    }

    let mut values = vec![FieldValue::Null; FLOW_FIELDS.len()];
    let mut extra: BTreeMap<&str, &str> = BTreeMap::new();
    let mut field_issues = Vec::new();
    for ((token, target), header) in tokens.iter().zip(mapping).zip(&out.header) {
        let Some(i) = *target else {
            extra.insert(header, token);
            continue;
        };
        match parse_value(token, FLOW_FIELDS[i].ty) {
            Some(v) => values[i] = v,
            None => field_issues.push(ParseIssue {
                line_no,
                kind: IssueKind::Field,
                field: Some(FLOW_FIELDS[i].aws.to_string()),
                raw_value: Some(token.to_string()),
                raw_line: None,
            }),
        }
    }

    let has_parse_issue = !field_issues.is_empty();
    let record = derive(values, line_no, has_parse_issue, &extra);
    for issue in field_issues {
        record_issue(out, issue);
    }
    if has_parse_issue {
        out.rows_with_issues += 1;
    } else {
        out.rows_valid += 1;
    }
    match record.values[I_LOG_STATUS].as_str() {
        Some("NODATA") => out.nodata_rows += 1,
        Some("SKIPDATA") => out.skipdata_rows += 1,
        _ => {}
    }
    if let Some(s) = record.start_unix() {
        out.min_start = Some(out.min_start.map_or(s, |m| m.min(s)));
    }
    if let Some(e) = record.end_unix() {
        out.max_end = Some(out.max_end.map_or(e, |m| m.max(e)));
    }
    out.records.push(record);
}

/// `Some(value)` for a well-formed token (`-` → `Null`); `None` when malformed.
fn parse_value(token: &str, ty: FieldType) -> Option<FieldValue> {
    if token == "-" {
        return Some(FieldValue::Null);
    }
    match ty {
        FieldType::Text => Some(FieldValue::Text(token.to_string())),
        FieldType::Int => token.parse().ok().map(FieldValue::Int),
        FieldType::BigInt => token.parse().ok().map(FieldValue::BigInt),
    }
}

/// A header: lowercase hyphenated names, no repeats, at least three known fields.
fn is_header(tokens: &[&str]) -> bool {
    let well_formed = |t: &&str| {
        !t.is_empty()
            && t.split('-').all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            })
    };
    let mut seen = HashSet::new();
    tokens.iter().all(well_formed)
        && tokens.iter().all(|t| seen.insert(*t))
        && tokens
            .iter()
            .filter(|t| FLOW_FIELDS.iter().any(|f| f.aws == **t))
            .count()
            >= 3
}

/// A headerless version-2 default record (a CloudWatch Logs export).
fn is_v2_record(tokens: &[&str]) -> bool {
    tokens.len() == V2_FIELD_COUNT
        && tokens[0] == "2"
        && tokens[I_START].parse::<i64>().is_ok()
        && tokens[I_END].parse::<i64>().is_ok()
}

fn derive(
    values: Vec<FieldValue>,
    line_no: i64,
    has_parse_issue: bool,
    extra: &BTreeMap<&str, &str>,
) -> FlowRecord {
    let addr = |i: usize| values[i].as_str();
    let src = addr(I_PKT_SRCADDR).or(addr(I_SRCADDR));
    let dst = addr(I_PKT_DSTADDR).or(addr(I_DSTADDR));

    let status = values[I_LOG_STATUS].as_str();
    let no_traffic = matches!(status, Some("NODATA" | "SKIPDATA"));
    let (local, remote, direction_source) = match values[I_FLOW_DIRECTION].as_str() {
        _ if no_traffic => (None, None, DirectionSource::Unknown),
        Some("ingress") => (dst, src, DirectionSource::Record),
        Some("egress") => (src, dst, DirectionSource::Record),
        _ => heuristic_endpoints(src, dst),
    };

    let ip_version = [src, dst]
        .into_iter()
        .flatten()
        .find_map(|a| a.parse::<IpAddr>().ok())
        .map(|ip| if ip.is_ipv4() { 4 } else { 6 });

    let protocol_name = values[I_PROTOCOL].as_i64().map(|p| match p {
        1 => "ICMP".to_string(),
        6 => "TCP".to_string(),
        17 => "UDP".to_string(),
        58 => "ICMPv6".to_string(),
        other => other.to_string(),
    });

    let extra =
        (!extra.is_empty()).then(|| serde_json::to_string(extra).expect("string map serialises"));

    FlowRecord {
        src_scope: src.and_then(address_scope),
        dst_scope: dst.and_then(address_scope),
        remote_scope: remote.and_then(address_scope),
        local_addr: local.map(String::from),
        remote_addr: remote.map(String::from),
        direction_source,
        protocol_name,
        ip_version,
        extra,
        values,
        line_no,
        has_parse_issue,
    }
}

/// The class of an address, or `None` when it does not parse as one.
fn address_scope(addr: &str) -> Option<&'static str> {
    let ip = addr.parse::<IpAddr>().ok()?;
    Some(match classify_special_ip(ip) {
        None => "public",
        Some("PRIVATE") => "private",
        Some("LOOPBACK") => "loopback",
        Some("LINK-LOCAL") => "link-local",
        Some(_) => "special",
    })
}

/// Without a recorded direction, attribute endpoints only when exactly one of
/// two IPv4 addresses is private/special; everything else is unknown.
fn heuristic_endpoints<'a>(
    src: Option<&'a str>,
    dst: Option<&'a str>,
) -> (Option<&'a str>, Option<&'a str>, DirectionSource) {
    let unknown = (None, None, DirectionSource::Unknown);
    let (Some(s), Some(d)) = (src, dst) else {
        return unknown;
    };
    let (Ok(IpAddr::V4(sv)), Ok(IpAddr::V4(dv))) = (s.parse::<IpAddr>(), d.parse::<IpAddr>())
    else {
        return unknown;
    };
    let s_special = classify_special_ip(IpAddr::V4(sv)).is_some();
    let d_special = classify_special_ip(IpAddr::V4(dv)).is_some();
    match (s_special, d_special) {
        (true, false) => (Some(s), Some(d), DirectionSource::Heuristic),
        (false, true) => (Some(d), Some(s), DirectionSource::Heuristic),
        _ => unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V2_HEADER: &str = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status";

    fn parse(lines: &[&str]) -> ParsedFlowFile {
        parse_flow_log(&lines.join("\n")).expect("parse should succeed")
    }

    fn text(r: &FlowRecord, aws: &str) -> Option<String> {
        r.get(aws).as_str().map(String::from)
    }

    // FP-00: the hot-path index constants point at the fields they name.
    #[test]
    fn test_index_constants_match_field_table() {
        for (i, aws) in [
            (I_SRCADDR, "srcaddr"),
            (I_DSTADDR, "dstaddr"),
            (I_PROTOCOL, "protocol"),
            (I_START, "start"),
            (I_END, "end"),
            (I_LOG_STATUS, "log-status"),
            (I_PKT_SRCADDR, "pkt-srcaddr"),
            (I_PKT_DSTADDR, "pkt-dstaddr"),
            (I_FLOW_DIRECTION, "flow-direction"),
        ] {
            assert_eq!(FLOW_FIELDS[i].aws, aws);
        }
        assert_eq!(FLOW_FIELDS[V2_FIELD_COUNT - 1].aws, "log-status");
    }

    // FP-01: the AWS v2 default example parses with typed values.
    #[test]
    fn test_parse_v2_default_with_header() {
        let p = parse(&[
            V2_HEADER,
            "2 123456789010 eni-1235b8ca123456789 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1418530010 1418530070 ACCEPT OK",
        ]);
        assert_eq!(p.records.len(), 1);
        let r = &p.records[0];
        assert_eq!(text(r, "srcaddr").as_deref(), Some("172.31.16.139"));
        assert_eq!(r.get("dstport"), &FieldValue::Int(22));
        assert_eq!(r.get("bytes"), &FieldValue::BigInt(4249));
        assert_eq!(r.start_unix(), Some(1418530010));
        assert_eq!(r.get("vpc-id"), &FieldValue::Null);
        assert_eq!(r.line_no, 2);
        assert_eq!(p.rows_total, 1);
        assert_eq!(p.rows_valid, 1);
        assert_eq!(p.header.len(), 14);
    }

    // FP-02: a reordered custom header maps by name, not position.
    #[test]
    fn test_parse_reordered_custom_header() {
        let p = parse(&[
            "version srcaddr dstaddr srcport dstport protocol start end type packets bytes account-id vpc-id subnet-id instance-id interface-id region az-id sublocation-type sublocation-id action tcp-flags pkt-srcaddr pkt-dstaddr pkt-src-aws-service pkt-dst-aws-service traffic-path flow-direction log-status",
            "5 10.0.0.71 52.95.128.179 34210 80 6 1616729292 1616729349 IPv4 7 471 123456789012 vpc-abcdefab012345678 subnet-aaaaaaaa012345678 i-0c50d5961bcb2d47b eni-1235b8ca123456789 ap-southeast-2 apse2-az3 - - ACCEPT 3 10.0.0.71 52.95.128.179 - S3 8 egress OK",
        ]);
        let r = &p.records[0];
        assert_eq!(
            text(r, "interface-id").as_deref(),
            Some("eni-1235b8ca123456789")
        );
        assert_eq!(r.get("traffic-path"), &FieldValue::Int(8));
        assert_eq!(text(r, "pkt-dst-aws-service").as_deref(), Some("S3"));
        assert_eq!(text(r, "type").as_deref(), Some("IPv4"));
        assert_eq!(r.get("packets"), &FieldValue::BigInt(7));
    }

    // FP-03: an unknown (future) field is accepted and preserved in `extra`.
    #[test]
    fn test_unknown_header_field_goes_to_extra() {
        let p = parse(&[
            "version srcaddr dstaddr future-field log-status",
            "12 10.0.0.1 10.0.0.2 shiny OK",
        ]);
        assert_eq!(p.header_unknown, vec!["future-field".to_string()]);
        let extra: serde_json::Value =
            serde_json::from_str(p.records[0].extra.as_deref().unwrap()).unwrap();
        assert_eq!(extra["future-field"], "shiny");
        assert!(!p.records[0].has_parse_issue);
    }

    // FP-04: a header with a repeated field is not a header; with no v2 fallback the file fails.
    #[test]
    fn test_duplicate_header_token_fails_file() {
        assert!(parse_flow_log("version srcaddr srcaddr dstaddr\n2 a b c").is_err());
    }

    // FP-05: a headerless 14-token v2 file (CloudWatch export) is accepted; line 1 is data.
    #[test]
    fn test_headerless_v2_is_accepted() {
        let p = parse(&[
            "2 123456789010 eni-1235b8ca123456789 172.31.9.69 172.31.9.12 49761 3389 6 20 4249 1418530010 1418530070 REJECT OK",
        ]);
        assert_eq!(p.records.len(), 1);
        assert_eq!(p.records[0].line_no, 1);
        assert_eq!(text(&p.records[0], "action").as_deref(), Some("REJECT"));
        assert_eq!(p.header.join(" "), V2_HEADER);
    }

    // FP-06: a first line that is neither a header nor v2 data fails the file (e.g. an ELB log).
    #[test]
    fn test_unrecognised_first_line_fails_file() {
        let elb = "https 2024-01-15T00:00:00.000000Z app/my-lb/abc 1.2.3.4:5 10.0.0.1:80 0.001 0.002 0.000 200 200 34 366 \"GET https://x/ HTTP/1.1\"";
        assert!(parse_flow_log(elb).is_err());
    }

    // FP-07: an empty file fails; a header-only file is valid and empty.
    #[test]
    fn test_empty_and_header_only_files() {
        assert!(parse_flow_log("").is_err());
        assert!(parse_flow_log("\n\n").is_err());
        let p = parse(&[V2_HEADER]);
        assert_eq!(p.records.len(), 0);
        assert_eq!(p.rows_total, 0);
    }

    // FP-08: `-` is NULL and is not an issue.
    #[test]
    fn test_dash_is_null_without_issue() {
        let p = parse(&[
            V2_HEADER,
            "2 123456789010 eni-1235b8ca123456789 - - - - - - - 1431280876 1431280934 - NODATA",
        ]);
        let r = &p.records[0];
        assert_eq!(r.get("srcaddr"), &FieldValue::Null);
        assert_eq!(r.get("bytes"), &FieldValue::Null);
        assert!(!r.has_parse_issue);
        assert!(p.issues.is_empty());
        assert_eq!(p.rows_valid, 1);
    }

    // FP-09: a malformed numeric value is NULL, flags the row and records the raw text.
    #[test]
    fn test_malformed_numeric_is_flagged_and_recorded() {
        let p = parse(&[
            V2_HEADER,
            "2 123456789010 eni-1 10.0.0.1 10.0.0.2 1 22 6 20 abc 1418530010 1418530070 ACCEPT OK",
        ]);
        let r = &p.records[0];
        assert_eq!(r.get("bytes"), &FieldValue::Null);
        assert!(r.has_parse_issue);
        assert_eq!(p.rows_with_issues, 1);
        assert_eq!(p.rows_valid, 0);
        assert_eq!(
            p.issues,
            vec![ParseIssue {
                line_no: 2,
                kind: IssueKind::Field,
                field: Some("bytes".into()),
                raw_value: Some("abc".into()),
                raw_line: None,
            }]
        );
    }

    // FP-10: short and long rows are rejected with their raw line; the file continues.
    #[test]
    fn test_wrong_token_count_rejects_row() {
        let good =
            "2 123456789010 eni-1 10.0.0.1 10.0.0.2 1 22 6 20 40 1418530010 1418530070 ACCEPT OK";
        let p = parse(&[
            V2_HEADER,
            "2 123456789010 eni-1",
            good,
            &format!("{good} extra"),
        ]);
        assert_eq!(p.records.len(), 1);
        assert_eq!(p.rows_total, 3);
        assert_eq!(p.rows_rejected, 2);
        assert_eq!(p.issues.len(), 2);
        assert_eq!(p.issues[0].kind, IssueKind::Row);
        assert_eq!(
            p.issues[0].raw_line.as_deref(),
            Some("2 123456789010 eni-1")
        );
        assert_eq!(p.issues[0].line_no, 2);
    }

    // FP-11: raw issue text is capped per file; counts stay complete.
    #[test]
    fn test_issue_capture_is_bounded() {
        let mut lines = vec![V2_HEADER.to_string()];
        lines.extend((0..150).map(|_| "short row".to_string()));
        let p = parse_flow_log(&lines.join("\n")).unwrap();
        assert_eq!(p.rows_rejected, 150);
        assert_eq!(p.issues.len(), MAX_ISSUES_PER_FILE);
    }

    // FP-12: NODATA / SKIPDATA are counted and have no endpoints.
    #[test]
    fn test_nodata_skipdata_counted() {
        let p = parse(&[
            V2_HEADER,
            "2 123456789010 eni-1 - - - - - - - 1431280876 1431280934 - NODATA",
            "2 123456789010 eni-1 - - - - - - - 1431280876 1431280934 - SKIPDATA",
        ]);
        assert_eq!(p.nodata_rows, 1);
        assert_eq!(p.skipdata_rows, 1);
        assert!(
            p.records
                .iter()
                .all(|r| r.direction_source == DirectionSource::Unknown && r.remote_addr.is_none())
        );
    }

    // FP-13: the file's observation window spans all records.
    #[test]
    fn test_min_start_max_end() {
        let p = parse(&[
            V2_HEADER,
            "2 1 eni-1 10.0.0.1 10.0.0.2 1 22 6 1 1 200 260 ACCEPT OK",
            "2 1 eni-1 10.0.0.1 10.0.0.2 1 22 6 1 1 100 300 ACCEPT OK",
        ]);
        assert_eq!(p.min_start, Some(100));
        assert_eq!(p.max_end, Some(300));
    }

    // ── Endpoint derivation (PRD §4.1) ───────────────────────────────────

    const DIR_HEADER: &str =
        "srcaddr dstaddr pkt-srcaddr pkt-dstaddr flow-direction protocol log-status";

    fn one(row: &str) -> FlowRecord {
        parse(&[DIR_HEADER, row]).records.remove(0)
    }

    fn endpoints(r: &FlowRecord) -> (Option<&str>, Option<&str>, DirectionSource) {
        (
            r.local_addr.as_deref(),
            r.remote_addr.as_deref(),
            r.direction_source,
        )
    }

    // FP-14: ingress — remote is the packet source, local the packet destination.
    #[test]
    fn test_ingress_uses_record_direction() {
        let r = one("52.95.128.179 10.0.0.71 52.95.128.179 10.0.0.71 ingress 6 OK");
        assert_eq!(
            endpoints(&r),
            (
                Some("10.0.0.71"),
                Some("52.95.128.179"),
                DirectionSource::Record
            )
        );
    }

    // FP-15: egress through a NAT gateway ENI — the original peer comes from pkt-dstaddr.
    #[test]
    fn test_egress_prefers_packet_addresses() {
        let r = one("10.0.1.5 10.0.0.220 10.0.1.5 203.0.113.5 egress 6 OK");
        assert_eq!(
            endpoints(&r),
            (
                Some("10.0.1.5"),
                Some("203.0.113.5"),
                DirectionSource::Record
            )
        );
    }

    // FP-16: with direction but no pkt-* fields, the interface addresses are used.
    #[test]
    fn test_direction_without_packet_fields() {
        let p = parse(&[
            "srcaddr dstaddr flow-direction log-status",
            "203.0.113.12 172.31.16.139 ingress OK",
        ]);
        assert_eq!(
            endpoints(&p.records[0]),
            (
                Some("172.31.16.139"),
                Some("203.0.113.12"),
                DirectionSource::Record
            )
        );
    }

    // FP-17: no direction, exactly one private IPv4 endpoint → heuristic.
    #[test]
    fn test_no_direction_one_private_is_heuristic() {
        let r = one("52.95.128.179 172.31.16.139 - - - 1 OK");
        assert_eq!(
            endpoints(&r),
            (
                Some("172.31.16.139"),
                Some("52.95.128.179"),
                DirectionSource::Heuristic
            )
        );
    }

    // FP-18: no direction and both private, both public, or IPv6 → unknown.
    #[test]
    fn test_no_direction_ambiguous_is_unknown() {
        for row in [
            "10.0.0.1 10.0.0.2 - - - 6 OK",
            "52.95.128.179 8.8.8.8 - - - 6 OK",
            "2001:db8::1 2001:db8::2 - - - 6 OK",
        ] {
            let r = one(row);
            assert_eq!(
                endpoints(&r),
                (None, None, DirectionSource::Unknown),
                "{row}"
            );
        }
    }

    // FP-19: protocol name and IP version are derived.
    #[test]
    fn test_protocol_name_and_ip_version() {
        let r = one("2001:db8::1 2001:db8::2 - - ingress 58 OK");
        assert_eq!(r.protocol_name.as_deref(), Some("ICMPv6"));
        assert_eq!(r.ip_version, Some(6));
        let r = one("10.0.0.1 10.0.0.2 - - egress 1 OK");
        assert_eq!(r.protocol_name.as_deref(), Some("ICMP"));
        assert_eq!(r.ip_version, Some(4));
        let r = one("10.0.0.1 10.0.0.2 - - egress 47 OK");
        assert_eq!(r.protocol_name.as_deref(), Some("47"));
    }

    // FP-20: address scopes come from the address class, with no GeoIP database.
    #[test]
    fn test_address_scopes() {
        let r = one("10.0.1.5 10.0.0.220 10.0.1.5 52.95.128.179 egress 6 OK");
        assert_eq!(r.src_scope, Some("private"));
        assert_eq!(r.dst_scope, Some("public"), "packet-level destination wins");
        assert_eq!(r.remote_scope, Some("public"));

        let r = one("169.254.1.1 127.0.0.1 - - - 6 OK");
        assert_eq!(
            (r.src_scope, r.dst_scope),
            (Some("link-local"), Some("loopback"))
        );
        assert_eq!(
            r.remote_scope, None,
            "no remote endpoint without a direction"
        );

        let r = parse(&[DIR_HEADER, "- - - - - - NODATA"]).records.remove(0);
        assert_eq!((r.src_scope, r.dst_scope), (None, None));
    }
}
