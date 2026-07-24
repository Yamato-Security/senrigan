//! Pure normalisation of Suzaku `timeline` rows into Senrigan's schema.
//!
//! Suzaku writes its DuckDB output as a single `timeline` table whose columns
//! are the keys of the active output profile (`config/aws_profile.yaml`,
//! `config/azure_profile.yaml`, or a user-supplied one).  Two properties of
//! that format drive everything in this module:
//!
//! * **Every column is `VARCHAR`.**  Suzaku formats each value for display
//!   before writing it, so timestamps, levels and severities all arrive as
//!   strings and have to be parsed back here.
//! * **A missing value is the literal `"-"`, not `NULL`.**  Feeding those
//!   placeholders into the dashboard would turn `"-"` into the single largest
//!   bucket of most charts, so they are normalised to `NULL` on import.
//!
//! The two profiles Suzaku ships use different column names for the same
//! concept (`EventName`/`Operation`, `EventSource`/`Workload`,
//! `UserName`/`User`, …).  [`SuzakuProfile`] resolves both into one schema so a
//! single dashboard works for AWS CloudTrail and Azure/M365 alike, and keeps
//! the untouched original row in `raw_row` so a custom profile never loses
//! data.
//!
//! Everything here is pure: no I/O and no DuckDB access.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::suzaku_db::{SuzakuDetection, SuzakuDetectionTag};

/// The placeholder Suzaku writes for a field the event does not carry.
const PLACEHOLDER: &str = "-";

/// Separator Suzaku uses when it folds several values into one column
/// (`format_tags`, and every column of a correlation-rule record).
pub const MULTI_VALUE_SEPARATOR: &str = " ¦ ";

/// ATT&CK tactic abbreviations emitted by Suzaku's `config/mitre_tactics.txt`.
///
/// Suzaku falls back to the un-abbreviated `attack.<tactic>` spelling when that
/// file is missing, so [`classify_tag`] recognises both forms.
const TACTIC_ABBREVIATIONS: &[&str] = &[
    "Recon",
    "ResDev",
    "InitAccess",
    "Exec",
    "Persis",
    "PrivEsc",
    "Stealth",
    "DefImpair",
    "CredAccess",
    "Disc",
    "LatMov",
    "Collect",
    "C2",
    "Exfil",
    "Impact",
];

/// Profile columns that only ever appear in an AWS CloudTrail timeline.
const AWS_MARKER_COLUMNS: &[&str] = &[
    "AWS-Region",
    "UserARN",
    "UserAccountID",
    "UserAccessKeyID",
    "UserPrincipalID",
];

/// Profile columns that only ever appear in an Azure / M365 timeline.
const AZURE_MARKER_COLUMNS: &[&str] = &[
    "Workload",
    "RecordType",
    "Operation",
    "CorrelationId",
    "AppId",
    "LogonError",
];

// ── Value helpers ─────────────────────────────────────────────────────────────

/// Trim a raw Suzaku cell and map its `"-"` placeholder (and empties) to `None`.
pub fn clean(value: Option<&str>) -> Option<String> {
    let trimmed = value?.trim();
    if trimmed.is_empty() || trimmed == PLACEHOLDER {
        return None;
    }
    Some(trimmed.to_string())
}

/// Sortable severity for a Sigma level: critical=5 … informational=1.
///
/// Unrecognised or missing levels rank 0, which keeps them below every real
/// severity in "worst first" chart orderings.
pub fn level_rank(level: Option<&str>) -> i32 {
    match level.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("critical") => 5,
        Some("high") => 4,
        Some("medium") => 3,
        Some("low") => 2,
        Some("informational") | Some("info") => 1,
        _ => 0,
    }
}

/// Parse a Suzaku timestamp into a UTC `"YYYY-MM-DD HH:MM:SS.mmm"` string.
///
/// Suzaku renders timestamps in one of two shapes: UTC with the RFC 3339 `T`
/// and `Z` stripped (`2023-07-10 12:27:45`), or — under `--localtime` — the
/// local time with an explicit offset (`2023-07-10 21:27:45+09:00`).  Both are
/// accepted and normalised to UTC so that a database assembled from several
/// Suzaku runs stays on one timeline.  Raw RFC 3339 (`--raw-output`) is
/// accepted too.  Anything unparseable yields `None` rather than a wrong
/// instant.
pub fn parse_detected_at(value: Option<&str>) -> Option<String> {
    let raw = clean(value)?;
    // Correlation records join every column's distinct values; keep the first
    // instant rather than failing the whole row.
    let raw = raw
        .split(MULTI_VALUE_SEPARATOR)
        .next()
        .unwrap_or(&raw)
        .trim();

    let utc: DateTime<Utc> =
        if let Ok(dt) = DateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%.f%:z") {
            dt.with_timezone(&Utc)
        } else if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
            dt.with_timezone(&Utc)
        } else if let Ok(naive) = NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%.f") {
            naive.and_utc()
        } else {
            return None;
        };

    Some(utc.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
}

/// Classify one Suzaku tag as `tactic`, `technique`, `group`, or `other`.
///
/// Handles both the abbreviated form Suzaku emits when
/// `config/mitre_tactics.txt` is available (`CredAccess`, `T1110`, `G0035`)
/// and the raw Sigma spelling it falls back to when that file is missing
/// (`attack.credential-access`, `attack.t1110`, `attack.g0035`).
pub fn classify_tag(tag: &str) -> &'static str {
    let tag = tag.trim();
    if tag.is_empty() {
        return "other";
    }
    // Raw Sigma spelling: attack.<something>
    if let Some(rest) = tag.to_ascii_lowercase().strip_prefix("attack.") {
        return if is_numbered_id(rest, 't') {
            "technique"
        } else if is_numbered_id(rest, 'g') {
            "group"
        } else {
            "tactic"
        };
    }
    if is_numbered_id(tag, 'T') {
        return "technique";
    }
    if is_numbered_id(tag, 'G') {
        return "group";
    }
    if TACTIC_ABBREVIATIONS
        .iter()
        .any(|t| t.eq_ignore_ascii_case(tag))
    {
        return "tactic";
    }
    "other"
}

/// True for ATT&CK-style identifiers: `<prefix>` followed by digits, optionally
/// with a `.`-separated sub-technique number (`T1562.001`).
fn is_numbered_id(value: &str, prefix: char) -> bool {
    let Some(rest) = value.strip_prefix([prefix, prefix.to_ascii_lowercase()]) else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    let mut parts = rest.split('.');
    let Some(head) = parts.next() else {
        return false;
    };
    if head.is_empty() || !head.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    parts.all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

/// Split a Suzaku ` ¦ `-separated tag string into `(tag_type, tag_value)`
/// pairs, preserving order and dropping duplicates.
pub fn split_tags(tags: Option<&str>) -> Vec<(&'static str, String)> {
    let Some(raw) = clean(tags) else {
        return Vec::new();
    };
    let mut seen: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for part in raw.split(MULTI_VALUE_SEPARATOR) {
        let value = part.trim();
        if value.is_empty() || value == PLACEHOLDER {
            continue;
        }
        if !seen.insert(value.to_string()) {
            continue;
        }
        out.push((classify_tag(value), value.to_string()));
    }
    out
}

/// Join every tag of one type back into a ` ¦ `-separated column value.
fn join_tags(tags: &[(&'static str, String)], wanted: &str) -> Option<String> {
    let values: Vec<&str> = tags
        .iter()
        .filter(|(t, _)| *t == wanted)
        .map(|(_, v)| v.as_str())
        .collect();
    if values.is_empty() {
        return None;
    }
    Some(values.join(MULTI_VALUE_SEPARATOR))
}

/// Derive a single `Success` / `Failure` outcome for a detection.
///
/// CloudTrail has no result field — an `errorCode` is the failure signal.
/// Azure/M365 carries `ResultStatus` (`Success`, `Failure`, …) or the numeric
/// sign-in `resultType`, where `0` means success.  A value that fits none of
/// those shapes is passed through unchanged rather than guessed at.
pub fn derive_outcome(
    provider: &str,
    error_code: Option<&str>,
    result: Option<&str>,
) -> Option<String> {
    if let Some(result) = clean(result) {
        let lower = result.to_ascii_lowercase();
        return Some(match lower.as_str() {
            "success" | "succeeded" | "0" => "Success".to_string(),
            "failure" | "failed" | "fail" => "Failure".to_string(),
            _ if lower.chars().all(|c| c.is_ascii_digit()) => "Failure".to_string(),
            _ => result,
        });
    }
    if provider == "aws" || error_code.is_some() {
        return Some(if error_code.is_some() {
            "Failure".to_string()
        } else {
            "Success".to_string()
        });
    }
    None
}

/// Deterministic identifier for one imported row.
///
/// Derived from the source file's SHA-256 and the row's ordinal, so re-running
/// an import over the same Suzaku output reproduces the same IDs (making the
/// delete-then-append replacement in `suzaku_import` idempotent) while two
/// byte-identical detections inside one file still get distinct IDs.
pub fn detection_id(source_sha: &str, row_index: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(source_sha.as_bytes());
    hasher.update(b":");
    hasher.update(row_index.to_string().as_bytes());
    hex::encode(hasher.finalize())
}

// ── Profile ───────────────────────────────────────────────────────────────────

/// The column layout of one Suzaku `timeline` table.
///
/// Built once per imported file: it resolves the profile's column names to
/// positions and infers which cloud the timeline describes, so per-row mapping
/// is a handful of index lookups.
pub struct SuzakuProfile {
    columns: Vec<String>,
    index: HashMap<String, usize>,
    provider: &'static str,
}

impl SuzakuProfile {
    /// Build a profile from the `timeline` table's column names, in order.
    pub fn new(columns: Vec<String>) -> Self {
        let index: HashMap<String, usize> = columns
            .iter()
            .enumerate()
            .map(|(i, c)| (c.to_ascii_lowercase(), i))
            .collect();
        let provider = infer_provider(&columns);
        Self {
            columns,
            index,
            provider,
        }
    }

    /// `aws`, `azure`, or `unknown` — inferred from the profile's columns.
    pub fn provider(&self) -> &'static str {
        self.provider
    }

    /// Column names in their original order.
    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    /// Cleaned value of `name`, or `None` when the profile has no such column.
    fn get(&self, values: &[Option<String>], name: &str) -> Option<String> {
        let idx = *self.index.get(&name.to_ascii_lowercase())?;
        clean(values.get(idx)?.as_deref())
    }

    /// Cleaned value of the first candidate column the profile actually has.
    ///
    /// This is what reconciles the AWS and Azure profiles: `EventName` on one
    /// and `Operation` on the other both land in `event_name`.
    fn pick(&self, values: &[Option<String>], names: &[&str]) -> Option<String> {
        names.iter().find_map(|name| self.get(values, name))
    }

    /// Normalise one `timeline` row into a [`SuzakuDetection`].
    pub fn map_row(
        &self,
        values: &[Option<String>],
        source_path: &str,
        source_sha: &str,
        row_index: usize,
    ) -> SuzakuDetection {
        let level = self
            .get(values, "Level")
            .map(|l| l.trim().to_ascii_lowercase());
        let tags_raw = self.get(values, "Tags");
        let tags = split_tags(tags_raw.as_deref());
        let error_code = self.pick(values, &["ErrorCode", "LogonError"]);
        let result = self.pick(values, &["Result", "ResultStatus"]);

        SuzakuDetection {
            detection_id: detection_id(source_sha, row_index),
            detected_at: parse_detected_at(self.get(values, "Timestamp").as_deref()),
            rule_title: self.get(values, "RuleTitle"),
            rule_id: self.get(values, "RuleID"),
            rule_author: self.get(values, "RuleAuthor"),
            level_rank: level_rank(level.as_deref()),
            level,
            mitre_tactics: join_tags(&tags, "tactic"),
            mitre_techniques: join_tags(&tags, "technique"),
            tags: tags_raw,
            cloud_provider: self.provider.to_string(),
            event_name: self.pick(values, &["EventName", "Operation"]),
            event_source: self.pick(values, &["EventSource", "Workload"]),
            aws_region: self.get(values, "AWS-Region"),
            source_ip: self.get(values, "SrcIP"),
            src_country: self.get(values, "SrcCountry"),
            src_city: self.get(values, "SrcCity"),
            src_asn: self.get(values, "SrcASN"),
            user_name: self.pick(values, &["UserName", "User"]),
            user_type: self.get(values, "UserType"),
            user_arn: self.get(values, "UserARN"),
            account_id: self.get(values, "UserAccountID"),
            principal_id: self.get(values, "UserPrincipalID"),
            access_key_id: self.get(values, "UserAccessKeyID"),
            user_agent: self.get(values, "UserAgent"),
            outcome: derive_outcome(self.provider, error_code.as_deref(), result.as_deref()),
            error_code,
            error_message: self.get(values, "ErrorMessage"),
            event_id: self.pick(values, &["EventID", "CorrelationId"]),
            target_object: self.get(values, "TargetObject"),
            record_type: self.get(values, "RecordType"),
            app_id: self.get(values, "AppId"),
            category: self.get(values, "Category"),
            details: self.get(values, "Details"),
            source_path: source_path.to_string(),
            source_sha: source_sha.to_string(),
            raw_row: self.raw_row_json(values),
        }
    }

    /// The original row as a JSON object — every profile column, verbatim.
    ///
    /// Placeholders are preserved here on purpose: `raw_row` is the escape
    /// hatch for a custom output profile whose columns this module does not
    /// know about, so it must be a faithful copy of what Suzaku wrote.
    fn raw_row_json(&self, values: &[Option<String>]) -> String {
        let mut map = Map::new();
        for (i, column) in self.columns.iter().enumerate() {
            let value = match values.get(i).and_then(|v| v.as_deref()) {
                Some(v) => Value::String(v.to_string()),
                None => Value::Null,
            };
            map.insert(column.clone(), value);
        }
        Value::Object(map).to_string()
    }
}

/// Explode a detection's tags into one [`SuzakuDetectionTag`] row each.
///
/// The identity and geography columns are copied onto every tag row so the
/// ATT&CK charts can group by tactic *and* filter by principal or country
/// without a join — Superset datasets are single-table.
pub fn tag_rows(detection: &SuzakuDetection) -> Vec<SuzakuDetectionTag> {
    split_tags(detection.tags.as_deref())
        .into_iter()
        .map(|(tag_type, tag_value)| SuzakuDetectionTag {
            detection_id: detection.detection_id.clone(),
            detected_at: detection.detected_at.clone(),
            level: detection.level.clone(),
            level_rank: detection.level_rank,
            rule_title: detection.rule_title.clone(),
            cloud_provider: detection.cloud_provider.clone(),
            user_name: detection.user_name.clone(),
            source_ip: detection.source_ip.clone(),
            src_country: detection.src_country.clone(),
            tag_type: tag_type.to_string(),
            tag_value,
            source_sha: detection.source_sha.clone(),
        })
        .collect()
}

/// Infer the cloud a timeline describes from its profile columns.
///
/// Counts marker columns unique to each profile rather than trusting a single
/// one, so a trimmed custom profile still resolves as long as it keeps any of
/// them.  A profile with no markers at all (or an equal number of both) is
/// `unknown`; every column still lands in `raw_row`.
fn infer_provider(columns: &[String]) -> &'static str {
    let names: HashSet<String> = columns.iter().map(|c| c.to_ascii_lowercase()).collect();
    let count = |markers: &[&str]| {
        markers
            .iter()
            .filter(|m| names.contains(&m.to_ascii_lowercase()))
            .count()
    };
    let aws = count(AWS_MARKER_COLUMNS);
    let azure = count(AZURE_MARKER_COLUMNS);
    match aws.cmp(&azure) {
        std::cmp::Ordering::Greater => "aws",
        std::cmp::Ordering::Less => "azure",
        std::cmp::Ordering::Equal => "unknown",
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Columns of Suzaku's shipped `config/aws_profile.yaml`, in order, with
    /// the three GeoIP columns `--geo-ip` appends.
    fn aws_columns() -> Vec<String> {
        [
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
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// Columns of Suzaku's shipped `config/azure_profile.yaml`, in order.
    fn azure_columns() -> Vec<String> {
        [
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
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn vals(values: &[&str]) -> Vec<Option<String>> {
        values.iter().map(|v| Some(v.to_string())).collect()
    }

    // Test SP-01: clean() maps the "-" placeholder and empties to None.
    #[test]
    fn test_clean_maps_placeholder_to_none() {
        assert_eq!(clean(Some("us-east-1")), Some("us-east-1".to_string()));
        assert_eq!(clean(Some("  padded  ")), Some("padded".to_string()));
        assert_eq!(clean(Some("-")), None);
        assert_eq!(clean(Some("")), None);
        assert_eq!(clean(Some("   ")), None);
        assert_eq!(clean(None), None);
    }

    // Test SP-02: a hyphen inside a real value is not treated as a placeholder.
    #[test]
    fn test_clean_keeps_values_containing_hyphens() {
        assert_eq!(
            clean(Some("ap-northeast-1")),
            Some("ap-northeast-1".to_string())
        );
    }

    // Test SP-03: level_rank orders every Sigma level, unknown lowest.
    #[test]
    fn test_level_rank_orders_severities() {
        assert_eq!(level_rank(Some("critical")), 5);
        assert_eq!(level_rank(Some("high")), 4);
        assert_eq!(level_rank(Some("medium")), 3);
        assert_eq!(level_rank(Some("low")), 2);
        assert_eq!(level_rank(Some("informational")), 1);
        assert_eq!(level_rank(Some("CRITICAL")), 5, "must be case-insensitive");
        assert_eq!(level_rank(Some("bogus")), 0);
        assert_eq!(level_rank(None), 0);
    }

    // Test SP-04: the default UTC rendering parses.
    #[test]
    fn test_parse_detected_at_utc_form() {
        assert_eq!(
            parse_detected_at(Some("2024-08-18 10:07:56")),
            Some("2024-08-18 10:07:56.000".to_string())
        );
    }

    // Test SP-05: --localtime output carries an offset and must be converted
    // back to UTC, so runs from different machines share one timeline.
    #[test]
    fn test_parse_detected_at_localtime_converts_to_utc() {
        assert_eq!(
            parse_detected_at(Some("2023-07-10 21:27:45+09:00")),
            Some("2023-07-10 12:27:45.000".to_string())
        );
    }

    // Test SP-06: fractional seconds and raw RFC 3339 are both accepted.
    #[test]
    fn test_parse_detected_at_accepts_fractions_and_rfc3339() {
        assert_eq!(
            parse_detected_at(Some("2024-08-18 10:07:56.250")),
            Some("2024-08-18 10:07:56.250".to_string())
        );
        assert_eq!(
            parse_detected_at(Some("2024-08-18T10:07:56Z")),
            Some("2024-08-18 10:07:56.000".to_string())
        );
    }

    // Test SP-07: unparseable or missing timestamps yield None rather than a
    // wrong instant.
    #[test]
    fn test_parse_detected_at_rejects_garbage() {
        assert_eq!(parse_detected_at(Some("-")), None);
        assert_eq!(parse_detected_at(Some("not-a-timestamp")), None);
        assert_eq!(parse_detected_at(None), None);
    }

    // Test SP-08: a correlation record joins its columns; keep the first instant.
    #[test]
    fn test_parse_detected_at_takes_first_of_a_joined_value() {
        assert_eq!(
            parse_detected_at(Some("2024-08-18 10:07:56 ¦ 2024-08-18 11:00:00")),
            Some("2024-08-18 10:07:56.000".to_string())
        );
    }

    // Test SP-09: tags are classified by shape, in both Suzaku spellings.
    #[test]
    fn test_classify_tag_recognises_both_spellings() {
        assert_eq!(classify_tag("CredAccess"), "tactic");
        assert_eq!(classify_tag("Impact"), "tactic");
        assert_eq!(classify_tag("attack.credential-access"), "tactic");
        assert_eq!(classify_tag("T1110"), "technique");
        assert_eq!(classify_tag("T1562.001"), "technique");
        assert_eq!(classify_tag("attack.t1562.001"), "technique");
        assert_eq!(classify_tag("G0035"), "group");
        assert_eq!(classify_tag("attack.g0035"), "group");
        assert_eq!(classify_tag("cve.2021.1234"), "other");
        assert_eq!(classify_tag(""), "other");
    }

    // Test SP-10: a tactic abbreviation that merely starts with T/G is not
    // mistaken for a technique or group ID.
    #[test]
    fn test_classify_tag_does_not_confuse_letters_with_ids() {
        assert_eq!(classify_tag("T"), "other");
        assert_eq!(classify_tag("TA0006"), "other");
        assert_eq!(classify_tag("Gather"), "other");
    }

    // Test SP-11: split_tags splits on Suzaku's separator, classifies each
    // entry, drops duplicates, and preserves order.
    #[test]
    fn test_split_tags_splits_classifies_and_dedups() {
        let tags = split_tags(Some("G0035 ¦ CredAccess ¦ Disc ¦ T1110 ¦ T1110"));
        assert_eq!(
            tags,
            vec![
                ("group", "G0035".to_string()),
                ("tactic", "CredAccess".to_string()),
                ("tactic", "Disc".to_string()),
                ("technique", "T1110".to_string()),
            ]
        );
        assert!(split_tags(Some("-")).is_empty());
        assert!(split_tags(None).is_empty());
    }

    // Test SP-12: CloudTrail has no result field, so an error code is the
    // failure signal and its absence means success.
    #[test]
    fn test_derive_outcome_for_aws() {
        assert_eq!(
            derive_outcome("aws", Some("AccessDenied"), None),
            Some("Failure".to_string())
        );
        assert_eq!(
            derive_outcome("aws", None, None),
            Some("Success".to_string())
        );
    }

    // Test SP-13: Azure carries an explicit result, including the numeric
    // sign-in resultType where 0 means success.
    #[test]
    fn test_derive_outcome_for_azure() {
        assert_eq!(
            derive_outcome("azure", None, Some("Success")),
            Some("Success".to_string())
        );
        assert_eq!(
            derive_outcome("azure", None, Some("Failed")),
            Some("Failure".to_string())
        );
        assert_eq!(
            derive_outcome("azure", None, Some("0")),
            Some("Success".to_string())
        );
        assert_eq!(
            derive_outcome("azure", None, Some("50126")),
            Some("Failure".to_string())
        );
        // A shape we do not recognise is passed through, never guessed at.
        assert_eq!(
            derive_outcome("azure", None, Some("PartiallySucceeded")),
            Some("PartiallySucceeded".to_string())
        );
        // No result and no error at all: unknown, not an assumed success.
        assert_eq!(derive_outcome("azure", None, None), None);
    }

    // Test SP-14: detection IDs are deterministic per (file, row) and unique
    // across rows — the basis of idempotent re-imports.
    #[test]
    fn test_detection_id_is_deterministic_and_unique() {
        assert_eq!(detection_id("abc", 0), detection_id("abc", 0));
        assert_ne!(detection_id("abc", 0), detection_id("abc", 1));
        assert_ne!(detection_id("abc", 0), detection_id("abd", 0));
        assert_eq!(detection_id("abc", 0).len(), 64);
    }

    // Test SP-15: provider inference for both shipped profiles.
    #[test]
    fn test_infer_provider() {
        assert_eq!(SuzakuProfile::new(aws_columns()).provider(), "aws");
        assert_eq!(SuzakuProfile::new(azure_columns()).provider(), "azure");
        let unknown = SuzakuProfile::new(vec!["Timestamp".to_string(), "RuleTitle".to_string()]);
        assert_eq!(unknown.provider(), "unknown");
    }

    // Test SP-16: an AWS row maps into the normalised schema, with placeholders
    // becoming NULL and the timestamp parsed.
    #[test]
    fn test_map_row_maps_the_aws_profile() {
        let profile = SuzakuProfile::new(aws_columns());
        let values = vals(&[
            "2024-08-18 10:07:56",
            "AWS EFS Fileshare Modified or Deleted",
            "Austin Songer",
            "medium",
            "DeleteFileSystem",
            "AccessDenied",
            "not authorized",
            "elasticfilesystem.amazonaws.com",
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
            "Impact ¦ T1485",
            "25cb1ba1-8a19-4a23-a198-d252664c8cef",
        ]);

        let d = profile.map_row(&values, "/data/suzaku/aws.duckdb", "sha-1", 0);

        assert_eq!(d.detected_at.as_deref(), Some("2024-08-18 10:07:56.000"));
        assert_eq!(
            d.rule_title.as_deref(),
            Some("AWS EFS Fileshare Modified or Deleted")
        );
        assert_eq!(d.level.as_deref(), Some("medium"));
        assert_eq!(d.level_rank, 3);
        assert_eq!(d.cloud_provider, "aws");
        assert_eq!(d.event_name.as_deref(), Some("DeleteFileSystem"));
        assert_eq!(
            d.event_source.as_deref(),
            Some("elasticfilesystem.amazonaws.com")
        );
        assert_eq!(d.aws_region.as_deref(), Some("us-east-1"));
        assert_eq!(d.source_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(d.user_name.as_deref(), Some("TrailDiscover"));
        assert_eq!(d.user_type.as_deref(), Some("IAMUser"));
        assert_eq!(d.account_id.as_deref(), Some("111111111111"));
        assert_eq!(d.access_key_id.as_deref(), Some("AKIA1234"));
        assert_eq!(d.error_code.as_deref(), Some("AccessDenied"));
        assert_eq!(d.outcome.as_deref(), Some("Failure"));
        assert_eq!(d.mitre_tactics.as_deref(), Some("Impact"));
        assert_eq!(d.mitre_techniques.as_deref(), Some("T1485"));
        // The un-enriched GeoIP placeholders must not become literal "-" values.
        assert_eq!(d.src_country, None);
        assert_eq!(d.src_city, None);
        assert_eq!(d.src_asn, None);
        // Azure-only fields stay empty for an AWS timeline.
        assert_eq!(d.record_type, None);
        assert_eq!(d.target_object, None);
    }

    // Test SP-17: the Azure/M365 profile resolves to the same columns even
    // though it names almost all of them differently.
    #[test]
    fn test_map_row_maps_the_azure_profile() {
        let profile = SuzakuProfile::new(azure_columns());
        let values = vals(&[
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
        ]);

        let d = profile.map_row(&values, "/data/suzaku/azure.duckdb", "sha-2", 3);

        assert_eq!(d.cloud_provider, "azure");
        // Operation → event_name, Workload → event_source, User → user_name.
        assert_eq!(d.event_name.as_deref(), Some("Add member to role."));
        assert_eq!(d.event_source.as_deref(), Some("AzureActiveDirectory"));
        assert_eq!(d.user_name.as_deref(), Some("attacker@contoso.com"));
        // CorrelationId stands in for EventID.
        assert_eq!(
            d.event_id.as_deref(),
            Some("0f1b2c3d-4e5f-6789-abcd-ef0123456789")
        );
        assert_eq!(d.record_type.as_deref(), Some("8"));
        assert_eq!(d.target_object.as_deref(), Some("Global Administrator"));
        assert_eq!(
            d.app_id.as_deref(),
            Some("1b730954-1685-4b74-9bfd-dac224a7b894")
        );
        assert_eq!(d.category.as_deref(), Some("AzureActiveDirectory"));
        assert_eq!(d.outcome.as_deref(), Some("Success"));
        assert_eq!(d.level_rank, 4);
        // AWS-only fields stay empty for an Azure timeline.
        assert_eq!(d.aws_region, None);
        assert_eq!(d.user_arn, None);
    }

    // Test SP-18: an unrecognised custom profile still imports — unknown
    // columns survive in raw_row rather than being dropped.
    #[test]
    fn test_map_row_keeps_unknown_columns_in_raw_row() {
        let profile = SuzakuProfile::new(vec![
            "Timestamp".to_string(),
            "RuleTitle".to_string(),
            "MyCustomField".to_string(),
        ]);
        let values = vals(&["2024-08-18 10:07:56", "Custom rule", "custom value"]);

        let d = profile.map_row(&values, "/data/suzaku/custom.duckdb", "sha-3", 0);

        assert_eq!(d.rule_title.as_deref(), Some("Custom rule"));
        let raw: Value = serde_json::from_str(&d.raw_row).expect("raw_row must be valid JSON");
        assert_eq!(raw["MyCustomField"], Value::String("custom value".into()));
    }

    // Test SP-19: raw_row is a faithful copy — placeholders included — so no
    // information from the original row is lost on import.
    #[test]
    fn test_raw_row_preserves_placeholders_and_nulls() {
        let profile = SuzakuProfile::new(vec![
            "Timestamp".to_string(),
            "SrcCountry".to_string(),
            "SrcCity".to_string(),
        ]);
        let values = vec![
            Some("2024-08-18 10:07:56".to_string()),
            Some("-".to_string()),
            None,
        ];

        let d = profile.map_row(&values, "/f.duckdb", "sha", 0);
        let raw: Value = serde_json::from_str(&d.raw_row).unwrap();
        assert_eq!(raw["SrcCountry"], Value::String("-".into()));
        assert_eq!(raw["SrcCity"], Value::Null);
        // …while the normalised column is NULL.
        assert_eq!(d.src_country, None);
    }

    // Test SP-20: tag_rows explodes the tag string and copies the detection's
    // pivot columns onto every row.
    #[test]
    fn test_tag_rows_explodes_tags_with_context() {
        let profile = SuzakuProfile::new(aws_columns());
        let mut values = vals(&["-"; 23]);
        values[0] = Some("2024-08-18 10:07:56".to_string());
        values[3] = Some("critical".to_string());
        values[9] = Some("203.0.113.7".to_string());
        values[14] = Some("TrailDiscover".to_string());
        values[21] = Some("CredAccess ¦ T1110 ¦ G0035".to_string());

        let detection = profile.map_row(&values, "/f.duckdb", "sha", 0);
        let tags = tag_rows(&detection);

        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0].tag_type, "tactic");
        assert_eq!(tags[0].tag_value, "CredAccess");
        assert_eq!(tags[1].tag_type, "technique");
        assert_eq!(tags[2].tag_type, "group");
        for tag in &tags {
            assert_eq!(tag.detection_id, detection.detection_id);
            assert_eq!(tag.level.as_deref(), Some("critical"));
            assert_eq!(tag.level_rank, 5);
            assert_eq!(tag.user_name.as_deref(), Some("TrailDiscover"));
            assert_eq!(tag.source_ip.as_deref(), Some("203.0.113.7"));
        }
    }

    // Test SP-21: an untagged detection produces no tag rows.
    #[test]
    fn test_tag_rows_empty_for_untagged_detection() {
        let detection = SuzakuDetection {
            tags: None,
            ..Default::default()
        };
        assert!(tag_rows(&detection).is_empty());
    }

    // Test SP-22: a row with fewer values than columns (a truncated read) maps
    // the columns it has instead of panicking.
    #[test]
    fn test_map_row_tolerates_short_rows() {
        let profile = SuzakuProfile::new(aws_columns());
        let values = vals(&["2024-08-18 10:07:56", "Some rule"]);
        let d = profile.map_row(&values, "/f.duckdb", "sha", 0);
        assert_eq!(d.rule_title.as_deref(), Some("Some rule"));
        assert_eq!(d.level, None);
    }
}
