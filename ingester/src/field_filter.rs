//! Recursive JSON field stripping for security-incident-oriented ingestion.
//!
//! [`FieldFilter`] removes a fixed set of "noise" keys from CloudTrail
//! `requestParameters` / `responseElements` JSON before it is written to
//! DuckDB. The `raw_event` column is intentionally left untouched so the
//! original record is always recoverable.
//!
//! The filter is opt-in (`--strip-fields` CLI flag); when disabled, JSON
//! is written verbatim — preserving the existing behaviour byte-for-byte.

use std::collections::HashSet;

use serde_json::Value;

/// Default set of CloudTrail keys considered low-signal for security
/// incident investigation.
///
/// Selection rule: a key is included only when it is **not useful as a
/// `request_parameters` / `response_elements` search criterion**. The
/// original event is always preserved verbatim in `raw_event`, so any
/// stripped value can still be retrieved by full-text search on that
/// column when needed — stripping only removes the dedicated-column
/// indexability of the field.
///
/// Categorised:
/// - **Pagination / size limits** — result set is irrelevant; only the
///   *fact* of the API call matters.
/// - **Idempotency tokens / dry-run** — AWS-internal request bookkeeping
///   with no investigative value.
/// - **Opaque ephemeral credentials** — `sessionToken` / `secretAccessKey`
///   are large base64 blobs that are never queried as search criteria.
/// - **AWS catalogue / reference response data** —
///   `eventCategoriesMapList`, `reservedNodeOfferings`, `sslPolicies`,
///   `orderableClusterOptions`. These are AWS-defined static catalogues
///   echoed back by `Describe*` operations.
/// - **Query-time filter echoes** — `filterSet`, `ownersSet`. Echoes of
///   the caller's filter criteria; almost always empty (`{}`) and never
///   useful as a search target after the fact.
/// - **Redundant transport headers** — `Host` / `host`. The HTTP host
///   header (e.g. `ec2.amazonaws.com`) duplicates information already
///   present in the dedicated `event_source` column.
///
/// Both camelCase and PascalCase variants are listed because AWS API
/// payloads use both conventions interchangeably.
pub const DEFAULT_STRIP_KEYS: &[&str] = &[
    // Pagination / size limits
    "maxResults",
    "MaxResults",
    "maxItems",
    "MaxItems",
    "nextToken",
    "NextToken",
    "marker",
    "Marker",
    "pageSize",
    "PageSize",
    // Idempotency / dry-run
    "dryRun",
    "DryRun",
    "clientToken",
    "ClientToken",
    "clientRequestToken",
    "ClientRequestToken",
    // Opaque ephemeral credentials issued by STS / AssumeRole
    "sessionToken",
    "SessionToken",
    "secretAccessKey",
    "SecretAccessKey",
    // AWS catalogue / reference data echoed by Describe* operations
    "eventCategoriesMapList",
    "reservedNodeOfferings",
    "sslPolicies",
    "orderableClusterOptions",
    // Query-time filter echoes
    "filterSet",
    "ownersSet",
    // Redundant transport headers (duplicated by event_source column)
    "Host",
    "host",
];

/// Filter that removes a fixed set of JSON keys at any depth.
///
/// `apply` is a no-op when the filter is empty, so callers can pass the
/// same filter unconditionally without paying a parse-and-reserialise cost
/// on the default (no-strip) path.
#[derive(Debug, Clone, Default)]
pub struct FieldFilter {
    keys: HashSet<String>,
}

impl FieldFilter {
    /// Build a filter that strips the given keys.
    pub fn new<I, S>(keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            keys: keys.into_iter().map(Into::into).collect(),
        }
    }

    /// Build a filter from [`DEFAULT_STRIP_KEYS`].
    pub fn default_strip() -> Self {
        Self::new(DEFAULT_STRIP_KEYS.iter().copied())
    }

    /// `true` when no keys are configured. The hot path uses this to
    /// short-circuit the parse-and-reserialise step entirely.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Apply the filter to a JSON string.
    ///
    /// Returns:
    /// - `Some(unchanged)` if the filter is empty — zero allocations.
    /// - `Some(unchanged)` if the input is not valid JSON — never destroys data.
    /// - `Some(filtered)` otherwise.
    ///
    /// Always preserves the input string when filtering is a no-op so the
    /// caller can blindly replace the field without comparing.
    pub fn apply(&self, json: &str) -> String {
        if self.keys.is_empty() {
            return json.to_owned();
        }
        let mut value: Value = match serde_json::from_str(json) {
            Ok(v) => v,
            // Not valid JSON (e.g. CloudTrail occasionally writes the literal
            // string "null" or numeric values) — leave untouched.
            Err(_) => return json.to_owned(),
        };
        self.strip(&mut value);
        // Re-serialisation can technically fail only on cycles, which serde_json::Value
        // cannot represent; fall back to the original on the unreachable error path.
        serde_json::to_string(&value).unwrap_or_else(|_| json.to_owned())
    }

    /// Recursively walk a `Value`, removing matching keys from any object.
    fn strip(&self, value: &mut Value) {
        match value {
            Value::Object(map) => {
                map.retain(|k, _| !self.keys.contains(k));
                for v in map.values_mut() {
                    self.strip(v);
                }
            }
            Value::Array(arr) => {
                for v in arr {
                    self.strip(v);
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_filter_returns_input_unchanged() {
        let filter = FieldFilter::default();
        assert!(filter.is_empty());
        let input = r#"{"maxResults":50,"bucketName":"x"}"#;
        assert_eq!(filter.apply(input), input);
    }

    #[test]
    fn test_default_strip_removes_pagination_keys() {
        let filter = FieldFilter::default_strip();
        let input = r#"{"maxResults":50,"nextToken":"abc","bucketName":"x"}"#;
        let out = filter.apply(input);
        let v: Value = serde_json::from_str(&out).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("maxResults"));
        assert!(!obj.contains_key("nextToken"));
        assert_eq!(obj.get("bucketName").and_then(Value::as_str), Some("x"));
    }

    #[test]
    fn test_strip_is_recursive_into_nested_objects() {
        let filter = FieldFilter::default_strip();
        let input = r#"{"outer":{"maxResults":10,"keep":"yes"},"keep_top":1}"#;
        let out = filter.apply(input);
        let v: Value = serde_json::from_str(&out).unwrap();
        let outer = v.get("outer").unwrap().as_object().unwrap();
        assert!(!outer.contains_key("maxResults"));
        assert_eq!(outer.get("keep").and_then(Value::as_str), Some("yes"));
        assert_eq!(v.get("keep_top").and_then(Value::as_i64), Some(1));
    }

    #[test]
    fn test_strip_descends_into_arrays() {
        let filter = FieldFilter::default_strip();
        let input = r#"{"items":[{"maxResults":1,"id":"a"},{"id":"b","nextToken":"t"}]}"#;
        let out = filter.apply(input);
        let v: Value = serde_json::from_str(&out).unwrap();
        let items = v.get("items").unwrap().as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert!(!items[0].as_object().unwrap().contains_key("maxResults"));
        assert!(!items[1].as_object().unwrap().contains_key("nextToken"));
        assert_eq!(items[0].get("id").and_then(Value::as_str), Some("a"));
        assert_eq!(items[1].get("id").and_then(Value::as_str), Some("b"));
    }

    #[test]
    fn test_strip_is_case_sensitive_with_both_variants() {
        // DEFAULT_STRIP_KEYS includes both `maxResults` and `MaxResults`.
        let filter = FieldFilter::default_strip();
        let input = r#"{"maxResults":1,"MaxResults":2,"MAXRESULTS":3}"#;
        let out = filter.apply(input);
        let v: Value = serde_json::from_str(&out).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("maxResults"));
        assert!(!obj.contains_key("MaxResults"));
        // Unlisted casing must be preserved.
        assert_eq!(obj.get("MAXRESULTS").and_then(Value::as_i64), Some(3));
    }

    #[test]
    fn test_invalid_json_is_returned_unchanged() {
        let filter = FieldFilter::default_strip();
        let input = "not json {";
        assert_eq!(filter.apply(input), input);
    }

    #[test]
    fn test_non_object_top_level_json_is_returned_unchanged() {
        let filter = FieldFilter::default_strip();
        // CloudTrail occasionally writes the literal `null` or a string.
        assert_eq!(filter.apply("null"), "null");
        assert_eq!(filter.apply(r#""abc""#), r#""abc""#);
    }

    #[test]
    fn test_custom_keys_are_stripped() {
        let filter = FieldFilter::new(["custom"]);
        let input = r#"{"custom":1,"keep":2}"#;
        let out = filter.apply(input);
        let v: Value = serde_json::from_str(&out).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("custom"));
        assert_eq!(obj.get("keep").and_then(Value::as_i64), Some(2));
    }
}
