//! Date-range filter for CloudTrail log file paths.
//!
//! CloudTrail stores log files under `yyyy/mm/dd/` directory segments.
//! This module extracts those path components and determines whether a file
//! falls within a caller-specified `[from, to]` date range (inclusive).
//!
//! Files whose path contains **no** recognizable date segment are always
//! included (conservative: we do not silently drop unclassifiable files).

use std::path::Path;

use anyhow::{Context, Result};
use chrono::NaiveDate;

// ── Public types ──────────────────────────────────────────────────────────────

/// An inclusive `[from, to]` date-range filter applied to file paths.
///
/// Both bounds are optional:
/// - If neither is set the filter is a no-op (every path matches).
/// - If only `from` is set, files dated before `from` are excluded.
/// - If only `to` is set, files dated after `to` are excluded.
/// - If both are set, only files within `[from, to]` are included.
#[derive(Debug, Default, Clone)]
pub struct DateFilter {
    /// Inclusive lower bound.
    pub from: Option<NaiveDate>,
    /// Inclusive upper bound.
    pub to: Option<NaiveDate>,
}

impl DateFilter {
    /// Create a new `DateFilter` from optional `NaiveDate` bounds.
    pub fn new(from: Option<NaiveDate>, to: Option<NaiveDate>) -> Self {
        Self { from, to }
    }

    /// Parse `from` and `to` from optional `YYYYMMDD` strings (e.g. `"20240115"`).
    ///
    /// Returns an error if either string cannot be parsed as a valid calendar date.
    pub fn from_strs(from: Option<&str>, to: Option<&str>) -> Result<Self> {
        let parse = |s: &str| {
            NaiveDate::parse_from_str(s, "%Y%m%d")
                .with_context(|| format!("Invalid date '{s}': expected YYYYMMDD (e.g. 20240115)"))
        };
        Ok(Self {
            from: from.map(parse).transpose()?,
            to: to.map(parse).transpose()?,
        })
    }

    /// Returns `true` if the file at `path` should be ingested.
    ///
    /// - If neither `from` nor `to` is set, always returns `true`.
    /// - If the path contains no `yyyy/mm/dd` segment, returns `true`
    ///   (conservative: do not silently drop files we cannot classify).
    /// - Otherwise checks that the extracted date falls within `[from, to]`.
    pub fn matches(&self, path: &Path) -> bool {
        if self.from.is_none() && self.to.is_none() {
            return true;
        }
        match extract_date_from_path(path) {
            // Cannot determine date → include the file (conservative).
            None => true,
            Some(date) => self.from.is_none_or(|f| date >= f) && self.to.is_none_or(|t| date <= t),
        }
    }
}

// ── Path-date extraction ──────────────────────────────────────────────────────

/// Scan the components of `path` for a consecutive `yyyy / mm / dd` triple and
/// return the first valid `NaiveDate` found, or `None` if none exists.
///
/// The function accepts paths such as:
/// - `2024/01/15/file.json.gz`
/// - `/AWSLogs/123456789012/CloudTrail/us-east-1/2023/11/30/file.json.gz`
pub fn extract_date_from_path(path: &Path) -> Option<NaiveDate> {
    let components: Vec<&str> = path
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();

    for window in components.windows(3) {
        if let [y, m, d] = window
            && let Ok(date) = NaiveDate::parse_from_str(&format!("{y}-{m}-{d}"), "%Y-%m-%d")
        {
            return Some(date);
        }
    }
    None
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Convenience: build a `NaiveDate` from numeric y/m/d.
    fn date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    // ── extract_date_from_path ────────────────────────────────────────────

    // Test 1: path with no date-like components returns None.
    #[test]
    fn test_extract_date_no_date_in_path() {
        let path = PathBuf::from("/logs/cloudtrail/event.json.gz");
        assert_eq!(extract_date_from_path(&path), None);
    }

    // Test 2: path with a standard yyyy/mm/dd triple returns the correct date.
    #[test]
    fn test_extract_date_standard_path() {
        let path = PathBuf::from("/logs/2024/01/15/event.json.gz");
        assert_eq!(extract_date_from_path(&path), Some(date(2024, 1, 15)));
    }

    // Test 3: CloudTrail-style deep path (AccountId/CloudTrail/region/yyyy/mm/dd).
    #[test]
    fn test_extract_date_cloudtrail_deep_path() {
        let path =
            PathBuf::from("/AWSLogs/123456789012/CloudTrail/us-east-1/2023/11/30/file.json.gz");
        assert_eq!(extract_date_from_path(&path), Some(date(2023, 11, 30)));
    }

    // Test 4: year/month/day where month is out of range (13) returns None.
    #[test]
    fn test_extract_date_invalid_month() {
        let path = PathBuf::from("/logs/2024/13/01/event.json.gz");
        assert_eq!(extract_date_from_path(&path), None);
    }

    // Test 5: month=02, day=30 is invalid — chrono rejects it, returns None.
    #[test]
    fn test_extract_date_invalid_day_for_month() {
        let path = PathBuf::from("/logs/2024/02/30/event.json.gz");
        assert_eq!(extract_date_from_path(&path), None);
    }

    // ── DateFilter::matches ───────────────────────────────────────────────

    // Test 6: no filter (default) always returns true.
    #[test]
    fn test_date_filter_no_filter_matches_any_path() {
        let filter = DateFilter::default();
        assert!(filter.matches(Path::new("/logs/2024/01/15/event.json.gz")));
        assert!(filter.matches(Path::new("/logs/no/date/here/event.json.gz")));
    }

    // Test 7: from-only — path on or after `from` matches; before does not.
    #[test]
    fn test_date_filter_from_only_accepts_on_or_after() {
        let filter = DateFilter::new(Some(date(2024, 1, 15)), None);
        assert!(
            filter.matches(Path::new("/logs/2024/01/15/event.json.gz")),
            "exact from date should match"
        );
        assert!(
            filter.matches(Path::new("/logs/2024/01/16/event.json.gz")),
            "after from date should match"
        );
        assert!(
            !filter.matches(Path::new("/logs/2024/01/14/event.json.gz")),
            "before from date should not match"
        );
    }

    // Test 8: to-only — path on or before `to` matches; after does not.
    #[test]
    fn test_date_filter_to_only_accepts_on_or_before() {
        let filter = DateFilter::new(None, Some(date(2024, 1, 15)));
        assert!(
            filter.matches(Path::new("/logs/2024/01/15/event.json.gz")),
            "exact to date should match"
        );
        assert!(
            filter.matches(Path::new("/logs/2024/01/14/event.json.gz")),
            "before to date should match"
        );
        assert!(
            !filter.matches(Path::new("/logs/2024/01/16/event.json.gz")),
            "after to date should not match"
        );
    }

    // Test 9: range filter — dates within [from, to] match (inclusive).
    #[test]
    fn test_date_filter_range_accepts_within() {
        let filter = DateFilter::new(Some(date(2024, 1, 10)), Some(date(2024, 1, 20)));
        assert!(filter.matches(Path::new("/logs/2024/01/10/event.json.gz")));
        assert!(filter.matches(Path::new("/logs/2024/01/15/event.json.gz")));
        assert!(filter.matches(Path::new("/logs/2024/01/20/event.json.gz")));
    }

    // Test 10: range filter — date before from is rejected.
    #[test]
    fn test_date_filter_range_rejects_before_from() {
        let filter = DateFilter::new(Some(date(2024, 1, 10)), Some(date(2024, 1, 20)));
        assert!(!filter.matches(Path::new("/logs/2024/01/09/event.json.gz")));
    }

    // Test 11: range filter — date after to is rejected.
    #[test]
    fn test_date_filter_range_rejects_after_to() {
        let filter = DateFilter::new(Some(date(2024, 1, 10)), Some(date(2024, 1, 20)));
        assert!(!filter.matches(Path::new("/logs/2024/01/21/event.json.gz")));
    }

    // Test 12: path with no date segment always matches even when filter is set
    // (conservative: include rather than exclude unclassifiable files).
    #[test]
    fn test_date_filter_no_date_in_path_always_matches() {
        let filter = DateFilter::new(Some(date(2024, 1, 10)), Some(date(2024, 1, 20)));
        assert!(
            filter.matches(Path::new("/logs/no/date/event.json.gz")),
            "path without date must still match (conservative fallback)"
        );
    }

    // ── DateFilter::from_strs ─────────────────────────────────────────────

    // Test 13: valid YYYYMMDD strings are parsed correctly.
    #[test]
    fn test_date_filter_from_strs_valid() {
        let filter = DateFilter::from_strs(Some("20240101"), Some("20241231")).unwrap();
        assert_eq!(filter.from, Some(date(2024, 1, 1)));
        assert_eq!(filter.to, Some(date(2024, 12, 31)));
    }

    // Test 14: None inputs produce a no-op filter.
    #[test]
    fn test_date_filter_from_strs_none_inputs() {
        let filter = DateFilter::from_strs(None, None).unwrap();
        assert!(filter.from.is_none());
        assert!(filter.to.is_none());
    }

    // Test 15: YYYY-MM-DD (hyphenated) format is rejected.
    #[test]
    fn test_date_filter_from_strs_invalid_format() {
        let result = DateFilter::from_strs(Some("2024-01-01"), None);
        assert!(result.is_err(), "YYYY-MM-DD format should be rejected");
    }

    // Test 16: invalid calendar date (month 13) returns an error.
    #[test]
    fn test_date_filter_from_strs_invalid_calendar_date() {
        let result = DateFilter::from_strs(Some("20241301"), None);
        assert!(result.is_err(), "month 13 is not a valid calendar date");
    }
}
