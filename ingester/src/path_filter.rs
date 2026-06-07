//! Glob-pattern include/exclude filter for ingestion file paths.
//!
//! S3 buckets often hold logs from multiple AWS services
//! (CloudTrail, Config, VPC Flow Logs, ALB, …) under the same prefix.
//! This module lets callers whittle down the candidate file list to only
//! the services they care about.
//!
//! # Pattern syntax
//!
//! Patterns follow shell-glob conventions (`*`, `?`, `[abc]`).
//! The `*` wildcard matches **any sequence of characters including `/`**,
//! so `*CloudTrail*` matches anywhere in the full path.
//!
//! # Semantics
//!
//! | include set | exclude set | result                                    |
//! |-------------|-------------|-------------------------------------------|
//! | empty       | empty       | always included                           |
//! | non-empty   | empty       | included iff path matches ≥1 include      |
//! | empty       | non-empty   | included iff path matches no exclude      |
//! | non-empty   | non-empty   | must satisfy both conditions above        |

use std::path::Path;

use anyhow::{Context, Result};
use glob::{MatchOptions, Pattern};

/// Match options used for every pattern: `*` crosses path separators and
/// comparisons are case-sensitive.
const MATCH_OPTS: MatchOptions = MatchOptions {
    case_sensitive: true,
    require_literal_separator: false,
    require_literal_leading_dot: false,
};

// ── Public types ──────────────────────────────────────────────────────────────

/// An include/exclude glob-pattern filter applied to file paths.
///
/// Construct with [`PathFilter::from_strs`]; the no-arg default is a no-op.
#[derive(Debug, Default, Clone)]
pub struct PathFilter {
    include: Vec<Pattern>,
    exclude: Vec<Pattern>,
}

impl PathFilter {
    /// Build a `PathFilter` from optional comma-separated glob-pattern strings.
    ///
    /// Each string is split on `,`, trimmed, and compiled into a glob
    /// [`Pattern`]. Returns an error if any pattern is syntactically invalid.
    ///
    /// # Examples
    /// ```
    /// use ingester::path_filter::PathFilter;
    /// let f = PathFilter::from_strs(Some("*CloudTrail*"), Some("*us-west-2*")).unwrap();
    /// ```
    pub fn from_strs(include: Option<&str>, exclude: Option<&str>) -> Result<Self> {
        let parse = |raw: &str| -> Result<Vec<Pattern>> {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|p| Pattern::new(p).with_context(|| format!("Invalid glob pattern '{p}'")))
                .collect()
        };
        Ok(Self {
            include: include.map(parse).transpose()?.unwrap_or_default(),
            exclude: exclude.map(parse).transpose()?.unwrap_or_default(),
        })
    }

    /// Returns `true` if `path` should be ingested.
    ///
    /// Matching is performed against the full path string (UTF-8 lossily
    /// converted). `*` crosses `/` boundaries.
    pub fn matches(&self, path: &Path) -> bool {
        let s = path.to_string_lossy();

        // Include check: when patterns are set, at least one must match.
        if !self.include.is_empty() && !self.include.iter().any(|p| p.matches_with(&s, MATCH_OPTS))
        {
            return false;
        }

        // Exclude check: no pattern must match.
        if self.exclude.iter().any(|p| p.matches_with(&s, MATCH_OPTS)) {
            return false;
        }

        true
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    const CLOUDTRAIL_PATH: &str =
        "/AWSLogs/123456789012/CloudTrail/us-east-1/2024/01/15/file.json.gz";
    const CONFIG_PATH: &str = "/AWSLogs/123456789012/Config/us-east-1/2024/01/15/file.json.gz";
    const FLOWLOG_PATH: &str =
        "/AWSLogs/123456789012/vpcflowlogs/us-west-2/2024/01/15/file.json.gz";

    // Test 1: default (no patterns) matches every path.
    #[test]
    fn test_path_filter_no_filter_matches_any_path() {
        let f = PathFilter::default();
        assert!(f.matches(Path::new(CLOUDTRAIL_PATH)));
        assert!(f.matches(Path::new(CONFIG_PATH)));
        assert!(f.matches(Path::new(FLOWLOG_PATH)));
    }

    // Test 2: include single pattern — matching path is included.
    #[test]
    fn test_path_filter_include_single_pattern_matches() {
        let f = PathFilter::from_strs(Some("*CloudTrail*"), None).unwrap();
        assert!(f.matches(Path::new(CLOUDTRAIL_PATH)));
    }

    // Test 3: include single pattern — non-matching path is excluded.
    #[test]
    fn test_path_filter_include_single_pattern_no_match() {
        let f = PathFilter::from_strs(Some("*CloudTrail*"), None).unwrap();
        assert!(!f.matches(Path::new(CONFIG_PATH)));
        assert!(!f.matches(Path::new(FLOWLOG_PATH)));
    }

    // Test 4: include multiple comma-separated patterns — OR logic (any match → included).
    #[test]
    fn test_path_filter_include_multiple_patterns_any_match() {
        let f = PathFilter::from_strs(Some("*CloudTrail*,*Config*"), None).unwrap();
        assert!(f.matches(Path::new(CLOUDTRAIL_PATH)));
        assert!(f.matches(Path::new(CONFIG_PATH)));
        assert!(!f.matches(Path::new(FLOWLOG_PATH)));
    }

    // Test 5: exclude single pattern — matching path is excluded.
    #[test]
    fn test_path_filter_exclude_single_pattern_excludes() {
        let f = PathFilter::from_strs(None, Some("*Config*")).unwrap();
        assert!(!f.matches(Path::new(CONFIG_PATH)));
    }

    // Test 6: exclude single pattern — non-matching path passes through.
    #[test]
    fn test_path_filter_exclude_single_pattern_non_matching_passes() {
        let f = PathFilter::from_strs(None, Some("*Config*")).unwrap();
        assert!(f.matches(Path::new(CLOUDTRAIL_PATH)));
        assert!(f.matches(Path::new(FLOWLOG_PATH)));
    }

    // Test 7: exclude multiple patterns — any match is sufficient to exclude.
    #[test]
    fn test_path_filter_exclude_multiple_patterns_any_match() {
        let f = PathFilter::from_strs(None, Some("*Config*,*vpcflowlogs*")).unwrap();
        assert!(f.matches(Path::new(CLOUDTRAIL_PATH)));
        assert!(!f.matches(Path::new(CONFIG_PATH)));
        assert!(!f.matches(Path::new(FLOWLOG_PATH)));
    }

    // Test 8: include AND exclude both match → exclude wins (path is excluded).
    #[test]
    fn test_path_filter_exclude_takes_priority_over_include() {
        // Include all AWSLogs, but exclude Config specifically.
        let f = PathFilter::from_strs(Some("*AWSLogs*"), Some("*Config*")).unwrap();
        assert!(f.matches(Path::new(CLOUDTRAIL_PATH))); // include ✓, exclude ✗
        assert!(!f.matches(Path::new(CONFIG_PATH))); // include ✓, exclude ✓ → rejected
    }

    // Test 9: include matches, exclude does not match → path is included.
    #[test]
    fn test_path_filter_include_matches_exclude_does_not() {
        let f = PathFilter::from_strs(Some("*CloudTrail*"), Some("*Config*")).unwrap();
        assert!(f.matches(Path::new(CLOUDTRAIL_PATH)));
    }

    // Test 10: glob wildcard — region-level filtering with `*`.
    #[test]
    fn test_path_filter_glob_wildcard_region() {
        let f = PathFilter::from_strs(Some("*us-east-1*"), None).unwrap();
        assert!(f.matches(Path::new(CLOUDTRAIL_PATH))); // us-east-1 in path
        assert!(!f.matches(Path::new(FLOWLOG_PATH))); // us-west-2 in path
    }

    // Test 11: `?` wildcard matches exactly one character.
    #[test]
    fn test_path_filter_glob_question_mark_wildcard() {
        // us-east-? matches us-east-1 but not us-east-12.
        let f = PathFilter::from_strs(Some("*us-east-?/*"), None).unwrap();
        assert!(f.matches(Path::new(CLOUDTRAIL_PATH)));
    }

    // Test 12: invalid glob pattern returns an error from from_strs.
    #[test]
    fn test_path_filter_from_strs_invalid_glob_returns_error() {
        let result = PathFilter::from_strs(Some("*CloudTrail["), None);
        assert!(
            result.is_err(),
            "unclosed '[' should be a glob syntax error"
        );
    }

    // Test 13: whitespace around patterns in comma-separated list is trimmed.
    #[test]
    fn test_path_filter_from_strs_trims_whitespace() {
        let f = PathFilter::from_strs(Some(" *CloudTrail* , *Config* "), None).unwrap();
        assert!(f.matches(Path::new(CLOUDTRAIL_PATH)));
        assert!(f.matches(Path::new(CONFIG_PATH)));
    }

    // Test 14: empty string produces a no-op filter (same as None).
    #[test]
    fn test_path_filter_from_strs_empty_string_is_noop() {
        let f = PathFilter::from_strs(Some(""), None).unwrap();
        assert!(f.matches(Path::new(CONFIG_PATH)));
        assert!(f.matches(Path::new(CLOUDTRAIL_PATH)));
    }

    // Test 15: account-id segment can be targeted specifically.
    #[test]
    fn test_path_filter_include_by_account_id() {
        let f = PathFilter::from_strs(Some("*123456789012*"), None).unwrap();
        let other =
            PathBuf::from("/AWSLogs/999999999999/CloudTrail/us-east-1/2024/01/15/file.json.gz");
        assert!(f.matches(Path::new(CLOUDTRAIL_PATH)));
        assert!(!f.matches(&other));
    }
}
