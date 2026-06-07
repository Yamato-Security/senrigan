//! Progress reporting for ingestion runs.
//!
//! Wraps `indicatif` so that callers can drive progress updates without
//! knowing the underlying rendering details. In test environments the bar
//! is hidden automatically when constructed with [`ProgressReporter::hidden`].

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

/// A thin wrapper around an `indicatif` progress bar used during ingestion.
pub struct ProgressReporter {
    bar: ProgressBar,
}

impl ProgressReporter {
    /// Create a visible progress bar for `total_files` files.
    pub fn new(total_files: u64) -> Self {
        let bar = ProgressBar::new(total_files);
        bar.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] \
                 {pos}/{len} files  ({msg})",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        Self { bar }
    }

    /// Create a hidden (no-output) reporter for use in tests.
    pub fn hidden() -> Self {
        let bar = ProgressBar::with_draw_target(Some(0), ProgressDrawTarget::hidden());
        Self { bar }
    }

    /// Advance the bar by one file and display `records` as the status message.
    pub fn inc(&self, records: usize) {
        self.bar.set_message(format!("{records} records"));
        self.bar.inc(1);
    }

    /// Mark the bar as finished (success path).
    ///
    /// Explicitly advances the position to `len` before calling
    /// `finish_with_message` so that the bar visually reaches 100% even when
    /// the final batch of increments was processed so quickly that the
    /// rate-limited renderer did not yet draw the updated position.
    pub fn finish(&self) {
        if let Some(len) = self.bar.length() {
            self.bar.set_position(len);
        }
        self.bar.finish_with_message("done");
    }

    /// Abandon the bar at its current position (error path).
    ///
    /// Unlike [`finish`], this does NOT advance the position to `len`.
    /// It prints the bar at whatever reached position and marks it as done,
    /// making it clear to the user that the run ended early.
    pub fn abandon(&self, message: &str) {
        self.bar.abandon_with_message(message.to_string());
    }

    /// Returns `true` if the bar has been finalized (either via [`finish`] or [`abandon`]).
    ///
    /// Exposed for testing only.
    #[cfg(test)]
    pub fn is_finished(&self) -> bool {
        self.bar.is_finished()
    }

    /// Returns the current position of the bar.
    ///
    /// Exposed for testing only.
    #[cfg(test)]
    pub fn position(&self) -> u64 {
        self.bar.position()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test PR-01: finish() finalizes the bar (is_finished returns true).
    #[test]
    fn test_finish_finalizes_bar() {
        let reporter = ProgressReporter::hidden();
        assert!(!reporter.is_finished(), "bar should not be finished yet");
        reporter.finish();
        assert!(
            reporter.is_finished(),
            "bar should be finished after finish()"
        );
    }

    // Test PR-02: abandon() also finalizes the bar (is_finished returns true).
    #[test]
    fn test_abandon_finalizes_bar() {
        let reporter = ProgressReporter::hidden();
        assert!(!reporter.is_finished(), "bar should not be finished yet");
        reporter.abandon("error");
        assert!(
            reporter.is_finished(),
            "bar should be finished after abandon()"
        );
    }

    // Test PR-03: inc() does not mark the bar as finished.
    #[test]
    fn test_inc_does_not_finalize_bar() {
        let reporter = ProgressReporter::new(10);
        reporter.inc(1);
        assert!(
            !reporter.is_finished(),
            "bar must not be finished after inc()"
        );
    }

    // Test PR-04: finish() sets the bar position to its full length.
    #[test]
    fn test_finish_sets_position_to_length() {
        let reporter = ProgressReporter::new(10);
        reporter.inc(0);
        reporter.inc(0);
        reporter.inc(0);
        // Bar is at position 3, length is 10.
        assert_eq!(reporter.position(), 3, "position should be 3 before finish");
        reporter.finish();
        // After finish(), the bar must be at its full length (10).
        assert_eq!(
            reporter.position(),
            reporter.bar.length().unwrap_or(0),
            "finish() must advance bar to its full length"
        );
    }
}
