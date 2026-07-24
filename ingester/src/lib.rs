//! Senrigan ingester library.
//!
//! Provides the public API for ingesting AWS CloudTrail log files into DuckDB.

pub mod config_db;
pub mod config_import;
pub mod config_parser;
pub mod date_filter;
pub mod db;
pub mod enrich;
pub mod field_filter;
pub mod geoip;
pub mod ingest;
pub mod parser;
pub mod path_filter;
pub mod progress;
pub mod suzaku_db;
pub mod suzaku_import;
pub mod suzaku_parser;

/// Shared test utilities.
///
/// Only compiled when running tests (`#[cfg(test)]`).
/// Provides `temp_db`, `setup_db`, `minimal_event`, `full_event`, etc.
/// so individual modules don't need to duplicate these helpers.
#[cfg(test)]
pub mod test_util;
