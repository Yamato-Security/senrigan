# AGENTS.md — Ingester Module (Rust)

> Module-specific TDD context for the `ingester` crate.
> For project-wide instructions, see the root [AGENTS.md](../AGENTS.md).
> For feature requirements, see [doc/PRD.md](../doc/PRD.md).

## Module Purpose

The ingester reads AWS CloudTrail log files (JSON and `.json.gz`) from the local filesystem,
parses them, and inserts the records into a DuckDB database.
It is the **only** component that opens DuckDB in `READ_WRITE` mode.
Optional GeoIP enrichment populates 7 geo columns using MaxMind GeoLite2 databases.

## Technology Stack

| Item | Value |
|------|-------|
| Language | Rust (edition 2024) |
| Build system | Cargo |
| Key crates | `serde`, `serde_json`, `flate2`, `duckdb`, `clap`, `anyhow`, `indicatif`, `walkdir`, `sha2`, `rayon`, `chrono`, `glob`, `maxminddb` |
| Test crates | `tempfile`, `assert_cmd`, `predicates` |
| DuckDB mode | `READ_WRITE` |

## Module Structure

```
ingester/
├── Cargo.toml
├── src/
│   ├── main.rs            # CLI entry point (clap) — ingest + enrich + config-import subcommands
│   ├── lib.rs             # Public API re-exports
│   ├── parser.rs          # CloudTrail JSON parsing (serde_json)
│   ├── db.rs              # DuckDB schema, batch insert (Appender), geo columns
│   ├── ingest.rs          # Pipeline: walk → filter → parallel parse → insert
│   │                      # gz decompression is done inline in parse_file_content()
│   ├── enrich.rs          # Geo back-fill for existing rows (enrich subcommand)
│   ├── geoip.rs           # MaxMind GeoLite2 lookup + private-IP classification
│   ├── field_filter.rs    # --strip-fields: recursive JSON key removal (FieldFilter)
│   ├── date_filter.rs     # --from / --to path-based date filter
│   ├── path_filter.rs     # --include / --exclude glob filter
│   ├── progress.rs        # Progress bar wrapper (indicatif)
│   ├── config_parser.rs   # AWS Config snapshot JSON → typed structs
│   ├── config_db.rs       # Config tables schema + Appender writes
│   ├── config_import.rs   # config-import pipeline: walk → SHA dedup → parse → insert
│   └── test_util.rs       # Shared test fixtures (only compiled under #[cfg(test)])
└── tests/
    ├── cli_test.rs              # CLI integration tests (assert_cmd) — ingest + enrich
    ├── config_import_test.rs    # CLI integration tests for config-import subcommand
    ├── integration_test.rs      # End-to-end pipeline tests
    ├── testdata/
    │   ├── single_event.json     # 1 CloudTrail event
    │   ├── multi_event.json      # 3 CloudTrail events
    │   ├── single_event.json.gz  # 1 event, gzip-compressed
    │   └── malformed.json        # Invalid JSON (error handling)
    └── testdata_config/
        └── config_snapshot_mini.json  # 2-resource AWS Config snapshot fixture
```

## Key Data Structures

```rust
/// Pre-extracted fields from `userIdentity.sessionContext`.
pub struct SessionContext {
    pub mfa_authenticated:   Option<String>,  // sessionContext.attributes.mfaAuthenticated
    pub creation_date:       Option<String>,  // sessionContext.attributes.creationDate
    pub issuer_type:         Option<String>,  // sessionContext.sessionIssuer.type
    pub issuer_arn:          Option<String>,  // sessionContext.sessionIssuer.arn
    pub issuer_account_id:   Option<String>,  // sessionContext.sessionIssuer.accountId
    pub issuer_user_name:    Option<String>,  // sessionContext.sessionIssuer.userName
    pub issuer_principal_id: Option<String>,  // sessionContext.sessionIssuer.principalId
}

/// Pre-extracted fields from the `userIdentity` sub-object.
pub struct UserIdentity {
    pub identity_type: Option<String>,  // userIdentity.type
    pub arn:           Option<String>,  // userIdentity.arn
    pub account_id:    Option<String>,  // userIdentity.accountId
    pub principal_id:  Option<String>,  // userIdentity.principalId
    pub access_key_id: Option<String>,  // userIdentity.accessKeyId
    pub user_name:     Option<String>,  // userIdentity.userName
    pub invoked_by:    Option<String>,  // userIdentity.invokedBy
    pub session:       SessionContext,
}

/// Pre-extracted fields from the `tlsDetails` sub-object.
pub struct TlsDetails {
    pub tls_version:               Option<String>,  // tlsDetails.tlsVersion
    pub cipher_suite:              Option<String>,  // tlsDetails.cipherSuite
    pub client_provided_host_header: Option<String>, // tlsDetails.clientProvidedHostHeader
}

/// A single CloudTrail event record.
///
/// Column layout mirrors the DB schema: core → geo (populated externally) → extended.
pub struct CloudTrailEvent {
    // ── Core fields ──────────────────────────────────────────────────────
    pub event_time:            Option<String>,
    pub event_name:            String,
    pub event_source:          String,
    pub aws_region:            String,
    pub source_ip_address:     Option<String>,
    pub user_agent:            Option<String>,
    pub user_identity:         UserIdentity,   // → user_identity_* columns
    pub request_parameters:    Option<String>, // JSON stored as VARCHAR
    pub response_elements:     Option<String>, // JSON stored as VARCHAR
    pub error_code:            Option<String>,
    pub error_message:         Option<String>,
    pub read_only:             Option<bool>,
    pub event_type:            Option<String>,
    pub recipient_account_id:  Option<String>,
    pub raw_json:              String,          // written to raw_event column

    // ── Extended fields (Step A) ─────────────────────────────────────────
    pub event_id:                        Option<String>,
    pub event_category:                  Option<String>,
    pub resources:                       Option<String>, // JSON array
    pub additional_event_data:           Option<String>, // JSON object
    pub shared_event_id:                 Option<String>,
    pub vpc_endpoint_id:                 Option<String>,
    pub management_event:                Option<String>, // "true"/"false"
    pub tls:                             TlsDetails,     // → tls_* columns
    pub service_event_details:           Option<String>, // JSON object
    pub session_credential_from_console: Option<String>, // "true"/"false"
    pub api_version:                     Option<String>,
}

/// Statistics returned after an ingestion run.
pub struct IngestStats {
    pub files_processed: usize,
    pub records_inserted: usize,
    pub errors: usize,
    pub elapsed_secs: f64,
}

/// Statistics returned after a geo-enrichment run.
pub struct EnrichStats {
    pub enriched_count: usize,
    pub skipped_count: usize,
    pub elapsed_secs: f64,
}

/// GeoIP lookup result for a single IP address.
pub struct GeoInfo {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city:         Option<String>,
    pub latitude:     Option<f64>,
    pub longitude:    Option<f64>,
    pub asn:          Option<String>,
    pub org:          Option<String>,
}
```

## Pipeline Internals

| Constant | Value | Purpose |
|----------|-------|---------|
| `PARSE_CHUNK_SIZE` | 256 | Files parsed in parallel per rayon chunk |
| `PIPELINE_BUFFER_DEPTH` | 2 | `sync_channel` depth — limits in-flight chunks |

- Files are read once: SHA-256, gz decompression (if needed), and JSON parsing all share the same byte buffer.
- `ingested_files` is loaded into a `HashMap` at startup (one `SELECT`) for O(1) dedup checks.
- `duckdb::Appender` is used for all inserts — never individual `INSERT` statements.
- GeoIP lookup is done per-event during the insert loop; private/reserved IPs are stored as `NULL`.

## TDD Test Coverage

Tests live in `#[cfg(test)] mod tests` within the same source file.
Integration and CLI tests are in `ingester/tests/`.

### parser.rs
- `test_parse_single_cloudtrail_event` — parse a minimal CloudTrail JSON record
- `test_parse_cloudtrail_records_array` — parse `{"Records": [...]}` with multiple events
- `test_parse_handles_missing_optional_fields` — missing optional fields do not panic
- `test_parse_malformed_json_returns_error` — invalid JSON returns `Err`
- `test_parse_empty_records_array` — `{"Records": []}` → empty vec, not error

### db.rs
- `test_create_cloudtrail_table` — `ensure_table()` creates both tables
- `test_create_table_is_idempotent` — calling twice does not error
- `test_insert_single_event` — insert one event, verify query-back
- `test_insert_batch_events` — insert 100 events, verify row count
- `test_insert_event_with_null_fields` — `None` optional fields insert without error
- `test_ensure_geo_columns_adds_seven_columns` — 7 geo columns added via `ALTER TABLE`
- `test_ensure_geo_columns_is_idempotent` — calling twice does not error
- `test_insert_events_with_geo_populates_columns` — GeoInfo provided → correct DB values
- `test_insert_events_without_geo_columns_are_null` — no enricher → geo columns NULL

### ingest.rs
- `test_ingest_single_json_file` — ingest `.json` → correct row count
- `test_ingest_single_gz_file` — ingest `.json.gz` → correct row count
- `test_ingest_directory` — ingest directory with multiple files → total row count
- `test_ingest_skips_non_json_files` — non-JSON files silently skipped
- `test_ingest_duplicate_prevention` — ingesting same file twice does not duplicate records
- `test_ingest_returns_stats` — returns `IngestStats { files_processed, records_inserted, errors, elapsed_secs }`

### geoip.rs
- `test_classify_rfc1918_*` — RFC-1918 addresses → `GeoInfo` with `None` fields (private)
- `test_classify_loopback_*` — loopback addresses handled gracefully
- `test_classify_public_returns_none` — public IPs → `None` without mmdb lookup
- `test_enricher_private_ip_skips_mmdb_access` — private IPs bypass mmdb lookup
- `test_enricher_none_returns_all_none` — no enricher → all geo fields `None`

### enrich.rs
- `test_enrich_public_ip_writes_geo_data` — public IP rows get geo data via UPDATE
- `test_enrich_skips_null_source_ip` — NULL source_ip rows are skipped
- `test_enrich_is_idempotent` — already-enriched rows (`geo_country_code IS NOT NULL`) are not overwritten
- `test_enrich_returns_stats` — returns `EnrichStats { enriched_count, skipped_count, elapsed_secs }`

### date_filter.rs / path_filter.rs
- `test_date_filter_*` — various from/to boundary cases; no-date files always match
- `test_path_filter_*` — include/exclude glob matching; `*` crosses path separators

### field_filter.rs
- `test_empty_filter_returns_input_unchanged` — `FieldFilter::default()` is a no-op; zero allocations
- `test_default_strip_removes_pagination_keys` — `maxResults`, `nextToken`, etc. are removed
- `test_strip_is_recursive_into_nested_objects` — nested JSON objects are also stripped
- `test_strip_descends_into_arrays` — arrays are traversed and objects inside are stripped
- `test_strip_is_case_sensitive_with_both_variants` — only listed casing variants are removed; unlisted casing (`MAXRESULTS`) is preserved
- `test_invalid_json_is_returned_unchanged` — non-JSON strings are passed through verbatim
- `test_non_object_top_level_json_is_returned_unchanged` — top-level `null` / string → no-op
- `test_custom_keys_are_stripped` — `FieldFilter::new([...])` strips arbitrary keys

### config_parser.rs / config_db.rs / config_import.rs
- `test_parse_config_snapshot_*` — parse Config snapshot JSON into typed structs
- `test_config_db_*` — create Config tables, insert snapshots/resources/edges
- `test_config_import_*` — walk → SHA dedup → parse → insert pipeline

### CLI (tests/cli_test.rs)
- `test_cli_ingest_command` — `ingester ingest --path <dir>` exits 0
- `test_cli_missing_path_shows_error` — missing `--path` produces usage error
- `test_cli_enrich_requires_geoip_arg` — `enrich` without GeoIP arg exits non-zero

### CLI (tests/config_import_test.rs)
- `test_cli_config_import_succeeds_and_prints_summary` — `ingester config-import --path <file>` exits 0 and prints summary (CLI-CI-01)
- `test_cli_config_import_missing_path_shows_error` — missing `--path` produces usage error (CLI-CI-02)

## Testing Patterns

### Temporary DuckDB for Tests

```rust
#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;
    use duckdb::Connection;

    fn temp_db() -> (Connection, NamedTempFile) {
        let tmp = NamedTempFile::new().unwrap();
        let conn = Connection::open(tmp.path()).unwrap();
        (conn, tmp)
    }
}
```

## Error Handling

- Use `anyhow::Result` as the return type for all public functions.
- Use `.with_context(|| format!("Failed to parse {}", path.display()))` for context.
- In `main.rs`, catch at top level and print with `eprintln!("error: {e:#}")`, then `process::exit(1)`.
