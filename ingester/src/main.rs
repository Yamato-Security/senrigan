/// Entry point for the Senrigan ingester CLI.
///
/// Parses CLI arguments and dispatches to the appropriate ingestion command.
/// All output messages and log entries are written in English.
use std::path::PathBuf;
use std::process;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use duckdb::Connection;
use ingester::config_import::{ImportOptions, import_config};
use ingester::date_filter::DateFilter;
use ingester::enrich::enrich_existing;
use ingester::field_filter::FieldFilter;
use ingester::geoip::{GeoipConfig, GeoipEnricher};
use ingester::ingest::{IngestOptions, ingest};
use ingester::path_filter::PathFilter;

/// Read an environment variable, returning `None` for both unset and empty values.
///
/// Docker Compose sets `VAR=${VAR:-}` which produces an empty string when the
/// host variable is unset. We treat `""` the same as absent.
fn env_var_non_empty(key: &str) -> Option<PathBuf> {
    std::env::var(key)
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

/// Resolve the DuckDB database path.
///
/// Resolution order: CLI argument → `DUCKDB_PATH` env var → default path.
fn resolve_db_path(cli_arg: Option<PathBuf>) -> PathBuf {
    cli_arg.unwrap_or_else(|| {
        std::env::var("DUCKDB_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/data/db/threat_hunting.db"))
    })
}

/// Resolve GeoIP database paths.
///
/// For each argument, uses the CLI value when provided; otherwise falls back
/// to the corresponding environment variable via [`env_var_non_empty`].
fn resolve_geoip_paths(
    city: Option<PathBuf>,
    country: Option<PathBuf>,
    asn: Option<PathBuf>,
) -> (Option<PathBuf>, Option<PathBuf>, Option<PathBuf>) {
    (
        city.or_else(|| env_var_non_empty("GEOIP_CITY_PATH")),
        country.or_else(|| env_var_non_empty("GEOIP_COUNTRY_PATH")),
        asn.or_else(|| env_var_non_empty("GEOIP_ASN_PATH")),
    )
}

/// Senrigan ingester — ingest AWS CloudTrail logs into DuckDB.
#[derive(Debug, Parser)]
#[command(name = "ingester", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Ingest CloudTrail log files into DuckDB.
    Ingest {
        /// Path to a file or directory containing CloudTrail log files.
        #[arg(short, long)]
        path: PathBuf,

        /// Path to the DuckDB database file.
        /// Falls back to the DUCKDB_PATH environment variable, then /data/db/threat_hunting.db.
        #[arg(short, long)]
        db: Option<PathBuf>,

        /// Disable progress bar output.
        #[arg(long)]
        no_progress: bool,

        /// Include only files whose path contains a date (yyyy/mm/dd) on or after
        /// this date. Format: YYYYMMDD (e.g. 20240115). CloudTrail stores logs under
        /// date-based directory segments; files with no date in their path are always included.
        #[arg(long, value_name = "YYYYMMDD")]
        from: Option<String>,

        /// Include only files whose path contains a date (yyyy/mm/dd) on or before
        /// this date. Format: YYYYMMDD (e.g. 20240131).
        #[arg(long, value_name = "YYYYMMDD")]
        to: Option<String>,

        /// Include only files whose full path matches at least one of these
        /// comma-separated glob patterns (e.g. `*CloudTrail*,*Config*`).
        /// `*` crosses path-separator boundaries.
        /// When omitted, all files are candidates.
        #[arg(long, value_name = "PATTERNS")]
        include: Option<String>,

        /// Exclude files whose full path matches any of these comma-separated
        /// glob patterns (e.g. `*vpcflowlogs*`).
        /// Evaluated after `--include`; a match here always wins.
        #[arg(long, value_name = "PATTERNS")]
        exclude: Option<String>,

        /// Number of worker threads used for parallel file parsing.
        /// Defaults to the number of logical CPU cores (rayon default).
        /// Set to 1 to disable parallelism, which minimises peak memory usage
        /// at the cost of throughput.
        #[arg(long, value_name = "N")]
        workers: Option<usize>,

        /// Path to GeoLite2-City.mmdb for geo-enrichment of source_ip_address.
        /// Falls back to the GEOIP_CITY_PATH environment variable.
        /// When omitted, geo columns are stored as NULL (unless --geoip-country is set).
        #[arg(long, value_name = "PATH")]
        geoip_city: Option<PathBuf>,

        /// Path to GeoLite2-Country.mmdb (lighter alternative to --geoip-city).
        /// Falls back to the GEOIP_COUNTRY_PATH environment variable.
        /// Provides country_code and country_name only; city/lat/lon will be NULL.
        /// Ignored when --geoip-city is also set.
        #[arg(long, value_name = "PATH")]
        geoip_country: Option<PathBuf>,

        /// Path to GeoLite2-ASN.mmdb for ASN/org enrichment.
        /// Falls back to the GEOIP_ASN_PATH environment variable.
        /// Works with both --geoip-city and --geoip-country.
        #[arg(long, value_name = "PATH")]
        geoip_asn: Option<PathBuf>,

        /// Strip a fixed list of low-signal CloudTrail keys from
        /// `requestParameters` / `responseElements` before they are
        /// written to DuckDB. Categories stripped:
        ///   - pagination/limits: maxResults, maxItems, nextToken,
        ///     marker, pageSize
        ///   - idempotency/dry-run: dryRun, clientToken,
        ///     clientRequestToken
        ///   - opaque ephemeral creds: sessionToken, secretAccessKey
        ///   - AWS catalogue echoes: eventCategoriesMapList,
        ///     reservedNodeOfferings, sslPolicies,
        ///     orderableClusterOptions
        ///   - query-time filter echoes: filterSet, ownersSet
        ///   - redundant transport headers: Host, host
        ///
        /// (PascalCase variants are included where AWS uses them.)
        ///
        /// `raw_event` is never modified, so the full original record
        /// is always recoverable via full-text search on that column.
        /// Intended for producing a leaner DB for security-incident
        /// triage; combine with `--db <path>` to write to a dedicated
        /// database file.
        #[arg(long)]
        strip_fields: bool,

        /// Drop the `raw_event` column entirely (write `NULL`). Step-A
        /// extended columns (user_identity_access_key_id,
        /// session_mfa_authenticated, resources, tls_*, etc.) are still
        /// populated, so investigation queries that target dedicated
        /// columns continue to work — only the unscoped full-text
        /// fallback via `WHERE raw_event LIKE …` is no longer
        /// available. Combined with `--strip-fields`, this produces
        /// the smallest possible DB for high-volume CloudTrail data.
        #[arg(long)]
        strip_raw_event: bool,

        /// Print a per-phase performance breakdown to stderr after ingestion
        /// completes. Shows time spent in file discovery, dedup-map load,
        /// parallel parsing, DuckDB insertion, GeoIP lookups, and batch
        /// marking. Useful for identifying pipeline bottlenecks.
        #[arg(long)]
        perf_log: bool,
    },

    /// Enrich existing cloudtrail_events rows with GeoIP data.
    ///
    /// Back-fills geo columns for a database that was ingested without a
    /// GeoIP enricher.  Only rows where geo_country_code IS NULL are updated.
    Enrich {
        /// Path to the DuckDB database file.
        /// Falls back to the DUCKDB_PATH environment variable, then /data/db/threat_hunting.db.
        #[arg(short, long)]
        db: Option<PathBuf>,

        /// Path to GeoLite2-City.mmdb.
        /// Falls back to the GEOIP_CITY_PATH environment variable.
        #[arg(long, value_name = "PATH")]
        geoip_city: Option<PathBuf>,

        /// Path to GeoLite2-Country.mmdb (lighter alternative to --geoip-city).
        /// Falls back to the GEOIP_COUNTRY_PATH environment variable.
        /// Provides country_code and country_name only; city/lat/lon will be NULL.
        /// Ignored when --geoip-city is also set.
        #[arg(long, value_name = "PATH")]
        geoip_country: Option<PathBuf>,

        /// Path to GeoLite2-ASN.mmdb.
        /// Falls back to the GEOIP_ASN_PATH environment variable.
        #[arg(long, value_name = "PATH")]
        geoip_asn: Option<PathBuf>,
    },

    /// Import AWS Config snapshot JSON files into DuckDB.
    ///
    /// Walks the given path for `.json` files and writes records to the
    /// `config_snapshots`, `config_resources`, and `config_edges` tables.
    /// Already-ingested files (matched by SHA-256) are skipped automatically.
    #[command(name = "config-import")]
    ConfigImport {
        /// Path to a file or directory containing Config snapshot JSON files.
        #[arg(short, long)]
        path: PathBuf,

        /// Path to the DuckDB database file.
        /// Falls back to the DUCKDB_PATH environment variable, then /data/db/threat_hunting.db.
        #[arg(short, long)]
        db: Option<PathBuf>,

        /// Disable progress bar output.
        #[arg(long)]
        no_progress: bool,
    },
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Ingest {
            path,
            db,
            no_progress,
            from,
            to,
            include,
            exclude,
            workers,
            geoip_city,
            geoip_country,
            geoip_asn,
            strip_fields,
            strip_raw_event,
            perf_log,
        } => {
            // Optionally cap the rayon thread pool before any parallel work.
            if let Some(n) = workers {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(n)
                    .build_global()
                    .ok();
            }

            let date_filter = DateFilter::from_strs(from.as_deref(), to.as_deref())
                .context("Invalid --from / --to argument")?;
            let path_filter = PathFilter::from_strs(include.as_deref(), exclude.as_deref())
                .context("Invalid --include / --exclude argument")?;

            let db_path = resolve_db_path(db);
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open DuckDB at {}", db_path.display()))?;

            let (city_path, country_path, asn_path) =
                resolve_geoip_paths(geoip_city, geoip_country, geoip_asn);

            // `--strip-fields` activates the built-in noise-key list. When
            // absent, the filter stays empty and JSON is written verbatim.
            let field_filter = if strip_fields {
                FieldFilter::default_strip()
            } else {
                FieldFilter::default()
            };

            let enricher: Option<GeoipEnricher> = if city_path.is_some() || country_path.is_some() {
                Some(
                    GeoipEnricher::open(&GeoipConfig {
                        city_db_path: city_path,
                        country_db_path: country_path,
                        asn_db_path: asn_path,
                    })
                    .context("Failed to open GeoIP database")?,
                )
            } else {
                None
            };

            let stats = ingest(
                &path,
                &conn,
                IngestOptions {
                    show_progress: !no_progress,
                    date_filter,
                    path_filter,
                    geoip: enricher.as_ref(),
                    field_filter,
                    strip_raw_event,
                    perf_log,
                },
            )?;

            println!(
                "Ingestion complete: files_processed={} records_inserted={} errors={} elapsed_secs={:.2}",
                stats.files_processed, stats.records_inserted, stats.errors, stats.elapsed_secs,
            );
            if perf_log {
                let pt = &stats.phase_timings;
                eprintln!(
                    "[perf] discovery={:.3}s dedup_load={:.3}s parse={:.3}s recv_wait={:.3}s insert={:.3}s (geoip={:.3}s batch_mark={:.3}s)",
                    pt.discovery_secs,
                    pt.dedup_map_load_secs,
                    pt.parse_active_secs,
                    pt.recv_wait_secs,
                    pt.insert_active_secs,
                    pt.geoip_secs,
                    pt.batch_mark_secs,
                );
                if stats.elapsed_secs > 0.0 {
                    eprintln!(
                        "[perf] throughput: {:.0} events/s (wall clock)",
                        stats.records_inserted as f64 / stats.elapsed_secs,
                    );
                }
            }
            Ok(())
        }

        Commands::Enrich {
            db,
            geoip_city,
            geoip_country,
            geoip_asn,
        } => {
            let db_path = resolve_db_path(db);
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open DuckDB at {}", db_path.display()))?;

            let (city_path, country_path, asn_path) =
                resolve_geoip_paths(geoip_city, geoip_country, geoip_asn);

            if city_path.is_none() && country_path.is_none() {
                anyhow::bail!(
                    "GeoLite2 database required: use --geoip-city, --geoip-country, \
                     or set GEOIP_CITY_PATH / GEOIP_COUNTRY_PATH"
                );
            }

            let enricher = GeoipEnricher::open(&GeoipConfig {
                city_db_path: city_path,
                country_db_path: country_path,
                asn_db_path: asn_path,
            })
            .context("Failed to open GeoIP database")?;

            let stats = enrich_existing(&conn, &enricher).context("Failed to enrich database")?;

            println!(
                "Enrichment complete: enriched_count={} skipped_count={} elapsed_secs={:.2}",
                stats.enriched_count, stats.skipped_count, stats.elapsed_secs,
            );
            Ok(())
        }

        Commands::ConfigImport {
            path,
            db,
            no_progress,
        } => {
            let db_path = resolve_db_path(db);
            let conn = Connection::open(&db_path)
                .with_context(|| format!("Failed to open DuckDB at {}", db_path.display()))?;

            let stats = import_config(
                &path,
                &conn,
                ImportOptions {
                    show_progress: !no_progress,
                },
            )
            .context("Config import failed")?;

            println!(
                "Config import complete: files_processed={} files_skipped={} \
                 resources_inserted={} edges_inserted={} errors={} elapsed_secs={:.2}",
                stats.files_processed,
                stats.files_skipped,
                stats.resources_inserted,
                stats.edges_inserted,
                stats.errors,
                stats.elapsed_secs,
            );
            Ok(())
        }
    }
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e:#}");
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test M-01: resolve_db_path returns the CLI argument when provided.
    #[test]
    fn test_resolve_db_path_returns_cli_arg() {
        let path = PathBuf::from("/custom/path.db");
        assert_eq!(resolve_db_path(Some(path.clone())), path);
    }

    // Test M-02: resolve_db_path returns the default path when None is passed
    // and DUCKDB_PATH is not set.
    #[test]
    fn test_resolve_db_path_returns_default_when_none() {
        // Temporarily unset DUCKDB_PATH for this test.
        // Note: env var mutation is not thread-safe in Rust; this test is
        // acceptable because it runs in isolation and restores state.
        let saved = std::env::var("DUCKDB_PATH").ok();
        // SAFETY: single-threaded test; env mutation is safe here.
        unsafe { std::env::remove_var("DUCKDB_PATH") };

        let result = resolve_db_path(None);
        assert_eq!(result, PathBuf::from("/data/db/threat_hunting.db"));

        // Restore env var.
        if let Some(v) = saved {
            // SAFETY: restoring env var in single-threaded test.
            unsafe { std::env::set_var("DUCKDB_PATH", v) };
        }
    }

    // Test M-03: resolve_geoip_paths returns CLI args when all are provided.
    #[test]
    fn test_resolve_geoip_paths_returns_cli_args() {
        let city = Some(PathBuf::from("/city.mmdb"));
        let country = Some(PathBuf::from("/country.mmdb"));
        let asn = Some(PathBuf::from("/asn.mmdb"));

        let (c, co, a) = resolve_geoip_paths(city.clone(), country.clone(), asn.clone());
        assert_eq!(c, city);
        assert_eq!(co, country);
        assert_eq!(a, asn);
    }

    // Test M-04: resolve_geoip_paths returns None for all when args are None
    // and env vars are not set.
    #[test]
    fn test_resolve_geoip_paths_returns_none_without_env() {
        let saved_city = std::env::var("GEOIP_CITY_PATH").ok();
        let saved_country = std::env::var("GEOIP_COUNTRY_PATH").ok();
        let saved_asn = std::env::var("GEOIP_ASN_PATH").ok();
        // SAFETY: single-threaded test; env mutation is safe here.
        unsafe {
            std::env::remove_var("GEOIP_CITY_PATH");
            std::env::remove_var("GEOIP_COUNTRY_PATH");
            std::env::remove_var("GEOIP_ASN_PATH");
        }

        let (city, country, asn) = resolve_geoip_paths(None, None, None);
        assert!(city.is_none());
        assert!(country.is_none());
        assert!(asn.is_none());

        // SAFETY: restoring env vars in single-threaded test.
        unsafe {
            if let Some(v) = saved_city {
                std::env::set_var("GEOIP_CITY_PATH", v);
            }
            if let Some(v) = saved_country {
                std::env::set_var("GEOIP_COUNTRY_PATH", v);
            }
            if let Some(v) = saved_asn {
                std::env::set_var("GEOIP_ASN_PATH", v);
            }
        }
    }
}
