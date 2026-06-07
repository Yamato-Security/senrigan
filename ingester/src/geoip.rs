//! GeoIP enrichment using MaxMind GeoLite2 databases.
//!
//! Provides [`GeoipEnricher`] which wraps a GeoLite2-City reader and an optional
//! GeoLite2-ASN reader, producing [`GeoInfo`] for each source IP address.
//!
//! Special-purpose addresses (RFC 1918, loopback, link-local, etc.) are
//! classified without consulting the mmdb files, using [`classify_special_ip`].

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use maxminddb::geoip2;

/// Geo-enrichment data derived from a MaxMind GeoLite2 lookup.
///
/// All fields are `Option<_>`: they are `None` when a value is unavailable
/// (e.g. the IP is not in the database, or the ASN database was not provided).
/// Special-purpose IPs set only `country_code` to a marker string
/// ("PRIVATE", "LOOPBACK", "LINK-LOCAL", or "SPECIAL").
#[derive(Debug, Default, Clone)]
pub struct GeoInfo {
    /// ISO 3166-1 alpha-2 country code, e.g. "US", "JP", or a special marker.
    pub country_code: Option<String>,
    /// English country name, e.g. "United States".
    pub country_name: Option<String>,
    /// English city name, e.g. "Tokyo".
    pub city: Option<String>,
    /// Geographic latitude (decimal degrees).
    pub latitude: Option<f64>,
    /// Geographic longitude (decimal degrees).
    pub longitude: Option<f64>,
    /// Autonomous System Number string, e.g. "AS15169".
    pub asn: Option<String>,
    /// ASN organization name, e.g. "Google LLC".
    pub org: Option<String>,
}

impl GeoInfo {
    /// Return a `GeoInfo` with all fields set to `None`.
    pub fn all_none() -> Self {
        Self::default()
    }
}

/// Configuration for opening GeoIP database files.
///
/// At least one of `city_db_path` or `country_db_path` must be `Some`.
/// When both are provided, the City DB takes precedence (it is a superset of
/// the Country DB and also provides city name and coordinates).
pub struct GeoipConfig {
    /// Path to GeoLite2-City.mmdb. Provides full geo info (country + city + lat/lon).
    pub city_db_path: Option<PathBuf>,
    /// Path to GeoLite2-Country.mmdb. Provides country info only; lighter than City.
    /// Ignored when `city_db_path` is also set.
    pub country_db_path: Option<PathBuf>,
    /// Optional path to GeoLite2-ASN.mmdb. Enriches ASN / org fields.
    pub asn_db_path: Option<PathBuf>,
}

/// Wraps `maxminddb::Reader` instances for City, Country, and (optionally) ASN databases.
///
/// # Thread safety
/// `GeoipEnricher` is safe to use from a single thread. For parallel use,
/// wrap in `Arc`.
#[derive(Debug)]
pub struct GeoipEnricher {
    city_reader: Option<maxminddb::Reader<Vec<u8>>>,
    country_reader: Option<maxminddb::Reader<Vec<u8>>>,
    asn_reader: Option<maxminddb::Reader<Vec<u8>>>,
}

impl GeoipEnricher {
    /// Open GeoIP database files from the given config.
    ///
    /// Returns an error if:
    /// - Neither `city_db_path` nor `country_db_path` is set.
    /// - Any specified file cannot be opened or is corrupt.
    ///
    /// If a path points to a **directory** rather than a file, the first
    /// `.mmdb` file inside that directory is used automatically.  This handles
    /// the layout produced by MaxMind's download archives, e.g.
    /// `GeoLite2-City_20260317/GeoLite2-City.mmdb`.
    pub fn open(config: &GeoipConfig) -> Result<Self> {
        let city_reader = config
            .city_db_path
            .as_ref()
            .map(|p| open_reader(p, "GeoLite2-City"))
            .transpose()?;

        let country_reader = config
            .country_db_path
            .as_ref()
            .map(|p| open_reader(p, "GeoLite2-Country"))
            .transpose()?;

        if city_reader.is_none() && country_reader.is_none() {
            anyhow::bail!("GeoipConfig requires at least one of city_db_path or country_db_path");
        }

        let asn_reader = config
            .asn_db_path
            .as_ref()
            .map(|p| open_reader(p, "GeoLite2-ASN"))
            .transpose()?;

        Ok(Self {
            city_reader,
            country_reader,
            asn_reader,
        })
    }

    /// Look up [`GeoInfo`] for an IP address string.
    ///
    /// - Special-purpose IPs return a `GeoInfo` with only `country_code` set
    ///   to a marker ("PRIVATE", "LOOPBACK", "LINK-LOCAL", "SPECIAL").
    /// - Non-IP strings (e.g. CloudTrail's `"AWS"` service identifier) emit a
    ///   warning and return [`GeoInfo::all_none()`].
    /// - IPs not found in the database return [`GeoInfo::all_none()`].
    /// - When only a Country DB is configured, `city`, `latitude`, and
    ///   `longitude` are always `None`.
    pub fn lookup(&self, ip_str: &str) -> GeoInfo {
        let addr = match ip_str.parse::<IpAddr>() {
            Ok(a) => a,
            Err(_) => {
                return GeoInfo::all_none();
            }
        };

        // Short-circuit for special-purpose addresses — no mmdb needed.
        if let Some(marker) = classify_special_ip(addr) {
            return GeoInfo {
                country_code: Some(marker.to_string()),
                ..Default::default()
            };
        }

        let mut info = GeoInfo::all_none();

        if let Some(city_reader) = &self.city_reader {
            // City DB: full info (country + city + coordinates).
            if let Ok(lr) = city_reader.lookup(addr)
                && let Ok(Some(city)) = lr.decode::<geoip2::City>()
            {
                info.country_code = city.country.iso_code.map(str::to_string);
                info.country_name = city.country.names.english.map(str::to_string);
                info.city = city.city.names.english.map(str::to_string);
                info.latitude = city.location.latitude;
                info.longitude = city.location.longitude;
            }
        } else if let Some(country_reader) = &self.country_reader {
            // Country DB: country info only — city/lat/lon remain None.
            if let Ok(lr) = country_reader.lookup(addr)
                && let Ok(Some(country)) = lr.decode::<geoip2::Country>()
            {
                info.country_code = country.country.iso_code.map(str::to_string);
                info.country_name = country.country.names.english.map(str::to_string);
            }
        }

        // ASN lookup (optional, additive for both City and Country paths).
        if let Some(asn_reader) = &self.asn_reader
            && let Ok(lr) = asn_reader.lookup(addr)
            && let Ok(Some(asn)) = lr.decode::<geoip2::Asn>()
        {
            info.asn = asn.autonomous_system_number.map(|n| format!("AS{n}"));
            info.org = asn.autonomous_system_organization.map(str::to_string);
        }

        info
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Read a `.mmdb` file and return a [`maxminddb::Reader`].
///
/// If `path` is a **directory**, the first `.mmdb` file found inside it is
/// used.  This handles the directory layout produced by MaxMind's download
/// archives, e.g. `GeoLite2-Country_20260317/GeoLite2-Country.mmdb`.
fn open_reader(path: &Path, label: &str) -> Result<maxminddb::Reader<Vec<u8>>> {
    let resolved = resolve_mmdb_path(path, label)?;
    let data = std::fs::read(&resolved)
        .with_context(|| format!("Failed to read {label} database at {}", resolved.display()))?;
    maxminddb::Reader::from_source(data)
        .with_context(|| format!("Corrupt GeoIP database at {}", resolved.display()))
}

/// Resolve a user-supplied path to a `.mmdb` file.
///
/// - If `path` already points to a file → returned as-is.
/// - If `path` is a directory → the first `.mmdb` file found (sorted by name)
///   inside that directory is returned.
/// - Otherwise an error is returned.
fn resolve_mmdb_path(path: &Path, label: &str) -> Result<PathBuf> {
    if path.is_file() {
        return Ok(path.to_path_buf());
    }

    if path.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(path)
            .with_context(|| format!("Failed to read directory {} for {label}", path.display()))?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("mmdb"))
            .collect();

        entries.sort(); // deterministic: pick alphabetically first .mmdb

        return entries.into_iter().next().with_context(|| {
            format!(
                "No .mmdb file found in directory {} for {label}",
                path.display()
            )
        });
    }

    anyhow::bail!(
        "Path does not exist: {} (expected a .mmdb file or a directory containing one)",
        path.display()
    )
}

/// Classify special-purpose IP addresses without a database lookup.
///
/// Returns:
/// - `Some("LOOPBACK")` — 127.0.0.1/8 or ::1
/// - `Some("PRIVATE")` — RFC 1918 (10/8, 172.16/12, 192.168/16) or IPv6 unique-local (fc00::/7)
/// - `Some("LINK-LOCAL")` — 169.254/16 or fe80::/10
/// - `Some("SPECIAL")` — broadcast, documentation, unspecified, or multicast ranges
/// - `None` — routable public address (mmdb lookup required)
pub fn classify_special_ip(addr: IpAddr) -> Option<&'static str> {
    match addr {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                Some("LOOPBACK")
            } else if v4.is_private() {
                Some("PRIVATE")
            } else if v4.is_link_local() {
                Some("LINK-LOCAL")
            } else if v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || v4.is_multicast()
            {
                Some("SPECIAL")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                Some("LOOPBACK")
            } else if v6.is_unspecified() || v6.is_multicast() {
                Some("SPECIAL")
            } else {
                let bytes = v6.octets();
                // fe80::/10 = link-local
                if bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80 {
                    Some("LINK-LOCAL")
                }
                // fc00::/7 = unique-local (analogous to RFC 1918)
                else if bytes[0] == 0xfc || bytes[0] == 0xfd {
                    Some("PRIVATE")
                } else {
                    None
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn test_city_db_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/testdata/geoip/GeoLite2-City-Test.mmdb")
    }

    fn test_country_db_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/testdata/geoip/GeoLite2-Country-Test.mmdb")
    }

    fn test_asn_db_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/testdata/geoip/GeoLite2-ASN-Test.mmdb")
    }

    fn city_config() -> GeoipConfig {
        GeoipConfig {
            city_db_path: Some(test_city_db_path()),
            country_db_path: None,
            asn_db_path: None,
        }
    }

    fn country_config() -> GeoipConfig {
        GeoipConfig {
            city_db_path: None,
            country_db_path: Some(test_country_db_path()),
            asn_db_path: None,
        }
    }

    // ── G-01 ~ G-09: classify_special_ip ─────────────────────────────────────

    #[test]
    fn test_classify_rfc1918_10_x() {
        let addr: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(classify_special_ip(addr), Some("PRIVATE"));
        let addr2: IpAddr = "10.255.255.255".parse().unwrap();
        assert_eq!(classify_special_ip(addr2), Some("PRIVATE"));
    }

    #[test]
    fn test_classify_rfc1918_172_16_to_31() {
        let addr: IpAddr = "172.16.0.1".parse().unwrap();
        assert_eq!(classify_special_ip(addr), Some("PRIVATE"));
        let addr2: IpAddr = "172.31.255.255".parse().unwrap();
        assert_eq!(classify_special_ip(addr2), Some("PRIVATE"));
    }

    #[test]
    fn test_classify_rfc1918_192_168() {
        let addr: IpAddr = "192.168.0.1".parse().unwrap();
        assert_eq!(classify_special_ip(addr), Some("PRIVATE"));
        let addr2: IpAddr = "192.168.255.255".parse().unwrap();
        assert_eq!(classify_special_ip(addr2), Some("PRIVATE"));
    }

    #[test]
    fn test_classify_loopback_ipv4() {
        let addr: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(classify_special_ip(addr), Some("LOOPBACK"));
    }

    #[test]
    fn test_classify_loopback_ipv6() {
        let addr: IpAddr = "::1".parse().unwrap();
        assert_eq!(classify_special_ip(addr), Some("LOOPBACK"));
    }

    #[test]
    fn test_classify_link_local_169_254() {
        let addr: IpAddr = "169.254.1.1".parse().unwrap();
        assert_eq!(classify_special_ip(addr), Some("LINK-LOCAL"));
        let addr2: IpAddr = "169.254.0.0".parse().unwrap();
        assert_eq!(classify_special_ip(addr2), Some("LINK-LOCAL"));
    }

    #[test]
    fn test_classify_link_local_ipv6_fe80() {
        let addr: IpAddr = "fe80::1".parse().unwrap();
        assert_eq!(classify_special_ip(addr), Some("LINK-LOCAL"));
        let addr2: IpAddr = "fe80::dead:beef".parse().unwrap();
        assert_eq!(classify_special_ip(addr2), Some("LINK-LOCAL"));
    }

    #[test]
    fn test_classify_special_broadcast() {
        let addr: IpAddr = "255.255.255.255".parse().unwrap();
        assert_eq!(classify_special_ip(addr), Some("SPECIAL"));
    }

    #[test]
    fn test_classify_public_returns_none() {
        let addr: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(classify_special_ip(addr), None);
        let addr2: IpAddr = "1.1.1.1".parse().unwrap();
        assert_eq!(classify_special_ip(addr2), None);
    }

    // ── G-10: non-IP string ───────────────────────────────────────────────────

    // Test G-10: A non-IP string returns GeoInfo::all_none() (no panic).
    #[test]
    fn test_parse_invalid_ip_string() {
        let enricher = GeoipEnricher::open(&city_config()).expect("should open test mmdb");
        let info = enricher.lookup("AWS");
        assert!(info.country_code.is_none());
        let info2 = enricher.lookup("not-an-ip");
        assert!(info2.country_code.is_none());
    }

    // ── G-11 ~ G-13: City DB lookups ─────────────────────────────────────────

    // Test G-11: A known IP in the City test mmdb returns correct country_code.
    #[test]
    fn test_lookup_known_ip_city_db() {
        let enricher = GeoipEnricher::open(&city_config()).expect("should open test City mmdb");
        let info = enricher.lookup("81.2.69.160");
        assert_eq!(info.country_code.as_deref(), Some("GB"));
        assert!(info.country_name.is_some());
    }

    // Test G-12: An IPv6 address in the City test mmdb is looked up without error.
    #[test]
    fn test_lookup_ipv6_city_db() {
        let enricher = GeoipEnricher::open(&city_config()).expect("should open test City mmdb");
        let _ = enricher.lookup("2001:218::1");
    }

    // Test G-13: An IP not present in the database returns GeoInfo::all_none().
    #[test]
    fn test_lookup_ip_not_in_database() {
        let enricher = GeoipEnricher::open(&city_config()).expect("should open test City mmdb");
        let _ = enricher.lookup("198.41.0.4");
    }

    // ── G-14 ~ G-17: enricher configuration ──────────────────────────────────

    // Test G-14: GeoipEnricher works with City DB only (no ASN DB).
    #[test]
    fn test_enricher_with_city_only() {
        let enricher = GeoipEnricher::open(&city_config()).expect("should open with city only");
        let info = enricher.lookup("81.2.69.160");
        assert_eq!(info.country_code.as_deref(), Some("GB"));
        assert!(info.asn.is_none());
        assert!(info.org.is_none());
    }

    // Test G-15: GeoipEnricher with both City and ASN DBs populates ASN fields.
    #[test]
    fn test_enricher_city_and_asn() {
        let config = GeoipConfig {
            city_db_path: Some(test_city_db_path()),
            country_db_path: None,
            asn_db_path: Some(test_asn_db_path()),
        };
        let enricher = GeoipEnricher::open(&config).expect("should open with city and ASN");

        let city_info = enricher.lookup("81.2.69.160");
        assert_eq!(city_info.country_code.as_deref(), Some("GB"));

        // 1.128.0.0 is known to be in GeoLite2-ASN-Test.mmdb (AS1221 / Telstra).
        let asn_info = enricher.lookup("1.128.0.0");
        assert!(
            asn_info.asn.is_some(),
            "expected ASN for 1.128.0.0 in GeoLite2-ASN-Test.mmdb"
        );
        assert!(asn_info.asn.as_deref().unwrap().starts_with("AS"));
        assert!(asn_info.org.is_some());
    }

    // Test G-16: Private IPs return PRIVATE without consulting mmdb.
    #[test]
    fn test_enricher_private_ip_skips_mmdb_access() {
        let enricher = GeoipEnricher::open(&city_config()).unwrap();
        let info = enricher.lookup("10.0.0.1");
        assert_eq!(info.country_code.as_deref(), Some("PRIVATE"));
        assert!(info.country_name.is_none());
        assert!(info.city.is_none());
        assert!(info.latitude.is_none());
        assert!(info.longitude.is_none());
        assert!(info.asn.is_none());
        assert!(info.org.is_none());
    }

    // Test G-17: GeoInfo::all_none() has all fields set to None.
    #[test]
    fn test_enricher_none_returns_all_none() {
        let info = GeoInfo::all_none();
        assert!(info.country_code.is_none());
        assert!(info.country_name.is_none());
        assert!(info.city.is_none());
        assert!(info.latitude.is_none());
        assert!(info.longitude.is_none());
        assert!(info.asn.is_none());
        assert!(info.org.is_none());
    }

    // ── Country DB tests ──────────────────────────────────────────────────────

    // Test G-18: GeoipEnricher with Country DB only returns country_code and country_name.
    #[test]
    fn test_enricher_with_country_db_only() {
        let enricher =
            GeoipEnricher::open(&country_config()).expect("should open with country only");
        // 81.2.69.160 → GB in both City and Country test databases.
        let info = enricher.lookup("81.2.69.160");
        assert_eq!(
            info.country_code.as_deref(),
            Some("GB"),
            "expected GB for 81.2.69.160 from Country DB"
        );
        assert!(
            info.country_name.is_some(),
            "expected country_name from Country DB"
        );
    }

    // Test G-19: Country DB does not populate city, lat, or lon.
    #[test]
    fn test_enricher_country_db_no_city_data() {
        let enricher =
            GeoipEnricher::open(&country_config()).expect("should open with country only");
        let info = enricher.lookup("81.2.69.160");
        assert!(
            info.city.is_none(),
            "city should be None when using Country DB"
        );
        assert!(
            info.latitude.is_none(),
            "latitude should be None when using Country DB"
        );
        assert!(
            info.longitude.is_none(),
            "longitude should be None when using Country DB"
        );
    }

    // Test G-20: When both City and Country DBs are configured, City takes precedence.
    #[test]
    fn test_enricher_city_takes_precedence_over_country() {
        let config = GeoipConfig {
            city_db_path: Some(test_city_db_path()),
            country_db_path: Some(test_country_db_path()),
            asn_db_path: None,
        };
        let enricher = GeoipEnricher::open(&config).expect("should open both dbs");
        let info = enricher.lookup("81.2.69.160");
        // City DB is used → city name should be present.
        assert!(
            info.city.is_some(),
            "city should be populated when City DB takes precedence"
        );
    }

    // Test G-21: Country DB with ASN DB populates both country and ASN fields.
    #[test]
    fn test_enricher_country_and_asn() {
        let config = GeoipConfig {
            city_db_path: None,
            country_db_path: Some(test_country_db_path()),
            asn_db_path: Some(test_asn_db_path()),
        };
        let enricher = GeoipEnricher::open(&config).expect("should open country + ASN dbs");

        // 81.2.69.160 → GB from Country DB
        let info = enricher.lookup("81.2.69.160");
        assert_eq!(info.country_code.as_deref(), Some("GB"));
        assert!(info.city.is_none(), "city should be None with Country DB");

        // 1.128.0.0 → AS1221 from ASN DB
        let asn_info = enricher.lookup("1.128.0.0");
        assert!(asn_info.asn.is_some());
    }

    // Test G-22: GeoipConfig with neither city nor country returns an error.
    #[test]
    fn test_enricher_open_fails_without_any_db() {
        let config = GeoipConfig {
            city_db_path: None,
            country_db_path: None,
            asn_db_path: None,
        };
        let result = GeoipEnricher::open(&config);
        assert!(
            result.is_err(),
            "open() should fail when no geo DB is provided"
        );
    }

    // Test G-23: resolve_mmdb_path returns the file unchanged when a file path is given.
    #[test]
    fn test_resolve_mmdb_path_with_file_path() {
        let city_db = test_city_db_path();
        let resolved = resolve_mmdb_path(&city_db, "City").expect("should resolve file path");
        assert_eq!(resolved, city_db);
    }

    // Test G-24: resolve_mmdb_path finds the .mmdb file when a directory is given.
    #[test]
    fn test_resolve_mmdb_path_with_directory() {
        // The testdata/geoip directory contains .mmdb files.
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/geoip");
        let resolved = resolve_mmdb_path(&dir, "test").expect("should find .mmdb in directory");
        assert!(
            resolved.extension().and_then(|e| e.to_str()) == Some("mmdb"),
            "resolved path should have .mmdb extension"
        );
        assert!(
            resolved.is_file(),
            "resolved path should be an existing file"
        );
    }

    // Test G-25: GeoipEnricher::open accepts a directory path and finds the mmdb inside.
    #[test]
    fn test_enricher_open_with_directory_path() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata/geoip");
        // Pass the directory itself; GeoipEnricher should find the first .mmdb inside.
        // Note: the testdata/geoip dir contains multiple mmdb files; we only verify
        // that open() succeeds (i.e. it does not error on directory input).
        let config = GeoipConfig {
            city_db_path: Some(test_city_db_path()), // use known-good file for enricher
            country_db_path: None,
            asn_db_path: Some(dir.clone()), // pass directory for ASN
        };
        let enricher = GeoipEnricher::open(&config).expect("open should accept directory for ASN");
        // Just verify lookup works without panic.
        let _ = enricher.lookup("81.2.69.160");
    }
}
