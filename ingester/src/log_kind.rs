//! Classify files found under a verbatim S3 copy of `AWSLogs/`.
//!
//! A whole-bucket copy holds more than CloudTrail: digests, Insights, AWS
//! Config history, VPC Flow Logs, ELB access logs. Each file is routed to the
//! pipeline that understands it, or counted as skipped, so nothing that is not
//! CloudTrail ends up reported as a CloudTrail parse error.
//!
//! Classification is by path only. AWS names every delivered object
//! `{account}_{service}_{region}_…`, so the service token in the file name is
//! the primary signal; a service directory segment is the fallback for renamed
//! files, and a bare extension check keeps hand-made `.json` fixtures working.

use std::path::Path;

/// Why a file was not ingested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SkipKind {
    /// VPC Flow Logs delivered as Parquet — out of scope.
    VpcFlowParquet,
    /// CloudTrail digest files (integrity hashes, not events).
    CloudTrailDigest,
    /// CloudTrail Insights events.
    CloudTrailInsight,
    /// AWS Config history / snapshot files.
    Config,
    /// Anything else (ELB logs, READMEs, unknown services).
    Other,
}

impl SkipKind {
    /// Human-readable label used in the CLI summary.
    pub fn label(self) -> &'static str {
        match self {
            SkipKind::VpcFlowParquet => "Parquet",
            SkipKind::CloudTrailDigest => "CloudTrail-Digest",
            SkipKind::CloudTrailInsight => "CloudTrail-Insight",
            SkipKind::Config => "Config",
            SkipKind::Other => "other",
        }
    }
}

/// The pipeline a file belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    /// A CloudTrail event file (`.json` / `.json.gz`).
    CloudTrail,
    /// A VPC Flow Logs plain-text file (`.log.gz` / `.log`).
    VpcFlowText,
    /// Not ingested; counted under the given kind.
    Skipped(SkipKind),
}

/// Classify `path` by file name, then by service directory, then by extension.
pub fn classify(path: &Path) -> LogKind {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();

    let service = service_from_file_name(name).or_else(|| service_from_directories(path));
    match service {
        Some(service) => classify_service(service, name),
        None if is_json(name) => LogKind::CloudTrail,
        None => LogKind::Skipped(SkipKind::Other),
    }
}

/// The `{service}` token of an AWS-delivered `{account}_{service}_{region}_…` name.
fn service_from_file_name(name: &str) -> Option<&str> {
    let mut tokens = name.split('_');
    let account = tokens.next()?;
    let service = tokens.next()?;
    let is_account = account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit());
    is_account.then_some(service)
}

/// The service directory of `AWSLogs/…/{service}/…`, plain or Hive-style.
fn service_from_directories(path: &Path) -> Option<&str> {
    path.parent()?
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .map(|c| c.strip_prefix("aws-service=").unwrap_or(c))
        .find(|c| KNOWN_SERVICES.contains(c))
}

/// Service names AWS writes into `AWSLogs/` paths that matter for routing.
const KNOWN_SERVICES: &[&str] = &[
    "CloudTrail",
    "CloudTrail-Digest",
    "CloudTrail-Insight",
    "Config",
    "vpcflowlogs",
    "elasticloadbalancing",
];

fn classify_service(service: &str, name: &str) -> LogKind {
    match service {
        "CloudTrail" if is_json(name) => LogKind::CloudTrail,
        "CloudTrail-Digest" => LogKind::Skipped(SkipKind::CloudTrailDigest),
        "CloudTrail-Insight" => LogKind::Skipped(SkipKind::CloudTrailInsight),
        "Config" => LogKind::Skipped(SkipKind::Config),
        "vpcflowlogs" if name.ends_with(".log.gz") || name.ends_with(".log") => {
            LogKind::VpcFlowText
        }
        "vpcflowlogs" if name.ends_with(".parquet") => LogKind::Skipped(SkipKind::VpcFlowParquet),
        _ => LogKind::Skipped(SkipKind::Other),
    }
}

fn is_json(name: &str) -> bool {
    name.ends_with(".json") || name.ends_with(".json.gz")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn kind(p: &str) -> LogKind {
        classify(&PathBuf::from(p))
    }

    const FLOW_NAME: &str =
        "123456789012_vpcflowlogs_us-east-1_fl-1234abcd_20240115T1620Z_fe123456.log.gz";

    // LK-01: a CloudTrail object in the default layout.
    #[test]
    fn test_cloudtrail_default_layout() {
        assert_eq!(
            kind(
                "AWSLogs/123456789012/CloudTrail/us-east-1/2024/01/15/123456789012_CloudTrail_us-east-1_20240115T0000Z_abc.json.gz"
            ),
            LogKind::CloudTrail
        );
    }

    // LK-02: a Flow Logs object in the default layout.
    #[test]
    fn test_vpc_flow_default_layout() {
        assert_eq!(
            kind(&format!(
                "AWSLogs/123456789012/vpcflowlogs/us-east-1/2024/01/15/{FLOW_NAME}"
            )),
            LogKind::VpcFlowText
        );
    }

    // LK-03: a Flow Logs object under Hive-compatible prefixes.
    #[test]
    fn test_vpc_flow_hive_layout() {
        assert_eq!(
            kind(&format!(
                "AWSLogs/aws-account-id=123456789012/aws-service=vpcflowlogs/aws-region=us-east-1/year=2024/month=01/day=15/{FLOW_NAME}"
            )),
            LogKind::VpcFlowText
        );
    }

    // LK-04: an Organization trail adds one directory level; the result is the same.
    #[test]
    fn test_organization_trail_layout() {
        assert_eq!(
            kind(
                "AWSLogs/o-abc123/123456789012/CloudTrail/us-east-1/2024/01/15/123456789012_CloudTrail_us-east-1_20240115T0000Z_abc.json.gz"
            ),
            LogKind::CloudTrail
        );
        assert_eq!(
            kind(&format!(
                "AWSLogs/o-abc123/123456789012/vpcflowlogs/us-east-1/2024/01/15/{FLOW_NAME}"
            )),
            LogKind::VpcFlowText
        );
    }

    // LK-05: Parquet flow logs are skipped and counted as such.
    #[test]
    fn test_vpc_flow_parquet_is_skipped() {
        assert_eq!(
            kind(
                "AWSLogs/123456789012/vpcflowlogs/us-east-1/2024/01/15/123456789012_vpcflowlogs_us-east-1_fl-1234abcd_20240115T1620Z_fe123456.log.parquet"
            ),
            LogKind::Skipped(SkipKind::VpcFlowParquet)
        );
    }

    // LK-06: digest files are JSON but not events.
    #[test]
    fn test_cloudtrail_digest_is_skipped() {
        assert_eq!(
            kind(
                "AWSLogs/123456789012/CloudTrail-Digest/us-east-1/2024/01/15/123456789012_CloudTrail-Digest_us-east-1_trail_us-east-1_20240115T000000Z.json.gz"
            ),
            LogKind::Skipped(SkipKind::CloudTrailDigest)
        );
    }

    // LK-07: Insights files are skipped.
    #[test]
    fn test_cloudtrail_insight_is_skipped() {
        assert_eq!(
            kind(
                "AWSLogs/123456789012/CloudTrail-Insight/us-east-1/2024/01/15/123456789012_CloudTrail-Insight_us-east-1_20240115T0000Z_abc.json.gz"
            ),
            LogKind::Skipped(SkipKind::CloudTrailInsight)
        );
    }

    // LK-08: AWS Config history in the same bucket is skipped.
    #[test]
    fn test_config_history_is_skipped() {
        assert_eq!(
            kind(
                "AWSLogs/123456789012/Config/us-east-1/2024/1/15/ConfigHistory/123456789012_Config_us-east-1_ConfigHistory_AWS::EC2::Instance_20240115T000000Z_20240115T060000Z_1.json.gz"
            ),
            LogKind::Skipped(SkipKind::Config)
        );
    }

    // LK-09: ELB logs share the `.log.gz` extension and must not be mistaken for flow logs.
    #[test]
    fn test_elb_log_is_not_a_flow_log() {
        assert_eq!(
            kind(
                "AWSLogs/123456789012/elasticloadbalancing/us-east-1/2024/01/15/123456789012_elasticloadbalancing_us-east-1_app.my-lb.abc_20240115T0000Z_10.0.0.1_xyz.log.gz"
            ),
            LogKind::Skipped(SkipKind::Other)
        );
    }

    // LK-10: a renamed flow log is still recognised by its service directory.
    #[test]
    fn test_flow_log_recognised_by_directory_when_renamed() {
        assert_eq!(
            kind("AWSLogs/123456789012/vpcflowlogs/us-east-1/2024/01/15/renamed.log.gz"),
            LogKind::VpcFlowText
        );
    }

    // LK-11: hand-made JSON with no service hint stays CloudTrail (backward compatibility).
    #[test]
    fn test_plain_json_without_hint_is_cloudtrail() {
        assert_eq!(kind("/tmp/fixtures/event.json"), LogKind::CloudTrail);
        assert_eq!(kind("/tmp/fixtures/event.json.gz"), LogKind::CloudTrail);
    }

    // LK-12: anything else is skipped as Other.
    #[test]
    fn test_unknown_file_is_other() {
        assert_eq!(
            kind("/tmp/fixtures/README.txt"),
            LogKind::Skipped(SkipKind::Other)
        );
        assert_eq!(
            kind("/tmp/fixtures/data.log.gz"),
            LogKind::Skipped(SkipKind::Other)
        );
    }

    // LK-13: a user directory named like a service does not override a CloudTrail file name.
    #[test]
    fn test_file_name_wins_over_directory() {
        assert_eq!(
            kind("/home/me/Config/123456789012_CloudTrail_us-east-1_20240115T0000Z_abc.json.gz"),
            LogKind::CloudTrail
        );
    }
}
