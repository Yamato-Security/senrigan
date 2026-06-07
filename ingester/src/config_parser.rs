//! AWS Config snapshot JSON → typed structs.
//!
//! Each `configurationItem` in a snapshot file maps to one [`ParsedResource`].
//! Its `relationships` list becomes [`ParsedEdge`] entries in the caller's
//! collection.
//!
//! [`parse_config_snapshot`] is the single public entry point.

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;

// ── Raw deserialization types (mirror the Config snapshot JSON schema) ────────

/// Top-level structure of an AWS Config snapshot file.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawConfigSnapshot {
    pub config_snapshot_id: String,
    pub configuration_items: Vec<RawConfigItem>,
}

/// One `configurationItem` entry.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawConfigItem {
    pub resource_id: String,
    pub resource_type: String,
    pub aws_region: Option<String>,
    pub resource_name: Option<String>,
    pub aws_account_id: Option<String>,
    /// ISO 8601 capture time, e.g. `"2026-01-01T00:00:00.000Z"`.
    pub configuration_item_capture_time: Option<String>,
    /// Sub-object serialised as compact JSON for DuckDB storage.
    pub configuration: Option<Value>,
    /// Tag map serialised as compact JSON, or `None` when the object is empty.
    pub tags: Option<Value>,
    pub relationships: Option<Vec<RawRelationship>>,
}

/// One `relationships` entry within a configuration item.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawRelationship {
    pub resource_id: Option<String>,
    pub resource_type: Option<String>,
    /// Relationship label, e.g. `"Contains "`, `"Is associated with "`.
    pub name: Option<String>,
}

// ── Normalised output types ───────────────────────────────────────────────────

/// Normalised, DuckDB-ready representation of one Config resource.
#[derive(Debug)]
pub struct ParsedResource {
    pub resource_id: String,
    pub resource_type: String,
    pub aws_region: Option<String>,
    pub resource_name: Option<String>,
    pub account_id: Option<String>,
    /// Timestamp normalised to `"YYYY-MM-DD HH:MM:SS.mmm"` for DuckDB TIMESTAMP.
    pub captured_at: Option<String>,
    /// Compact JSON string of the `configuration` sub-object.
    pub configuration: Option<String>,
    /// Compact JSON string of the `tags` map, or `None` when the map is empty.
    pub tags: Option<String>,
}

/// A directed edge derived from a `relationships` entry.
///
/// `source_id` is the `resourceId` of the containing item;
/// `target_id` is the `resourceId` referenced in the relationship.
#[derive(Debug)]
pub struct ParsedEdge {
    pub source_id: String,
    pub target_id: String,
    /// Trimmed relationship label, e.g. `"Is associated with"`.
    pub edge_type: String,
}

/// All data extracted from one Config snapshot file.
#[derive(Debug)]
pub struct ParsedSnapshot {
    pub snapshot_id: String,
    pub resources: Vec<ParsedResource>,
    pub edges: Vec<ParsedEdge>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Parse a raw Config snapshot JSON byte slice.
///
/// Returns a [`ParsedSnapshot`] on success, or an [`anyhow::Error`] when the
/// JSON is malformed or a required top-level field is absent.
///
/// Empty `tags` objects (`{}`) are normalised to `None` to avoid storing
/// meaningless empty-JSON strings.
pub fn parse_config_snapshot(data: &[u8]) -> Result<ParsedSnapshot> {
    let raw: RawConfigSnapshot =
        serde_json::from_slice(data).context("Failed to parse Config snapshot JSON")?;

    let snapshot_id = raw.config_snapshot_id;
    let mut resources = Vec::with_capacity(raw.configuration_items.len());
    let mut edges: Vec<ParsedEdge> = Vec::new();

    for item in raw.configuration_items {
        // --- configuration: serialise Value to compact JSON string ---
        let configuration = item.configuration.as_ref().map(|v| v.to_string());

        // --- tags: empty object → None, otherwise compact JSON ---
        let tags = item.tags.and_then(|v| match &v {
            Value::Object(m) if m.is_empty() => None,
            _ => Some(v.to_string()),
        });

        // --- captured_at: ISO 8601 → "YYYY-MM-DD HH:MM:SS.mmm" ---
        let captured_at = item
            .configuration_item_capture_time
            .as_deref()
            .map(normalise_timestamp);

        // --- relationships → edges (skip entries with no target resourceId) ---
        if let Some(rels) = item.relationships {
            for rel in rels {
                if let Some(target_id) = rel.resource_id
                    && !target_id.is_empty()
                {
                    edges.push(ParsedEdge {
                        source_id: item.resource_id.clone(),
                        target_id,
                        edge_type: rel.name.as_deref().unwrap_or("").trim().to_string(),
                    });
                }
            }
        }

        resources.push(ParsedResource {
            resource_id: item.resource_id,
            resource_type: item.resource_type,
            aws_region: item.aws_region,
            resource_name: item.resource_name,
            account_id: item.aws_account_id,
            captured_at,
            configuration,
            tags,
        });
    }

    Ok(ParsedSnapshot {
        snapshot_id,
        resources,
        edges,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Convert an ISO 8601 timestamp to the `"YYYY-MM-DD HH:MM:SS.mmm"` format
/// that DuckDB's `TIMESTAMP` column accepts.
///
/// Replaces the `T` separator with a space and strips the trailing `Z`.
fn normalise_timestamp(ts: &str) -> String {
    let s = ts.replace('T', " ");
    s.trim_end_matches('Z').to_string()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal two-resource snapshot used across multiple tests.
    const MINI_JSON: &[u8] = br#"{
        "fileVersion": "1.0",
        "configSnapshotId": "snap-001",
        "configurationItems": [
            {
                "relatedEvents": [],
                "relationships": [
                    {
                        "resourceId": "sg-aaaa",
                        "resourceType": "AWS::EC2::SecurityGroup",
                        "name": "Is associated with "
                    }
                ],
                "configuration": {"instanceType": "t3.micro"},
                "supplementaryConfiguration": {},
                "tags": {"Name": "web-server"},
                "configurationItemCaptureTime": "2026-01-01T00:00:00.000Z",
                "awsAccountId": "123456789012",
                "configurationItemStatus": "OK",
                "resourceType": "AWS::EC2::Instance",
                "resourceId":   "i-12345",
                "resourceName": "web-server",
                "awsRegion":    "ap-northeast-1",
                "availabilityZone": "ap-northeast-1a"
            },
            {
                "relatedEvents": [],
                "relationships": [],
                "configuration": {"groupId": "sg-aaaa"},
                "supplementaryConfiguration": {},
                "tags": {},
                "configurationItemCaptureTime": "2026-01-01T00:00:00.000Z",
                "awsAccountId": "123456789012",
                "configurationItemStatus": "OK",
                "resourceType": "AWS::EC2::SecurityGroup",
                "resourceId":   "sg-aaaa",
                "resourceName": "web-sg",
                "awsRegion":    "ap-northeast-1",
                "availabilityZone": "Not Applicable"
            }
        ]
    }"#;

    // Test CP-01: snapshot_id is parsed correctly.
    #[test]
    fn test_parse_snapshot_id() {
        let snap = parse_config_snapshot(MINI_JSON).unwrap();
        assert_eq!(snap.snapshot_id, "snap-001");
    }

    // Test CP-02: correct number of resources is parsed.
    #[test]
    fn test_parse_resource_count() {
        let snap = parse_config_snapshot(MINI_JSON).unwrap();
        assert_eq!(snap.resources.len(), 2);
    }

    // Test CP-03: resource fields (id, type, region, name, account_id) are mapped correctly.
    #[test]
    fn test_parse_resource_fields() {
        let snap = parse_config_snapshot(MINI_JSON).unwrap();
        let r = &snap.resources[0];
        assert_eq!(r.resource_id, "i-12345");
        assert_eq!(r.resource_type, "AWS::EC2::Instance");
        assert_eq!(r.aws_region.as_deref(), Some("ap-northeast-1"));
        assert_eq!(r.resource_name.as_deref(), Some("web-server"));
        assert_eq!(r.account_id.as_deref(), Some("123456789012"));
    }

    // Test CP-04: configuration sub-object is serialised as a compact JSON string.
    #[test]
    fn test_parse_configuration_as_json_string() {
        let snap = parse_config_snapshot(MINI_JSON).unwrap();
        let cfg = snap.resources[0].configuration.as_deref().unwrap();
        assert!(
            cfg.contains("t3.micro"),
            "configuration JSON must contain the instanceType value"
        );
    }

    // Test CP-05: empty tags object is normalised to None.
    #[test]
    fn test_empty_tags_normalised_to_none() {
        let snap = parse_config_snapshot(MINI_JSON).unwrap();
        let sg = snap
            .resources
            .iter()
            .find(|r| r.resource_id == "sg-aaaa")
            .unwrap();
        assert!(
            sg.tags.is_none(),
            "empty tags {{}} must be normalised to None"
        );
    }

    // Test CP-06: non-empty tags are serialised as a JSON string.
    #[test]
    fn test_nonempty_tags_serialised_as_json_string() {
        let snap = parse_config_snapshot(MINI_JSON).unwrap();
        let inst = snap
            .resources
            .iter()
            .find(|r| r.resource_id == "i-12345")
            .unwrap();
        let tags = inst.tags.as_deref().unwrap();
        assert!(
            tags.contains("web-server"),
            "tags must contain the Name value"
        );
    }

    // Test CP-07: relationships are converted to edges with correct fields and trimmed edge_type.
    #[test]
    fn test_parse_relationships_as_edges() {
        let snap = parse_config_snapshot(MINI_JSON).unwrap();
        assert_eq!(snap.edges.len(), 1);
        let e = &snap.edges[0];
        assert_eq!(e.source_id, "i-12345");
        assert_eq!(e.target_id, "sg-aaaa");
        assert_eq!(
            e.edge_type, "Is associated with",
            "trailing whitespace in relationship name must be trimmed"
        );
    }

    // Test CP-08: ISO 8601 timestamp is normalised to DuckDB-compatible format.
    #[test]
    fn test_timestamp_normalised_to_duckdb_format() {
        let snap = parse_config_snapshot(MINI_JSON).unwrap();
        let ts = snap.resources[0].captured_at.as_deref().unwrap();
        assert!(
            ts.starts_with("2026-01-01 00:00:00"),
            "timestamp should be normalised, got: {ts}"
        );
        assert!(
            !ts.contains('T') && !ts.ends_with('Z'),
            "normalised timestamp must not contain 'T' or 'Z'"
        );
    }

    // Test CP-09: malformed JSON returns an error.
    #[test]
    fn test_malformed_json_returns_error() {
        let result = parse_config_snapshot(b"not valid json {{{");
        assert!(result.is_err(), "malformed JSON must return Err");
    }

    // Test CP-10: an item with null relationships produces no edges.
    #[test]
    fn test_item_with_null_relationships_produces_no_edges() {
        let json = br#"{
            "configSnapshotId": "snap-002",
            "configurationItems": [
                {
                    "relationships": null,
                    "configuration": null,
                    "tags": null,
                    "awsAccountId": "123456789012",
                    "resourceType": "AWS::S3::Bucket",
                    "resourceId":   "my-bucket",
                    "awsRegion":    "us-east-1"
                }
            ]
        }"#;
        let snap = parse_config_snapshot(json).unwrap();
        assert!(
            snap.edges.is_empty(),
            "null relationships must produce no edges"
        );
    }
}
