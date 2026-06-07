/**
 * Service-level color palette shared between group node borders, leaf-node
 * SVG badges, and the MiniMap.  A single source of truth so every surface
 * that colours an AWS service uses the same hex value.
 *
 * Services are organised into logical AWS categories.  Within a category the
 * hue is shared; future refinements can differentiate by lightness/saturation
 * while keeping the category association obvious.
 */

// ---------------------------------------------------------------------------
// Category → service name mapping (source of truth for legend rendering)
// ---------------------------------------------------------------------------

export const SERVICE_CATEGORIES: Record<string, string[]> = {
  Compute:     ["EC2", "Lambda", "ECS", "ECR", "EKS", "AutoScaling", "CloudFront"],
  Storage:     ["S3", "Backup"],
  Database:    ["RDS", "DynamoDB", "Cassandra", "Athena"],
  Network:     ["ElasticLoadBalancing", "ElasticLoadBalancingV2"],
  Security:    ["IAM", "KMS", "SecretsManager", "WAFv2"],
  Integration: ["SNS", "SQS", "Events", "Scheduler", "StepFunctions"],
  Management:  ["CloudFormation", "CloudTrail", "Config", "Logs"],
  Developer:   ["CodeDeploy", "Glue", "AppConfig", "DataZone"],
};

// ---------------------------------------------------------------------------
// Category hues (one hex per category)
// ---------------------------------------------------------------------------

const CATEGORY_COLOR: Record<string, string> = {
  Compute:     "#FF9900",  // AWS orange
  Storage:     "#3F8624",  // green
  Database:    "#527FFF",  // blue
  Network:     "#8C4FFF",  // purple
  Security:    "#DD344C",  // red
  Integration: "#FF4F8B",  // pink
  Management:  "#E7157B",  // magenta
  Developer:   "#EE3524",  // coral
};

// ---------------------------------------------------------------------------
// Flat service → colour lookup (derived from the two tables above)
// ---------------------------------------------------------------------------

const SERVICE_PRIMARY: Record<string, string> = {};

for (const [category, services] of Object.entries(SERVICE_CATEGORIES)) {
  const color = CATEGORY_COLOR[category] ?? "#6B7280";
  for (const svc of services) {
    SERVICE_PRIMARY[svc] = color;
  }
}

/** Neutral color used when a service has no mapped palette entry. */
export const NEUTRAL_COLOR = "#6B7280";

/** MiniMap color for plain leaf (non-group) nodes — lighter than service tones. */
export const MINIMAP_LEAF_COLOR = "#D1D5DB";

/**
 * Extract the service namespace from a resource type string.
 *   "AWS::EC2::Instance"  → "EC2"
 *   "__service__IAM"      → "IAM"
 *   ""                    → ""
 */
function _extractService(resourceType: string): string {
  if (!resourceType) return "";
  if (resourceType.startsWith("__service__")) {
    return resourceType.slice("__service__".length);
  }
  const parts = resourceType.split("::");
  return parts.length >= 2 ? parts[1] : "";
}

/**
 * Return the primary hex colour associated with a given AWS resource type.
 * Falls back to {@link NEUTRAL_COLOR} when the service is unknown.
 */
export function serviceColorOf(resourceType: string): string {
  const svc = _extractService(resourceType);
  return SERVICE_PRIMARY[svc] ?? NEUTRAL_COLOR;
}

/**
 * Expose the flat lookup so icon generators can access it without re-deriving.
 * Keys are service namespaces ("EC2", "IAM", …); values are hex colours.
 */
export { SERVICE_PRIMARY as SERVICE_PALETTE };
