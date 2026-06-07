/**
 * Front-end display configuration for the Config Viz graph.
 */

/**
 * Service namespaces whose top-level service-group node is expanded by default.
 * All other service groups start collapsed so large services (IAM, Lambda, …)
 * do not overwhelm the initial view.
 *
 * "EC2" covers VPC / Subnet / NetworkACL / Instance resources.
 * "S3"  covers S3 Bucket and sub-resources.
 */
export const AUTO_EXPAND_SERVICES: ReadonlySet<string> = new Set(["EC2", "S3"]);

/**
 * Maximum number of direct children rendered per non-priority service group
 * when the group is expanded.  Prevents very large service groups (e.g. IAM
 * with hundreds of roles) from flooding the canvas and causing layout
 * overflow.
 *
 * Priority service groups (AUTO_EXPAND_SERVICES) are never truncated.
 */
export const MAX_CHILDREN_PER_SERVICE = 30;

