import { SERVICE_PALETTE, NEUTRAL_COLOR } from "./serviceColors";

/** Fallback icon URL for resource types with no specific icon mapping. */
export const FALLBACK_ICON = "/icons/default.png";

/** Generate a colored SVG data URI for a service namespace. */
function _serviceSvgDataUri(service: string): string {
  const color = SERVICE_PALETTE[service] ?? NEUTRAL_COLOR;
  const abbrev = service.length <= 3 ? service.toUpperCase() : service.substring(0, 3).toUpperCase();
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 32 32"><rect width="32" height="32" rx="5" fill="${color}"/><text x="16" y="21" text-anchor="middle" fill="white" font-family="Arial,sans-serif" font-size="10" font-weight="bold">${abbrev}</text></svg>`;
  return `data:image/svg+xml;base64,${btoa(svg)}`;
}

// ---------------------------------------------------------------------------
// Specific icon mapping (file-based, served by /icons/)
// ---------------------------------------------------------------------------
const ICON_MAP: Record<string, string> = {
  "AWS::EC2::Instance":                        "/icons/EC2_Instance.png",
  "AWS::EC2::VPC":                             "/icons/VPC.png",
  "AWS::EC2::Subnet":                          "/icons/Subnet.png",
  "AWS::EC2::SecurityGroup":                   "/icons/Security_Group.png",
  "AWS::EC2::InternetGateway":                 "/icons/Internet_Gateway.png",
  "AWS::EC2::RouteTable":                      "/icons/Route_Table.png",
  "AWS::EC2::NetworkInterface":                "/icons/Network_Interface.png",
  "AWS::EC2::EIP":                             "/icons/Elastic_IP.png",
  "AWS::S3::Bucket":                           "/icons/S3_Bucket.png",
  "AWS::IAM::Role":                            "/icons/IAM_Role.png",
  "AWS::IAM::User":                            "/icons/IAM_User.png",
  "AWS::IAM::Group":                           "/icons/IAM_Group.png",
  "AWS::IAM::Policy":                          "/icons/IAM_Policy.png",
  "AWS::Lambda::Function":                     "/icons/Lambda_Function.png",
  "AWS::RDS::DBInstance":                      "/icons/RDS_Instance.png",
  "AWS::RDS::DBSubnetGroup":                   "/icons/RDS_Subnet_Group.png",
  "AWS::CloudTrail::Trail":                    "/icons/CloudTrail.png",
  "AWS::CloudTrail::EventDataStore":           "/icons/CloudTrail.png",
  "AWS::CloudFormation::Stack":                "/icons/CloudFormation.png",
  "AWS::ElasticLoadBalancingV2::LoadBalancer": "/icons/ELB.png",
  "AWS::ElasticLoadBalancingV2::TargetGroup":  "/icons/Target_Group.png",
  "AWS::AutoScaling::AutoScalingGroup":        "/icons/Auto_Scaling.png",
  "AWS::ECS::Cluster":                         "/icons/ECS_Cluster.png",
  "AWS::ECS::Service":                         "/icons/ECS_Service.png",
  "AWS::EKS::Cluster":                         "/icons/EKS_Cluster.png",
  "AWS::SNS::Topic":                           "/icons/SNS_Topic.png",
  "AWS::SQS::Queue":                           "/icons/SQS_Queue.png",
  "AWS::DynamoDB::Table":                      "/icons/DynamoDB_Table.png",
  "AWS::KMS::Key":                             "/icons/KMS_Key.png",
  "AWS::Logs::LogGroup":                       "/icons/CloudWatch_Logs.png",
};

/**
 * Returns the icon URL for a given AWS resource type.
 *
 * Resolution order:
 *   1. Exact match in ICON_MAP → file-based PNG from /icons/
 *   2. Service-namespace SVG data URI (colored badge with service abbreviation)
 *   3. FALLBACK_ICON (grey PNG)
 *
 * @param resourceType - e.g. "AWS::EC2::Instance" or "__service__EC2"
 */
export function getIconUrl(resourceType: string): string {
  // Specific file icon
  if (ICON_MAP[resourceType]) return ICON_MAP[resourceType];

  // Service-group virtual node: "__service__EC2"
  if (resourceType.startsWith("__service__")) {
    const svc = resourceType.replace("__service__", "");
    return _serviceSvgDataUri(svc);
  }

  // Extract service namespace: "AWS::EC2::VPC" → "EC2"
  const parts = resourceType.split("::");
  if (parts.length >= 2) {
    return _serviceSvgDataUri(parts[1]);
  }

  return FALLBACK_ICON;
}
