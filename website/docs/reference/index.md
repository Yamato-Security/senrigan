# Built-in Query & Dashboard Reference

> 💡 No SQL or deep AWS knowledge required — just select a hunt from the dropdown and get results instantly.

## 🎯 Built-in Hunts — 100+ queries

Categories are ordered by DFIR triage priority — check detection-tool tampering first, then identity abuse, then data impact.

| Category | Queries | Key Threats Covered |
|----------|:-------:|---------------------|
| 🛡 Detection & Response | 12 | Audit-service tampering (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · SCP deletion · alarm suppression · log exfiltration |
| 🔑 Identity & Access | 26 | Root usage · console login/MFA · privilege escalation · trust policy backdoor · PassRole abuse · cross-account AssumeRole · SSO/SAML/OIDC · credential enumeration |
| 🪣 Data & Storage | 21 | S3 bulk deletion/download · secrets bulk read · backup tampering · KMS ops · snapshot sharing · EBS Direct API exfiltration · DynamoDB export · S3 cross-account replication |
| ⚡ Compute & Serverless | 14 | EC2 mass stop/terminate · SSM lateral movement · Lambda/ECS/EKS/ECR tampering · EventBridge persistence · cryptomining · Lightsail abuse |
| 🌐 Network & Infrastructure | 14 | SG open to internet · VPC flow log deletion · CloudFront hijack · covert VPN/TGW tunnels · Elastic IP C2 · API Gateway keys |
| 🕵 Threat Patterns | 5 | Off-hours writes · recon burst · multi-region spread · unusual user agents · first-time API calls |
| 📊 Activity & Baseline | 3 | Console write events · error spikes · recent errors |
| 🌍 GeoIP Analysis ✦ | 12 | Impossible travel · multi-country credentials · geo-ranked logins/denials/writes · country/city/ASN breakdown · event_name × country · identity × country |
| ☁ IaC & Platform | 2 | CI/CD supply chain · CloudFormation abuse |

<details>
<summary>📋 Full list — all 100+ queries (click to expand)</summary>

## Built-in Hunts

### 🛡 Detection & Response

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | Detects any attempt to stop or modify CloudTrail — the most critical cover-up indicator |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | Detects GuardDuty disable, delete, and threat-intel manipulation |
| 3 | ⛔ Security Hub Tampering | timeseries | Detects Security Hub disable, standard disable, and finding suppression |
| 4 | ⚙️ AWS Config Tampering | timeseries | Detects AWS Config recorder/rule deletion (eliminates compliance evidence) |
| 5 | 🛡 Organizations SCP Changes | timeseries | Detects SCP creation, update, and deletion — removing a Deny SCP eliminates guardrails across every account in the OU |
| 6 | 🚫 AWS Macie Tampering | timeseries | Detects Macie disable and finding-filter creation (pre-exfiltration defense evasion) |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | Detects alarm deletion and DisableAlarmActions — silences security alerting without deleting the alarm |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | Detects CW Logs subscription filter creation/deletion (real-time log exfiltration to attacker Kinesis/Lambda) |
| 9 | 🏹 WAF WebACL Changes | timeseries | Detects WAF WebACL creation, update, and deletion across WAFv2/WAF Classic |
| 10 | 🔍 GuardDuty Findings Read | timeseries | Detects ListFindings / GetFindings — attacker reads active findings to understand what the SOC has already detected |
| 11 | 💰 Budget / Cost Anomaly Changes | timeseries | Detects Budget/AnomalyMonitor deletion (hiding cryptomining costs) |
| 12 | 🚫 Access Denied Errors | bar | Groups AccessDenied errors by identity and API — top offenders indicate credential misuse |

### 🔑 Identity & Access

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | Detects any API call made by the root account — root should never be used in production |
| 2 | 🔓 Console Login without MFA | timeseries | Detects console logins where MFA was not used — high-risk indicator of account compromise |
| 3 | 🌐 Console Logins | timeseries | Lists all console login attempts including successes and failures (brute force detection) |
| 4 | 🔐 MFA & Password Changes | timeseries | Detects MFA deactivation and password resets — strong indicator of account takeover |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | Detects IAM policy attachment and role manipulation (PutUserPolicy, AttachRolePolicy, CreatePolicyVersion, etc.) |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | Detects UpdateAssumeRolePolicy — adding external principals to a trust policy creates a persistent backdoor |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | Detects permission boundary put/delete events — removing a boundary immediately expands effective permissions |
| 8 | 👑 User Added to Admin Group | timeseries | Detects users added to groups with 'admin' in the name — classic privilege escalation |
| 9 | 👥 IAM Group Membership Changes | timeseries | Detects all AddUserToGroup / RemoveUserFromGroup / CreateGroup / DeleteGroup events regardless of group name |
| 10 | 👤 New IAM Users / Keys | timeseries | Identifies IAM user and access key creation events — unexpected creation may indicate persistence |
| 11 | 🎯 IAM PassRole Abuse | timeseries | Detects iam:PassRole usage by inspecting receiving-service events (RunInstances, CreateFunction, CreateNotebookInstance, etc.) where a role ARN is passed |
| 12 | 🔐 AssumeRole Cross-Account | timeseries | Shows AssumeRole events where caller and target are in different AWS accounts (lateral movement) |
| 13 | 🏢 Cross-Account Access | timeseries | Finds all events where caller account differs from recipient account |
| 14 | 🔑 STS Federation Token Issuance | timeseries | Detects GetFederationToken and GetSessionToken — converts long-lived keys into persistent temporary credentials |
| 15 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | Detects OIDC trust abuse (misconfigured sub claim / GitHub Actions without repo condition) |
| 16 | 🆔 IAM Identity Center (SSO) Events | timeseries | Detects AWS IAM Identity Center management actions (CreatePermissionSet, CreateAccountAssignment, etc.) |
| 17 | 🔗 SAML / OIDC Provider Updates | timeseries | Detects SAML/OIDC identity provider changes — updating SAML metadata with attacker-controlled IdP creates a persistent authentication backdoor |
| 18 | 🧐 IAM Access Analyzer Calls | timeseries | Detects any use of IAM Access Analyzer — attackers leverage the native analyzer to enumerate externally accessible resources without custom recon scripts |
| 19 | 🔄 Credential Report & Enumeration | timeseries | Detects IAM enumeration (GenerateCredentialReport, ListUsers, ListRoles, GetAccountAuthorizationDetails, etc.) |
| 20 | 🗝 Access Key Abuse | bar | Detects access keys used from 3+ distinct source IPs in 7 days — strong indicator of key leak |
| 21 | 📰 AWS Organizations Account Creation | timeseries | Detects Organizations account creation and delegated administrator changes (shadow account persistence) |
| 22 | 👥 Cognito Unauthenticated Access | timeseries | Detects Cognito Identity Pools with allowUnauthenticatedIdentities=true |
| 23 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | Detects Glue DevEndpoint creation (iam:PassRole + glue:CreateDevEndpoint = SSH-accessible endpoint running with the passed role's full permissions) and connection enumeration for credential harvest |
| 24 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | Detects SageMaker notebook creation and presigned URL generation — iam:PassRole + sagemaker:CreateNotebookInstance launches a Jupyter environment with the passed role's full AWS permissions |
| 25 | 🛠 Data Pipeline / CodeStar Privilege Escalation | timeseries | Detects Data Pipeline and CodeStar resource creation used for iam:PassRole escalation (CreateProjectFromTemplate creates an admin IAM role as a side effect) |
| 26 | 🧩 Step Functions Privilege Escalation | timeseries | Detects Step Functions state machine creation (iam:PassRole + states:CreateStateMachine executes Lambda/ECS tasks under the passed role) |

### 🪣 Data & Storage

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | Detects identities performing ≥50 DeleteObject/DeleteObjects calls per hour — ransomware / wiper data destruction pattern |
| 2 | 🔥 AWS Backup Tampering | timeseries | Detects Backup Vault / Plan / RecoveryPoint deletion and Vault Lock removal — ransomware first step to eliminate recovery options |
| 3 | 🔓 KMS Key Operations | timeseries | Flags sensitive KMS operations (DisableKey, ScheduleKeyDeletion, CreateGrant, PutKeyPolicy, high-volume Decrypt) |
| 4 | 🔓 S3 Public Access Block Disabled | — | Detects S3 public access block settings being disabled — immediate data exposure risk |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | Detects S3 bucket policy and ACL modifications (PutBucketPolicy with Principal='*' is especially critical) |
| 6 | 🪣 S3 Data Access Anomalies | bar | Detects bulk GetObject calls (≥100/hour) — automated data exfiltration pattern |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | Detects identities retrieving ≥10 distinct secrets in one hour — credential harvesting signal |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | Detects secret deletion, PutResourcePolicy (cross-account sharing), and CancelRotateSecret |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | Detects identities reading ≥20 parameters in one hour — an often-overlooked exfiltration channel |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | Detects RDS/Aurora snapshots shared to external AWS accounts (database exfiltration via snapshot) |
| 11 | 💣 RDS Deleted without Final Snapshot | — | Detects RDS deletion with skipFinalSnapshot=true — potential data destruction |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | Detects RDS instances created or modified with publiclyAccessible=true |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | Detects ExportTableToPointInTime (server-side full-table export bypassing GetItem DLP), DeleteTable, and PITR disable |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | Detects EBS Direct API (ListSnapshotBlocks / GetSnapshotBlock) — Pacu ebs__download_snapshots streams raw snapshot data without EC2, bypassing ModifySnapshotAttribute detection |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | Detects Firehose delivery stream creation/update pointing to external S3 — real-time data pipeline invisible to network DLP |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | Detects PutBucketReplication — silently copies all new objects to attacker-controlled bucket without generating additional GetObject events |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | Detects versioning suspension (enables permanent deletion) and server-access logging disable (removes evidence trail) |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | Detects SES receipt rule and identity configuration changes — forwarding rules relay all inbound mail to attacker addresses; verified identities enable phishing campaigns |
| 19 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | Detects SQS/SNS policy changes granting access to external accounts (silent message streaming to attacker endpoints) |
| 20 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | Detects EBS snapshots or AMIs shared publicly (group=all) — allows anyone to copy disk images and extract data |
| 21 | 📧 Data Exfiltration Channels | bar | Detects high-volume SNS/SQS/SES/S3 PutObject calls (≥50/hour) from a single identity |

### ⚡ Compute & Serverless

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | Detects identities performing ≥5 StopInstances/TerminateInstances in one hour — ransomware / wiper indicator |
| 2 | 🖥️ SSM Session / Run Command | timeseries | Detects SSM StartSession, SendCommand, and StartAutomationExecution — primary lateral movement path via managed instances |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | Detects SendSSHPublicKey and SendSerialConsoleSSHPublicKey — bypasses EC2 key pairs (valid 60 seconds, leaves no SSH key artifacts) |
| 4 | 📝 EC2 User Data Modification | timeseries | Detects ModifyInstanceAttribute with userData change — script runs as root on next boot |
| 5 | ⚡ Lambda Function Tampering | timeseries | Detects Lambda creation, code updates (UpdateFunctionCode), and permission changes (AddPermission) |
| 6 | 📦 Lambda Layer Addition | timeseries | Detects Lambda layer publication and AddLayerVersionPermission with wildcard principal (public supply-chain attack) |
| 7 | 📦 ECS Task Definition  | timeseries | Detects RegisterTaskDefinition / UpdateService — Pacu ecs__backdoor_task_def injects a malicious sidecar container without touching ECR |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | Detects AssociateIamInstanceProfile / ReplaceIamInstanceProfileAssociation — attaches a privileged profile enabling lateral movement |
| 9 | 🖥 EC2 Instance Launches | timeseries | Lists all RunInstances events including instance type, count, key name, and AMI (cryptomining detection) |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | Detects large Spot Fleet requests (ec2) and Auto Scaling group creation with high capacity (autoscaling) — cryptomining financial-impact indicator |
| 11 | ☸️ EKS Cluster API Calls | timeseries | Detects EKS cluster control-plane modifications (public API server exposure, rogue Fargate profiles) |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | Detects ECR repository/image events (PutImage tagged 'latest' poisons all subsequent deployments) |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | Detects EventBridge rule and Scheduler modifications (PutRule, CreateSchedule) — establishes persistence without a running process |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | Detects Lightsail key retrieval, port exposure, and instance access — Pacu lightsail__download_ssh_keys / lightsail__generate_temp_access |

### 🌐 Network & Infrastructure

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🌍 Security Group Opened to Internet | timeseries | Finds security group rules allowing traffic from 0.0.0.0/0 — direct public exposure risk |
| 2 | 🔥 Security Group Modifications | timeseries | Detects all security group rule changes (AuthorizeSecurityGroupIngress, ModifySecurityGroupRules, etc.) |
| 3 | 🌊 VPC Flow Log Changes | timeseries | Detects deletion of VPC Flow Logs — removing flow logs eliminates primary network forensic evidence |
| 4 | 🌐 CloudFront Distribution Tampering | timeseries | Detects CloudFront origin changes that redirect all CDN traffic to attacker-controlled servers (MitM) |
| 5 | 🛡 Network Firewall / Shield Tampering | timeseries | Detects Network Firewall and Shield protection removal — exposes entire subnet ranges to attack traffic |
| 6 | 🧱 Network ACL Changes | timeseries | Detects NACL entry creation, deletion, and replacement — NACLs override security groups at the subnet level |
| 7 | 🛣️ Route Table Changes | timeseries | Detects route table modifications — attackers redirect traffic to malicious gateways for interception or C2 |
| 8 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | Detects new VPN connections and Transit Gateway attachments — creates persistent Layer-3 network paths for C2 or exfiltration |
| 9 | 📡 Elastic IP Allocation / Association | timeseries | Detects Elastic IP allocation/association — assigns a fixed public IP to compromised instances for stable C2 infrastructure |
| 10 | 🗝️ EC2 Key Pair Creation | timeseries | Detects CreateKeyPair and ImportKeyPair — attacker creates SSH keys for persistent instance access |
| 11 | 📡 Network Infrastructure Changes | timeseries | Detects VPC / subnet / IGW / NAT Gateway / peering changes that may establish attacker-controlled infrastructure |
| 12 | 🏷 ACM Certificate Operations | timeseries | Detects ACM certificate requests and deletions — compromised accounts can issue TLS certs for phishing domains |
| 13 | 🔑 API Gateway Key Creation & Management | timeseries | Detects API Gateway key creation and authorizer changes — Pacu api_gateway__create_api_keys generates persistent credentials that survive IAM key rotation |
| 14 | 🚧 VPC Endpoint Access Denied | timeseries | Detects access denied errors via VPC endpoints — may indicate misconfigured endpoint policy |

### 🕵 Threat Patterns

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | Identifies callers who ran 10+ distinct Describe*/List*/Get* APIs in one hour — common early attack phase |
| 2 | 🤖 Unusual User Agents | bar | Lists rare user agents (<5 events) or known attacker tools (Pacu, curl, wget) — may indicate attack tooling |
| 3 | 🌍 Multi-Region Activity | bar | Detects identities performing writes in 3+ regions in one day — geographic spread may indicate compromise |
| 4 | 🕵 First-Time API Calls (24h) | — | Finds API calls seen in the last 24h but never before — novel operations may indicate attacker tooling |

### 📊 Activity & Baseline

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | Identifies mutating API calls made via the AWS console — useful when CLI-only access is expected |
| 2 | 🔍 Events with Errors (24h) | timeseries | Lists all error events in the past 24 hours — quick overview of what is failing or being probed |
| 3 | ❌ Error Spike Detection | — | Finds 1-hour windows where error count exceeds daily average by 3× |

### 🌍 GeoIP Analysis

> Requires GeoLite2 `.mmdb` files for population (columns are NULL if ingested without GeoIP).

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🕵 Impossible Travel Detection | — | Detects same identity calling APIs from distant cities within 2 hours — strong credential compromise indicator |
| 2 | ⚠ Identity Multi-Country Access | bar | Finds identities making API calls from 2+ countries — legitimate users rarely operate from multiple countries simultaneously |
| 3 | 🗺 Console Logins by Country | timeseries | Maps console login events to their geographic origin — logins from unexpected countries are high-risk |
| 4 | 🚨 Unusual Country Access | bar | Detects rare country/identity combinations (<10 events) — low-volume foreign access may be attacker infrastructure |
| 5 | 🚫 Access Denied by Country | bar | Groups access denied errors by source country — concentrated denials from one country may signal an attack |
| 6 | 🔍 Write Events by Country | bar | Shows mutating API calls grouped by source country — writes from unexpected countries are a stronger signal than reads |
| 7 | 🌍 Top Source Countries | bar | Ranks source countries by API call volume with write-event and unique-identity breakdowns |
| 8 | 🏢 Top ASN / Organizations | bar | Lists autonomous systems (ISPs/cloud providers) by API call volume — VPN/hosting ASNs may indicate attacker infrastructure |
| 9 | 📍 Top Source Cities | bar | Ranks source cities by event volume — city-level data pinpoints specific attacker infrastructure or office locations |
| 10 | 🌐 Private / Internal IP Summary | bar | Summarises events from private/loopback/AWS-internal IPs — baseline for expected internal traffic |
| 11 | 📋 API Calls by Country (Event Name) | table | Top (event_name, country) pairs by call volume — reveals which API operations originate from unexpected geographic regions |
| 12 | 👤 Identities by Country (user_identity_arn) | table | Top (user_identity_arn, country) pairs by call volume — surfaces IAM identities active from unexpected countries with first/last seen |

### ☁ IaC & Platform

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | Detects CI/CD pipeline creation and modification (UpdateProject injects malicious build steps into every subsequent build) |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | Detects CloudFormation stack operations — attackers may use IaC to rapidly deploy malicious infrastructure |

</details>

---

## 📊 Dashboard Charts — 80+ charts

| Tab | Charts | What It Shows |
|-----|:------:|---------------|
| 🔑 Identity & Access | 9 | Console logins · MFA trend · login heatmap · sensitive APIs · root usage · IAM entity activity · privilege escalation · SSO/privesc |
| 🎯 Threat Detection | 12 | Event volume · read/write ratio · defense evasion · access denied · error trend · SCP/Config/NACL/EventBridge tampering |
| 📊 API Activity | 7 | Top APIs · region distribution · source IPs · user agents · secrets anomaly · external AssumeRole · Route53 changes |
| 🖥️ Computing | 5 | SSM execution · EC2 public snapshot · EKS/ECR events · ECS backdoor · EBS Direct API exfiltration |
| 🪣 S3 & RDS | 9 | S3 policy/ACL · bulk download/deletion · versioning/logging disabled · cross-account replication · RDS snapshot share · Backup tampering |
| 🌍 GeoIP Intelligence | 6 | World map · top countries / cities / ASNs by request volume · event_name × country · identity × country |
| 🕒 Temporal Analysis | 6 | First/last seen by identity/IP/API/agent · dormant accounts reactivated · velocity spikes |
| 🚨 High-Risk API Monitor | 7 | HRM time series · top calls/actors/IPs · defense evasion/credential detail · by region |

<details>
<summary>📋 Full list — all 80+ charts (click to expand)</summary>

## Dashboard Charts (Apache Superset — `dashboard/`)

### 🔑 Identity & Access

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | Console Login Activity | Console sign-in events grouped by IAM identity (DSH-08) |
| 2 | MFA-less Login Trend | Daily console logins split by MFA usage (DSH-28) |
| 3 | Login Activity Heatmap (Hour × Day) | Console login counts by day-of-week and hour-of-day in JST (DSH-19) |
| 4 | Sensitive API Calls | Invocations of known security-sensitive AWS API actions (DSH-12) |
| 5 | Root Account Usage | All API calls made by the AWS Root account (DSH-13) |
| 6 | IAM Entity Activity | Top 50 IAM entities ranked by total API calls, with write ratio and error rate |
| 7 | Privilege Escalation Timeline | Daily counts of privilege-escalation API calls by event name (DSH-30) |
| 8 | IAM Identity Center (SSO) Events | AWS IAM Identity Center management events from sso.amazonaws.com (DSH-44) |
| 9 | Glue & SageMaker Privilege Escalation | Glue DevEndpoint and SageMaker Notebook events used for IAM privilege escalation via iam:PassRole (DSH-50) |

### 🎯 Threat Detection

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | CloudTrail Events Over Time | Hourly Read vs Write event volume over time (DSH-01) |
| 2 | Write/Read Ratio Trend | Hourly breakdown of read vs write API calls (DSH-20) |
| 3 | Throttling Exception Spikes | Hourly throttling/rate-limit errors by AWS service (DSH-21) |
| 4 | Defense Evasion Events | All CloudTrail events matching known defense-evasion techniques (DSH-22) |
| 5 | Top Access Denied Actions | Top 20 API actions returning AccessDenied errors (DSH-09) |
| 6 | Error Event Trend | Hourly error events broken down by error_code (DSH-04) |
| 7 | Organizations / SCP Changes | AWS Organizations management events including SCP policy changes (DSH-24) |
| 8 | First-Time Service Sources | All distinct AWS service sources ordered by first appearance date (DSH-26) |
| 9 | VPC Flow Log Changes | VPC Flow Log creation and deletion events (DSH-42) |
| 10 | AWS Config Tampering | AWS Config recorder and rule tampering events (DSH-43) |
| 11 | Network ACL / Route Table Changes | NACL and route table modification events (DSH-46) |
| 12 | EventBridge / CloudWatch Rule Tampering | EventBridge and CloudWatch Events rule tampering (DSH-47) |

### 📊 API Activity

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | Top 20 API Calls | The 20 most frequently called AWS API actions (DSH-02) |
| 2 | Region Activity | Distribution of CloudTrail events across AWS regions (DSH-14) |
| 3 | Top Source IP Addresses | Top 100 external source IPs by request count (DSH-05) |
| 4 | User Agent Analysis | Top 50 user agents by request count with error and write breakdowns (DSH-11) |
| 5 | Secrets Access Anomaly | Identities accessing Secrets Manager or SSM Parameter Store ≥10 times in one hour |
| 6 | AssumedRole from External IP | AssumeRole calls from public (non-private) IP addresses (DSH-27) |
| 7 | Route53 DNS Changes | Route 53 hosted-zone and resolver configuration changes (DSH-29) |

### 🖥️ Computing

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | SSM Session / Run Command Execution | AWS Systems Manager remote-execution events (DSH-39) |
| 2 | EC2 Public Snapshot / AMI Sharing | EBS snapshot and AMI public-sharing events (DSH-41) |
| 3 | EKS / ECR Container Platform Events | EKS cluster and ECR container registry events (DSH-48) |
| 4 | ECS Task Definition | ECS task definition registration and service update events — Pacu ecs__backdoor_task_def pattern (DSH-49) |
| 5 | EBS Direct API Snapshot Exfiltration | EBS Direct API calls (ListSnapshotBlocks / GetSnapshotBlock) used to stream snapshot data without EC2 (DSH-51) |

### 🪣 S3 & RDS

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | S3 Protection Config Changes | S3 events that weaken bucket security posture (DSH-25) |
| 2 | S3 Bucket Policy / ACL Changes | S3 bucket policy and ACL modification events (DSH-45) |
| 3 | RDS Snapshot Cross-Account Share | RDS and Aurora snapshot sharing events (DSH-40) |
| 4 | S3 Bulk Download | Identities performing ≥100 GetObject calls per hour — automated data exfiltration pattern (DSH-52) |
| 5 | S3 Bulk Object Deletion | Identities performing ≥50 DeleteObject/DeleteObjects calls per hour — ransomware data destruction pattern (DSH-53) |
| 6 | S3 Versioning / Logging Disabled | PutBucketVersioning (Suspended) and PutBucketLogging (disabled) — anti-forensics precursor to data destruction (DSH-54) |
| 7 | S3 Cross-Account Replication | PutBucketReplication / DeleteBucketReplication — persistent silent exfiltration channel to attacker-controlled account (DSH-55) |
| 8 | RDS Deleted without Final Snapshot | DeleteDBInstance / DeleteDBCluster with skipFinalSnapshot=true — irrecoverable data destruction (DSH-56) |
| 9 | AWS Backup Tampering | Backup Vault / Plan / RecoveryPoint deletion and Vault Lock removal — ransomware first step to eliminate recovery options (DSH-57) |

### 🌍 GeoIP Intelligence

> Requires GeoLite2 `.mmdb` files. GeoIP columns are NULL if ingested without GeoIP.

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | Global Request Origin Map | World map showing geographic distribution of CloudTrail API call origins |
| 2 | Top Countries by Request Volume | Top 20 source countries by API call volume with write-event and unique-caller breakdowns |
| 3 | Top Cities by Request Volume | Top 25 cities by API call volume with write-event and unique-caller breakdowns |
| 4 | Top ASN Organizations by Request Volume | Top 25 ASN organizations by API call volume |
| 5 | API Calls by Country (Event Name × GeoIP) | Top 50 (event_name, country) pairs — reveals which API operations are called from each geographic region (DSH-79) |
| 6 | Identities by Country (user_identity_arn × GeoIP) | Top 50 (user_identity_arn, country) pairs — surfaces IAM identities active from unexpected countries with write count and first/last seen (DSH-80) |

### 🕒 Temporal Analysis

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | First / Last Seen per IAM Identity | IAM identities with first/last seen timestamps, event counts, and distinct APIs |
| 2 | First / Last Seen per Source IP | Source IPs with first/last seen, distinct identities, and distinct APIs |
| 3 | First / Last Seen per API Call | API actions ordered by first appearance — new calls may indicate novel attack tooling (DSH-33) |
| 4 | First / Last Seen per User Agent | User agents ordered by first appearance — new tooling detection (DSH-34) |
| 5 | Dormant Accounts Reactivated | Identities with inactivity gaps of 72+ hours that resumed activity (DSH-37) |
| 6 | Event Velocity Spikes per Identity | Identities with 50+ events per hour burst activity (DSH-38) |

### 🚨 High-Risk API Monitor (HRM)

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | High-Risk API Events Over Time | Daily call volume for APIs commonly observed in attack campaigns (HRM-39) |
| 2 | Top High-Risk API Calls | API actions from the high-risk watchlist ranked by total call count (HRM-40) |
| 3 | Top Actors — High-Risk APIs | IAM principals ranked by total calls to high-risk watchlist APIs (HRM-42) |
| 4 | Top Source IPs — High-Risk APIs | Source IPs ranked by total calls to high-risk watchlist APIs (HRM-43) |
| 5 | Defense Evasion API Events | Detailed event log for APIs used to disable or tamper with audit controls (HRM-44) |
| 6 | Credential Access API Events | Detailed event log for APIs used to retrieve secrets and credentials (HRM-45) |
| 7 | High-Risk API Calls by Region | High-risk watchlist API calls distributed by AWS region (HRM-46) |

</details>

---
