# Built-in Query & Dashboard Reference

> 💡 No SQL or deep AWS knowledge required — just select a hunt from the dropdown and get results instantly.

## 🎯 Built-in Hunts — 136 queries

Categories are ordered by DFIR triage priority — check detection-tool tampering first, then identity abuse, then data impact.

| Category | Queries | Key Threats Covered |
|----------|:-------:|---------------------|
| 🛡 Detection & Response | 13 | Audit-service tampering (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · SCP deletion · alarm suppression · log exfiltration · ransomware kill-chain correlation |
| 🔑 Identity & Access | 36 | Root usage · console login/MFA · privilege escalation · trust policy backdoor · PassRole abuse · cross-account AssumeRole · SSO/SAML/OIDC · credential enumeration · IAM entity deletion · AssumeRoot takeover · Cognito user-pool/token abuse · Support case suppression · role chaining · session credential tracing · GetCallerIdentity recon · federated console logins · Identity Center permission sets & delegated admin · non-MFA API calls |
| 🪣 Data & Storage | 30 | S3 bulk deletion/download · secrets bulk read · backup tampering · KMS ops · snapshot sharing · EBS Direct API exfiltration · DynamoDB export · S3 cross-account replication · SSE-C ransomware encryption · lifecycle-triggered deletion · RDS Data API manipulation · storage re-encryption for impact · ransom note placement · breach-notification scoping · cross-account object copy · presigned URL generation |
| ⚡ Compute & Serverless | 17 | EC2 mass stop/terminate · SSM lateral movement · Lambda/ECS/EKS/ECR tampering · EventBridge persistence · cryptomining · Lightsail abuse · IMDS/SSRF weakening · AMI/snapshot deletion · WorkSpaces hijacking |
| 🤖 AI & LLM Abuse | 10 | Bedrock invocation spikes · model access enablement · invocation-logging tampering · region-sweep reconnaissance · failed-invocation bursts · AgentCore token vault · gateway authorization bypass · memory integrity · sandbox network drift · observability tampering |
| 🌐 Network & Infrastructure | 13 | SG open to internet · VPC flow log deletion · CloudFront hijack · covert VPN/TGW tunnels · Elastic IP C2 · API Gateway keys · Route 53/domain hijack · DDoS protection weakening |
| 🕵 Threat Patterns | 10 | Reconnaissance burst · unusual user agents · multi-region spread · first-time API calls · first-seen region activity · off-hours activity · self-service privilege escalation · daily volume deviation · creation in unused regions · high-volume API use |
| 📊 Activity & Baseline | 3 | Console write events · error spikes · recent errors |
| 🌍 GeoIP Analysis | 2 | Rare country/identity pairings · access-denied concentration by country (volume rankings live on the dashboard Geo tab) |
| ☁ IaC & Platform | 2 | CI/CD supply chain · CloudFormation abuse |

<details markdown="1">
<summary>📋 Full list — all 136 queries (click to expand)</summary>

## Built-in Hunts

### 🛡 Detection & Response

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | Detects any attempt to stop or modify CloudTrail. The most critical alert — indicates cover-up. |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | Detects GuardDuty disable, delete, and threat-intel manipulation. Any GuardDuty change mid-investigation is a critical indicator. |
| 3 | ⛔ Security Hub Tampering | timeseries | Detects Security Hub disable, standard disable, and finding suppression. Silencing Security Hub removes the central aggregation point for all security findings. |
| 4 | ⚙️ AWS Config Tampering | timeseries | Detects AWS Config recorder/rule deletion. Stopping Config eliminates compliance evidence and change-tracking for an entire region. |
| 5 | 🛡 Organizations Service Control Policy (SCP) Changes | timeseries | Detects SCP creation, modification, and deletion. Removing a Deny SCP immediately eliminates guardrails across every account in the affected OU. |
| 6 | 🚫 AWS Macie Tampering | timeseries | Detects Macie disable and finding-filter creation. Attackers suppress Macie findings before exfiltrating sensitive data from S3. |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | Detects CloudWatch alarm deletion and disabling. Silencing alarms tied to GuardDuty, CloudTrail metric filters, or billing thresholds is a key defense-evasion indicator. |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | Detects CW Logs subscription filter creation/deletion and log group deletion. Attackers stream logs to an external destination or destroy evidence in place. |
| 9 | 🏹 WAF WebACL Changes | timeseries | Detects WAF WebACL creation, update, and deletion. Removing or weakening a WebACL disables protection against SQLi, XSS, and DDoS attacks. |
| 10 | 🔍 GuardDuty Findings Read | timeseries | Detects read-only GuardDuty API calls. Pacu's guardduty__list_findings module reads active findings to understand what the defender has already detected, allowing the attacker to adapt their tactics and avoid triggering new alerts. |
| 11 | 💰 Budget / Cost Anomaly Changes | timeseries | Detects deletion or modification of AWS Budgets and Cost Anomaly monitors. Attackers remove budget alerts to hide cryptomining or resource-intensive operations. |
| 12 | 🚫 Access Denied Errors | bar | Groups AccessDenied errors by identity and API. Top offenders may indicate credential misuse. |
| 13 | ⛓ Ransomware Kill-Chain Sequence | bar | Correlates the three ransomware stages — recovery removed, protection disabled, data destroyed or encrypted — per principal and day. Each stage alone is operational noise; all three together are not. |

### 🔑 Identity & Access

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | Detects any API call made by the root account. Root should never be used in production. |
| 2 | 🔓 Console Login without MFA | timeseries | Detects console logins where MFA was not used. High-risk indicator of account compromise. |
| 3 | 🌐 Console Logins | timeseries | Lists all console login attempts. Brute force = multiple failures followed by success. |
| 4 | 🔐 MFA & Password Changes | timeseries | Detects MFA deactivation and password resets. Strong indicator of account takeover. |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | Detects IAM policy attachment and role manipulation events used for privilege escalation. |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | Detects UpdateAssumeRolePolicy calls. Adding external account principals to a trust policy creates a persistent backdoor. |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | Detects permission boundary put/delete events. Removing a permission boundary immediately expands a principal's effective permissions, enabling privilege escalation. |
| 8 | 👑 User Added to Admin Group | timeseries | Detects users added to groups with 'admin' in the name. Classic privilege escalation technique. |
| 9 | 👥 IAM Group Membership Changes | timeseries | Detects all AddUserToGroup and RemoveUserFromGroup events regardless of group name. Any group addition may indicate privilege escalation through group-inherited policies. |
| 10 | 👤 New IAM Users / Keys | timeseries | Identifies IAM user and access key creation events. Unexpected creation may indicate persistence. |
| 11 | 🎯 IAM PassRole Abuse | timeseries | Detects iam:PassRole calls. Passing a privileged role to EC2/Lambda/Glue/ECS/SageMaker is the most common lateral privilege escalation path. |
| 12 | 🏢 Cross-Account Access | timeseries | Finds events where the caller account differs from the recipient account. Lateral movement signal. |
| 13 | 🔑 STS Federation Token Issuance | timeseries | Detects GetFederationToken and GetSessionToken calls. Attackers use these to convert long-lived keys into persistent temporary credentials. |
| 14 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | Detects AssumeRoleWithWebIdentity calls. Abusing a misconfigured OIDC trust (e.g., overly broad sub claim) lets attackers hijack a role using attacker-controlled tokens. |
| 15 | 🆔 IAM Identity Center (SSO) Events | timeseries | Detects AWS IAM Identity Center management actions. Attackers abuse SSO to create backdoor permission sets or assign accounts to attacker-controlled users. |
| 16 | 🔗 SAML / OIDC Provider Updates | timeseries | Detects SAML/OIDC identity provider changes. Updating a SAML provider with attacker-controlled metadata creates a persistent authentication backdoor. |
| 17 | 🧐 IAM Access Analyzer Calls | timeseries | Detects any use of IAM Access Analyzer. Attackers use the native AWS analyzer to enumerate externally accessible resources without writing custom recon scripts. |
| 18 | 🔄 Credential Report & Enumeration | timeseries | Detects IAM enumeration activity that maps the entire IAM landscape. Common in early attack stages. |
| 19 | 🗝 Access Key Abuse | bar | Detects access keys used from 3+ distinct source IPs in 7 days. Strong indicator of key leak. |
| 20 | 📰 AWS Organizations Account Creation | timeseries | Detects Organizations account creation and delegated administrator changes. Attackers create shadow accounts to establish persistent footholds outside the main account. |
| 21 | 👥 Cognito Unauthenticated Access | timeseries | Detects Cognito Identity Pools with unauthenticated access enabled. Allows anonymous users to call AWS APIs with the unauthenticated IAM role's permissions. |
| 22 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | Detects Glue development endpoint creation and connection enumeration. iam:PassRole + glue:CreateDevEndpoint grants full role permissions via SSH — one of the most overlooked IAM privilege escalation techniques. |
| 23 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | Detects SageMaker notebook instance creation and presigned URL generation. iam:PassRole + sagemaker:CreateNotebookInstance provides a Jupyter environment with the passed role's full AWS permissions. CreatePresignedNotebookInstanceUrl alone can grant access to an existing notebook. |
| 24 | 🪓 IAM Entity Deletion | timeseries | Detects deletion of IAM users, roles, policies, and MFA devices. Attackers delete IAM entities to remove traces of their activity or lock defenders out. |
| 25 | 👑 AssumeRoot Usage | timeseries | Detects sts:AssumeRoot calls from the management account into member-account root. A compromised management account can take over every member account this way. |
| 26 | 🎫 Support Case Manipulation | timeseries | Detects AWS Support case closure and comment activity. Attackers resolve abuse/support cases to suppress AWS notifications about a compromise. |
| 27 | 🪪 Cognito User Pool Manipulation | timeseries | Detects Cognito user-pool and app-client changes: extended token validity, new clients, and admin user creation. Attackers abuse these to mint long-lived tokens or seed backdoor users. |
| 28 | 🔗 Role Chaining (Session → Role) | timeseries | Detects an assumed-role session assuming a further role. Single AssumeRole calls look ordinary; the chain is how an attacker walks from a compromised instance role to the permissions they actually want. |
| 29 | 🎫 Session Credential Trace | bar | Summarises what each temporary STS session (ASIA… access key) did: how many calls, which services, which IPs and over what window. The scoping question every credential-compromise investigation starts with. |
| 30 | 🌐 AssumeRole Target Account (roleArn) | timeseries | Detects account-boundary crossings by reading the target account out of the requested roleArn, which works even when only the calling account's logs were ingested. |
| 31 | 📊 AssumeRole Fan-In by Target Role | bar | Ranks roles by who assumes them and from where. A role normally assumed by one account that suddenly gains a second caller stands out here, while the raw event list buries it. |
| 32 | 🔍 GetCallerIdentity Reconnaissance | bar | Surfaces GetCallerIdentity calls per principal and source IP. It is the first command run against stolen credentials — and a single call, which volume-threshold recon hunts never reach. |
| 33 | 🪪 Federated Console Logins | timeseries | Lists console logins that arrived through an external identity provider, with the provider name and origin. When the IdP is the compromised component, AWS sees only a valid login. |
| 34 | 🎟 Identity Center Permission Set Grants | timeseries | Detects IAM Identity Center permission-set creation, policy attachment and account assignment — the path to standing admin access across every account in the organisation. |
| 35 | 🧑 Identity Store User & Group Creation | timeseries | Detects users, groups and memberships created directly in the Identity Center identity store — persistence that never appears in IAM and so is missed by IAM-only monitoring. |
| 36 | 👑 Delegated Administrator Registration | timeseries | Detects registration of a delegated administrator for an organisation service. The only event the upstream Identity Center playbook grades CRITICAL — it hands organisation-wide control to another account. |

### 🪣 Data & Storage

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | Detects high-volume DeleteObject/DeleteObjects calls (>=50/hour). Distinct from exfiltration — this is data destruction / ransomware pattern. |
| 2 | 🔥 AWS Backup Tampering | timeseries | Detects Backup Vault/Plan/RecoveryPoint deletion. Destroying backups is the first step in ransomware attacks to prevent recovery. |
| 3 | 🔓 KMS Key Operations | timeseries | Flags sensitive KMS operations including key deletion and high-volume Decrypt calls. |
| 4 | 🔓 S3 Public Access Block Disabled | — | Detects S3 public access block settings being disabled. Immediate data exposure risk. |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | Detects S3 bucket policy and ACL modifications. These can make a bucket publicly readable or grant access to attacker-controlled accounts. |
| 6 | 🪣 S3 Data Access Anomalies | bar | Detects bulk GetObject calls (>=100/hour) that may indicate data exfiltration. |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | Detects bulk retrieval of secrets (DB passwords, API keys, etc.). Ten or more GetSecretValue calls in one hour is a strong credential-harvesting signal. |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | Detects Secrets Manager secret deletion and cross-account resource policy changes. Complements existing bulk-read detection with destruction and policy-exfiltration vectors. |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | Detects bulk reads of SSM Parameter Store entries. An often-overlooked exfiltration channel compared with Secrets Manager. |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | Detects RDS/Aurora snapshots shared to external AWS accounts. Classic data exfiltration via snapshot sharing. |
| 11 | 💣 RDS Deleted without Final Snapshot | — | Detects RDS instance/cluster deletion with skipFinalSnapshot=true. Potential data destruction. |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | Detects RDS instances created or modified with PubliclyAccessible=true. Exposes the database directly to the internet, bypassing VPC security controls. |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | Detects DynamoDB ExportTableToPointInTime (silent full-table export to S3) and table deletion. High-risk exfiltration and destruction vector. |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | Detects EBS Direct API calls (ListSnapshotBlocks / GetSnapshotBlock). Pacu's ebs__download_snapshots uses this API to stream raw snapshot data without creating EC2 instances, bypassing traditional snapshot-sharing detection. |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | Detects Kinesis Firehose delivery stream creation/update pointing to external S3. Real-time data pipeline exfiltration invisible to network DLP. |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | Detects PutBucketReplication and DeleteBucketReplication. Cross-account replication silently copies all new objects to an attacker-controlled bucket. |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | Detects S3 versioning suspension and server access logging disable. Disabling versioning enables data destruction; disabling logging erases the access evidence trail. |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | Detects SES receipt rule and identity configuration changes. Forwarding rules can auto-relay all inbound mail to attacker addresses; verified identities enable phishing campaigns. |
| 19 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | Detects SQS/SNS queue/topic policy changes that grant access to external accounts. Creates a silent exfiltration channel without triggering high-volume send alerts. |
| 20 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | Detects EBS snapshots or AMIs shared publicly (group=all). Enables anyone to copy your disk images and extract data. |
| 21 | 📧 Data Exfiltration Channels | bar | Detects high-volume SNS/SQS/SES/S3 PutObject calls (>=50/hour) that may indicate exfiltration. |
| 22 | 🔐 S3 SSE-C Encryption (Ransomware) | timeseries | Detects S3 objects re-encrypted with attacker-supplied SSE-C keys, plus bucket default-encryption changes. Without the customer key the victim cannot decrypt — a cloud-native ransomware pattern. |
| 23 | ⏳ S3 Lifecycle-Triggered Deletion | timeseries | Detects S3 lifecycle rules that expire objects, plus lifecycle-config deletion. Attackers set a short expiration to silently purge data over time without issuing DeleteObject calls. |
| 24 | 🗃 RDS Query & Instance Manipulation | timeseries | Detects RDS Data API queries, master-password resets, and snapshot restores. Attackers read data directly, reset credentials to gain access, or restore snapshots into instances they control. |
| 25 | 🔎 S3 Bucket Enumeration | bar | Detects callers sweeping bucket and object metadata (≥10 List/GetBucket* reads in one hour). A common early step to locate valuable data before exfiltration. |
| 26 | 🔑 Storage Re-Encryption for Impact | timeseries | Detects EBS/RDS snapshots and volumes re-encrypted with an explicit KMS key, plus disabling of default EBS encryption. Re-encrypting with an attacker-held key holds the data for ransom. |
| 27 | 📝 Ransom Note Placement | timeseries | Detects PutObject calls whose object key looks like a ransom note. Unlike the other ransomware hunts this one confirms impact rather than suggesting it — a note means the operator is already demanding payment. |
| 28 | 📐 Data Access Scope (Breach Notification) | bar | Quantifies what each principal read per day: buckets touched and approximate distinct objects. Produces the 'approximate number of records' figure a GDPR Article 33 notification requires. |
| 29 | 📤 Cross-Account Object Copy | timeseries | Detects objects copied between buckets, including PutObject calls carrying an x-amz-copy-source header. Staging data into an account you do not control leaves this trace and no other. |
| 30 | 🔗 Presigned URL Generation | bar | Counts presigned URL generation per principal. A presigned URL moves data to anyone holding the link, with no further authentication and no further CloudTrail record. |

### ⚡ Compute & Serverless

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | Detects high-volume EC2 StopInstances/TerminateInstances (>=5 in one hour). Indicates ransomware disruption or destructive attack. |
| 2 | 🖥️ SSM Session / Run Command | timeseries | Detects SSM StartSession, SendCommand, and automation executions. Primary lateral movement path via managed instances. |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | Detects EC2 Instance Connect and Serial Console access, which lets attackers reach an instance from a browser or CLI without an SSH key or bastion host. A primary lateral-movement path for attackers who lack SSH keys. |
| 4 | 📝 EC2 User Data Modification | timeseries | Detects ModifyInstanceAttribute calls that change the userData field. User data scripts run as root at next boot, providing a persistent code-execution backdoor. |
| 5 | ⚡ Lambda Function Tampering | timeseries | Detects Lambda creation, code updates, and permission changes. Attackers use Lambda for persistence. |
| 6 | 📦 Lambda Layer Addition | timeseries | Detects Lambda layer publication and permission changes. Publishing a malicious shared layer and adding it to production functions injects attacker code into the dependency chain. |
| 7 | 📦 ECS Task Definition | timeseries | Detects ECS task definition registration and service updates. Pacu's ecs__backdoor_task_def registers a new task definition version pointing to a malicious container image, then updates the service to deploy it — all without touching ECR. |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | Detects IAM instance profile association and replacement. Attaching a privileged profile grants the instance elevated permissions for lateral movement. |
| 9 | 🖥 EC2 Instance Launches | timeseries | Lists all RunInstances events. Unexpected launches in unusual regions may indicate cryptomining. |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | Detects large Spot Fleet requests, Reserved Instance purchases, and Auto Scaling group creation with high capacity. Cryptomining financial-impact indicator. |
| 11 | ☸️ EKS Cluster API Calls | timeseries | Detects EKS cluster control-plane modifications. Public API server exposure or rogue Fargate profiles enable container platform takeover. |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | Detects ECR repository creation/deletion, policy changes, and image pushes. Injecting malicious images into a production repository is a supply-chain persistence technique. |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | Detects EventBridge rule and EventBridge Scheduler modifications. Attackers use scheduled rules to establish persistence without a long-running process. |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | Detects Lightsail instance access, key pair operations, and port exposure. Pacu has three dedicated Lightsail modules (enum, download_ssh_keys, generate_temp_access). Lightsail resources operate outside the standard EC2 security boundary. |
| 15 | 🛰 IMDS Options Weakening | timeseries | Detects ModifyInstanceMetadataOptions calls that make IMDSv2 optional or re-enable the metadata endpoint. Weakening IMDS re-opens the SSRF path to steal instance-role credentials. |
| 16 | 💥 AMI & Snapshot Deletion | bar | Detects bulk deregistration of AMIs and deletion of EBS snapshots (≥5 in one hour). Destroying golden images and backups removes recovery options during a destructive attack. |
| 17 | 🖥 WorkSpaces Hijacking | timeseries | Detects Amazon WorkSpaces provisioning and pool creation. Attackers spin up desktops at the victim's expense, an under-monitored compute-hijacking channel outside the EC2 boundary. |

### 🤖 AI & LLM Abuse

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🤖 Bedrock Model Invocation Spike | timeseries | Detects principals invoking Bedrock models 50+ times in one hour. High-volume inference on stolen credentials (LLMjacking) can cost the victim tens of thousands of dollars per day. |
| 2 | 🔓 Bedrock Model Access Enablement | timeseries | Detects foundation-model access being enabled or provisioned capacity purchased. In orgs that never adopted Bedrock this is a near-zero-noise LLMjacking indicator — the attacker's canonical first write. |
| 3 | 🙈 Bedrock Invocation Logging Tampering | timeseries | Detects deletion or modification of Bedrock model-invocation logging, plus attackers checking whether logging is enabled before abusing the account (a documented LLMjacking IOC). |
| 4 | 🧭 Bedrock Reconnaissance Sweep | bar | Identifies callers enumerating Bedrock models across 2+ regions or with 10+ enumeration calls in one hour. Stolen-key holders sweep regions to find where models are usable. |
| 5 | ⛔ Failed Bedrock Invocations | bar | Finds bursts of failed Bedrock invocations (AccessDenied / ValidationException). Stolen-key testing produces failure storms across models and regions before a working combination is found. |
| 6 | 🔑 AgentCore Token Vault Abuse | bar | Aggregates AgentCore token-vault issuance per principal and source. These calls hand out third-party OAuth tokens and API keys, so abuse here reaches services outside AWS entirely. |
| 7 | 🚪 AgentCore Gateway Authorization Bypass | timeseries | Detects AgentCore Gateway and policy changes, including a Cedar policy engine dropped to LOG_ONLY. Authorization that only logs still returns success, so nothing downstream looks wrong. |
| 8 | 🧠 AgentCore Memory Integrity | timeseries | Detects AgentCore Memory and Registry changes, including a memory stream repointed at a foreign Kinesis ARN. Poisoned long-term memory persists across every future session of the agent. |
| 9 | 📦 AgentCore Sandbox Network Mode Drift | timeseries | Lists AgentCore code interpreter and browser lifecycle events with their network mode. The mode cannot be edited, so a delete followed by a create is the only way to widen a sandbox's network access. |
| 10 | 🙈 AgentCore Observability Tampering | timeseries | Detects AgentCore evaluator changes and X-Ray sampling or trace-destination changes. An attacker-created evaluator reads every response it grades, exporting model output through a legitimate channel. |

### 🌐 Network & Infrastructure

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🔥 Security Group Modifications | timeseries | Detects security group rule changes, especially rules allowing 0.0.0.0/0 on any port. |
| 2 | 🌊 VPC Flow Log Changes | timeseries | Detects deletion of VPC Flow Logs. Removing flow logs eliminates network-level evidence — a critical defense evasion indicator. |
| 3 | 🌐 CloudFront Distribution Tampering | timeseries | Detects CloudFront distribution creation and origin changes. Modifying origins redirects CDN traffic to attacker-controlled servers for MitM interception or data collection. |
| 4 | 🧱 Network ACL Changes | timeseries | Detects Network ACL entry creation, deletion, and replacement. NACLs override security groups and can open entire subnets to attackers. |
| 5 | 🛣️ Route Table Changes | timeseries | Detects route table modifications. Adding or replacing routes can redirect traffic to attacker-controlled hosts (MitM, traffic hijacking). |
| 6 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | Detects new VPN connections, Direct Connect, and Transit Gateway attachments. Attackers create covert network tunnels for persistent C2 or data exfiltration channels. |
| 7 | 📡 Elastic IP Allocation / Association | timeseries | Detects Elastic IP allocation and association. Attackers assign a fixed public IP to a compromised instance to create stable C2 infrastructure. |
| 8 | 🗝️ EC2 Key Pair Creation | timeseries | Detects CreateKeyPair and ImportKeyPair events. Attackers create or import SSH keys as a persistence mechanism to maintain instance access. |
| 9 | 📡 Network Infrastructure Changes | timeseries | Detects VPC and network-level changes that may establish attacker-controlled infrastructure. |
| 10 | 🏷 ACM Certificate Operations | timeseries | Detects ACM certificate requests and deletions. Attackers use compromised accounts to issue TLS certificates for attacker-controlled domains to build phishing infrastructure. |
| 11 | 🔑 API Gateway Key Creation & Management | timeseries | Detects API Gateway key creation and REST API management. Pacu's api_gateway__create_api_keys creates persistent API credentials that survive IAM key rotation. Attackers also modify API authorizers to weaken access controls. |
| 12 | 🌐 Route 53 & Domain Changes | timeseries | Detects DNS record edits, hosted-zone changes, and domain registration/transfer. Attackers redirect traffic, take over dangling subdomains, or register lookalike domains for phishing. |
| 13 | 🛡 DDoS Protection Weakening | timeseries | Detects edge protections being loosened rather than removed: a WebACL default action flipped to allow, rule groups relaxed, Shield protections deleted, CloudFront origins repointed. |

### 🕵 Threat Patterns

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | Identifies callers who ran 10+ distinct read-only API calls in one hour. Common early attack phase. |
| 2 | 🤖 Unusual User Agents | bar | Lists rare user agents (<5 events). Custom tooling like Pacu or curl may indicate attacker tooling. |
| 3 | 🌍 Multi-Region Activity | bar | Detects identities performing writes in 3+ regions in one day. Geographic spread may indicate compromise. |
| 4 | 🕵 First-Time API Calls (24h) | — | Finds API calls seen in the last 24h but never before. Novel operations may indicate attacker tooling. |
| 5 | 🗺 First-Seen Region Activity | bar | Finds AWS regions whose first-ever activity falls in the last 24h of the dataset. Operating in a never-before-used region is a classic way to hide cryptomining or staging from region-scoped monitoring. |
| 6 | 🌙 Off-Hours Activity | bar | Groups activity by principal and hour of day inside a configurable out-of-hours window. The first indicator the upstream insider-threat playbook lists, and one no other hunt covers. |
| 7 | 🪞 Self-Service Privilege Escalation | timeseries | Detects a principal modifying its own permissions — the caller ARN and the target user or role name are the same. Existing escalation hunts see the grant but lose the fact that it was self-applied. |
| 8 | 📈 Principal Daily Volume Deviation | bar | Compares each principal's daily call volume against its own average, splitting reads from writes. Catches the exfiltration that uses only permitted APIs, where the anomaly is quantity rather than action. |
| 9 | 🗺 Resource Creation Outside Normal Regions | bar | Flags resource creation in regions the account barely uses, with the baseline derived from the data rather than hardcoded. Cryptomining and private side projects both land here. |
| 10 | 📞 High-Volume API Calls per Principal | bar | Lists principal and API pairings exceeding 50 successful calls, with the first and last call. Enumeration, bulk extraction and mass deletion all share this shape. |

### 📊 Activity & Baseline

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | Identifies mutating API calls made via the AWS console. Useful when CLI-only access is expected. |
| 2 | 🔍 Events with Errors (24h) | timeseries | Lists all error events in the past 24 hours. Quick overview of what is failing right now. |
| 3 | ❌ Error Spike Detection | — | Finds 1-hour windows where error count exceeds the daily average by 3x. Signals scanning or outage. |

### 🌍 GeoIP Analysis

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🚨 Unusual Country Access | bar | Detects API calls from unexpected countries by showing rare country/identity combinations. |
| 2 | 🚫 Access Denied by Country | bar | Groups access denied errors by source country. Concentrated denials from one country may signal an attack. |

### ☁ IaC & Platform

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | Detects CI/CD pipeline creation and modification. Injecting malicious build steps or modifying pipeline sources poisons all subsequent deployments. |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | Detects CloudFormation stack operations. Attackers may use IaC to rapidly deploy malicious infrastructure. |

</details>

---

## 📊 Dashboard Charts — 115 charts

| Tab | Charts | What It Shows |
|-----|:------:|---------------|
| 🚦 Overview | 10 | 9 triage KPI cards (events, principals, IPs, root, MFA-less logins, access denied, defense evasion, countries, regions) + global event-volume trend |
| 🎯 Threat Detection | 14 | Defense-evasion catch-all · logging gaps · VPC flow log/Config/EventBridge/WAF tampering · SCP/org-membership changes · error & throttling trends · write/read ratio · P1/P2 escalation-trigger KPI cards |
| 🔑 Identity & Access | 36 | Console logins · MFA trend · login heatmap · failed→success auth sequence · root usage · IAM entity activity/deletion · privilege-escalation timeline · new principals · SSO · cross-account AssumeRole · AssumeRoot usage |
| 🚨 High-Risk API Monitor | 5 | Security-service tampering & credential-retrieval API logs · top high-risk calls · top actors · high-risk call volume over time |
| 📊 API Activity | 6 | Top APIs · access-denied actions · region distribution · error-code composition · source IPs · user agents |
| 🪣 S3 & RDS | 18 | S3 bulk download/deletion · versioning/logging disabled · cross-account replication · bucket policy/ACL · enumeration · protection config · Backup vault deletion · KMS key deletion · RDS snapshot share / deleted without snapshot · SSE-C ransomware encryption · lifecycle-triggered deletion · RDS query/instance manipulation · storage re-encryption for impact · breach-notification access scope · cross-account object copy · ransom note placement |
| 🖥️ Computing | 17 | EC2 launches/mass-stop/key pairs/instance profile/user-data/snapshot sharing/spot fleet · ECS/Lambda/SSM/EBS Direct API/EKS-ECR/CloudFormation · IMDS weakening · AMI/snapshot deletion · WorkSpaces hijacking |
| 🤖 AI / LLM | 6 | Bedrock invocation trend · model access & logging changes · failed invocations · callers by origin (LLMjacking triage) · AgentCore token issuance · gateway & policy changes |
| 🌐 Network | 5 | Security group changes · NACL/route table changes · VPC infrastructure · VPC peering/Transit Gateway · Route53 DNS changes |
| 🕒 Temporal Analysis | 8 | Event velocity spikes · dormant accounts reactivated · first/last seen by identity/IP/API/service source · off-hours write heatmap · principal daily read/write volume |
| 🌍 GeoIP Intelligence | 6 | Impossible travel (multi-country principals) · top countries/cities/ASNs · world map · event_name × country |

<details markdown="1">
<summary>📋 Full list — all 115 charts (click to expand)</summary>

## Dashboard Charts (Apache Superset — `dashboard/`)

### 🚦 Overview

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | Total Events | Total number of CloudTrail events in the selected range (KPI-81). The denominator for triage — anchor for every per-principal or per-IP ratio. |
| 2 | Distinct Principals | Count of unique IAM principal ARNs active in the selected range (KPI-82). Use to scope how many identities are involved in the activity under review. |
| 3 | Distinct Source IPs | Count of unique caller source IP addresses in the selected range (KPI-83). A jump versus baseline suggests proxy/VPN rotation or distributed access. |
| 4 | Root Account Events | Number of events performed by the account root identity (KPI-84). Root activity should be near-zero — any non-zero value warrants investigation. |
| 5 | MFA-less Console Logins | Number of console logins without MFA in the selected range (KPI-85). A direct indicator of credential compromise — drill into MFA-less Login Trend. |
| 6 | Access Denied Events | Number of authorization-failure events in the selected range (KPI-86). A spike suggests reconnaissance or privilege probing — pivot by principal/IP. |
| 7 | Defense-Evasion Hits | Number of audit/monitoring tampering events in the selected range (KPI-87). Highest-priority triage signal — any non-zero value means detection may have been disabled. Drill into Security Monitoring & Control Changes. MITRE ATT&CK: TA0005 Defense Evasion. |
| 8 | Distinct Countries | Count of unique source countries in the selected range (KPI-88). Requires GeoIP enrichment (docker/data/geoip/). A wide spread suggests access from unexpected geographic origins. |
| 9 | Active Regions | Count of distinct AWS regions with activity in the selected range (KPI-89). Activity in unused regions can indicate resource abuse or attacker staging. |
| 10 | CloudTrail Events Over Time | Hourly Read vs Write event volume over time (DSH-01). Stacked bars show the Read/Write split: a sudden rise in write_events signals that an attacker is transitioning from reconnaissance to active exploitation.  Useful for identifying activity spikes and off-hours operations. |

### 🎯 Threat Detection

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | Security Monitoring & Control Changes | Comprehensive catch-all for all defense-evasion events (DSH-22). Covers CloudTrail tampering (StopLogging, DeleteTrail), GuardDuty disabling, AWS Config disabling, VPC Flow Log deletion, CloudWatch log deletion, and security service disabling (SecurityHub, IAM Access Analyzer). Any event here warrants immediate investigation. For deeper analysis use dedicated charts: VPC Flow Log Changes (DSH-42), AWS Config Tampering (DSH-43), EventBridge/CW Tampering (DSH-47). MITRE ATT&CK: TA0005 Defense Evasion. |
| 2 | CloudTrail Logging Gap (Hourly Volume) | Hourly CloudTrail event volume (DSH-91).  A sudden drop to zero between active periods suggests logging was disabled (StopLogging/DeleteTrail) or a delivery blind spot exists.  Investigate any unexpected gap against the Security Monitoring & Control Changes table. MITRE ATT&CK: T1562.008 Impair Defenses — Disable Cloud Logs. |
| 3 | VPC Flow Log Changes | VPC Flow Log creation and deletion events (DSH-42). DeleteFlowLogs eliminates the primary network forensic evidence source, making post-incident analysis of lateral movement and data exfiltration impossible.  CreateFlowLogs during an incident may indicate log redirection to an attacker-controlled S3 bucket. MITRE ATT&CK: TA0005 Defense Evasion. |
| 4 | AWS Config Recorder & Rule Changes | AWS Config recorder and rule tampering events (DSH-43): StopConfigurationRecorder, DeleteConfigurationRecorder, DeleteDeliveryChannel, DeleteConfigRule, and PutConfigRule. Stopping the Config recorder eliminates compliance evidence and change-tracking for the entire region, allowing subsequent infrastructure changes to go undetected by Config rules and Security Hub standards. MITRE ATT&CK: TA0005 Defense Evasion. |
| 5 | EventBridge & CloudWatch Rule Modifications | EventBridge and CloudWatch Events rule tampering (DSH-47): DeleteRule, DisableRule (silencing scheduled detection), CreateSchedule/UpdateSchedule (attacker cron jobs for C2 beaconing), PutSubscriptionFilter (redirecting CloudTrail/VPC logs to attacker account), DeleteLogGroup (destroying VPC Flow Log records). Combined monitoring-layer tampering chart for DFIR. MITRE ATT&CK: TA0003 Persistence / TA0005 Defense Evasion / TA0011 C2. |
| 6 | WAF Configuration Changes | AWS WAF v2 / WAF Classic configuration change events (DSH-75). Covers WebACL creation/update/deletion, IP set manipulation, rule group changes, logging configuration changes, and WAF association/disassociation with protected resources. Disabling WAF rules or logging while an attack is in progress is a strong defense-evasion indicator. MITRE ATT&CK: TA0005 Defense Evasion / TA0003 Persistence. |
| 7 | Organizations / SCP Changes | AWS Organizations management-plane events including SCP policy changes (DSH-24). An attacker with master-account access may disable SCP guardrails to remove preventive controls across the entire AWS organization. MITRE ATT&CK: TA0004 Privilege Escalation / TA0005 Defense Evasion. |
| 8 | Error Event Trend | Hourly error events broken down by error_code (DSH-04). ThrottlingException spikes indicate automated scanning or attack tooling; AccessDenied / UnauthorizedAccess spikes indicate privilege probing; sudden appearance of new error codes may indicate novel attack techniques. |
| 9 | Throttling Exception Spikes | Hourly throttling / rate-limit errors broken down by AWS service (DSH-21). ThrottlingException spikes indicate that an identity (or tool) is issuing API calls far faster than expected, which is a hallmark of automated attack tooling performing reconnaissance or enumeration. MITRE ATT&CK: TA0007 Discovery. |
| 10 | Write/Read Ratio Trend | Hourly breakdown of read vs write API calls (DSH-20). A sustained increase in write_events relative to read_events indicates that an attacker has moved from reconnaissance to active exploitation. MITRE ATT&CK: TA0040 Impact / TA0007 Discovery. |
| 11 | CloudTrail Events Over Time | Hourly Read vs Write event volume over time (DSH-01). Stacked bars show the Read/Write split: a sudden rise in write_events signals that an attacker is transitioning from reconnaissance to active exploitation.  Useful for identifying activity spikes and off-hours operations. |
| 12 | Organization Membership Changes | Organizations membership changes that detach accounts from guardrails or move them under an attacker-controlled organization. Threat Technique Catalog for AWS: T1666.A002 / T1666.A003. |
| 13 | P1 Escalation Triggers | Events matching the TRIAGE_GUIDE escalation triggers that demand a response within 15 minutes: root usage, logging or detection tampering, ransom notes, delegated-administrator registration. Non-zero means start the clock. |
| 14 | P2 Escalation Triggers | Events matching the TRIAGE_GUIDE conditions for a response within the hour: credential creation, privilege grants, trust-policy edits and cross-account role assumption. Read it against the P1 card, not on its own. |

### 🔑 Identity & Access

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | Console Login Activity | AWS Management Console sign-in events grouped by IAM identity (DSH-08). Tracks successful, failed, and MFA-less login attempts.  A high failure-to-success ratio may indicate brute-force or credential stuffing. mfa_less_count (MFAUsed = 'No') is a direct account-compromise indicator, though it only applies to classic ConsoleLogin events -- the newer OAuth2 sign-in flow (CreateOAuth2Token / AuthorizeOAuth2Access) does not report MFA status. Events are filtered to event_type = 'AwsConsoleSignIn'. |
| 2 | MFA-less Login Trend | Daily console logins split by MFA usage (DSH-28). mfa_less_logins (MFAUsed = 'No') is a direct indicator of account compromise or phishing; a sustained rise in MFA-less logins should trigger an immediate review of IAM authentication policies. MITRE ATT&CK: TA0001 Initial Access. |
| 3 | Failed -> Success Auth Sequence | Console login failures and successes per principal + source IP (DSH-93). A large failure_count paired with a non-zero success_count indicates a brute force / password spray that eventually succeeded — treat the success as the compromise point and pivot on the source IP. MITRE ATT&CK: T1110 Brute Force. |
| 4 | Login Activity Heatmap (Hour x Day) | Console login counts as a heatmap of hour-of-day (X) by day-of-week (Y) in JST (DSH-19).  Bright cells in late-night (22:00-06:00 JST) columns or weekend rows are a strong indicator of account compromise or credential misuse. MITRE ATT&CK: TA0001 Initial Access. |
| 5 | Root Account Usage | All API calls made by the AWS Root account (DSH-13). Root account usage should be extremely rare in well-governed environments. Any Root activity — especially CreateAccessKey, ConsoleLogin, or StopLogging — is a critical indicator of compromise or policy violation. |
| 6 | IAM Entity Activity | Top 50 IAM entities ranked by total API calls, with write ratio and error breakdowns (DSH-03). Entities with a high write_ratio_pct or error_events relative to total_events may indicate credential abuse or privilege escalation. last_seen shows the most recent activity timestamp for each entity. |
| 7 | IAM Privilege Change Event Timeline | Daily counts of privilege-escalation API calls broken down by event name (DSH-30). A spike on a single day indicates a targeted attack campaign; a slow increase may indicate an insider threat or an attacker with a persistent foothold. MITRE ATT&CK: TA0004 Privilege Escalation. |
| 8 | New IAM Principal Creation Timeline | Daily IAM principal and credential creation events, stacked by event type (DSH-95).  A spike in CreateAccessKey / CreateLoginProfile / CreateUser is a persistence indicator following initial access — correlate with the acting principal and source IP. MITRE ATT&CK: T1136 Create Account / T1098 Account Manipulation. |
| 9 | Glue & SageMaker IAM Role Pass Events | Glue DevEndpoint and SageMaker Notebook events used for IAM privilege escalation (DSH-50). iam:PassRole + glue:CreateDevEndpoint creates an SSH-accessible Python/Spark environment with the passed role's full permissions. iam:PassRole + sagemaker:CreateNotebookInstance provides a Jupyter notebook with the same effect. sagemaker:CreatePresignedNotebookInstanceUrl alone can grant access to an existing notebook without owning the underlying role. Both are documented in the AWS-IAM-Privilege-Escalation repository and implemented in Pacu's iam__privesc_scan module. MITRE ATT&CK: TA0004 Privilege Escalation. |
| 10 | AssumedRole from External IP | AssumedRole API calls originating from public (non-private) IP addresses (DSH-27). EC2 instance metadata service (IMDS) credentials are normally used only from within the VPC.  Calls from external IPs indicate that temporary credentials have been leaked — typically via SSRF, container escape, or key export. MITRE ATT&CK: TA0008 Lateral Movement / TA0006 Credential Access. |
| 11 | Cross-Account AssumeRole | AssumeRole / AssumeRoleWithWebIdentity calls where recipient_account_id differs from the caller's account (DSH-94).  Unexpected external account IDs indicate trusted-relationship abuse or lateral movement across accounts — verify each destination account is an approved trust. MITRE ATT&CK: T1199 Trusted Relationship / TA0008 Lateral Movement. |
| 12 | Secrets Access Anomaly | Identities accessing Secrets Manager or SSM Parameter Store ≥10 times in one hour (DSH-23).  Bulk credential reads are a post-exploitation indicator: attackers harvest stored secrets to pivot to other services or accounts. MITRE ATT&CK: TA0006 Credential Access / TA0010 Exfiltration. |
| 13 | Security-Relevant API Calls | Invocations of known security-sensitive AWS API actions (DSH-12). Covers IAM credential changes, policy modifications, S3 bucket policy changes, security group modifications, key management, STS token operations, security service disabling, Secrets Manager reads, and Organizations management. These calls should be rare in normal operations; unexpected occurrences may indicate privilege escalation, persistence, or data exfiltration. |
| 14 | IAM Identity Center (SSO) Events | AWS IAM Identity Center management events (DSH-44) from sso.amazonaws.com, sso-directory.amazonaws.com, sso-oauth.amazonaws.com, and identitystore.amazonaws.com. Identity Center is the primary authentication path in multi-account organizations. Key threats: CreatePermissionSet (backdoor admin access), CreateAccountAssignment (assigning accounts to attacker-controlled users), and AttachManagedPolicyToPermissionSet (privilege escalation). MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence / TA0004 Privilege Escalation. |
| 15 | IAM Entity Deletion | Deletion of IAM users, roles, policies, and MFA devices used to erase traces of attacker-created identities or lock defenders out. Threat Technique Catalog for AWS: T1070.A001. |
| 16 | AssumeRoot Usage | sts:AssumeRoot calls from the management account into member-account root — a full member-account takeover path. Threat Technique Catalog for AWS: AT1669. |
| 17 | Role Chaining (Session → Role) | Role-chain hops — an assumed-role session assuming a further role. Depth is the signal: a session that assumes a role which assumes another role is moving laterally, not doing its job. Requires the promoted session_issuer_arn column. |
| 18 | Session Credential Trace (ASIA keys) | What each temporary STS session did, keyed by its ASIA access key: call count, distinct APIs, source IPs, regions and time span. A session spanning several source IPs is the one to pull apart first. |
| 19 | API Calls Without MFA | Write calls made by a session that was not MFA-authenticated. Unlike the MFA-less Console Logins card this covers every API call, not just ConsoleLogin. |
| 20 | Federated Console Logins by Provider & Origin | Console logins brokered by an external identity provider, with the provider name, country and ASN. When the IdP is the compromised component AWS sees only a valid login. |
| 21 | Identity Center Permission Set Grants | Daily IAM Identity Center privilege grants by event name. A permission set is organisation-wide: one assignment can grant admin in an account the actor never touched directly. |

### 🚨 High-Risk API Monitor

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | Security Service Modification API Events | Detailed event log for APIs used to disable or tamper with audit controls (HRM-44). Covers: DeleteTrail, StopLogging, UpdateTrail, PutEventSelectors (CloudTrail tampering), DeletePolicy and DetachPolicy (removing IAM guardrails). Any occurrence outside a sanctioned change window warrants immediate investigation. MITRE ATT&CK: TA0005 Defense Evasion. |
| 2 | Credential Retrieval API Events | Detailed event log for APIs used to retrieve secrets and credentials (HRM-45). Covers: GetSecretValue (Secrets Manager), GetParameter / GetParameterHistory (SSM). A single call may be legitimate; dozens of unique secrets accessed in rapid succession is a strong attacker signal. MITRE ATT&CK: TA0006 Credential Access. |
| 3 | Top High-Risk API Calls | API actions from the high-risk watchlist ranked by total call count (HRM-40). Frequent presence of reconnaissance APIs (ListUsers, GetCallerIdentity) is expected in many environments; focus investigation on credential-access and defense-evasion APIs that appear with unusual volume or from unexpected principals. |
| 4 | Top Actors — High-Risk APIs | IAM principals ranked by total calls to high-risk watchlist APIs (HRM-42). Cross-reference with the attack-category chart to see what actions each principal is performing.  Service roles making frequent AssumeRole calls are expected; human users calling GetSecretValue or DeleteTrail in bulk are not. |
| 5 | High-Risk API Events Over Time | Daily call volume for APIs commonly observed in attack campaigns (HRM-39). A sudden spike in normally rare actions such as DeleteTrail or GetSecretValue warrants immediate investigation.  Note that many of these APIs are also called in legitimate workflows — use volume anomalies as the primary signal, not mere presence. MITRE ATT&CK: TA0001 / TA0003 / TA0004 / TA0005 / TA0006 / TA0007 / TA0008. |

### 📊 API Activity

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | Top 20 API Calls | The 20 most frequently called AWS API actions (DSH-02). High call counts for sensitive actions (e.g. AssumeRole, GetSecretValue) may indicate automated tooling or reconnaissance. |
| 2 | Top Access Denied Actions | Top 20 API actions that returned AccessDenied or Client.UnauthorizedAccess errors (DSH-09). Repeated access-denied events against sensitive APIs (e.g. AssumeRole, GetSecretValue, PutBucketPolicy) are strong indicators of privilege escalation attempts or lateral movement. |
| 3 | Region Activity | Distribution of CloudTrail events across AWS regions (DSH-14). write_ratio_pct highlights regions with disproportionate write activity — unexpected regions with high write ratios may indicate crypto-mining EC2 instances, lateral movement, or data exfiltration to less-monitored regions. |
| 4 | Error-Code Composition Over Time | Daily CloudTrail error volume, stacked by error_code (DSH-96).  A rising AccessDenied / UnauthorizedOperation band indicates reconnaissance or privilege probing; Throttling spikes suggest enumeration at scale. MITRE ATT&CK: TA0007 Discovery. |
| 5 | Top Source IP Addresses | Top 100 external source IPs by request count (DSH-05). Excludes AWS-internal IP patterns (*.amazonaws.com). IPs with high write_requests relative to request_count may indicate exfiltration, lateral movement, or automated attack tooling. |
| 6 | User Agent Analysis | Top 50 user agents by request count with error and write breakdowns (DSH-11). Unusual or custom user agents (e.g. Python/boto3, custom scripts, Pacu, ScoutSuite) may indicate automated attack tooling. AWS internal agents (console.amazonaws.com, signin.amazonaws.com) are expected; unknown strings warrant investigation. |

### 🪣 S3 & RDS

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | S3 High-Volume Object Downloads | S3 bulk GetObject calls (DSH-52): identities that performed >=100 GetObject requests in a single hour, grouped by hour bucket, identity, and source IP. High-volume reads indicate automated data exfiltration — attackers dump bucket contents before destroying or ransoming them.  Combine with the S3 Bulk Deletion chart to identify the full ransomware chain: exfiltrate then destroy. MITRE ATT&CK: TA0010 Exfiltration. |
| 2 | S3 Bulk Object Deletion | S3 bulk DeleteObject/DeleteObjects calls (DSH-53): identities that deleted >=50 objects in a single hour, grouped by hour bucket, identity, and source IP. High-volume deletions are the data destruction phase of a ransomware attack — the attacker exfiltrates first (see S3 Bulk Download chart), then wipes the source bucket to extort the victim.  Also covers accidental mass-deletion. MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction. |
| 3 | S3 Versioning / Logging Disabled | S3 versioning suspension and logging disable events (DSH-54): PutBucketVersioning with Status=Suspended and PutBucketLogging with an empty BucketLoggingStatus.  Attackers disable versioning to prevent object recovery after deletion, and disable logging to erase the access evidence trail. Both are anti-forensics precursors to data destruction. MITRE ATT&CK: TA0005 Defense Evasion / T1070 Indicator Removal. |
| 4 | S3 Cross-Account Replication | S3 cross-account replication configuration events (DSH-55): PutBucketReplication and DeleteBucketReplication. Cross-account replication silently copies every new object into an attacker-controlled bucket, establishing a persistent exfiltration channel that bypasses network DLP controls.  Any PutBucketReplication pointing to an external account ID is a critical incident indicator. MITRE ATT&CK: TA0010 Exfiltration / T1537 Transfer Data to Cloud Account. |
| 5 | S3 Bucket Policy / ACL Changes | S3 bucket policy and ACL modification events (DSH-45): PutBucketPolicy, DeleteBucketPolicy, PutBucketAcl, PutBucketCors, PutBucketWebsite, and DeleteBucketWebsite. These changes can expose bucket contents publicly or grant access to attacker-controlled accounts. PutBucketPolicy with Principal='*' is an immediate data exposure indicator. MITRE ATT&CK: TA0010 Exfiltration / TA0005 Defense Evasion. |
| 6 | S3 Bucket & Object List Activity | S3 enumeration API calls grouped by identity and source IP (DSH-74). Covers ListBuckets (full-account discovery), ListObjects / ListObjectsV2 (per-bucket enumeration), ListObjectVersions, ListMultipartUploads, HeadBucket, and HeadObject. A sudden spike in list calls from a new identity or external IP strongly suggests reconnaissance following credential compromise. MITRE ATT&CK: TA0007 Discovery. |
| 7 | S3 Protection Config Changes | S3 events that weaken bucket security posture (DSH-25). Disabling server-access logging removes the audit trail; removing the public- access block exposes data to the internet; deleting bucket encryption or replication weakens data-at-rest protection.  These are pre-exfiltration or cover-up actions. MITRE ATT&CK: TA0005 Defense Evasion / TA0040 Impact. |
| 8 | AWS Backup Vault & Plan Deletion Events | AWS Backup Vault, Plan, and Recovery Point deletion events (DSH-57): DeleteBackupVault, DeleteBackupPlan, DeleteRecoveryPoint, DeleteBackupSelection, DisassociateRecoveryPoint, PutBackupVaultAccessPolicy, and DeleteBackupVaultLockConfiguration. Destroying backups is the first step in a ransomware campaign — it ensures the victim cannot restore from backups before the ransom demand is made. Vault Lock deletion (DeleteBackupVaultLockConfiguration) is especially critical as it removes WORM immutability from the vault. MITRE ATT&CK: TA0040 Impact / T1490 Inhibit System Recovery. |
| 9 | KMS Key Deletion & Disable Events | KMS key deletion, disabling, and rotation management events (DSH-66). ScheduleKeyDeletion — schedules key deletion (7-30 day window to cancel). DisableKey — immediately stops encryption/decryption with the key. DeleteImportedKeyMaterial — destroys the key material for imported keys instantly. DisableKeyRotation — prevents automatic annual key rotation. Any of these events renders all data encrypted under the key permanently inaccessible.  Use CancelKeyDeletion to reverse ScheduleKeyDeletion before the deletion date. MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction. |
| 10 | RDS Deleted without Final Snapshot | RDS instance and cluster deletion with skipFinalSnapshot=true (DSH-56): DeleteDBInstance and DeleteDBCluster events where no final snapshot was taken. Skipping the final snapshot makes the database irrecoverable — no restore point exists after deletion.  Ransomware actors use this to maximise victim pressure when AWS Backup has also been disabled.  Any event here is a critical incident. MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction. |
| 11 | RDS Snapshot Cross-Account Share | RDS and Aurora snapshot sharing events (DSH-40): ModifyDBSnapshotAttribute and ModifyDBClusterSnapshotAttribute where restore permission was granted to another AWS account (valuesToAdd).  Attackers share snapshots to their own account to exfiltrate an entire database without S3/network-based DLP. Any external account ID in the restore attribute is a critical exfiltration indicator. MITRE ATT&CK: TA0010 Exfiltration. |
| 12 | S3 SSE-C Ransomware Encryption | S3 objects re-encrypted with attacker-supplied SSE-C keys plus bucket default-encryption changes — cloud-native ransomware. Threat Technique Catalog for AWS: T1486.A001. |
| 13 | S3 Lifecycle-Triggered Deletion | S3 lifecycle rules that expire objects (and lifecycle-config deletion) used to silently purge data without DeleteObject bursts. Threat Technique Catalog for AWS: T1485.001. |
| 14 | RDS Query & Instance Manipulation | RDS Data API queries and snapshot restores used to read data directly or restore into an attacker-controlled instance. Threat Technique Catalog for AWS: AT1023.001 / T1213.A013. |
| 15 | Storage Re-Encryption for Impact | EBS/RDS snapshots and volumes re-encrypted with an explicit attacker-controlled KMS key, plus default-encryption disable. Threat Technique Catalog for AWS: T1486.A002 / T1486.A003. |
| 16 | Data Access Scope (Breach Notification) | Per principal: S3 read calls, distinct buckets and approximate distinct objects. Produces the 'approximate number of records' figure GDPR Article 33 requires. Needs CloudTrail data events on the buckets. |
| 17 | Cross-Account Object Copy | S3 CopyObject calls and PutObject calls carrying an x-amz-copy-source header, with source and destination. The replication charts cover configuration; this covers the individual copies. |
| 18 | Ransom Note Placement | PutObject calls whose object key looks like a ransom note. Unlike the other ransomware panels this confirms impact rather than suggesting it — any row here is a P1. |

### 🖥️ Computing

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | EC2 Instance Launches | All EC2 RunInstances events (DSH-58). Attackers launch instances for crypto mining (GPU/spot), C2 relay, or lateral movement staging — often in unexpected regions to avoid detection. Filter by aws_region for region-anomaly investigation; filter by user_identity_arn to trace which credential triggered the launch. MITRE ATT&CK: TA0002 Execution / TA0040 Impact (Resource Hijacking). |
| 2 | RunInstances Spike by Region | Daily EC2 RunInstances volume, stacked by AWS region (DSH-97).  A sudden spike — particularly in regions outside normal operation — indicates cryptomining or resource abuse.  Cross-reference the acting principal and source IP. MITRE ATT&CK: T1496 Resource Hijacking. |
| 3 | EC2 Mass Stop / Terminate | EC2 StopInstances and TerminateInstances events (DSH-62). A single API call can stop or terminate dozens of instances simultaneously. Mass termination is the destructive phase of a ransomware or sabotage attack — taking down production EC2 capacity.  Check the request_parameters field for the full list of affected instanceIds.  Pair with AWS Backup Tampering and S3 Bulk Deletion charts to identify the full ransomware chain. MITRE ATT&CK: TA0040 Impact / T1489 Service Stop. |
| 4 | EC2 Key Pair Creation | EC2 key pair creation and import events (DSH-59): CreateKeyPair, ImportKeyPair, DeleteKeyPair. Attackers create new key pairs to establish persistent SSH access to EC2 instances that survive IAM credential rotation.  ImportKeyPair injects an attacker-controlled public key directly without AWS generating it. Any CreateKeyPair or ImportKeyPair from an unfamiliar identity or IP is a persistence indicator. MITRE ATT&CK: TA0003 Persistence. |
| 5 | EC2 Instance Profile Changes | EC2 instance profile and IAM instance profile management events (DSH-60). IAM: CreateInstanceProfile, DeleteInstanceProfile, AddRoleToInstanceProfile, RemoveRoleFromInstanceProfile. EC2: AssociateIamInstanceProfile, DisassociateIamInstanceProfile, ReplaceIamInstanceProfileAssociation. Changing an instance profile replaces the IAM role available to all code on the instance — a common privilege escalation path when the attacker controls an instance but wants a higher-privilege role. MITRE ATT&CK: TA0004 Privilege Escalation / TA0003 Persistence. |
| 6 | EC2 User Data Modification | EC2 user data modification events (DSH-61): ModifyInstanceAttribute where the userData attribute is changed.  EC2 user data is executed by cloud-init on every instance (re)start — injecting a malicious script provides persistent code execution that survives reboots.  Often paired with a stop/start sequence (see EC2 Mass Stop / Terminate chart) to trigger execution. MITRE ATT&CK: TA0003 Persistence / TA0002 Execution. |
| 7 | EC2 Public Snapshot / AMI Sharing | EC2 EBS snapshot and AMI public-sharing events (DSH-41): ModifySnapshotAttribute with createVolumePermission granted to group 'all', and ModifyImageAttribute with launchPermission granted to group 'all'. A public snapshot or AMI allows any AWS account to copy the disk image and extract sensitive data, credentials, and private keys stored on the volume. MITRE ATT&CK: TA0010 Exfiltration. |
| 8 | EC2 Spot Fleet & Reserved Instance Purchases | EC2 Spot Fleet, Fleet, and Reserved Instance purchase events (DSH-63): RequestSpotFleet, ModifySpotFleetRequest, CancelSpotFleetRequests, CreateFleet, DeleteFleet, PurchaseReservedInstancesOffering, RequestSpotInstances, CancelSpotInstanceRequests. Attackers use Spot Fleets to launch large GPU/CPU clusters for crypto mining, generating high AWS bills while staying under per-instance detection thresholds. Any unexpected Spot Fleet or Reserved Instance purchase warrants investigation. MITRE ATT&CK: TA0040 Impact / T1496 Resource Hijacking. |
| 9 | ECS Task Definition & Service Changes | ECS task definition registration and service modification events (DSH-49). Pacu's ecs__backdoor_task_def registers a new task definition revision that injects a credential-stealing sidecar container, then issues UpdateService to deploy it — bypassing ECR image monitoring entirely. Any unexpected RegisterTaskDefinition or UpdateService from an unfamiliar caller or IP warrants immediate investigation. MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0006 Credential Access. |
| 10 | Lambda Function Configuration & Permission Changes | Lambda function creation, code update, and permission events (DSH-64). UpdateFunctionCode replaces function code with a malicious payload. AddPermission grants cross-account or public Lambda invocation access. CreateFunctionUrlConfig creates a public HTTP endpoint for direct C2. CreateEventSourceMapping wires the function to trigger on S3/DynamoDB/SQS. PublishLayerVersion injects a malicious shared layer across multiple functions. Any of these from an unexpected identity or IP is a persistence/execution indicator. MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0011 Command and Control. |
| 11 | SSM Session / Run Command Execution | AWS Systems Manager remote-execution events (DSH-39): StartSession, TerminateSession, ResumeSession, SendCommand, and StartAutomationExecution. SSM Session Manager provides shell access without open SSH/RDP ports and is the primary lateral-movement mechanism for attackers with stolen IAM credentials. Any unexpected session or command from an unusual IP or identity warrants immediate investigation. MITRE ATT&CK: TA0008 Lateral Movement / TA0002 Execution. |
| 12 | EBS Direct API Snapshot Block Access | EBS Direct API calls used to exfiltrate snapshot data (DSH-51). Pacu's ebs__download_snapshots uses ListSnapshotBlocks and GetSnapshotBlock to stream a complete EBS disk image block-by-block without creating an EC2 instance, requesting a snapshot copy, or triggering a ModifySnapshotAttribute event — making it invisible to traditional snapshot-sharing detection. Any GetSnapshotBlock or ListSnapshotBlocks call from an unexpected identity or IP address is a critical exfiltration indicator. MITRE ATT&CK: TA0010 Exfiltration / TA0009 Collection. |
| 13 | EKS / ECR Container Platform Events | EKS cluster and ECR container registry events (DSH-48). EKS: UpdateClusterConfig (public API), CreateFargateProfile (malicious workloads), AssociateIdentityProviderConfig (rogue OIDC IdP). ECR: PutImage (backdoored image push), SetRepositoryPolicy (cross-account access), PutRegistryPolicy (org-wide registry exposure). Container platform events are critical for detecting supply-chain attacks and Kubernetes control-plane compromise. MITRE ATT&CK: TA0002 Execution / TA0003 Persistence / TA0010 Exfiltration. |
| 14 | CloudFormation Stack Changes | CloudFormation stack and change-set management events (DSH-65). A single UpdateStack can deploy EC2 instances, modify IAM roles, or reconfigure networking — consolidating dozens of individual API calls into one event. CreateStackSet deploys attacker infrastructure across all accounts in an org. ExecuteChangeSet applies a pre-staged change, hiding the blast radius from initial review.  DeleteStack can destroy forensic evidence resources. MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0005 Defense Evasion. |
| 15 | IMDS Options Weakening | ModifyInstanceMetadataOptions calls that make IMDSv2 optional or re-enable the metadata endpoint, re-opening SSRF credential theft. Threat Technique Catalog for AWS: T1552.005. |
| 16 | AMI & Snapshot Deletion | Deregistration of AMIs and deletion of EBS snapshots that destroy the recovery baseline during a destructive attack. Threat Technique Catalog for AWS: T1485.A002. |
| 17 | WorkSpaces Hijacking | Amazon WorkSpaces provisioning used for compute hijacking outside the EC2 security boundary. Threat Technique Catalog for AWS: T1496.A009. |

### 🤖 AI / LLM

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | Bedrock Model Invocation Trend | Daily Amazon Bedrock model invocation volume per principal (DSH-98). High-volume inference on stolen credentials (LLMjacking) is resold through reverse proxies at the victim's expense.  Investigate any spike, any principal that has never invoked Bedrock before, and any invocation from an unexpected origin. MITRE ATT&CK: TA0040 Impact (T1496 Resource Hijacking). |
| 2 | Bedrock Model Access & Logging Changes | Foundation-model access enablement and invocation-logging tampering (DSH-99).  Attackers with stolen credentials self-enable Bedrock model access before abusing it, and check or delete the model-invocation logging configuration so their prompts are not recorded — both documented LLMjacking indicators.  Any row in an org that never adopted Bedrock warrants immediate investigation. MITRE ATT&CK: TA0005 Defense Evasion / TA0040 Impact (T1496). |
| 3 | Bedrock Failed Invocations | Failed Amazon Bedrock invocation attempts grouped by caller and error code (DSH-100).  Bursts of AccessDenied / ValidationException errors across multiple models and regions indicate an attacker probing which models a stolen key can invoke — the reconnaissance phase of LLMjacking. MITRE ATT&CK: TA0006 Credential Access / TA0007 Discovery. |
| 4 | Bedrock Callers by Origin | Inventory of all Amazon Bedrock callers with origin and model diversity (DSH-101).  Baseline view for LLMjacking triage: principals calling from unexpected countries, hosting/VPN ASNs, or generic scripting user agents (python-requests, curl) with high call volume are prime suspects. MITRE ATT&CK: TA0040 Impact (T1496 Resource Hijacking). |
| 5 | AgentCore Token Issuance (Daily) | Daily AgentCore token-vault issuance by operation. These calls hand out third-party OAuth tokens and API keys, so abuse reaches services outside AWS entirely. |
| 6 | AgentCore Gateway & Policy Changes | AgentCore Gateway, target and policy changes, surfacing the Cedar policy engine mode. An engine moved from ENFORCE to LOG_ONLY still returns success, so nothing downstream looks wrong. |

### 🌐 Network

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | Security Group Changes | EC2 security group rule changes (DSH-76). Covers inbound/outbound rule authorization and revocation, security group creation and deletion, and rule description updates. Ingress rules opened to 0.0.0.0/0 on administrative ports (22, 3389, etc.) are a strong indicator of backdoor access or misconfiguration. MITRE ATT&CK: TA0003 Persistence / TA0005 Defense Evasion. |
| 2 | Network ACL / Route Table Changes | Network ACL and route table modification events (DSH-46). NACL changes (CreateNetworkAclEntry, DeleteNetworkAclEntry, ReplaceNetworkAclEntry) can bypass security group restrictions for entire subnets. Route table changes (CreateRoute, ReplaceRoute, DeleteRoute) can redirect traffic to attacker-controlled infrastructure for interception or establish silent C2 communication channels. MITRE ATT&CK: TA0005 Defense Evasion / TA0011 Command and Control. |
| 3 | VPC Infrastructure Changes | VPC topology change events (DSH-77). Covers VPC creation/deletion/modification, subnet changes, internet gateway attachment, NAT gateway creation/deletion, VPC endpoint changes, and Elastic IP allocation/association. Unexpected IGW attachments or new NAT gateways in unused regions are strong indicators of attacker-controlled exfiltration infrastructure. MITRE ATT&CK: TA0010 Exfiltration / TA0003 Persistence / TA0011 C2. |
| 4 | VPC Peering & Transit Gateway Changes | VPC peering connection and Transit Gateway change events (DSH-78). Covers VPC peering creation/acceptance/deletion and Transit Gateway creation, VPC attachment, and peering attachment management. Cross-account peering requests or new Transit Gateway attachments from unexpected accounts indicate lateral movement between AWS accounts. MITRE ATT&CK: TA0008 Lateral Movement / TA0010 Exfiltration. |
| 5 | Route53 DNS Changes | Route 53 hosted-zone and resolver configuration changes (DSH-29). DNS tunnelling uses TXT/CNAME records and large numbers of subdomains to exfiltrate data in DNS query payloads.  New hosted zones and unexpected ChangeResourceRecordSets calls should be investigated immediately. MITRE ATT&CK: TA0010 Exfiltration. |

### 🕒 Temporal Analysis

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | Event Velocity Spikes per Identity | Identities with 50+ events per hour burst activity periods (DSH-38). Credential stuffing, automated enumeration, or data exfiltration create sharp velocity spikes above normal baselines.  Shows the hour bucket, identity, and event count for each spike. MITRE ATT&CK: TA0006 Credential Access / TA0009 Collection / TA0010 Exfiltration. |
| 2 | Dormant Accounts Reactivated | Identities with inactivity gaps of 72+ hours that resumed activity (DSH-37). A classic pattern of compromised dormant credentials being weaponized. Shows the maximum gap in hours/days between consecutive events per identity. MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence. |
| 3 | First / Last Seen per IAM Identity | IAM identities with first/last seen timestamps, event counts, distinct APIs, distinct IPs, and active span in days (DSH-31).  Sort by first_seen DESC to find newly appeared identities.  Short active spans with high event counts signal compromised credentials or automated attacks. MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence. |
| 4 | First / Last Seen per Source IP | Source IPs with first/last seen, distinct identities, distinct APIs, and GeoIP context (DSH-32).  New IPs appearing late in the dataset suggest lateral movement or new attacker infrastructure. MITRE ATT&CK: TA0001 Initial Access / TA0008 Lateral Movement. |
| 5 | First / Last Seen per API Call | API actions ordered by first appearance (DSH-33).  New API calls appearing for the first time suggest reconnaissance or privilege escalation attempts. MITRE ATT&CK: TA0007 Discovery / TA0004 Privilege Escalation. |
| 6 | First / Last Seen per Service Source | First and last seen timestamps for every distinct AWS service source (DSH-26). Sort by first_seen DESC to surface newly introduced services (potential attacker infrastructure).  Sort by last_seen ASC to find services that have gone silent (possible cleanup after compromise). MITRE ATT&CK: TA0003 Persistence / TA0007 Discovery. |
| 7 | Off-Hours Write Activity (Hour x Day) | Write-event counts as a heatmap of hour-of-day by day-of-week in JST. The login heatmap covers ConsoleLogin only; this covers every mutating call, which is where bulk off-hours access shows up. |
| 8 | Principal Daily Volume (Read vs Write) | Daily call volume per principal, split into reads and writes. Judge each principal against itself: a build role making ten thousand calls a day is normal, a human making two hundred is not. |

### 🌍 GeoIP Intelligence

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | Impossible Travel (Multi-Country Principals) | IAM principals ranked by distinct source countries, with distinct source IPs, total events, and first/last seen (DSH-92).  distinct_countries >= 2 for a human principal is a strong account-compromise signal — cross-reference the time window and source IPs.  Requires GeoIP enrichment. MITRE ATT&CK: TA0001 Initial Access / T1078 Valid Accounts. |
| 2 | Top Countries by Request Volume | Top 20 source countries by API call volume, with write-event and unique-caller breakdowns (DSH-15). Countries not normally associated with the organisation's operations may indicate credential theft or attacker-controlled infrastructure. Requires GeoLite2 enrichment — NULL rows are excluded automatically. |
| 3 | Top ASN Organizations by Request Volume | Top 25 ASN organizations by API call volume with write-event and unique-caller breakdowns (DSH-18). Traffic originating from VPN providers, Tor exit nodes, hosting companies, or cloud providers outside the expected footprint may indicate attacker use of anonymisation infrastructure. Requires GeoLite2 enrichment — NULL rows are excluded automatically. |
| 4 | Top Cities by Request Volume | Top 25 cities by API call volume with write-event and unique-caller breakdowns (DSH-17). City-level granularity can reveal specific data centre locations used by threat actors that would be obscured by country-level analysis alone. Requires GeoLite2 enrichment — NULL rows are excluded automatically. |
| 5 | Global Request Origin Map | World map showing the geographic distribution of CloudTrail API call origins (DSH-16). Country colour intensity is proportional to event count. Countries not normally associated with the organisation's operations may indicate credential theft or attacker-controlled infrastructure. Requires GeoLite2 enrichment — NULL rows are excluded automatically. |
| 6 | API Calls by Country (Event Name × GeoIP) | Top 50 (event_name, country) pairs by API call volume (DSH-79). Reveals which API operations are being called from each geographic region. Write operations from unexpected countries are a strong indicator of credential compromise. Requires GeoLite2 enrichment — private/internal IPs and NULL rows are excluded. |

</details>

---
