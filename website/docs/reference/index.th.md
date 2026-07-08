# เอกสารอ้างอิง Query และ Dashboard ในตัว

> 💡 ไม่ต้องใช้ SQL หรือความรู้เชิงลึกเกี่ยวกับ AWS — เพียงเลือก hunt จาก dropdown แล้วรับผลลัพธ์ได้ทันที

## 🎯 Hunts ในตัว — มากกว่า 100 queries

หมวดหมู่ถูกจัดเรียงตามลำดับความสำคัญของการ triage แบบ DFIR — ตรวจสอบการดัดแปลงเครื่องมือตรวจจับก่อน จากนั้นจึงตรวจสอบการใช้อัตลักษณ์ในทางมิชอบ แล้วตามด้วยผลกระทบต่อข้อมูล

| หมวดหมู่ | Queries | ภัยคุกคามสำคัญที่ครอบคลุม |
|----------|:-------:|---------------------|
| 🛡 Detection & Response | 12 | การดัดแปลง audit-service (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · การลบ SCP · การระงับสัญญาณเตือน · การลักลอบนำ log ออก |
| 🔑 Identity & Access | 26 | การใช้งาน root · การล็อกอินคอนโซล/MFA · การยกระดับสิทธิ์ · backdoor ผ่าน trust policy · การใช้ PassRole ในทางมิชอบ · AssumeRole ข้ามบัญชี · SSO/SAML/OIDC · การแจกแจง credential |
| 🪣 Data & Storage | 21 | การลบ/ดาวน์โหลด S3 จำนวนมาก · การอ่าน secrets จำนวนมาก · การดัดแปลง backup · การดำเนินการ KMS · การแชร์ snapshot · การลักลอบนำข้อมูลออกผ่าน EBS Direct API · การ export DynamoDB · การ replicate S3 ข้ามบัญชี |
| ⚡ Compute & Serverless | 14 | การหยุด/ยกเลิก EC2 จำนวนมาก · การเคลื่อนตัวด้านข้างผ่าน SSM · การดัดแปลง Lambda/ECS/EKS/ECR · การคงอยู่ผ่าน EventBridge · cryptomining · การใช้ Lightsail ในทางมิชอบ |
| 🌐 Network & Infrastructure | 14 | SG เปิดสู่อินเทอร์เน็ต · การลบ VPC flow log · การยึด CloudFront · อุโมงค์ VPN/TGW แอบแฝง · Elastic IP สำหรับ C2 · คีย์ API Gateway |
| 🕵 Threat Patterns | 5 | การเขียนนอกเวลาทำการ · การ recon แบบรัวเร็ว · การกระจายข้ามหลายภูมิภาค · user agents ที่ผิดปกติ · การเรียก API ครั้งแรก |
| 📊 Activity & Baseline | 3 | เหตุการณ์การเขียนผ่านคอนโซล · การพุ่งขึ้นของ error · error ล่าสุด |
| 🌍 GeoIP Analysis ✦ | 12 | การเดินทางที่เป็นไปไม่ได้ · credential หลายประเทศ · การล็อกอิน/การปฏิเสธ/การเขียนจัดอันดับตามภูมิศาสตร์ · การแยกย่อยตามประเทศ/เมือง/ASN · event_name × country · identity × country |
| ☁ IaC & Platform | 2 | การโจมตี supply chain ของ CI/CD · การใช้ CloudFormation ในทางมิชอบ |

<details markdown="1">
<summary>📋 รายการทั้งหมด — ทุก queries มากกว่า 100 รายการ (คลิกเพื่อขยาย)</summary>

## Hunts ในตัว

### 🛡 Detection & Response

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | ตรวจจับความพยายามใด ๆ ที่จะหยุดหรือแก้ไข CloudTrail — ตัวบ่งชี้การปกปิดที่สำคัญที่สุด |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | ตรวจจับการปิดใช้งาน การลบ และการบิดเบือน threat-intel ของ GuardDuty |
| 3 | ⛔ Security Hub Tampering | timeseries | ตรวจจับการปิดใช้งาน Security Hub การปิดใช้งาน standard และการระงับ finding |
| 4 | ⚙️ AWS Config Tampering | timeseries | ตรวจจับการลบ recorder/rule ของ AWS Config (ขจัดหลักฐานการปฏิบัติตามข้อกำหนด) |
| 5 | 🛡 Organizations SCP Changes | timeseries | ตรวจจับการสร้าง การอัปเดต และการลบ SCP — การลบ Deny SCP จะขจัด guardrails ในทุกบัญชีของ OU |
| 6 | 🚫 AWS Macie Tampering | timeseries | ตรวจจับการปิดใช้งาน Macie และการสร้าง finding-filter (การหลบเลี่ยงการป้องกันก่อนการลักลอบนำข้อมูลออก) |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | ตรวจจับการลบ alarm และ DisableAlarmActions — ปิดเสียงการแจ้งเตือนด้านความปลอดภัยโดยไม่ลบ alarm |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | ตรวจจับการสร้าง/ลบ subscription filter ของ CW Logs (การลักลอบนำ log ออกแบบเรียลไทม์ไปยัง Kinesis/Lambda ของผู้โจมตี) |
| 9 | 🏹 WAF WebACL Changes | timeseries | ตรวจจับการสร้าง การอัปเดต และการลบ WAF WebACL ทั่วทั้ง WAFv2/WAF Classic |
| 10 | 🔍 GuardDuty Findings Read | timeseries | ตรวจจับ ListFindings / GetFindings — ผู้โจมตีอ่าน finding ที่ใช้งานอยู่เพื่อเข้าใจว่า SOC ตรวจพบสิ่งใดไปแล้ว |
| 11 | 💰 Budget / Cost Anomaly Changes | timeseries | ตรวจจับการลบ Budget/AnomalyMonitor (การซ่อนค่าใช้จ่ายจาก cryptomining) |
| 12 | 🚫 Access Denied Errors | bar | จัดกลุ่ม error AccessDenied ตามอัตลักษณ์และ API — ผู้กระทำผิดอันดับต้นบ่งชี้การใช้ credential ในทางมิชอบ |

### 🔑 Identity & Access

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | ตรวจจับการเรียก API ใด ๆ ที่ทำโดยบัญชี root — ไม่ควรใช้ root ใน production เลย |
| 2 | 🔓 Console Login without MFA | timeseries | ตรวจจับการล็อกอินคอนโซลที่ไม่ได้ใช้ MFA — ตัวบ่งชี้ความเสี่ยงสูงของการถูกบุกรุกบัญชี |
| 3 | 🌐 Console Logins | timeseries | แสดงรายการความพยายามล็อกอินคอนโซลทั้งหมดรวมถึงที่สำเร็จและล้มเหลว (การตรวจจับ brute force) |
| 4 | 🔐 MFA & Password Changes | timeseries | ตรวจจับการปิดใช้งาน MFA และการรีเซ็ตรหัสผ่าน — ตัวบ่งชี้ที่ชัดเจนของการยึดบัญชี |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | ตรวจจับการแนบ IAM policy และการบิดเบือน role (PutUserPolicy, AttachRolePolicy, CreatePolicyVersion ฯลฯ) |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | ตรวจจับ UpdateAssumeRolePolicy — การเพิ่ม principal ภายนอกเข้าไปใน trust policy สร้าง backdoor แบบถาวร |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | ตรวจจับเหตุการณ์ put/delete ของ permission boundary — การลบ boundary จะขยายสิทธิ์ที่มีผลทันที |
| 8 | 👑 User Added to Admin Group | timeseries | ตรวจจับผู้ใช้ที่ถูกเพิ่มเข้ากลุ่มที่มีคำว่า 'admin' ในชื่อ — การยกระดับสิทธิ์แบบคลาสสิก |
| 9 | 👥 IAM Group Membership Changes | timeseries | ตรวจจับเหตุการณ์ AddUserToGroup / RemoveUserFromGroup / CreateGroup / DeleteGroup ทั้งหมดโดยไม่คำนึงถึงชื่อกลุ่ม |
| 10 | 👤 New IAM Users / Keys | timeseries | ระบุเหตุการณ์การสร้างผู้ใช้ IAM และ access key — การสร้างที่ไม่คาดคิดอาจบ่งชี้การคงอยู่ |
| 11 | 🎯 IAM PassRole Abuse | timeseries | ตรวจจับการใช้ iam:PassRole โดยตรวจสอบเหตุการณ์ของบริการที่รับ (RunInstances, CreateFunction, CreateNotebookInstance ฯลฯ) ที่มีการส่ง role ARN |
| 12 | 🔐 AssumeRole Cross-Account | timeseries | แสดงเหตุการณ์ AssumeRole ที่ผู้เรียกและเป้าหมายอยู่ในบัญชี AWS ต่างกัน (การเคลื่อนตัวด้านข้าง) |
| 13 | 🏢 Cross-Account Access | timeseries | ค้นหาเหตุการณ์ทั้งหมดที่บัญชีผู้เรียกต่างจากบัญชีผู้รับ |
| 14 | 🔑 STS Federation Token Issuance | timeseries | ตรวจจับ GetFederationToken และ GetSessionToken — แปลงคีย์อายุยาวให้เป็น credential ชั่วคราวแบบถาวร |
| 15 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | ตรวจจับการใช้ OIDC trust ในทางมิชอบ (sub claim ที่ตั้งค่าผิด / GitHub Actions โดยไม่มีเงื่อนไข repo) |
| 16 | 🆔 IAM Identity Center (SSO) Events | timeseries | ตรวจจับการดำเนินการจัดการ AWS IAM Identity Center (CreatePermissionSet, CreateAccountAssignment ฯลฯ) |
| 17 | 🔗 SAML / OIDC Provider Updates | timeseries | ตรวจจับการเปลี่ยนแปลง identity provider SAML/OIDC — การอัปเดต metadata ของ SAML ด้วย IdP ที่ผู้โจมตีควบคุมสร้าง backdoor การยืนยันตัวตนแบบถาวร |
| 18 | 🧐 IAM Access Analyzer Calls | timeseries | ตรวจจับการใช้ IAM Access Analyzer ใด ๆ — ผู้โจมตีใช้ analyzer ในตัวเพื่อแจกแจงทรัพยากรที่เข้าถึงได้จากภายนอกโดยไม่ต้องใช้สคริปต์ recon เอง |
| 19 | 🔄 Credential Report & Enumeration | timeseries | ตรวจจับการแจกแจง IAM (GenerateCredentialReport, ListUsers, ListRoles, GetAccountAuthorizationDetails ฯลฯ) |
| 20 | 🗝 Access Key Abuse | bar | ตรวจจับ access key ที่ใช้จาก source IP ที่แตกต่างกัน 3+ แห่งภายใน 7 วัน — ตัวบ่งชี้ที่ชัดเจนของการรั่วไหลของคีย์ |
| 21 | 📰 AWS Organizations Account Creation | timeseries | ตรวจจับการสร้างบัญชี Organizations และการเปลี่ยนแปลง delegated administrator (การคงอยู่ผ่านบัญชีเงา) |
| 22 | 👥 Cognito Unauthenticated Access | timeseries | ตรวจจับ Cognito Identity Pools ที่มี allowUnauthenticatedIdentities=true |
| 23 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | ตรวจจับการสร้าง Glue DevEndpoint (iam:PassRole + glue:CreateDevEndpoint = endpoint ที่เข้าถึงผ่าน SSH ได้ซึ่งทำงานด้วยสิทธิ์เต็มของ role ที่ส่งมา) และการแจกแจง connection เพื่อเก็บเกี่ยว credential |
| 24 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | ตรวจจับการสร้าง notebook SageMaker และการสร้าง presigned URL — iam:PassRole + sagemaker:CreateNotebookInstance เปิด environment Jupyter ด้วยสิทธิ์ AWS เต็มของ role ที่ส่งมา |
| 25 | 🛠 Data Pipeline / CodeStar Privilege Escalation | timeseries | ตรวจจับการสร้างทรัพยากร Data Pipeline และ CodeStar ที่ใช้สำหรับการยกระดับสิทธิ์ผ่าน iam:PassRole (CreateProjectFromTemplate สร้าง IAM role แบบ admin เป็นผลข้างเคียง) |
| 26 | 🧩 Step Functions Privilege Escalation | timeseries | ตรวจจับการสร้าง state machine ของ Step Functions (iam:PassRole + states:CreateStateMachine ดำเนินงาน Lambda/ECS ภายใต้ role ที่ส่งมา) |

### 🪣 Data & Storage

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | ตรวจจับอัตลักษณ์ที่เรียก DeleteObject/DeleteObjects ≥50 ครั้งต่อชั่วโมง — รูปแบบการทำลายข้อมูลจาก ransomware / wiper |
| 2 | 🔥 AWS Backup Tampering | timeseries | ตรวจจับการลบ Backup Vault / Plan / RecoveryPoint และการลบ Vault Lock — ขั้นตอนแรกของ ransomware เพื่อขจัดทางเลือกในการกู้คืน |
| 3 | 🔓 KMS Key Operations | timeseries | ระบุการดำเนินการ KMS ที่ละเอียดอ่อน (DisableKey, ScheduleKeyDeletion, CreateGrant, PutKeyPolicy, Decrypt ปริมาณสูง) |
| 4 | 🔓 S3 Public Access Block Disabled | — | ตรวจจับการปิดใช้งานการตั้งค่า public access block ของ S3 — ความเสี่ยงในการเปิดเผยข้อมูลทันที |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | ตรวจจับการแก้ไข policy และ ACL ของ S3 bucket (PutBucketPolicy ที่มี Principal='*' สำคัญเป็นพิเศษ) |
| 6 | 🪣 S3 Data Access Anomalies | bar | ตรวจจับการเรียก GetObject จำนวนมาก (≥100/ชั่วโมง) — รูปแบบการลักลอบนำข้อมูลออกแบบอัตโนมัติ |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | ตรวจจับอัตลักษณ์ที่ดึง secret ที่แตกต่างกัน ≥10 รายการในหนึ่งชั่วโมง — สัญญาณการเก็บเกี่ยว credential |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | ตรวจจับการลบ secret, PutResourcePolicy (การแชร์ข้ามบัญชี) และ CancelRotateSecret |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | ตรวจจับอัตลักษณ์ที่อ่าน parameter ≥20 รายการในหนึ่งชั่วโมง — ช่องทางการลักลอบนำข้อมูลออกที่มักถูกมองข้าม |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | ตรวจจับ snapshot ของ RDS/Aurora ที่แชร์ไปยังบัญชี AWS ภายนอก (การลักลอบนำฐานข้อมูลออกผ่าน snapshot) |
| 11 | 💣 RDS Deleted without Final Snapshot | — | ตรวจจับการลบ RDS ที่มี skipFinalSnapshot=true — อาจเป็นการทำลายข้อมูล |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | ตรวจจับ RDS instance ที่ถูกสร้างหรือแก้ไขด้วย publiclyAccessible=true |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | ตรวจจับ ExportTableToPointInTime (การ export ทั้งตารางฝั่งเซิร์ฟเวอร์ที่ข้าม DLP ของ GetItem), DeleteTable และการปิดใช้งาน PITR |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | ตรวจจับ EBS Direct API (ListSnapshotBlocks / GetSnapshotBlock) — Pacu ebs__download_snapshots สตรีมข้อมูล snapshot ดิบโดยไม่ใช้ EC2 หลบเลี่ยงการตรวจจับ ModifySnapshotAttribute |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | ตรวจจับการสร้าง/อัปเดต delivery stream ของ Firehose ที่ชี้ไปยัง S3 ภายนอก — pipeline ข้อมูลเรียลไทม์ที่ DLP เครือข่ายมองไม่เห็น |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | ตรวจจับ PutBucketReplication — คัดลอก object ใหม่ทั้งหมดไปยัง bucket ที่ผู้โจมตีควบคุมอย่างเงียบ ๆ โดยไม่สร้างเหตุการณ์ GetObject เพิ่มเติม |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | ตรวจจับการระงับ versioning (เปิดทางให้ลบอย่างถาวร) และการปิดใช้งาน server-access logging (ลบร่องรอยหลักฐาน) |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | ตรวจจับการเปลี่ยนแปลง receipt rule และการตั้งค่า identity ของ SES — forwarding rule ส่งต่อเมลขาเข้าทั้งหมดไปยังที่อยู่ของผู้โจมตี; identity ที่ยืนยันแล้วเปิดทางให้แคมเปญ phishing |
| 19 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | ตรวจจับการเปลี่ยนแปลง policy ของ SQS/SNS ที่ให้สิทธิ์เข้าถึงบัญชีภายนอก (การสตรีมข้อความอย่างเงียบ ๆ ไปยัง endpoint ของผู้โจมตี) |
| 20 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | ตรวจจับ EBS snapshot หรือ AMI ที่แชร์สู่สาธารณะ (group=all) — เปิดทางให้ใครก็ได้คัดลอก disk image และดึงข้อมูล |
| 21 | 📧 Data Exfiltration Channels | bar | ตรวจจับการเรียก SNS/SQS/SES/S3 PutObject ปริมาณสูง (≥50/ชั่วโมง) จากอัตลักษณ์เดียว |

### ⚡ Compute & Serverless

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | ตรวจจับอัตลักษณ์ที่เรียก StopInstances/TerminateInstances ≥5 ครั้งในหนึ่งชั่วโมง — ตัวบ่งชี้ ransomware / wiper |
| 2 | 🖥️ SSM Session / Run Command | timeseries | ตรวจจับ SSM StartSession, SendCommand และ StartAutomationExecution — เส้นทางหลักของการเคลื่อนตัวด้านข้างผ่าน managed instance |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | ตรวจจับ SendSSHPublicKey และ SendSerialConsoleSSHPublicKey — ข้าม key pair ของ EC2 (มีผล 60 วินาที ไม่ทิ้งร่องรอย SSH key) |
| 4 | 📝 EC2 User Data Modification | timeseries | ตรวจจับ ModifyInstanceAttribute ที่เปลี่ยน userData — สคริปต์ทำงานเป็น root เมื่อบูตครั้งถัดไป |
| 5 | ⚡ Lambda Function Tampering | timeseries | ตรวจจับการสร้าง Lambda การอัปเดตโค้ด (UpdateFunctionCode) และการเปลี่ยนแปลงสิทธิ์ (AddPermission) |
| 6 | 📦 Lambda Layer Addition | timeseries | ตรวจจับการเผยแพร่ Lambda layer และ AddLayerVersionPermission ที่มี principal เป็น wildcard (การโจมตี supply-chain สาธารณะ) |
| 7 | 📦 ECS Task Definition  | timeseries | ตรวจจับ RegisterTaskDefinition / UpdateService — Pacu ecs__backdoor_task_def แทรก sidecar container ที่เป็นอันตรายโดยไม่แตะ ECR |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | ตรวจจับ AssociateIamInstanceProfile / ReplaceIamInstanceProfileAssociation — แนบ profile ที่มีสิทธิ์สูงเพื่อเปิดทางการเคลื่อนตัวด้านข้าง |
| 9 | 🖥 EC2 Instance Launches | timeseries | แสดงรายการเหตุการณ์ RunInstances ทั้งหมดรวมถึง instance type, จำนวน, key name และ AMI (การตรวจจับ cryptomining) |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | ตรวจจับคำขอ Spot Fleet ขนาดใหญ่ (ec2) และการสร้าง Auto Scaling group ที่มี capacity สูง (autoscaling) — ตัวบ่งชี้ผลกระทบทางการเงินจาก cryptomining |
| 11 | ☸️ EKS Cluster API Calls | timeseries | ตรวจจับการแก้ไข control-plane ของ EKS cluster (การเปิดเผย API server สาธารณะ, Fargate profile ปลอม) |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | ตรวจจับเหตุการณ์ repository/image ของ ECR (PutImage ที่แท็ก 'latest' ทำให้การ deploy ครั้งต่อ ๆ ไปทั้งหมดเป็นพิษ) |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | ตรวจจับการแก้ไข rule ของ EventBridge และ Scheduler (PutRule, CreateSchedule) — สร้างการคงอยู่โดยไม่มีโปรเซสที่กำลังทำงาน |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | ตรวจจับการดึงคีย์ การเปิดพอร์ต และการเข้าถึง instance ของ Lightsail — Pacu lightsail__download_ssh_keys / lightsail__generate_temp_access |

### 🌐 Network & Infrastructure

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 🌍 Security Group Opened to Internet | timeseries | ค้นหา rule ของ security group ที่อนุญาต traffic จาก 0.0.0.0/0 — ความเสี่ยงการเปิดเผยสู่สาธารณะโดยตรง |
| 2 | 🔥 Security Group Modifications | timeseries | ตรวจจับการเปลี่ยนแปลง rule ของ security group ทั้งหมด (AuthorizeSecurityGroupIngress, ModifySecurityGroupRules ฯลฯ) |
| 3 | 🌊 VPC Flow Log Changes | timeseries | ตรวจจับการลบ VPC Flow Logs — การลบ flow log ขจัดหลักฐานเชิงนิติวิทยาศาสตร์เครือข่ายหลัก |
| 4 | 🌐 CloudFront Distribution Tampering | timeseries | ตรวจจับการเปลี่ยน origin ของ CloudFront ที่เปลี่ยนเส้นทาง traffic ของ CDN ทั้งหมดไปยังเซิร์ฟเวอร์ที่ผู้โจมตีควบคุม (MitM) |
| 5 | 🛡 Network Firewall / Shield Tampering | timeseries | ตรวจจับการลบการป้องกัน Network Firewall และ Shield — เปิดเผยช่วง subnet ทั้งหมดต่อ traffic การโจมตี |
| 6 | 🧱 Network ACL Changes | timeseries | ตรวจจับการสร้าง การลบ และการแทนที่ entry ของ NACL — NACL ลบล้าง security group ที่ระดับ subnet |
| 7 | 🛣️ Route Table Changes | timeseries | ตรวจจับการแก้ไข route table — ผู้โจมตีเปลี่ยนเส้นทาง traffic ไปยัง gateway ที่เป็นอันตรายเพื่อดักจับหรือ C2 |
| 8 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | ตรวจจับการเชื่อมต่อ VPN ใหม่และการแนบ Transit Gateway — สร้างเส้นทางเครือข่าย Layer-3 แบบถาวรสำหรับ C2 หรือการลักลอบนำข้อมูลออก |
| 9 | 📡 Elastic IP Allocation / Association | timeseries | ตรวจจับการจัดสรร/การเชื่อมโยง Elastic IP — กำหนด public IP คงที่ให้กับ instance ที่ถูกบุกรุกเพื่อโครงสร้างพื้นฐาน C2 ที่เสถียร |
| 10 | 🗝️ EC2 Key Pair Creation | timeseries | ตรวจจับ CreateKeyPair และ ImportKeyPair — ผู้โจมตีสร้าง SSH key เพื่อการเข้าถึง instance แบบถาวร |
| 11 | 📡 Network Infrastructure Changes | timeseries | ตรวจจับการเปลี่ยนแปลง VPC / subnet / IGW / NAT Gateway / peering ที่อาจสร้างโครงสร้างพื้นฐานที่ผู้โจมตีควบคุม |
| 12 | 🏷 ACM Certificate Operations | timeseries | ตรวจจับคำขอและการลบ certificate ของ ACM — บัญชีที่ถูกบุกรุกสามารถออก TLS cert สำหรับโดเมน phishing |
| 13 | 🔑 API Gateway Key Creation & Management | timeseries | ตรวจจับการสร้างคีย์และการเปลี่ยนแปลง authorizer ของ API Gateway — Pacu api_gateway__create_api_keys สร้าง credential แบบถาวรที่อยู่รอดจากการหมุน IAM key |
| 14 | 🚧 VPC Endpoint Access Denied | timeseries | ตรวจจับ error access denied ผ่าน VPC endpoint — อาจบ่งชี้ endpoint policy ที่ตั้งค่าผิด |

### 🕵 Threat Patterns

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | ระบุผู้เรียกที่รัน API Describe*/List*/Get* ที่แตกต่างกัน 10+ รายการในหนึ่งชั่วโมง — ระยะแรกของการโจมตีที่พบบ่อย |
| 2 | 🤖 Unusual User Agents | bar | แสดงรายการ user agents ที่พบยาก (<5 เหตุการณ์) หรือเครื่องมือผู้โจมตีที่รู้จัก (Pacu, curl, wget) — อาจบ่งชี้เครื่องมือโจมตี |
| 3 | 🌍 Multi-Region Activity | bar | ตรวจจับอัตลักษณ์ที่เขียนในภูมิภาค 3+ แห่งในหนึ่งวัน — การกระจายทางภูมิศาสตร์อาจบ่งชี้การถูกบุกรุก |
| 4 | 🕵 First-Time API Calls (24h) | — | ค้นหาการเรียก API ที่พบใน 24 ชั่วโมงที่ผ่านมาแต่ไม่เคยพบมาก่อน — การดำเนินการใหม่อาจบ่งชี้เครื่องมือของผู้โจมตี |

### 📊 Activity & Baseline

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | ระบุการเรียก API ที่เปลี่ยนแปลงข้อมูลซึ่งทำผ่านคอนโซล AWS — มีประโยชน์เมื่อคาดว่าจะเข้าถึงผ่าน CLI เท่านั้น |
| 2 | 🔍 Events with Errors (24h) | timeseries | แสดงรายการเหตุการณ์ error ทั้งหมดใน 24 ชั่วโมงที่ผ่านมา — ภาพรวมอย่างรวดเร็วของสิ่งที่ล้มเหลวหรือถูกตรวจสอบ |
| 3 | ❌ Error Spike Detection | — | ค้นหาช่วงเวลา 1 ชั่วโมงที่จำนวน error เกินค่าเฉลี่ยรายวัน 3 เท่า |

### 🌍 GeoIP Analysis

> ต้องใช้ไฟล์ GeoLite2 `.mmdb` สำหรับการเติมข้อมูล (คอลัมน์จะเป็น NULL หากนำเข้าโดยไม่มี GeoIP)

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 🕵 Impossible Travel Detection | — | ตรวจจับอัตลักษณ์เดียวกันที่เรียก API จากเมืองที่อยู่ห่างไกลกันภายใน 2 ชั่วโมง — ตัวบ่งชี้ที่ชัดเจนของการถูกบุกรุก credential |
| 2 | ⚠ Identity Multi-Country Access | bar | ค้นหาอัตลักษณ์ที่เรียก API จาก 2+ ประเทศ — ผู้ใช้ที่ถูกต้องไม่ค่อยทำงานจากหลายประเทศพร้อมกัน |
| 3 | 🗺 Console Logins by Country | timeseries | แมปเหตุการณ์ล็อกอินคอนโซลกับแหล่งที่มาทางภูมิศาสตร์ — การล็อกอินจากประเทศที่ไม่คาดคิดมีความเสี่ยงสูง |
| 4 | 🚨 Unusual Country Access | bar | ตรวจจับการรวมกันของประเทศ/อัตลักษณ์ที่พบยาก (<10 เหตุการณ์) — การเข้าถึงจากต่างประเทศปริมาณต่ำอาจเป็นโครงสร้างพื้นฐานของผู้โจมตี |
| 5 | 🚫 Access Denied by Country | bar | จัดกลุ่ม error access denied ตามประเทศต้นทาง — การปฏิเสธที่กระจุกตัวจากประเทศเดียวอาจส่งสัญญาณการโจมตี |
| 6 | 🔍 Write Events by Country | bar | แสดงการเรียก API ที่เปลี่ยนแปลงข้อมูลจัดกลุ่มตามประเทศต้นทาง — การเขียนจากประเทศที่ไม่คาดคิดเป็นสัญญาณที่แรงกว่าการอ่าน |
| 7 | 🌍 Top Source Countries | bar | จัดอันดับประเทศต้นทางตามปริมาณการเรียก API พร้อมการแยกย่อยเหตุการณ์การเขียนและอัตลักษณ์ที่ไม่ซ้ำ |
| 8 | 🏢 Top ASN / Organizations | bar | แสดงรายการ autonomous system (ISP/ผู้ให้บริการคลาวด์) ตามปริมาณการเรียก API — ASN ของ VPN/hosting อาจบ่งชี้โครงสร้างพื้นฐานของผู้โจมตี |
| 9 | 📍 Top Source Cities | bar | จัดอันดับเมืองต้นทางตามปริมาณเหตุการณ์ — ข้อมูลระดับเมืองระบุโครงสร้างพื้นฐานของผู้โจมตีหรือสถานที่สำนักงานที่เฉพาะเจาะจง |
| 10 | 🌐 Private / Internal IP Summary | bar | สรุปเหตุการณ์จาก IP แบบ private/loopback/ภายใน AWS — เส้นฐานสำหรับ traffic ภายในที่คาดหวัง |
| 11 | 📋 API Calls by Country (Event Name) | table | คู่ (event_name, country) อันดับต้นตามปริมาณการเรียก — เผยให้เห็นว่าการดำเนินการ API ใดมาจากภูมิภาคที่ไม่คาดคิด |
| 12 | 👤 Identities by Country (user_identity_arn) | table | คู่ (user_identity_arn, country) อันดับต้นตามปริมาณการเรียก — เผยอัตลักษณ์ IAM ที่ใช้งานจากประเทศที่ไม่คาดคิดพร้อมเวลาที่พบครั้งแรก/ครั้งสุดท้าย |

### ☁ IaC & Platform

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | ตรวจจับการสร้างและแก้ไข pipeline ของ CI/CD (UpdateProject แทรกขั้นตอน build ที่เป็นอันตรายในทุก build ครั้งต่อ ๆ ไป) |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | ตรวจจับการดำเนินการ stack ของ CloudFormation — ผู้โจมตีอาจใช้ IaC เพื่อ deploy โครงสร้างพื้นฐานที่เป็นอันตรายอย่างรวดเร็ว |

</details>

---

## 📊 Dashboard Charts — มากกว่า 80 charts

| Tab | Charts | สิ่งที่แสดง |
|-----|:------:|---------------|
| 🔑 Identity & Access | 9 | การล็อกอินคอนโซล · แนวโน้ม MFA · heatmap การล็อกอิน · API ที่ละเอียดอ่อน · การใช้ root · กิจกรรมของ IAM entity · การยกระดับสิทธิ์ · SSO/privesc |
| 🎯 Threat Detection | 12 | ปริมาณเหตุการณ์ · อัตราส่วน read/write · การหลบเลี่ยงการป้องกัน · access denied · แนวโน้ม error · การดัดแปลง SCP/Config/NACL/EventBridge |
| 📊 API Activity | 7 | API อันดับต้น · การกระจายตามภูมิภาค · source IP · user agents · ความผิดปกติของ secrets · AssumeRole ภายนอก · การเปลี่ยนแปลง Route53 |
| 🖥️ Computing | 5 | การดำเนินการ SSM · EC2 public snapshot · เหตุการณ์ EKS/ECR · ECS backdoor · การลักลอบนำข้อมูลออกผ่าน EBS Direct API |
| 🪣 S3 & RDS | 9 | policy/ACL ของ S3 · การดาวน์โหลด/ลบจำนวนมาก · การปิดใช้งาน versioning/logging · การ replicate ข้ามบัญชี · การแชร์ snapshot RDS · การดัดแปลง Backup |
| 🌍 GeoIP Intelligence | 6 | แผนที่โลก · ประเทศ / เมือง / ASN อันดับต้นตามปริมาณคำขอ · event_name × country · identity × country |
| 🕒 Temporal Analysis | 6 | เวลาที่พบครั้งแรก/ครั้งสุดท้ายตาม identity/IP/API/agent · บัญชีที่ไม่ใช้งานถูกเปิดใช้ใหม่ · การพุ่งขึ้นของความเร็ว |
| 🚨 High-Risk API Monitor | 7 | อนุกรมเวลา HRM · การเรียก/ผู้กระทำ/IP อันดับต้น · รายละเอียดการหลบเลี่ยงการป้องกัน/credential · ตามภูมิภาค |

<details markdown="1">
<summary>📋 รายการทั้งหมด — ทุก charts มากกว่า 80 รายการ (คลิกเพื่อขยาย)</summary>

## Dashboard Charts (Apache Superset — `dashboard/`)

### 🔑 Identity & Access

| # | Chart Name | คำอธิบาย |
|---|------------|-------------|
| 1 | Console Login Activity | เหตุการณ์ sign-in คอนโซลจัดกลุ่มตามอัตลักษณ์ IAM (DSH-08) |
| 2 | MFA-less Login Trend | การล็อกอินคอนโซลรายวันแยกตามการใช้ MFA (DSH-28) |
| 3 | Login Activity Heatmap (Hour × Day) | จำนวนการล็อกอินคอนโซลตามวันในสัปดาห์และชั่วโมงของวันในเวลา JST (DSH-19) |
| 4 | Sensitive API Calls | การเรียกใช้การกระทำ API ของ AWS ที่ทราบว่าละเอียดอ่อนด้านความปลอดภัย (DSH-12) |
| 5 | Root Account Usage | การเรียก API ทั้งหมดที่ทำโดยบัญชี Root ของ AWS (DSH-13) |
| 6 | IAM Entity Activity | IAM entity อันดับต้น 50 รายการจัดอันดับตามจำนวนการเรียก API ทั้งหมด พร้อมอัตราส่วนการเขียนและอัตรา error |
| 7 | Privilege Escalation Timeline | จำนวนการเรียก API การยกระดับสิทธิ์รายวันตามชื่อเหตุการณ์ (DSH-30) |
| 8 | IAM Identity Center (SSO) Events | เหตุการณ์การจัดการ AWS IAM Identity Center จาก sso.amazonaws.com (DSH-44) |
| 9 | Glue & SageMaker Privilege Escalation | เหตุการณ์ Glue DevEndpoint และ SageMaker Notebook ที่ใช้สำหรับการยกระดับสิทธิ์ IAM ผ่าน iam:PassRole (DSH-50) |

### 🎯 Threat Detection

| # | Chart Name | คำอธิบาย |
|---|------------|-------------|
| 1 | CloudTrail Events Over Time | ปริมาณเหตุการณ์ Read เทียบกับ Write รายชั่วโมงตามเวลา (DSH-01) |
| 2 | Write/Read Ratio Trend | การแยกย่อยการเรียก API read เทียบกับ write รายชั่วโมง (DSH-20) |
| 3 | Throttling Exception Spikes | error throttling/rate-limit รายชั่วโมงตามบริการ AWS (DSH-21) |
| 4 | Defense Evasion Events | เหตุการณ์ CloudTrail ทั้งหมดที่ตรงกับเทคนิคการหลบเลี่ยงการป้องกันที่รู้จัก (DSH-22) |
| 5 | Top Access Denied Actions | การกระทำ API อันดับต้น 20 รายการที่คืน error AccessDenied (DSH-09) |
| 6 | Error Event Trend | เหตุการณ์ error รายชั่วโมงแยกย่อยตาม error_code (DSH-04) |
| 7 | Organizations / SCP Changes | เหตุการณ์การจัดการ AWS Organizations รวมถึงการเปลี่ยนแปลง policy SCP (DSH-24) |
| 8 | First-Time Service Sources | แหล่งบริการ AWS ที่แตกต่างกันทั้งหมดเรียงตามวันที่ปรากฏครั้งแรก (DSH-26) |
| 9 | VPC Flow Log Changes | เหตุการณ์การสร้างและการลบ VPC Flow Log (DSH-42) |
| 10 | AWS Config Tampering | เหตุการณ์การดัดแปลง recorder และ rule ของ AWS Config (DSH-43) |
| 11 | Network ACL / Route Table Changes | เหตุการณ์การแก้ไข NACL และ route table (DSH-46) |
| 12 | EventBridge / CloudWatch Rule Tampering | การดัดแปลง rule ของ EventBridge และ CloudWatch Events (DSH-47) |

### 📊 API Activity

| # | Chart Name | คำอธิบาย |
|---|------------|-------------|
| 1 | Top 20 API Calls | การกระทำ API ของ AWS ที่ถูกเรียกบ่อยที่สุด 20 รายการ (DSH-02) |
| 2 | Region Activity | การกระจายของเหตุการณ์ CloudTrail ทั่วภูมิภาค AWS (DSH-14) |
| 3 | Top Source IP Addresses | source IP ภายนอกอันดับต้น 100 รายการตามจำนวนคำขอ (DSH-05) |
| 4 | User Agent Analysis | user agents อันดับต้น 50 รายการตามจำนวนคำขอพร้อมการแยกย่อย error และการเขียน (DSH-11) |
| 5 | Secrets Access Anomaly | อัตลักษณ์ที่เข้าถึง Secrets Manager หรือ SSM Parameter Store ≥10 ครั้งในหนึ่งชั่วโมง |
| 6 | AssumedRole from External IP | การเรียก AssumeRole จากที่อยู่ IP สาธารณะ (ไม่ใช่ private) (DSH-27) |
| 7 | Route53 DNS Changes | การเปลี่ยนแปลงการตั้งค่า hosted-zone และ resolver ของ Route 53 (DSH-29) |

### 🖥️ Computing

| # | Chart Name | คำอธิบาย |
|---|------------|-------------|
| 1 | SSM Session / Run Command Execution | เหตุการณ์การดำเนินการระยะไกลของ AWS Systems Manager (DSH-39) |
| 2 | EC2 Public Snapshot / AMI Sharing | เหตุการณ์การแชร์ EBS snapshot และ AMI สู่สาธารณะ (DSH-41) |
| 3 | EKS / ECR Container Platform Events | เหตุการณ์ EKS cluster และ ECR container registry (DSH-48) |
| 4 | ECS Task Definition | เหตุการณ์การลงทะเบียน task definition และการอัปเดต service ของ ECS — รูปแบบ Pacu ecs__backdoor_task_def (DSH-49) |
| 5 | EBS Direct API Snapshot Exfiltration | การเรียก EBS Direct API (ListSnapshotBlocks / GetSnapshotBlock) ที่ใช้สตรีมข้อมูล snapshot โดยไม่ใช้ EC2 (DSH-51) |

### 🪣 S3 & RDS

| # | Chart Name | คำอธิบาย |
|---|------------|-------------|
| 1 | S3 Protection Config Changes | เหตุการณ์ S3 ที่ลดทอนความมั่นคงด้านความปลอดภัยของ bucket (DSH-25) |
| 2 | S3 Bucket Policy / ACL Changes | เหตุการณ์การแก้ไข policy และ ACL ของ S3 bucket (DSH-45) |
| 3 | RDS Snapshot Cross-Account Share | เหตุการณ์การแชร์ snapshot ของ RDS และ Aurora (DSH-40) |
| 4 | S3 Bulk Download | อัตลักษณ์ที่เรียก GetObject ≥100 ครั้งต่อชั่วโมง — รูปแบบการลักลอบนำข้อมูลออกแบบอัตโนมัติ (DSH-52) |
| 5 | S3 Bulk Object Deletion | อัตลักษณ์ที่เรียก DeleteObject/DeleteObjects ≥50 ครั้งต่อชั่วโมง — รูปแบบการทำลายข้อมูลจาก ransomware (DSH-53) |
| 6 | S3 Versioning / Logging Disabled | PutBucketVersioning (Suspended) และ PutBucketLogging (disabled) — สัญญาณนำหน้าการต่อต้านนิติวิทยาศาสตร์ก่อนการทำลายข้อมูล (DSH-54) |
| 7 | S3 Cross-Account Replication | PutBucketReplication / DeleteBucketReplication — ช่องทางการลักลอบนำข้อมูลออกแบบเงียบและถาวรไปยังบัญชีที่ผู้โจมตีควบคุม (DSH-55) |
| 8 | RDS Deleted without Final Snapshot | DeleteDBInstance / DeleteDBCluster ที่มี skipFinalSnapshot=true — การทำลายข้อมูลที่กู้คืนไม่ได้ (DSH-56) |
| 9 | AWS Backup Tampering | การลบ Backup Vault / Plan / RecoveryPoint และการลบ Vault Lock — ขั้นตอนแรกของ ransomware เพื่อขจัดทางเลือกในการกู้คืน (DSH-57) |

### 🌍 GeoIP Intelligence

> ต้องใช้ไฟล์ GeoLite2 `.mmdb` คอลัมน์ GeoIP จะเป็น NULL หากนำเข้าโดยไม่มี GeoIP

| # | Chart Name | คำอธิบาย |
|---|------------|-------------|
| 1 | Global Request Origin Map | แผนที่โลกที่แสดงการกระจายทางภูมิศาสตร์ของแหล่งที่มาการเรียก API ของ CloudTrail |
| 2 | Top Countries by Request Volume | ประเทศต้นทางอันดับต้น 20 รายการตามปริมาณการเรียก API พร้อมการแยกย่อยเหตุการณ์การเขียนและผู้เรียกที่ไม่ซ้ำ |
| 3 | Top Cities by Request Volume | เมืองอันดับต้น 25 รายการตามปริมาณการเรียก API พร้อมการแยกย่อยเหตุการณ์การเขียนและผู้เรียกที่ไม่ซ้ำ |
| 4 | Top ASN Organizations by Request Volume | องค์กร ASN อันดับต้น 25 รายการตามปริมาณการเรียก API |
| 5 | API Calls by Country (Event Name × GeoIP) | คู่ (event_name, country) อันดับต้น 50 รายการ — เผยให้เห็นว่าการดำเนินการ API ใดถูกเรียกจากแต่ละภูมิภาค (DSH-79) |
| 6 | Identities by Country (user_identity_arn × GeoIP) | คู่ (user_identity_arn, country) อันดับต้น 50 รายการ — เผยอัตลักษณ์ IAM ที่ใช้งานจากประเทศที่ไม่คาดคิดพร้อมจำนวนการเขียนและเวลาที่พบครั้งแรก/ครั้งสุดท้าย (DSH-80) |

### 🕒 Temporal Analysis

| # | Chart Name | คำอธิบาย |
|---|------------|-------------|
| 1 | First / Last Seen per IAM Identity | อัตลักษณ์ IAM พร้อม timestamp ที่พบครั้งแรก/ครั้งสุดท้าย จำนวนเหตุการณ์ และ API ที่แตกต่างกัน |
| 2 | First / Last Seen per Source IP | source IP พร้อมเวลาที่พบครั้งแรก/ครั้งสุดท้าย อัตลักษณ์ที่แตกต่างกัน และ API ที่แตกต่างกัน |
| 3 | First / Last Seen per API Call | การกระทำ API เรียงตามการปรากฏครั้งแรก — การเรียกใหม่อาจบ่งชี้เครื่องมือโจมตีแบบใหม่ (DSH-33) |
| 4 | First / Last Seen per User Agent | user agents เรียงตามการปรากฏครั้งแรก — การตรวจจับเครื่องมือใหม่ (DSH-34) |
| 5 | Dormant Accounts Reactivated | อัตลักษณ์ที่มีช่วงไม่ใช้งาน 72+ ชั่วโมงและกลับมาทำกิจกรรมอีกครั้ง (DSH-37) |
| 6 | Event Velocity Spikes per Identity | อัตลักษณ์ที่มีกิจกรรมพุ่งขึ้น 50+ เหตุการณ์ต่อชั่วโมง (DSH-38) |

### 🚨 High-Risk API Monitor (HRM)

| # | Chart Name | คำอธิบาย |
|---|------------|-------------|
| 1 | High-Risk API Events Over Time | ปริมาณการเรียกรายวันสำหรับ API ที่มักพบในแคมเปญการโจมตี (HRM-39) |
| 2 | Top High-Risk API Calls | การกระทำ API จาก watchlist ความเสี่ยงสูงจัดอันดับตามจำนวนการเรียกทั้งหมด (HRM-40) |
| 3 | Top Actors — High-Risk APIs | IAM principal จัดอันดับตามจำนวนการเรียกทั้งหมดไปยัง API ใน watchlist ความเสี่ยงสูง (HRM-42) |
| 4 | Top Source IPs — High-Risk APIs | source IP จัดอันดับตามจำนวนการเรียกทั้งหมดไปยัง API ใน watchlist ความเสี่ยงสูง (HRM-43) |
| 5 | Defense Evasion API Events | บันทึกเหตุการณ์โดยละเอียดสำหรับ API ที่ใช้ปิดใช้งานหรือดัดแปลงการควบคุมการตรวจสอบ (HRM-44) |
| 6 | Credential Access API Events | บันทึกเหตุการณ์โดยละเอียดสำหรับ API ที่ใช้ดึง secret และ credential (HRM-45) |
| 7 | High-Risk API Calls by Region | การเรียก API ใน watchlist ความเสี่ยงสูงกระจายตามภูมิภาค AWS (HRM-46) |

</details>

---
