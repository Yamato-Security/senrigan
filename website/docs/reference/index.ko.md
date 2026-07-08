# 내장 쿼리 및 대시보드 레퍼런스

> 💡 SQL이나 깊은 AWS 지식이 필요 없습니다 — 드롭다운에서 헌트를 선택하기만 하면 즉시 결과를 얻을 수 있습니다.

## 🎯 내장 헌트 — 100개 이상의 쿼리

카테고리는 DFIR 트리아지 우선순위 순으로 정렬되어 있습니다 — 먼저 탐지 도구 변조를 확인하고, 그다음 자격 증명 남용, 그다음 데이터 영향을 확인하세요.

| 카테고리 | 쿼리 | 다루는 주요 위협 |
|----------|:-------:|---------------------|
| 🛡 탐지 및 대응 | 12 | 감사 서비스 변조 (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · SCP 삭제 · 알람 억제 · 로그 유출 |
| 🔑 자격 증명 및 접근 | 26 | 루트 사용 · 콘솔 로그인/MFA · 권한 상승 · 신뢰 정책 백도어 · PassRole 남용 · 교차 계정 AssumeRole · SSO/SAML/OIDC · 자격 증명 열거 |
| 🪣 데이터 및 스토리지 | 21 | S3 대량 삭제/다운로드 · 시크릿 대량 읽기 · 백업 변조 · KMS 작업 · 스냅샷 공유 · EBS Direct API 유출 · DynamoDB 내보내기 · S3 교차 계정 복제 |
| ⚡ 컴퓨팅 및 서버리스 | 14 | EC2 대량 중지/종료 · SSM 측면 이동 · Lambda/ECS/EKS/ECR 변조 · EventBridge 지속성 · 크립토마이닝 · Lightsail 남용 |
| 🌐 네트워크 및 인프라 | 14 | SG 인터넷 개방 · VPC 흐름 로그 삭제 · CloudFront 하이재킹 · 은밀한 VPN/TGW 터널 · Elastic IP C2 · API Gateway 키 |
| 🕵 위협 패턴 | 5 | 업무 외 시간 쓰기 · 정찰 버스트 · 다중 리전 확산 · 비정상 사용자 에이전트 · 최초 API 호출 |
| 📊 활동 및 베이스라인 | 3 | 콘솔 쓰기 이벤트 · 오류 급증 · 최근 오류 |
| 🌍 GeoIP 분석 ✦ | 12 | 불가능한 이동 · 다중 국가 자격 증명 · 지역별 순위 로그인/거부/쓰기 · 국가/도시/ASN 분석 · event_name × country · identity × country |
| ☁ IaC 및 플랫폼 | 2 | CI/CD 공급망 · CloudFormation 남용 |

<details markdown="1">
<summary>📋 전체 목록 — 100개 이상의 모든 쿼리 (클릭하여 확장)</summary>

## 내장 헌트

### 🛡 탐지 및 대응

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | CloudTrail을 중지하거나 수정하려는 모든 시도를 탐지합니다 — 가장 중요한 은폐 지표입니다 |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | GuardDuty 비활성화, 삭제, 위협 인텔리전스 조작을 탐지합니다 |
| 3 | ⛔ Security Hub Tampering | timeseries | Security Hub 비활성화, 표준 비활성화, 발견 항목 억제를 탐지합니다 |
| 4 | ⚙️ AWS Config Tampering | timeseries | AWS Config 레코더/규칙 삭제를 탐지합니다 (규정 준수 증거를 제거함) |
| 5 | 🛡 Organizations SCP Changes | timeseries | SCP 생성, 업데이트, 삭제를 탐지합니다 — Deny SCP를 제거하면 OU 내 모든 계정의 가드레일이 사라집니다 |
| 6 | 🚫 AWS Macie Tampering | timeseries | Macie 비활성화 및 발견 항목 필터 생성을 탐지합니다 (유출 전 방어 회피) |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | 알람 삭제 및 DisableAlarmActions를 탐지합니다 — 알람을 삭제하지 않고 보안 경보를 무력화합니다 |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | CW Logs 구독 필터 생성/삭제를 탐지합니다 (공격자의 Kinesis/Lambda로 실시간 로그 유출) |
| 9 | 🏹 WAF WebACL Changes | timeseries | WAFv2/WAF Classic 전반에서 WAF WebACL 생성, 업데이트, 삭제를 탐지합니다 |
| 10 | 🔍 GuardDuty Findings Read | timeseries | ListFindings / GetFindings를 탐지합니다 — 공격자가 활성 발견 항목을 읽어 SOC가 이미 무엇을 탐지했는지 파악합니다 |
| 11 | 💰 Budget / Cost Anomaly Changes | timeseries | Budget/AnomalyMonitor 삭제를 탐지합니다 (크립토마이닝 비용 은폐) |
| 12 | 🚫 Access Denied Errors | bar | AccessDenied 오류를 자격 증명 및 API별로 그룹화합니다 — 상위 위반자는 자격 증명 오용을 나타냅니다 |

### 🔑 자격 증명 및 접근

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | 루트 계정으로 수행된 모든 API 호출을 탐지합니다 — 루트는 프로덕션에서 절대 사용해서는 안 됩니다 |
| 2 | 🔓 Console Login without MFA | timeseries | MFA가 사용되지 않은 콘솔 로그인을 탐지합니다 — 계정 침해의 고위험 지표입니다 |
| 3 | 🌐 Console Logins | timeseries | 성공 및 실패를 포함한 모든 콘솔 로그인 시도를 나열합니다 (무차별 대입 탐지) |
| 4 | 🔐 MFA & Password Changes | timeseries | MFA 비활성화 및 비밀번호 재설정을 탐지합니다 — 계정 탈취의 강력한 지표입니다 |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | IAM 정책 연결 및 역할 조작을 탐지합니다 (PutUserPolicy, AttachRolePolicy, CreatePolicyVersion 등) |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | UpdateAssumeRolePolicy를 탐지합니다 — 신뢰 정책에 외부 주체를 추가하면 지속적인 백도어가 생성됩니다 |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | 권한 경계 put/delete 이벤트를 탐지합니다 — 경계를 제거하면 즉시 유효 권한이 확장됩니다 |
| 8 | 👑 User Added to Admin Group | timeseries | 이름에 'admin'이 포함된 그룹에 추가된 사용자를 탐지합니다 — 전형적인 권한 상승입니다 |
| 9 | 👥 IAM Group Membership Changes | timeseries | 그룹 이름과 관계없이 모든 AddUserToGroup / RemoveUserFromGroup / CreateGroup / DeleteGroup 이벤트를 탐지합니다 |
| 10 | 👤 New IAM Users / Keys | timeseries | IAM 사용자 및 액세스 키 생성 이벤트를 식별합니다 — 예기치 않은 생성은 지속성을 나타낼 수 있습니다 |
| 11 | 🎯 IAM PassRole Abuse | timeseries | 역할 ARN이 전달되는 수신 서비스 이벤트(RunInstances, CreateFunction, CreateNotebookInstance 등)를 검사하여 iam:PassRole 사용을 탐지합니다 |
| 12 | 🔐 AssumeRole Cross-Account | timeseries | 호출자와 대상이 서로 다른 AWS 계정에 있는 AssumeRole 이벤트를 보여줍니다 (측면 이동) |
| 13 | 🏢 Cross-Account Access | timeseries | 호출자 계정이 수신자 계정과 다른 모든 이벤트를 찾습니다 |
| 14 | 🔑 STS Federation Token Issuance | timeseries | GetFederationToken 및 GetSessionToken을 탐지합니다 — 수명이 긴 키를 지속적인 임시 자격 증명으로 변환합니다 |
| 15 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | OIDC 신뢰 남용을 탐지합니다 (잘못 구성된 sub 클레임 / repo 조건이 없는 GitHub Actions) |
| 16 | 🆔 IAM Identity Center (SSO) Events | timeseries | AWS IAM Identity Center 관리 작업을 탐지합니다 (CreatePermissionSet, CreateAccountAssignment 등) |
| 17 | 🔗 SAML / OIDC Provider Updates | timeseries | SAML/OIDC 자격 증명 공급자 변경을 탐지합니다 — 공격자가 제어하는 IdP로 SAML 메타데이터를 업데이트하면 지속적인 인증 백도어가 생성됩니다 |
| 18 | 🧐 IAM Access Analyzer Calls | timeseries | IAM Access Analyzer의 모든 사용을 탐지합니다 — 공격자는 사용자 지정 정찰 스크립트 없이 외부에서 접근 가능한 리소스를 열거하기 위해 네이티브 분석기를 활용합니다 |
| 19 | 🔄 Credential Report & Enumeration | timeseries | IAM 열거를 탐지합니다 (GenerateCredentialReport, ListUsers, ListRoles, GetAccountAuthorizationDetails 등) |
| 20 | 🗝 Access Key Abuse | bar | 7일 내 3개 이상의 서로 다른 소스 IP에서 사용된 액세스 키를 탐지합니다 — 키 유출의 강력한 지표입니다 |
| 21 | 📰 AWS Organizations Account Creation | timeseries | Organizations 계정 생성 및 위임 관리자 변경을 탐지합니다 (섀도 계정 지속성) |
| 22 | 👥 Cognito Unauthenticated Access | timeseries | allowUnauthenticatedIdentities=true인 Cognito 자격 증명 풀을 탐지합니다 |
| 23 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | Glue DevEndpoint 생성(iam:PassRole + glue:CreateDevEndpoint = 전달된 역할의 전체 권한으로 실행되는 SSH 접근 가능 엔드포인트) 및 자격 증명 수집을 위한 연결 열거를 탐지합니다 |
| 24 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | SageMaker 노트북 생성 및 사전 서명 URL 생성을 탐지합니다 — iam:PassRole + sagemaker:CreateNotebookInstance는 전달된 역할의 전체 AWS 권한으로 Jupyter 환경을 실행합니다 |
| 25 | 🛠 Data Pipeline / CodeStar Privilege Escalation | timeseries | iam:PassRole 상승에 사용되는 Data Pipeline 및 CodeStar 리소스 생성을 탐지합니다 (CreateProjectFromTemplate은 부작용으로 관리자 IAM 역할을 생성합니다) |
| 26 | 🧩 Step Functions Privilege Escalation | timeseries | Step Functions 상태 머신 생성을 탐지합니다 (iam:PassRole + states:CreateStateMachine은 전달된 역할로 Lambda/ECS 작업을 실행합니다) |

### 🪣 데이터 및 스토리지

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | 시간당 50회 이상의 DeleteObject/DeleteObjects 호출을 수행하는 자격 증명을 탐지합니다 — 랜섬웨어 / 와이퍼 데이터 파괴 패턴입니다 |
| 2 | 🔥 AWS Backup Tampering | timeseries | Backup Vault / Plan / RecoveryPoint 삭제 및 Vault Lock 제거를 탐지합니다 — 복구 옵션을 제거하는 랜섬웨어의 첫 단계입니다 |
| 3 | 🔓 KMS Key Operations | timeseries | 민감한 KMS 작업을 표시합니다 (DisableKey, ScheduleKeyDeletion, CreateGrant, PutKeyPolicy, 대량 Decrypt) |
| 4 | 🔓 S3 Public Access Block Disabled | — | S3 퍼블릭 액세스 차단 설정이 비활성화되는 것을 탐지합니다 — 즉각적인 데이터 노출 위험입니다 |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | S3 버킷 정책 및 ACL 수정을 탐지합니다 (Principal='*'인 PutBucketPolicy는 특히 중요합니다) |
| 6 | 🪣 S3 Data Access Anomalies | bar | 대량 GetObject 호출(시간당 100회 이상)을 탐지합니다 — 자동화된 데이터 유출 패턴입니다 |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | 한 시간 내에 10개 이상의 서로 다른 시크릿을 검색하는 자격 증명을 탐지합니다 — 자격 증명 수집 신호입니다 |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | 시크릿 삭제, PutResourcePolicy(교차 계정 공유), CancelRotateSecret를 탐지합니다 |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | 한 시간 내에 20개 이상의 파라미터를 읽는 자격 증명을 탐지합니다 — 종종 간과되는 유출 채널입니다 |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | 외부 AWS 계정으로 공유된 RDS/Aurora 스냅샷을 탐지합니다 (스냅샷을 통한 데이터베이스 유출) |
| 11 | 💣 RDS Deleted without Final Snapshot | — | skipFinalSnapshot=true인 RDS 삭제를 탐지합니다 — 잠재적 데이터 파괴입니다 |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | publiclyAccessible=true로 생성되거나 수정된 RDS 인스턴스를 탐지합니다 |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | ExportTableToPointInTime(GetItem DLP를 우회하는 서버 측 전체 테이블 내보내기), DeleteTable, PITR 비활성화를 탐지합니다 |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | EBS Direct API(ListSnapshotBlocks / GetSnapshotBlock)를 탐지합니다 — Pacu ebs__download_snapshots는 EC2 없이 원시 스냅샷 데이터를 스트리밍하여 ModifySnapshotAttribute 탐지를 우회합니다 |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | 외부 S3를 가리키는 Firehose 전송 스트림 생성/업데이트를 탐지합니다 — 네트워크 DLP에 보이지 않는 실시간 데이터 파이프라인입니다 |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | PutBucketReplication을 탐지합니다 — 추가 GetObject 이벤트를 생성하지 않고 모든 새 객체를 공격자가 제어하는 버킷으로 조용히 복사합니다 |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | 버전 관리 일시 중단(영구 삭제 활성화) 및 서버 액세스 로깅 비활성화(증거 추적 제거)를 탐지합니다 |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | SES 수신 규칙 및 자격 증명 구성 변경을 탐지합니다 — 전달 규칙은 모든 수신 메일을 공격자 주소로 중계하고, 검증된 자격 증명은 피싱 캠페인을 가능하게 합니다 |
| 19 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | 외부 계정에 접근 권한을 부여하는 SQS/SNS 정책 변경을 탐지합니다 (공격자 엔드포인트로의 조용한 메시지 스트리밍) |
| 20 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | 공개적으로 공유된(group=all) EBS 스냅샷 또는 AMI를 탐지합니다 — 누구나 디스크 이미지를 복사하고 데이터를 추출할 수 있습니다 |
| 21 | 📧 Data Exfiltration Channels | bar | 단일 자격 증명에서 발생하는 대량 SNS/SQS/SES/S3 PutObject 호출(시간당 50회 이상)을 탐지합니다 |

### ⚡ 컴퓨팅 및 서버리스

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | 한 시간 내에 5회 이상의 StopInstances/TerminateInstances를 수행하는 자격 증명을 탐지합니다 — 랜섬웨어 / 와이퍼 지표입니다 |
| 2 | 🖥️ SSM Session / Run Command | timeseries | SSM StartSession, SendCommand, StartAutomationExecution을 탐지합니다 — 관리형 인스턴스를 통한 주요 측면 이동 경로입니다 |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | SendSSHPublicKey 및 SendSerialConsoleSSHPublicKey를 탐지합니다 — EC2 키 페어를 우회합니다 (60초간 유효, SSH 키 흔적을 남기지 않음) |
| 4 | 📝 EC2 User Data Modification | timeseries | userData가 변경된 ModifyInstanceAttribute를 탐지합니다 — 다음 부팅 시 스크립트가 루트로 실행됩니다 |
| 5 | ⚡ Lambda Function Tampering | timeseries | Lambda 생성, 코드 업데이트(UpdateFunctionCode), 권한 변경(AddPermission)을 탐지합니다 |
| 6 | 📦 Lambda Layer Addition | timeseries | Lambda 레이어 게시 및 와일드카드 주체를 사용한 AddLayerVersionPermission을 탐지합니다 (공개 공급망 공격) |
| 7 | 📦 ECS Task Definition  | timeseries | RegisterTaskDefinition / UpdateService를 탐지합니다 — Pacu ecs__backdoor_task_def는 ECR을 건드리지 않고 악성 사이드카 컨테이너를 주입합니다 |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | AssociateIamInstanceProfile / ReplaceIamInstanceProfileAssociation을 탐지합니다 — 측면 이동을 가능하게 하는 권한 있는 프로필을 연결합니다 |
| 9 | 🖥 EC2 Instance Launches | timeseries | 인스턴스 유형, 개수, 키 이름, AMI를 포함한 모든 RunInstances 이벤트를 나열합니다 (크립토마이닝 탐지) |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | 대규모 Spot Fleet 요청(ec2) 및 높은 용량의 Auto Scaling 그룹 생성(autoscaling)을 탐지합니다 — 크립토마이닝 재무 영향 지표입니다 |
| 11 | ☸️ EKS Cluster API Calls | timeseries | EKS 클러스터 컨트롤 플레인 수정을 탐지합니다 (퍼블릭 API 서버 노출, 비정상 Fargate 프로필) |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | ECR 리포지토리/이미지 이벤트를 탐지합니다 ('latest'로 태그된 PutImage는 이후의 모든 배포를 오염시킵니다) |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | EventBridge 규칙 및 Scheduler 수정을 탐지합니다 (PutRule, CreateSchedule) — 실행 중인 프로세스 없이 지속성을 확립합니다 |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | Lightsail 키 검색, 포트 노출, 인스턴스 접근을 탐지합니다 — Pacu lightsail__download_ssh_keys / lightsail__generate_temp_access |

### 🌐 네트워크 및 인프라

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 🌍 Security Group Opened to Internet | timeseries | 0.0.0.0/0에서 오는 트래픽을 허용하는 보안 그룹 규칙을 찾습니다 — 직접적인 공개 노출 위험입니다 |
| 2 | 🔥 Security Group Modifications | timeseries | 모든 보안 그룹 규칙 변경을 탐지합니다 (AuthorizeSecurityGroupIngress, ModifySecurityGroupRules 등) |
| 3 | 🌊 VPC Flow Log Changes | timeseries | VPC 흐름 로그의 삭제를 탐지합니다 — 흐름 로그를 제거하면 주요 네트워크 포렌식 증거가 사라집니다 |
| 4 | 🌐 CloudFront Distribution Tampering | timeseries | 모든 CDN 트래픽을 공격자가 제어하는 서버로 리디렉션하는 CloudFront 오리진 변경을 탐지합니다 (MitM) |
| 5 | 🛡 Network Firewall / Shield Tampering | timeseries | Network Firewall 및 Shield 보호 제거를 탐지합니다 — 전체 서브넷 범위를 공격 트래픽에 노출시킵니다 |
| 6 | 🧱 Network ACL Changes | timeseries | NACL 항목 생성, 삭제, 교체를 탐지합니다 — NACL은 서브넷 수준에서 보안 그룹을 재정의합니다 |
| 7 | 🛣️ Route Table Changes | timeseries | 라우트 테이블 수정을 탐지합니다 — 공격자는 가로채기 또는 C2를 위해 악성 게이트웨이로 트래픽을 리디렉션합니다 |
| 8 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | 새로운 VPN 연결 및 Transit Gateway 연결을 탐지합니다 — C2 또는 유출을 위한 지속적인 계층 3 네트워크 경로를 생성합니다 |
| 9 | 📡 Elastic IP Allocation / Association | timeseries | Elastic IP 할당/연결을 탐지합니다 — 안정적인 C2 인프라를 위해 침해된 인스턴스에 고정 퍼블릭 IP를 할당합니다 |
| 10 | 🗝️ EC2 Key Pair Creation | timeseries | CreateKeyPair 및 ImportKeyPair를 탐지합니다 — 공격자가 지속적인 인스턴스 접근을 위해 SSH 키를 생성합니다 |
| 11 | 📡 Network Infrastructure Changes | timeseries | 공격자가 제어하는 인프라를 구축할 수 있는 VPC / 서브넷 / IGW / NAT Gateway / 피어링 변경을 탐지합니다 |
| 12 | 🏷 ACM Certificate Operations | timeseries | ACM 인증서 요청 및 삭제를 탐지합니다 — 침해된 계정은 피싱 도메인용 TLS 인증서를 발급할 수 있습니다 |
| 13 | 🔑 API Gateway Key Creation & Management | timeseries | API Gateway 키 생성 및 권한 부여자 변경을 탐지합니다 — Pacu api_gateway__create_api_keys는 IAM 키 교체에도 살아남는 지속적인 자격 증명을 생성합니다 |
| 14 | 🚧 VPC Endpoint Access Denied | timeseries | VPC 엔드포인트를 통한 액세스 거부 오류를 탐지합니다 — 잘못 구성된 엔드포인트 정책을 나타낼 수 있습니다 |

### 🕵 위협 패턴

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | 한 시간 내에 10개 이상의 서로 다른 Describe*/List*/Get* API를 실행한 호출자를 식별합니다 — 일반적인 초기 공격 단계입니다 |
| 2 | 🤖 Unusual User Agents | bar | 드문 사용자 에이전트(5개 미만 이벤트) 또는 알려진 공격자 도구(Pacu, curl, wget)를 나열합니다 — 공격 도구를 나타낼 수 있습니다 |
| 3 | 🌍 Multi-Region Activity | bar | 하루에 3개 이상의 리전에서 쓰기를 수행하는 자격 증명을 탐지합니다 — 지리적 확산은 침해를 나타낼 수 있습니다 |
| 4 | 🕵 First-Time API Calls (24h) | — | 지난 24시간 내에는 보였지만 이전에는 본 적 없는 API 호출을 찾습니다 — 새로운 작업은 공격자 도구를 나타낼 수 있습니다 |

### 📊 활동 및 베이스라인

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | AWS 콘솔을 통해 수행된 변경 API 호출을 식별합니다 — CLI 전용 접근이 예상될 때 유용합니다 |
| 2 | 🔍 Events with Errors (24h) | timeseries | 지난 24시간 동안의 모든 오류 이벤트를 나열합니다 — 무엇이 실패하거나 탐색되고 있는지에 대한 빠른 개요입니다 |
| 3 | ❌ Error Spike Detection | — | 오류 수가 일일 평균을 3배 초과하는 1시간 구간을 찾습니다 |

### 🌍 GeoIP 분석

> 채우기 위해 GeoLite2 `.mmdb` 파일이 필요합니다 (GeoIP 없이 수집된 경우 열은 NULL입니다).

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 🕵 Impossible Travel Detection | — | 동일 자격 증명이 2시간 이내에 멀리 떨어진 도시에서 API를 호출하는 것을 탐지합니다 — 강력한 자격 증명 침해 지표입니다 |
| 2 | ⚠ Identity Multi-Country Access | bar | 2개 이상의 국가에서 API 호출을 하는 자격 증명을 찾습니다 — 정상 사용자는 여러 국가에서 동시에 작업하는 경우가 드뭅니다 |
| 3 | 🗺 Console Logins by Country | timeseries | 콘솔 로그인 이벤트를 지리적 출처에 매핑합니다 — 예기치 않은 국가에서의 로그인은 고위험입니다 |
| 4 | 🚨 Unusual Country Access | bar | 드문 국가/자격 증명 조합(10개 미만 이벤트)을 탐지합니다 — 소량의 외국 접근은 공격자 인프라일 수 있습니다 |
| 5 | 🚫 Access Denied by Country | bar | 액세스 거부 오류를 소스 국가별로 그룹화합니다 — 한 국가에서 집중된 거부는 공격을 시사할 수 있습니다 |
| 6 | 🔍 Write Events by Country | bar | 변경 API 호출을 소스 국가별로 그룹화하여 보여줍니다 — 예기치 않은 국가에서의 쓰기는 읽기보다 더 강한 신호입니다 |
| 7 | 🌍 Top Source Countries | bar | 쓰기 이벤트 및 고유 자격 증명 분석과 함께 API 호출량으로 소스 국가의 순위를 매깁니다 |
| 8 | 🏢 Top ASN / Organizations | bar | API 호출량으로 자율 시스템(ISP/클라우드 공급자)을 나열합니다 — VPN/호스팅 ASN은 공격자 인프라를 나타낼 수 있습니다 |
| 9 | 📍 Top Source Cities | bar | 이벤트량으로 소스 도시의 순위를 매깁니다 — 도시 수준 데이터는 특정 공격자 인프라 또는 사무실 위치를 정확히 찾아냅니다 |
| 10 | 🌐 Private / Internal IP Summary | bar | 프라이빗/루프백/AWS 내부 IP에서 발생한 이벤트를 요약합니다 — 예상되는 내부 트래픽의 베이스라인입니다 |
| 11 | 📋 API Calls by Country (Event Name) | table | 호출량 기준 상위 (event_name, country) 쌍 — 어떤 API 작업이 예기치 않은 지리적 지역에서 발생하는지 드러냅니다 |
| 12 | 👤 Identities by Country (user_identity_arn) | table | 호출량 기준 상위 (user_identity_arn, country) 쌍 — 처음/마지막 관찰과 함께 예기치 않은 국가에서 활동하는 IAM 자격 증명을 표면화합니다 |

### ☁ IaC 및 플랫폼

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | CI/CD 파이프라인 생성 및 수정을 탐지합니다 (UpdateProject는 이후의 모든 빌드에 악성 빌드 단계를 주입합니다) |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | CloudFormation 스택 작업을 탐지합니다 — 공격자는 악성 인프라를 신속하게 배포하기 위해 IaC를 사용할 수 있습니다 |

</details>

---

## 📊 대시보드 차트 — 80개 이상의 차트

| 탭 | 차트 | 표시 내용 |
|-----|:------:|---------------|
| 🔑 자격 증명 및 접근 | 9 | 콘솔 로그인 · MFA 추세 · 로그인 히트맵 · 민감한 API · 루트 사용 · IAM 엔티티 활동 · 권한 상승 · SSO/privesc |
| 🎯 위협 탐지 | 12 | 이벤트량 · 읽기/쓰기 비율 · 방어 회피 · 액세스 거부 · 오류 추세 · SCP/Config/NACL/EventBridge 변조 |
| 📊 API 활동 | 7 | 상위 API · 리전 분포 · 소스 IP · 사용자 에이전트 · 시크릿 이상 · 외부 AssumeRole · Route53 변경 |
| 🖥️ 컴퓨팅 | 5 | SSM 실행 · EC2 퍼블릭 스냅샷 · EKS/ECR 이벤트 · ECS 백도어 · EBS Direct API 유출 |
| 🪣 S3 및 RDS | 9 | S3 정책/ACL · 대량 다운로드/삭제 · 버전 관리/로깅 비활성화 · 교차 계정 복제 · RDS 스냅샷 공유 · 백업 변조 |
| 🌍 GeoIP 인텔리전스 | 6 | 세계 지도 · 요청량 기준 상위 국가 / 도시 / ASN · event_name × country · identity × country |
| 🕒 시간적 분석 | 6 | 자격 증명/IP/API/에이전트별 처음/마지막 관찰 · 휴면 계정 재활성화 · 속도 급증 |
| 🚨 고위험 API 모니터 | 7 | HRM 시계열 · 상위 호출/행위자/IP · 방어 회피/자격 증명 상세 · 리전별 |

<details markdown="1">
<summary>📋 전체 목록 — 80개 이상의 모든 차트 (클릭하여 확장)</summary>

## 대시보드 차트 (Apache Superset — `dashboard/`)

### 🔑 자격 증명 및 접근

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | Console Login Activity | IAM 자격 증명별로 그룹화된 콘솔 로그인 이벤트 (DSH-08) |
| 2 | MFA-less Login Trend | MFA 사용 여부로 분리된 일일 콘솔 로그인 (DSH-28) |
| 3 | Login Activity Heatmap (Hour × Day) | JST 기준 요일 및 시간대별 콘솔 로그인 수 (DSH-19) |
| 4 | Sensitive API Calls | 알려진 보안 민감 AWS API 작업의 호출 (DSH-12) |
| 5 | Root Account Usage | AWS 루트 계정으로 수행된 모든 API 호출 (DSH-13) |
| 6 | IAM Entity Activity | 쓰기 비율 및 오류율과 함께 총 API 호출로 순위가 매겨진 상위 50개 IAM 엔티티 |
| 7 | Privilege Escalation Timeline | 이벤트 이름별 권한 상승 API 호출의 일일 수 (DSH-30) |
| 8 | IAM Identity Center (SSO) Events | sso.amazonaws.com의 AWS IAM Identity Center 관리 이벤트 (DSH-44) |
| 9 | Glue & SageMaker Privilege Escalation | iam:PassRole을 통한 IAM 권한 상승에 사용되는 Glue DevEndpoint 및 SageMaker Notebook 이벤트 (DSH-50) |

### 🎯 위협 탐지

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | CloudTrail Events Over Time | 시간 경과에 따른 시간당 읽기 대 쓰기 이벤트량 (DSH-01) |
| 2 | Write/Read Ratio Trend | 읽기 대 쓰기 API 호출의 시간당 분석 (DSH-20) |
| 3 | Throttling Exception Spikes | AWS 서비스별 시간당 스로틀링/속도 제한 오류 (DSH-21) |
| 4 | Defense Evasion Events | 알려진 방어 회피 기법과 일치하는 모든 CloudTrail 이벤트 (DSH-22) |
| 5 | Top Access Denied Actions | AccessDenied 오류를 반환하는 상위 20개 API 작업 (DSH-09) |
| 6 | Error Event Trend | error_code별로 분석된 시간당 오류 이벤트 (DSH-04) |
| 7 | Organizations / SCP Changes | SCP 정책 변경을 포함한 AWS Organizations 관리 이벤트 (DSH-24) |
| 8 | First-Time Service Sources | 최초 출현 날짜순으로 정렬된 모든 고유 AWS 서비스 소스 (DSH-26) |
| 9 | VPC Flow Log Changes | VPC 흐름 로그 생성 및 삭제 이벤트 (DSH-42) |
| 10 | AWS Config Tampering | AWS Config 레코더 및 규칙 변조 이벤트 (DSH-43) |
| 11 | Network ACL / Route Table Changes | NACL 및 라우트 테이블 수정 이벤트 (DSH-46) |
| 12 | EventBridge / CloudWatch Rule Tampering | EventBridge 및 CloudWatch Events 규칙 변조 (DSH-47) |

### 📊 API 활동

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | Top 20 API Calls | 가장 자주 호출되는 20개의 AWS API 작업 (DSH-02) |
| 2 | Region Activity | AWS 리전 전반의 CloudTrail 이벤트 분포 (DSH-14) |
| 3 | Top Source IP Addresses | 요청 수 기준 상위 100개 외부 소스 IP (DSH-05) |
| 4 | User Agent Analysis | 오류 및 쓰기 분석과 함께 요청 수 기준 상위 50개 사용자 에이전트 (DSH-11) |
| 5 | Secrets Access Anomaly | 한 시간 내에 Secrets Manager 또는 SSM Parameter Store에 10회 이상 접근하는 자격 증명 |
| 6 | AssumedRole from External IP | 퍼블릭(비프라이빗) IP 주소에서의 AssumeRole 호출 (DSH-27) |
| 7 | Route53 DNS Changes | Route 53 호스팅 영역 및 리졸버 구성 변경 (DSH-29) |

### 🖥️ 컴퓨팅

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | SSM Session / Run Command Execution | AWS Systems Manager 원격 실행 이벤트 (DSH-39) |
| 2 | EC2 Public Snapshot / AMI Sharing | EBS 스냅샷 및 AMI 퍼블릭 공유 이벤트 (DSH-41) |
| 3 | EKS / ECR Container Platform Events | EKS 클러스터 및 ECR 컨테이너 레지스트리 이벤트 (DSH-48) |
| 4 | ECS Task Definition | ECS 작업 정의 등록 및 서비스 업데이트 이벤트 — Pacu ecs__backdoor_task_def 패턴 (DSH-49) |
| 5 | EBS Direct API Snapshot Exfiltration | EC2 없이 스냅샷 데이터를 스트리밍하는 데 사용되는 EBS Direct API 호출(ListSnapshotBlocks / GetSnapshotBlock) (DSH-51) |

### 🪣 S3 및 RDS

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | S3 Protection Config Changes | 버킷 보안 태세를 약화시키는 S3 이벤트 (DSH-25) |
| 2 | S3 Bucket Policy / ACL Changes | S3 버킷 정책 및 ACL 수정 이벤트 (DSH-45) |
| 3 | RDS Snapshot Cross-Account Share | RDS 및 Aurora 스냅샷 공유 이벤트 (DSH-40) |
| 4 | S3 Bulk Download | 시간당 100회 이상의 GetObject 호출을 수행하는 자격 증명 — 자동화된 데이터 유출 패턴 (DSH-52) |
| 5 | S3 Bulk Object Deletion | 시간당 50회 이상의 DeleteObject/DeleteObjects 호출을 수행하는 자격 증명 — 랜섬웨어 데이터 파괴 패턴 (DSH-53) |
| 6 | S3 Versioning / Logging Disabled | PutBucketVersioning (Suspended) 및 PutBucketLogging (disabled) — 데이터 파괴의 안티 포렌식 전조 (DSH-54) |
| 7 | S3 Cross-Account Replication | PutBucketReplication / DeleteBucketReplication — 공격자가 제어하는 계정으로의 지속적인 조용한 유출 채널 (DSH-55) |
| 8 | RDS Deleted without Final Snapshot | skipFinalSnapshot=true인 DeleteDBInstance / DeleteDBCluster — 복구 불가능한 데이터 파괴 (DSH-56) |
| 9 | AWS Backup Tampering | Backup Vault / Plan / RecoveryPoint 삭제 및 Vault Lock 제거 — 복구 옵션을 제거하는 랜섬웨어의 첫 단계 (DSH-57) |

### 🌍 GeoIP 인텔리전스

> GeoLite2 `.mmdb` 파일이 필요합니다. GeoIP 없이 수집된 경우 GeoIP 열은 NULL입니다.

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | Global Request Origin Map | CloudTrail API 호출 출처의 지리적 분포를 보여주는 세계 지도 |
| 2 | Top Countries by Request Volume | 쓰기 이벤트 및 고유 호출자 분석과 함께 API 호출량 기준 상위 20개 소스 국가 |
| 3 | Top Cities by Request Volume | 쓰기 이벤트 및 고유 호출자 분석과 함께 API 호출량 기준 상위 25개 도시 |
| 4 | Top ASN Organizations by Request Volume | API 호출량 기준 상위 25개 ASN 조직 |
| 5 | API Calls by Country (Event Name × GeoIP) | 상위 50개 (event_name, country) 쌍 — 어떤 API 작업이 각 지리적 지역에서 호출되는지 드러냅니다 (DSH-79) |
| 6 | Identities by Country (user_identity_arn × GeoIP) | 상위 50개 (user_identity_arn, country) 쌍 — 쓰기 수 및 처음/마지막 관찰과 함께 예기치 않은 국가에서 활동하는 IAM 자격 증명을 표면화합니다 (DSH-80) |

### 🕒 시간적 분석

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | First / Last Seen per IAM Identity | 처음/마지막 관찰 타임스탬프, 이벤트 수, 고유 API를 가진 IAM 자격 증명 |
| 2 | First / Last Seen per Source IP | 처음/마지막 관찰, 고유 자격 증명, 고유 API를 가진 소스 IP |
| 3 | First / Last Seen per API Call | 최초 출현순으로 정렬된 API 작업 — 새로운 호출은 새로운 공격 도구를 나타낼 수 있습니다 (DSH-33) |
| 4 | First / Last Seen per User Agent | 최초 출현순으로 정렬된 사용자 에이전트 — 새로운 도구 탐지 (DSH-34) |
| 5 | Dormant Accounts Reactivated | 72시간 이상의 비활성 간격 후 활동을 재개한 자격 증명 (DSH-37) |
| 6 | Event Velocity Spikes per Identity | 시간당 50개 이상의 이벤트 버스트 활동을 보이는 자격 증명 (DSH-38) |

### 🚨 고위험 API 모니터 (HRM)

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | High-Risk API Events Over Time | 공격 캠페인에서 흔히 관찰되는 API의 일일 호출량 (HRM-39) |
| 2 | Top High-Risk API Calls | 총 호출 수 기준으로 순위가 매겨진 고위험 감시 목록의 API 작업 (HRM-40) |
| 3 | Top Actors — High-Risk APIs | 고위험 감시 목록 API에 대한 총 호출 수 기준으로 순위가 매겨진 IAM 주체 (HRM-42) |
| 4 | Top Source IPs — High-Risk APIs | 고위험 감시 목록 API에 대한 총 호출 수 기준으로 순위가 매겨진 소스 IP (HRM-43) |
| 5 | Defense Evasion API Events | 감사 제어를 비활성화하거나 변조하는 데 사용되는 API의 상세 이벤트 로그 (HRM-44) |
| 6 | Credential Access API Events | 시크릿 및 자격 증명을 검색하는 데 사용되는 API의 상세 이벤트 로그 (HRM-45) |
| 7 | High-Risk API Calls by Region | AWS 리전별로 분포된 고위험 감시 목록 API 호출 (HRM-46) |

</details>

---
