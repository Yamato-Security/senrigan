# 내장 쿼리 및 대시보드 레퍼런스

> 💡 SQL이나 깊은 AWS 지식이 필요 없습니다 — 드롭다운에서 헌트를 선택하기만 하면 즉시 결과를 얻을 수 있습니다.

## 🎯 내장 헌트 — 126 쿼리

카테고리는 DFIR 트리아지 우선순위 순으로 정렬되어 있습니다 — 먼저 탐지 도구 변조를 확인하고, 그다음 자격 증명 남용, 그다음 데이터 영향을 확인하세요.

| 카테고리 | 쿼리 | 다루는 주요 위협 |
|----------|:-------:|---------------------|
| 🛡 Detection & Response | 12 | 감사 서비스 변조 (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · SCP 삭제 · 알람 억제 · 로그 유출 |
| 🔑 Identity & Access | 30 | 루트 사용 · 콘솔 로그인/MFA · 권한 상승 · 신뢰 정책 백도어 · PassRole 남용 · 교차 계정 AssumeRole · SSO/SAML/OIDC · 자격 증명 열거 · IAM 엔티티 삭제 · AssumeRoot 탈취 · Cognito 사용자 풀/토큰 남용 · 지원 케이스 억제 |
| 🪣 Data & Storage | 26 | S3 대량 삭제/다운로드 · 시크릿 대량 읽기 · 백업 변조 · KMS 작업 · 스냅샷 공유 · EBS Direct API 유출 · DynamoDB 내보내기 · S3 교차 계정 복제 · SSE-C 랜섬웨어 암호화 · 수명 주기 트리거 삭제 · RDS Data API 조작 · 영향을 위한 스토리지 재암호화 |
| ⚡ Compute & Serverless | 17 | EC2 대량 중지/종료 · SSM 측면 이동 · Lambda/ECS/EKS/ECR 변조 · EventBridge 지속성 · 크립토마이닝 · Lightsail 남용 · IMDS/SSRF 약화 · AMI/스냅샷 삭제 · WorkSpaces 탈취 |
| 🤖 AI & LLM Abuse | 6 | Bedrock 호출 급증 · 모델 액세스 활성화 · 호출 로깅 변조 · 리전 횡단 정찰 · 실패 호출 버스트 · 호출자/발신지 목록화 (LLMjacking) |
| 🌐 Network & Infrastructure | 15 | SG 인터넷 개방 · VPC 흐름 로그 삭제 · CloudFront 하이재킹 · 은밀한 VPN/TGW 터널 · Elastic IP C2 · API Gateway 키 · Route 53/도메인 탈취 |
| 🕵 Threat Patterns | 5 | 정찰 버스트 · 비정상 사용자 에이전트 · 다중 리전 확산 · 최초 API 호출 · 최초 관찰 리전 활동 |
| 📊 Activity & Baseline | 3 | 콘솔 쓰기 이벤트 · 오류 급증 · 최근 오류 |
| 🌍 GeoIP Analysis | 10 | 국가별 콘솔 로그인/거부/쓰기 · 드문 국가에서의 접근 · 국가/ASN/도시 분석 · event_name × country · identity × country · 프라이빗 IP 베이스라인 |
| ☁ IaC & Platform | 2 | CI/CD 공급망 · CloudFormation 남용 |

<details markdown="1">
<summary>📋 전체 목록 — 전체 126 쿼리 (클릭하여 확장)</summary>

## 내장 헌트

### 🛡 Detection & Response

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | CloudTrail을 중지하거나 수정하려는 모든 시도를 탐지합니다. 가장 중요한 경보 — 은폐를 나타냅니다. |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | GuardDuty 비활성화, 삭제, 위협 인텔리전스 조작을 탐지합니다. 조사 중 GuardDuty에 대한 어떤 변경도 중대한 지표입니다. |
| 3 | ⛔ Security Hub Tampering | timeseries | Security Hub 비활성화, 표준 비활성화, 발견 항목 억제를 탐지합니다. Security Hub를 무력화하면 모든 보안 발견 항목의 중앙 집계 지점이 사라집니다. |
| 4 | ⚙️ AWS Config Tampering | timeseries | AWS Config 레코더/규칙 삭제를 탐지합니다. Config를 중지하면 전체 리전의 규정 준수 증거와 변경 추적이 사라집니다. |
| 5 | 🛡 Organizations Service Control Policy (SCP) Changes | timeseries | SCP 생성, 수정, 삭제를 탐지합니다. Deny SCP를 제거하면 영향을 받는 OU 내 모든 계정의 가드레일이 즉시 사라집니다. |
| 6 | 🚫 AWS Macie Tampering | timeseries | Macie 비활성화 및 발견 항목 필터 생성을 탐지합니다. 공격자는 S3에서 민감한 데이터를 유출하기 전에 Macie 발견 항목을 억제합니다. |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | CloudWatch 알람 삭제 및 비활성화를 탐지합니다. GuardDuty, CloudTrail 메트릭 필터, 예산 임계값에 연결된 알람을 무력화하는 것은 방어 회피의 핵심 지표입니다. |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | CW Logs 구독 필터 생성/삭제 및 로그 그룹 삭제를 탐지합니다. 공격자는 로그를 외부 대상으로 스트리밍하거나 그 자리에서 증거를 파괴합니다. |
| 9 | 🏹 WAF WebACL Changes | timeseries | WAF WebACL 생성, 업데이트, 삭제를 탐지합니다. WebACL을 제거하거나 약화시키면 SQLi, XSS, DDoS 공격에 대한 보호가 비활성화됩니다. |
| 10 | 🔍 GuardDuty Findings Read | timeseries | 읽기 전용 GuardDuty API 호출을 탐지합니다. Pacu의 guardduty__list_findings 모듈은 활성 발견 항목을 읽어 방어자가 이미 탐지한 내용을 파악함으로써, 공격자가 전술을 조정하고 새로운 경보 발생을 피할 수 있게 합니다. |
| 11 | 💰 Budget / Cost Anomaly Changes | timeseries | AWS Budgets 및 Cost Anomaly 모니터의 삭제나 수정을 탐지합니다. 공격자는 크립토마이닝이나 리소스 집약적 작업을 숨기기 위해 예산 알림을 제거합니다. |
| 12 | 🚫 Access Denied Errors | bar | AccessDenied 오류를 자격 증명 및 API별로 그룹화합니다. 상위 위반자는 자격 증명 오용을 나타낼 수 있습니다. |

### 🔑 Identity & Access

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | 루트 계정으로 수행된 모든 API 호출을 탐지합니다. 루트는 프로덕션에서 절대 사용해서는 안 됩니다. |
| 2 | 🔓 Console Login without MFA | timeseries | MFA가 사용되지 않은 콘솔 로그인을 탐지합니다. 계정 침해의 고위험 지표입니다. |
| 3 | 🌐 Console Logins | timeseries | 모든 콘솔 로그인 시도를 나열합니다. 여러 번의 실패 후 성공이 이어지면 무차별 대입 공격입니다. |
| 4 | 🔐 MFA & Password Changes | timeseries | MFA 비활성화 및 비밀번호 재설정을 탐지합니다. 계정 탈취의 강력한 지표입니다. |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | 권한 상승에 사용되는 IAM 정책 연결 및 역할 조작 이벤트를 탐지합니다. |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | UpdateAssumeRolePolicy 호출을 탐지합니다. 신뢰 정책에 외부 계정 주체를 추가하면 지속적인 백도어가 생성됩니다. |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | 권한 경계 put/delete 이벤트를 탐지합니다. 권한 경계를 제거하면 주체의 유효 권한이 즉시 확장되어 권한 상승을 가능하게 합니다. |
| 8 | 👑 User Added to Admin Group | timeseries | 이름에 'admin'이 포함된 그룹에 추가된 사용자를 탐지합니다. 전형적인 권한 상승 기법입니다. |
| 9 | 👥 IAM Group Membership Changes | timeseries | 그룹 이름과 관계없이 모든 AddUserToGroup 및 RemoveUserFromGroup 이벤트를 탐지합니다. 그룹 추가는 그룹 상속 정책을 통한 권한 상승을 나타낼 수 있습니다. |
| 10 | 👤 New IAM Users / Keys | timeseries | IAM 사용자 및 액세스 키 생성 이벤트를 식별합니다. 예기치 않은 생성은 지속성을 나타낼 수 있습니다. |
| 11 | 🎯 IAM PassRole Abuse | timeseries | iam:PassRole 호출을 탐지합니다. 특권 역할을 EC2/Lambda/Glue/ECS/SageMaker에 전달하는 것은 가장 일반적인 측면 권한 상승 경로입니다. |
| 12 | 🔐 AssumeRole Cross-Account | timeseries | 호출자와 대상이 서로 다른 AWS 계정에 있는 AssumeRole 이벤트를 보여줍니다. 측면 이동을 나타냅니다. |
| 13 | 🏢 Cross-Account Access | timeseries | 호출자 계정이 수신자 계정과 다른 이벤트를 찾습니다. 측면 이동 신호입니다. |
| 14 | 🔑 STS Federation Token Issuance | timeseries | GetFederationToken 및 GetSessionToken 호출을 탐지합니다. 공격자는 이를 사용해 수명이 긴 키를 지속적인 임시 자격 증명으로 변환합니다. |
| 15 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | AssumeRoleWithWebIdentity 호출을 탐지합니다. 잘못 구성된 OIDC 신뢰 (예: 지나치게 넓은 sub 클레임)를 악용하면 공격자가 제어하는 토큰을 사용해 역할을 하이재킹할 수 있습니다. |
| 16 | 🆔 IAM Identity Center (SSO) Events | timeseries | AWS IAM Identity Center 관리 작업을 탐지합니다. 공격자는 SSO를 악용해 백도어 권한 세트를 만들거나 공격자가 제어하는 사용자에게 계정을 할당합니다. |
| 17 | 🔗 SAML / OIDC Provider Updates | timeseries | SAML/OIDC 자격 증명 공급자 변경을 탐지합니다. 공격자가 제어하는 메타데이터로 SAML 공급자를 업데이트하면 지속적인 인증 백도어가 생성됩니다. |
| 18 | 🧐 IAM Access Analyzer Calls | timeseries | IAM Access Analyzer의 모든 사용을 탐지합니다. 공격자는 사용자 지정 정찰 스크립트를 작성하지 않고도 외부에서 접근 가능한 리소스를 열거하기 위해 네이티브 AWS 분석기를 활용합니다. |
| 19 | 🔄 Credential Report & Enumeration | timeseries | 전체 IAM 환경을 매핑하는 IAM 열거 활동을 탐지합니다. 공격 초기 단계에서 흔히 발견됩니다. |
| 20 | 🗝 Access Key Abuse | bar | 7일 내 3개 이상의 서로 다른 소스 IP에서 사용된 액세스 키를 탐지합니다. 키 유출의 강력한 지표입니다. |
| 21 | 📰 AWS Organizations Account Creation | timeseries | Organizations 계정 생성 및 위임 관리자 변경을 탐지합니다. 공격자는 메인 계정 밖에 지속적인 거점을 마련하기 위해 섀도 계정을 생성합니다. |
| 22 | 👥 Cognito Unauthenticated Access | timeseries | 미인증 액세스가 활성화된 Cognito 자격 증명 풀을 탐지합니다. 익명 사용자가 미인증 IAM 역할의 권한으로 AWS API를 호출할 수 있게 합니다. |
| 23 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | Glue 개발 엔드포인트 생성과 자격 증명 수집을 위한 연결 열거를 탐지합니다. iam:PassRole + glue:CreateDevEndpoint는 전달된 역할의 전체 권한으로 SSH를 통한 접근을 부여합니다 — 가장 간과되기 쉬운 IAM 권한 상승 기법 중 하나입니다. |
| 24 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | SageMaker 노트북 인스턴스 생성 및 사전 서명 URL 생성을 탐지합니다. iam:PassRole + sagemaker:CreateNotebookInstance는 전달된 역할의 전체 AWS 권한을 가진 Jupyter 환경을 제공합니다. CreatePresignedNotebookInstanceUrl 단독으로도 기존 노트북에 대한 접근을 허용할 수 있습니다. |
| 25 | 🛠 Data Pipeline / CodeStar Privilege Escalation | timeseries | Data Pipeline 및 CodeStar 리소스 생성을 탐지합니다. 둘 다 iam:PassRole을 받아들이며 전달된 역할의 권한으로 임의의 코드를 실행할 수 있습니다. CodeStar:CreateProjectFromTemplate은 관리자 IAM 역할을 생성하는 문서화되지 않은 API입니다. |
| 26 | 🧩 Step Functions Privilege Escalation | timeseries | Step Functions 상태 머신 생성 및 실행을 탐지합니다. iam:PassRole + states:CreateStateMachine + states:StartExecution을 통해 전달된 역할의 권한으로 임의의 Lambda / ECS 작업을 실행할 수 있습니다. |
| 27 | 🪓 IAM Entity Deletion | timeseries | IAM 사용자, 역할, 정책, MFA 디바이스의 삭제를 탐지합니다. 공격자는 자신의 활동 흔적을 지우거나 방어자를 잠그기 위해 IAM 엔티티를 삭제합니다. |
| 28 | 👑 AssumeRoot Usage | timeseries | 관리 계정에서 회원 계정의 루트로 향하는 sts:AssumeRoot 호출을 탐지합니다. 관리 계정이 침해되면 이 방법으로 모든 회원 계정을 장악할 수 있습니다. |
| 29 | 🎫 Support Case Manipulation | timeseries | AWS Support 케이스 종료 및 댓글 활동을 탐지합니다. 공격자는 침해에 대한 AWS 알림을 억제하기 위해 남용/지원 케이스를 해결 처리합니다. |
| 30 | 🪪 Cognito User Pool Manipulation | timeseries | Cognito 사용자 풀 및 앱 클라이언트 변경(토큰 유효 기간 연장, 새 클라이언트, 관리자 사용자 생성)을 탐지합니다. 공격자는 이를 악용해 수명이 긴 토큰을 발급하거나 백도어 사용자를 심습니다. |

### 🪣 Data & Storage

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | 고빈도 DeleteObject/DeleteObjects 호출(시간당 50회 이상)을 탐지합니다. 유출과는 다른 — 데이터 파괴 / 랜섬웨어 패턴입니다. |
| 2 | 🔥 AWS Backup Tampering | timeseries | Backup Vault/Plan/RecoveryPoint 삭제를 탐지합니다. 백업 파괴는 복구를 막기 위한 랜섬웨어 공격의 첫 단계입니다. |
| 3 | 🔓 KMS Key Operations | timeseries | 키 삭제 및 대량 Decrypt 호출을 포함한 민감한 KMS 작업을 표시합니다. |
| 4 | 🔓 S3 Public Access Block Disabled | — | S3 퍼블릭 액세스 차단 설정이 비활성화되는 것을 탐지합니다. 즉각적인 데이터 노출 위험입니다. |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | S3 버킷 정책 및 ACL 변경을 탐지합니다. 버킷을 공개적으로 읽을 수 있게 만들거나 공격자가 제어하는 계정에 접근 권한을 부여할 수 있습니다. |
| 6 | 🪣 S3 Data Access Anomalies | bar | 데이터 유출을 나타낼 수 있는 대량 GetObject 호출(시간당 100회 이상)을 탐지합니다. |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | 시크릿(DB 비밀번호, API 키 등)의 대량 검색을 탐지합니다. 한 시간에 10회 이상의 GetSecretValue 호출은 자격 증명 수집의 강력한 신호입니다. |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | Secrets Manager 시크릿 삭제와 교차 계정 리소스 정책 변경을 탐지합니다. 기존의 대량 읽기 탐지를 파괴 및 정책을 통한 유출 벡터로 보완합니다. |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | SSM Parameter Store 항목의 대량 읽기를 탐지합니다. Secrets Manager에 비해 간과되기 쉬운 유출 채널입니다. |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | 외부 AWS 계정으로 공유된 RDS/Aurora 스냅샷을 탐지합니다. 스냅샷 공유를 통한 전형적인 데이터 유출입니다. |
| 11 | 💣 RDS Deleted without Final Snapshot | — | skipFinalSnapshot=true인 RDS 인스턴스/클러스터 삭제를 탐지합니다. 잠재적 데이터 파괴입니다. |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | PubliclyAccessible=true로 생성되거나 수정된 RDS 인스턴스를 탐지합니다. VPC 보안 제어를 우회하여 데이터베이스를 인터넷에 직접 노출시킵니다. |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | DynamoDB의 ExportTableToPointInTime(S3로의 조용한 전체 테이블 내보내기)과 테이블 삭제를 탐지합니다. 고위험 유출 및 파괴 벡터입니다. |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | EBS Direct API 호출(ListSnapshotBlocks / GetSnapshotBlock)을 탐지합니다. Pacu의 ebs__download_snapshots는 이 API를 사용해 EC2 인스턴스를 생성하지 않고 원시 스냅샷 데이터를 스트리밍하며, 기존의 스냅샷 공유 탐지를 우회합니다. |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | 외부 S3를 가리키는 Kinesis Firehose 전송 스트림 생성/업데이트를 탐지합니다. 네트워크 DLP에는 보이지 않는 실시간 데이터 파이프라인 유출입니다. |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | PutBucketReplication과 DeleteBucketReplication을 탐지합니다. 교차 계정 복제는 모든 새 객체를 공격자가 제어하는 버킷으로 조용히 복사합니다. |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | S3 버전 관리 중단 및 서버 액세스 로깅 비활성화를 탐지합니다. 버전 관리 비활성화는 데이터 파괴를 가능하게 하고, 로깅 비활성화는 접근 증거 흔적을 지웁니다. |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | SES 수신 규칙 및 자격 증명 구성 변경을 탐지합니다. 전달 규칙은 모든 수신 메일을 공격자 주소로 자동 중계할 수 있고, 검증된 자격 증명은 피싱 캠페인을 가능하게 합니다. |
| 19 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | 외부 계정에 접근 권한을 부여하는 SQS/SNS 큐/토픽 정책 변경을 탐지합니다. 대량 전송 경보를 유발하지 않고 조용한 유출 채널을 만듭니다. |
| 20 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | 공개적으로 공유된(group=all) EBS 스냅샷 또는 AMI를 탐지합니다. 누구나 디스크 이미지를 복사하고 데이터를 추출할 수 있게 됩니다. |
| 21 | 📧 Data Exfiltration Channels | bar | 유출을 나타낼 수 있는 대량 SNS/SQS/SES/S3 PutObject 호출(시간당 50회 이상)을 탐지합니다. |
| 22 | 🔐 S3 SSE-C Encryption (Ransomware) | timeseries | 공격자가 제공한 SSE-C 키로 재암호화된 S3 객체와 버킷 기본 암호화 설정 변경을 탐지합니다. 고객 키가 없으면 피해자는 복호화할 수 없습니다 — 클라우드 네이티브 랜섬웨어 패턴입니다. |
| 23 | ⏳ S3 Lifecycle-Triggered Deletion | timeseries | 객체를 만료시키는 S3 수명 주기 규칙과 수명 주기 구성 삭제를 탐지합니다. 공격자는 DeleteObject 호출 없이 시간이 지남에 따라 데이터를 조용히 삭제하기 위해 짧은 만료 기간을 설정합니다. |
| 24 | 🗃 RDS Query & Instance Manipulation | timeseries | RDS Data API 쿼리, 마스터 비밀번호 재설정, 스냅샷 복원을 탐지합니다. 공격자는 데이터를 직접 읽거나, 접근 권한을 얻기 위해 자격 증명을 재설정하거나, 스냅샷을 자신이 제어하는 인스턴스로 복원합니다. |
| 25 | 🔎 S3 Bucket Enumeration | bar | 버킷 및 객체 메타데이터를 훑는 호출자를 탐지합니다(한 시간에 10회 이상의 List/GetBucket* 읽기). 유출 전 가치 있는 데이터를 찾는 흔한 초기 단계입니다. |
| 26 | 🔑 Storage Re-Encryption for Impact | timeseries | 명시적 KMS 키로 재암호화된 EBS/RDS 스냅샷 및 볼륨과 기본 EBS 암호화 비활성화를 탐지합니다. 공격자가 보유한 키로 재암호화하면 데이터를 인질로 잡을 수 있습니다. |

### ⚡ Compute & Serverless

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | 고빈도 EC2 StopInstances/TerminateInstances(한 시간에 5회 이상)를 탐지합니다. 랜섬웨어에 의한 방해 또는 파괴적 공격을 나타냅니다. |
| 2 | 🖥️ SSM Session / Run Command | timeseries | SSM StartSession, SendCommand, 자동화 실행을 탐지합니다. 관리형 인스턴스를 통한 주요 측면 이동 경로입니다. |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | EC2 Instance Connect 및 시리얼 콘솔 접근을 탐지합니다. 이를 통해 공격자는 SSH 키나 배스천 호스트 없이 브라우저나 CLI에서 인스턴스에 접근할 수 있습니다. SSH 키가 없는 공격자에게 주요 측면 이동 경로입니다. |
| 4 | 📝 EC2 User Data Modification | timeseries | userData 필드를 변경하는 ModifyInstanceAttribute 호출을 탐지합니다. 사용자 데이터 스크립트는 다음 부팅 시 루트로 실행되어 지속적인 코드 실행 백도어를 제공합니다. |
| 5 | ⚡ Lambda Function Tampering | timeseries | Lambda 생성, 코드 업데이트, 권한 변경을 탐지합니다. 공격자는 지속성을 위해 Lambda를 사용합니다. |
| 6 | 📦 Lambda Layer Addition | timeseries | Lambda 레이어 게시 및 권한 변경을 탐지합니다. 악성 공유 레이어를 게시하고 프로덕션 함수에 추가하면 의존성 체인에 공격자의 코드가 주입됩니다. |
| 7 | 📦 ECS Task Definition | timeseries | ECS 작업 정의 등록 및 서비스 업데이트를 탐지합니다. Pacu의 ecs__backdoor_task_def는 악성 컨테이너 이미지를 가리키는 새 작업 정의 버전을 등록하고, 서비스를 업데이트하여 배포합니다 — ECR을 전혀 건드리지 않습니다. |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | IAM 인스턴스 프로필 연결 및 교체를 탐지합니다. 특권 프로필을 연결하면 인스턴스에 측면 이동을 위한 상승된 권한이 부여됩니다. |
| 9 | 🖥 EC2 Instance Launches | timeseries | 모든 RunInstances 이벤트를 나열합니다. 예기치 않은 리전에서의 시작은 크립토마이닝을 나타낼 수 있습니다. |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | 대규모 Spot Fleet 요청, 예약 인스턴스 구매, 높은 용량의 Auto Scaling 그룹 생성을 탐지합니다. 크립토마이닝의 재무적 영향 지표입니다. |
| 11 | ☸️ EKS Cluster API Calls | timeseries | EKS 클러스터 컨트롤 플레인 수정을 탐지합니다. 퍼블릭 API 서버 노출이나 불법 Fargate 프로필은 컨테이너 플랫폼 탈취를 가능하게 합니다. |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | ECR 리포지토리 생성/삭제, 정책 변경, 이미지 푸시를 탐지합니다. 프로덕션 리포지토리에 악성 이미지를 주입하는 것은 공급망 지속성 기법입니다. |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | EventBridge 규칙 및 EventBridge Scheduler 수정을 탐지합니다. 공격자는 실행 중인 프로세스 없이 지속성을 확립하기 위해 예약된 규칙을 사용합니다. |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | Lightsail 인스턴스 접근, 키 페어 작업, 포트 노출을 탐지합니다. Pacu에는 3개의 전용 Lightsail 모듈(enum, download_ssh_keys, generate_temp_access)이 있습니다. Lightsail 리소스는 표준 EC2 보안 경계 밖에서 작동합니다. |
| 15 | 🛰 IMDS Options Weakening | timeseries | IMDSv2를 선택 사항으로 만들거나 메타데이터 엔드포인트를 다시 활성화하는 ModifyInstanceMetadataOptions 호출을 탐지합니다. IMDS를 약화시키면 인스턴스 역할 자격 증명을 훔치는 SSRF 경로가 다시 열립니다. |
| 16 | 💥 AMI & Snapshot Deletion | bar | AMI의 대량 등록 취소 및 EBS 스냅샷 삭제(한 시간에 5회 이상)를 탐지합니다. 골든 이미지와 백업을 파괴하면 파괴적 공격 중 복구 옵션이 사라집니다. |
| 17 | 🖥 WorkSpaces Hijacking | timeseries | Amazon WorkSpaces 프로비저닝 및 풀 생성을 탐지합니다. 공격자는 피해자의 비용으로 데스크톱을 구동합니다 — EC2 경계 밖에 있는, 감시가 부족한 컴퓨팅 하이재킹 채널입니다. |

### 🤖 AI & LLM Abuse

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 🤖 Bedrock Model Invocation Spike | timeseries | 한 시간에 50회 이상 Bedrock 모델을 호출하는 주체를 탐지합니다. 도난당한 자격 증명을 이용한 대량 추론(LLMjacking)은 피해자에게 하루 수만 달러의 비용을 초래할 수 있습니다. |
| 2 | 🔓 Bedrock Model Access Enablement | timeseries | 파운데이션 모델 접근 활성화나 프로비저닝된 용량 구매를 탐지합니다. Bedrock을 한 번도 도입하지 않은 조직에서 이것은 노이즈가 거의 없는 LLMjacking 지표입니다 — 공격자의 전형적인 첫 번째 쓰기 작업입니다. |
| 3 | 🙈 Bedrock Invocation Logging Tampering | timeseries | Bedrock 모델 호출 로깅의 삭제나 수정, 그리고 공격자가 계정을 악용하기 전에 로깅이 활성화되어 있는지 확인하는 행위를 탐지합니다(문서화된 LLMjacking IOC입니다). |
| 4 | 🧭 Bedrock Reconnaissance Sweep | bar | 2개 이상의 리전에 걸쳐 Bedrock 모델을 열거하거나 한 시간에 10회 이상 열거 호출을 수행하는 호출자를 식별합니다. 도난당한 키의 소유자는 모델을 사용할 수 있는 위치를 찾기 위해 리전을 훑습니다. |
| 5 | ⛔ Failed Bedrock Invocations | bar | 실패한 Bedrock 호출(AccessDenied / ValidationException)의 버스트를 발견합니다. 도난당한 키 테스트는 유효한 조합을 찾을 때까지 여러 모델과 리전에 걸쳐 실패의 폭풍을 만들어냅니다. |
| 6 | 🌍 Bedrock Callers & Origins | — | Bedrock을 사용한 적이 있는 모든 주체를 소스 IP, GeoIP 발신지, 사용자 에이전트, 모델 다양성과 함께 목록화합니다. Bedrock을 사용할 이유가 전혀 없는 호출자나 발신지를 찾아냅니다. |

### 🌐 Network & Infrastructure

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 🌍 Security Group Opened to Internet | timeseries | 0.0.0.0/0에서 오는 트래픽을 허용하는 보안 그룹 규칙을 찾습니다. 직접적인 공개 노출 위험입니다. |
| 2 | 🔥 Security Group Modifications | timeseries | 보안 그룹 규칙 변경, 특히 임의의 포트에서 0.0.0.0/0을 허용하는 규칙을 탐지합니다. |
| 3 | 🌊 VPC Flow Log Changes | timeseries | VPC 흐름 로그의 삭제를 탐지합니다. 흐름 로그를 삭제하면 네트워크 수준의 증거가 사라지며, 이는 중요한 방어 회피 지표입니다. |
| 4 | 🌐 CloudFront Distribution Tampering | timeseries | CloudFront 배포 생성과 오리진 변경을 탐지합니다. 오리진 변경은 CDN 트래픽을 공격자가 제어하는 서버로 리디렉션하여 MitM 가로채기나 데이터 수집을 가능하게 합니다. |
| 5 | 🛡 Network Firewall / Shield Tampering | timeseries | Network Firewall 및 Shield 보호 제거를 탐지합니다. 네트워크 계층 방어를 삭제하면 VPC가 직접적인 공격 트래픽에 노출됩니다. |
| 6 | 🧱 Network ACL Changes | timeseries | 네트워크 ACL 항목 생성, 삭제, 교체를 탐지합니다. NACL은 보안 그룹을 재정의하며 서브넷 전체를 공격자에게 노출시킬 수 있습니다. |
| 7 | 🛣️ Route Table Changes | timeseries | 라우트 테이블 변경을 탐지합니다. 라우트 추가나 교체를 통해 트래픽을 공격자가 제어하는 호스트로 리디렉션할 수 있습니다(MitM, 트래픽 하이재킹). |
| 8 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | 새로운 VPN 연결, Direct Connect, Transit Gateway 연결을 탐지합니다. 공격자는 지속적인 C2 또는 유출 채널을 위해 은밀한 네트워크 터널을 생성합니다. |
| 9 | 📡 Elastic IP Allocation / Association | timeseries | Elastic IP 할당 및 연결을 탐지합니다. 공격자는 안정적인 C2 인프라를 구축하기 위해 침해된 인스턴스에 고정 퍼블릭 IP를 할당합니다. |
| 10 | 🗝️ EC2 Key Pair Creation | timeseries | CreateKeyPair 및 ImportKeyPair 이벤트를 탐지합니다. 공격자는 인스턴스 접근을 유지하기 위한 지속성 메커니즘으로 SSH 키를 생성하거나 가져옵니다. |
| 11 | 📡 Network Infrastructure Changes | timeseries | 공격자가 제어하는 인프라를 구축할 수 있는 VPC 및 네트워크 수준의 변경을 탐지합니다. |
| 12 | 🏷 ACM Certificate Operations | timeseries | ACM 인증서 요청 및 삭제를 탐지합니다. 공격자는 침해된 계정을 사용해 피싱 인프라를 구축하기 위한 공격자 제어 도메인용 TLS 인증서를 발급합니다. |
| 13 | 🔑 API Gateway Key Creation & Management | timeseries | API Gateway 키 생성 및 REST API 관리를 탐지합니다. Pacu의 api_gateway__create_api_keys는 IAM 키 교체에도 살아남는 지속적인 API 자격 증명을 생성합니다. 공격자는 접근 제어를 약화시키기 위해 API 권한 부여자도 수정합니다. |
| 14 | 🚧 VPC Endpoint Access Denied | timeseries | VPC 엔드포인트를 통한 액세스 거부 오류를 탐지합니다. 잘못 구성된 엔드포인트 정책을 나타낼 수 있습니다. |
| 15 | 🌐 Route 53 & Domain Changes | timeseries | DNS 레코드 편집, 호스팅 영역 변경, 도메인 등록/이전을 탐지합니다. 공격자는 트래픽을 리디렉션하거나, 방치된 서브도메인을 탈취하거나, 피싱을 위한 유사 도메인을 등록합니다. |

### 🕵 Threat Patterns

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | 한 시간에 10개 이상의 서로 다른 읽기 전용 API 호출을 수행한 호출자를 식별합니다. 일반적인 초기 공격 단계입니다. |
| 2 | 🤖 Unusual User Agents | bar | 드문 사용자 에이전트(5개 미만의 이벤트)를 나열합니다. Pacu나 curl 같은 사용자 지정 도구는 공격자 도구를 나타낼 수 있습니다. |
| 3 | 🌍 Multi-Region Activity | bar | 하루에 3개 이상의 리전에서 쓰기를 수행하는 자격 증명을 탐지합니다. 지리적 확산은 침해를 나타낼 수 있습니다. |
| 4 | 🕵 First-Time API Calls (24h) | — | 지난 24시간 내에는 보였지만 이전에는 본 적 없는 API 호출을 찾습니다. 새로운 작업은 공격자 도구를 나타낼 수 있습니다. |
| 5 | 🗺 First-Seen Region Activity | bar | 데이터셋의 지난 24시간 내에 사상 첫 활동이 발생한 AWS 리전을 찾습니다. 이전에 한 번도 사용된 적 없는 리전에서 작업하는 것은 리전 범위 모니터링으로부터 크립토마이닝이나 준비 작업을 숨기는 전형적인 방법입니다. |

### 📊 Activity & Baseline

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | AWS 콘솔을 통해 수행된 변경 API 호출을 식별합니다. CLI 전용 접근이 예상될 때 유용합니다. |
| 2 | 🔍 Events with Errors (24h) | timeseries | 지난 24시간 동안의 모든 오류 이벤트를 나열합니다. 현재 무엇이 실패하고 있는지 빠르게 파악할 수 있습니다. |
| 3 | ❌ Error Spike Detection | — | 오류 수가 일일 평균을 3배 초과하는 1시간 구간을 찾습니다. 스캐닝이나 장애를 시사합니다. |

### 🌍 GeoIP Analysis

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 🗺 Console Logins by Country | timeseries | 콘솔 로그인 이벤트를 지리적 출처에 매핑합니다. 예기치 않은 국가에서의 로그인은 고위험입니다. |
| 2 | 🚨 Unusual Country Access | bar | 드문 국가/자격 증명 조합을 보여줌으로써 예기치 않은 국가에서의 API 호출을 탐지합니다. |
| 3 | 🚫 Access Denied by Country | bar | 액세스 거부 오류를 소스 국가별로 그룹화합니다. 한 국가에서 집중된 거부는 공격을 시사할 수 있습니다. |
| 4 | 🔍 Write Events by Country | bar | 국가별로 그룹화된 변경(쓰기) API 호출을 보여줍니다. 예기치 않은 국가에서의 쓰기는 우선순위가 높습니다. |
| 5 | 🌍 Top Source Countries | bar | API 호출량으로 소스 국가의 순위를 매깁니다. 모든 활동의 지리적 분포를 식별합니다. |
| 6 | 🏢 Top ASN / Organizations | bar | API 호출량으로 자율 시스템(ISP/클라우드 공급자)을 나열합니다. VPN/호스팅 공급자를 찾아냅니다. |
| 7 | 📍 Top Source Cities | bar | 이벤트량으로 소스 도시의 순위를 매깁니다. 가장 활발한 지리적 출처를 정확히 찾아냅니다. |
| 8 | 📋 API Calls by Country (Event Name) | bar | 각 국가에서 호출되는 API 작업을 보여줍니다. 예기치 않은 국가에서의 쓰기 이벤트는 자격 증명 침해를 나타냅니다. |
| 9 | 👤 Identities by Country (user_identity_arn) | bar | 각 국가에서 활동하는 IAM 자격 증명을 보여줍니다. 새로운 국가에서 나타나는 자격 증명은 높은 신뢰도의 침해 지표입니다. |
| 10 | 🌐 Private / Internal IP Summary | bar | 프라이빗, 루프백, AWS 내부 IP에서 발생한 이벤트를 요약합니다. 예상되는 내부 트래픽의 베이스라인입니다. |

### ☁ IaC & Platform

| # | 레이블 | 차트 | 설명 |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | CI/CD 파이프라인 생성 및 수정을 탐지합니다. 악성 빌드 단계 주입이나 파이프라인 소스 변경은 이후의 모든 배포를 오염시킵니다. |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | CloudFormation 스택 작업을 탐지합니다. 공격자는 악성 인프라를 신속하게 배포하기 위해 IaC를 사용할 수 있습니다. |

</details>

---

## 📊 대시보드 차트 — 101 차트

| 탭 | 차트 | 표시 내용 |
|-----|:------:|---------------|
| 🚦 Overview | 10 | 9개의 트리아지 KPI 카드(이벤트, 주체, IP, 루트, MFA 없는 로그인, 액세스 거부, 방어 회피, 국가, 리전) + 전역 이벤트량 추세 |
| 🎯 Threat Detection | 12 | 방어 회피 종합 · 로깅 공백 · VPC 흐름 로그/Config/EventBridge/WAF 변조 · SCP/조직 멤버십 변경 · 오류 및 스로틀링 추세 · 쓰기/읽기 비율 |
| 🔑 Identity & Access | 16 | 콘솔 로그인 · MFA 추세 · 로그인 히트맵 · 실패→성공 인증 시퀀스 · 루트 사용 · IAM 엔티티 활동/삭제 · 권한 상승 타임라인 · 새 주체 · SSO · 교차 계정 AssumeRole · AssumeRoot 사용 |
| 🚨 High-Risk API Monitor | 5 | 보안 서비스 변조 & 자격 증명 검색 API 로그 · 상위 고위험 호출 · 상위 행위자 · 시계열 고위험 호출량 |
| 📊 API Activity | 6 | 상위 API · 액세스 거부 작업 · 리전 분포 · 오류 코드 구성 · 소스 IP · 사용자 에이전트 |
| 🪣 S3 & RDS | 15 | S3 대량 다운로드/삭제 · 버전 관리/로깅 비활성화 · 교차 계정 복제 · 버킷 정책/ACL · 열거 · 보호 설정 · Backup vault 삭제 · KMS 키 삭제 · RDS 스냅샷 공유 / 스냅샷 없는 삭제 · SSE-C 랜섬웨어 암호화 · 수명 주기 트리거 삭제 · RDS 쿼리/인스턴스 조작 · 영향을 위한 스토리지 재암호화 |
| 🖥️ Computing | 17 | EC2 시작/대량 중지/키 페어/인스턴스 프로필/사용자 데이터/스냅샷 공유/spot fleet · ECS/Lambda/SSM/EBS Direct API/EKS-ECR/CloudFormation · IMDS 약화 · AMI/스냅샷 삭제 · WorkSpaces 탈취 |
| 🤖 AI / LLM | 4 | Bedrock 호출 추세 · 모델 액세스 & 로그 변경 · 실패 호출 · 발신지별 호출자(LLMjacking 트리아지) |
| 🌐 Network | 5 | 보안 그룹 변경 · NACL/라우트 테이블 변경 · VPC 인프라 · VPC 피어링/Transit Gateway · Route53 DNS 변경 |
| 🕒 Temporal Analysis | 6 | 이벤트 속도 급증 · 재활성화된 휴면 계정 · 자격 증명/IP/API/서비스 소스별 처음/마지막 관찰 |
| 🌍 GeoIP Intelligence | 6 | 불가능한 이동(다중 국가 주체) · 상위 국가/도시/ASN · 세계 지도 · event_name × country |

<details markdown="1">
<summary>📋 전체 목록 — 전체 101 차트 (클릭하여 확장)</summary>

## 대시보드 차트 (Apache Superset — `dashboard/`)

### 🚦 Overview

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | Total Events | 선택한 범위 내 CloudTrail 이벤트의 총 수(KPI-81). 트리아지의 분모이며, 주체별 또는 IP별 모든 비율의 기준입니다. |
| 2 | Distinct Principals | 선택한 범위에서 활동한 고유 IAM 주체 ARN의 수(KPI-82). 검토 대상 활동에 관련된 자격 증명 수를 파악하는 데 사용합니다. |
| 3 | Distinct Source IPs | 선택한 범위에서 고유한 호출자 소스 IP 주소의 수(KPI-83). 베이스라인 대비 급증은 프록시/VPN 로테이션이나 분산 접근을 시사합니다. |
| 4 | Root Account Events | 계정 루트 자격 증명으로 수행된 이벤트 수(KPI-84). 루트 활동은 거의 0에 가까워야 합니다 — 0이 아닌 값은 모두 조사가 필요합니다. |
| 5 | MFA-less Console Logins | 선택한 범위에서 MFA 없는 콘솔 로그인 수(KPI-85). 자격 증명 침해의 직접적인 지표입니다 — MFA-less Login Trend를 자세히 살펴보세요. |
| 6 | Access Denied Events | 선택한 범위에서 인가 실패 이벤트 수(KPI-86). 급증은 정찰이나 권한 탐색을 시사합니다 — 주체/IP로 피벗하세요. |
| 7 | Defense-Evasion Hits | 선택한 범위에서 감사/모니터링 변조 이벤트 수(KPI-87). 최우선 트리아지 신호입니다 — 0이 아닌 값은 탐지가 비활성화되었을 수 있음을 의미합니다. Security Monitoring & Control Changes를 자세히 살펴보세요. MITRE ATT&CK: TA0005 Defense Evasion. |
| 8 | Distinct Countries | 선택한 범위에서 고유 소스 국가의 수(KPI-88). GeoIP 보강(docker/data/geoip/)이 필요합니다. 넓은 분포는 예기치 않은 지리적 출처에서의 접근을 시사합니다. |
| 9 | Active Regions | 선택한 범위에서 활동이 있는 고유 AWS 리전의 수(KPI-89). 사용하지 않는 리전에서의 활동은 리소스 남용이나 공격자의 준비 단계를 나타낼 수 있습니다. |
| 10 | CloudTrail Events Over Time | 시간 경과에 따른 시간당 Read 대 Write 이벤트량(DSH-01). 누적 막대는 Read/Write 분할을 보여줍니다 — write_events의 급격한 증가는 공격자가 정찰에서 적극적인 공격으로 전환하고 있음을 나타냅니다. 활동 급증이나 업무 외 시간 작업을 식별하는 데 유용합니다. |

### 🎯 Threat Detection

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | Security Monitoring & Control Changes | 모든 방어 회피 이벤트에 대한 종합적인 캐치올(DSH-22). CloudTrail 변조(StopLogging, DeleteTrail), GuardDuty 비활성화, AWS Config 비활성화, VPC 흐름 로그 삭제, CloudWatch 로그 삭제, 보안 서비스 비활성화(SecurityHub, IAM Access Analyzer)를 다룹니다. 여기에 나타나는 모든 이벤트는 즉각적인 조사가 필요합니다. 더 자세한 분석을 위해서는 전용 차트를 사용하세요: VPC Flow Log Changes(DSH-42), AWS Config Tampering(DSH-43), EventBridge/CW Tampering(DSH-47). MITRE ATT&CK: TA0005 Defense Evasion. |
| 2 | CloudTrail Logging Gap (Hourly Volume) | 시간별 CloudTrail 이벤트량(DSH-91). 활성 기간 사이에 갑자기 0으로 떨어지는 것은 로깅이 비활성화되었거나(StopLogging/DeleteTrail) 전달 사각지대가 존재함을 시사합니다. 예기치 않은 공백은 Security Monitoring & Control Changes 테이블과 대조하여 조사하세요. MITRE ATT&CK: T1562.008 Impair Defenses — Disable Cloud Logs. |
| 3 | VPC Flow Log Changes | VPC 흐름 로그 생성 및 삭제 이벤트(DSH-42). DeleteFlowLogs는 주요 네트워크 포렌식 증거 소스를 제거하여 측면 이동 및 데이터 유출에 대한 사후 분석을 불가능하게 만듭니다. 인시던트 중의 CreateFlowLogs는 공격자가 제어하는 S3 버킷으로의 로그 리디렉션을 나타낼 수 있습니다. MITRE ATT&CK: TA0005 Defense Evasion. |
| 4 | AWS Config Recorder & Rule Changes | AWS Config 레코더 및 규칙 변조 이벤트(DSH-43): StopConfigurationRecorder, DeleteConfigurationRecorder, DeleteDeliveryChannel, DeleteConfigRule, PutConfigRule. Config 레코더를 중지하면 전체 리전의 규정 준수 증거와 변경 추적이 사라져, 이후의 인프라 변경이 Config 규칙 및 Security Hub 표준에 의해 탐지되지 않게 됩니다. MITRE ATT&CK: TA0005 Defense Evasion. |
| 5 | EventBridge & CloudWatch Rule Modifications | EventBridge 및 CloudWatch Events 규칙 변조(DSH-47): DeleteRule, DisableRule(예약된 탐지 무력화), CreateSchedule/UpdateSchedule(C2 비콘용 공격자 cron 작업), PutSubscriptionFilter(CloudTrail/VPC 로그를 공격자 계정으로 리디렉션), DeleteLogGroup(VPC 흐름 로그 기록 파괴). DFIR을 위한 모니터링 계층 변조 통합 차트입니다. MITRE ATT&CK: TA0003 Persistence / TA0005 Defense Evasion / TA0011 C2. |
| 6 | WAF Configuration Changes | AWS WAF v2 / WAF Classic 설정 변경 이벤트(DSH-75). WebACL 생성/업데이트/삭제, IP 세트 조작, 규칙 그룹 변경, 로깅 구성 변경, 보호 대상 리소스와 WAF의 연결/해제를 다룹니다. 공격이 진행 중일 때 WAF 규칙이나 로깅을 비활성화하는 것은 강력한 방어 회피 지표입니다. MITRE ATT&CK: TA0005 Defense Evasion / TA0003 Persistence. |
| 7 | Organizations / SCP Changes | SCP 정책 변경을 포함한 AWS Organizations 관리 플레인 이벤트(DSH-24). 마스터 계정 접근 권한을 가진 공격자는 전체 AWS 조직에 걸친 예방적 제어를 제거하기 위해 SCP 가드레일을 비활성화할 수 있습니다. MITRE ATT&CK: TA0004 Privilege Escalation / TA0005 Defense Evasion. |
| 8 | Error Event Trend | error_code별로 분류한 시간별 오류 이벤트(DSH-04). ThrottlingException 급증은 자동화된 스캐닝이나 공격 도구를 나타내고, AccessDenied / UnauthorizedAccess 급증은 권한 탐색을 나타냅니다. 새로운 오류 코드의 갑작스러운 출현은 새로운 공격 기법을 나타낼 수 있습니다. |
| 9 | Throttling Exception Spikes | AWS 서비스별 시간별 스로틀링/속도 제한 오류(DSH-21). ThrottlingException 급증은 자격 증명(또는 도구)이 예상보다 훨씬 빠르게 API 호출을 발생시키고 있음을 나타내며, 이는 정찰이나 열거를 수행하는 자동화된 공격 도구의 특징입니다. MITRE ATT&CK: TA0007 Discovery. |
| 10 | Write/Read Ratio Trend | 읽기 대 쓰기 API 호출의 시간별 분석(DSH-20). read_events 대비 write_events의 지속적인 증가는 공격자가 정찰에서 적극적인 공격으로 전환했음을 나타냅니다. MITRE ATT&CK: TA0040 Impact / TA0007 Discovery. |
| 11 | CloudTrail Events Over Time | 시간 경과에 따른 시간당 Read 대 Write 이벤트량(DSH-01). 누적 막대는 Read/Write 분할을 보여줍니다 — write_events의 급격한 증가는 공격자가 정찰에서 적극적인 공격으로 전환하고 있음을 나타냅니다. 활동 급증이나 업무 외 시간 작업을 식별하는 데 유용합니다. |
| 12 | Organization Membership Changes | 계정을 가드레일에서 분리하거나 공격자가 제어하는 조직 아래로 이동시키는 Organizations 멤버십 변경. Threat Technique Catalog for AWS: T1666.A002 / T1666.A003. |

### 🔑 Identity & Access

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | Console Login Activity | IAM 자격 증명별로 그룹화된 AWS Management Console 로그인 이벤트(DSH-08). 성공, 실패, MFA 없는 로그인 시도를 추적합니다. 실패 대 성공 비율이 높으면 무차별 대입이나 크리덴셜 스터핑을 나타낼 수 있습니다. mfa_less_count(MFAUsed = 'No')는 계정 침해의 직접적인 지표이지만, 이는 기존의 ConsoleLogin 이벤트에만 적용되며, 새로운 OAuth2 로그인 흐름(CreateOAuth2Token / AuthorizeOAuth2Access)은 MFA 상태를 보고하지 않습니다. 이벤트는 event_type = 'AwsConsoleSignIn'으로 필터링됩니다. |
| 2 | MFA-less Login Trend | MFA 사용 여부로 분리된 일일 콘솔 로그인(DSH-28). mfa_less_logins(MFAUsed = 'No')는 계정 침해나 피싱의 직접적인 지표입니다. MFA 없는 로그인의 지속적인 증가는 IAM 인증 정책의 즉각적인 검토를 촉발해야 합니다. MITRE ATT&CK: TA0001 Initial Access. |
| 3 | Failed -> Success Auth Sequence | 주체 + 소스 IP별 콘솔 로그인 실패 및 성공(DSH-93). 큰 failure_count와 0이 아닌 success_count의 조합은 결국 성공한 무차별 대입 / 패스워드 스프레이를 나타냅니다 — 성공을 침해 지점으로 취급하고 소스 IP로 피벗하세요. MITRE ATT&CK: T1110 Brute Force. |
| 4 | Login Activity Heatmap (Hour x Day) | JST 기준 요일(Y)별 시간대(X)별 콘솔 로그인 수의 히트맵(DSH-19). 심야(22:00-06:00 JST) 열이나 주말 행이 밝게 나타나면 계정 침해나 자격 증명 오용의 강력한 지표입니다. MITRE ATT&CK: TA0001 Initial Access. |
| 5 | Root Account Usage | AWS Root 계정으로 수행된 모든 API 호출(DSH-13). 잘 관리되는 환경에서는 루트 계정 사용이 극히 드물어야 합니다. 루트 활동 — 특히 CreateAccessKey, ConsoleLogin, StopLogging — 은 모두 침해 또는 정책 위반의 중대한 지표입니다. |
| 6 | IAM Entity Activity | 총 API 호출 수로 순위를 매긴 상위 50개 IAM 엔티티(쓰기 비율 및 오류 분석 포함)(DSH-03). write_ratio_pct 또는 error_events가 높은 엔티티는 자격 증명 오용이나 권한 상승을 나타낼 수 있습니다. last_seen은 각 엔티티의 가장 최근 활동 타임스탬프를 보여줍니다. |
| 7 | IAM Privilege Change Event Timeline | 이벤트 이름별로 분류한 권한 상승 API 호출의 일일 수(DSH-30). 하루 만의 급증은 표적 공격 캠페인을 나타내고, 완만한 증가는 내부자 위협이나 지속적인 거점을 가진 공격자를 나타낼 수 있습니다. MITRE ATT&CK: TA0004 Privilege Escalation. |
| 8 | New IAM Principal Creation Timeline | 이벤트 유형별로 누적된 일일 IAM 주체 및 자격 증명 생성 이벤트(DSH-95). CreateAccessKey / CreateLoginProfile / CreateUser의 급증은 초기 접근 이후의 지속성 지표입니다 — 실행 주체와 소스 IP를 상관 분석하세요. MITRE ATT&CK: T1136 Create Account / T1098 Account Manipulation. |
| 9 | Glue & SageMaker IAM Role Pass Events | IAM 권한 상승에 사용되는 Glue DevEndpoint 및 SageMaker Notebook 이벤트(DSH-50). iam:PassRole + glue:CreateDevEndpoint는 전달된 역할의 전체 권한을 가진 SSH 접근 가능한 Python/Spark 환경을 생성합니다. iam:PassRole + sagemaker:CreateNotebookInstance는 동일한 효과를 가진 Jupyter 노트북을 제공합니다. sagemaker:CreatePresignedNotebookInstanceUrl 단독으로도 기본 역할을 소유하지 않고 기존 노트북에 대한 접근을 부여할 수 있습니다. 둘 다 AWS-IAM-Privilege-Escalation 저장소에 문서화되어 있으며 Pacu의 iam__privesc_scan 모듈에 구현되어 있습니다. MITRE ATT&CK: TA0004 Privilege Escalation. |
| 10 | AssumedRole from External IP | 퍼블릭(비프라이빗) IP 주소에서 발생한 AssumedRole API 호출(DSH-27). EC2 인스턴스 메타데이터 서비스(IMDS) 자격 증명은 일반적으로 VPC 내에서만 사용됩니다. 외부 IP에서의 호출은 임시 자격 증명이 유출되었음을 나타냅니다 — 일반적으로 SSRF, 컨테이너 탈출, 키 내보내기를 통해서입니다. MITRE ATT&CK: TA0008 Lateral Movement / TA0006 Credential Access. |
| 11 | Cross-Account AssumeRole | recipient_account_id가 호출자의 계정과 다른 AssumeRole / AssumeRoleWithWebIdentity 호출(DSH-94). 예기치 않은 외부 계정 ID는 신뢰 관계 남용이나 계정 간 측면 이동을 나타냅니다 — 각 대상 계정이 승인된 신뢰 대상인지 확인하세요. MITRE ATT&CK: T1199 Trusted Relationship / TA0008 Lateral Movement. |
| 12 | Secrets Access Anomaly | 한 시간에 10회 이상 Secrets Manager 또는 SSM Parameter Store에 접근하는 자격 증명(DSH-23). 대량 자격 증명 읽기는 침해 후 지표입니다 — 공격자는 다른 서비스나 계정으로 피벗하기 위해 저장된 시크릿을 수집합니다. MITRE ATT&CK: TA0006 Credential Access / TA0010 Exfiltration. |
| 13 | Security-Relevant API Calls | 알려진 보안 민감 AWS API 작업의 호출(DSH-12). IAM 자격 증명 변경, 정책 수정, S3 버킷 정책 변경, 보안 그룹 수정, 키 관리, STS 토큰 작업, 보안 서비스 비활성화, Secrets Manager 읽기, Organizations 관리를 다룹니다. 이러한 호출은 정상적인 운영에서 드물어야 합니다 — 예기치 않은 발생은 권한 상승, 지속성, 또는 데이터 유출을 나타낼 수 있습니다. |
| 14 | IAM Identity Center (SSO) Events | sso.amazonaws.com, sso-directory.amazonaws.com, sso-oauth.amazonaws.com, identitystore.amazonaws.com에서 발생하는 AWS IAM Identity Center 관리 이벤트(DSH-44). Identity Center는 다중 계정 조직에서 주요 인증 경로입니다. 주요 위협: CreatePermissionSet(백도어 관리자 접근), CreateAccountAssignment(공격자가 제어하는 사용자에게 계정 할당), AttachManagedPolicyToPermissionSet(권한 상승). MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence / TA0004 Privilege Escalation. |
| 15 | IAM Entity Deletion | 공격자가 생성한 자격 증명의 흔적을 지우거나 방어자를 잠그는 데 사용되는 IAM 사용자, 역할, 정책, MFA 디바이스의 삭제. Threat Technique Catalog for AWS: T1070.A001. |
| 16 | AssumeRoot Usage | 관리 계정에서 회원 계정의 루트로 향하는 sts:AssumeRoot 호출 — 회원 계정을 완전히 장악하는 경로입니다. Threat Technique Catalog for AWS: AT1669. |

### 🚨 High-Risk API Monitor

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | Security Service Modification API Events | 감사 제어를 비활성화하거나 변조하는 데 사용되는 API의 상세 이벤트 로그(HRM-44). 다루는 범위: DeleteTrail, StopLogging, UpdateTrail, PutEventSelectors(CloudTrail 변조), DeletePolicy 및 DetachPolicy(IAM 가드레일 제거). 승인된 변경 기간 외에 발생하는 것은 모두 즉각적인 조사가 필요합니다. MITRE ATT&CK: TA0005 Defense Evasion. |
| 2 | Credential Retrieval API Events | 시크릿과 자격 증명을 검색하는 데 사용되는 API의 상세 이벤트 로그(HRM-45). 다루는 범위: GetSecretValue(Secrets Manager), GetParameter / GetParameterHistory(SSM). 단일 호출은 정당할 수 있지만, 짧은 시간 내에 수십 개의 서로 다른 시크릿에 접근하는 것은 강력한 공격자 신호입니다. MITRE ATT&CK: TA0006 Credential Access. |
| 3 | Top High-Risk API Calls | 총 호출 수로 순위를 매긴 고위험 감시 목록의 API 작업(HRM-40). 많은 환경에서 정찰 API(ListUsers, GetCallerIdentity)가 자주 나타나는 것은 예상되는 일입니다 — 비정상적인 양으로, 또는 예기치 않은 주체로부터 나타나는 자격 증명 접근 및 방어 회피 API에 조사의 초점을 맞추세요. |
| 4 | Top Actors — High-Risk APIs | 고위험 감시 목록 API에 대한 총 호출 수로 순위를 매긴 IAM 주체(HRM-42). 각 주체가 수행하는 작업을 확인하려면 attack-category 차트와 상호 참조하세요. 서비스 역할이 AssumeRole을 자주 호출하는 것은 예상되지만, 사람 사용자가 GetSecretValue나 DeleteTrail을 대량으로 호출하는 것은 예상되지 않습니다. |
| 5 | High-Risk API Events Over Time | 공격 캠페인에서 흔히 관찰되는 API의 일일 호출량(HRM-39). DeleteTrail이나 GetSecretValue처럼 일반적으로 드문 작업의 갑작스러운 급증은 즉각적인 조사가 필요합니다. 이러한 API 중 많은 수가 정당한 워크플로에서도 호출된다는 점에 유의하세요 — 단순한 존재가 아닌 양적 이상을 주요 신호로 사용하세요. MITRE ATT&CK: TA0001 / TA0003 / TA0004 / TA0005 / TA0006 / TA0007 / TA0008. |

### 📊 API Activity

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | Top 20 API Calls | 가장 자주 호출되는 20개의 AWS API 작업(DSH-02). 민감한 작업(AssumeRole, GetSecretValue 등)의 호출 수가 많으면 자동화된 도구나 정찰을 나타낼 수 있습니다. |
| 2 | Top Access Denied Actions | AccessDenied 또는 Client.UnauthorizedAccess 오류를 반환한 상위 20개 API 작업(DSH-09). 민감한 API(AssumeRole, GetSecretValue, PutBucketPolicy 등)에 대한 반복적인 액세스 거부 이벤트는 권한 상승 시도나 측면 이동의 강력한 지표입니다. |
| 3 | Region Activity | AWS 리전 전반의 CloudTrail 이벤트 분포(DSH-14). write_ratio_pct는 쓰기 활동이 불균형하게 많은 리전을 강조합니다 — 높은 쓰기 비율을 가진 예기치 않은 리전은 크립토마이닝 EC2 인스턴스, 측면 이동, 또는 감시가 적은 리전으로의 데이터 유출을 나타낼 수 있습니다. |
| 4 | Error-Code Composition Over Time | error_code별로 누적한 일일 CloudTrail 오류량(DSH-96). AccessDenied / UnauthorizedOperation 대역의 상승은 정찰이나 권한 탐색을 나타내고, Throttling 급증은 대규모 열거를 시사합니다. MITRE ATT&CK: TA0007 Discovery. |
| 5 | Top Source IP Addresses | 요청 수 기준 상위 100개 외부 소스 IP(DSH-05). AWS 내부 IP 패턴(*.amazonaws.com)은 제외됩니다. request_count 대비 write_requests가 많은 IP는 유출, 측면 이동, 또는 자동화된 공격 도구를 나타낼 수 있습니다. |
| 6 | User Agent Analysis | 요청 수 기준 상위 50개 사용자 에이전트(오류 및 쓰기 분석 포함)(DSH-11). 비정상적이거나 사용자 지정된 사용자 에이전트(Python/boto3, 사용자 지정 스크립트, Pacu, ScoutSuite 등)는 자동화된 공격 도구를 나타낼 수 있습니다. AWS 내부 에이전트(console.amazonaws.com, signin.amazonaws.com)는 예상되지만, 알려지지 않은 문자열은 조사가 필요합니다. |

### 🪣 S3 & RDS

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | S3 High-Volume Object Downloads | S3 대량 GetObject 호출(DSH-52): 한 시간에 100회 이상의 GetObject 요청을 수행한 자격 증명을 시간 버킷, 자격 증명, 소스 IP별로 그룹화. 대량 읽기는 자동화된 데이터 유출을 나타냅니다 — 공격자는 버킷 내용을 파괴하거나 몸값을 요구하기 전에 덤프합니다. S3 Bulk Deletion 차트와 결합하면 유출 후 파괴라는 랜섬웨어의 전체 흐름을 파악할 수 있습니다. MITRE ATT&CK: TA0010 Exfiltration. |
| 2 | S3 Bulk Object Deletion | S3 대량 DeleteObject/DeleteObjects 호출(DSH-53): 한 시간에 50개 이상의 객체를 삭제한 자격 증명을 시간 버킷, 자격 증명, 소스 IP별로 그룹화. 대량 삭제는 랜섬웨어 공격의 데이터 파괴 단계입니다 — 공격자는 먼저 유출(S3 Bulk Download 차트 참조)한 후 소스 버킷을 지워 피해자를 협박합니다. 우발적인 대량 삭제도 다룹니다. MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction. |
| 3 | S3 Versioning / Logging Disabled | S3 버전 관리 중단 및 로깅 비활성화 이벤트(DSH-54): Status=Suspended인 PutBucketVersioning과 BucketLoggingStatus가 비어 있는 PutBucketLogging. 공격자는 삭제 후 객체 복구를 방지하기 위해 버전 관리를 비활성화하고, 접근 증거 흔적을 지우기 위해 로깅을 비활성화합니다. 둘 다 데이터 파괴의 전조가 되는 안티 포렌식 행위입니다. MITRE ATT&CK: TA0005 Defense Evasion / T1070 Indicator Removal. |
| 4 | S3 Cross-Account Replication | S3 교차 계정 복제 구성 이벤트(DSH-55): PutBucketReplication 및 DeleteBucketReplication. 교차 계정 복제는 모든 새 객체를 공격자가 제어하는 버킷으로 조용히 복사하여, 네트워크 DLP 제어를 우회하는 지속적인 유출 채널을 구축합니다. 외부 계정 ID를 가리키는 PutBucketReplication은 모두 중대한 인시던트 지표입니다. MITRE ATT&CK: TA0010 Exfiltration / T1537 Transfer Data to Cloud Account. |
| 5 | S3 Bucket Policy / ACL Changes | S3 버킷 정책 및 ACL 수정 이벤트(DSH-45): PutBucketPolicy, DeleteBucketPolicy, PutBucketAcl, PutBucketCors, PutBucketWebsite, DeleteBucketWebsite. 이러한 변경은 버킷 콘텐츠를 공개적으로 노출하거나 공격자가 제어하는 계정에 접근 권한을 부여할 수 있습니다. Principal='*'인 PutBucketPolicy는 즉각적인 데이터 노출 지표입니다. MITRE ATT&CK: TA0010 Exfiltration / TA0005 Defense Evasion. |
| 6 | S3 Bucket & Object List Activity | 자격 증명 및 소스 IP별로 그룹화한 S3 열거 API 호출(DSH-74). ListBuckets(전체 계정 발견), ListObjects / ListObjectsV2(버킷별 열거), ListObjectVersions, ListMultipartUploads, HeadBucket, HeadObject를 다룹니다. 새로운 자격 증명이나 외부 IP에서의 list 호출 급증은 자격 증명 침해 후 정찰을 강하게 시사합니다. MITRE ATT&CK: TA0007 Discovery. |
| 7 | S3 Protection Config Changes | 버킷의 보안 태세를 약화시키는 S3 이벤트(DSH-25). 서버 액세스 로깅 비활성화는 감사 추적을 제거하고, 퍼블릭 액세스 차단 해제는 데이터를 인터넷에 노출시키며, 버킷 암호화나 복제 삭제는 저장 데이터 보호를 약화시킵니다. 이는 유출 전 또는 은폐 조치입니다. MITRE ATT&CK: TA0005 Defense Evasion / TA0040 Impact. |
| 8 | AWS Backup Vault & Plan Deletion Events | AWS Backup Vault, Plan, Recovery Point 삭제 이벤트(DSH-57): DeleteBackupVault, DeleteBackupPlan, DeleteRecoveryPoint, DeleteBackupSelection, DisassociateRecoveryPoint, PutBackupVaultAccessPolicy, DeleteBackupVaultLockConfiguration. 백업 파괴는 랜섬웨어 캠페인의 첫 단계입니다 — 몸값 요구 전에 피해자가 백업에서 복원할 수 없도록 보장합니다. Vault Lock 삭제(DeleteBackupVaultLockConfiguration)는 vault에서 WORM 불변성을 제거하기 때문에 특히 중대합니다. MITRE ATT&CK: TA0040 Impact / T1490 Inhibit System Recovery. |
| 9 | KMS Key Deletion & Disable Events | KMS 키 삭제, 비활성화, 로테이션 관리 이벤트(DSH-66). ScheduleKeyDeletion — 키 삭제를 예약(7~30일 취소 가능 기간). DisableKey — 키를 이용한 암호화/복호화를 즉시 중지. DeleteImportedKeyMaterial — 가져온 키의 키 자료를 즉시 파괴. DisableKeyRotation — 연간 자동 키 로테이션을 방지. 이러한 이벤트 중 하나라도 발생하면 해당 키로 암호화된 모든 데이터가 영구적으로 접근 불가능해집니다. 삭제일 이전에 ScheduleKeyDeletion을 취소하려면 CancelKeyDeletion을 사용하세요. MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction. |
| 10 | RDS Deleted without Final Snapshot | 최종 스냅샷 없이 삭제된 RDS 인스턴스 및 클러스터(DSH-56): 최종 스냅샷이 생성되지 않은 DeleteDBInstance 및 DeleteDBCluster 이벤트. 최종 스냅샷을 건너뛰면 데이터베이스를 복구할 수 없게 됩니다 — 삭제 후 복원 지점이 존재하지 않습니다. 랜섬웨어 행위자는 AWS Backup도 비활성화된 경우 피해자에 대한 압박을 극대화하기 위해 이를 사용합니다. 여기에 나타나는 모든 이벤트는 중대한 인시던트입니다. MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction. |
| 11 | RDS Snapshot Cross-Account Share | RDS 및 Aurora 스냅샷 공유 이벤트(DSH-40): 복원 권한이 다른 AWS 계정에 부여된(valuesToAdd) ModifyDBSnapshotAttribute 및 ModifyDBClusterSnapshotAttribute. 공격자는 S3/네트워크 기반 DLP를 거치지 않고 전체 데이터베이스를 유출하기 위해 자신의 계정에 스냅샷을 공유합니다. 복원 속성에 포함된 외부 계정 ID는 모두 중대한 유출 지표입니다. MITRE ATT&CK: TA0010 Exfiltration. |
| 12 | S3 SSE-C Ransomware Encryption | 공격자가 제공한 SSE-C 키로 재암호화된 S3 객체와 버킷 기본 암호화 설정 변경 — 클라우드 네이티브 랜섬웨어입니다. Threat Technique Catalog for AWS: T1486.A001. |
| 13 | S3 Lifecycle-Triggered Deletion | DeleteObject 폭주 없이 데이터를 조용히 삭제하는 데 사용되는, 객체를 만료시키는 S3 수명 주기 규칙(및 수명 주기 구성 삭제). Threat Technique Catalog for AWS: T1485.001. |
| 14 | RDS Query & Instance Manipulation | 데이터를 직접 읽거나 공격자가 제어하는 인스턴스로 복원하는 데 사용되는 RDS Data API 쿼리 및 스냅샷 복원. Threat Technique Catalog for AWS: AT1023.001 / T1213.A013. |
| 15 | Storage Re-Encryption for Impact | 공격자가 제어하는 명시적 KMS 키로 재암호화된 EBS/RDS 스냅샷 및 볼륨과 기본 암호화 비활성화. Threat Technique Catalog for AWS: T1486.A002 / T1486.A003. |

### 🖥️ Computing

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | EC2 Instance Launches | 모든 EC2 RunInstances 이벤트(DSH-58). 공격자는 크립토마이닝(GPU/spot), C2 릴레이, 또는 측면 이동 준비를 위해 인스턴스를 시작합니다 — 탐지를 피하기 위해 예기치 않은 리전에서 이루어지는 경우가 많습니다. 리전 이상 조사를 위해서는 aws_region으로 필터링하고, 어떤 자격 증명이 시작을 트리거했는지 추적하려면 user_identity_arn으로 필터링하세요. MITRE ATT&CK: TA0002 Execution / TA0040 Impact (Resource Hijacking). |
| 2 | RunInstances Spike by Region | AWS 리전별로 누적한 일일 EC2 RunInstances 량(DSH-97). 특히 정상 운영 범위 밖의 리전에서의 갑작스러운 급증은 크립토마이닝이나 리소스 남용을 나타냅니다. 실행 주체와 소스 IP를 상호 참조하세요. MITRE ATT&CK: T1496 Resource Hijacking. |
| 3 | EC2 Mass Stop / Terminate | EC2 StopInstances 및 TerminateInstances 이벤트(DSH-62). 단일 API 호출로 수십 개의 인스턴스를 동시에 중지하거나 종료할 수 있습니다. 대량 종료는 랜섬웨어나 사보타주 공격의 파괴 단계로, 프로덕션 EC2 용량을 다운시킵니다. 영향을 받은 모든 instanceId의 전체 목록은 request_parameters 필드를 확인하세요. 랜섬웨어의 전체 흐름을 파악하려면 AWS Backup Tampering 및 S3 Bulk Deletion 차트와 함께 확인하세요. MITRE ATT&CK: TA0040 Impact / T1489 Service Stop. |
| 4 | EC2 Key Pair Creation | EC2 키 페어 생성 및 가져오기 이벤트(DSH-59): CreateKeyPair, ImportKeyPair, DeleteKeyPair. 공격자는 IAM 자격 증명 로테이션에도 살아남는 지속적인 SSH 접근을 EC2 인스턴스에 확립하기 위해 새 키 페어를 생성합니다. ImportKeyPair는 AWS가 생성하지 않고도 공격자가 제어하는 공개 키를 직접 주입합니다. 낯선 자격 증명이나 IP에서의 CreateKeyPair 또는 ImportKeyPair는 모두 지속성 지표입니다. MITRE ATT&CK: TA0003 Persistence. |
| 5 | EC2 Instance Profile Changes | EC2 인스턴스 프로필 및 IAM 인스턴스 프로필 관리 이벤트(DSH-60). IAM: CreateInstanceProfile, DeleteInstanceProfile, AddRoleToInstanceProfile, RemoveRoleFromInstanceProfile. EC2: AssociateIamInstanceProfile, DisassociateIamInstanceProfile, ReplaceIamInstanceProfileAssociation. 인스턴스 프로필을 변경하면 인스턴스의 모든 코드가 사용할 수 있는 IAM 역할이 교체됩니다 — 공격자가 인스턴스를 제어하지만 더 높은 권한의 역할을 원할 때 흔히 사용되는 권한 상승 경로입니다. MITRE ATT&CK: TA0004 Privilege Escalation / TA0003 Persistence. |
| 6 | EC2 User Data Modification | EC2 사용자 데이터 수정 이벤트(DSH-61): userData 속성이 변경된 ModifyInstanceAttribute. EC2 사용자 데이터는 인스턴스가 (재)시작될 때마다 cloud-init에 의해 실행됩니다 — 악성 스크립트를 주입하면 재부팅에도 살아남는 지속적인 코드 실행이 가능해집니다. 실행을 트리거하기 위해 종종 중지/시작 시퀀스(EC2 Mass Stop / Terminate 차트 참조)와 함께 사용됩니다. MITRE ATT&CK: TA0003 Persistence / TA0002 Execution. |
| 7 | EC2 Public Snapshot / AMI Sharing | EC2 EBS 스냅샷 및 AMI 퍼블릭 공유 이벤트(DSH-41): 그룹 'all'에 createVolumePermission이 부여된 ModifySnapshotAttribute와 그룹 'all'에 launchPermission이 부여된 ModifyImageAttribute. 퍼블릭 스냅샷이나 AMI는 모든 AWS 계정이 디스크 이미지를 복사하고 볼륨에 저장된 민감한 데이터, 자격 증명, 개인 키를 추출할 수 있게 합니다. MITRE ATT&CK: TA0010 Exfiltration. |
| 8 | EC2 Spot Fleet & Reserved Instance Purchases | EC2 Spot Fleet, Fleet, 예약 인스턴스 구매 이벤트(DSH-63): RequestSpotFleet, ModifySpotFleetRequest, CancelSpotFleetRequests, CreateFleet, DeleteFleet, PurchaseReservedInstancesOffering, RequestSpotInstances, CancelSpotInstanceRequests. 공격자는 Spot Fleet을 사용해 크립토마이닝을 위한 대규모 GPU/CPU 클러스터를 시작하며, 인스턴스별 탐지 임계값을 피하면서 높은 AWS 청구액을 발생시킵니다. 예기치 않은 Spot Fleet 또는 예약 인스턴스 구매는 모두 조사가 필요합니다. MITRE ATT&CK: TA0040 Impact / T1496 Resource Hijacking. |
| 9 | ECS Task Definition & Service Changes | ECS 작업 정의 등록 및 서비스 수정 이벤트(DSH-49). Pacu의 ecs__backdoor_task_def는 자격 증명을 훔치는 사이드카 컨테이너를 주입하는 새 작업 정의 리비전을 등록하고, 이를 배포하기 위해 UpdateService를 실행합니다 — ECR 이미지 모니터링을 완전히 우회합니다. 낯선 호출자나 IP에서의 예기치 않은 RegisterTaskDefinition 또는 UpdateService는 모두 즉각적인 조사가 필요합니다. MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0006 Credential Access. |
| 10 | Lambda Function Configuration & Permission Changes | Lambda 함수 생성, 코드 업데이트, 권한 이벤트(DSH-64). UpdateFunctionCode는 함수 코드를 악성 페이로드로 교체합니다. AddPermission은 교차 계정 또는 퍼블릭 Lambda 호출 접근을 부여합니다. CreateFunctionUrlConfig는 직접적인 C2를 위한 퍼블릭 HTTP 엔드포인트를 생성합니다. CreateEventSourceMapping은 함수가 S3/DynamoDB/SQS에서 트리거되도록 연결합니다. PublishLayerVersion은 여러 함수에 걸쳐 악성 공유 레이어를 주입합니다. 이 중 어느 것이든 예기치 않은 자격 증명이나 IP에서 발생하면 지속성/실행 지표입니다. MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0011 Command and Control. |
| 11 | SSM Session / Run Command Execution | AWS Systems Manager 원격 실행 이벤트(DSH-39): StartSession, TerminateSession, ResumeSession, SendCommand, StartAutomationExecution. SSM Session Manager는 열린 SSH/RDP 포트 없이 셸 접근을 제공하며, 도난당한 IAM 자격 증명을 가진 공격자에게 주요 측면 이동 메커니즘입니다. 특이한 IP나 자격 증명에서의 예기치 않은 세션이나 명령은 모두 즉각적인 조사가 필요합니다. MITRE ATT&CK: TA0008 Lateral Movement / TA0002 Execution. |
| 12 | EBS Direct API Snapshot Block Access | 스냅샷 데이터 유출에 사용되는 EBS Direct API 호출(DSH-51). Pacu의 ebs__download_snapshots는 ListSnapshotBlocks와 GetSnapshotBlock을 사용해, EC2 인스턴스 생성, 스냅샷 복사 요청, ModifySnapshotAttribute 이벤트 트리거 없이 완전한 EBS 디스크 이미지를 블록 단위로 스트리밍합니다 — 기존의 스냅샷 공유 탐지에는 보이지 않습니다. 낯선 자격 증명이나 IP 주소에서의 GetSnapshotBlock 또는 ListSnapshotBlocks 호출은 모두 중대한 유출 지표입니다. MITRE ATT&CK: TA0010 Exfiltration / TA0009 Collection. |
| 13 | EKS / ECR Container Platform Events | EKS 클러스터 및 ECR 컨테이너 레지스트리 이벤트(DSH-48). EKS: UpdateClusterConfig(퍼블릭 API), CreateFargateProfile(악성 워크로드), AssociateIdentityProviderConfig(불법 OIDC IdP). ECR: PutImage(백도어가 포함된 이미지 푸시), SetRepositoryPolicy(교차 계정 접근), PutRegistryPolicy(조직 전체 레지스트리 노출). 컨테이너 플랫폼 이벤트는 공급망 공격 및 Kubernetes 컨트롤 플레인 침해를 탐지하는 데 중요합니다. MITRE ATT&CK: TA0002 Execution / TA0003 Persistence / TA0010 Exfiltration. |
| 14 | CloudFormation Stack Changes | CloudFormation 스택 및 변경 세트 관리 이벤트(DSH-65). 단일 UpdateStack으로 EC2 인스턴스를 배포하거나, IAM 역할을 수정하거나, 네트워킹을 재구성할 수 있어 수십 개의 개별 API 호출을 하나의 이벤트로 통합합니다. CreateStackSet은 조직 내 모든 계정에 공격자 인프라를 배포합니다. ExecuteChangeSet은 사전 준비된 변경을 적용하여 초기 검토에서 영향 범위를 숨깁니다. DeleteStack은 포렌식 증거가 되는 리소스를 파괴할 수 있습니다. MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0005 Defense Evasion. |
| 15 | IMDS Options Weakening | IMDSv2를 선택 사항으로 만들거나 메타데이터 엔드포인트를 다시 활성화하여 SSRF 자격 증명 탈취 경로를 다시 여는 ModifyInstanceMetadataOptions 호출. Threat Technique Catalog for AWS: T1552.005. |
| 16 | AMI & Snapshot Deletion | 파괴적 공격 중 복구 기준선을 파괴하는 AMI 등록 취소 및 EBS 스냅샷 삭제. Threat Technique Catalog for AWS: T1485.A002. |
| 17 | WorkSpaces Hijacking | EC2 보안 경계 밖에서 컴퓨팅 하이재킹에 사용되는 Amazon WorkSpaces 프로비저닝. Threat Technique Catalog for AWS: T1496.A009. |

### 🤖 AI / LLM

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | Bedrock Model Invocation Trend | 주체별 일일 Amazon Bedrock 모델 호출량(DSH-98). 도난당한 자격 증명을 이용한 대량 추론(LLMjacking)은 피해자의 비용으로 리버스 프록시를 통해 재판매됩니다. 급증, 이전에 Bedrock을 한 번도 호출한 적 없는 주체, 예기치 않은 발신지로부터의 호출은 모두 조사하세요. MITRE ATT&CK: TA0040 Impact (T1496 Resource Hijacking). |
| 2 | Bedrock Model Access & Logging Changes | 파운데이션 모델 접근 활성화 및 호출 로깅 변조(DSH-99). 도난당한 자격 증명을 가진 공격자는 악용하기 전에 스스로 Bedrock 모델 접근을 활성화하고, 프롬프트가 기록되지 않도록 모델 호출 로깅 설정을 확인하거나 삭제합니다 — 둘 다 문서화된 LLMjacking 지표입니다. Bedrock을 한 번도 도입하지 않은 조직에서의 어떤 행도 즉각적인 조사가 필요합니다. MITRE ATT&CK: TA0005 Defense Evasion / TA0040 Impact (T1496). |
| 3 | Bedrock Failed Invocations | 호출자와 오류 코드로 그룹화한 실패한 Amazon Bedrock 호출 시도(DSH-100). 여러 모델과 리전에 걸친 AccessDenied / ValidationException 오류의 버스트는 공격자가 도난당한 키로 호출할 수 있는 모델을 탐색하고 있음을 나타냅니다 — LLMjacking의 정찰 단계입니다. MITRE ATT&CK: TA0006 Credential Access / TA0007 Discovery. |
| 4 | Bedrock Callers by Origin | 발신지와 모델 다양성을 포함한 모든 Amazon Bedrock 호출자의 목록(DSH-101). LLMjacking 트리아지를 위한 베이스라인 뷰: 예기치 않은 국가, 호스팅/VPN ASN, 또는 일반적인 스크립트 사용자 에이전트(python-requests, curl)에서 높은 호출량으로 호출하는 주체는 유력한 용의자입니다. MITRE ATT&CK: TA0040 Impact (T1496 Resource Hijacking). |

### 🌐 Network

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | Security Group Changes | EC2 보안 그룹 규칙 변경(DSH-76). 인바운드/아웃바운드 규칙 허용 및 취소, 보안 그룹 생성 및 삭제, 규칙 설명 업데이트를 다룹니다. 관리 포트(22, 3389 등)에서 0.0.0.0/0에 개방된 인바운드 규칙은 백도어 접근이나 잘못된 구성의 강력한 지표입니다. MITRE ATT&CK: TA0003 Persistence / TA0005 Defense Evasion. |
| 2 | Network ACL / Route Table Changes | 네트워크 ACL 및 라우트 테이블 수정 이벤트(DSH-46). NACL 변경(CreateNetworkAclEntry, DeleteNetworkAclEntry, ReplaceNetworkAclEntry)은 전체 서브넷에 대해 보안 그룹 제한을 우회할 수 있습니다. 라우트 테이블 변경(CreateRoute, ReplaceRoute, DeleteRoute)은 가로채기를 위해 트래픽을 공격자가 제어하는 인프라로 리디렉션하거나 조용한 C2 통신 채널을 구축할 수 있습니다. MITRE ATT&CK: TA0005 Defense Evasion / TA0011 Command and Control. |
| 3 | VPC Infrastructure Changes | VPC 토폴로지 변경 이벤트(DSH-77). VPC 생성/삭제/수정, 서브넷 변경, 인터넷 게이트웨이 연결, NAT 게이트웨이 생성/삭제, VPC 엔드포인트 변경, Elastic IP 할당/연결을 다룹니다. 예기치 않은 IGW 연결이나 사용하지 않는 리전에서의 새 NAT 게이트웨이는 공격자가 제어하는 유출 인프라의 강력한 지표입니다. MITRE ATT&CK: TA0010 Exfiltration / TA0003 Persistence / TA0011 C2. |
| 4 | VPC Peering & Transit Gateway Changes | VPC 피어링 연결 및 Transit Gateway 변경 이벤트(DSH-78). VPC 피어링 생성/수락/삭제 및 Transit Gateway 생성, VPC 연결, 피어링 연결 관리를 다룹니다. 교차 계정 피어링 요청이나 예기치 않은 계정에서의 새 Transit Gateway 연결은 AWS 계정 간 측면 이동을 나타냅니다. MITRE ATT&CK: TA0008 Lateral Movement / TA0010 Exfiltration. |
| 5 | Route53 DNS Changes | Route 53 호스팅 영역 및 리졸버 구성 변경(DSH-29). DNS 터널링은 TXT/CNAME 레코드와 대량의 서브도메인을 사용해 DNS 쿼리 페이로드로 데이터를 유출합니다. 새 호스팅 영역이나 예기치 않은 ChangeResourceRecordSets 호출은 즉시 조사해야 합니다. MITRE ATT&CK: TA0010 Exfiltration. |

### 🕒 Temporal Analysis

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | Event Velocity Spikes per Identity | 한 시간에 50건 이상의 이벤트 버스트 활동 기간을 가진 자격 증명(DSH-38). 크리덴셜 스터핑, 자동화된 열거, 데이터 유출은 정상 베이스라인을 넘는 급격한 속도 급증을 만들어냅니다. 각 급증의 시간 버킷, 자격 증명, 이벤트 수를 보여줍니다. MITRE ATT&CK: TA0006 Credential Access / TA0009 Collection / TA0010 Exfiltration. |
| 2 | Dormant Accounts Reactivated | 72시간 이상의 비활성 기간을 거쳐 활동을 재개한 자격 증명(DSH-37). 침해된 휴면 자격 증명이 무기화되는 전형적인 패턴입니다. 자격 증명별로 연속된 이벤트 사이의 최대 간격을 시간/일 단위로 보여줍니다. MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence. |
| 3 | First / Last Seen per IAM Identity | 처음/마지막 관찰 타임스탬프, 이벤트 수, 고유 API 수, 고유 IP 수, 일 단위 활동 기간을 가진 IAM 자격 증명(DSH-31). first_seen 내림차순으로 정렬하면 새로 나타난 자격 증명을 찾을 수 있습니다. 이벤트 수는 많은데 활동 기간이 짧으면 침해된 자격 증명이나 자동화된 공격을 나타냅니다. MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence. |
| 4 | First / Last Seen per Source IP | 처음/마지막 관찰, 고유 자격 증명, 고유 API, GeoIP 컨텍스트를 가진 소스 IP(DSH-32). 데이터셋 후반에 나타나는 새 IP는 측면 이동이나 새로운 공격자 인프라를 시사합니다. MITRE ATT&CK: TA0001 Initial Access / TA0008 Lateral Movement. |
| 5 | First / Last Seen per API Call | 최초 출현 순으로 정렬된 API 작업(DSH-33). 처음으로 나타나는 새로운 API 호출은 정찰이나 권한 상승 시도를 시사합니다. MITRE ATT&CK: TA0007 Discovery / TA0004 Privilege Escalation. |
| 6 | First / Last Seen per Service Source | 모든 고유 AWS 서비스 소스의 처음/마지막 관찰 타임스탬프(DSH-26). first_seen 내림차순으로 정렬하면 새로 도입된 서비스(잠재적 공격자 인프라)가 드러납니다. last_seen 오름차순으로 정렬하면 활동이 멈춘 서비스(침해 후 정리 가능성)를 찾을 수 있습니다. MITRE ATT&CK: TA0003 Persistence / TA0007 Discovery. |

### 🌍 GeoIP Intelligence

| # | 차트 이름 | 설명 |
|---|------------|-------------|
| 1 | Impossible Travel (Multi-Country Principals) | 서로 다른 소스 국가의 수로 순위를 매긴 IAM 주체(고유 소스 IP, 총 이벤트 수, 처음/마지막 관찰 포함)(DSH-92). 사람 주체에서 distinct_countries >= 2는 강력한 계정 침해 신호입니다 — 시간 창과 소스 IP를 상호 참조하세요. GeoIP 보강이 필요합니다. MITRE ATT&CK: TA0001 Initial Access / T1078 Valid Accounts. |
| 2 | Top Countries by Request Volume | API 호출량 기준 상위 20개 소스 국가(쓰기 이벤트 및 고유 호출자 분석 포함)(DSH-15). 조직의 업무와 일반적으로 관련 없는 국가는 자격 증명 도난이나 공격자가 제어하는 인프라를 나타낼 수 있습니다. GeoLite2 보강이 필요합니다 — NULL 행은 자동으로 제외됩니다. |
| 3 | Top ASN Organizations by Request Volume | API 호출량 기준 상위 25개 ASN 조직(쓰기 이벤트 및 고유 호출자 분석 포함)(DSH-18). VPN 공급자, Tor 출구 노드, 호스팅 회사, 또는 예상 범위 밖의 클라우드 공급자에서 발생한 트래픽은 공격자의 익명화 인프라 사용을 나타낼 수 있습니다. GeoLite2 보강이 필요합니다 — NULL 행은 자동으로 제외됩니다. |
| 4 | Top Cities by Request Volume | API 호출량 기준 상위 25개 도시(쓰기 이벤트 및 고유 호출자 분석 포함)(DSH-17). 도시 수준의 세분성은 국가 수준 분석만으로는 드러나지 않는, 위협 행위자가 사용하는 특정 데이터 센터 위치를 밝혀낼 수 있습니다. GeoLite2 보강이 필요합니다 — NULL 행은 자동으로 제외됩니다. |
| 5 | Global Request Origin Map | CloudTrail API 호출 출처의 지리적 분포를 보여주는 세계 지도(DSH-16). 국가 색상 농도는 이벤트 수에 비례합니다. 조직의 업무와 일반적으로 관련 없는 국가는 자격 증명 도난이나 공격자가 제어하는 인프라를 나타낼 수 있습니다. GeoLite2 보강이 필요합니다 — NULL 행은 자동으로 제외됩니다. |
| 6 | API Calls by Country (Event Name × GeoIP) | API 호출량 기준 상위 50개 (event_name, country) 쌍(DSH-79). 어떤 API 작업이 각 지리적 지역에서 호출되는지 드러냅니다. 예기치 않은 국가에서의 쓰기 작업은 자격 증명 침해의 강력한 지표입니다. GeoLite2 보강이 필요합니다 — 프라이빗/내부 IP와 NULL 행은 제외됩니다. |

</details>

---
