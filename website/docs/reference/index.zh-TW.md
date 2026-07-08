# 內建查詢與儀表板參考

> 💡 無需 SQL 或深入的 AWS 知識——只要從下拉選單中選擇一項獵捕，即可立即取得結果。

## 🎯 內建獵捕——100+ 個查詢

類別依 DFIR 分流優先順序排列——先檢查偵測工具竄改，接著是身分濫用，再來是資料影響。

| 類別 | 查詢 | 涵蓋的主要威脅 |
|----------|:-------:|---------------------|
| 🛡 偵測與回應 | 12 | 稽核服務竄改（CloudTrail/GuardDuty/Config/SecurityHub/Macie）· SCP 刪除 · 警報抑制 · 日誌外洩 |
| 🔑 身分與存取 | 26 | Root 使用 · 主控台登入/MFA · 權限提升 · 信任政策後門 · PassRole 濫用 · 跨帳戶 AssumeRole · SSO/SAML/OIDC · 憑證列舉 |
| 🪣 資料與儲存 | 21 | S3 大量刪除/下載 · 機密大量讀取 · 備份竄改 · KMS 操作 · 快照分享 · EBS Direct API 外洩 · DynamoDB 匯出 · S3 跨帳戶複寫 |
| ⚡ 運算與無伺服器 | 14 | EC2 大量停止/終止 · SSM 橫向移動 · Lambda/ECS/EKS/ECR 竄改 · EventBridge 持續駐留 · 加密貨幣挖礦 · Lightsail 濫用 |
| 🌐 網路與基礎設施 | 14 | SG 對網際網路開放 · VPC 流量日誌刪除 · CloudFront 劫持 · 隱蔽 VPN/TGW 通道 · Elastic IP C2 · API Gateway 金鑰 |
| 🕵 威脅樣態 | 5 | 非上班時間寫入 · 偵察爆發 · 多區域擴散 · 異常使用者代理 · 首次 API 呼叫 |
| 📊 活動與基準線 | 3 | 主控台寫入事件 · 錯誤激增 · 近期錯誤 |
| 🌍 GeoIP 分析 ✦ | 12 | 不可能的移動 · 多國憑證 · 地理排名登入/拒絕/寫入 · 國家/城市/ASN 細分 · event_name × country · identity × country |
| ☁ IaC 與平台 | 2 | CI/CD 供應鏈 · CloudFormation 濫用 |

<details markdown="1">
<summary>📋 完整清單——全部 100+ 個查詢（點擊展開）</summary>

## 內建獵捕

### 🛡 偵測與回應

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | 偵測任何停止或修改 CloudTrail 的嘗試——最關鍵的掩蓋行為指標 |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | 偵測 GuardDuty 停用、刪除及威脅情資操弄 |
| 3 | ⛔ Security Hub Tampering | timeseries | 偵測 Security Hub 停用、標準停用及發現項目抑制 |
| 4 | ⚙️ AWS Config Tampering | timeseries | 偵測 AWS Config 記錄器/規則刪除（消除合規證據） |
| 5 | 🛡 Organizations SCP Changes | timeseries | 偵測 SCP 建立、更新及刪除——移除 Deny SCP 會消除整個 OU 中每個帳戶的防護機制 |
| 6 | 🚫 AWS Macie Tampering | timeseries | 偵測 Macie 停用及發現項目篩選器建立（外洩前的防禦規避） |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | 偵測警報刪除及 DisableAlarmActions——在不刪除警報的情況下使安全警示靜音 |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | 偵測 CW Logs 訂閱篩選器建立/刪除（即時將日誌外洩至攻擊者的 Kinesis/Lambda） |
| 9 | 🏹 WAF WebACL Changes | timeseries | 偵測 WAFv2/WAF Classic 中的 WAF WebACL 建立、更新及刪除 |
| 10 | 🔍 GuardDuty Findings Read | timeseries | 偵測 ListFindings / GetFindings——攻擊者讀取作用中的發現項目以了解 SOC 已偵測到什麼 |
| 11 | 💰 Budget / Cost Anomaly Changes | timeseries | 偵測 Budget/AnomalyMonitor 刪除（隱藏加密貨幣挖礦成本） |
| 12 | 🚫 Access Denied Errors | bar | 依身分及 API 將 AccessDenied 錯誤分組——排名最高者表示憑證遭濫用 |

### 🔑 身分與存取

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | 偵測 root 帳戶發出的任何 API 呼叫——正式環境中絕不應使用 root |
| 2 | 🔓 Console Login without MFA | timeseries | 偵測未使用 MFA 的主控台登入——帳戶遭入侵的高風險指標 |
| 3 | 🌐 Console Logins | timeseries | 列出所有主控台登入嘗試，包含成功與失敗（暴力破解偵測） |
| 4 | 🔐 MFA & Password Changes | timeseries | 偵測 MFA 停用及密碼重設——帳戶遭接管的強烈指標 |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | 偵測 IAM 政策附加及角色操弄（PutUserPolicy、AttachRolePolicy、CreatePolicyVersion 等） |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | 偵測 UpdateAssumeRolePolicy——將外部主體新增至信任政策會建立持續性後門 |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | 偵測權限邊界 put/delete 事件——移除邊界會立即擴大有效權限 |
| 8 | 👑 User Added to Admin Group | timeseries | 偵測使用者被加入名稱中含 'admin' 的群組——典型的權限提升 |
| 9 | 👥 IAM Group Membership Changes | timeseries | 偵測所有 AddUserToGroup / RemoveUserFromGroup / CreateGroup / DeleteGroup 事件，無論群組名稱為何 |
| 10 | 👤 New IAM Users / Keys | timeseries | 辨識 IAM 使用者及存取金鑰建立事件——意外建立可能表示持續駐留 |
| 11 | 🎯 IAM PassRole Abuse | timeseries | 偵測 iam:PassRole 使用，方法是檢查傳遞角色 ARN 的接收服務事件（RunInstances、CreateFunction、CreateNotebookInstance 等） |
| 12 | 🔐 AssumeRole Cross-Account | timeseries | 顯示呼叫方與目標位於不同 AWS 帳戶的 AssumeRole 事件（橫向移動） |
| 13 | 🏢 Cross-Account Access | timeseries | 找出所有呼叫方帳戶與接收方帳戶不同的事件 |
| 14 | 🔑 STS Federation Token Issuance | timeseries | 偵測 GetFederationToken 及 GetSessionToken——將長期金鑰轉換為持續性的臨時憑證 |
| 15 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | 偵測 OIDC 信任濫用（錯誤設定的 sub 宣告 / 無 repo 條件的 GitHub Actions） |
| 16 | 🆔 IAM Identity Center (SSO) Events | timeseries | 偵測 AWS IAM Identity Center 管理動作（CreatePermissionSet、CreateAccountAssignment 等） |
| 17 | 🔗 SAML / OIDC Provider Updates | timeseries | 偵測 SAML/OIDC 身分提供者變更——以攻擊者控制的 IdP 更新 SAML 中繼資料會建立持續性的驗證後門 |
| 18 | 🧐 IAM Access Analyzer Calls | timeseries | 偵測任何 IAM Access Analyzer 的使用——攻擊者利用原生分析器列舉可從外部存取的資源，無需自訂偵察腳本 |
| 19 | 🔄 Credential Report & Enumeration | timeseries | 偵測 IAM 列舉（GenerateCredentialReport、ListUsers、ListRoles、GetAccountAuthorizationDetails 等） |
| 20 | 🗝 Access Key Abuse | bar | 偵測在 7 天內從 3 個以上不同來源 IP 使用的存取金鑰——金鑰外洩的強烈指標 |
| 21 | 📰 AWS Organizations Account Creation | timeseries | 偵測 Organizations 帳戶建立及委派管理員變更（影子帳戶持續駐留） |
| 22 | 👥 Cognito Unauthenticated Access | timeseries | 偵測 allowUnauthenticatedIdentities=true 的 Cognito Identity Pools |
| 23 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | 偵測 Glue DevEndpoint 建立（iam:PassRole + glue:CreateDevEndpoint = 以所傳遞角色完整權限執行的 SSH 可存取端點）及為竊取憑證而進行的連線列舉 |
| 24 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | 偵測 SageMaker notebook 建立及預先簽署 URL 產生——iam:PassRole + sagemaker:CreateNotebookInstance 會以所傳遞角色的完整 AWS 權限啟動 Jupyter 環境 |
| 25 | 🛠 Data Pipeline / CodeStar Privilege Escalation | timeseries | 偵測用於 iam:PassRole 提權的 Data Pipeline 及 CodeStar 資源建立（CreateProjectFromTemplate 會附帶建立一個管理員 IAM 角色） |
| 26 | 🧩 Step Functions Privilege Escalation | timeseries | 偵測 Step Functions 狀態機建立（iam:PassRole + states:CreateStateMachine 會以所傳遞角色執行 Lambda/ECS 任務） |

### 🪣 資料與儲存

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | 偵測每小時執行 ≥50 次 DeleteObject/DeleteObjects 呼叫的身分——勒索軟體 / 抹除程式資料破壞樣態 |
| 2 | 🔥 AWS Backup Tampering | timeseries | 偵測 Backup Vault / Plan / RecoveryPoint 刪除及 Vault Lock 移除——勒索軟體消除復原選項的第一步 |
| 3 | 🔓 KMS Key Operations | timeseries | 標記敏感的 KMS 操作（DisableKey、ScheduleKeyDeletion、CreateGrant、PutKeyPolicy、大量 Decrypt） |
| 4 | 🔓 S3 Public Access Block Disabled | — | 偵測 S3 公開存取封鎖設定遭停用——立即的資料曝險 |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | 偵測 S3 儲存桶政策及 ACL 修改（含 Principal='*' 的 PutBucketPolicy 尤其關鍵） |
| 6 | 🪣 S3 Data Access Anomalies | bar | 偵測大量 GetObject 呼叫（≥100/小時）——自動化資料外洩樣態 |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | 偵測在一小時內擷取 ≥10 個不同機密的身分——竊取憑證的訊號 |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | 偵測機密刪除、PutResourcePolicy（跨帳戶分享）及 CancelRotateSecret |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | 偵測在一小時內讀取 ≥20 個參數的身分——一個常被忽略的外洩通道 |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | 偵測分享給外部 AWS 帳戶的 RDS/Aurora 快照（透過快照進行資料庫外洩） |
| 11 | 💣 RDS Deleted without Final Snapshot | — | 偵測 skipFinalSnapshot=true 的 RDS 刪除——潛在的資料破壞 |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | 偵測以 publiclyAccessible=true 建立或修改的 RDS 執行個體 |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | 偵測 ExportTableToPointInTime（繞過 GetItem DLP 的伺服器端整表匯出）、DeleteTable 及 PITR 停用 |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | 偵測 EBS Direct API（ListSnapshotBlocks / GetSnapshotBlock）——Pacu ebs__download_snapshots 在不使用 EC2 的情況下串流原始快照資料，繞過 ModifySnapshotAttribute 偵測 |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | 偵測指向外部 S3 的 Firehose 傳遞串流建立/更新——即時資料管線，對網路 DLP 不可見 |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | 偵測 PutBucketReplication——在不產生額外 GetObject 事件的情況下，靜默地將所有新物件複製到攻擊者控制的儲存桶 |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | 偵測版本控制暫停（啟用永久刪除）及伺服器存取日誌停用（移除證據軌跡） |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | 偵測 SES 接收規則及身分設定變更——轉寄規則會將所有收到的郵件轉送至攻擊者地址；經驗證的身分可用於釣魚活動 |
| 19 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | 偵測授予外部帳戶存取權的 SQS/SNS 政策變更（靜默地將訊息串流至攻擊者端點） |
| 20 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | 偵測公開分享（group=all）的 EBS 快照或 AMI——讓任何人都能複製磁碟映像並擷取資料 |
| 21 | 📧 Data Exfiltration Channels | bar | 偵測來自單一身分的大量 SNS/SQS/SES/S3 PutObject 呼叫（≥50/小時） |

### ⚡ 運算與無伺服器

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | 偵測在一小時內執行 ≥5 次 StopInstances/TerminateInstances 的身分——勒索軟體 / 抹除程式指標 |
| 2 | 🖥️ SSM Session / Run Command | timeseries | 偵測 SSM StartSession、SendCommand 及 StartAutomationExecution——透過受管執行個體的主要橫向移動路徑 |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | 偵測 SendSSHPublicKey 及 SendSerialConsoleSSHPublicKey——繞過 EC2 金鑰對（有效 60 秒，不留下 SSH 金鑰跡證） |
| 4 | 📝 EC2 User Data Modification | timeseries | 偵測帶有 userData 變更的 ModifyInstanceAttribute——腳本會在下次開機時以 root 執行 |
| 5 | ⚡ Lambda Function Tampering | timeseries | 偵測 Lambda 建立、程式碼更新（UpdateFunctionCode）及權限變更（AddPermission） |
| 6 | 📦 Lambda Layer Addition | timeseries | 偵測 Lambda 層發佈及帶有萬用字元主體的 AddLayerVersionPermission（公開供應鏈攻擊） |
| 7 | 📦 ECS Task Definition  | timeseries | 偵測 RegisterTaskDefinition / UpdateService——Pacu ecs__backdoor_task_def 在不觸及 ECR 的情況下注入惡意 sidecar 容器 |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | 偵測 AssociateIamInstanceProfile / ReplaceIamInstanceProfileAssociation——附加具特權的設定檔以啟用橫向移動 |
| 9 | 🖥 EC2 Instance Launches | timeseries | 列出所有 RunInstances 事件，包含執行個體類型、數量、金鑰名稱及 AMI（加密貨幣挖礦偵測） |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | 偵測大型 Spot Fleet 請求（ec2）及高容量的 Auto Scaling 群組建立（autoscaling）——加密貨幣挖礦的財務影響指標 |
| 11 | ☸️ EKS Cluster API Calls | timeseries | 偵測 EKS 叢集控制平面修改（公開 API 伺服器曝露、惡意 Fargate 設定檔） |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | 偵測 ECR 儲存庫/映像事件（標記為 'latest' 的 PutImage 會污染所有後續部署） |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | 偵測 EventBridge 規則及 Scheduler 修改（PutRule、CreateSchedule）——在無執行中行程的情況下建立持續駐留 |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | 偵測 Lightsail 金鑰擷取、連接埠曝露及執行個體存取——Pacu lightsail__download_ssh_keys / lightsail__generate_temp_access |

### 🌐 網路與基礎設施

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 🌍 Security Group Opened to Internet | timeseries | 找出允許來自 0.0.0.0/0 流量的安全群組規則——直接的公開曝險 |
| 2 | 🔥 Security Group Modifications | timeseries | 偵測所有安全群組規則變更（AuthorizeSecurityGroupIngress、ModifySecurityGroupRules 等） |
| 3 | 🌊 VPC Flow Log Changes | timeseries | 偵測 VPC 流量日誌的刪除——移除流量日誌會消除主要的網路鑑識證據 |
| 4 | 🌐 CloudFront Distribution Tampering | timeseries | 偵測將所有 CDN 流量重新導向至攻擊者控制伺服器的 CloudFront 來源變更（MitM） |
| 5 | 🛡 Network Firewall / Shield Tampering | timeseries | 偵測 Network Firewall 及 Shield 保護移除——將整個子網路範圍暴露於攻擊流量 |
| 6 | 🧱 Network ACL Changes | timeseries | 偵測 NACL 項目建立、刪除及取代——NACL 會在子網路層級覆寫安全群組 |
| 7 | 🛣️ Route Table Changes | timeseries | 偵測路由表修改——攻擊者將流量重新導向至惡意閘道以進行攔截或 C2 |
| 8 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | 偵測新的 VPN 連線及 Transit Gateway 附加——為 C2 或外洩建立持續性的第 3 層網路路徑 |
| 9 | 📡 Elastic IP Allocation / Association | timeseries | 偵測 Elastic IP 配置/關聯——為遭入侵的執行個體指派固定公開 IP，以建立穩定的 C2 基礎設施 |
| 10 | 🗝️ EC2 Key Pair Creation | timeseries | 偵測 CreateKeyPair 及 ImportKeyPair——攻擊者建立 SSH 金鑰以持續存取執行個體 |
| 11 | 📡 Network Infrastructure Changes | timeseries | 偵測可能建立攻擊者控制基礎設施的 VPC / 子網路 / IGW / NAT Gateway / 對等互連變更 |
| 12 | 🏷 ACM Certificate Operations | timeseries | 偵測 ACM 憑證請求及刪除——遭入侵的帳戶可為釣魚網域發行 TLS 憑證 |
| 13 | 🔑 API Gateway Key Creation & Management | timeseries | 偵測 API Gateway 金鑰建立及授權方變更——Pacu api_gateway__create_api_keys 產生可在 IAM 金鑰輪換後仍存續的持續性憑證 |
| 14 | 🚧 VPC Endpoint Access Denied | timeseries | 偵測透過 VPC 端點的存取遭拒錯誤——可能表示端點政策設定錯誤 |

### 🕵 威脅樣態

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | 辨識在一小時內執行 10 個以上不同 Describe*/List*/Get* API 的呼叫方——常見的早期攻擊階段 |
| 2 | 🤖 Unusual User Agents | bar | 列出罕見的使用者代理（<5 次事件）或已知的攻擊者工具（Pacu、curl、wget）——可能表示攻擊工具 |
| 3 | 🌍 Multi-Region Activity | bar | 偵測在一天內於 3 個以上區域執行寫入的身分——地理擴散可能表示遭入侵 |
| 4 | 🕵 First-Time API Calls (24h) | — | 找出在過去 24 小時內出現但先前從未見過的 API 呼叫——新穎的操作可能表示攻擊者工具 |

### 📊 活動與基準線

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | 辨識透過 AWS 主控台發出的變更性 API 呼叫——在預期僅有 CLI 存取時很有用 |
| 2 | 🔍 Events with Errors (24h) | timeseries | 列出過去 24 小時內的所有錯誤事件——快速概覽哪些項目正在失敗或被探測 |
| 3 | ❌ Error Spike Detection | — | 找出錯誤計數超過每日平均 3 倍的 1 小時時段 |

### 🌍 GeoIP 分析

> 需要 GeoLite2 `.mmdb` 檔案以進行填入（若擷取時未使用 GeoIP，則欄位為 NULL）。

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 🕵 Impossible Travel Detection | — | 偵測同一身分在 2 小時內從相距遙遠的城市呼叫 API——憑證遭入侵的強烈指標 |
| 2 | ⚠ Identity Multi-Country Access | bar | 找出從 2 個以上國家發出 API 呼叫的身分——合法使用者很少同時從多個國家操作 |
| 3 | 🗺 Console Logins by Country | timeseries | 將主控台登入事件對應至其地理來源——來自非預期國家的登入屬高風險 |
| 4 | 🚨 Unusual Country Access | bar | 偵測罕見的國家/身分組合（<10 次事件）——低量的外國存取可能是攻擊者基礎設施 |
| 5 | 🚫 Access Denied by Country | bar | 依來源國家將存取遭拒錯誤分組——集中於某一國家的拒絕可能是攻擊訊號 |
| 6 | 🔍 Write Events by Country | bar | 顯示依來源國家分組的變更性 API 呼叫——來自非預期國家的寫入比讀取更具訊號意義 |
| 7 | 🌍 Top Source Countries | bar | 依 API 呼叫量為來源國家排名，並提供寫入事件及不重複身分的細分 |
| 8 | 🏢 Top ASN / Organizations | bar | 依 API 呼叫量列出自治系統（ISP/雲端供應商）——VPN/託管 ASN 可能表示攻擊者基礎設施 |
| 9 | 📍 Top Source Cities | bar | 依事件量為來源城市排名——城市層級資料可精確定位特定的攻擊者基礎設施或辦公地點 |
| 10 | 🌐 Private / Internal IP Summary | bar | 彙總來自私有/迴路/AWS 內部 IP 的事件——預期內部流量的基準線 |
| 11 | 📋 API Calls by Country (Event Name) | table | 依呼叫量排序的前幾名 (event_name, country) 配對——揭示哪些 API 操作源自非預期的地理區域 |
| 12 | 👤 Identities by Country (user_identity_arn) | table | 依呼叫量排序的前幾名 (user_identity_arn, country) 配對——揭露從非預期國家活動的 IAM 身分，並附首次/最後出現時間 |

### ☁ IaC 與平台

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | 偵測 CI/CD 管線建立及修改（UpdateProject 會將惡意建置步驟注入每次後續建置） |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | 偵測 CloudFormation 堆疊操作——攻擊者可能利用 IaC 快速部署惡意基礎設施 |

</details>

---

## 📊 儀表板圖表——80+ 個圖表

| 分頁 | 圖表 | 顯示內容 |
|-----|:------:|---------------|
| 🔑 身分與存取 | 9 | 主控台登入 · MFA 趨勢 · 登入熱圖 · 敏感 API · root 使用 · IAM 實體活動 · 權限提升 · SSO/privesc |
| 🎯 威脅偵測 | 12 | 事件量 · 讀/寫比 · 防禦規避 · 存取遭拒 · 錯誤趨勢 · SCP/Config/NACL/EventBridge 竄改 |
| 📊 API 活動 | 7 | 熱門 API · 區域分佈 · 來源 IP · 使用者代理 · 機密異常 · 外部 AssumeRole · Route53 變更 |
| 🖥️ 運算 | 5 | SSM 執行 · EC2 公開快照 · EKS/ECR 事件 · ECS 後門 · EBS Direct API 外洩 |
| 🪣 S3 與 RDS | 9 | S3 政策/ACL · 大量下載/刪除 · 版本控制/日誌停用 · 跨帳戶複寫 · RDS 快照分享 · Backup 竄改 |
| 🌍 GeoIP 情資 | 6 | 世界地圖 · 依請求量排名的熱門國家 / 城市 / ASN · event_name × country · identity × country |
| 🕒 時序分析 | 6 | 依身分/IP/API/代理的首次/最後出現 · 重新啟用的休眠帳戶 · 速率激增 |
| 🚨 高風險 API 監控 | 7 | HRM 時間序列 · 熱門呼叫/行為者/IP · 防禦規避/憑證明細 · 依區域 |

<details markdown="1">
<summary>📋 完整清單——全部 80+ 個圖表（點擊展開）</summary>

## 儀表板圖表（Apache Superset——`dashboard/`）

### 🔑 身分與存取

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | Console Login Activity | 依 IAM 身分分組的主控台登入事件（DSH-08） |
| 2 | MFA-less Login Trend | 依 MFA 使用情況拆分的每日主控台登入（DSH-28） |
| 3 | Login Activity Heatmap (Hour × Day) | 以 JST 計的依星期幾及一天中時段的主控台登入計數（DSH-19） |
| 4 | Sensitive API Calls | 已知安全敏感 AWS API 動作的呼叫（DSH-12） |
| 5 | Root Account Usage | AWS Root 帳戶發出的所有 API 呼叫（DSH-13） |
| 6 | IAM Entity Activity | 依 API 呼叫總數排名的前 50 個 IAM 實體，附寫入比及錯誤率 |
| 7 | Privilege Escalation Timeline | 依事件名稱的權限提升 API 呼叫每日計數（DSH-30） |
| 8 | IAM Identity Center (SSO) Events | 來自 sso.amazonaws.com 的 AWS IAM Identity Center 管理事件（DSH-44） |
| 9 | Glue & SageMaker Privilege Escalation | 透過 iam:PassRole 用於 IAM 權限提升的 Glue DevEndpoint 及 SageMaker Notebook 事件（DSH-50） |

### 🎯 威脅偵測

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | CloudTrail Events Over Time | 隨時間變化的每小時讀取與寫入事件量（DSH-01） |
| 2 | Write/Read Ratio Trend | 讀取與寫入 API 呼叫的每小時細分（DSH-20） |
| 3 | Throttling Exception Spikes | 依 AWS 服務的每小時節流/速率限制錯誤（DSH-21） |
| 4 | Defense Evasion Events | 所有符合已知防禦規避技術的 CloudTrail 事件（DSH-22） |
| 5 | Top Access Denied Actions | 傳回 AccessDenied 錯誤的前 20 個 API 動作（DSH-09） |
| 6 | Error Event Trend | 依 error_code 細分的每小時錯誤事件（DSH-04） |
| 7 | Organizations / SCP Changes | 包含 SCP 政策變更的 AWS Organizations 管理事件（DSH-24） |
| 8 | First-Time Service Sources | 依首次出現日期排序的所有不同 AWS 服務來源（DSH-26） |
| 9 | VPC Flow Log Changes | VPC 流量日誌建立及刪除事件（DSH-42） |
| 10 | AWS Config Tampering | AWS Config 記錄器及規則竄改事件（DSH-43） |
| 11 | Network ACL / Route Table Changes | NACL 及路由表修改事件（DSH-46） |
| 12 | EventBridge / CloudWatch Rule Tampering | EventBridge 及 CloudWatch Events 規則竄改（DSH-47） |

### 📊 API 活動

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | Top 20 API Calls | 最常被呼叫的 20 個 AWS API 動作（DSH-02） |
| 2 | Region Activity | CloudTrail 事件在各 AWS 區域的分佈（DSH-14） |
| 3 | Top Source IP Addresses | 依請求數排名的前 100 個外部來源 IP（DSH-05） |
| 4 | User Agent Analysis | 依請求數排名的前 50 個使用者代理，附錯誤及寫入細分（DSH-11） |
| 5 | Secrets Access Anomaly | 在一小時內存取 Secrets Manager 或 SSM Parameter Store ≥10 次的身分 |
| 6 | AssumedRole from External IP | 來自公開（非私有）IP 位址的 AssumeRole 呼叫（DSH-27） |
| 7 | Route53 DNS Changes | Route 53 託管區域及解析器設定變更（DSH-29） |

### 🖥️ 運算

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | SSM Session / Run Command Execution | AWS Systems Manager 遠端執行事件（DSH-39） |
| 2 | EC2 Public Snapshot / AMI Sharing | EBS 快照及 AMI 公開分享事件（DSH-41） |
| 3 | EKS / ECR Container Platform Events | EKS 叢集及 ECR 容器登錄事件（DSH-48） |
| 4 | ECS Task Definition | ECS 任務定義註冊及服務更新事件——Pacu ecs__backdoor_task_def 樣態（DSH-49） |
| 5 | EBS Direct API Snapshot Exfiltration | 用於在不使用 EC2 的情況下串流快照資料的 EBS Direct API 呼叫（ListSnapshotBlocks / GetSnapshotBlock）（DSH-51） |

### 🪣 S3 與 RDS

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | S3 Protection Config Changes | 削弱儲存桶安全態勢的 S3 事件（DSH-25） |
| 2 | S3 Bucket Policy / ACL Changes | S3 儲存桶政策及 ACL 修改事件（DSH-45） |
| 3 | RDS Snapshot Cross-Account Share | RDS 及 Aurora 快照分享事件（DSH-40） |
| 4 | S3 Bulk Download | 每小時執行 ≥100 次 GetObject 呼叫的身分——自動化資料外洩樣態（DSH-52） |
| 5 | S3 Bulk Object Deletion | 每小時執行 ≥50 次 DeleteObject/DeleteObjects 呼叫的身分——勒索軟體資料破壞樣態（DSH-53） |
| 6 | S3 Versioning / Logging Disabled | PutBucketVersioning（Suspended）及 PutBucketLogging（disabled）——資料破壞前的反鑑識前兆（DSH-54） |
| 7 | S3 Cross-Account Replication | PutBucketReplication / DeleteBucketReplication——通往攻擊者控制帳戶的持續性靜默外洩通道（DSH-55） |
| 8 | RDS Deleted without Final Snapshot | 帶有 skipFinalSnapshot=true 的 DeleteDBInstance / DeleteDBCluster——不可復原的資料破壞（DSH-56） |
| 9 | AWS Backup Tampering | Backup Vault / Plan / RecoveryPoint 刪除及 Vault Lock 移除——勒索軟體消除復原選項的第一步（DSH-57） |

### 🌍 GeoIP 情資

> 需要 GeoLite2 `.mmdb` 檔案。若擷取時未使用 GeoIP，則 GeoIP 欄位為 NULL。

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | Global Request Origin Map | 顯示 CloudTrail API 呼叫來源地理分佈的世界地圖 |
| 2 | Top Countries by Request Volume | 依 API 呼叫量排名的前 20 個來源國家，附寫入事件及不重複呼叫方細分 |
| 3 | Top Cities by Request Volume | 依 API 呼叫量排名的前 25 個城市，附寫入事件及不重複呼叫方細分 |
| 4 | Top ASN Organizations by Request Volume | 依 API 呼叫量排名的前 25 個 ASN 組織 |
| 5 | API Calls by Country (Event Name × GeoIP) | 前 50 個 (event_name, country) 配對——揭示哪些 API 操作從各地理區域被呼叫（DSH-79） |
| 6 | Identities by Country (user_identity_arn × GeoIP) | 前 50 個 (user_identity_arn, country) 配對——揭露從非預期國家活動的 IAM 身分，附寫入計數及首次/最後出現時間（DSH-80） |

### 🕒 時序分析

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | First / Last Seen per IAM Identity | IAM 身分及其首次/最後出現時間戳記、事件計數及不重複 API |
| 2 | First / Last Seen per Source IP | 來源 IP 及其首次/最後出現時間、不重複身分及不重複 API |
| 3 | First / Last Seen per API Call | 依首次出現排序的 API 動作——新呼叫可能表示新穎的攻擊工具（DSH-33） |
| 4 | First / Last Seen per User Agent | 依首次出現排序的使用者代理——新工具偵測（DSH-34） |
| 5 | Dormant Accounts Reactivated | 有 72 小時以上不活動間隔後又恢復活動的身分（DSH-37） |
| 6 | Event Velocity Spikes per Identity | 每小時有 50 次以上事件爆發活動的身分（DSH-38） |

### 🚨 高風險 API 監控（HRM）

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | High-Risk API Events Over Time | 攻擊活動中常見 API 的每日呼叫量（HRM-39） |
| 2 | Top High-Risk API Calls | 依呼叫總數排名的高風險監控清單 API 動作（HRM-40） |
| 3 | Top Actors — High-Risk APIs | 依對高風險監控清單 API 的呼叫總數排名的 IAM 主體（HRM-42） |
| 4 | Top Source IPs — High-Risk APIs | 依對高風險監控清單 API 的呼叫總數排名的來源 IP（HRM-43） |
| 5 | Defense Evasion API Events | 用於停用或竄改稽核控制的 API 詳細事件日誌（HRM-44） |
| 6 | Credential Access API Events | 用於擷取機密及憑證的 API 詳細事件日誌（HRM-45） |
| 7 | High-Risk API Calls by Region | 依 AWS 區域分佈的高風險監控清單 API 呼叫（HRM-46） |

</details>

---
