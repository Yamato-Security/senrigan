# 內建查詢與儀表板參考

> 💡 無需 SQL 或深入的 AWS 知識——只要從下拉選單中選擇一項獵捕，即可立即取得結果。

## 🎯 內建獵捕——139 個查詢

類別依 DFIR 分流優先順序排列——先檢查偵測工具竄改，接著是身分濫用，再來是資料影響。

| 類別 | 查詢數 | 涵蓋的主要威脅 |
|----------|:-------:|---------------------|
| 🛡 Detection & Response | 14 | 稽核服務竄改（CloudTrail/GuardDuty/Config/SecurityHub/Macie）· SCP 刪除 · 警報抑制 · 日誌外洩 · 勒索軟體攻擊鏈關聯分析 |
| 🔑 Identity & Access | 36 | Root 使用 · 主控台登入/MFA · 權限提升 · 信任政策後門 · PassRole 濫用 · 跨帳戶 AssumeRole · SSO/SAML/OIDC · 憑證列舉 · IAM 實體刪除 · AssumeRoot 接管 · Cognito user pool/權杖濫用 · 支援案件壓制 · 角色串接 · 工作階段憑證追蹤 · GetCallerIdentity 偵查 · 聯合身分主控台登入 · Identity Center 權限集與委派管理員 · 無 MFA 的 API 呼叫 |
| 🪣 Data & Storage | 31 | S3 大量刪除/下載 · 機密大量讀取 · 備份竄改 · KMS 操作 · 快照分享 · EBS Direct API 外洩 · DynamoDB 匯出 · S3 跨帳戶複寫 · SSE-C 勒索軟體加密 · 生命週期觸發刪除 · RDS Data API 操弄 · 用於造成影響的儲存體再加密 · 勒索訊息投放 · 外洩通報範圍界定 · 跨帳戶物件複製 · 預簽章 URL 產生 |
| ⚡ Compute & Serverless | 17 | EC2 大量停止/終止 · SSM 橫向移動 · Lambda/ECS/EKS/ECR 竄改 · EventBridge 持續駐留 · 加密貨幣挖礦 · Lightsail 濫用 · IMDS/SSRF 削弱 · AMI/快照刪除 · WorkSpaces 劫持 |
| 🤖 AI & LLM Abuse | 10 | Bedrock 呼叫量激增 · 模型存取啟用 · 呼叫日誌竄改 · 跨區域偵察掃描 · 失敗呼叫爆發 · AgentCore 權杖保管庫 · 閘道授權繞過 · 記憶體完整性 · 沙箱網路模式變更 · 可觀測性竄改 |
| 🌐 Network & Infrastructure | 13 | SG 對網際網路開放 · VPC 流量日誌刪除 · CloudFront 劫持 · 隱蔽 VPN/TGW 通道 · Elastic IP C2 · API Gateway 金鑰 · Route 53/網域劫持 · DDoS 防護弱化 |
| 🕵 Threat Patterns | 11 | 偵察爆發 · 異常使用者代理 · 多區域擴散 · 首次 API 呼叫 · 首次出現區域活動 · 非上班時間活動 · 自我權限提升 · 每日流量偏差 · 未使用區域的資源建立 · 大量 API 呼叫 |
| 📊 Activity & Baseline | 3 | 主控台寫入事件 · 錯誤激增 · 近期錯誤 |
| 🌍 GeoIP Analysis | 2 | 依國家排序的主控台登入/拒絕/寫入 · 罕見國家存取 |
| ☁ IaC & Platform | 2 | CI/CD 供應鏈 · CloudFormation 濫用 |

<details markdown="1">
<summary>📋 完整清單——全部 139 個查詢（點擊展開）</summary>

## 內建獵捕

### 🛡 Detection & Response

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | 偵測任何停止或修改 CloudTrail 的嘗試。最關鍵的警示——表示正在掩蓋行蹤。 |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | 偵測 GuardDuty 停用、刪除及威脅情資操弄。在調查期間對 GuardDuty 的任何變更都是關鍵指標。 |
| 3 | ⛔ Security Hub Tampering | timeseries | 偵測 Security Hub 停用、標準停用及發現項目抑制。使 Security Hub 靜音會消除所有安全發現項目的中央彙整點。 |
| 4 | ⚙️ AWS Config Tampering | timeseries | 偵測 AWS Config 記錄器/規則刪除。停止 Config 會消除整個區域的合規證據及變更追蹤。 |
| 5 | 🛡 Organizations Service Control Policy (SCP) Changes | timeseries | 偵測 SCP 建立、修改及刪除。移除 Deny SCP 會立即消除受影響 OU 中每個帳戶的防護機制。 |
| 6 | 🚫 AWS Macie Tampering | timeseries | 偵測 Macie 停用及發現項目篩選器建立。攻擊者在從 S3 外洩敏感資料之前會先抑制 Macie 的發現項目。 |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | 偵測 CloudWatch 警報刪除及停用。使綁定 GuardDuty、CloudTrail 度量篩選器或計費門檻的警報靜音是重要的防禦規避指標。 |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | 偵測 CW Logs 訂閱篩選器建立/刪除及日誌群組刪除。攻擊者會將日誌串流至外部目的地，或就地銷毀證據。 |
| 9 | 🏹 WAF WebACL Changes | timeseries | 偵測 WAF WebACL 建立、更新及刪除。移除或削弱 WebACL 會停用對 SQLi、XSS 及 DDoS 攻擊的保護。 |
| 10 | 🔍 GuardDuty Findings Read | timeseries | 偵測唯讀的 GuardDuty API 呼叫。Pacu 的 guardduty__list_findings 模組會讀取現有的發現項目，以了解防禦方已偵測到什麼，讓攻擊者能調整戰術並避免觸發新警示。 |
| 11 | 🩺 Security Monitoring Posture Recon | timeseries | 偵測對監控堆疊本身的唯讀探測 — 追蹤是否運作中、GuardDuty 是否啟用、Config 是否正在記錄。這是防禦規避的前一步，也是最後一次留下乾淨紀錄的機會。 |
| 12 | 💰 Budget / Cost Anomaly Changes | timeseries | 偵測 AWS Budgets 及 Cost Anomaly 監控器的刪除或修改。攻擊者會移除預算警示以隱藏加密貨幣挖礦或高資源消耗的操作。 |
| 13 | 🚫 Access Denied Errors | bar | 依身分及 API 將 AccessDenied 錯誤分組。排名最高者可能表示憑證遭濫用。 |
| 14 | ⛓ Ransomware Kill-Chain Sequence | bar | 依主體與日期關聯勒索軟體的三個階段 — 移除復原手段、停用保護、破壞或加密資料。單一階段看似營運雜訊，三者同時出現則不然。 |

### 🔑 Identity & Access

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | 偵測 root 帳戶發出的任何 API 呼叫。正式環境中絕不應使用 root。 |
| 2 | 🔓 Console Login without MFA | timeseries | 偵測未使用 MFA 的主控台登入。帳戶遭入侵的高風險指標。 |
| 3 | 🌐 Console Logins | timeseries | 列出所有主控台登入嘗試。暴力破解＝多次失敗後接著成功。 |
| 4 | 🔐 MFA & Password Changes | timeseries | 偵測 MFA 停用及密碼重設。帳戶遭接管的強烈指標。 |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | 偵測用於權限提升的 IAM 政策附加及角色操弄事件。 |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | 偵測 UpdateAssumeRolePolicy 呼叫。將外部帳戶主體新增至信任政策會建立持續性後門。 |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | 偵測權限邊界 put/delete 事件。移除權限邊界會立即擴大主體的有效權限，造成權限提升。 |
| 8 | 👑 User Added to Admin Group | timeseries | 偵測使用者被加入名稱中含 'admin' 的群組。典型的權限提升技巧。 |
| 9 | 👥 IAM Group Membership Changes | timeseries | 偵測所有 AddUserToGroup 及 RemoveUserFromGroup 事件，無論群組名稱為何。任何群組新增都可能透過群組繼承的政策造成權限提升。 |
| 10 | 👤 New IAM Users / Keys | timeseries | 辨識 IAM 使用者及存取金鑰建立事件。意外的建立可能表示持續駐留。 |
| 11 | 🎯 IAM PassRole Abuse | timeseries | 偵測 iam:PassRole 呼叫。將具特權的角色傳遞給 EC2/Lambda/Glue/ECS/SageMaker 是最常見的橫向權限提升路徑。 |
| 12 | 🏢 Cross-Account Access | timeseries | 找出呼叫方帳戶與接收方帳戶不同的事件。橫向移動訊號。 |
| 13 | 🔑 STS Federation Token Issuance | timeseries | 偵測 GetFederationToken 及 GetSessionToken 呼叫。攻擊者利用這些呼叫將長期金鑰轉換為持續性的臨時憑證。 |
| 14 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | 偵測 AssumeRoleWithWebIdentity 呼叫。濫用設定錯誤的 OIDC 信任（例如過於寬鬆的 sub 宣告）讓攻擊者能使用攻擊者控制的權杖劫持角色。 |
| 15 | 🆔 IAM Identity Center (SSO) Events | timeseries | 偵測 AWS IAM Identity Center 管理動作。攻擊者濫用 SSO 建立後門式權限集，或將帳戶指派給攻擊者控制的使用者。 |
| 16 | 🔗 SAML / OIDC Provider Updates | timeseries | 偵測 SAML/OIDC 身分提供者變更。以攻擊者控制的中繼資料更新 SAML 提供者會建立持續性的驗證後門。 |
| 17 | 🧐 IAM Access Analyzer Calls | timeseries | 偵測任何 IAM Access Analyzer 的使用。攻擊者利用原生分析器列舉可從外部存取的資源，無需自行撰寫偵察腳本。 |
| 18 | 🔄 Credential Report & Enumeration | timeseries | 偵測用來盤點「有誰存在」以及「他們能做什麼」的 IAM 列舉行為。這類呼叫短時間內集中出現，尤其伴隨 AccessDenied 時，即是攻擊初期階段。 |
| 19 | 🗝 Access Key Abuse | bar | 偵測在 7 天內從 3 個以上不同來源 IP 使用的存取金鑰。金鑰外洩的強烈指標。 |
| 20 | 📰 AWS Organizations Account Creation | timeseries | 偵測 Organizations 帳戶建立及委派管理員變更。攻擊者建立影子帳戶以在主帳戶之外建立持續性據點。 |
| 21 | 👥 Cognito Unauthenticated Access | timeseries | 偵測啟用未經驗證存取的 Cognito Identity Pools。允許匿名使用者以未經驗證 IAM 角色的權限呼叫 AWS API。 |
| 22 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | 偵測 Glue 開發端點建立及連線列舉。iam:PassRole + glue:CreateDevEndpoint 會以所傳遞角色的完整權限授予可透過 SSH 存取的端點——最容易被忽略的 IAM 權限提升技巧之一。 |
| 23 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | 偵測 SageMaker notebook 執行個體建立及預先簽署 URL 產生。iam:PassRole + sagemaker:CreateNotebookInstance 會提供具有所傳遞角色完整 AWS 權限的 Jupyter 環境。僅 CreatePresignedNotebookInstanceUrl 就能授予對現有 notebook 的存取權。 |
| 24 | 🪓 IAM Entity Deletion | timeseries | 偵測 IAM 使用者、角色、政策及 MFA 裝置的刪除。攻擊者刪除 IAM 實體以消除其活動痕跡，或將防禦方鎖在外面。 |
| 25 | 👑 AssumeRoot Usage | timeseries | 偵測從管理帳戶進入成員帳戶 root 的 sts:AssumeRoot 呼叫。遭入侵的管理帳戶可藉此接管每一個成員帳戶。 |
| 26 | 🎫 Support Case Manipulation | timeseries | 偵測 AWS Support 案件關閉及留言活動。攻擊者會結案濫用/支援案件，以壓制 AWS 關於入侵事件的通知。 |
| 27 | 🪪 Cognito User Pool Manipulation | timeseries | 偵測 Cognito user pool 及 app client 的變更：延長權杖有效期、新增 client，以及建立管理員使用者。攻擊者濫用這些手法來核發長效權杖或植入後門使用者。 |
| 28 | 🔗 Role Chaining (Session → Role) | timeseries | 偵測已擔任角色的工作階段再去擔任另一個角色。單次 AssumeRole 呼叫看來平常；串接才是攻擊者從遭入侵的執行個體角色走向真正想要之權限的路徑。 |
| 29 | 🎫 Session Credential Trace | bar | 彙總每個臨時 STS 工作階段（ASIA… 存取金鑰）做了什麼：呼叫次數、服務、來源 IP 與時間範圍。這是每一次憑證外洩調查最先提出的範圍問題。 |
| 30 | 🌐 AssumeRole Target Account (roleArn) | timeseries | 從請求的 roleArn 讀取目標帳戶以偵測跨帳戶行為，即使只匯入了呼叫端帳戶的日誌也有效。 |
| 31 | 📊 AssumeRole Fan-In by Target Role | bar | 依誰擔任角色以及來自何處為角色排序。平時僅由一個帳戶擔任的角色突然多出第二個呼叫者，在此會凸顯出來，而在原始事件清單中則被淹沒。 |
| 32 | 🔍 GetCallerIdentity Reconnaissance | bar | 依主體與來源 IP 顯示 GetCallerIdentity 呼叫。這是使用竊得憑證後執行的第一個指令，而且只有一次呼叫，以數量門檻為基礎的偵查獵捕永遠達不到。 |
| 33 | 🪪 Federated Console Logins | timeseries | 列出透過外部身分提供者進入的主控台登入，並顯示提供者名稱與來源。當遭入侵的是 IdP 本身時，AWS 只會看到一次有效登入。 |
| 34 | 🎟 Identity Center Permission Set Grants | timeseries | 偵測 IAM Identity Center 的權限集建立、政策附加與帳戶指派 — 通往組織中每個帳戶常設管理員存取權的路徑。 |
| 35 | 🧑 Identity Store User & Group Creation | timeseries | 偵測直接在 Identity Center 身分存放區建立的使用者、群組與成員資格 — 這種持久化完全不會出現在 IAM，只監控 IAM 便會遺漏。 |
| 36 | 👑 Delegated Administrator Registration | timeseries | 偵測組織服務委派管理員的註冊。這是上游 Identity Center 手冊唯一評為 CRITICAL 的事件，會將整個組織的控制權交給另一個帳戶。 |

### 🪣 Data & Storage

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | 偵測高流量的 DeleteObject/DeleteObjects 呼叫（每小時 ≥50 次）。與外洩不同——這是資料破壞/勒索軟體樣態。 |
| 2 | 🔥 AWS Backup Tampering | timeseries | 偵測 Backup Vault/Plan/RecoveryPoint 刪除。摧毀備份是勒索軟體攻擊防止復原的第一步。 |
| 3 | 🔓 KMS Key Operations | timeseries | 標記敏感的 KMS 操作，包括金鑰刪除及大量的 Decrypt 呼叫。 |
| 4 | 🔓 S3 Public Access Block Disabled | — | 偵測 S3 公開存取保護被停用或直接刪除。屬於立即性的資料外洩風險。 |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | 偵測 S3 儲存桶政策及 ACL 修改。這些變更可能使儲存桶可被公開讀取，或授予攻擊者控制帳戶的存取權。 |
| 6 | 🪣 S3 Data Access Anomalies | bar | 偵測可能表示資料外洩的大量 GetObject 呼叫（≥100/小時）。 |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | 偵測大量擷取機密（資料庫密碼、API 金鑰等）。一小時內十次以上的 GetSecretValue 呼叫是強烈的憑證竊取訊號。 |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | 偵測 Secrets Manager 機密刪除及跨帳戶資源政策變更。補足現有的大量讀取偵測，涵蓋銷毀及透過政策外洩的途徑。 |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | 偵測 SSM Parameter Store 項目的大量讀取。相較於 Secrets Manager，這是一個常被忽略的外洩通道。 |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | 偵測分享給外部 AWS 帳戶的 RDS/Aurora 快照。透過快照分享進行的典型資料外洩。 |
| 11 | 💣 RDS Deleted without Final Snapshot | — | 偵測 skipFinalSnapshot=true 的 RDS 執行個體/叢集刪除。潛在的資料破壞。 |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | 偵測以 PubliclyAccessible=true 建立或修改的 RDS 執行個體。將資料庫直接暴露於網際網路，繞過 VPC 安全控制。 |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | 偵測 DynamoDB ExportTableToPointInTime（靜默將整個資料表匯出至 S3）及資料表刪除。高風險的外洩及破壞途徑。 |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | 偵測 EBS Direct API 呼叫（ListSnapshotBlocks / GetSnapshotBlock）。Pacu 的 ebs__download_snapshots 使用此 API 在不建立 EC2 執行個體的情況下串流原始快照資料，繞過傳統的快照分享偵測。 |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | 偵測指向外部 S3 的 Kinesis Firehose 傳遞串流建立/更新。即時資料管線外洩，對網路 DLP 不可見。 |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | 偵測 PutBucketReplication 及 DeleteBucketReplication。跨帳戶複寫會靜默地將所有新物件複製到攻擊者控制的儲存桶。 |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | 偵測 S3 版本控制暫停及伺服器存取日誌停用。停用版本控制會使永久刪除成為可能；停用日誌會清除存取的證據軌跡。 |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | 偵測 SES 接收規則及身分設定變更。轉寄規則可自動將所有收到的郵件轉送至攻擊者的地址；經驗證的身分可用於進行釣魚活動。 |
| 19 | 📨 SES / SNS Sending Quota Abuse | timeseries | 偵測讓垃圾訊息得以獲利的前置作業 — 調高 SMS 支出上限、重新啟用 SES 寄送、使用大量寄送 API。這些都是單次低頻呼叫，每小時門檻永遠無法觸及。 |
| 20 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | 偵測授予外部帳戶存取權的 SQS/SNS 佇列/主題政策變更。在不觸發大量傳送警示的情況下建立靜默的外洩通道。 |
| 21 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | 偵測公開分享（group=all）的 EBS 快照或 AMI。讓任何人都能複製你的磁碟映像並擷取資料。 |
| 22 | 📧 Data Exfiltration Channels | bar | 偵測可能表示外洩的高流量 SNS/SQS/SES/S3 PutObject 呼叫（≥50/小時）。 |
| 23 | 🔐 S3 SSE-C Encryption (Ransomware) | timeseries | 偵測以攻擊者提供的 SSE-C 金鑰重新加密的 S3 物件，以及儲存桶預設加密設定的變更。沒有客戶金鑰，受害者便無法解密——這是一種雲端原生的勒索軟體樣態。 |
| 24 | ⏳ S3 Lifecycle-Triggered Deletion | timeseries | 偵測使物件過期的 S3 生命週期規則，以及生命週期設定的刪除。攻擊者設定短期到期時間，在不發出 DeleteObject 呼叫的情況下隨時間靜默清除資料。 |
| 25 | 🗃 RDS Query & Instance Manipulation | timeseries | 偵測 RDS Data API 查詢、主密碼重設及快照還原。攻擊者直接讀取資料、重設憑證以取得存取權，或將快照還原至其控制的執行個體。 |
| 26 | 🔎 S3 Bucket Enumeration | bar | 偵測掃描儲存桶及物件中繼資料的呼叫方（一小時內 ≥10 次 List/GetBucket* 讀取）。這是外洩前定位有價值資料的常見早期步驟。 |
| 27 | 🔑 Storage Re-Encryption for Impact | timeseries | 偵測以明確指定的 KMS 金鑰重新加密的 EBS/RDS 快照及磁碟區，以及預設 EBS 加密的停用。以攻擊者持有的金鑰重新加密，即是以資料進行勒索。 |
| 28 | 📝 Ransom Note Placement | timeseries | 偵測物件金鑰看似勒索訊息的 PutObject 呼叫。與其他勒索軟體獵捕不同，這項確認而非暗示損害 — 出現勒索訊息代表對方已在索取贖金。 |
| 29 | 📐 Data Access Scope (Breach Notification) | bar | 量化每個主體每日讀取的內容：接觸的儲存貯體數與概略的不重複物件數。可產出 GDPR 第 33 條通報所需的「大略記錄筆數」。 |
| 30 | 📤 Cross-Account Object Copy | timeseries | 偵測在儲存貯體之間複製的物件，包含帶有 x-amz-copy-source 標頭的 PutObject 呼叫。將資料暫存到你無法控制的帳戶只會留下這一種痕跡。 |
| 31 | 🔗 Presigned URL Generation | bar | 統計每個主體產生預簽章 URL 的次數。預簽章 URL 會把資料交給任何持有連結的人，不需再次驗證，也不再留下 CloudTrail 記錄。 |

### ⚡ Compute & Serverless

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | 偵測高流量的 EC2 StopInstances/TerminateInstances（一小時內 ≥5 次）。表示勒索軟體式破壞或摧毀性攻擊。 |
| 2 | 🖥️ SSM Session / Run Command | timeseries | 偵測 SSM StartSession、SendCommand 及自動化執行。透過受管執行個體的主要橫向移動路徑。 |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | 偵測 EC2 Instance Connect 及 Serial Console 存取，讓攻擊者無需 SSH 金鑰或跳板主機即可從瀏覽器或 CLI 存取執行個體。這是缺乏 SSH 金鑰的攻擊者主要的橫向移動路徑。 |
| 4 | 📝 EC2 User Data Modification | timeseries | 偵測改變 userData 欄位的 ModifyInstanceAttribute 呼叫。User data 腳本會在下次開機時以 root 身分執行，提供持續性的程式碼執行後門。 |
| 5 | ⚡ Lambda Function Tampering | timeseries | 偵測 Lambda 建立、程式碼更新及權限變更。攻擊者利用 Lambda 進行持續駐留。 |
| 6 | 📦 Lambda Layer Addition | timeseries | 偵測 Lambda 層發佈及權限變更。發佈惡意的共用層並將其加入 production 函式會將攻擊者的程式碼注入依賴鏈中。 |
| 7 | 📦 ECS Task Definition | timeseries | 偵測 ECS task definition 註冊及服務更新。Pacu 的 ecs__backdoor_task_def 會註冊指向惡意容器映像的新 task definition 版本，接著更新服務以部署它——全程不觸及 ECR。 |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | 偵測 IAM instance profile 的關聯及取代。附加具特權的 profile 會授予執行個體用於橫向移動的較高權限。 |
| 9 | 🖥 EC2 Instance Launches | timeseries | 列出所有 RunInstances 事件。在異常區域的意外啟動可能表示加密貨幣挖礦。 |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | 偵測大型 Spot Fleet 請求、Reserved Instance 購買，以及高容量的 Auto Scaling 群組建立。加密貨幣挖礦的財務影響指標。 |
| 11 | ☸️ EKS Cluster API Calls | timeseries | 偵測 EKS 叢集控制平面修改。公開 API 伺服器曝露或惡意的 Fargate profile 可能導致容器平台遭到接管。 |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | 偵測 ECR 儲存庫建立/刪除、政策變更及映像推送。將惡意映像注入 production 儲存庫是一種供應鏈持續駐留技巧。 |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | 偵測 EventBridge 規則及 EventBridge Scheduler 修改。攻擊者使用排程規則在無需執行中行程的情況下建立持續駐留。 |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | 偵測 Lightsail 執行個體存取、金鑰對操作及連接埠曝露。Pacu 有三個專屬的 Lightsail 模組（enum、download_ssh_keys、generate_temp_access）。Lightsail 資源運作於標準 EC2 安全邊界之外。 |
| 15 | 🛰 IMDS Options Weakening | timeseries | 偵測使 IMDSv2 變為選用、或重新啟用中繼資料端點的 ModifyInstanceMetadataOptions 呼叫。削弱 IMDS 會重新開啟竊取執行個體角色憑證的 SSRF 途徑。 |
| 16 | 💥 AMI & Snapshot Deletion | bar | 偵測大量取消註冊 AMI 及刪除 EBS 快照（一小時內 ≥5 次）。摧毀黃金映像及備份會在破壞性攻擊期間移除復原選項。 |
| 17 | 🖥 WorkSpaces Hijacking | timeseries | 偵測 Amazon WorkSpaces 佈建及 pool 建立。攻擊者以受害者的費用啟動桌面環境，這是 EC2 邊界之外一個監控不足的運算劫持通道。 |

### 🤖 AI & LLM Abuse

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 🤖 Bedrock Model Invocation Spike | timeseries | 偵測在一小時內呼叫 Bedrock 模型 50 次以上的主體。以竊取的憑證進行高流量推論（LLMjacking）每天可能讓受害者損失數萬美元。 |
| 2 | 🔓 Bedrock Model Access Enablement | timeseries | 偵測 foundation model 存取的啟用或已佈建容量的購買。在從未採用 Bedrock 的組織中，這是幾乎零雜訊的 LLMjacking 指標——是攻擊者典型的第一次寫入動作。 |
| 3 | 🙈 Bedrock Invocation Logging Tampering | timeseries | 偵測 Bedrock 模型呼叫日誌的刪除或修改，以及攻擊者在濫用帳戶前檢查日誌是否啟用（一個有文件記載的 LLMjacking IOC）。 |
| 4 | 🧭 Bedrock Reconnaissance Sweep | bar | 識別在 2 個以上區域列舉 Bedrock 模型、或在一小時內有 10 次以上列舉呼叫的呼叫方。持有被竊憑證者會掃描各區域以找出模型可用之處。 |
| 5 | ⛔ Failed Bedrock Invocations | bar | 找出失敗的 Bedrock 呼叫爆發（AccessDenied / ValidationException）。竊取憑證的測試會在找到可用組合之前，跨多個模型及區域產生失敗風暴。 |
| 6 | 🔑 AgentCore Token Vault Abuse | bar | 依主體與來源彙總 AgentCore 權杖保管庫的發放。這些呼叫會發出第三方 OAuth 權杖與 API 金鑰，因此濫用會延伸到 AWS 之外的服務。 |
| 7 | 🚪 AgentCore Gateway Authorization Bypass | timeseries | 偵測 AgentCore 閘道與政策變更，包含 Cedar 政策引擎被降為 LOG_ONLY。只記錄而不執行的授權仍會回傳成功，因此下游看不出任何異常。 |
| 8 | 🧠 AgentCore Memory Integrity | timeseries | 偵測 AgentCore Memory 與 Registry 變更，包含記憶體串流被改指向其他帳戶的 Kinesis ARN。遭汙染的長期記憶會延續到代理程式日後的每一次工作階段。 |
| 9 | 📦 AgentCore Sandbox Network Mode Drift | timeseries | 列出 AgentCore 程式碼直譯器與瀏覽器的生命週期事件及其網路模式。模式無法編輯，因此刪除後重建是擴大沙箱網路存取的唯一途徑。 |
| 10 | 🙈 AgentCore Observability Tampering | timeseries | 偵測 AgentCore 評估器變更以及 X-Ray 取樣或追蹤目的地變更。攻擊者建立的評估器會讀取其評分的每一則回應，透過正當管道匯出模型輸出。 |

### 🌐 Network & Infrastructure

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 🔥 Security Group Modifications | timeseries | 偵測安全群組規則變更，特別是允許任意連接埠 0.0.0.0/0 的規則。 |
| 2 | 🌊 VPC Flow Log Changes | timeseries | 偵測 VPC 流量日誌的刪除。移除流量日誌會消除網路層級的證據——重要的防禦規避指標。 |
| 3 | 🌐 CloudFront Distribution Tampering | timeseries | 偵測 CloudFront distribution 建立及來源變更。修改來源會將 CDN 流量重新導向至攻擊者控制的伺服器，以進行 MitM 攔截或資料蒐集。 |
| 4 | 🧱 Network ACL Changes | timeseries | 偵測 Network ACL 項目建立、刪除及取代。NACL 會覆寫安全群組，並可能將整個子網路開放給攻擊者。 |
| 5 | 🛣️ Route Table Changes | timeseries | 偵測路由表修改。新增或取代路由可將流量重新導向至攻擊者控制的主機（MitM、流量劫持）。 |
| 6 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | 偵測新的 VPN 連線、Direct Connect 及 Transit Gateway 附加。攻擊者建立隱蔽的網路通道，用於持續性 C2 或資料外洩通道。 |
| 7 | 📡 Elastic IP Allocation / Association | timeseries | 偵測 Elastic IP 的配置及關聯。攻擊者為遭入侵的執行個體指派固定的公開 IP，以建立穩定的 C2 基礎設施。 |
| 8 | 🗝️ EC2 Key Pair Creation | timeseries | 偵測 CreateKeyPair 及 ImportKeyPair 事件。攻擊者建立或匯入 SSH 金鑰，作為維持執行個體存取的持續駐留機制。 |
| 9 | 📡 Network Infrastructure Changes | timeseries | 偵測可能建立攻擊者控制基礎設施的 VPC 及網路層級變更。 |
| 10 | 🏷 ACM Certificate Operations | timeseries | 偵測 ACM 憑證請求及刪除。攻擊者利用遭入侵的帳戶為攻擊者控制的網域核發 TLS 憑證，以建立釣魚基礎設施。 |
| 11 | 🔑 API Gateway Key Creation & Management | timeseries | 偵測 API Gateway 金鑰建立及 REST API 管理。Pacu 的 api_gateway__create_api_keys 會建立可在 IAM 金鑰輪換後仍存續的持續性 API 憑證。攻擊者也會修改 API authorizer 以削弱存取控制。 |
| 12 | 🌐 Route 53 & Domain Changes | timeseries | 偵測 DNS 記錄編輯、託管區域變更及網域註冊/移轉。攻擊者藉此重新導向流量、接管懸置的子網域，或註冊仿冒網域以進行釣魚攻擊。 |
| 13 | 🛡 DDoS Protection Weakening | timeseries | 偵測邊緣防護被放寬而非移除：WebACL 預設動作改為允許、規則群組放鬆、Shield 保護遭刪除、CloudFront 來源被改指向。 |

### 🕵 Threat Patterns

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | 識別在一小時內執行 10 個以上不同唯讀 API 呼叫的呼叫方。常見的早期攻擊階段。 |
| 2 | 🤖 Unusual User Agents | bar | 列出罕見的使用者代理（少於 5 次事件）。像 Pacu 或 curl 這類自訂工具可能表示攻擊者的工具。 |
| 3 | 🌍 Multi-Region Activity | bar | 偵測在一天內於 3 個以上區域執行寫入的身分。地理擴散可能表示遭入侵。 |
| 4 | 🧭 Single-API Multi-Region Fan-Out | bar | 標記單一主體在一小時內於多個區域重複呼叫同一個 API。這是腳本化掃描的特徵，其他區域類獵捕查詢完全看不到。 |
| 5 | 🕵 First-Time API Calls (24h) | — | 找出在過去 24 小時內出現但先前從未見過的 API 呼叫。新穎的操作可能表示攻擊者的工具。 |
| 6 | 🗺 First-Seen Region Activity | bar | 找出資料集中最近 24 小時內首次出現活動的 AWS 區域。在從未使用過的區域中操作，是躲避區域範圍監控以隱藏加密貨幣挖礦或前置作業的典型手法。 |
| 7 | 🌙 Off-Hours Activity | bar | 在可設定的非上班時段區間內，依主體與時段將活動分組。這是上游內部威脅手冊最先列出的指標，也是其他獵捕完全未涵蓋的一項。 |
| 8 | 🪞 Self-Service Privilege Escalation | timeseries | 偵測主體修改自身權限 — 呼叫端 ARN 與目標使用者或角色名稱相同。既有的提權獵捕看得到授予行為，卻遺漏了那是自我套用的事實。 |
| 9 | 📈 Principal Daily Volume Deviation | bar | 將每個主體的每日呼叫量與其自身平均值比較，並區分讀取與寫入。可捕捉僅使用被允許 API 的外洩，此時異常在於數量而非行為。 |
| 10 | 🗺 Resource Creation Outside Normal Regions | bar | 標記在帳戶幾乎不使用之區域建立資源的行為，基準值由資料推導而非寫死。加密貨幣挖礦與私人專案都會出現在這裡。 |
| 11 | 📞 High-Volume API Calls per Principal | bar | 列出成功呼叫超過 50 次的主體與 API 組合，並附上首次與最後一次呼叫。列舉、大量擷取與大量刪除都具有相同形態。 |

### 📊 Activity & Baseline

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | 辨識透過 AWS 主控台發出的變更性 API 呼叫。在預期僅有 CLI 存取時很有用。 |
| 2 | 🔍 Events with Errors (24h) | timeseries | 列出過去 24 小時內的所有錯誤事件。快速概覽目前正在失敗的項目。 |
| 3 | ❌ Error Spike Detection | — | 找出錯誤計數超過每日平均值 3 倍的 1 小時時段。表示掃描或服務中斷的訊號。 |

### 🌍 GeoIP Analysis

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 🚨 Unusual Country Access | bar | 藉由顯示罕見的國家/身分組合，偵測來自非預期國家的 API 呼叫。 |
| 2 | 🚫 Access Denied by Country | bar | 依來源國家將存取遭拒錯誤分組。集中於某一國家的拒絕可能是攻擊訊號。 |

### ☁ IaC & Platform

| # | 標籤 | 圖表 | 說明 |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | 偵測 CI/CD 管線建立及修改。注入惡意的建置步驟或修改管線來源會汙染所有後續的部署。 |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | 偵測 CloudFormation 堆疊操作。攻擊者可能利用 IaC 快速部署惡意基礎設施。 |

</details>

---

## 📊 Dashboard Charts——118 個圖表

| 分頁 | 圖表數 | 顯示內容 |
|-----|:------:|---------------|
| 🚦 Overview | 10 | 9 張分流 KPI 卡片（事件、主體、IP、root、無 MFA 登入、access denied、防禦規避、國家、區域）+ 全域事件量趨勢 |
| 🎯 Threat Detection | 16 | 防禦規避總覽 · 日誌缺口 · VPC flow log/Config/EventBridge/WAF 竄改 · SCP/組織成員變更 · 錯誤及節流趨勢 · write/read 比率 · P1/P2 升級觸發條件 KPI 卡 |
| 🔑 Identity & Access | 36 | 主控台登入 · MFA 趨勢 · 登入熱圖 · 失敗→成功驗證序列 · root 使用 · IAM 實體活動/刪除 · 權限提升時間軸 · 新主體 · SSO · 跨帳戶 AssumeRole · AssumeRoot 使用 |
| 🚨 High-Risk API Monitor | 5 | 安全服務竄改及憑證擷取的 API 日誌 · 熱門高風險呼叫 · 熱門行為者 · 高風險呼叫量隨時間變化 |
| 📊 API Activity | 6 | 熱門 API · access-denied 動作 · 區域分布 · 錯誤代碼組成 · 來源 IP · 使用者代理 |
| 🪣 S3 & RDS | 19 | S3 大量下載/刪除 · 版本控制/日誌停用 · 跨帳戶複寫 · 儲存桶政策/ACL · 列舉 · 保護設定 · Backup vault 刪除 · KMS 金鑰刪除 · RDS 快照分享／未快照即刪除 · SSE-C 勒索軟體加密 · 生命週期觸發刪除 · RDS 查詢/執行個體操弄 · 用於造成影響的儲存體再加密 · 外洩通報用存取範圍 · 跨帳戶物件複製 · 勒索訊息投放 |
| 🖥️ Computing | 17 | EC2 啟動/大量停止/金鑰對/instance profile/user-data/快照分享/spot fleet · ECS/Lambda/SSM/EBS Direct API/EKS-ECR/CloudFormation · IMDS 削弱 · AMI/快照刪除 · WorkSpaces 劫持 |
| 🤖 AI / LLM | 6 | Bedrock 呼叫趨勢 · 模型存取及日誌變更 · 失敗的呼叫 · 依來源分類的呼叫方（LLMjacking 分流） · AgentCore 權杖發放 · 閘道與政策變更 |
| 🌐 Network | 5 | Security group 變更 · NACL/route table 變更 · VPC 基礎設施 · VPC peering/Transit Gateway · Route53 DNS 變更 |
| 🕒 Temporal Analysis | 8 | 事件速率激增 · 重新啟用的休眠帳戶 · 依身分/IP/API/服務來源的首次/最後出現 · 非上班時間寫入熱圖 · 主體每日讀寫量 |
| 🌍 GeoIP Intelligence | 6 | 不可能的移動（多國主體）· 熱門國家/城市/ASN · 世界地圖 · event_name × country |

<details markdown="1">
<summary>📋 完整清單——全部 118 個圖表（點擊展開）</summary>

## Dashboard Charts (Apache Superset — `dashboard/`)

### 🚦 Overview

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | Total Events | 所選範圍內 CloudTrail 事件的總數（KPI-81）。分流的分母——是每個主體或每個 IP 比率的錨點。 |
| 2 | Distinct Principals | 所選範圍內活躍的不重複 IAM 主體 ARN 數量（KPI-82）。用於界定正在審查的活動涉及多少身分。 |
| 3 | Distinct Source IPs | 所選範圍內不重複的呼叫方來源 IP 位址數量（KPI-83）。與基準線相比的躍升暗示 proxy/VPN 輪替或分散式存取。 |
| 4 | Root Account Events | 由帳戶 root 身分執行的事件數量（KPI-84）。Root 活動應接近於零——任何非零值都值得調查。 |
| 5 | MFA-less Console Logins | 所選範圍內未使用 MFA 的主控台登入次數（KPI-85）。憑證遭入侵的直接指標——深入至 MFA-less Login Trend。 |
| 6 | Access Denied Events | 所選範圍內授權失敗事件的數量（KPI-86）。激增暗示偵察或權限測試——依主體/IP 深入分析。 |
| 7 | Defense-Evasion Hits | 所選範圍內稽核/監控竄改事件的數量（KPI-87）。優先順序最高的分流訊號——任何非零值都表示偵測功能可能已被停用。深入至 Security Monitoring & Control Changes。MITRE ATT&CK：TA0005 Defense Evasion。 |
| 8 | Distinct Countries | 所選範圍內不重複來源國家的數量（KPI-88）。需要 GeoIP 資料填充（docker/data/geoip/）。廣泛的分布暗示來自非預期地理來源的存取。 |
| 9 | Active Regions | 所選範圍內有活動的不同 AWS 區域數量（KPI-89）。未使用區域中的活動可能表示資源濫用或攻擊者的前置準備。 |
| 10 | CloudTrail Events Over Time | 隨時間變化的每小時讀取與寫入事件量（DSH-01）。堆疊長條圖顯示讀取/寫入的比例：write_events 的驟然上升表示攻擊者正從偵察轉向主動的攻擊利用。有助於識別活動激增及非上班時間的操作。 |

### 🎯 Threat Detection

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | Security Monitoring & Control Changes | 涵蓋所有防禦規避事件的綜合總覽（DSH-22）。涵蓋 CloudTrail 竄改（StopLogging、DeleteTrail）、GuardDuty 停用、AWS Config 停用、VPC Flow Log 刪除、CloudWatch 日誌刪除，以及安全服務停用（SecurityHub、IAM Access Analyzer）。此處的任何事件都值得立即調查。如需更深入的分析，請使用專屬圖表：VPC Flow Log Changes（DSH-42）、AWS Config Tampering（DSH-43）、EventBridge/CW Tampering（DSH-47）。MITRE ATT&CK：TA0005 Defense Evasion。 |
| 2 | CloudTrail Logging Gap (Hourly Volume) | 每小時的 CloudTrail 事件量（DSH-91）。在活躍期間之間驟然降至零，暗示日誌記錄已被停用（StopLogging/DeleteTrail），或存在傳遞盲點。針對任何非預期的缺口，對照 Security Monitoring & Control Changes 表格進行調查。MITRE ATT&CK：T1562.008 Impair Defenses — Disable Cloud Logs。 |
| 3 | VPC Flow Log Changes | VPC Flow Log 建立及刪除事件（DSH-42）。DeleteFlowLogs 會消除主要的網路鑑識證據來源，使橫向移動及資料外洩的事後分析成為不可能。事件期間的 CreateFlowLogs 可能表示日誌被重新導向至攻擊者控制的 S3 儲存桶。MITRE ATT&CK：TA0005 Defense Evasion。 |
| 4 | AWS Config Recorder & Rule Changes | AWS Config 記錄器及規則竄改事件（DSH-43）：StopConfigurationRecorder、DeleteConfigurationRecorder、DeleteDeliveryChannel、DeleteConfigRule 及 PutConfigRule。停止 Config 記錄器會消除整個區域的合規證據及變更追蹤，使後續的基礎設施變更不會被 Config 規則及 Security Hub 標準偵測到。MITRE ATT&CK：TA0005 Defense Evasion。 |
| 5 | EventBridge & CloudWatch Rule Modifications | EventBridge 及 CloudWatch Events 規則竄改（DSH-47）：DeleteRule、DisableRule（使排程偵測靜音）、CreateSchedule/UpdateSchedule（攻擊者用於 C2 信標的 cron job）、PutSubscriptionFilter（將 CloudTrail/VPC 日誌重新導向至攻擊者帳戶）、DeleteLogGroup（銷毀 VPC Flow Log 紀錄）。供 DFIR 使用的監控層竄改綜合圖表。MITRE ATT&CK：TA0003 Persistence / TA0005 Defense Evasion / TA0011 C2。 |
| 6 | WAF Configuration Changes | AWS WAF v2 / WAF Classic 設定變更事件（DSH-75）。涵蓋 WebACL 建立/更新/刪除、IP set 操作、規則群組變更、日誌設定變更，以及 WAF 與受保護資源的關聯/取消關聯。在攻擊進行中停用 WAF 規則或日誌記錄是強烈的防禦規避指標。MITRE ATT&CK：TA0005 Defense Evasion / TA0003 Persistence。 |
| 7 | Organizations / SCP Changes | 包含 SCP 政策變更的 AWS Organizations 管理層事件（DSH-24）。擁有主帳戶存取權的攻擊者可能停用 SCP 防護機制，以移除整個 AWS organization 中的預防性控制。MITRE ATT&CK：TA0004 Privilege Escalation / TA0005 Defense Evasion。 |
| 8 | Error Event Trend | 依 error_code 細分的每小時錯誤事件（DSH-04）。ThrottlingException 激增表示自動化掃描或攻擊工具；AccessDenied / UnauthorizedAccess 激增表示權限測試；新錯誤代碼的突然出現可能表示新穎的攻擊技巧。 |
| 9 | Throttling Exception Spikes | 依 AWS 服務細分的每小時節流/速率限制錯誤（DSH-21）。ThrottlingException 激增表示某身分（或工具）發出 API 呼叫的速度遠快於預期，這是進行偵察或列舉的自動化攻擊工具的特徵。MITRE ATT&CK：TA0007 Discovery。 |
| 10 | Write/Read Ratio Trend | 讀取與寫入 API 呼叫的每小時細分（DSH-20）。write_events 相對於 read_events 的持續增加，表示攻擊者已從偵察轉向主動的攻擊利用。MITRE ATT&CK：TA0040 Impact / TA0007 Discovery。 |
| 11 | CloudTrail Events Over Time | 隨時間變化的每小時讀取與寫入事件量（DSH-01）。堆疊長條圖顯示讀取/寫入的比例：write_events 的驟然上升表示攻擊者正從偵察轉向主動的攻擊利用。有助於識別活動激增及非上班時間的操作。 |
| 12 | Organization Membership Changes | 將帳戶從防護機制中分離、或將其移至攻擊者控制的 organization 之下的 Organizations 成員變更。Threat Technique Catalog for AWS：T1666.A002 / T1666.A003。 |
| 13 | P1 Escalation Triggers | 符合 TRIAGE_GUIDE 中須於 15 分鐘內回應之升級觸發條件的事件：root 使用、記錄或偵測遭竄改、勒索訊息、委派管理員註冊。非零即代表計時開始。 |
| 14 | P2 Escalation Triggers | 符合 TRIAGE_GUIDE 中須於一小時內回應之條件的事件：憑證建立、權限授予、信任政策修改與跨帳戶角色擔任。應與 P1 卡一起判讀，而非單獨看。 |

### 🔑 Identity & Access

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | Console Login Activity | 依 IAM 身分分組的 AWS Management Console 登入事件（DSH-08）。追蹤成功、失敗及無 MFA 的登入嘗試。高比例的失敗對成功可能表示暴力破解或憑證填充攻擊。mfa_less_count（MFAUsed = 'No'）是帳戶遭入侵的直接指標，但僅適用於傳統的 ConsoleLogin 事件——較新的 OAuth2 登入流程（CreateOAuth2Token / AuthorizeOAuth2Access）不會回報 MFA 狀態。事件已篩選為僅限 event_type = 'AwsConsoleSignIn'。 |
| 2 | MFA-less Login Trend | 依 MFA 使用情況拆分的每日主控台登入（DSH-28）。mfa_less_logins（MFAUsed = 'No'）是帳戶遭入侵或釣魚攻擊的直接指標；無 MFA 登入的持續上升應立即觸發對 IAM 驗證政策的審查。MITRE ATT&CK：TA0001 Initial Access。 |
| 3 | Failed -> Success Auth Sequence | 每個主體 + 來源 IP 的主控台登入失敗及成功次數（DSH-93）。大量的 failure_count 搭配非零的 success_count 表示最終成功的暴力破解／密碼噴灑攻擊——將該次成功視為入侵時間點，並依來源 IP 深入分析。MITRE ATT&CK：T1110 Brute Force。 |
| 4 | Login Activity Heatmap (Hour x Day) | 以 JST 計算，依一天中的時段（X）及星期幾（Y）呈現的主控台登入次數熱圖（DSH-19）。深夜時段（22:00-06:00 JST）欄位或週末列出現亮眼的儲存格，是帳戶遭入侵或憑證濫用的強烈指標。MITRE ATT&CK：TA0001 Initial Access。 |
| 5 | Root Account Usage | 由 AWS Root 帳戶發出的所有 API 呼叫（DSH-13）。在治理良好的環境中，Root 帳戶的使用應該極為罕見。任何 Root 活動——特別是 CreateAccessKey、ConsoleLogin 或 StopLogging——都是遭入侵或違反政策的關鍵指標。 |
| 6 | IAM Entity Activity | 依 API 呼叫總數排名的前 50 個 IAM 實體，附寫入比率及錯誤細分（DSH-03）。write_ratio_pct 或 error_events 相對於 total_events 較高的實體可能表示憑證濫用或權限提升。last_seen 顯示每個實體最新的活動時間戳記。 |
| 7 | IAM Privilege Change Event Timeline | 依事件名稱細分的權限提升 API 呼叫每日次數（DSH-30）。單日內的激增表示有針對性的攻擊活動；緩慢上升則可能表示內部威脅或擁有持續性據點的攻擊者。MITRE ATT&CK：TA0004 Privilege Escalation。 |
| 8 | New IAM Principal Creation Timeline | 每日 IAM 主體及憑證建立事件，依事件類型堆疊（DSH-95）。CreateAccessKey / CreateLoginProfile / CreateUser 的激增是初始存取後的持續駐留指標——請與行為主體及來源 IP 進行關聯分析。MITRE ATT&CK：T1136 Create Account / T1098 Account Manipulation。 |
| 9 | Glue & SageMaker IAM Role Pass Events | 用於 IAM 權限提升的 Glue DevEndpoint 及 SageMaker Notebook 事件（DSH-50）。iam:PassRole + glue:CreateDevEndpoint 會以所傳遞角色的完整權限建立可透過 SSH 存取的 Python/Spark 環境。iam:PassRole + sagemaker:CreateNotebookInstance 提供效果相同的 Jupyter notebook。僅 sagemaker:CreatePresignedNotebookInstanceUrl 就能在不擁有基礎角色的情況下授予對現有 notebook 的存取權。兩者都記載於 AWS-IAM-Privilege-Escalation 儲存庫中，並在 Pacu 的 iam__privesc_scan 模組中實作。MITRE ATT&CK：TA0004 Privilege Escalation。 |
| 10 | AssumedRole from External IP | 來自公開（非私有）IP 位址的 AssumedRole API 呼叫（DSH-27）。EC2 執行個體中繼資料服務（IMDS）的憑證通常只應從 VPC 內部使用。來自外部 IP 的呼叫表示臨時憑證已遭外洩——通常是透過 SSRF、容器逃逸或金鑰匯出。MITRE ATT&CK：TA0008 Lateral Movement / TA0006 Credential Access。 |
| 11 | Cross-Account AssumeRole | recipient_account_id 與呼叫方帳戶不同的 AssumeRole / AssumeRoleWithWebIdentity 呼叫（DSH-94）。非預期的外部帳戶 ID 表示信任關係遭濫用或跨帳戶橫向移動——請驗證每個目的地帳戶都是核准的信任對象。MITRE ATT&CK：T1199 Trusted Relationship / TA0008 Lateral Movement。 |
| 12 | Secrets Access Anomaly | 在一小時內存取 Secrets Manager 或 SSM Parameter Store ≥10 次的身分（DSH-23）。大量憑證讀取是攻擊得逞後的指標：攻擊者蒐集儲存的機密以轉向其他服務或帳戶。MITRE ATT&CK：TA0006 Credential Access / TA0010 Exfiltration。 |
| 13 | Security-Relevant API Calls | 已知安全敏感的 AWS API 動作呼叫（DSH-12）。涵蓋 IAM 憑證變更、政策修改、S3 儲存桶政策變更、安全群組修改、金鑰管理、STS 權杖操作、安全服務停用、Secrets Manager 讀取，以及 Organizations 管理。這些呼叫在正常操作中應該很罕見；意外發生可能表示權限提升、持續駐留或資料外洩。 |
| 14 | IAM Identity Center (SSO) Events | 來自 sso.amazonaws.com、sso-directory.amazonaws.com、sso-oauth.amazonaws.com 及 identitystore.amazonaws.com 的 AWS IAM Identity Center 管理事件（DSH-44）。Identity Center 是多帳戶組織中主要的驗證路徑。主要威脅：CreatePermissionSet（後門管理員存取）、CreateAccountAssignment（將帳戶指派給攻擊者控制的使用者），以及 AttachManagedPolicyToPermissionSet（權限提升）。MITRE ATT&CK：TA0001 Initial Access / TA0003 Persistence / TA0004 Privilege Escalation。 |
| 15 | IAM Entity Deletion | 用於消除攻擊者所建立身分痕跡、或將防禦方鎖在外面的 IAM 使用者、角色、政策及 MFA 裝置刪除。Threat Technique Catalog for AWS：T1070.A001。 |
| 16 | AssumeRoot Usage | 從管理帳戶進入成員帳戶 root 的 sts:AssumeRoot 呼叫——一條完整接管成員帳戶的途徑。Threat Technique Catalog for AWS：AT1669。 |
| 17 | Role Chaining (Session → Role) | 角色串接跳躍 — 已擔任的角色工作階段再擔任另一個角色。深度即為訊號。需要提升後的 session_issuer_arn 欄位。 |
| 18 | Session Credential Trace (ASIA keys) | 以 ASIA 存取金鑰為單位呈現每個臨時 STS 工作階段做了什麼：呼叫次數、不重複 API、來源 IP、區域與時間範圍。先從橫跨多個來源 IP 的工作階段查起。 |
| 19 | API Calls Without MFA | 由未通過 MFA 驗證之工作階段發出的寫入呼叫。與「無 MFA 主控台登入」卡不同，此處涵蓋所有 API 呼叫，而非僅 ConsoleLogin。 |
| 20 | Federated Console Logins by Provider & Origin | 經由外部身分提供者的主控台登入，並顯示提供者名稱、國家與 ASN。當遭入侵的是 IdP 時，AWS 只會看到一次有效登入。 |
| 21 | Identity Center Permission Set Grants | 依事件名稱呈現每日 IAM Identity Center 權限授予。權限集的範圍涵蓋整個組織：一次指派即可在攻擊者從未接觸的帳戶取得管理員權限。 |

### 🚨 High-Risk API Monitor

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | Security Service Modification API Events | 用於停用或竄改稽核控制的 API 詳細事件日誌（HRM-44）。涵蓋：DeleteTrail、StopLogging、UpdateTrail、PutEventSelectors（CloudTrail 竄改）、DeletePolicy 及 DetachPolicy（移除 IAM 防護機制）。任何在核准變更視窗之外發生的事件都值得立即調查。MITRE ATT&CK：TA0005 Defense Evasion。 |
| 2 | Credential Retrieval API Events | 用於擷取機密及憑證的 API 詳細事件日誌（HRM-45）。涵蓋：GetSecretValue（Secrets Manager）、GetParameter / GetParameterHistory（SSM）。單次呼叫可能屬合法行為；但快速連續存取數十個不同機密則是強烈的攻擊者訊號。MITRE ATT&CK：TA0006 Credential Access。 |
| 3 | Top High-Risk API Calls | 依總呼叫次數排名的高風險監控清單中的 API 動作（HRM-40）。偵察類 API（ListUsers、GetCallerIdentity）頻繁出現在許多環境中屬正常現象；請將調查重點放在以異常流量出現、或來自非預期主體的憑證存取與防禦規避類 API。 |
| 4 | Top Actors — High-Risk APIs | 依對高風險監控清單 API 的總呼叫次數排名的 IAM 主體（HRM-42）。與攻擊類別圖表交叉比對，以了解每個主體正在執行什麼動作。頻繁呼叫 AssumeRole 的服務角色屬正常現象；但人類使用者大量呼叫 GetSecretValue 或 DeleteTrail 則並不正常。 |
| 5 | High-Risk API Events Over Time | 攻擊活動中常見 API 的每日呼叫量（HRM-39）。通常罕見的動作（如 DeleteTrail 或 GetSecretValue）突然激增，值得立即調查。請注意，這些 API 中有許多也會在合法的工作流程中被呼叫——請將流量異常作為主要訊號，而非僅憑其出現。MITRE ATT&CK：TA0001 / TA0003 / TA0004 / TA0005 / TA0006 / TA0007 / TA0008。 |

### 📊 API Activity

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | Top 20 API Calls | 最常被呼叫的 20 個 AWS API 動作（DSH-02）。敏感動作（如 AssumeRole、GetSecretValue）的高呼叫次數可能表示自動化工具或偵察行為。 |
| 2 | Top Access Denied Actions | 回傳 AccessDenied 或 Client.UnauthorizedAccess 錯誤的前 20 個 API 動作（DSH-09）。針對敏感 API（如 AssumeRole、GetSecretValue、PutBucketPolicy）反覆出現的 access-denied 事件，是權限提升嘗試或橫向移動的強烈指標。 |
| 3 | Region Activity | CloudTrail 事件在各 AWS 區域的分布（DSH-14）。write_ratio_pct 凸顯出寫入活動比例失衡的區域——非預期區域出現高寫入比率，可能表示 crypto-mining 的 EC2 執行個體、橫向移動，或外洩至監控較少的區域。 |
| 4 | Error-Code Composition Over Time | 依 error_code 堆疊的每日 CloudTrail 錯誤量（DSH-96）。上升的 AccessDenied / UnauthorizedOperation 帶狀區塊表示偵察或權限測試；Throttling 激增則暗示大規模的列舉行為。MITRE ATT&CK：TA0007 Discovery。 |
| 5 | Top Source IP Addresses | 依請求數排名的前 100 個外部來源 IP（DSH-05）。排除 AWS 內部 IP 樣式（*.amazonaws.com）。write_requests 相對於 request_count 較高的 IP 可能表示外洩、橫向移動或自動化攻擊工具。 |
| 6 | User Agent Analysis | 依請求數排名的前 50 個使用者代理，附錯誤及寫入細分（DSH-11）。異常或自訂的使用者代理（如 Python/boto3、自訂腳本、Pacu、ScoutSuite）可能表示自動化攻擊工具。AWS 內部代理（console.amazonaws.com、signin.amazonaws.com）屬正常現象；未知的字串則值得調查。 |

### 🪣 S3 & RDS

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | S3 High-Volume Object Downloads | S3 大量 GetObject 呼叫（DSH-52）：在單一小時內執行 ≥100 次 GetObject 請求的身分，依小時區間、身分及來源 IP 分組。高流量讀取表示自動化資料外洩——攻擊者在破壞或勒索之前先傾印儲存桶內容。搭配 S3 Bulk Deletion 圖表可識別完整的勒索軟體鏈：先外洩再破壞。MITRE ATT&CK：TA0010 Exfiltration。 |
| 2 | S3 Bulk Object Deletion | S3 大量 DeleteObject/DeleteObjects 呼叫（DSH-53）：在單一小時內刪除 ≥50 個物件的身分，依小時區間、身分及來源 IP 分組。高流量刪除是勒索軟體攻擊的資料破壞階段——攻擊者先外洩（見 S3 Bulk Download 圖表），接著清空來源儲存桶以向受害者勒索。也涵蓋意外的大量刪除。MITRE ATT&CK：TA0040 Impact / T1485 Data Destruction。 |
| 3 | S3 Versioning / Logging Disabled | S3 版本控制暫停及日誌停用事件（DSH-54）：Status=Suspended 的 PutBucketVersioning，以及 BucketLoggingStatus 為空的 PutBucketLogging。攻擊者停用版本控制以防止刪除後的物件復原，並停用日誌以清除存取的證據軌跡。兩者都是資料破壞前的反鑑識前兆。MITRE ATT&CK：TA0005 Defense Evasion / T1070 Indicator Removal。 |
| 4 | S3 Cross-Account Replication | S3 跨帳戶複寫設定事件（DSH-55）：PutBucketReplication 及 DeleteBucketReplication。跨帳戶複寫會靜默地將每個新物件複製到攻擊者控制的儲存桶，建立繞過網路 DLP 控制的持續性外洩通道。任何指向外部帳戶 ID 的 PutBucketReplication 都是重大事件指標。MITRE ATT&CK：TA0010 Exfiltration / T1537 Transfer Data to Cloud Account。 |
| 5 | S3 Bucket Policy / ACL Changes | S3 儲存桶政策及 ACL 修改事件（DSH-45）：PutBucketPolicy、DeleteBucketPolicy、PutBucketAcl、PutBucketCors、PutBucketWebsite 及 DeleteBucketWebsite。這些變更可能將儲存桶內容公開，或授予攻擊者控制帳戶的存取權。Principal='*' 的 PutBucketPolicy 是立即的資料曝險指標。MITRE ATT&CK：TA0010 Exfiltration / TA0005 Defense Evasion。 |
| 6 | S3 Bucket & Object List Activity | 依身分及來源 IP 分組的 S3 列舉 API 呼叫（DSH-74）。涵蓋 ListBuckets（全帳戶探索）、ListObjects / ListObjectsV2（逐儲存桶列舉）、ListObjectVersions、ListMultipartUploads、HeadBucket 及 HeadObject。來自新身分或外部 IP 的 list 呼叫突然激增，強烈暗示憑證遭入侵後的偵察行為。MITRE ATT&CK：TA0007 Discovery。 |
| 7 | S3 Protection Config Changes | 削弱儲存桶安全態勢的 S3 事件（DSH-25）。停用伺服器存取日誌會移除稽核軌跡；移除公開存取封鎖會將資料暴露於網際網路；刪除儲存桶加密或複寫會削弱靜態資料的保護。這些都是外洩前或掩蓋行蹤的動作。MITRE ATT&CK：TA0005 Defense Evasion / TA0040 Impact。 |
| 8 | AWS Backup Vault & Plan Deletion Events | AWS Backup Vault、Plan 及 Recovery Point 刪除事件（DSH-57）：DeleteBackupVault、DeleteBackupPlan、DeleteRecoveryPoint、DeleteBackupSelection、DisassociateRecoveryPoint、PutBackupVaultAccessPolicy 及 DeleteBackupVaultLockConfiguration。摧毀備份是勒索軟體活動的第一步——確保受害者在勒索要求提出之前無法從備份復原。刪除 Vault Lock（DeleteBackupVaultLockConfiguration）尤其關鍵，因為它會移除 vault 的 WORM 不可變性。MITRE ATT&CK：TA0040 Impact / T1490 Inhibit System Recovery。 |
| 9 | KMS Key Deletion & Disable Events | KMS 金鑰刪除、停用及輪換管理事件（DSH-66）。ScheduleKeyDeletion——排程金鑰刪除（7-30 天的取消視窗）。DisableKey——立即停止以該金鑰進行加密/解密。DeleteImportedKeyMaterial——立即銷毀匯入金鑰的金鑰材料。DisableKeyRotation——阻止自動的每年金鑰輪換。這些事件中的任何一項都會使以該金鑰加密的所有資料永久無法存取。使用 CancelKeyDeletion 可在刪除日期前復原 ScheduleKeyDeletion。MITRE ATT&CK：TA0040 Impact / T1485 Data Destruction。 |
| 10 | RDS Deleted without Final Snapshot | 帶有 skipFinalSnapshot=true 的 RDS 執行個體及叢集刪除（DSH-56）：未建立最終快照的 DeleteDBInstance 及 DeleteDBCluster 事件。跳過最終快照會使資料庫無法復原——刪除後不存在任何復原點。當 AWS Backup 也已被停用時，勒索軟體行為者會利用此手法將對受害者的壓力最大化。此處的任何事件都屬重大事件。MITRE ATT&CK：TA0040 Impact / T1485 Data Destruction。 |
| 11 | RDS Snapshot Cross-Account Share | RDS 及 Aurora 快照分享事件（DSH-40）：將復原權限授予其他 AWS 帳戶（valuesToAdd）的 ModifyDBSnapshotAttribute 及 ModifyDBClusterSnapshotAttribute。攻擊者將快照分享至自己的帳戶，以在不使用 S3/網路型 DLP 的情況下外洩整個資料庫。復原屬性中任何外部帳戶 ID 都是重大的外洩指標。MITRE ATT&CK：TA0010 Exfiltration。 |
| 12 | S3 SSE-C Ransomware Encryption | 以攻擊者提供的 SSE-C 金鑰重新加密的 S3 物件，加上儲存桶預設加密設定的變更——雲端原生的勒索軟體手法。Threat Technique Catalog for AWS：T1486.A001。 |
| 13 | S3 Lifecycle-Triggered Deletion | 用於在不產生 DeleteObject 爆量的情況下靜默清除資料的、使物件過期的 S3 生命週期規則（及生命週期設定刪除）。Threat Technique Catalog for AWS：T1485.001。 |
| 14 | RDS Query & Instance Manipulation | 用於直接讀取資料、或還原至攻擊者控制執行個體的 RDS Data API 查詢及快照還原。Threat Technique Catalog for AWS：AT1023.001 / T1213.A013。 |
| 15 | Storage Re-Encryption for Impact | 以攻擊者控制的明確 KMS 金鑰重新加密的 EBS/RDS 快照及磁碟區，加上停用預設加密。Threat Technique Catalog for AWS：T1486.A002 / T1486.A003。 |
| 16 | Data Access Scope (Breach Notification) | 依主體呈現 S3 讀取呼叫、不重複儲存貯體與概略不重複物件數。可產出 GDPR 第 33 條要求的數字。需要儲存貯體的 CloudTrail 資料事件。 |
| 17 | Cross-Account Object Copy | S3 CopyObject 呼叫以及帶有 x-amz-copy-source 標頭的 PutObject，並顯示來源與目的地。複寫圖表涵蓋設定；本圖表涵蓋個別複製行為。 |
| 18 | Ransom Note Placement | 物件金鑰看似勒索訊息的 PutObject 呼叫。與其他勒索軟體面板不同，此圖表確認損害 — 只要出現一列即為 P1。 |

### 🖥️ Computing

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | EC2 Instance Launches | 所有 EC2 RunInstances 事件（DSH-58）。攻擊者為了加密貨幣挖礦（GPU/spot）、C2 中繼或橫向移動的前置準備而啟動執行個體——通常在非預期的區域以避免偵測。依 aws_region 篩選以進行區域異常調查；依 user_identity_arn 篩選以追蹤是哪個憑證觸發了啟動。MITRE ATT&CK：TA0002 Execution / TA0040 Impact（Resource Hijacking）。 |
| 2 | RunInstances Spike by Region | 依 AWS 區域堆疊的每日 EC2 RunInstances 量（DSH-97）。突然的激增——尤其在正常運作範圍以外的區域——表示加密貨幣挖礦或資源濫用。請交叉比對行為主體及來源 IP。MITRE ATT&CK：T1496 Resource Hijacking。 |
| 3 | EC2 Mass Stop / Terminate | EC2 StopInstances 及 TerminateInstances 事件（DSH-62）。單一 API 呼叫可同時停止或終止數十個執行個體。大量終止是勒索軟體或蓄意破壞攻擊的破壞性階段——使 production 的 EC2 容量停擺。請檢查 request_parameters 欄位以取得受影響 instanceId 的完整清單。搭配 AWS Backup Tampering 及 S3 Bulk Deletion 圖表以識別完整的勒索軟體鏈。MITRE ATT&CK：TA0040 Impact / T1489 Service Stop。 |
| 4 | EC2 Key Pair Creation | EC2 金鑰對建立及匯入事件（DSH-59）：CreateKeyPair、ImportKeyPair、DeleteKeyPair。攻擊者建立新的金鑰對，以對能在 IAM 憑證輪換後仍存續的 EC2 執行個體建立持續性的 SSH 存取。ImportKeyPair 會直接注入攻擊者控制的公開金鑰，而無需 AWS 產生它。來自不熟悉身分或 IP 的任何 CreateKeyPair 或 ImportKeyPair 都是持續駐留指標。MITRE ATT&CK：TA0003 Persistence。 |
| 5 | EC2 Instance Profile Changes | EC2 instance profile 及 IAM instance profile 管理事件（DSH-60）。IAM：CreateInstanceProfile、DeleteInstanceProfile、AddRoleToInstanceProfile、RemoveRoleFromInstanceProfile。EC2：AssociateIamInstanceProfile、DisassociateIamInstanceProfile、ReplaceIamInstanceProfileAssociation。變更 instance profile 會取代執行個體上所有程式碼可用的 IAM 角色——當攻擊者控制執行個體但想要更高權限角色時，是常見的權限提升路徑。MITRE ATT&CK：TA0004 Privilege Escalation / TA0003 Persistence。 |
| 6 | EC2 User Data Modification | EC2 user data 修改事件（DSH-61）：變更 userData 屬性的 ModifyInstanceAttribute。EC2 user data 會在每次執行個體（重新）啟動時由 cloud-init 執行——注入惡意腳本可提供在重新開機後仍存續的持續性程式碼執行。通常會搭配 stop/start 序列（見 EC2 Mass Stop / Terminate 圖表）以觸發執行。MITRE ATT&CK：TA0003 Persistence / TA0002 Execution。 |
| 7 | EC2 Public Snapshot / AMI Sharing | EC2 EBS 快照及 AMI 公開分享事件（DSH-41）：createVolumePermission 授予群組 'all' 的 ModifySnapshotAttribute，以及 launchPermission 授予群組 'all' 的 ModifyImageAttribute。公開的快照或 AMI 讓任何 AWS 帳戶都能複製磁碟映像，並擷取 volume 上儲存的敏感資料、憑證及私密金鑰。MITRE ATT&CK：TA0010 Exfiltration。 |
| 8 | EC2 Spot Fleet & Reserved Instance Purchases | EC2 Spot Fleet、Fleet 及 Reserved Instance 購買事件（DSH-63）：RequestSpotFleet、ModifySpotFleetRequest、CancelSpotFleetRequests、CreateFleet、DeleteFleet、PurchaseReservedInstancesOffering、RequestSpotInstances、CancelSpotInstanceRequests。攻擊者利用 Spot Fleet 啟動大型 GPU/CPU 叢集進行加密貨幣挖礦，在維持於單一執行個體偵測門檻之下的同時，產生高額的 AWS 帳單。任何非預期的 Spot Fleet 或 Reserved Instance 購買都值得調查。MITRE ATT&CK：TA0040 Impact / T1496 Resource Hijacking。 |
| 9 | ECS Task Definition & Service Changes | ECS task definition 註冊及服務修改事件（DSH-49）。Pacu 的 ecs__backdoor_task_def 會註冊一個新的 task definition 修訂版本，其中注入了竊取憑證的 sidecar 容器，接著發出 UpdateService 以部署它——完全繞過 ECR 映像監控。來自不熟悉呼叫方或 IP 的任何非預期 RegisterTaskDefinition 或 UpdateService 都值得立即調查。MITRE ATT&CK：TA0003 Persistence / TA0002 Execution / TA0006 Credential Access。 |
| 10 | Lambda Function Configuration & Permission Changes | Lambda 函式建立、程式碼更新及權限事件（DSH-64）。UpdateFunctionCode 會以惡意 payload 取代函式程式碼。AddPermission 會授予跨帳戶或公開的 Lambda 呼叫存取權。CreateFunctionUrlConfig 會建立用於直接 C2 的公開 HTTP 端點。CreateEventSourceMapping 會將函式連接至由 S3/DynamoDB/SQS 觸發。PublishLayerVersion 會將惡意的共用層注入多個函式。這些若來自非預期的身分或 IP，都是持續駐留/執行的指標。MITRE ATT&CK：TA0003 Persistence / TA0002 Execution / TA0011 Command and Control。 |
| 11 | SSM Session / Run Command Execution | AWS Systems Manager 遠端執行事件（DSH-39）：StartSession、TerminateSession、ResumeSession、SendCommand 及 StartAutomationExecution。SSM Session Manager 在不開放 SSH/RDP 連接埠的情況下提供 shell 存取，是持有被竊 IAM 憑證的攻擊者主要的橫向移動機制。來自異常 IP 或身分的任何非預期 session 或指令都值得立即調查。MITRE ATT&CK：TA0008 Lateral Movement / TA0002 Execution。 |
| 12 | EBS Direct API Snapshot Block Access | 用於外洩快照資料的 EBS Direct API 呼叫（DSH-51）。Pacu 的 ebs__download_snapshots 使用 ListSnapshotBlocks 及 GetSnapshotBlock，在不建立 EC2 執行個體、不請求快照副本，也不觸發 ModifySnapshotAttribute 事件的情況下，逐 block 串流完整的 EBS 磁碟映像——使其對傳統的快照分享偵測不可見。來自非預期身分或 IP 位址的任何 GetSnapshotBlock 或 ListSnapshotBlocks 呼叫都是重大的外洩指標。MITRE ATT&CK：TA0010 Exfiltration / TA0009 Collection。 |
| 13 | EKS / ECR Container Platform Events | EKS 叢集及 ECR 容器登錄事件（DSH-48）。EKS：UpdateClusterConfig（公開 API）、CreateFargateProfile（惡意工作負載）、AssociateIdentityProviderConfig（惡意 OIDC IdP）。ECR：PutImage（推送含後門的映像）、SetRepositoryPolicy（跨帳戶存取）、PutRegistryPolicy（全組織的登錄曝露）。容器平台事件對於偵測供應鏈攻擊及 Kubernetes 控制平面遭入侵至關重要。MITRE ATT&CK：TA0002 Execution / TA0003 Persistence / TA0010 Exfiltration。 |
| 14 | CloudFormation Stack Changes | CloudFormation 堆疊及 change-set 管理事件（DSH-65）。單一 UpdateStack 可部署 EC2 執行個體、修改 IAM 角色，或重新設定網路——將數十個個別的 API 呼叫合併為單一事件。CreateStackSet 會將攻擊者的基礎設施部署至組織中的所有帳戶。ExecuteChangeSet 會套用預先準備的變更，使初步審查看不到其影響範圍。DeleteStack 可能銷毀鑑識證據資源。MITRE ATT&CK：TA0003 Persistence / TA0002 Execution / TA0005 Defense Evasion。 |
| 15 | IMDS Options Weakening | 使 IMDSv2 變為選用、或重新啟用中繼資料端點，進而重新開啟 SSRF 憑證竊取途徑的 ModifyInstanceMetadataOptions 呼叫。Threat Technique Catalog for AWS：T1552.005。 |
| 16 | AMI & Snapshot Deletion | 在破壞性攻擊期間摧毀復原基準的 AMI 取消註冊及 EBS 快照刪除。Threat Technique Catalog for AWS：T1485.A002。 |
| 17 | WorkSpaces Hijacking | 用於在 EC2 安全邊界之外進行運算劫持的 Amazon WorkSpaces 佈建。Threat Technique Catalog for AWS：T1496.A009。 |

### 🤖 AI / LLM

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | Bedrock Model Invocation Trend | 每個主體每日的 Amazon Bedrock 模型呼叫量（DSH-98）。以竊取的憑證進行高流量推論（LLMjacking），會透過反向代理轉售，並由受害者承擔費用。請調查任何激增、任何先前從未呼叫過 Bedrock 的主體，以及來自非預期來源的任何呼叫。MITRE ATT&CK：TA0040 Impact（T1496 Resource Hijacking）。 |
| 2 | Bedrock Model Access & Logging Changes | Foundation model 存取啟用及呼叫日誌竄改（DSH-99）。持有被竊憑證的攻擊者會在濫用之前自行啟用 Bedrock 模型存取權，並檢查或刪除模型呼叫日誌設定，以避免其提示詞被記錄——兩者皆為有文件記載的 LLMjacking 指標。在從未採用 Bedrock 的組織中，任何一筆紀錄都值得立即調查。MITRE ATT&CK：TA0005 Defense Evasion / TA0040 Impact（T1496）。 |
| 3 | Bedrock Failed Invocations | 依呼叫方及錯誤代碼分組的失敗 Amazon Bedrock 呼叫嘗試（DSH-100）。跨多個模型及區域的 AccessDenied / ValidationException 錯誤爆發，表示攻擊者正在試探被竊金鑰能呼叫哪些模型——這是 LLMjacking 的偵察階段。MITRE ATT&CK：TA0006 Credential Access / TA0007 Discovery。 |
| 4 | Bedrock Callers by Origin | 所有 Amazon Bedrock 呼叫方的盤點，附來源及模型多樣性（DSH-101）。用於 LLMjacking 分流的基準線視圖：從非預期國家、託管/VPN ASN，或呼叫量高的通用腳本使用者代理（python-requests、curl）呼叫的主體，都是主要嫌疑對象。MITRE ATT&CK：TA0040 Impact（T1496 Resource Hijacking）。 |
| 5 | AgentCore Token Issuance (Daily) | 依操作呈現每日 AgentCore 權杖保管庫發放。這些呼叫會發出第三方 OAuth 權杖與 API 金鑰，因此濫用會延伸至 AWS 之外的服務。 |
| 6 | AgentCore Gateway & Policy Changes | AgentCore 閘道、目標與政策變更，並呈現 Cedar 政策引擎模式。從 ENFORCE 改為 LOG_ONLY 後仍回傳成功，因此下游看不出任何異常。 |

### 🌐 Network

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | Security Group Changes | EC2 security group 規則變更（DSH-76）。涵蓋輸入/輸出規則的授權及撤銷、security group 的建立及刪除，以及規則說明的更新。開放至 0.0.0.0/0 且針對管理連接埠（22、3389 等）的輸入規則，是後門存取或設定錯誤的強烈指標。MITRE ATT&CK：TA0003 Persistence / TA0005 Defense Evasion。 |
| 2 | Network ACL / Route Table Changes | Network ACL 及 route table 修改事件（DSH-46）。NACL 變更（CreateNetworkAclEntry、DeleteNetworkAclEntry、ReplaceNetworkAclEntry）可繞過整個子網路的 security group 限制。Route table 變更（CreateRoute、ReplaceRoute、DeleteRoute）可將流量重新導向至攻擊者控制的基礎設施以進行攔截，或建立靜默的 C2 通訊通道。MITRE ATT&CK：TA0005 Defense Evasion / TA0011 Command and Control。 |
| 3 | VPC Infrastructure Changes | VPC 拓撲變更事件（DSH-77）。涵蓋 VPC 建立/刪除/修改、子網路變更、internet gateway 附加、NAT gateway 建立/刪除、VPC endpoint 變更，以及 Elastic IP 配置/關聯。非預期的 IGW 附加或未使用區域中的新 NAT gateway，是攻擊者控制的外洩基礎設施的強烈指標。MITRE ATT&CK：TA0010 Exfiltration / TA0003 Persistence / TA0011 C2。 |
| 4 | VPC Peering & Transit Gateway Changes | VPC peering 連線及 Transit Gateway 變更事件（DSH-78）。涵蓋 VPC peering 建立/接受/刪除，以及 Transit Gateway 建立、VPC 附加及 peering 附加管理。來自非預期帳戶的跨帳戶 peering 請求或新的 Transit Gateway 附加，表示 AWS 帳戶之間的橫向移動。MITRE ATT&CK：TA0008 Lateral Movement / TA0010 Exfiltration。 |
| 5 | Route53 DNS Changes | Route 53 託管區域及解析器設定變更（DSH-29）。DNS 通道技術利用 TXT/CNAME 紀錄及大量子網域，在 DNS 查詢的 payload 中外洩資料。新的託管區域及非預期的 ChangeResourceRecordSets 呼叫應立即調查。MITRE ATT&CK：TA0010 Exfiltration。 |

### 🕒 Temporal Analysis

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | Event Velocity Spikes per Identity | 每小時有 50 次以上事件爆發活動期間的身分（DSH-38）。憑證填充、自動化列舉或資料外洩會在正常基準線之上產生急遽的速率激增。顯示每次激增的小時區間、身分及事件計數。MITRE ATT&CK：TA0006 Credential Access / TA0009 Collection / TA0010 Exfiltration。 |
| 2 | Dormant Accounts Reactivated | 有 72 小時以上不活動間隔後恢復活動的身分（DSH-37）。這是遭入侵的休眠憑證被武器化的典型樣態。顯示每個身分連續事件之間以小時/天計的最大間隔。MITRE ATT&CK：TA0001 Initial Access / TA0003 Persistence。 |
| 3 | First / Last Seen per IAM Identity | IAM 身分及其首次/最後出現時間戳記、事件計數、不重複的 API、不重複的 IP，以及以天計的活躍時長（DSH-31）。依 first_seen 遞減排序以找出新出現的身分。活躍時長短但事件計數高，表示憑證遭入侵或自動化攻擊。MITRE ATT&CK：TA0001 Initial Access / TA0003 Persistence。 |
| 4 | First / Last Seen per Source IP | 來源 IP 及其首次/最後出現時間、不重複身分、不重複 API，以及 GeoIP 背景資訊（DSH-32）。在資料集中較晚出現的新 IP 暗示橫向移動或新的攻擊者基礎設施。MITRE ATT&CK：TA0001 Initial Access / TA0008 Lateral Movement。 |
| 5 | First / Last Seen per API Call | 依首次出現排序的 API 動作（DSH-33）。首次出現的新 API 呼叫暗示偵察或權限提升的嘗試。MITRE ATT&CK：TA0007 Discovery / TA0004 Privilege Escalation。 |
| 6 | First / Last Seen per Service Source | 每個不同 AWS 服務來源的首次及最後出現時間戳記（DSH-26）。依 first_seen 遞減排序以浮現新引進的服務（潛在的攻擊者基礎設施）。依 last_seen 遞增排序以找出已沉寂的服務（可能是入侵後的清理行為）。MITRE ATT&CK：TA0003 Persistence / TA0007 Discovery。 |
| 7 | Off-Hours Write Activity (Hour x Day) | 以 JST 時段 × 星期呈現寫入事件數的熱圖。登入熱圖僅涵蓋 ConsoleLogin；本圖表涵蓋所有變更類呼叫，也正是大量非上班時間存取顯現之處。 |
| 8 | Principal Daily Volume (Read vs Write) | 依主體呈現每日呼叫量，並區分讀取與寫入。請將每個主體與其自身比較：建置角色每日一萬次屬正常，人類兩百次則否。 |

### 🌍 GeoIP Intelligence

| # | 圖表名稱 | 說明 |
|---|------------|-------------|
| 1 | Impossible Travel (Multi-Country Principals) | 依不同來源國家數量排名的 IAM 主體，附不重複來源 IP、事件總數，以及首次/最後出現時間（DSH-92）。對於人類主體而言，distinct_countries >= 2 是帳戶遭入侵的強烈訊號——請交叉比對時間範圍及來源 IP。需要 GeoIP 資料填充。MITRE ATT&CK：TA0001 Initial Access / T1078 Valid Accounts。 |
| 2 | Top Countries by Request Volume | 依 API 呼叫量排名的前 20 個來源國家，附寫入事件及不重複呼叫方細分（DSH-15）。通常與組織營運無關的國家，可能表示憑證竊取或攻擊者控制的基礎設施。需要 GeoLite2 資料填充——NULL 列會自動排除。 |
| 3 | Top ASN Organizations by Request Volume | 依 API 呼叫量排名的前 25 個 ASN 組織，附寫入事件及不重複呼叫方細分（DSH-18）。來自 VPN 供應商、Tor 出口節點、託管公司，或超出預期範圍的雲端供應商的流量，可能表示攻擊者使用匿名化基礎設施。需要 GeoLite2 資料填充——NULL 列會自動排除。 |
| 4 | Top Cities by Request Volume | 依 API 呼叫量排名的前 25 個城市，附寫入事件及不重複呼叫方細分（DSH-17）。城市層級的細緻度可揭露威脅行為者所使用的特定資料中心位置，這在僅進行國家層級分析時會被掩蓋。需要 GeoLite2 資料填充——NULL 列會自動排除。 |
| 5 | Global Request Origin Map | 顯示 CloudTrail API 呼叫來源地理分布的世界地圖（DSH-16）。國家的顏色深淺與事件計數成正比。通常與組織營運無關的國家，可能表示憑證竊取或攻擊者控制的基礎設施。需要 GeoLite2 資料填充——NULL 列會自動排除。 |
| 6 | API Calls by Country (Event Name × GeoIP) | 依 API 呼叫量排名的前 50 個 (event_name, country) 配對（DSH-79）。揭示哪些 API 操作是從各地理區域被呼叫的。來自非預期國家的寫入操作是憑證遭入侵的強烈指標。需要 GeoLite2 資料填充——私有/內部 IP 及 NULL 列會被排除。 |

</details>

---
