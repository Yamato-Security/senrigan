# 組み込みクエリ & ダッシュボードリファレンス

> 💡 SQL や AWS の深い知識は不要 — ドロップダウンからハントを選択するだけで即座に結果が得られます。

## 🎯 組み込みハント — 100 以上のクエリ

カテゴリは DFIR トリアージの優先度順に並んでいます — まず検知ツールの改ざんを確認し、次に ID 悪用、その後にデータへの影響を確認します。

| カテゴリ | クエリ数 | カバーする主な脅威 |
|----------|:-------:|---------------------|
| 🛡 Detection & Response | 12 | 監査サービスの改ざん (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · SCP 削除 · アラーム抑制 · ログの持ち出し |
| 🔑 Identity & Access | 26 | root の使用 · コンソールログイン/MFA · 権限昇格 · 信頼ポリシーのバックドア · PassRole 悪用 · クロスアカウント AssumeRole · SSO/SAML/OIDC · 認証情報の列挙 |
| 🪣 Data & Storage | 21 | S3 一括削除/ダウンロード · シークレットの一括読み取り · バックアップ改ざん · KMS 操作 · スナップショット共有 · EBS Direct API 持ち出し · DynamoDB エクスポート · S3 クロスアカウントレプリケーション |
| ⚡ Compute & Serverless | 14 | EC2 大量停止/終了 · SSM 横展開 · Lambda/ECS/EKS/ECR 改ざん · EventBridge 永続化 · クリプトマイニング · Lightsail 悪用 |
| 🌐 Network & Infrastructure | 14 | SG のインターネット公開 · VPC フローログ削除 · CloudFront ハイジャック · 秘匿 VPN/TGW トンネル · Elastic IP C2 · API Gateway キー |
| 🕵 Threat Patterns | 5 | 業務時間外の書き込み · 偵察バースト · マルチリージョン拡散 · 異常なユーザーエージェント · 初回 API 呼び出し |
| 📊 Activity & Baseline | 3 | コンソール書き込みイベント · エラー急増 · 直近のエラー |
| 🌍 GeoIP Analysis ✦ | 12 | 移動不可能な旅程 · 複数国の認証情報 · 地理ランク付けされたログイン/拒否/書き込み · 国/都市/ASN の内訳 · event_name × country · identity × country |
| ☁ IaC & Platform | 2 | CI/CD サプライチェーン · CloudFormation 悪用 |

<details markdown="1">
<summary>📋 全リスト — 100 以上の全クエリ (クリックで展開)</summary>

## 組み込みハント

### 🛡 Detection & Response

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | CloudTrail を停止または変更しようとするあらゆる試みを検知 — 最も重大な隠蔽の指標 |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | GuardDuty の無効化、削除、脅威インテリジェンスの操作を検知 |
| 3 | ⛔ Security Hub Tampering | timeseries | Security Hub の無効化、標準の無効化、検出結果の抑制を検知 |
| 4 | ⚙️ AWS Config Tampering | timeseries | AWS Config レコーダー/ルールの削除を検知 (コンプライアンス証跡を消去) |
| 5 | 🛡 Organizations SCP Changes | timeseries | SCP の作成、更新、削除を検知 — Deny SCP の削除は OU 内のすべてのアカウントのガードレールを取り除く |
| 6 | 🚫 AWS Macie Tampering | timeseries | Macie の無効化と検出結果フィルターの作成を検知 (持ち出し前の防御回避) |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | アラーム削除と DisableAlarmActions を検知 — アラームを削除せずにセキュリティアラートを無音化 |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | CW Logs サブスクリプションフィルターの作成/削除を検知 (攻撃者の Kinesis/Lambda へのリアルタイムログ持ち出し) |
| 9 | 🏹 WAF WebACL Changes | timeseries | WAFv2/WAF Classic 全体で WAF WebACL の作成、更新、削除を検知 |
| 10 | 🔍 GuardDuty Findings Read | timeseries | ListFindings / GetFindings を検知 — 攻撃者がアクティブな検出結果を読み取り、SOC が既に検知している内容を把握 |
| 11 | 💰 Budget / Cost Anomaly Changes | timeseries | Budget/AnomalyMonitor の削除を検知 (クリプトマイニングのコストを隠蔽) |
| 12 | 🚫 Access Denied Errors | bar | AccessDenied エラーを ID と API ごとにグループ化 — 上位の違反者は認証情報の悪用を示す |

### 🔑 Identity & Access

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | root アカウントによるあらゆる API 呼び出しを検知 — 本番環境で root を使用すべきではない |
| 2 | 🔓 Console Login without MFA | timeseries | MFA が使用されなかったコンソールログインを検知 — アカウント侵害の高リスク指標 |
| 3 | 🌐 Console Logins | timeseries | 成功と失敗を含むすべてのコンソールログイン試行を一覧表示 (ブルートフォース検知) |
| 4 | 🔐 MFA & Password Changes | timeseries | MFA の無効化とパスワードリセットを検知 — アカウント乗っ取りの強い指標 |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | IAM ポリシーのアタッチとロール操作を検知 (PutUserPolicy、AttachRolePolicy、CreatePolicyVersion など) |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | UpdateAssumeRolePolicy を検知 — 信頼ポリシーに外部プリンシパルを追加すると永続的なバックドアが作られる |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | アクセス許可境界の put/delete イベントを検知 — 境界の削除は実効的な権限を即座に拡大する |
| 8 | 👑 User Added to Admin Group | timeseries | 名前に 'admin' を含むグループにユーザーが追加されたことを検知 — 典型的な権限昇格 |
| 9 | 👥 IAM Group Membership Changes | timeseries | グループ名に関わらずすべての AddUserToGroup / RemoveUserFromGroup / CreateGroup / DeleteGroup イベントを検知 |
| 10 | 👤 New IAM Users / Keys | timeseries | IAM ユーザーとアクセスキーの作成イベントを特定 — 予期しない作成は永続化を示す可能性がある |
| 11 | 🎯 IAM PassRole Abuse | timeseries | ロール ARN が渡される受信サービスイベント (RunInstances、CreateFunction、CreateNotebookInstance など) を検査することで iam:PassRole の使用を検知 |
| 12 | 🔐 AssumeRole Cross-Account | timeseries | 呼び出し元とターゲットが異なる AWS アカウントにある AssumeRole イベントを表示 (横展開) |
| 13 | 🏢 Cross-Account Access | timeseries | 呼び出し元アカウントが受信側アカウントと異なるすべてのイベントを検出 |
| 14 | 🔑 STS Federation Token Issuance | timeseries | GetFederationToken と GetSessionToken を検知 — 長期キーを永続的な一時認証情報に変換する |
| 15 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | OIDC 信頼の悪用 (誤設定された sub クレーム / repo 条件のない GitHub Actions) を検知 |
| 16 | 🆔 IAM Identity Center (SSO) Events | timeseries | AWS IAM Identity Center の管理アクション (CreatePermissionSet、CreateAccountAssignment など) を検知 |
| 17 | 🔗 SAML / OIDC Provider Updates | timeseries | SAML/OIDC ID プロバイダーの変更を検知 — 攻撃者が制御する IdP で SAML メタデータを更新すると永続的な認証バックドアが作られる |
| 18 | 🧐 IAM Access Analyzer Calls | timeseries | IAM Access Analyzer のあらゆる使用を検知 — 攻撃者はネイティブのアナライザーを活用し、カスタムの偵察スクリプトなしで外部からアクセス可能なリソースを列挙する |
| 19 | 🔄 Credential Report & Enumeration | timeseries | IAM の列挙 (GenerateCredentialReport、ListUsers、ListRoles、GetAccountAuthorizationDetails など) を検知 |
| 20 | 🗝 Access Key Abuse | bar | 7 日間に 3 つ以上の異なるソース IP から使用されたアクセスキーを検知 — キー漏洩の強い指標 |
| 21 | 📰 AWS Organizations Account Creation | timeseries | Organizations のアカウント作成と委任管理者の変更を検知 (シャドーアカウントによる永続化) |
| 22 | 👥 Cognito Unauthenticated Access | timeseries | allowUnauthenticatedIdentities=true の Cognito ID プールを検知 |
| 23 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | Glue DevEndpoint の作成 (iam:PassRole + glue:CreateDevEndpoint = 渡されたロールの全権限で動作する SSH アクセス可能なエンドポイント) と認証情報収集のための接続列挙を検知 |
| 24 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | SageMaker ノートブックの作成と署名付き URL の生成を検知 — iam:PassRole + sagemaker:CreateNotebookInstance は渡されたロールの全 AWS 権限を持つ Jupyter 環境を起動する |
| 25 | 🛠 Data Pipeline / CodeStar Privilege Escalation | timeseries | iam:PassRole 昇格に使われる Data Pipeline と CodeStar のリソース作成を検知 (CreateProjectFromTemplate は副作用として管理者 IAM ロールを作成する) |
| 26 | 🧩 Step Functions Privilege Escalation | timeseries | Step Functions ステートマシンの作成を検知 (iam:PassRole + states:CreateStateMachine は渡されたロールで Lambda/ECS タスクを実行する) |

### 🪣 Data & Storage

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | 1 時間あたり 50 回以上の DeleteObject/DeleteObjects 呼び出しを行う ID を検知 — ランサムウェア / ワイパーによるデータ破壊パターン |
| 2 | 🔥 AWS Backup Tampering | timeseries | Backup Vault / Plan / RecoveryPoint の削除と Vault Lock の解除を検知 — 復旧オプションを排除するランサムウェアの最初のステップ |
| 3 | 🔓 KMS Key Operations | timeseries | 機微な KMS 操作 (DisableKey、ScheduleKeyDeletion、CreateGrant、PutKeyPolicy、大量の Decrypt) をフラグ付け |
| 4 | 🔓 S3 Public Access Block Disabled | — | S3 パブリックアクセスブロック設定の無効化を検知 — 即座のデータ露出リスク |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | S3 バケットポリシーと ACL の変更を検知 (Principal='*' を伴う PutBucketPolicy は特に重大) |
| 6 | 🪣 S3 Data Access Anomalies | bar | 一括 GetObject 呼び出し (1 時間あたり 100 回以上) を検知 — 自動化されたデータ持ち出しパターン |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | 1 時間で 10 個以上の異なるシークレットを取得する ID を検知 — 認証情報収集のシグナル |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | シークレットの削除、PutResourcePolicy (クロスアカウント共有)、CancelRotateSecret を検知 |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | 1 時間で 20 個以上のパラメーターを読み取る ID を検知 — 見落とされがちな持ち出し経路 |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | 外部 AWS アカウントに共有された RDS/Aurora スナップショットを検知 (スナップショット経由のデータベース持ち出し) |
| 11 | 💣 RDS Deleted without Final Snapshot | — | skipFinalSnapshot=true での RDS 削除を検知 — データ破壊の可能性 |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | publiclyAccessible=true で作成または変更された RDS インスタンスを検知 |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | ExportTableToPointInTime (GetItem DLP を回避するサーバーサイドのテーブル全体エクスポート)、DeleteTable、PITR 無効化を検知 |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | EBS Direct API (ListSnapshotBlocks / GetSnapshotBlock) を検知 — Pacu の ebs__download_snapshots は EC2 なしで生のスナップショットデータをストリーミングし、ModifySnapshotAttribute の検知を回避する |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | 外部 S3 を指す Firehose 配信ストリームの作成/更新を検知 — ネットワーク DLP には見えないリアルタイムデータパイプライン |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | PutBucketReplication を検知 — 追加の GetObject イベントを生成せずに、すべての新規オブジェクトを攻撃者が制御するバケットに密かにコピーする |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | バージョニングの停止 (完全削除を可能にする) とサーバーアクセスログの無効化 (証跡を消去する) を検知 |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | SES 受信ルールと ID 設定の変更を検知 — 転送ルールはすべての受信メールを攻撃者アドレスに中継し、検証済み ID はフィッシングキャンペーンを可能にする |
| 19 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | 外部アカウントへのアクセスを許可する SQS/SNS ポリシー変更を検知 (攻撃者のエンドポイントへの密かなメッセージストリーミング) |
| 20 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | 公開共有された (group=all) EBS スナップショットまたは AMI を検知 — 誰でもディスクイメージをコピーしてデータを抽出できる |
| 21 | 📧 Data Exfiltration Channels | bar | 単一の ID からの大量の SNS/SQS/SES/S3 PutObject 呼び出し (1 時間あたり 50 回以上) を検知 |

### ⚡ Compute & Serverless

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | 1 時間で 5 回以上の StopInstances/TerminateInstances を行う ID を検知 — ランサムウェア / ワイパーの指標 |
| 2 | 🖥️ SSM Session / Run Command | timeseries | SSM StartSession、SendCommand、StartAutomationExecution を検知 — マネージドインスタンス経由の主要な横展開経路 |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | SendSSHPublicKey と SendSerialConsoleSSHPublicKey を検知 — EC2 キーペアを回避する (60 秒間有効で SSH キーのアーティファクトを残さない) |
| 4 | 📝 EC2 User Data Modification | timeseries | userData の変更を伴う ModifyInstanceAttribute を検知 — スクリプトは次回起動時に root として実行される |
| 5 | ⚡ Lambda Function Tampering | timeseries | Lambda の作成、コードの更新 (UpdateFunctionCode)、権限の変更 (AddPermission) を検知 |
| 6 | 📦 Lambda Layer Addition | timeseries | Lambda レイヤーの公開と、ワイルドカードプリンシパルを伴う AddLayerVersionPermission を検知 (パブリックなサプライチェーン攻撃) |
| 7 | 📦 ECS Task Definition  | timeseries | RegisterTaskDefinition / UpdateService を検知 — Pacu の ecs__backdoor_task_def は ECR に触れずに悪意のあるサイドカーコンテナを注入する |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | AssociateIamInstanceProfile / ReplaceIamInstanceProfileAssociation を検知 — 横展開を可能にする特権プロファイルをアタッチする |
| 9 | 🖥 EC2 Instance Launches | timeseries | インスタンスタイプ、数、キー名、AMI を含むすべての RunInstances イベントを一覧表示 (クリプトマイニング検知) |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | 大規模な Spot Fleet リクエスト (ec2) と高キャパシティの Auto Scaling グループ作成 (autoscaling) を検知 — クリプトマイニングによる財務的影響の指標 |
| 11 | ☸️ EKS Cluster API Calls | timeseries | EKS クラスターのコントロールプレーン変更 (パブリック API サーバーの露出、不正な Fargate プロファイル) を検知 |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | ECR リポジトリ/イメージのイベントを検知 ('latest' タグ付きの PutImage は後続のすべてのデプロイを汚染する) |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | EventBridge ルールと Scheduler の変更 (PutRule、CreateSchedule) を検知 — 実行中のプロセスなしで永続化を確立する |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | Lightsail のキー取得、ポート露出、インスタンスアクセスを検知 — Pacu の lightsail__download_ssh_keys / lightsail__generate_temp_access |

### 🌐 Network & Infrastructure

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 🌍 Security Group Opened to Internet | timeseries | 0.0.0.0/0 からのトラフィックを許可するセキュリティグループルールを検出 — 直接的なパブリック露出リスク |
| 2 | 🔥 Security Group Modifications | timeseries | すべてのセキュリティグループルール変更 (AuthorizeSecurityGroupIngress、ModifySecurityGroupRules など) を検知 |
| 3 | 🌊 VPC Flow Log Changes | timeseries | VPC フローログの削除を検知 — フローログの削除は主要なネットワークフォレンジック証拠を消去する |
| 4 | 🌐 CloudFront Distribution Tampering | timeseries | すべての CDN トラフィックを攻撃者が制御するサーバーにリダイレクトする CloudFront オリジンの変更を検知 (MitM) |
| 5 | 🛡 Network Firewall / Shield Tampering | timeseries | Network Firewall と Shield 保護の削除を検知 — サブネット範囲全体を攻撃トラフィックにさらす |
| 6 | 🧱 Network ACL Changes | timeseries | NACL エントリの作成、削除、置換を検知 — NACL はサブネットレベルでセキュリティグループを上書きする |
| 7 | 🛣️ Route Table Changes | timeseries | ルートテーブルの変更を検知 — 攻撃者は傍受や C2 のためにトラフィックを悪意のあるゲートウェイにリダイレクトする |
| 8 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | 新しい VPN 接続と Transit Gateway アタッチメントを検知 — C2 や持ち出しのための永続的なレイヤー 3 ネットワーク経路を作成する |
| 9 | 📡 Elastic IP Allocation / Association | timeseries | Elastic IP の割り当て/関連付けを検知 — 安定した C2 インフラのために、侵害されたインスタンスに固定パブリック IP を割り当てる |
| 10 | 🗝️ EC2 Key Pair Creation | timeseries | CreateKeyPair と ImportKeyPair を検知 — 攻撃者が永続的なインスタンスアクセスのために SSH キーを作成する |
| 11 | 📡 Network Infrastructure Changes | timeseries | 攻撃者が制御するインフラを確立する可能性のある VPC / サブネット / IGW / NAT Gateway / ピアリングの変更を検知 |
| 12 | 🏷 ACM Certificate Operations | timeseries | ACM 証明書のリクエストと削除を検知 — 侵害されたアカウントはフィッシングドメイン用の TLS 証明書を発行できる |
| 13 | 🔑 API Gateway Key Creation & Management | timeseries | API Gateway キーの作成とオーソライザーの変更を検知 — Pacu の api_gateway__create_api_keys は IAM キーローテーションを生き延びる永続的な認証情報を生成する |
| 14 | 🚧 VPC Endpoint Access Denied | timeseries | VPC エンドポイント経由のアクセス拒否エラーを検知 — エンドポイントポリシーの誤設定を示す可能性がある |

### 🕵 Threat Patterns

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | 1 時間で 10 個以上の異なる Describe*/List*/Get* API を実行した呼び出し元を特定 — 攻撃初期段階によく見られる |
| 2 | 🤖 Unusual User Agents | bar | まれなユーザーエージェント (5 イベント未満) または既知の攻撃ツール (Pacu、curl、wget) を一覧表示 — 攻撃ツールを示す可能性がある |
| 3 | 🌍 Multi-Region Activity | bar | 1 日に 3 つ以上のリージョンで書き込みを行う ID を検知 — 地理的な拡散は侵害を示す可能性がある |
| 4 | 🕵 First-Time API Calls (24h) | — | 過去 24 時間で見られたがそれ以前には一度も見られなかった API 呼び出しを検出 — 新規の操作は攻撃ツールを示す可能性がある |

### 📊 Activity & Baseline

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | AWS コンソール経由で行われた変更系 API 呼び出しを特定 — CLI のみのアクセスが想定される場合に有用 |
| 2 | 🔍 Events with Errors (24h) | timeseries | 過去 24 時間のすべてのエラーイベントを一覧表示 — 何が失敗しているか、または探られているかの概要を素早く把握 |
| 3 | ❌ Error Spike Detection | — | エラー数が日平均を 3 倍超える 1 時間のウィンドウを検出 |

### 🌍 GeoIP Analysis

> 投入には GeoLite2 の `.mmdb` ファイルが必要です (GeoIP なしで取り込むと列は NULL になります)。

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 🕵 Impossible Travel Detection | — | 同一 ID が 2 時間以内に離れた都市から API を呼び出すことを検知 — 認証情報侵害の強い指標 |
| 2 | ⚠ Identity Multi-Country Access | bar | 2 か国以上から API 呼び出しを行う ID を検出 — 正当なユーザーが複数の国から同時に操作することはまれ |
| 3 | 🗺 Console Logins by Country | timeseries | コンソールログインイベントをその地理的発信元にマッピング — 予期しない国からのログインは高リスク |
| 4 | 🚨 Unusual Country Access | bar | まれな国/ID の組み合わせ (10 イベント未満) を検知 — 少量の海外アクセスは攻撃者インフラの可能性がある |
| 5 | 🚫 Access Denied by Country | bar | アクセス拒否エラーをソース国ごとにグループ化 — 1 つの国に集中する拒否は攻撃の兆候の可能性がある |
| 6 | 🔍 Write Events by Country | bar | ソース国ごとにグループ化された変更系 API 呼び出しを表示 — 予期しない国からの書き込みは読み取りよりも強いシグナル |
| 7 | 🌍 Top Source Countries | bar | API 呼び出し量でソース国をランク付けし、書き込みイベントとユニーク ID の内訳を表示 |
| 8 | 🏢 Top ASN / Organizations | bar | API 呼び出し量で自律システム (ISP/クラウドプロバイダー) を一覧表示 — VPN/ホスティング ASN は攻撃者インフラを示す可能性がある |
| 9 | 📍 Top Source Cities | bar | イベント量でソース都市をランク付け — 都市レベルのデータは特定の攻撃者インフラやオフィスの場所を特定する |
| 10 | 🌐 Private / Internal IP Summary | bar | プライベート/ループバック/AWS 内部 IP からのイベントを要約 — 想定される内部トラフィックのベースライン |
| 11 | 📋 API Calls by Country (Event Name) | table | 呼び出し量上位の (event_name, country) ペア — どの API 操作が予期しない地理的地域から発信されているかを明らかにする |
| 12 | 👤 Identities by Country (user_identity_arn) | table | 呼び出し量上位の (user_identity_arn, country) ペア — 予期しない国からアクティブな IAM ID を初回/最終確認とともに浮き彫りにする |

### ☁ IaC & Platform

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | CI/CD パイプラインの作成と変更を検知 (UpdateProject は後続のすべてのビルドに悪意のあるビルドステップを注入する) |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | CloudFormation スタック操作を検知 — 攻撃者は IaC を使って悪意のあるインフラを迅速にデプロイする可能性がある |

</details>

---

## 📊 ダッシュボードチャート — 80 以上のチャート

| タブ | チャート数 | 表示内容 |
|-----|:------:|---------------|
| 🔑 Identity & Access | 9 | コンソールログイン · MFA トレンド · ログインヒートマップ · 機微な API · root の使用 · IAM エンティティのアクティビティ · 権限昇格 · SSO/権限昇格 |
| 🎯 Threat Detection | 12 | イベント量 · 読み取り/書き込み比率 · 防御回避 · アクセス拒否 · エラートレンド · SCP/Config/NACL/EventBridge 改ざん |
| 📊 API Activity | 7 | 上位 API · リージョン分布 · ソース IP · ユーザーエージェント · シークレットの異常 · 外部 AssumeRole · Route53 変更 |
| 🖥️ Computing | 5 | SSM 実行 · EC2 パブリックスナップショット · EKS/ECR イベント · ECS バックドア · EBS Direct API 持ち出し |
| 🪣 S3 & RDS | 9 | S3 ポリシー/ACL · 一括ダウンロード/削除 · バージョニング/ログの無効化 · クロスアカウントレプリケーション · RDS スナップショット共有 · バックアップ改ざん |
| 🌍 GeoIP Intelligence | 6 | 世界地図 · リクエスト量別の上位国 / 都市 / ASN · event_name × country · identity × country |
| 🕒 Temporal Analysis | 6 | ID/IP/API/エージェント別の初回/最終確認 · 再アクティブ化された休眠アカウント · 速度の急増 |
| 🚨 High-Risk API Monitor | 7 | HRM 時系列 · 上位の呼び出し/アクター/IP · 防御回避/認証情報の詳細 · リージョン別 |

<details markdown="1">
<summary>📋 全リスト — 80 以上の全チャート (クリックで展開)</summary>

## ダッシュボードチャート (Apache Superset — `dashboard/`)

### 🔑 Identity & Access

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | Console Login Activity | IAM ID ごとにグループ化されたコンソールサインインイベント (DSH-08) |
| 2 | MFA-less Login Trend | MFA 使用の有無で分割した日次コンソールログイン (DSH-28) |
| 3 | Login Activity Heatmap (Hour × Day) | JST での曜日と時間帯別のコンソールログイン数 (DSH-19) |
| 4 | Sensitive API Calls | 既知のセキュリティ上機微な AWS API アクションの呼び出し (DSH-12) |
| 5 | Root Account Usage | AWS Root アカウントによるすべての API 呼び出し (DSH-13) |
| 6 | IAM Entity Activity | 総 API 呼び出し数でランク付けした上位 50 の IAM エンティティ (書き込み比率とエラー率付き) |
| 7 | Privilege Escalation Timeline | イベント名別の権限昇格 API 呼び出しの日次集計 (DSH-30) |
| 8 | IAM Identity Center (SSO) Events | sso.amazonaws.com からの AWS IAM Identity Center 管理イベント (DSH-44) |
| 9 | Glue & SageMaker Privilege Escalation | iam:PassRole 経由の IAM 権限昇格に使われる Glue DevEndpoint と SageMaker Notebook のイベント (DSH-50) |

### 🎯 Threat Detection

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | CloudTrail Events Over Time | 時系列での時間別の Read 対 Write のイベント量 (DSH-01) |
| 2 | Write/Read Ratio Trend | 読み取り対書き込み API 呼び出しの時間別内訳 (DSH-20) |
| 3 | Throttling Exception Spikes | AWS サービス別の時間別スロットリング/レート制限エラー (DSH-21) |
| 4 | Defense Evasion Events | 既知の防御回避手法に一致するすべての CloudTrail イベント (DSH-22) |
| 5 | Top Access Denied Actions | AccessDenied エラーを返す上位 20 の API アクション (DSH-09) |
| 6 | Error Event Trend | error_code 別に分解した時間別エラーイベント (DSH-04) |
| 7 | Organizations / SCP Changes | SCP ポリシー変更を含む AWS Organizations 管理イベント (DSH-24) |
| 8 | First-Time Service Sources | 初出日順に並べたすべての異なる AWS サービスソース (DSH-26) |
| 9 | VPC Flow Log Changes | VPC フローログの作成と削除イベント (DSH-42) |
| 10 | AWS Config Tampering | AWS Config レコーダーとルールの改ざんイベント (DSH-43) |
| 11 | Network ACL / Route Table Changes | NACL とルートテーブルの変更イベント (DSH-46) |
| 12 | EventBridge / CloudWatch Rule Tampering | EventBridge と CloudWatch Events ルールの改ざん (DSH-47) |

### 📊 API Activity

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | Top 20 API Calls | 最も頻繁に呼び出される 20 の AWS API アクション (DSH-02) |
| 2 | Region Activity | AWS リージョン全体での CloudTrail イベントの分布 (DSH-14) |
| 3 | Top Source IP Addresses | リクエスト数別の上位 100 の外部ソース IP (DSH-05) |
| 4 | User Agent Analysis | リクエスト数別の上位 50 のユーザーエージェント (エラーと書き込みの内訳付き) (DSH-11) |
| 5 | Secrets Access Anomaly | 1 時間に 10 回以上 Secrets Manager または SSM Parameter Store にアクセスする ID |
| 6 | AssumedRole from External IP | パブリック (非プライベート) IP アドレスからの AssumeRole 呼び出し (DSH-27) |
| 7 | Route53 DNS Changes | Route 53 ホストゾーンとリゾルバー設定の変更 (DSH-29) |

### 🖥️ Computing

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | SSM Session / Run Command Execution | AWS Systems Manager のリモート実行イベント (DSH-39) |
| 2 | EC2 Public Snapshot / AMI Sharing | EBS スナップショットと AMI のパブリック共有イベント (DSH-41) |
| 3 | EKS / ECR Container Platform Events | EKS クラスターと ECR コンテナレジストリのイベント (DSH-48) |
| 4 | ECS Task Definition | ECS タスク定義の登録とサービス更新イベント — Pacu の ecs__backdoor_task_def パターン (DSH-49) |
| 5 | EBS Direct API Snapshot Exfiltration | EC2 なしでスナップショットデータをストリーミングするために使われる EBS Direct API 呼び出し (ListSnapshotBlocks / GetSnapshotBlock) (DSH-51) |

### 🪣 S3 & RDS

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | S3 Protection Config Changes | バケットのセキュリティ態勢を弱める S3 イベント (DSH-25) |
| 2 | S3 Bucket Policy / ACL Changes | S3 バケットポリシーと ACL の変更イベント (DSH-45) |
| 3 | RDS Snapshot Cross-Account Share | RDS と Aurora のスナップショット共有イベント (DSH-40) |
| 4 | S3 Bulk Download | 1 時間あたり 100 回以上の GetObject 呼び出しを行う ID — 自動化されたデータ持ち出しパターン (DSH-52) |
| 5 | S3 Bulk Object Deletion | 1 時間あたり 50 回以上の DeleteObject/DeleteObjects 呼び出しを行う ID — ランサムウェアによるデータ破壊パターン (DSH-53) |
| 6 | S3 Versioning / Logging Disabled | PutBucketVersioning (Suspended) と PutBucketLogging (disabled) — データ破壊の前兆となるアンチフォレンジック (DSH-54) |
| 7 | S3 Cross-Account Replication | PutBucketReplication / DeleteBucketReplication — 攻撃者が制御するアカウントへの永続的で密かな持ち出し経路 (DSH-55) |
| 8 | RDS Deleted without Final Snapshot | skipFinalSnapshot=true での DeleteDBInstance / DeleteDBCluster — 復旧不能なデータ破壊 (DSH-56) |
| 9 | AWS Backup Tampering | Backup Vault / Plan / RecoveryPoint の削除と Vault Lock の解除 — 復旧オプションを排除するランサムウェアの最初のステップ (DSH-57) |

### 🌍 GeoIP Intelligence

> GeoLite2 の `.mmdb` ファイルが必要です。GeoIP なしで取り込むと GeoIP 列は NULL になります。

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | Global Request Origin Map | CloudTrail API 呼び出し発信元の地理的分布を示す世界地図 |
| 2 | Top Countries by Request Volume | API 呼び出し量別の上位 20 のソース国 (書き込みイベントとユニーク呼び出し元の内訳付き) |
| 3 | Top Cities by Request Volume | API 呼び出し量別の上位 25 の都市 (書き込みイベントとユニーク呼び出し元の内訳付き) |
| 4 | Top ASN Organizations by Request Volume | API 呼び出し量別の上位 25 の ASN 組織 |
| 5 | API Calls by Country (Event Name × GeoIP) | 上位 50 の (event_name, country) ペア — 各地理的地域からどの API 操作が呼び出されるかを明らかにする (DSH-79) |
| 6 | Identities by Country (user_identity_arn × GeoIP) | 上位 50 の (user_identity_arn, country) ペア — 予期しない国からアクティブな IAM ID を書き込み数と初回/最終確認とともに浮き彫りにする (DSH-80) |

### 🕒 Temporal Analysis

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | First / Last Seen per IAM Identity | 初回/最終確認のタイムスタンプ、イベント数、異なる API 数を持つ IAM ID |
| 2 | First / Last Seen per Source IP | 初回/最終確認、異なる ID、異なる API を持つソース IP |
| 3 | First / Last Seen per API Call | 初出順に並べた API アクション — 新規の呼び出しは新しい攻撃ツールを示す可能性がある (DSH-33) |
| 4 | First / Last Seen per User Agent | 初出順に並べたユーザーエージェント — 新しいツールの検知 (DSH-34) |
| 5 | Dormant Accounts Reactivated | 72 時間以上の非アクティブ期間を経て活動を再開した ID (DSH-37) |
| 6 | Event Velocity Spikes per Identity | 1 時間あたり 50 件以上のイベントのバースト活動を持つ ID (DSH-38) |

### 🚨 High-Risk API Monitor (HRM)

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | High-Risk API Events Over Time | 攻撃キャンペーンでよく見られる API の日次呼び出し量 (HRM-39) |
| 2 | Top High-Risk API Calls | 総呼び出し数でランク付けした高リスクウォッチリストの API アクション (HRM-40) |
| 3 | Top Actors — High-Risk APIs | 高リスクウォッチリスト API への総呼び出し数でランク付けした IAM プリンシパル (HRM-42) |
| 4 | Top Source IPs — High-Risk APIs | 高リスクウォッチリスト API への総呼び出し数でランク付けしたソース IP (HRM-43) |
| 5 | Defense Evasion API Events | 監査制御の無効化や改ざんに使われる API の詳細なイベントログ (HRM-44) |
| 6 | Credential Access API Events | シークレットと認証情報の取得に使われる API の詳細なイベントログ (HRM-45) |
| 7 | High-Risk API Calls by Region | AWS リージョン別に分布した高リスクウォッチリスト API 呼び出し (HRM-46) |

</details>

---
