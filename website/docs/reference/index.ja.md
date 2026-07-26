# 組み込みクエリ & ダッシュボードリファレンス

> 💡 SQL や AWS の深い知識は不要 — ドロップダウンからハントを選択するだけで即座に結果が得られます。

## 🎯 組み込みハント — 126 クエリ

カテゴリは DFIR トリアージの優先度順に並んでいます — まず検知ツールの改ざんを確認し、次に ID 悪用、その後にデータへの影響を確認します。

| カテゴリ | クエリ数 | カバーする主な脅威 |
|----------|:-------:|---------------------|
| 🛡 Detection & Response | 12 | 監査サービスの改ざん (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · SCP 削除 · アラーム抑制 · ログの持ち出し |
| 🔑 Identity & Access | 30 | root の使用 · コンソールログイン/MFA · 権限昇格 · 信頼ポリシーのバックドア · PassRole 悪用 · クロスアカウント AssumeRole · SSO/SAML/OIDC · 認証情報の列挙 · IAM エンティティ削除 · AssumeRoot 乗っ取り · Cognito ユーザープール/トークン悪用 · サポートケース抑制 |
| 🪣 Data & Storage | 26 | S3 一括削除/ダウンロード · シークレットの一括読み取り · バックアップ改ざん · KMS 操作 · スナップショット共有 · EBS Direct API 持ち出し · DynamoDB エクスポート · S3 クロスアカウントレプリケーション · SSE-C ランサムウェア暗号化 · ライフサイクルトリガー削除 · RDS Data API 操作 · 影響のためのストレージ再暗号化 |
| ⚡ Compute & Serverless | 17 | EC2 大量停止/終了 · SSM 横展開 · Lambda/ECS/EKS/ECR 改ざん · EventBridge 永続化 · クリプトマイニング · Lightsail 悪用 · IMDS/SSRF 弱体化 · AMI/スナップショット削除 · WorkSpaces ハイジャック |
| 🤖 AI & LLM Abuse | 6 | Bedrock 呼び出しの急増 · モデルアクセスの有効化 · 呼び出しログの改ざん · リージョン横断偵察 · 失敗呼び出しのバースト · 呼び出し元/発信元の棚卸し (LLMjacking) |
| 🌐 Network & Infrastructure | 15 | SG のインターネット公開 · VPC フローログ削除 · CloudFront ハイジャック · 秘匿 VPN/TGW トンネル · Elastic IP C2 · API Gateway キー · Route 53/ドメインハイジャック |
| 🕵 Threat Patterns | 5 | 偵察バースト · 異常なユーザーエージェント · マルチリージョン拡散 · 初回 API 呼び出し · 初検出リージョンアクティビティ |
| 📊 Activity & Baseline | 3 | コンソール書き込みイベント · エラー急増 · 直近のエラー |
| 🌍 GeoIP Analysis | 10 | 国別のコンソールログイン/拒否/書き込み · まれな国からのアクセス · 国/ASN/都市の内訳 · event_name × country · identity × country · プライベート IP ベースライン |
| ☁ IaC & Platform | 2 | CI/CD サプライチェーン · CloudFormation 悪用 |

<details markdown="1">
<summary>📋 全リスト — 全 126 クエリ (クリックで展開)</summary>

## 組み込みハント

### 🛡 Detection & Response

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | CloudTrail を停止または変更しようとするあらゆる試みを検知します。最も重大なアラート — 隠蔽を示します。 |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | GuardDuty の無効化、削除、脅威インテリジェンスの操作を検知します。調査中の GuardDuty の変更はいずれも重大な指標です。 |
| 3 | ⛔ Security Hub Tampering | timeseries | Security Hub の無効化、標準の無効化、検出結果の抑制を検知します。Security Hub を無音化すると、すべてのセキュリティ検出結果の中央集約ポイントが失われます。 |
| 4 | ⚙️ AWS Config Tampering | timeseries | AWS Config レコーダー/ルールの削除を検知します。Config を停止すると、リージョン全体のコンプライアンス証跡と変更追跡が失われます。 |
| 5 | 🛡 Organizations Service Control Policy (SCP) Changes | timeseries | SCP の作成、変更、削除を検知します。Deny SCP を削除すると、影響を受ける OU 内のすべてのアカウントのガードレールが即座に失われます。 |
| 6 | 🚫 AWS Macie Tampering | timeseries | Macie の無効化と検出結果フィルターの作成を検知します。攻撃者は S3 から機密データを持ち出す前に Macie の検出結果を抑制します。 |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | CloudWatch アラームの削除と無効化を検知します。GuardDuty、CloudTrail メトリクスフィルター、請求しきい値に紐づくアラームを無音化することは、防御回避の重要な指標です。 |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | CW Logs サブスクリプションフィルターの作成/削除とロググループの削除を検知します。攻撃者はログを外部の宛先にストリーミングするか、その場で証拠を破棄します。 |
| 9 | 🏹 WAF WebACL Changes | timeseries | WAF WebACL の作成、更新、削除を検知します。WebACL の削除や弱体化は、SQLi、XSS、DDoS 攻撃に対する防御を無効化します。 |
| 10 | 🔍 GuardDuty Findings Read | timeseries | 読み取り専用の GuardDuty API 呼び出しを検知します。Pacu の guardduty__list_findings モジュールはアクティブな検出結果を読み取り、防御側がすでに何を検知したかを把握することで、攻撃者が戦術を適応させ新たなアラートのトリガーを回避できるようにします。 |
| 11 | 💰 Budget / Cost Anomaly Changes | timeseries | AWS Budgets および Cost Anomaly モニターの削除や変更を検知します。攻撃者はクリプトマイニングやリソース集約的な操作を隠すために予算アラートを削除します。 |
| 12 | 🚫 Access Denied Errors | bar | AccessDenied エラーを ID と API ごとにグループ化します。上位の違反者は認証情報の悪用を示す可能性があります。 |

### 🔑 Identity & Access

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | root アカウントによるあらゆる API 呼び出しを検知します。root は本番環境で使用すべきではありません。 |
| 2 | 🔓 Console Login without MFA | timeseries | MFA が使用されなかったコンソールログインを検知します。アカウント侵害の高リスク指標です。 |
| 3 | 🌐 Console Logins | timeseries | すべてのコンソールログイン試行を一覧表示します。複数回の失敗の後に成功が続く場合はブルートフォースです。 |
| 4 | 🔐 MFA & Password Changes | timeseries | MFA の無効化とパスワードリセットを検知します。アカウント乗っ取りの強い指標です。 |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | 権限昇格に使われる IAM ポリシーのアタッチとロール操作イベントを検知します。 |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | UpdateAssumeRolePolicy 呼び出しを検知します。信頼ポリシーに外部アカウントのプリンシパルを追加すると、永続的なバックドアが作られます。 |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | アクセス許可境界の put/delete イベントを検知します。アクセス許可境界を削除すると、プリンシパルの実効権限が即座に拡大し、権限昇格を可能にします。 |
| 8 | 👑 User Added to Admin Group | timeseries | 名前に 'admin' を含むグループに追加されたユーザーを検知します。典型的な権限昇格の手法です。 |
| 9 | 👥 IAM Group Membership Changes | timeseries | グループ名に関わらず、すべての AddUserToGroup および RemoveUserFromGroup イベントを検知します。グループへの追加はいずれも、グループ継承ポリシーを通じた権限昇格を示す可能性があります。 |
| 10 | 👤 New IAM Users / Keys | timeseries | IAM ユーザーとアクセスキーの作成イベントを特定します。予期しない作成は永続化を示す可能性があります。 |
| 11 | 🎯 IAM PassRole Abuse | timeseries | iam:PassRole 呼び出しを検知します。特権ロールを EC2/Lambda/Glue/ECS/SageMaker に渡すことは、最も一般的な横方向の権限昇格経路です。 |
| 12 | 🔐 AssumeRole Cross-Account | timeseries | 呼び出し元とターゲットが異なる AWS アカウントにある AssumeRole イベントを表示します。横展開を示します。 |
| 13 | 🏢 Cross-Account Access | timeseries | 呼び出し元アカウントが受信側アカウントと異なるイベントを検出します。横展開のシグナルです。 |
| 14 | 🔑 STS Federation Token Issuance | timeseries | GetFederationToken と GetSessionToken 呼び出しを検知します。攻撃者はこれらを使って長期キーを永続的な一時認証情報に変換します。 |
| 15 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | AssumeRoleWithWebIdentity 呼び出しを検知します。誤設定された OIDC 信頼 (例: 過度に広い sub クレーム) を悪用すると、攻撃者が制御するトークンを使ってロールをハイジャックできます。 |
| 16 | 🆔 IAM Identity Center (SSO) Events | timeseries | AWS IAM Identity Center の管理アクションを検知します。攻撃者は SSO を悪用してバックドアの権限セットを作成したり、攻撃者が制御するユーザーにアカウントを割り当てたりします。 |
| 17 | 🔗 SAML / OIDC Provider Updates | timeseries | SAML/OIDC ID プロバイダーの変更を検知します。攻撃者が制御するメタデータで SAML プロバイダーを更新すると、永続的な認証バックドアが作られます。 |
| 18 | 🧐 IAM Access Analyzer Calls | timeseries | IAM Access Analyzer のあらゆる使用を検知します。攻撃者はネイティブの AWS アナライザーを利用して、カスタムの偵察スクリプトを書かずに外部からアクセス可能なリソースを列挙します。 |
| 19 | 🔄 Credential Report & Enumeration | timeseries | IAM の全体像をマッピングする IAM 列挙アクティビティを検知します。攻撃初期段階でよく見られます。 |
| 20 | 🗝 Access Key Abuse | bar | 7 日間に 3 つ以上の異なるソース IP から使用されたアクセスキーを検知します。キー漏洩の強い指標です。 |
| 21 | 📰 AWS Organizations Account Creation | timeseries | Organizations のアカウント作成と委任管理者の変更を検知します。攻撃者はメインアカウントの外に永続的な足場を築くためにシャドーアカウントを作成します。 |
| 22 | 👥 Cognito Unauthenticated Access | timeseries | 未認証アクセスが有効になっている Cognito ID プールを検知します。匿名ユーザーが未認証 IAM ロールの権限で AWS API を呼び出せるようになります。 |
| 23 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | Glue 開発エンドポイントの作成と接続の列挙を検知します。iam:PassRole + glue:CreateDevEndpoint は SSH 経由でロールの全権限を付与します — 最も見落とされがちな IAM 権限昇格手法の一つです。 |
| 24 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | SageMaker ノートブックインスタンスの作成と署名付き URL の生成を検知します。iam:PassRole + sagemaker:CreateNotebookInstance は、渡されたロールの全 AWS 権限を持つ Jupyter 環境を提供します。CreatePresignedNotebookInstanceUrl 単体でも既存のノートブックへのアクセスを許可できます。 |
| 25 | 🛠 Data Pipeline / CodeStar Privilege Escalation | timeseries | Data Pipeline と CodeStar のリソース作成を検知します。どちらも iam:PassRole を受け付け、渡されたロールの権限で任意のコードを実行できます。CodeStar:CreateProjectFromTemplate は管理者 IAM ロールを作成する非公開の API です。 |
| 26 | 🧩 Step Functions Privilege Escalation | timeseries | Step Functions ステートマシンの作成と実行を検知します。iam:PassRole + states:CreateStateMachine + states:StartExecution により、渡されたロールの権限で任意の Lambda / ECS タスクを実行できます。 |
| 27 | 🪓 IAM Entity Deletion | timeseries | IAM ユーザー、ロール、ポリシー、MFA デバイスの削除を検知します。攻撃者は自らの活動の痕跡を消したり、防御側をロックアウトしたりするために IAM エンティティを削除します。 |
| 28 | 👑 AssumeRoot Usage | timeseries | 管理アカウントからメンバーアカウントの root への sts:AssumeRoot 呼び出しを検知します。管理アカウントが侵害されると、この方法ですべてのメンバーアカウントを乗っ取ることができます。 |
| 29 | 🎫 Support Case Manipulation | timeseries | AWS サポートケースのクローズとコメント活動を検知します。攻撃者は侵害に関する AWS の通知を抑制するために、不正使用/サポートケースを解決します。 |
| 30 | 🪪 Cognito User Pool Manipulation | timeseries | Cognito ユーザープールとアプリクライアントの変更 (トークン有効期限の延長、新規クライアント、管理者ユーザーの作成) を検知します。攻撃者はこれらを悪用して長期間有効なトークンを発行したり、バックドアユーザーを仕込んだりします。 |

### 🪣 Data & Storage

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | 高頻度の DeleteObject/DeleteObjects 呼び出し (1 時間あたり 50 回以上) を検知します。持ち出しとは異なる — データ破壊 / ランサムウェアのパターンです。 |
| 2 | 🔥 AWS Backup Tampering | timeseries | Backup Vault/Plan/RecoveryPoint の削除を検知します。バックアップの破壊はランサムウェア攻撃の最初のステップで、復旧を防ぎます。 |
| 3 | 🔓 KMS Key Operations | timeseries | キー削除や大量の Decrypt 呼び出しを含む機微な KMS 操作にフラグを立てます。 |
| 4 | 🔓 S3 Public Access Block Disabled | — | S3 パブリックアクセスブロック設定が無効化されるのを検知します。即座のデータ露出リスクです。 |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | S3 バケットポリシーと ACL の変更を検知します。バケットを公開読み取り可能にしたり、攻撃者が制御するアカウントにアクセス権を付与したりする可能性があります。 |
| 6 | 🪣 S3 Data Access Anomalies | bar | データ持ち出しを示す可能性のある大量の GetObject 呼び出し (1 時間あたり 100 回以上) を検知します。 |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | シークレット (DB パスワード、API キーなど) の一括取得を検知します。1 時間に 10 回以上の GetSecretValue 呼び出しは、認証情報収集の強いシグナルです。 |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | Secrets Manager のシークレット削除とクロスアカウントリソースポリシーの変更を検知します。既存の一括読み取り検知を、破壊とポリシーによる持ち出しベクトルで補完します。 |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | SSM Parameter Store エントリの一括読み取りを検知します。Secrets Manager と比べて見落とされがちな持ち出し経路です。 |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | 外部 AWS アカウントに共有された RDS/Aurora スナップショットを検知します。スナップショット共有による典型的なデータ持ち出しです。 |
| 11 | 💣 RDS Deleted without Final Snapshot | — | skipFinalSnapshot=true での RDS インスタンス/クラスターの削除を検知します。データ破壊の可能性があります。 |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | PubliclyAccessible=true で作成または変更された RDS インスタンスを検知します。VPC のセキュリティ制御を回避してデータベースをインターネットに直接露出させます。 |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | DynamoDB の ExportTableToPointInTime (S3 へのサイレントなテーブル全体エクスポート) とテーブル削除を検知します。高リスクな持ち出し・破壊ベクトルです。 |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | EBS Direct API 呼び出し (ListSnapshotBlocks / GetSnapshotBlock) を検知します。Pacu の ebs__download_snapshots はこの API を使って EC2 インスタンスを作成せずに生のスナップショットデータをストリーミングし、従来のスナップショット共有検知を回避します。 |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | 外部 S3 を指す Kinesis Firehose 配信ストリームの作成/更新を検知します。ネットワーク DLP からは見えないリアルタイムのデータパイプライン持ち出しです。 |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | PutBucketReplication と DeleteBucketReplication を検知します。クロスアカウントレプリケーションは、新規オブジェクトすべてを攻撃者が制御するバケットに密かにコピーします。 |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | S3 バージョニングの停止とサーバーアクセスログの無効化を検知します。バージョニングの無効化はデータ破壊を可能にし、ログの無効化はアクセス証跡を消去します。 |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | SES 受信ルールと ID 設定の変更を検知します。転送ルールはすべての受信メールを攻撃者アドレスに自動中継でき、検証済み ID はフィッシングキャンペーンを可能にします。 |
| 19 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | 外部アカウントへのアクセスを許可する SQS/SNS のキュー/トピックポリシー変更を検知します。大量送信アラートを発生させずに密かな持ち出し経路を作ります。 |
| 20 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | 公開共有された (group=all) EBS スナップショットまたは AMI を検知します。誰でもディスクイメージをコピーしてデータを抽出できるようになります。 |
| 21 | 📧 Data Exfiltration Channels | bar | 持ち出しを示す可能性のある大量の SNS/SQS/SES/S3 PutObject 呼び出し (1 時間あたり 50 回以上) を検知します。 |
| 22 | 🔐 S3 SSE-C Encryption (Ransomware) | timeseries | 攻撃者が提供した SSE-C キーで再暗号化された S3 オブジェクトと、バケットのデフォルト暗号化設定の変更を検知します。顧客キーがなければ被害者は復号できません — クラウドネイティブなランサムウェアのパターンです。 |
| 23 | ⏳ S3 Lifecycle-Triggered Deletion | timeseries | オブジェクトを期限切れにする S3 ライフサイクルルールと、ライフサイクル設定の削除を検知します。攻撃者は短い有効期限を設定することで、DeleteObject 呼び出しを発行せずに時間をかけてデータを密かに消去します。 |
| 24 | 🗃 RDS Query & Instance Manipulation | timeseries | RDS Data API のクエリ、マスターパスワードのリセット、スナップショットの復元を検知します。攻撃者はデータを直接読み取ったり、アクセスを得るために認証情報をリセットしたり、スナップショットを自分が制御するインスタンスに復元したりします。 |
| 25 | 🔎 S3 Bucket Enumeration | bar | バケットとオブジェクトのメタデータを走査する呼び出し元を検知します (1 時間に 10 回以上の List/GetBucket* 読み取り)。持ち出し前に価値あるデータの場所を特定する一般的な初期ステップです。 |
| 26 | 🔑 Storage Re-Encryption for Impact | timeseries | 明示的な KMS キーで再暗号化された EBS/RDS スナップショットとボリューム、およびデフォルトの EBS 暗号化の無効化を検知します。攻撃者が保有するキーで再暗号化することで、データを人質に取ります。 |

### ⚡ Compute & Serverless

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | 高頻度の EC2 StopInstances/TerminateInstances (1 時間に 5 回以上) を検知します。ランサムウェアによる妨害または破壊的な攻撃を示します。 |
| 2 | 🖥️ SSM Session / Run Command | timeseries | SSM StartSession、SendCommand、オートメーション実行を検知します。マネージドインスタンス経由の主要な横展開経路です。 |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | EC2 Instance Connect とシリアルコンソールアクセスを検知します。これにより攻撃者は SSH キーやバスティオンホストなしでブラウザや CLI からインスタンスに到達できます。SSH キーを持たない攻撃者にとって主要な横展開経路です。 |
| 4 | 📝 EC2 User Data Modification | timeseries | userData フィールドを変更する ModifyInstanceAttribute 呼び出しを検知します。ユーザーデータスクリプトは次回起動時に root として実行され、永続的なコード実行のバックドアとなります。 |
| 5 | ⚡ Lambda Function Tampering | timeseries | Lambda の作成、コード更新、権限変更を検知します。攻撃者は永続化のために Lambda を使用します。 |
| 6 | 📦 Lambda Layer Addition | timeseries | Lambda レイヤーの公開と権限変更を検知します。悪意のある共有レイヤーを公開し本番関数に追加すると、依存関係チェーンに攻撃者のコードが注入されます。 |
| 7 | 📦 ECS Task Definition | timeseries | ECS タスク定義の登録とサービス更新を検知します。Pacu の ecs__backdoor_task_def は悪意のあるコンテナイメージを指す新しいタスク定義バージョンを登録し、サービスを更新してデプロイします — ECR に一切触れません。 |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | IAM インスタンスプロファイルの関連付けと置換を検知します。特権プロファイルをアタッチすると、インスタンスに横展開のための昇格した権限が与えられます。 |
| 9 | 🖥 EC2 Instance Launches | timeseries | すべての RunInstances イベントを一覧表示します。予期しないリージョンでの起動はクリプトマイニングを示す可能性があります。 |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | 大規模な Spot Fleet リクエスト、リザーブドインスタンスの購入、高キャパシティの Auto Scaling グループ作成を検知します。クリプトマイニングによる財務的影響の指標です。 |
| 11 | ☸️ EKS Cluster API Calls | timeseries | EKS クラスターのコントロールプレーン変更を検知します。パブリックな API サーバーの露出や不正な Fargate プロファイルは、コンテナプラットフォームの乗っ取りを可能にします。 |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | ECR リポジトリの作成/削除、ポリシー変更、イメージのプッシュを検知します。本番リポジトリに悪意のあるイメージを注入するのはサプライチェーン永続化の手法です。 |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | EventBridge ルールと EventBridge Scheduler の変更を検知します。攻撃者はスケジュールされたルールを使って、実行中のプロセスなしで永続化を確立します。 |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | Lightsail インスタンスへのアクセス、キーペア操作、ポート露出を検知します。Pacu には 3 つの専用 Lightsail モジュール (enum、download_ssh_keys、generate_temp_access) があります。Lightsail リソースは標準の EC2 セキュリティ境界の外で動作します。 |
| 15 | 🛰 IMDS Options Weakening | timeseries | IMDSv2 を任意設定にしたり、メタデータエンドポイントを再有効化したりする ModifyInstanceMetadataOptions 呼び出しを検知します。IMDS を弱体化すると、インスタンスロールの認証情報を盗む SSRF 経路が再び開かれます。 |
| 16 | 💥 AMI & Snapshot Deletion | bar | AMI の一括登録解除と EBS スナップショットの削除 (1 時間に 5 回以上) を検知します。ゴールデンイメージとバックアップの破壊は、破壊的な攻撃の際に復旧手段を奪います。 |
| 17 | 🖥 WorkSpaces Hijacking | timeseries | Amazon WorkSpaces のプロビジョニングとプールの作成を検知します。攻撃者は被害者の負担でデスクトップを起動します — EC2 の境界外にある、監視の行き届いていないコンピュートハイジャックのチャネルです。 |

### 🤖 AI & LLM Abuse

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 🤖 Bedrock Model Invocation Spike | timeseries | 1 時間に 50 回以上 Bedrock モデルを呼び出すプリンシパルを検知します。盗まれた認証情報による大量推論 (LLMjacking) は、被害者に 1 日あたり数万ドルのコストを負わせる可能性があります。 |
| 2 | 🔓 Bedrock Model Access Enablement | timeseries | 基盤モデルへのアクセスの有効化やプロビジョンドキャパシティの購入を検知します。Bedrock を一度も導入していない組織では、これはほぼノイズのない LLMjacking の指標です — 攻撃者の典型的な最初の書き込みです。 |
| 3 | 🙈 Bedrock Invocation Logging Tampering | timeseries | Bedrock のモデル呼び出しログの削除や変更、さらに攻撃者がアカウントを悪用する前にログが有効かどうかを確認する行為を検知します (文書化された LLMjacking の IOC です)。 |
| 4 | 🧭 Bedrock Reconnaissance Sweep | bar | 2 リージョン以上にわたって Bedrock モデルを列挙する、または 1 時間に 10 回以上列挙呼び出しを行う呼び出し元を特定します。盗まれたキーの保有者はモデルが使用可能な場所を見つけるためにリージョンを横断して探索します。 |
| 5 | ⛔ Failed Bedrock Invocations | bar | 失敗した Bedrock 呼び出し (AccessDenied / ValidationException) のバーストを検出します。盗まれたキーのテストでは、有効な組み合わせが見つかるまでモデルとリージョンをまたいで失敗の嵐が発生します。 |
| 6 | 🌍 Bedrock Callers & Origins | — | Bedrock に触れたことのあるすべてのプリンシパルを、送信元 IP、GeoIP の発信元、ユーザーエージェント、モデルの多様性とともに棚卸しします。Bedrock を使う理由がないはずの呼び出し元や発信元を見つけます。 |

### 🌐 Network & Infrastructure

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 🌍 Security Group Opened to Internet | timeseries | 0.0.0.0/0 からのトラフィックを許可するセキュリティグループルールを検出します。直接的なパブリック露出リスクです。 |
| 2 | 🔥 Security Group Modifications | timeseries | セキュリティグループルールの変更、特に任意のポートで 0.0.0.0/0 を許可するルールを検知します。 |
| 3 | 🌊 VPC Flow Log Changes | timeseries | VPC フローログの削除を検知します。フローログを削除するとネットワークレベルの証拠が失われ、重大な防御回避の指標となります。 |
| 4 | 🌐 CloudFront Distribution Tampering | timeseries | CloudFront ディストリビューションの作成とオリジンの変更を検知します。オリジンの変更は CDN トラフィックを攻撃者が制御するサーバーにリダイレクトし、MitM による傍受やデータ収集を可能にします。 |
| 5 | 🛡 Network Firewall / Shield Tampering | timeseries | Network Firewall と Shield の保護の削除を検知します。ネットワーク層の防御を削除すると、VPC が直接的な攻撃トラフィックにさらされます。 |
| 6 | 🧱 Network ACL Changes | timeseries | ネットワーク ACL エントリの作成、削除、置換を検知します。NACL はセキュリティグループを上書きし、サブネット全体を攻撃者にさらす可能性があります。 |
| 7 | 🛣️ Route Table Changes | timeseries | ルートテーブルの変更を検知します。ルートの追加や置換により、トラフィックを攻撃者が制御するホストにリダイレクトできます (MitM、トラフィックハイジャック)。 |
| 8 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | 新しい VPN 接続、Direct Connect、Transit Gateway のアタッチメントを検知します。攻撃者は永続的な C2 や持ち出しチャネルのために秘匿ネットワークトンネルを作成します。 |
| 9 | 📡 Elastic IP Allocation / Association | timeseries | Elastic IP の割り当てと関連付けを検知します。攻撃者は安定した C2 インフラを作るために、侵害されたインスタンスに固定パブリック IP を割り当てます。 |
| 10 | 🗝️ EC2 Key Pair Creation | timeseries | CreateKeyPair と ImportKeyPair イベントを検知します。攻撃者はインスタンスへのアクセスを維持するための永続化手段として SSH キーを作成またはインポートします。 |
| 11 | 📡 Network Infrastructure Changes | timeseries | 攻撃者が制御するインフラを確立する可能性のある VPC およびネットワークレベルの変更を検知します。 |
| 12 | 🏷 ACM Certificate Operations | timeseries | ACM 証明書のリクエストと削除を検知します。攻撃者は侵害したアカウントを使って、フィッシングインフラを構築するために攻撃者が制御するドメイン用の TLS 証明書を発行します。 |
| 13 | 🔑 API Gateway Key Creation & Management | timeseries | API Gateway キーの作成と REST API 管理を検知します。Pacu の api_gateway__create_api_keys は、IAM キーローテーションを生き延びる永続的な API 認証情報を作成します。攻撃者はアクセス制御を弱めるために API オーソライザーも変更します。 |
| 14 | 🚧 VPC Endpoint Access Denied | timeseries | VPC エンドポイント経由のアクセス拒否エラーを検知します。エンドポイントポリシーの誤設定を示す可能性があります。 |
| 15 | 🌐 Route 53 & Domain Changes | timeseries | DNS レコードの編集、ホストゾーンの変更、ドメインの登録/移管を検知します。攻撃者はトラフィックをリダイレクトしたり、宙に浮いたサブドメインを乗っ取ったり、フィッシング用のなりすましドメインを登録したりします。 |

### 🕵 Threat Patterns

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | 1 時間に 10 個以上の異なる読み取り専用 API 呼び出しを行った呼び出し元を特定します。一般的な攻撃初期段階です。 |
| 2 | 🤖 Unusual User Agents | bar | まれなユーザーエージェント (5 イベント未満) を一覧表示します。Pacu や curl のようなカスタムツールは攻撃者のツールを示す可能性があります。 |
| 3 | 🌍 Multi-Region Activity | bar | 1 日に 3 つ以上のリージョンで書き込みを行う ID を検知します。地理的な拡散は侵害を示す可能性があります。 |
| 4 | 🕵 First-Time API Calls (24h) | — | 過去 24 時間に見られたが、それ以前には一度も見られなかった API 呼び出しを検出します。新規の操作は攻撃者ツールを示す可能性があります。 |
| 5 | 🗺 First-Seen Region Activity | bar | データセットの直近 24 時間に初めての活動が発生した AWS リージョンを見つけます。これまで使用されたことのないリージョンで活動することは、リージョン限定の監視からクリプトマイニングやステージングを隠す典型的な手法です。 |

### 📊 Activity & Baseline

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | AWS コンソール経由で行われた変更系 API 呼び出しを特定します。CLI のみのアクセスが想定される場合に有用です。 |
| 2 | 🔍 Events with Errors (24h) | timeseries | 過去 24 時間のすべてのエラーイベントを一覧表示します。現在何が失敗しているかを素早く把握できます。 |
| 3 | ❌ Error Spike Detection | — | エラー数が日平均を 3 倍超える 1 時間のウィンドウを検出します。スキャンや障害を示唆します。 |

### 🌍 GeoIP Analysis

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 🗺 Console Logins by Country | timeseries | コンソールログインイベントをその地理的発信元にマッピングします。予期しない国からのログインは高リスクです。 |
| 2 | 🚨 Unusual Country Access | bar | まれな国/ID の組み合わせを表示することで、予期しない国からの API 呼び出しを検知します。 |
| 3 | 🚫 Access Denied by Country | bar | アクセス拒否エラーをソース国ごとにグループ化します。1 つの国に集中する拒否は攻撃を示す可能性があります。 |
| 4 | 🔍 Write Events by Country | bar | 国ごとにグループ化された変更系 (書き込み) API 呼び出しを表示します。予期しない国からの書き込みは優先度が高いです。 |
| 5 | 🌍 Top Source Countries | bar | API 呼び出し量でソース国をランク付けします。すべてのアクティビティの地理的分布を特定します。 |
| 6 | 🏢 Top ASN / Organizations | bar | API 呼び出し量で自律システム (ISP/クラウドプロバイダー) を一覧表示します。VPN/ホスティングプロバイダーを見つけます。 |
| 7 | 📍 Top Source Cities | bar | イベント量でソース都市をランク付けします。最も活発な地理的発信元を特定します。 |
| 8 | 📋 API Calls by Country (Event Name) | bar | 各国から呼び出されている API 操作を表示します。予期しない国からの書き込みイベントは認証情報侵害を示します。 |
| 9 | 👤 Identities by Country (user_identity_arn) | bar | 各国からアクティブな IAM ID を表示します。新しい国から現れる ID は高信頼度の侵害指標です。 |
| 10 | 🌐 Private / Internal IP Summary | bar | プライベート、ループバック、AWS 内部 IP からのイベントを要約します。想定される内部トラフィックのベースラインです。 |

### ☁ IaC & Platform

| # | ラベル | チャート | 説明 |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | CI/CD パイプラインの作成と変更を検知します。悪意のあるビルドステップの注入やパイプラインソースの変更は、後続のすべてのデプロイを汚染します。 |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | CloudFormation スタック操作を検知します。攻撃者は IaC を使って悪意のあるインフラを迅速にデプロイする可能性があります。 |

</details>

---

## 📊 ダッシュボードチャート — 101 チャート

| タブ | チャート数 | 表示内容 |
|-----|:------:|---------------|
| 🚦 Overview | 10 | 9 種類のトリアージ KPI カード (イベント、プリンシパル、IP、root、MFA なしログイン、アクセス拒否、防御回避、国、リージョン) + グローバルなイベント量の推移 |
| 🎯 Threat Detection | 12 | 防御回避のキャッチオール · ロギングギャップ · VPC フローログ/Config/EventBridge/WAF の改ざん · SCP/組織メンバーシップの変更 · エラー/スロットリングの推移 · 書き込み/読み取り比率 |
| 🔑 Identity & Access | 16 | コンソールログイン · MFA 推移 · ログインヒートマップ · 失敗→成功の認証シーケンス · root の使用 · IAM エンティティのアクティビティ/削除 · 権限昇格タイムライン · 新規プリンシパル · SSO · クロスアカウント AssumeRole · AssumeRoot の使用 |
| 🚨 High-Risk API Monitor | 5 | セキュリティサービス改ざん & 認証情報取得 API のログ · 上位の高リスク呼び出し · 上位アクター · 時系列の高リスク呼び出し量 |
| 📊 API Activity | 6 | 上位 API · アクセス拒否アクション · リージョン分布 · エラーコードの構成 · ソース IP · ユーザーエージェント |
| 🪣 S3 & RDS | 15 | S3 一括ダウンロード/削除 · バージョニング/ロギングの無効化 · クロスアカウントレプリケーション · バケットポリシー/ACL · 列挙 · 保護設定 · Backup vault の削除 · KMS キーの削除 · RDS スナップショット共有 / スナップショットなしの削除 · SSE-C ランサムウェア暗号化 · ライフサイクルトリガー削除 · RDS クエリ/インスタンス操作 · 影響のためのストレージ再暗号化 |
| 🖥️ Computing | 17 | EC2 起動/大量停止/キーペア/インスタンスプロファイル/ユーザーデータ/スナップショット共有/spot fleet · ECS/Lambda/SSM/EBS Direct API/EKS-ECR/CloudFormation · IMDS の弱体化 · AMI/スナップショット削除 · WorkSpaces ハイジャック |
| 🤖 AI / LLM | 4 | Bedrock 呼び出しの推移 · モデルアクセス & ログ変更 · 失敗呼び出し · 発信元別の呼び出し元 (LLMjacking トリアージ) |
| 🌐 Network | 5 | セキュリティグループの変更 · NACL/ルートテーブルの変更 · VPC インフラ · VPC ピアリング/Transit Gateway · Route53 DNS の変更 |
| 🕒 Temporal Analysis | 6 | イベント速度の急増 · 再アクティブ化された休眠アカウント · ID/IP/API/サービスソース別の初回/最終確認 |
| 🌍 GeoIP Intelligence | 6 | 移動不可能な旅程 (複数国のプリンシパル) · 上位国/都市/ASN · 世界地図 · event_name × country |

<details markdown="1">
<summary>📋 全リスト — 全 101 チャート (クリックで展開)</summary>

## ダッシュボードチャート (Apache Superset — `dashboard/`)

### 🚦 Overview

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | Total Events | 選択した範囲内の CloudTrail イベントの総数 (KPI-81)。トリアージの分母であり、プリンシパルまたは IP ごとのあらゆる比率の基準です。 |
| 2 | Distinct Principals | 選択した範囲でアクティブなユニークな IAM プリンシパル ARN の数 (KPI-82)。レビュー対象のアクティビティに関与する ID の数を把握するために使用します。 |
| 3 | Distinct Source IPs | 選択した範囲でのユニークな呼び出し元ソース IP アドレスの数 (KPI-83)。ベースラインに対する急増は、プロキシ/VPN のローテーションや分散アクセスを示唆します。 |
| 4 | Root Account Events | アカウント root ID によって実行されたイベント数 (KPI-84)。root のアクティビティはほぼゼロであるべきです — 0 以外の値はいずれも調査が必要です。 |
| 5 | MFA-less Console Logins | 選択した範囲での MFA なしコンソールログインの数 (KPI-85)。認証情報侵害の直接的な指標です — MFA-less Login Trend を掘り下げてください。 |
| 6 | Access Denied Events | 選択した範囲での認可失敗イベントの数 (KPI-86)。急増は偵察や権限探索を示唆します — プリンシパル/IP でピボットしてください。 |
| 7 | Defense-Evasion Hits | 選択した範囲での監査/監視改ざんイベントの数 (KPI-87)。最優先のトリアージシグナルです — 0 以外の値は検知が無効化された可能性を意味します。Security Monitoring & Control Changes を掘り下げてください。MITRE ATT&CK: TA0005 Defense Evasion。 |
| 8 | Distinct Countries | 選択した範囲でのユニークなソース国の数 (KPI-88)。GeoIP エンリッチメント (docker/data/geoip/) が必要です。広い分布は予期しない地理的発信元からのアクセスを示唆します。 |
| 9 | Active Regions | 選択した範囲でアクティビティがあるユニークな AWS リージョンの数 (KPI-89)。未使用リージョンでのアクティビティは、リソースの悪用や攻撃者のステージングを示す可能性があります。 |
| 10 | CloudTrail Events Over Time | 時系列での時間別 Read 対 Write イベント量 (DSH-01)。積み上げ棒グラフは Read/Write の内訳を示します — write_events の急上昇は、攻撃者が偵察からアクティブな攻撃に移行していることを示します。アクティビティの急増や時間外の操作を特定するのに役立ちます。 |

### 🎯 Threat Detection

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | Security Monitoring & Control Changes | すべての防御回避イベントの包括的なキャッチオール (DSH-22)。CloudTrail の改ざん (StopLogging、DeleteTrail)、GuardDuty の無効化、AWS Config の無効化、VPC フローログの削除、CloudWatch ログの削除、セキュリティサービスの無効化 (SecurityHub、IAM Access Analyzer) をカバーします。ここに現れるイベントはいずれも即座の調査が必要です。詳細な分析には専用チャートを使用してください: VPC Flow Log Changes (DSH-42)、AWS Config Tampering (DSH-43)、EventBridge/CW Tampering (DSH-47)。MITRE ATT&CK: TA0005 Defense Evasion。 |
| 2 | CloudTrail Logging Gap (Hourly Volume) | 時間別 CloudTrail イベント量 (DSH-91)。アクティブな期間の間に突然ゼロに落ちる場合、ロギングが無効化された (StopLogging/DeleteTrail) か、配信の死角が存在することを示唆します。予期しないギャップは Security Monitoring & Control Changes テーブルと照合して調査してください。MITRE ATT&CK: T1562.008 Impair Defenses — Disable Cloud Logs。 |
| 3 | VPC Flow Log Changes | VPC フローログの作成と削除イベント (DSH-42)。DeleteFlowLogs は主要なネットワークフォレンジック証拠源を排除し、横展開やデータ持ち出しの事後分析を不可能にします。インシデント中の CreateFlowLogs は、攻撃者が制御する S3 バケットへのログリダイレクトを示す可能性があります。MITRE ATT&CK: TA0005 Defense Evasion。 |
| 4 | AWS Config Recorder & Rule Changes | AWS Config レコーダーとルールの改ざんイベント (DSH-43): StopConfigurationRecorder、DeleteConfigurationRecorder、DeleteDeliveryChannel、DeleteConfigRule、PutConfigRule。Config レコーダーを停止すると、リージョン全体のコンプライアンス証跡と変更追跡が失われ、その後のインフラ変更が Config ルールや Security Hub の標準で検知されなくなります。MITRE ATT&CK: TA0005 Defense Evasion。 |
| 5 | EventBridge & CloudWatch Rule Modifications | EventBridge と CloudWatch Events ルールの改ざん (DSH-47): DeleteRule、DisableRule (スケジュールされた検知の無音化)、CreateSchedule/UpdateSchedule (C2 ビーコニング用の攻撃者 cron ジョブ)、PutSubscriptionFilter (CloudTrail/VPC ログを攻撃者アカウントにリダイレクト)、DeleteLogGroup (VPC フローログ記録の破壊)。DFIR 向けの監視層改ざんの統合チャートです。MITRE ATT&CK: TA0003 Persistence / TA0005 Defense Evasion / TA0011 C2。 |
| 6 | WAF Configuration Changes | AWS WAF v2 / WAF Classic の設定変更イベント (DSH-75)。WebACL の作成/更新/削除、IP セットの操作、ルールグループの変更、ロギング設定の変更、保護対象リソースとの WAF の関連付け/解除をカバーします。攻撃進行中に WAF ルールやロギングを無効化することは、強い防御回避の指標です。MITRE ATT&CK: TA0005 Defense Evasion / TA0003 Persistence。 |
| 7 | Organizations / SCP Changes | SCP ポリシー変更を含む AWS Organizations 管理プレーンイベント (DSH-24)。マスターアカウントへのアクセス権を持つ攻撃者は、AWS 組織全体の予防的コントロールを取り除くために SCP ガードレールを無効化する可能性があります。MITRE ATT&CK: TA0004 Privilege Escalation / TA0005 Defense Evasion。 |
| 8 | Error Event Trend | error_code 別に分解した時間別エラーイベント (DSH-04)。ThrottlingException の急増は自動化されたスキャンや攻撃ツールを示し、AccessDenied / UnauthorizedAccess の急増は権限探索を示します。新しいエラーコードの突然の出現は新しい攻撃手法を示す可能性があります。 |
| 9 | Throttling Exception Spikes | AWS サービス別の時間別スロットリング/レート制限エラー (DSH-21)。ThrottlingException の急増は、ID (またはツール) が想定よりもはるかに速く API 呼び出しを発行していることを示し、これは偵察や列挙を行う自動化された攻撃ツールの特徴です。MITRE ATT&CK: TA0007 Discovery。 |
| 10 | Write/Read Ratio Trend | 読み取り対書き込み API 呼び出しの時間別内訳 (DSH-20)。read_events に対する write_events の持続的な増加は、攻撃者が偵察からアクティブな攻撃へ移行したことを示します。MITRE ATT&CK: TA0040 Impact / TA0007 Discovery。 |
| 11 | CloudTrail Events Over Time | 時系列での時間別 Read 対 Write イベント量 (DSH-01)。積み上げ棒グラフは Read/Write の内訳を示します — write_events の急上昇は、攻撃者が偵察からアクティブな攻撃に移行していることを示します。アクティビティの急増や時間外の操作を特定するのに役立ちます。 |
| 12 | Organization Membership Changes | アカウントをガードレールから切り離したり、攻撃者が制御する組織の配下に移動させたりする Organizations のメンバーシップ変更。Threat Technique Catalog for AWS: T1666.A002 / T1666.A003。 |

### 🔑 Identity & Access

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | Console Login Activity | IAM ID ごとにグループ化された AWS Management Console のサインインイベント (DSH-08)。成功、失敗、MFA なしのログイン試行を追跡します。失敗対成功の比率が高い場合、ブルートフォースやクレデンシャルスタッフィングを示す可能性があります。mfa_less_count (MFAUsed = 'No') はアカウント侵害の直接的な指標ですが、これは従来の ConsoleLogin イベントにのみ適用され、新しい OAuth2 サインインフロー (CreateOAuth2Token / AuthorizeOAuth2Access) は MFA ステータスを報告しません。イベントは event_type = 'AwsConsoleSignIn' でフィルタリングされます。 |
| 2 | MFA-less Login Trend | MFA 使用の有無で分割した日次コンソールログイン (DSH-28)。mfa_less_logins (MFAUsed = 'No') はアカウント侵害またはフィッシングの直接的な指標です。MFA なしログインの持続的な増加は、IAM 認証ポリシーの即座のレビューを促すべきです。MITRE ATT&CK: TA0001 Initial Access。 |
| 3 | Failed -> Success Auth Sequence | プリンシパル + ソース IP ごとのコンソールログインの失敗と成功 (DSH-93)。大きな failure_count と 0 でない success_count の組み合わせは、最終的に成功したブルートフォース/パスワードスプレーを示します — 成功を侵害のポイントとして扱い、ソース IP でピボットしてください。MITRE ATT&CK: T1110 Brute Force。 |
| 4 | Login Activity Heatmap (Hour x Day) | JST での曜日 (Y) 別・時間帯 (X) 別のコンソールログイン数のヒートマップ (DSH-19)。深夜 (22:00-06:00 JST) の列や週末の行が明るい場合、アカウント侵害や認証情報の悪用の強い指標です。MITRE ATT&CK: TA0001 Initial Access。 |
| 5 | Root Account Usage | AWS Root アカウントによるすべての API 呼び出し (DSH-13)。適切にガバナンスされた環境では、root アカウントの使用は極めてまれであるべきです。root のアクティビティ — 特に CreateAccessKey、ConsoleLogin、StopLogging — はいずれも侵害またはポリシー違反の重大な指標です。 |
| 6 | IAM Entity Activity | 総 API 呼び出し数でランク付けした上位 50 の IAM エンティティ (書き込み比率とエラーの内訳付き) (DSH-03)。write_ratio_pct または error_events が高いエンティティは、認証情報の悪用や権限昇格を示す可能性があります。last_seen は各エンティティの最新のアクティビティタイムスタンプを示します。 |
| 7 | IAM Privilege Change Event Timeline | イベント名別に分解した権限昇格 API 呼び出しの日次カウント (DSH-30)。単一日の急増は標的型攻撃キャンペーンを示し、緩やかな増加はインサイダー脅威や永続的な足場を持つ攻撃者を示す可能性があります。MITRE ATT&CK: TA0004 Privilege Escalation。 |
| 8 | New IAM Principal Creation Timeline | イベントタイプ別に積み上げた日次 IAM プリンシパルおよび認証情報作成イベント (DSH-95)。CreateAccessKey / CreateLoginProfile / CreateUser の急増は初期アクセス後の永続化の指標です — 実行プリンシパルとソース IP を相関させてください。MITRE ATT&CK: T1136 Create Account / T1098 Account Manipulation。 |
| 9 | Glue & SageMaker IAM Role Pass Events | IAM 権限昇格に使われる Glue DevEndpoint と SageMaker Notebook イベント (DSH-50)。iam:PassRole + glue:CreateDevEndpoint は、渡されたロールの全権限を持つ SSH アクセス可能な Python/Spark 環境を作成します。iam:PassRole + sagemaker:CreateNotebookInstance は同様の効果を持つ Jupyter ノートブックを提供します。sagemaker:CreatePresignedNotebookInstanceUrl 単体でも、基盤となるロールを所有せずに既存のノートブックへのアクセスを許可できます。両方とも AWS-IAM-Privilege-Escalation リポジトリに文書化されており、Pacu の iam__privesc_scan モジュールに実装されています。MITRE ATT&CK: TA0004 Privilege Escalation。 |
| 10 | AssumedRole from External IP | パブリック (非プライベート) IP アドレスから発信された AssumedRole API 呼び出し (DSH-27)。EC2 インスタンスメタデータサービス (IMDS) の認証情報は通常 VPC 内からのみ使用されます。外部 IP からの呼び出しは、一時認証情報が漏洩したこと (通常は SSRF、コンテナエスケープ、キーのエクスポート経由) を示します。MITRE ATT&CK: TA0008 Lateral Movement / TA0006 Credential Access。 |
| 11 | Cross-Account AssumeRole | recipient_account_id が呼び出し元のアカウントと異なる AssumeRole / AssumeRoleWithWebIdentity 呼び出し (DSH-94)。予期しない外部アカウント ID は、信頼関係の悪用やアカウント間の横展開を示します — 各宛先アカウントが承認された信頼先であることを確認してください。MITRE ATT&CK: T1199 Trusted Relationship / TA0008 Lateral Movement。 |
| 12 | Secrets Access Anomaly | 1 時間に 10 回以上 Secrets Manager または SSM Parameter Store にアクセスする ID (DSH-23)。一括での認証情報読み取りは、侵害後の指標です — 攻撃者は他のサービスやアカウントにピボットするために保存されたシークレットを収集します。MITRE ATT&CK: TA0006 Credential Access / TA0010 Exfiltration。 |
| 13 | Security-Relevant API Calls | 既知のセキュリティ上機微な AWS API アクションの呼び出し (DSH-12)。IAM 認証情報の変更、ポリシーの変更、S3 バケットポリシーの変更、セキュリティグループの変更、キー管理、STS トークン操作、セキュリティサービスの無効化、Secrets Manager の読み取り、Organizations 管理をカバーします。これらの呼び出しは通常の運用ではまれであるべきです — 予期しない発生は権限昇格、永続化、またはデータ持ち出しを示す可能性があります。 |
| 14 | IAM Identity Center (SSO) Events | sso.amazonaws.com、sso-directory.amazonaws.com、sso-oauth.amazonaws.com、identitystore.amazonaws.com からの AWS IAM Identity Center 管理イベント (DSH-44)。Identity Center はマルチアカウント組織における主要な認証経路です。主な脅威: CreatePermissionSet (バックドア管理者アクセス)、CreateAccountAssignment (攻撃者が制御するユーザーへのアカウント割り当て)、AttachManagedPolicyToPermissionSet (権限昇格)。MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence / TA0004 Privilege Escalation。 |
| 15 | IAM Entity Deletion | 攻撃者が作成した ID の痕跡を消去したり、防御側をロックアウトしたりするために使われる IAM ユーザー、ロール、ポリシー、MFA デバイスの削除。Threat Technique Catalog for AWS: T1070.A001。 |
| 16 | AssumeRoot Usage | 管理アカウントからメンバーアカウントの root への sts:AssumeRoot 呼び出し — メンバーアカウントを完全に乗っ取る経路です。Threat Technique Catalog for AWS: AT1669。 |

### 🚨 High-Risk API Monitor

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | Security Service Modification API Events | 監査コントロールを無効化または改ざんするために使われる API の詳細なイベントログ (HRM-44)。カバー範囲: DeleteTrail、StopLogging、UpdateTrail、PutEventSelectors (CloudTrail の改ざん)、DeletePolicy と DetachPolicy (IAM ガードレールの削除)。承認された変更ウィンドウ外での発生はいずれも即座の調査が必要です。MITRE ATT&CK: TA0005 Defense Evasion。 |
| 2 | Credential Retrieval API Events | シークレットと認証情報の取得に使われる API の詳細なイベントログ (HRM-45)。カバー範囲: GetSecretValue (Secrets Manager)、GetParameter / GetParameterHistory (SSM)。単発の呼び出しは正当な場合がありますが、短時間で数十の異なるシークレットにアクセスすることは強い攻撃者シグナルです。MITRE ATT&CK: TA0006 Credential Access。 |
| 3 | Top High-Risk API Calls | 高リスクウォッチリストからの API アクションを総呼び出し数でランク付け (HRM-40)。多くの環境で偵察 API (ListUsers、GetCallerIdentity) が頻繁に現れるのは想定内です — 通常とは異なる量で、または予期しないプリンシパルから現れる認証情報アクセスや防御回避の API に調査の重点を置いてください。 |
| 4 | Top Actors — High-Risk APIs | 高リスクウォッチリスト API への総呼び出し数でランク付けした IAM プリンシパル (HRM-42)。各プリンシパルが実行しているアクションを確認するために、attack-category チャートと相互参照してください。サービスロールが AssumeRole を頻繁に呼び出すのは想定内ですが、人間のユーザーが大量に GetSecretValue や DeleteTrail を呼び出すのは想定外です。 |
| 5 | High-Risk API Events Over Time | 攻撃キャンペーンで一般的に観測される API の日次呼び出し量 (HRM-39)。DeleteTrail や GetSecretValue のような通常はまれなアクションの突然の急増は即座の調査が必要です。これらの API の多くは正当なワークフローでも呼び出されることに注意してください — 単なる存在ではなく、量の異常を主要なシグナルとして使用してください。MITRE ATT&CK: TA0001 / TA0003 / TA0004 / TA0005 / TA0006 / TA0007 / TA0008。 |

### 📊 API Activity

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | Top 20 API Calls | 最も頻繁に呼び出される 20 の AWS API アクション (DSH-02)。機微なアクション (AssumeRole、GetSecretValue など) の呼び出し数が多い場合、自動化されたツールや偵察を示す可能性があります。 |
| 2 | Top Access Denied Actions | AccessDenied または Client.UnauthorizedAccess エラーを返した上位 20 の API アクション (DSH-09)。機微な API (AssumeRole、GetSecretValue、PutBucketPolicy など) に対する繰り返しのアクセス拒否イベントは、権限昇格の試みや横展開の強い指標です。 |
| 3 | Region Activity | AWS リージョン全体での CloudTrail イベントの分布 (DSH-14)。write_ratio_pct は書き込みアクティビティが不釣り合いに多いリージョンを強調します — 高い書き込み比率を持つ予期しないリージョンは、クリプトマイニング EC2 インスタンス、横展開、または監視の少ないリージョンへのデータ持ち出しを示す可能性があります。 |
| 4 | Error-Code Composition Over Time | error_code 別に積み上げた日次 CloudTrail エラー量 (DSH-96)。AccessDenied / UnauthorizedOperation の帯の上昇は偵察や権限探索を示し、Throttling の急増は大規模な列挙を示唆します。MITRE ATT&CK: TA0007 Discovery。 |
| 5 | Top Source IP Addresses | リクエスト数別の上位 100 の外部ソース IP (DSH-05)。AWS 内部の IP パターン (*.amazonaws.com) は除外されます。request_count に対して write_requests が多い IP は、持ち出し、横展開、または自動化された攻撃ツールを示す可能性があります。 |
| 6 | User Agent Analysis | リクエスト数別の上位 50 のユーザーエージェント (エラーと書き込みの内訳付き) (DSH-11)。異常な、またはカスタムのユーザーエージェント (Python/boto3、カスタムスクリプト、Pacu、ScoutSuite など) は自動化された攻撃ツールを示す可能性があります。AWS 内部のエージェント (console.amazonaws.com、signin.amazonaws.com) は想定内ですが、未知の文字列は調査が必要です。 |

### 🪣 S3 & RDS

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | S3 High-Volume Object Downloads | S3 大量 GetObject 呼び出し (DSH-52): 1 時間に 100 回以上の GetObject リクエストを行った ID を、時間バケット、ID、ソース IP ごとにグループ化。大量の読み取りは自動化されたデータ持ち出しを示します — 攻撃者はバケットの内容を破壊または身代金要求の対象にする前にダンプします。S3 Bulk Deletion チャートと組み合わせることで、持ち出し→破壊というランサムウェアの全体像を特定できます。MITRE ATT&CK: TA0010 Exfiltration。 |
| 2 | S3 Bulk Object Deletion | S3 大量 DeleteObject/DeleteObjects 呼び出し (DSH-53): 1 時間に 50 個以上のオブジェクトを削除した ID を、時間バケット、ID、ソース IP ごとにグループ化。大量の削除はランサムウェア攻撃のデータ破壊フェーズです — 攻撃者はまず持ち出し (S3 Bulk Download チャート参照) を行い、その後ソースバケットを消去して被害者を脅迫します。偶発的な大量削除もカバーします。MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction。 |
| 3 | S3 Versioning / Logging Disabled | S3 バージョニングの停止とロギングの無効化イベント (DSH-54): Status=Suspended の PutBucketVersioning と、BucketLoggingStatus が空の PutBucketLogging。攻撃者は削除後のオブジェクト復旧を防ぐためにバージョニングを無効化し、アクセス証跡を消去するためにロギングを無効化します。どちらもデータ破壊の前段階となるアンチフォレンジック行為です。MITRE ATT&CK: TA0005 Defense Evasion / T1070 Indicator Removal。 |
| 4 | S3 Cross-Account Replication | S3 クロスアカウントレプリケーション設定イベント (DSH-55): PutBucketReplication と DeleteBucketReplication。クロスアカウントレプリケーションは、新規オブジェクトすべてを攻撃者が制御するバケットに密かにコピーし、ネットワーク DLP コントロールを回避する永続的な持ち出しチャネルを確立します。外部アカウント ID を指す PutBucketReplication はいずれも重大なインシデント指標です。MITRE ATT&CK: TA0010 Exfiltration / T1537 Transfer Data to Cloud Account。 |
| 5 | S3 Bucket Policy / ACL Changes | S3 バケットポリシーと ACL の変更イベント (DSH-45): PutBucketPolicy、DeleteBucketPolicy、PutBucketAcl、PutBucketCors、PutBucketWebsite、DeleteBucketWebsite。これらの変更はバケットの内容を公開したり、攻撃者が制御するアカウントにアクセス権を付与したりする可能性があります。Principal='*' の PutBucketPolicy は即座のデータ露出指標です。MITRE ATT&CK: TA0010 Exfiltration / TA0005 Defense Evasion。 |
| 6 | S3 Bucket & Object List Activity | ID とソース IP ごとにグループ化した S3 列挙 API 呼び出し (DSH-74)。ListBuckets (アカウント全体の発見)、ListObjects / ListObjectsV2 (バケットごとの列挙)、ListObjectVersions、ListMultipartUploads、HeadBucket、HeadObject をカバーします。新しい ID や外部 IP からの list 呼び出しの突然の急増は、認証情報侵害後の偵察を強く示唆します。MITRE ATT&CK: TA0007 Discovery。 |
| 7 | S3 Protection Config Changes | バケットのセキュリティ態勢を弱める S3 イベント (DSH-25)。サーバーアクセスロギングの無効化は監査証跡を削除し、パブリックアクセスブロックの解除はデータをインターネットに露出させ、バケット暗号化やレプリケーションの削除は保管データの保護を弱めます。これらは持ち出し前または隠蔽のアクションです。MITRE ATT&CK: TA0005 Defense Evasion / TA0040 Impact。 |
| 8 | AWS Backup Vault & Plan Deletion Events | AWS Backup Vault、Plan、Recovery Point の削除イベント (DSH-57): DeleteBackupVault、DeleteBackupPlan、DeleteRecoveryPoint、DeleteBackupSelection、DisassociateRecoveryPoint、PutBackupVaultAccessPolicy、DeleteBackupVaultLockConfiguration。バックアップの破壊はランサムウェアキャンペーンの最初のステップです — 身代金要求の前に被害者がバックアップから復元できないようにします。Vault Lock の削除 (DeleteBackupVaultLockConfiguration) は、vault から WORM の不変性を取り除くため特に重大です。MITRE ATT&CK: TA0040 Impact / T1490 Inhibit System Recovery。 |
| 9 | KMS Key Deletion & Disable Events | KMS キーの削除、無効化、ローテーション管理イベント (DSH-66)。ScheduleKeyDeletion — キー削除をスケジュール (7〜30 日間キャンセル可能)。DisableKey — キーによる暗号化/復号を即座に停止。DeleteImportedKeyMaterial — インポートされたキーのキーマテリアルを即座に破壊。DisableKeyRotation — 年次自動キーローテーションを防止。これらのイベントのいずれかにより、そのキーで暗号化されたすべてのデータが永久にアクセス不能になります。削除日前に ScheduleKeyDeletion を取り消すには CancelKeyDeletion を使用してください。MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction。 |
| 10 | RDS Deleted without Final Snapshot | 最終スナップショットなしでの RDS インスタンス/クラスターの削除 (DSH-56): 最終スナップショットが取得されなかった DeleteDBInstance と DeleteDBCluster イベント。最終スナップショットをスキップすると、データベースは復旧不能になります — 削除後に復元ポイントが存在しません。ランサムウェアの実行者は、AWS Backup も無効化されている場合に被害者への圧力を最大化するためにこれを使用します。ここに現れるイベントはいずれも重大インシデントです。MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction。 |
| 11 | RDS Snapshot Cross-Account Share | RDS と Aurora のスナップショット共有イベント (DSH-40): 復元権限が別の AWS アカウントに付与された (valuesToAdd) ModifyDBSnapshotAttribute と ModifyDBClusterSnapshotAttribute。攻撃者は S3/ネットワークベースの DLP を介さずにデータベース全体を持ち出すために、自分のアカウントにスナップショットを共有します。復元属性に含まれる外部アカウント ID はいずれも重大な持ち出し指標です。MITRE ATT&CK: TA0010 Exfiltration。 |
| 12 | S3 SSE-C Ransomware Encryption | 攻撃者が提供した SSE-C キーで再暗号化された S3 オブジェクトと、バケットのデフォルト暗号化設定の変更 — クラウドネイティブなランサムウェアです。Threat Technique Catalog for AWS: T1486.A001。 |
| 13 | S3 Lifecycle-Triggered Deletion | DeleteObject のバーストなしでデータを密かに消去するために使われる、オブジェクトを期限切れにする S3 ライフサイクルルール (およびライフサイクル設定の削除)。Threat Technique Catalog for AWS: T1485.001。 |
| 14 | RDS Query & Instance Manipulation | データを直接読み取ったり、攻撃者が制御するインスタンスに復元したりするために使われる RDS Data API のクエリとスナップショットの復元。Threat Technique Catalog for AWS: AT1023.001 / T1213.A013。 |
| 15 | Storage Re-Encryption for Impact | 攻撃者が制御する明示的な KMS キーで再暗号化された EBS/RDS スナップショットとボリューム、およびデフォルト暗号化の無効化。Threat Technique Catalog for AWS: T1486.A002 / T1486.A003。 |

### 🖥️ Computing

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | EC2 Instance Launches | すべての EC2 RunInstances イベント (DSH-58)。攻撃者はクリプトマイニング (GPU/spot)、C2 リレー、または横展開のステージングのためにインスタンスを起動します — 検知を回避するために予期しないリージョンで行われることがよくあります。リージョン異常の調査には aws_region でフィルタリングし、どの認証情報が起動をトリガーしたかを追跡するには user_identity_arn でフィルタリングしてください。MITRE ATT&CK: TA0002 Execution / TA0040 Impact (Resource Hijacking)。 |
| 2 | RunInstances Spike by Region | AWS リージョン別に積み上げた日次 EC2 RunInstances 量 (DSH-97)。特に通常の運用範囲外のリージョンでの突然の急増は、クリプトマイニングやリソースの悪用を示します。実行プリンシパルとソース IP を相互参照してください。MITRE ATT&CK: T1496 Resource Hijacking。 |
| 3 | EC2 Mass Stop / Terminate | EC2 StopInstances と TerminateInstances イベント (DSH-62)。単一の API 呼び出しで数十のインスタンスを同時に停止または終了できます。大量終了はランサムウェアや妨害攻撃の破壊フェーズであり、本番の EC2 キャパシティを停止させます。影響を受けたすべての instanceId については request_parameters フィールドを確認してください。ランサムウェアの全体像を特定するには、AWS Backup Tampering と S3 Bulk Deletion チャートと組み合わせてください。MITRE ATT&CK: TA0040 Impact / T1489 Service Stop。 |
| 4 | EC2 Key Pair Creation | EC2 キーペアの作成とインポートイベント (DSH-59): CreateKeyPair、ImportKeyPair、DeleteKeyPair。攻撃者は IAM 認証情報のローテーションを生き延びる永続的な SSH アクセスを EC2 インスタンスに確立するために新しいキーペアを作成します。ImportKeyPair は AWS が生成することなく攻撃者が制御する公開鍵を直接注入します。見慣れない ID や IP からの CreateKeyPair または ImportKeyPair はいずれも永続化の指標です。MITRE ATT&CK: TA0003 Persistence。 |
| 5 | EC2 Instance Profile Changes | EC2 インスタンスプロファイルと IAM インスタンスプロファイルの管理イベント (DSH-60)。IAM: CreateInstanceProfile、DeleteInstanceProfile、AddRoleToInstanceProfile、RemoveRoleFromInstanceProfile。EC2: AssociateIamInstanceProfile、DisassociateIamInstanceProfile、ReplaceIamInstanceProfileAssociation。インスタンスプロファイルを変更すると、インスタンス上のすべてのコードが利用できる IAM ロールが置き換わります — 攻撃者がインスタンスを制御していて、より高い権限のロールを求めている場合の一般的な権限昇格経路です。MITRE ATT&CK: TA0004 Privilege Escalation / TA0003 Persistence。 |
| 6 | EC2 User Data Modification | EC2 ユーザーデータの変更イベント (DSH-61): userData 属性が変更された ModifyInstanceAttribute。EC2 のユーザーデータは、インスタンスの (再) 起動のたびに cloud-init によって実行されます — 悪意のあるスクリプトを注入すると、再起動を生き延びる永続的なコード実行が可能になります。実行をトリガーするために停止/起動のシーケンス (EC2 Mass Stop / Terminate チャート参照) と組み合わされることがよくあります。MITRE ATT&CK: TA0003 Persistence / TA0002 Execution。 |
| 7 | EC2 Public Snapshot / AMI Sharing | EC2 EBS スナップショットと AMI のパブリック共有イベント (DSH-41): グループ 'all' に createVolumePermission が付与された ModifySnapshotAttribute と、グループ 'all' に launchPermission が付与された ModifyImageAttribute。パブリックなスナップショットや AMI は、任意の AWS アカウントがディスクイメージをコピーし、ボリュームに保存された機微なデータ、認証情報、秘密鍵を抽出できるようにします。MITRE ATT&CK: TA0010 Exfiltration。 |
| 8 | EC2 Spot Fleet & Reserved Instance Purchases | EC2 Spot Fleet、Fleet、リザーブドインスタンスの購入イベント (DSH-63): RequestSpotFleet、ModifySpotFleetRequest、CancelSpotFleetRequests、CreateFleet、DeleteFleet、PurchaseReservedInstancesOffering、RequestSpotInstances、CancelSpotInstanceRequests。攻撃者は Spot Fleet を使ってクリプトマイニング用の大規模な GPU/CPU クラスターを起動し、インスタンスごとの検知しきい値を下回りながら高額な AWS 請求を発生させます。予期しない Spot Fleet やリザーブドインスタンスの購入はいずれも調査が必要です。MITRE ATT&CK: TA0040 Impact / T1496 Resource Hijacking。 |
| 9 | ECS Task Definition & Service Changes | ECS タスク定義の登録とサービス変更イベント (DSH-49)。Pacu の ecs__backdoor_task_def は、認証情報を盗むサイドカーコンテナを注入する新しいタスク定義リビジョンを登録し、それをデプロイするために UpdateService を発行します — ECR イメージの監視を完全に回避します。見慣れない呼び出し元や IP からの予期しない RegisterTaskDefinition や UpdateService はいずれも即座の調査が必要です。MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0006 Credential Access。 |
| 10 | Lambda Function Configuration & Permission Changes | Lambda 関数の作成、コード更新、権限イベント (DSH-64)。UpdateFunctionCode は関数のコードを悪意のあるペイロードに置き換えます。AddPermission はクロスアカウントまたはパブリックな Lambda 呼び出しアクセスを付与します。CreateFunctionUrlConfig は直接の C2 用のパブリック HTTP エンドポイントを作成します。CreateEventSourceMapping は関数を S3/DynamoDB/SQS でトリガーするよう配線します。PublishLayerVersion は複数の関数にまたがって悪意のある共有レイヤーを注入します。これらのいずれかが予期しない ID や IP から行われる場合、永続化/実行の指標です。MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0011 Command and Control。 |
| 11 | SSM Session / Run Command Execution | AWS Systems Manager のリモート実行イベント (DSH-39): StartSession、TerminateSession、ResumeSession、SendCommand、StartAutomationExecution。SSM Session Manager は開いた SSH/RDP ポートなしでシェルアクセスを提供し、盗まれた IAM 認証情報を持つ攻撃者にとって主要な横展開メカニズムです。異常な IP や ID からの予期しないセッションやコマンドはいずれも即座の調査が必要です。MITRE ATT&CK: TA0008 Lateral Movement / TA0002 Execution。 |
| 12 | EBS Direct API Snapshot Block Access | スナップショットデータの持ち出しに使われる EBS Direct API 呼び出し (DSH-51)。Pacu の ebs__download_snapshots は ListSnapshotBlocks と GetSnapshotBlock を使い、EC2 インスタンスの作成、スナップショットコピーのリクエスト、ModifySnapshotAttribute イベントのトリガーなしで、完全な EBS ディスクイメージをブロックごとにストリーミングします — 従来のスナップショット共有検知からは見えません。見慣れない ID や IP アドレスからの GetSnapshotBlock や ListSnapshotBlocks 呼び出しはいずれも重大な持ち出し指標です。MITRE ATT&CK: TA0010 Exfiltration / TA0009 Collection。 |
| 13 | EKS / ECR Container Platform Events | EKS クラスターと ECR コンテナレジストリのイベント (DSH-48)。EKS: UpdateClusterConfig (パブリック API)、CreateFargateProfile (悪意のあるワークロード)、AssociateIdentityProviderConfig (不正な OIDC IdP)。ECR: PutImage (バックドア入りイメージのプッシュ)、SetRepositoryPolicy (クロスアカウントアクセス)、PutRegistryPolicy (組織全体のレジストリ露出)。コンテナプラットフォームイベントは、サプライチェーン攻撃や Kubernetes コントロールプレーンの侵害を検知するために重要です。MITRE ATT&CK: TA0002 Execution / TA0003 Persistence / TA0010 Exfiltration。 |
| 14 | CloudFormation Stack Changes | CloudFormation スタックと変更セットの管理イベント (DSH-65)。単一の UpdateStack で EC2 インスタンスをデプロイしたり、IAM ロールを変更したり、ネットワーキングを再構成したりでき、個別の API 呼び出しを数十件、1 つのイベントに集約します。CreateStackSet は組織内のすべてのアカウントに攻撃者のインフラをデプロイします。ExecuteChangeSet は事前にステージングされた変更を適用し、初期レビューから影響範囲を隠します。DeleteStack はフォレンジック証拠となるリソースを破壊できます。MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0005 Defense Evasion。 |
| 15 | IMDS Options Weakening | IMDSv2 を任意設定にしたり、メタデータエンドポイントを再有効化したりする ModifyInstanceMetadataOptions 呼び出し。SSRF による認証情報窃取の経路を再び開きます。Threat Technique Catalog for AWS: T1552.005。 |
| 16 | AMI & Snapshot Deletion | 破壊的な攻撃の際に復旧のベースラインを破壊する、AMI の登録解除と EBS スナップショットの削除。Threat Technique Catalog for AWS: T1485.A002。 |
| 17 | WorkSpaces Hijacking | EC2 のセキュリティ境界外でのコンピュートハイジャックに使われる Amazon WorkSpaces のプロビジョニング。Threat Technique Catalog for AWS: T1496.A009。 |

### 🤖 AI / LLM

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | Bedrock Model Invocation Trend | プリンシパルごとの日次 Amazon Bedrock モデル呼び出し量 (DSH-98)。盗まれた認証情報による大量推論 (LLMjacking) は、被害者の費用でリバースプロキシを介して転売されます。急増、これまで一度も Bedrock を呼び出したことのないプリンシパル、予期しない発信元からの呼び出しはいずれも調査してください。MITRE ATT&CK: TA0040 Impact (T1496 Resource Hijacking)。 |
| 2 | Bedrock Model Access & Logging Changes | 基盤モデルのアクセス有効化と呼び出しログの改ざん (DSH-99)。盗まれた認証情報を持つ攻撃者は、悪用する前に自ら Bedrock のモデルアクセスを有効化し、プロンプトが記録されないようにモデル呼び出しログの設定を確認または削除します — どちらも文書化された LLMjacking の指標です。Bedrock を一度も導入していない組織でのいずれの行も即座の調査が必要です。MITRE ATT&CK: TA0005 Defense Evasion / TA0040 Impact (T1496)。 |
| 3 | Bedrock Failed Invocations | 呼び出し元とエラーコードでグループ化した失敗した Amazon Bedrock 呼び出し試行 (DSH-100)。複数のモデルとリージョンにまたがる AccessDenied / ValidationException エラーのバーストは、攻撃者が盗まれたキーで呼び出せるモデルを探っていることを示します — LLMjacking の偵察フェーズです。MITRE ATT&CK: TA0006 Credential Access / TA0007 Discovery。 |
| 4 | Bedrock Callers by Origin | 発信元とモデルの多様性を含むすべての Amazon Bedrock 呼び出し元の一覧 (DSH-101)。LLMjacking トリアージのためのベースラインビュー: 予期しない国、ホスティング/VPN の ASN、または汎用的なスクリプト用ユーザーエージェント (python-requests、curl) から高い呼び出し量で呼び出しているプリンシパルは、有力な容疑者です。MITRE ATT&CK: TA0040 Impact (T1496 Resource Hijacking)。 |

### 🌐 Network

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | Security Group Changes | EC2 セキュリティグループルールの変更 (DSH-76)。インバウンド/アウトバウンドルールの許可と取り消し、セキュリティグループの作成と削除、ルールの説明の更新をカバーします。管理用ポート (22、3389 など) で 0.0.0.0/0 に開かれたインバウンドルールは、バックドアアクセスや誤設定の強い指標です。MITRE ATT&CK: TA0003 Persistence / TA0005 Defense Evasion。 |
| 2 | Network ACL / Route Table Changes | ネットワーク ACL とルートテーブルの変更イベント (DSH-46)。NACL の変更 (CreateNetworkAclEntry、DeleteNetworkAclEntry、ReplaceNetworkAclEntry) は、サブネット全体でセキュリティグループの制限を回避できます。ルートテーブルの変更 (CreateRoute、ReplaceRoute、DeleteRoute) は、傍受のためにトラフィックを攻撃者が制御するインフラにリダイレクトしたり、密かな C2 通信チャネルを確立したりできます。MITRE ATT&CK: TA0005 Defense Evasion / TA0011 Command and Control。 |
| 3 | VPC Infrastructure Changes | VPC トポロジー変更イベント (DSH-77)。VPC の作成/削除/変更、サブネットの変更、インターネットゲートウェイのアタッチ、NAT ゲートウェイの作成/削除、VPC エンドポイントの変更、Elastic IP の割り当て/関連付けをカバーします。予期しない IGW のアタッチや未使用リージョンでの新しい NAT ゲートウェイは、攻撃者が制御する持ち出しインフラの強い指標です。MITRE ATT&CK: TA0010 Exfiltration / TA0003 Persistence / TA0011 C2。 |
| 4 | VPC Peering & Transit Gateway Changes | VPC ピアリング接続と Transit Gateway の変更イベント (DSH-78)。VPC ピアリングの作成/承認/削除、Transit Gateway の作成、VPC アタッチメント、ピアリングアタッチメント管理をカバーします。クロスアカウントのピアリングリクエストや予期しないアカウントからの新しい Transit Gateway アタッチメントは、AWS アカウント間の横展開を示します。MITRE ATT&CK: TA0008 Lateral Movement / TA0010 Exfiltration。 |
| 5 | Route53 DNS Changes | Route 53 ホストゾーンとリゾルバー設定の変更 (DSH-29)。DNS トンネリングは TXT/CNAME レコードと大量のサブドメインを使って DNS クエリペイロードでデータを持ち出します。新しいホストゾーンや予期しない ChangeResourceRecordSets 呼び出しは即座に調査すべきです。MITRE ATT&CK: TA0010 Exfiltration。 |

### 🕒 Temporal Analysis

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | Event Velocity Spikes per Identity | 1 時間に 50 件以上のイベントのバーストアクティビティ期間を持つ ID (DSH-38)。クレデンシャルスタッフィング、自動化された列挙、データ持ち出しは、通常のベースラインを超える急激な速度の急増を生み出します。各急増の時間バケット、ID、イベント数を表示します。MITRE ATT&CK: TA0006 Credential Access / TA0009 Collection / TA0010 Exfiltration。 |
| 2 | Dormant Accounts Reactivated | 72 時間以上の非アクティブ期間を経て活動を再開した ID (DSH-37)。侵害された休眠認証情報が武器化される典型的なパターンです。ID ごとに連続するイベント間の最大ギャップを時間/日単位で表示します。MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence。 |
| 3 | First / Last Seen per IAM Identity | 初回/最終確認のタイムスタンプ、イベント数、異なる API 数、異なる IP 数、日単位のアクティブ期間を持つ IAM ID (DSH-31)。first_seen の降順でソートすると新しく現れた ID を見つけられます。イベント数が多いのにアクティブ期間が短い場合、侵害された認証情報や自動化された攻撃を示します。MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence。 |
| 4 | First / Last Seen per Source IP | 初回/最終確認、異なる ID、異なる API、GeoIP コンテキストを持つソース IP (DSH-32)。データセットの後半に現れる新しい IP は、横展開や新しい攻撃者インフラを示唆します。MITRE ATT&CK: TA0001 Initial Access / TA0008 Lateral Movement。 |
| 5 | First / Last Seen per API Call | 初出順に並べた API アクション (DSH-33)。初めて現れる新しい API 呼び出しは、偵察や権限昇格の試みを示唆します。MITRE ATT&CK: TA0007 Discovery / TA0004 Privilege Escalation。 |
| 6 | First / Last Seen per Service Source | すべての異なる AWS サービスソースの初回/最終確認タイムスタンプ (DSH-26)。first_seen の降順でソートすると、新しく導入されたサービス (潜在的な攻撃者インフラ) が浮かび上がります。last_seen の昇順でソートすると、活動が止まったサービス (侵害後のクリーンアップの可能性) を見つけられます。MITRE ATT&CK: TA0003 Persistence / TA0007 Discovery。 |

### 🌍 GeoIP Intelligence

| # | チャート名 | 説明 |
|---|------------|-------------|
| 1 | Impossible Travel (Multi-Country Principals) | 異なるソース国の数でランク付けした IAM プリンシパル (異なるソース IP、総イベント数、初回/最終確認付き) (DSH-92)。人間のプリンシパルで distinct_countries >= 2 は強いアカウント侵害シグナルです — 時間ウィンドウとソース IP を相互参照してください。GeoIP エンリッチメントが必要です。MITRE ATT&CK: TA0001 Initial Access / T1078 Valid Accounts。 |
| 2 | Top Countries by Request Volume | API 呼び出し量別の上位 20 のソース国 (書き込みイベントとユニーク呼び出し元の内訳付き) (DSH-15)。組織の業務と通常関連のない国は、認証情報の窃取や攻撃者が制御するインフラを示す可能性があります。GeoLite2 エンリッチメントが必要です — NULL 行は自動的に除外されます。 |
| 3 | Top ASN Organizations by Request Volume | API 呼び出し量別の上位 25 の ASN 組織 (書き込みイベントとユニーク呼び出し元の内訳付き) (DSH-18)。VPN プロバイダー、Tor 出口ノード、ホスティング会社、または想定される範囲外のクラウドプロバイダーから発信されたトラフィックは、攻撃者による匿名化インフラの使用を示す可能性があります。GeoLite2 エンリッチメントが必要です — NULL 行は自動的に除外されます。 |
| 4 | Top Cities by Request Volume | API 呼び出し量別の上位 25 の都市 (書き込みイベントとユニーク呼び出し元の内訳付き) (DSH-17)。都市レベルの粒度は、国レベルの分析だけでは見えない、脅威アクターが使用する特定のデータセンターの場所を明らかにできます。GeoLite2 エンリッチメントが必要です — NULL 行は自動的に除外されます。 |
| 5 | Global Request Origin Map | CloudTrail API 呼び出し発信元の地理的分布を示す世界地図 (DSH-16)。国の色の濃さはイベント数に比例します。組織の業務と通常関連のない国は、認証情報の窃取や攻撃者が制御するインフラを示す可能性があります。GeoLite2 エンリッチメントが必要です — NULL 行は自動的に除外されます。 |
| 6 | API Calls by Country (Event Name × GeoIP) | API 呼び出し量別の上位 50 の (event_name, country) ペア (DSH-79)。どの API 操作が各地理的地域から呼び出されているかを明らかにします。予期しない国からの書き込み操作は、認証情報侵害の強い指標です。GeoLite2 エンリッチメントが必要です — プライベート/内部 IP と NULL 行は除外されます。 |

</details>

---
