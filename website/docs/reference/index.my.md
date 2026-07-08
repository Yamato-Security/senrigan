# Built-in Query နှင့် Dashboard အကိုးအကား

> 💡 SQL သို့မဟုတ် AWS အသိပညာ နက်နက်ရှိုင်းရှိုင်း မလိုအပ်ပါ — dropdown မှ hunt တစ်ခုကို ရွေးချယ်ပြီး ရလဒ်များကို ချက်ချင်းရယူလိုက်ပါ။

## 🎯 Built-in Hunts — query 100+ ခု

အမျိုးအစားများကို DFIR triage ဦးစားပေးအလိုက် စီထားသည် — ဦးစွာ detection-tool tampering ကို စစ်ဆေးပါ၊ ထို့နောက် identity abuse၊ ထို့နောက် data impact ကို စစ်ဆေးပါ။

| Category | Queries | Key Threats Covered |
|----------|:-------:|---------------------|
| 🛡 Detection & Response | 12 | Audit-service tampering (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · SCP ဖျက်ခြင်း · alarm ဖိနှိပ်ခြင်း · log exfiltration |
| 🔑 Identity & Access | 26 | Root အသုံးပြုခြင်း · console login/MFA · privilege escalation · trust policy backdoor · PassRole အလွဲသုံးစားလုပ်ခြင်း · cross-account AssumeRole · SSO/SAML/OIDC · credential enumeration |
| 🪣 Data & Storage | 21 | S3 အစုလိုက် ဖျက်ခြင်း/download · secrets အစုလိုက်ဖတ်ခြင်း · backup tampering · KMS ops · snapshot မျှဝေခြင်း · EBS Direct API exfiltration · DynamoDB export · S3 cross-account replication |
| ⚡ Compute & Serverless | 14 | EC2 အစုလိုက် stop/terminate · SSM lateral movement · Lambda/ECS/EKS/ECR tampering · EventBridge persistence · cryptomining · Lightsail အလွဲသုံးစားလုပ်ခြင်း |
| 🌐 Network & Infrastructure | 14 | SG ကို အင်တာနက်သို့ ဖွင့်ခြင်း · VPC flow log ဖျက်ခြင်း · CloudFront hijack · ဖုံးကွယ်ထားသော VPN/TGW tunnel · Elastic IP C2 · API Gateway keys |
| 🕵 Threat Patterns | 5 | အလုပ်ချိန်ပြင်ပ ရေးသားခြင်း · recon burst · multi-region ပျံ့နှံ့ခြင်း · ပုံမှန်မဟုတ်သော user agents · ပထမဆုံးအကြိမ် API calls |
| 📊 Activity & Baseline | 3 | Console write events · error spikes · မကြာသေးမီက errors |
| 🌍 GeoIP Analysis ✦ | 12 | မဖြစ်နိုင်သော ခရီးသွားလာမှု · multi-country credentials · geo-ranked logins/denials/writes · country/city/ASN ခွဲခြမ်းစိတ်ဖြာမှု · event_name × country · identity × country |
| ☁ IaC & Platform | 2 | CI/CD supply chain · CloudFormation အလွဲသုံးစားလုပ်ခြင်း |

<details markdown="1">
<summary>📋 စာရင်းအပြည့်အစုံ — query 100+ ခုလုံး (ချဲ့ရန် နှိပ်ပါ)</summary>

## Built-in Hunts

### 🛡 Detection & Response

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | CloudTrail ကို ရပ်တန့်ရန် သို့မဟုတ် ပြုပြင်ရန် ကြိုးပမ်းမှုမှန်သမျှကို ထောက်လှမ်းသည် — အရေးကြီးဆုံး ဖုံးကွယ်မှု ညွှန်ပြချက် |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | GuardDuty ပိတ်ခြင်း၊ ဖျက်ခြင်း နှင့် threat-intel ကိုင်တွယ်ခြင်းတို့ကို ထောက်လှမ်းသည် |
| 3 | ⛔ Security Hub Tampering | timeseries | Security Hub ပိတ်ခြင်း၊ standard ပိတ်ခြင်း နှင့် finding ဖိနှိပ်ခြင်းတို့ကို ထောက်လှမ်းသည် |
| 4 | ⚙️ AWS Config Tampering | timeseries | AWS Config recorder/rule ဖျက်ခြင်းကို ထောက်လှမ်းသည် (compliance သက်သေအထောက်အထားကို ဖယ်ရှားသည်) |
| 5 | 🛡 Organizations SCP Changes | timeseries | SCP ဖန်တီးခြင်း၊ update လုပ်ခြင်း နှင့် ဖျက်ခြင်းတို့ကို ထောက်လှမ်းသည် — Deny SCP တစ်ခုကို ဖယ်ရှားခြင်းသည် OU အတွင်းရှိ အကောင့်တိုင်းတွင် guardrail များကို ဖျောက်ဖျက်လိုက်သည် |
| 6 | 🚫 AWS Macie Tampering | timeseries | Macie ပိတ်ခြင်း နှင့် finding-filter ဖန်တီးခြင်းတို့ကို ထောက်လှမ်းသည် (exfiltration မပြုလုပ်မီ ကာကွယ်မှု ရှောင်လွှဲခြင်း) |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | alarm ဖျက်ခြင်း နှင့် DisableAlarmActions ကို ထောက်လှမ်းသည် — alarm ကို မဖျက်ဘဲ security alerting ကို တိတ်ဆိတ်စေသည် |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | CW Logs subscription filter ဖန်တီးခြင်း/ဖျက်ခြင်းကို ထောက်လှမ်းသည် (တိုက်ခိုက်သူ၏ Kinesis/Lambda သို့ real-time log exfiltration) |
| 9 | 🏹 WAF WebACL Changes | timeseries | WAFv2/WAF Classic တစ်လျှောက် WAF WebACL ဖန်တီးခြင်း၊ update လုပ်ခြင်း နှင့် ဖျက်ခြင်းတို့ကို ထောက်လှမ်းသည် |
| 10 | 🔍 GuardDuty Findings Read | timeseries | ListFindings / GetFindings ကို ထောက်လှမ်းသည် — တိုက်ခိုက်သူသည် SOC က ဘာတွေ ထောက်လှမ်းပြီးပြီဆိုသည်ကို နားလည်ရန် active findings များကို ဖတ်သည် |
| 11 | 💰 Budget / Cost Anomaly Changes | timeseries | Budget/AnomalyMonitor ဖျက်ခြင်းကို ထောက်လှမ်းသည် (cryptomining ကုန်ကျစရိတ်များကို ဖုံးကွယ်ခြင်း) |
| 12 | 🚫 Access Denied Errors | bar | AccessDenied error များကို identity နှင့် API အလိုက် အုပ်စုဖွဲ့သည် — အများဆုံး ကျူးလွန်သူများသည် credential အလွဲသုံးစားကို ညွှန်ပြသည် |

### 🔑 Identity & Access

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | root account က ပြုလုပ်သော API call မှန်သမျှကို ထောက်လှမ်းသည် — root ကို production တွင် ဘယ်တော့မှ မသုံးသင့်ပါ |
| 2 | 🔓 Console Login without MFA | timeseries | MFA မသုံးဘဲ console login လုပ်ခြင်းကို ထောက်လှမ်းသည် — account အပေးယူခံရခြင်း၏ အန္တရာယ်များသော ညွှန်ပြချက် |
| 3 | 🌐 Console Logins | timeseries | အောင်မြင်မှုနှင့် ကျရှုံးမှုများ အပါအဝင် console login ကြိုးပမ်းမှုအားလုံးကို စာရင်းပြုစုသည် (brute force ထောက်လှမ်းခြင်း) |
| 4 | 🔐 MFA & Password Changes | timeseries | MFA ပိတ်ခြင်း နှင့် password reset လုပ်ခြင်းတို့ကို ထောက်လှမ်းသည် — account သိမ်းယူခံရခြင်း၏ ခိုင်မာသော ညွှန်ပြချက် |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | IAM policy ပူးတွဲခြင်း နှင့် role ကိုင်တွယ်ခြင်းတို့ကို ထောက်လှမ်းသည် (PutUserPolicy, AttachRolePolicy, CreatePolicyVersion စသည်) |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | UpdateAssumeRolePolicy ကို ထောက်လှမ်းသည် — trust policy တစ်ခုသို့ ပြင်ပ principal များ ထည့်ခြင်းသည် တည်မြဲသော backdoor တစ်ခုကို ဖန်တီးသည် |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | permission boundary put/delete event များကို ထောက်လှမ်းသည် — boundary တစ်ခုကို ဖယ်ရှားခြင်းသည် ထိရောက်သော permission များကို ချက်ချင်း ချဲ့ထွင်လိုက်သည် |
| 8 | 👑 User Added to Admin Group | timeseries | အမည်တွင် 'admin' ပါသော group များသို့ ထည့်သွင်းခံရသော user များကို ထောက်လှမ်းသည် — ဂန္ထဝင် privilege escalation |
| 9 | 👥 IAM Group Membership Changes | timeseries | group အမည် မည်သို့ပင်ဖြစ်စေ AddUserToGroup / RemoveUserFromGroup / CreateGroup / DeleteGroup event အားလုံးကို ထောက်လှမ်းသည် |
| 10 | 👤 New IAM Users / Keys | timeseries | IAM user နှင့် access key ဖန်တီးခြင်း event များကို ဖော်ထုတ်သည် — မမျှော်လင့်သော ဖန်တီးမှုသည် persistence ကို ညွှန်ပြနိုင်သည် |
| 11 | 🎯 IAM PassRole Abuse | timeseries | role ARN တစ်ခု ဖြတ်သန်းသွားသော လက်ခံရရှိသည့်-service event များ (RunInstances, CreateFunction, CreateNotebookInstance စသည်) ကို စစ်ဆေးခြင်းဖြင့် iam:PassRole အသုံးပြုမှုကို ထောက်လှမ်းသည် |
| 12 | 🔐 AssumeRole Cross-Account | timeseries | caller နှင့် target တို့ မတူညီသော AWS account များတွင် ရှိနေသော AssumeRole event များကို ပြသည် (lateral movement) |
| 13 | 🏢 Cross-Account Access | timeseries | caller account သည် recipient account နှင့် ကွဲပြားသော event အားလုံးကို ရှာဖွေသည် |
| 14 | 🔑 STS Federation Token Issuance | timeseries | GetFederationToken နှင့် GetSessionToken ကို ထောက်လှမ်းသည် — သက်တမ်းရှည် key များကို တည်မြဲသော ယာယီ credential များအဖြစ် ပြောင်းလဲသည် |
| 15 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | OIDC trust အလွဲသုံးစားကို ထောက်လှမ်းသည် (မှားယွင်းစွာ ပြင်ဆင်ထားသော sub claim / repo အခြေအနေမပါသော GitHub Actions) |
| 16 | 🆔 IAM Identity Center (SSO) Events | timeseries | AWS IAM Identity Center management လုပ်ဆောင်ချက်များ (CreatePermissionSet, CreateAccountAssignment စသည်) ကို ထောက်လှမ်းသည် |
| 17 | 🔗 SAML / OIDC Provider Updates | timeseries | SAML/OIDC identity provider ပြောင်းလဲမှုများကို ထောက်လှမ်းသည် — တိုက်ခိုက်သူ ထိန်းချုပ်ထားသော IdP ဖြင့် SAML metadata ကို update လုပ်ခြင်းသည် တည်မြဲသော authentication backdoor တစ်ခုကို ဖန်တီးသည် |
| 18 | 🧐 IAM Access Analyzer Calls | timeseries | IAM Access Analyzer ၏ အသုံးပြုမှုမှန်သမျှကို ထောက်လှမ်းသည် — တိုက်ခိုက်သူများသည် custom recon script များမလိုဘဲ ပြင်ပမှ ဝင်ရောက်နိုင်သော resource များကို စာရင်းပြုစုရန် native analyzer ကို အသုံးချသည် |
| 19 | 🔄 Credential Report & Enumeration | timeseries | IAM enumeration (GenerateCredentialReport, ListUsers, ListRoles, GetAccountAuthorizationDetails စသည်) ကို ထောက်လှမ်းသည် |
| 20 | 🗝 Access Key Abuse | bar | ၇ ရက်အတွင်း ကွဲပြားသော source IP ၃ ခုနှင့်အထက်မှ အသုံးပြုခဲ့သော access key များကို ထောက်လှမ်းသည် — key ပေါက်ကြားမှု၏ ခိုင်မာသော ညွှန်ပြချက် |
| 21 | 📰 AWS Organizations Account Creation | timeseries | Organizations account ဖန်တီးခြင်း နှင့် ကိုယ်စားလှယ်အုပ်ချုပ်ရေးမှူး ပြောင်းလဲခြင်းတို့ကို ထောက်လှမ်းသည် (shadow account persistence) |
| 22 | 👥 Cognito Unauthenticated Access | timeseries | allowUnauthenticatedIdentities=true ရှိသော Cognito Identity Pool များကို ထောက်လှမ်းသည် |
| 23 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | Glue DevEndpoint ဖန်တီးခြင်း (iam:PassRole + glue:CreateDevEndpoint = ဖြတ်သန်းပေးထားသော role ၏ permission အပြည့်အဝဖြင့် run နေသော SSH-ဝင်ရောက်နိုင်သည့် endpoint) နှင့် credential ရိတ်သိမ်းရန် connection enumeration ကို ထောက်လှမ်းသည် |
| 24 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | SageMaker notebook ဖန်တီးခြင်း နှင့် presigned URL ထုတ်ပေးခြင်းတို့ကို ထောက်လှမ်းသည် — iam:PassRole + sagemaker:CreateNotebookInstance သည် ဖြတ်သန်းပေးထားသော role ၏ AWS permission အပြည့်အဝဖြင့် Jupyter environment တစ်ခုကို စတင်သည် |
| 25 | 🛠 Data Pipeline / CodeStar Privilege Escalation | timeseries | iam:PassRole escalation အတွက် အသုံးပြုသော Data Pipeline နှင့် CodeStar resource ဖန်တီးခြင်းကို ထောက်လှမ်းသည် (CreateProjectFromTemplate သည် side effect အဖြစ် admin IAM role တစ်ခုကို ဖန်တီးသည်) |
| 26 | 🧩 Step Functions Privilege Escalation | timeseries | Step Functions state machine ဖန်တီးခြင်းကို ထောက်လှမ်းသည် (iam:PassRole + states:CreateStateMachine သည် ဖြတ်သန်းပေးထားသော role အောက်တွင် Lambda/ECS task များကို execute လုပ်သည်) |

### 🪣 Data & Storage

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | တစ်နာရီလျှင် DeleteObject/DeleteObjects call ၅၀ နှင့်အထက် ပြုလုပ်နေသော identity များကို ထောက်လှမ်းသည် — ransomware / wiper data ဖျက်ဆီးမှု ပုံစံ |
| 2 | 🔥 AWS Backup Tampering | timeseries | Backup Vault / Plan / RecoveryPoint ဖျက်ခြင်း နှင့် Vault Lock ဖယ်ရှားခြင်းကို ထောက်လှမ်းသည် — ပြန်လည်ရယူရေး ရွေးချယ်စရာများကို ဖျောက်ဖျက်ရန် ransomware ၏ ပထမဆုံးခြေလှမ်း |
| 3 | 🔓 KMS Key Operations | timeseries | အရေးကြီးသော KMS operation များ (DisableKey, ScheduleKeyDeletion, CreateGrant, PutKeyPolicy, ပမာဏများသော Decrypt) ကို အလံပြသည် |
| 4 | 🔓 S3 Public Access Block Disabled | — | S3 public access block setting များ ပိတ်ခံရခြင်းကို ထောက်လှမ်းသည် — ချက်ချင်း data ဖော်ထုတ်ခံရမှု အန္တရာယ် |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | S3 bucket policy နှင့် ACL ပြုပြင်ခြင်းများကို ထောက်လှမ်းသည် (Principal='*' ပါသော PutBucketPolicy သည် အထူးအရေးကြီးသည်) |
| 6 | 🪣 S3 Data Access Anomalies | bar | အစုလိုက် GetObject call များ (၁၀၀/နာရီ နှင့်အထက်) ကို ထောက်လှမ်းသည် — အလိုအလျောက် data exfiltration ပုံစံ |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | တစ်နာရီအတွင်း ကွဲပြားသော secret ၁၀ ခုနှင့်အထက် ရယူနေသော identity များကို ထောက်လှမ်းသည် — credential ရိတ်သိမ်းမှု အချက်ပြ |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | secret ဖျက်ခြင်း၊ PutResourcePolicy (cross-account မျှဝေခြင်း) နှင့် CancelRotateSecret တို့ကို ထောက်လှမ်းသည် |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | တစ်နာရီအတွင်း parameter ၂၀ နှင့်အထက် ဖတ်နေသော identity များကို ထောက်လှမ်းသည် — မကြာခဏ လျစ်လျူရှုခံရသော exfiltration channel |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | ပြင်ပ AWS account များသို့ မျှဝေထားသော RDS/Aurora snapshot များကို ထောက်လှမ်းသည် (snapshot မှတစ်ဆင့် database exfiltration) |
| 11 | 💣 RDS Deleted without Final Snapshot | — | skipFinalSnapshot=true ဖြင့် RDS ဖျက်ခြင်းကို ထောက်လှမ်းသည် — data ဖျက်ဆီးနိုင်ခြေ |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | publiclyAccessible=true ဖြင့် ဖန်တီး သို့မဟုတ် ပြုပြင်ထားသော RDS instance များကို ထောက်လှမ်းသည် |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | ExportTableToPointInTime (GetItem DLP ကို ကျော်ဖြတ်သော server-side full-table export)၊ DeleteTable နှင့် PITR ပိတ်ခြင်းတို့ကို ထောက်လှမ်းသည် |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | EBS Direct API (ListSnapshotBlocks / GetSnapshotBlock) ကို ထောက်လှမ်းသည် — Pacu ebs__download_snapshots သည် EC2 မလိုဘဲ raw snapshot data ကို stream လုပ်ပြီး ModifySnapshotAttribute ထောက်လှမ်းမှုကို ကျော်ဖြတ်သည် |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | ပြင်ပ S3 သို့ ညွှန်ပြသော Firehose delivery stream ဖန်တီးခြင်း/update လုပ်ခြင်းကို ထောက်လှမ်းသည် — network DLP သို့ မမြင်နိုင်သော real-time data pipeline |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | PutBucketReplication ကို ထောက်လှမ်းသည် — အပို GetObject event များ မထုတ်ပေးဘဲ object အသစ်အားလုံးကို တိုက်ခိုက်သူ ထိန်းချုပ်ထားသော bucket သို့ တိတ်တဆိတ် ကူးယူသည် |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | versioning ဆိုင်းငံ့ခြင်း (အမြဲတမ်း ဖျက်ခြင်းကို ဖွင့်ပေးသည်) နှင့် server-access logging ပိတ်ခြင်း (သက်သေ ခြေရာများကို ဖယ်ရှားသည်) တို့ကို ထောက်လှမ်းသည် |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | SES receipt rule နှင့် identity configuration ပြောင်းလဲမှုများကို ထောက်လှမ်းသည် — forwarding rule များသည် ဝင်လာသော mail အားလုံးကို တိုက်ခိုက်သူ၏ လိပ်စာများသို့ ပို့ပေးသည်၊ စိစစ်ထားသော identity များသည် phishing campaign များကို ဖွင့်ပေးသည် |
| 19 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | ပြင်ပ account များသို့ access ပေးသော SQS/SNS policy ပြောင်းလဲမှုများကို ထောက်လှမ်းသည် (တိုက်ခိုက်သူ endpoint များသို့ တိတ်တဆိတ် message stream ပို့ခြင်း) |
| 20 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | အများသူငှာ (group=all) မျှဝေထားသော EBS snapshot များ သို့မဟုတ် AMI များကို ထောက်လှမ်းသည် — မည်သူမဆို disk image များကို ကူးယူပြီး data ထုတ်ယူခွင့်ပေးသည် |
| 21 | 📧 Data Exfiltration Channels | bar | identity တစ်ခုတည်းမှ ပမာဏများသော SNS/SQS/SES/S3 PutObject call များ (၅၀/နာရီ နှင့်အထက်) ကို ထောက်လှမ်းသည် |

### ⚡ Compute & Serverless

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | တစ်နာရီအတွင်း StopInstances/TerminateInstances ၅ ခုနှင့်အထက် ပြုလုပ်နေသော identity များကို ထောက်လှမ်းသည် — ransomware / wiper ညွှန်ပြချက် |
| 2 | 🖥️ SSM Session / Run Command | timeseries | SSM StartSession, SendCommand နှင့် StartAutomationExecution ကို ထောက်လှမ်းသည် — managed instance များမှတစ်ဆင့် အဓိက lateral movement လမ်းကြောင်း |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | SendSSHPublicKey နှင့် SendSerialConsoleSSHPublicKey ကို ထောက်လှမ်းသည် — EC2 key pair များကို ကျော်ဖြတ်သည် (၆၀ စက္ကန့် တရားဝင်၊ SSH key artifact များ မချန်ထား) |
| 4 | 📝 EC2 User Data Modification | timeseries | userData ပြောင်းလဲမှုဖြင့် ModifyInstanceAttribute ကို ထောက်လှမ်းသည် — script သည် နောက်တစ်ကြိမ် boot တွင် root အဖြစ် run သည် |
| 5 | ⚡ Lambda Function Tampering | timeseries | Lambda ဖန်တီးခြင်း၊ code update (UpdateFunctionCode) နှင့် permission ပြောင်းလဲခြင်း (AddPermission) တို့ကို ထောက်လှမ်းသည် |
| 6 | 📦 Lambda Layer Addition | timeseries | Lambda layer ထုတ်ဝေခြင်း နှင့် wildcard principal ဖြင့် AddLayerVersionPermission ကို ထောက်လှမ်းသည် (အများသူငှာ supply-chain တိုက်ခိုက်မှု) |
| 7 | 📦 ECS Task Definition  | timeseries | RegisterTaskDefinition / UpdateService ကို ထောက်လှမ်းသည် — Pacu ecs__backdoor_task_def သည် ECR ကို မထိဘဲ အန္တရာယ်ရှိသော sidecar container တစ်ခုကို ထည့်သွင်းသည် |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | AssociateIamInstanceProfile / ReplaceIamInstanceProfileAssociation ကို ထောက်လှမ်းသည် — lateral movement ကို ဖွင့်ပေးသော privileged profile တစ်ခုကို ပူးတွဲသည် |
| 9 | 🖥 EC2 Instance Launches | timeseries | instance type, count, key name နှင့် AMI အပါအဝင် RunInstances event အားလုံးကို စာရင်းပြုစုသည် (cryptomining ထောက်လှမ်းခြင်း) |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | ကြီးမားသော Spot Fleet request (ec2) နှင့် capacity မြင့်မားသော Auto Scaling group ဖန်တီးခြင်း (autoscaling) ကို ထောက်လှမ်းသည် — cryptomining ဘဏ္ဍာရေး-သက်ရောက်မှု ညွှန်ပြချက် |
| 11 | ☸️ EKS Cluster API Calls | timeseries | EKS cluster control-plane ပြုပြင်မှုများ (public API server ဖော်ထုတ်ခြင်း၊ rogue Fargate profile များ) ကို ထောက်လှမ်းသည် |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | ECR repository/image event များကို ထောက်လှမ်းသည် (PutImage တွင် 'latest' tag တပ်ခြင်းသည် နောက်ဆက်တွဲ deployment အားလုံးကို အဆိပ်ထည့်သည်) |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | EventBridge rule နှင့် Scheduler ပြုပြင်မှုများ (PutRule, CreateSchedule) ကို ထောက်လှမ်းသည် — run နေသော process မရှိဘဲ persistence ကို တည်ဆောက်သည် |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | Lightsail key ရယူခြင်း၊ port ဖော်ထုတ်ခြင်း နှင့် instance access တို့ကို ထောက်လှမ်းသည် — Pacu lightsail__download_ssh_keys / lightsail__generate_temp_access |

### 🌐 Network & Infrastructure

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🌍 Security Group Opened to Internet | timeseries | 0.0.0.0/0 မှ traffic ကို ခွင့်ပြုသော security group rule များကို ရှာဖွေသည် — တိုက်ရိုက် အများသူငှာ ဖော်ထုတ်ခံရမှု အန္တရာယ် |
| 2 | 🔥 Security Group Modifications | timeseries | security group rule ပြောင်းလဲမှုအားလုံး (AuthorizeSecurityGroupIngress, ModifySecurityGroupRules စသည်) ကို ထောက်လှမ်းသည် |
| 3 | 🌊 VPC Flow Log Changes | timeseries | VPC Flow Log များ ဖျက်ခြင်းကို ထောက်လှမ်းသည် — flow log များ ဖယ်ရှားခြင်းသည် အဓိက network forensic သက်သေအထောက်အထားကို ဖျောက်ဖျက်သည် |
| 4 | 🌐 CloudFront Distribution Tampering | timeseries | CDN traffic အားလုံးကို တိုက်ခိုက်သူ ထိန်းချုပ်ထားသော server များသို့ redirect လုပ်သော CloudFront origin ပြောင်းလဲမှုများကို ထောက်လှမ်းသည် (MitM) |
| 5 | 🛡 Network Firewall / Shield Tampering | timeseries | Network Firewall နှင့် Shield protection ဖယ်ရှားခြင်းကို ထောက်လှမ်းသည် — subnet အကွာအဝေးတစ်ခုလုံးကို တိုက်ခိုက်မှု traffic သို့ ဖော်ထုတ်သည် |
| 6 | 🧱 Network ACL Changes | timeseries | NACL entry ဖန်တီးခြင်း၊ ဖျက်ခြင်း နှင့် အစားထိုးခြင်းတို့ကို ထောက်လှမ်းသည် — NACL များသည် subnet အဆင့်တွင် security group များကို override လုပ်သည် |
| 7 | 🛣️ Route Table Changes | timeseries | route table ပြုပြင်မှုများကို ထောက်လှမ်းသည် — တိုက်ခိုက်သူများသည် ကြားဖြတ်ဖမ်းယူခြင်း သို့မဟုတ် C2 အတွက် traffic ကို အန္တရာယ်ရှိသော gateway များသို့ redirect လုပ်သည် |
| 8 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | VPN connection အသစ်များ နှင့် Transit Gateway attachment များကို ထောက်လှမ်းသည် — C2 သို့မဟုတ် exfiltration အတွက် တည်မြဲသော Layer-3 network လမ်းကြောင်းများကို ဖန်တီးသည် |
| 9 | 📡 Elastic IP Allocation / Association | timeseries | Elastic IP allocation/association ကို ထောက်လှမ်းသည် — တည်ငြိမ်သော C2 အခြေခံအဆောက်အအုံအတွက် အပေးယူခံရသော instance များသို့ ပုံသေ public IP တစ်ခုကို သတ်မှတ်ပေးသည် |
| 10 | 🗝️ EC2 Key Pair Creation | timeseries | CreateKeyPair နှင့် ImportKeyPair ကို ထောက်လှမ်းသည် — တိုက်ခိုက်သူသည် တည်မြဲသော instance access အတွက် SSH key များ ဖန်တီးသည် |
| 11 | 📡 Network Infrastructure Changes | timeseries | တိုက်ခိုက်သူ ထိန်းချုပ်ထားသော အခြေခံအဆောက်အအုံကို တည်ဆောက်နိုင်သော VPC / subnet / IGW / NAT Gateway / peering ပြောင်းလဲမှုများကို ထောက်လှမ်းသည် |
| 12 | 🏷 ACM Certificate Operations | timeseries | ACM certificate တောင်းဆိုခြင်းနှင့် ဖျက်ခြင်းတို့ကို ထောက်လှမ်းသည် — အပေးယူခံရသော account များသည် phishing domain များအတွက် TLS cert များ ထုတ်ပေးနိုင်သည် |
| 13 | 🔑 API Gateway Key Creation & Management | timeseries | API Gateway key ဖန်တီးခြင်း နှင့် authorizer ပြောင်းလဲမှုများကို ထောက်လှမ်းသည် — Pacu api_gateway__create_api_keys သည် IAM key rotation ကို ရှင်သန်နိုင်သော တည်မြဲသော credential များ ဖန်တီးသည် |
| 14 | 🚧 VPC Endpoint Access Denied | timeseries | VPC endpoint များမှတစ်ဆင့် access denied error များကို ထောက်လှမ်းသည် — မှားယွင်းစွာ ပြင်ဆင်ထားသော endpoint policy ကို ညွှန်ပြနိုင်သည် |

### 🕵 Threat Patterns

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | တစ်နာရီအတွင်း ကွဲပြားသော Describe*/List*/Get* API ၁၀ ခုနှင့်အထက် run ခဲ့သော caller များကို ဖော်ထုတ်သည် — တိုက်ခိုက်မှု၏ အစောပိုင်း အဆင့် |
| 2 | 🤖 Unusual User Agents | bar | ရှားပါးသော user agent များ (event ၅ ခုအောက်) သို့မဟုတ် လူသိများသော တိုက်ခိုက်သူ tool များ (Pacu, curl, wget) ကို စာရင်းပြုစုသည် — တိုက်ခိုက်မှု tooling ကို ညွှန်ပြနိုင်သည် |
| 3 | 🌍 Multi-Region Activity | bar | တစ်ရက်အတွင်း region ၃ ခုနှင့်အထက်တွင် ရေးသားမှု ပြုလုပ်နေသော identity များကို ထောက်လှမ်းသည် — ပထဝီဝင် ပျံ့နှံ့မှုသည် အပေးယူခံရခြင်းကို ညွှန်ပြနိုင်သည် |
| 4 | 🕵 First-Time API Calls (24h) | — | နောက်ဆုံး ၂၄ နာရီအတွင်း တွေ့ရှိသော်လည်း ယခင်က ဘယ်တုန်းကမှ မတွေ့ဖူးသော API call များကို ရှာဖွေသည် — အသစ်အဆန်း operation များသည် တိုက်ခိုက်သူ tooling ကို ညွှန်ပြနိုင်သည် |

### 📊 Activity & Baseline

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | AWS console မှတစ်ဆင့် ပြုလုပ်သော ပြောင်းလဲစေသော API call များကို ဖော်ထုတ်သည် — CLI-only access ကို မျှော်လင့်ထားသည့်အခါ အသုံးဝင်သည် |
| 2 | 🔍 Events with Errors (24h) | timeseries | လွန်ခဲ့သော ၂၄ နာရီအတွင်း error event အားလုံးကို စာရင်းပြုစုသည် — ဘာတွေ ကျရှုံးနေသလဲ သို့မဟုတ် စမ်းသပ်ခံနေရသလဲ ဆိုသည်ကို လျင်မြန်စွာ ခြုံငုံကြည့်ရှုနိုင်သည် |
| 3 | ❌ Error Spike Detection | — | error အရေအတွက်သည် နေ့စဉ်ပျမ်းမျှထက် ၃ ဆ ကျော်လွန်သော ၁-နာရီ window များကို ရှာဖွေသည် |

### 🌍 GeoIP Analysis

> ဖြည့်စွက်ရန် GeoLite2 `.mmdb` file များ လိုအပ်သည် (GeoIP မပါဘဲ ingest လုပ်ပါက column များသည် NULL ဖြစ်သည်)။

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🕵 Impossible Travel Detection | — | တူညီသော identity တစ်ခုသည် ၂ နာရီအတွင်း ဝေးကွာသော မြို့များမှ API များ ခေါ်ဆိုနေခြင်းကို ထောက်လှမ်းသည် — ခိုင်မာသော credential အပေးယူခံရခြင်း ညွှန်ပြချက် |
| 2 | ⚠ Identity Multi-Country Access | bar | နိုင်ငံ ၂ ခုနှင့်အထက်မှ API call များ ပြုလုပ်နေသော identity များကို ရှာဖွေသည် — တရားဝင် user များသည် နိုင်ငံအများအပြားမှ တစ်ပြိုင်နက် ဆောင်ရွက်ခြင်း ရှားပါးသည် |
| 3 | 🗺 Console Logins by Country | timeseries | console login event များကို ၎င်းတို့၏ ပထဝီဝင် မူရင်းနေရာသို့ ချိတ်ဆက်ပြသည် — မမျှော်လင့်သော နိုင်ငံများမှ login များသည် အန္တရာယ်များသည် |
| 4 | 🚨 Unusual Country Access | bar | ရှားပါးသော country/identity ပေါင်းစပ်မှုများ (event ၁၀ ခုအောက်) ကို ထောက်လှမ်းသည် — ပမာဏနည်းသော နိုင်ငံခြား access သည် တိုက်ခိုက်သူ၏ အခြေခံအဆောက်အအုံ ဖြစ်နိုင်သည် |
| 5 | 🚫 Access Denied by Country | bar | access denied error များကို source country အလိုက် အုပ်စုဖွဲ့သည် — နိုင်ငံတစ်ခုမှ စုစည်းထားသော denial များသည် တိုက်ခိုက်မှုကို အချက်ပြနိုင်သည် |
| 6 | 🔍 Write Events by Country | bar | ပြောင်းလဲစေသော API call များကို source country အလိုက် အုပ်စုဖွဲ့ ပြသည် — မမျှော်လင့်သော နိုင်ငံများမှ ရေးသားမှုများသည် ဖတ်ခြင်းထက် ပိုမိုခိုင်မာသော အချက်ပြ ဖြစ်သည် |
| 7 | 🌍 Top Source Countries | bar | source country များကို API call ပမာဏအလိုက် ရေးသား-event နှင့် ထူးခြားသော-identity ခွဲခြမ်းမှုများဖြင့် အဆင့်သတ်မှတ်သည် |
| 8 | 🏢 Top ASN / Organizations | bar | autonomous system များ (ISP/cloud provider) ကို API call ပမာဏအလိုက် စာရင်းပြုစုသည် — VPN/hosting ASN များသည် တိုက်ခိုက်သူ၏ အခြေခံအဆောက်အအုံကို ညွှန်ပြနိုင်သည် |
| 9 | 📍 Top Source Cities | bar | source city များကို event ပမာဏအလိုက် အဆင့်သတ်မှတ်သည် — city-အဆင့် data သည် တိကျသော တိုက်ခိုက်သူ အခြေခံအဆောက်အအုံ သို့မဟုတ် ရုံးတည်နေရာများကို တိတိကျကျ ဖော်ပြသည် |
| 10 | 🌐 Private / Internal IP Summary | bar | private/loopback/AWS-internal IP များမှ event များကို အကျဉ်းချုပ်သည် — မျှော်လင့်ထားသော internal traffic အတွက် baseline |
| 11 | 📋 API Calls by Country (Event Name) | table | call ပမာဏအလိုက် ထိပ်တန်း (event_name, country) တွဲများ — မမျှော်လင့်သော ပထဝီဝင် ဒေသများမှ မည်သည့် API operation များ စတင်လာသည်ကို ဖော်ထုတ်သည် |
| 12 | 👤 Identities by Country (user_identity_arn) | table | call ပမာဏအလိုက် ထိပ်တန်း (user_identity_arn, country) တွဲများ — first/last seen ဖြင့် မမျှော်လင့်သော နိုင်ငံများမှ active ဖြစ်နေသော IAM identity များကို ဖော်ထုတ်သည် |

### ☁ IaC & Platform

| # | Label | Chart | Description |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | CI/CD pipeline ဖန်တီးခြင်းနှင့် ပြုပြင်ခြင်းကို ထောက်လှမ်းသည် (UpdateProject သည် နောက်ဆက်တွဲ build တိုင်းတွင် အန္တရာယ်ရှိသော build step များ ထည့်သွင်းသည်) |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | CloudFormation stack operation များကို ထောက်လှမ်းသည် — တိုက်ခိုက်သူများသည် အန္တရာယ်ရှိသော အခြေခံအဆောက်အအုံကို လျင်မြန်စွာ deploy လုပ်ရန် IaC ကို အသုံးပြုနိုင်သည် |

</details>

---

## 📊 Dashboard Charts — chart 80+ ခု

| Tab | Charts | What It Shows |
|-----|:------:|---------------|
| 🔑 Identity & Access | 9 | Console logins · MFA trend · login heatmap · sensitive APIs · root usage · IAM entity activity · privilege escalation · SSO/privesc |
| 🎯 Threat Detection | 12 | Event volume · read/write ratio · defense evasion · access denied · error trend · SCP/Config/NACL/EventBridge tampering |
| 📊 API Activity | 7 | Top APIs · region distribution · source IPs · user agents · secrets anomaly · external AssumeRole · Route53 changes |
| 🖥️ Computing | 5 | SSM execution · EC2 public snapshot · EKS/ECR events · ECS backdoor · EBS Direct API exfiltration |
| 🪣 S3 & RDS | 9 | S3 policy/ACL · bulk download/deletion · versioning/logging disabled · cross-account replication · RDS snapshot share · Backup tampering |
| 🌍 GeoIP Intelligence | 6 | World map · request ပမာဏအလိုက် ထိပ်တန်း countries / cities / ASNs · event_name × country · identity × country |
| 🕒 Temporal Analysis | 6 | First/last seen by identity/IP/API/agent · dormant accounts reactivated · velocity spikes |
| 🚨 High-Risk API Monitor | 7 | HRM time series · top calls/actors/IPs · defense evasion/credential detail · by region |

<details markdown="1">
<summary>📋 စာရင်းအပြည့်အစုံ — chart 80+ ခုလုံး (ချဲ့ရန် နှိပ်ပါ)</summary>

## Dashboard Charts (Apache Superset — `dashboard/`)

### 🔑 Identity & Access

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | Console Login Activity | IAM identity အလိုက် အုပ်စုဖွဲ့ထားသော console sign-in event များ (DSH-08) |
| 2 | MFA-less Login Trend | MFA အသုံးပြုမှုအလိုက် ခွဲထားသော နေ့စဉ် console login များ (DSH-28) |
| 3 | Login Activity Heatmap (Hour × Day) | JST တွင် day-of-week နှင့် hour-of-day အလိုက် console login အရေအတွက်များ (DSH-19) |
| 4 | Sensitive API Calls | လူသိများသော security-အရေးကြီးသည့် AWS API action များ၏ ခေါ်ဆိုမှုများ (DSH-12) |
| 5 | Root Account Usage | AWS Root account က ပြုလုပ်သော API call အားလုံး (DSH-13) |
| 6 | IAM Entity Activity | စုစုပေါင်း API call အလိုက် အဆင့်သတ်မှတ်ထားသော ထိပ်တန်း IAM entity ၅၀၊ write ratio နှင့် error rate ဖြင့် |
| 7 | Privilege Escalation Timeline | event name အလိုက် privilege-escalation API call များ၏ နေ့စဉ် အရေအတွက်များ (DSH-30) |
| 8 | IAM Identity Center (SSO) Events | sso.amazonaws.com မှ AWS IAM Identity Center management event များ (DSH-44) |
| 9 | Glue & SageMaker Privilege Escalation | iam:PassRole မှတစ်ဆင့် IAM privilege escalation အတွက် အသုံးပြုသော Glue DevEndpoint နှင့် SageMaker Notebook event များ (DSH-50) |

### 🎯 Threat Detection

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | CloudTrail Events Over Time | အချိန်အလိုက် နာရီအလိုက် Read နှင့် Write event ပမာဏ (DSH-01) |
| 2 | Write/Read Ratio Trend | read နှင့် write API call များ၏ နာရီအလိုက် ခွဲခြမ်းမှု (DSH-20) |
| 3 | Throttling Exception Spikes | AWS service အလိုက် နာရီအလိုက် throttling/rate-limit error များ (DSH-21) |
| 4 | Defense Evasion Events | လူသိများသော defense-evasion technique များနှင့် ကိုက်ညီသော CloudTrail event အားလုံး (DSH-22) |
| 5 | Top Access Denied Actions | AccessDenied error များ ပြန်ပေးသော ထိပ်တန်း API action ၂၀ (DSH-09) |
| 6 | Error Event Trend | error_code အလိုက် ခွဲခြားထားသော နာရီအလိုက် error event များ (DSH-04) |
| 7 | Organizations / SCP Changes | SCP policy ပြောင်းလဲမှုများ အပါအဝင် AWS Organizations management event များ (DSH-24) |
| 8 | First-Time Service Sources | ပထမဆုံး ပေါ်ထွန်းသည့်ရက်အလိုက် စီထားသော ကွဲပြားသော AWS service source အားလုံး (DSH-26) |
| 9 | VPC Flow Log Changes | VPC Flow Log ဖန်တီးခြင်းနှင့် ဖျက်ခြင်း event များ (DSH-42) |
| 10 | AWS Config Tampering | AWS Config recorder နှင့် rule tampering event များ (DSH-43) |
| 11 | Network ACL / Route Table Changes | NACL နှင့် route table ပြုပြင်မှု event များ (DSH-46) |
| 12 | EventBridge / CloudWatch Rule Tampering | EventBridge နှင့် CloudWatch Events rule tampering (DSH-47) |

### 📊 API Activity

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | Top 20 API Calls | အများဆုံး ခေါ်ဆိုသော AWS API action ၂၀ (DSH-02) |
| 2 | Region Activity | AWS region များတစ်လျှောက် CloudTrail event များ၏ ဖြန့်ဝေမှု (DSH-14) |
| 3 | Top Source IP Addresses | request count အလိုက် ထိပ်တန်း external source IP ၁၀၀ (DSH-05) |
| 4 | User Agent Analysis | error နှင့် write ခွဲခြမ်းမှုများဖြင့် request count အလိုက် ထိပ်တန်း user agent ၅၀ (DSH-11) |
| 5 | Secrets Access Anomaly | တစ်နာရီအတွင်း Secrets Manager သို့မဟုတ် SSM Parameter Store ကို ၁၀ ကြိမ်နှင့်အထက် access လုပ်နေသော identity များ |
| 6 | AssumedRole from External IP | public (non-private) IP address များမှ AssumeRole call များ (DSH-27) |
| 7 | Route53 DNS Changes | Route 53 hosted-zone နှင့် resolver configuration ပြောင်းလဲမှုများ (DSH-29) |

### 🖥️ Computing

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | SSM Session / Run Command Execution | AWS Systems Manager remote-execution event များ (DSH-39) |
| 2 | EC2 Public Snapshot / AMI Sharing | EBS snapshot နှင့် AMI public-sharing event များ (DSH-41) |
| 3 | EKS / ECR Container Platform Events | EKS cluster နှင့် ECR container registry event များ (DSH-48) |
| 4 | ECS Task Definition | ECS task definition မှတ်ပုံတင်ခြင်း နှင့် service update event များ — Pacu ecs__backdoor_task_def ပုံစံ (DSH-49) |
| 5 | EBS Direct API Snapshot Exfiltration | EC2 မလိုဘဲ snapshot data ကို stream လုပ်ရန် အသုံးပြုသော EBS Direct API call များ (ListSnapshotBlocks / GetSnapshotBlock) (DSH-51) |

### 🪣 S3 & RDS

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | S3 Protection Config Changes | bucket security အနေအထားကို အားနည်းစေသော S3 event များ (DSH-25) |
| 2 | S3 Bucket Policy / ACL Changes | S3 bucket policy နှင့် ACL ပြုပြင်မှု event များ (DSH-45) |
| 3 | RDS Snapshot Cross-Account Share | RDS နှင့် Aurora snapshot မျှဝေခြင်း event များ (DSH-40) |
| 4 | S3 Bulk Download | တစ်နာရီလျှင် GetObject call ၁၀၀ နှင့်အထက် ပြုလုပ်နေသော identity များ — အလိုအလျောက် data exfiltration ပုံစံ (DSH-52) |
| 5 | S3 Bulk Object Deletion | တစ်နာရီလျှင် DeleteObject/DeleteObjects call ၅၀ နှင့်အထက် ပြုလုပ်နေသော identity များ — ransomware data ဖျက်ဆီးမှု ပုံစံ (DSH-53) |
| 6 | S3 Versioning / Logging Disabled | PutBucketVersioning (Suspended) နှင့် PutBucketLogging (disabled) — data ဖျက်ဆီးမှု၏ ရှေ့ပြေး anti-forensics (DSH-54) |
| 7 | S3 Cross-Account Replication | PutBucketReplication / DeleteBucketReplication — တိုက်ခိုက်သူ ထိန်းချုပ်ထားသော account သို့ တည်မြဲ တိတ်တဆိတ် exfiltration channel (DSH-55) |
| 8 | RDS Deleted without Final Snapshot | skipFinalSnapshot=true ဖြင့် DeleteDBInstance / DeleteDBCluster — ပြန်လည်ရယူ၍မရသော data ဖျက်ဆီးမှု (DSH-56) |
| 9 | AWS Backup Tampering | Backup Vault / Plan / RecoveryPoint ဖျက်ခြင်း နှင့် Vault Lock ဖယ်ရှားခြင်း — ပြန်လည်ရယူရေး ရွေးချယ်စရာများကို ဖျောက်ဖျက်ရန် ransomware ၏ ပထမဆုံးခြေလှမ်း (DSH-57) |

### 🌍 GeoIP Intelligence

> GeoLite2 `.mmdb` file များ လိုအပ်သည်။ GeoIP မပါဘဲ ingest လုပ်ပါက GeoIP column များသည် NULL ဖြစ်သည်။

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | Global Request Origin Map | CloudTrail API call မူရင်းနေရာများ၏ ပထဝီဝင် ဖြန့်ဝေမှုကို ပြသသော World map |
| 2 | Top Countries by Request Volume | write-event နှင့် ထူးခြားသော-caller ခွဲခြမ်းမှုများဖြင့် API call ပမာဏအလိုက် ထိပ်တန်း source country ၂၀ |
| 3 | Top Cities by Request Volume | write-event နှင့် ထူးခြားသော-caller ခွဲခြမ်းမှုများဖြင့် API call ပမာဏအလိုက် ထိပ်တန်း city ၂၅ |
| 4 | Top ASN Organizations by Request Volume | API call ပမာဏအလိုက် ထိပ်တန်း ASN organization ၂၅ |
| 5 | API Calls by Country (Event Name × GeoIP) | ထိပ်တန်း (event_name, country) တွဲ ၅၀ — ပထဝီဝင် ဒေသတစ်ခုစီမှ မည်သည့် API operation များ ခေါ်ဆိုသည်ကို ဖော်ထုတ်သည် (DSH-79) |
| 6 | Identities by Country (user_identity_arn × GeoIP) | ထိပ်တန်း (user_identity_arn, country) တွဲ ၅၀ — write count နှင့် first/last seen ဖြင့် မမျှော်လင့်သော နိုင်ငံများမှ active ဖြစ်နေသော IAM identity များကို ဖော်ထုတ်သည် (DSH-80) |

### 🕒 Temporal Analysis

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | First / Last Seen per IAM Identity | first/last seen timestamp၊ event count နှင့် ကွဲပြားသော API များ ပါသော IAM identity များ |
| 2 | First / Last Seen per Source IP | first/last seen၊ ကွဲပြားသော identity များ နှင့် ကွဲပြားသော API များ ပါသော source IP များ |
| 3 | First / Last Seen per API Call | ပထမဆုံး ပေါ်ထွန်းမှုအလိုက် စီထားသော API action များ — call အသစ်များသည် အသစ်အဆန်း တိုက်ခိုက်မှု tooling ကို ညွှန်ပြနိုင်သည် (DSH-33) |
| 4 | First / Last Seen per User Agent | ပထမဆုံး ပေါ်ထွန်းမှုအလိုက် စီထားသော user agent များ — tooling အသစ် ထောက်လှမ်းခြင်း (DSH-34) |
| 5 | Dormant Accounts Reactivated | ၇၂ နာရီနှင့်အထက် မလှုပ်ရှားသော ကွာဟမှုများရှိပြီး activity ပြန်စတင်ခဲ့သော identity များ (DSH-37) |
| 6 | Event Velocity Spikes per Identity | တစ်နာရီလျှင် event ၅၀ နှင့်အထက် burst activity ရှိသော identity များ (DSH-38) |

### 🚨 High-Risk API Monitor (HRM)

| # | Chart Name | Description |
|---|------------|-------------|
| 1 | High-Risk API Events Over Time | တိုက်ခိုက်မှု campaign များတွင် အများအားဖြင့် တွေ့ရှိရသော API များ၏ နေ့စဉ် call ပမာဏ (HRM-39) |
| 2 | Top High-Risk API Calls | စုစုပေါင်း call count အလိုက် အဆင့်သတ်မှတ်ထားသော high-risk watchlist မှ API action များ (HRM-40) |
| 3 | Top Actors — High-Risk APIs | high-risk watchlist API များသို့ စုစုပေါင်း call အလိုက် အဆင့်သတ်မှတ်ထားသော IAM principal များ (HRM-42) |
| 4 | Top Source IPs — High-Risk APIs | high-risk watchlist API များသို့ စုစုပေါင်း call အလိုက် အဆင့်သတ်မှတ်ထားသော source IP များ (HRM-43) |
| 5 | Defense Evasion API Events | audit control များကို ပိတ်ရန် သို့မဟုတ် tamper လုပ်ရန် အသုံးပြုသော API များအတွက် အသေးစိတ် event log (HRM-44) |
| 6 | Credential Access API Events | secret နှင့် credential များ ရယူရန် အသုံးပြုသော API များအတွက် အသေးစိတ် event log (HRM-45) |
| 7 | High-Risk API Calls by Region | AWS region အလိုက် ဖြန့်ဝေထားသော high-risk watchlist API call များ (HRM-46) |

</details>

---
