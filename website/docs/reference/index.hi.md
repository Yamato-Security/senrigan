# बिल्ट-इन क्वेरी और डैशबोर्ड संदर्भ

> 💡 किसी SQL या गहन AWS ज्ञान की आवश्यकता नहीं — बस ड्रॉपडाउन से एक hunt चुनें और तुरंत परिणाम प्राप्त करें।

## 🎯 बिल्ट-इन Hunts — 100+ क्वेरीज़

श्रेणियाँ DFIR triage प्राथमिकता के अनुसार क्रमबद्ध हैं — पहले डिटेक्शन-टूल छेड़छाड़ की जाँच करें, फिर पहचान दुरुपयोग, फिर डेटा प्रभाव।

| श्रेणी | क्वेरीज़ | कवर किए गए प्रमुख खतरे |
|----------|:-------:|---------------------|
| 🛡 Detection & Response | 12 | ऑडिट-सेवा छेड़छाड़ (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · SCP विलोपन · अलार्म दमन · लॉग एक्सफिल्ट्रेशन |
| 🔑 Identity & Access | 26 | Root उपयोग · console लॉगिन/MFA · विशेषाधिकार वृद्धि · trust policy बैकडोर · PassRole दुरुपयोग · cross-account AssumeRole · SSO/SAML/OIDC · क्रेडेंशियल गणना |
| 🪣 Data & Storage | 21 | S3 बल्क विलोपन/डाउनलोड · secrets बल्क रीड · backup छेड़छाड़ · KMS ops · snapshot साझाकरण · EBS Direct API एक्सफिल्ट्रेशन · DynamoDB export · S3 cross-account replication |
| ⚡ Compute & Serverless | 14 | EC2 मास stop/terminate · SSM लेटरल मूवमेंट · Lambda/ECS/EKS/ECR छेड़छाड़ · EventBridge परसिस्टेंस · cryptomining · Lightsail दुरुपयोग |
| 🌐 Network & Infrastructure | 14 | SG इंटरनेट के लिए खुला · VPC flow log विलोपन · CloudFront हाइजैक · गुप्त VPN/TGW टनल · Elastic IP C2 · API Gateway keys |
| 🕵 Threat Patterns | 5 | ऑफ-ऑवर्स राइट्स · recon बर्स्ट · multi-region प्रसार · असामान्य user agents · पहली-बार API कॉल |
| 📊 Activity & Baseline | 3 | Console राइट इवेंट · error स्पाइक्स · हाल की errors |
| 🌍 GeoIP Analysis ✦ | 12 | असंभव यात्रा · multi-country क्रेडेंशियल · geo-ranked लॉगिन/denials/राइट्स · country/city/ASN विभाजन · event_name × country · identity × country |
| ☁ IaC & Platform | 2 | CI/CD आपूर्ति श्रृंखला · CloudFormation दुरुपयोग |

<details markdown="1">
<summary>📋 पूरी सूची — सभी 100+ क्वेरीज़ (विस्तृत करने के लिए क्लिक करें)</summary>

## बिल्ट-इन Hunts

### 🛡 Detection & Response

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | CloudTrail को रोकने या संशोधित करने के किसी भी प्रयास का पता लगाता है — सबसे महत्वपूर्ण कवर-अप संकेतक |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | GuardDuty disable, delete, और threat-intel हेरफेर का पता लगाता है |
| 3 | ⛔ Security Hub Tampering | timeseries | Security Hub disable, standard disable, और finding दमन का पता लगाता है |
| 4 | ⚙️ AWS Config Tampering | timeseries | AWS Config recorder/rule विलोपन का पता लगाता है (अनुपालन साक्ष्य समाप्त करता है) |
| 5 | 🛡 Organizations SCP Changes | timeseries | SCP निर्माण, अद्यतन, और विलोपन का पता लगाता है — Deny SCP हटाने से OU के प्रत्येक account में guardrails समाप्त हो जाते हैं |
| 6 | 🚫 AWS Macie Tampering | timeseries | Macie disable और finding-filter निर्माण का पता लगाता है (पूर्व-एक्सफिल्ट्रेशन बचाव चोरी) |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | अलार्म विलोपन और DisableAlarmActions का पता लगाता है — अलार्म हटाए बिना सुरक्षा अलर्टिंग को मौन कर देता है |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | CW Logs subscription filter निर्माण/विलोपन का पता लगाता है (हमलावर Kinesis/Lambda में रियल-टाइम लॉग एक्सफिल्ट्रेशन) |
| 9 | 🏹 WAF WebACL Changes | timeseries | WAFv2/WAF Classic में WAF WebACL निर्माण, अद्यतन, और विलोपन का पता लगाता है |
| 10 | 🔍 GuardDuty Findings Read | timeseries | ListFindings / GetFindings का पता लगाता है — हमलावर सक्रिय findings पढ़कर समझता है कि SOC ने पहले से क्या पता लगाया है |
| 11 | 💰 Budget / Cost Anomaly Changes | timeseries | Budget/AnomalyMonitor विलोपन का पता लगाता है (cryptomining लागत छिपाना) |
| 12 | 🚫 Access Denied Errors | bar | AccessDenied errors को identity और API द्वारा समूहित करता है — शीर्ष अपराधी क्रेडेंशियल दुरुपयोग का संकेत देते हैं |

### 🔑 Identity & Access

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | root account द्वारा की गई किसी भी API कॉल का पता लगाता है — production में root का कभी उपयोग नहीं करना चाहिए |
| 2 | 🔓 Console Login without MFA | timeseries | उन console लॉगिन का पता लगाता है जहाँ MFA का उपयोग नहीं किया गया — account समझौते का उच्च-जोखिम संकेतक |
| 3 | 🌐 Console Logins | timeseries | सफलता और विफलता सहित सभी console लॉगिन प्रयासों को सूचीबद्ध करता है (brute force डिटेक्शन) |
| 4 | 🔐 MFA & Password Changes | timeseries | MFA निष्क्रियकरण और password रीसेट का पता लगाता है — account टेकओवर का मजबूत संकेतक |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | IAM policy attachment और role हेरफेर का पता लगाता है (PutUserPolicy, AttachRolePolicy, CreatePolicyVersion, आदि) |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | UpdateAssumeRolePolicy का पता लगाता है — trust policy में बाहरी principals जोड़ने से एक स्थायी बैकडोर बनता है |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | permission boundary put/delete इवेंट का पता लगाता है — boundary हटाने से प्रभावी permissions तुरंत विस्तृत हो जाते हैं |
| 8 | 👑 User Added to Admin Group | timeseries | नाम में 'admin' वाले groups में जोड़े गए users का पता लगाता है — क्लासिक विशेषाधिकार वृद्धि |
| 9 | 👥 IAM Group Membership Changes | timeseries | group नाम की परवाह किए बिना सभी AddUserToGroup / RemoveUserFromGroup / CreateGroup / DeleteGroup इवेंट का पता लगाता है |
| 10 | 👤 New IAM Users / Keys | timeseries | IAM user और access key निर्माण इवेंट की पहचान करता है — अप्रत्याशित निर्माण परसिस्टेंस का संकेत दे सकता है |
| 11 | 🎯 IAM PassRole Abuse | timeseries | प्राप्तकर्ता-सेवा इवेंट (RunInstances, CreateFunction, CreateNotebookInstance, आदि) का निरीक्षण करके iam:PassRole उपयोग का पता लगाता है जहाँ एक role ARN पास किया जाता है |
| 12 | 🔐 AssumeRole Cross-Account | timeseries | वे AssumeRole इवेंट दिखाता है जहाँ caller और target विभिन्न AWS accounts में हैं (लेटरल मूवमेंट) |
| 13 | 🏢 Cross-Account Access | timeseries | वे सभी इवेंट खोजता है जहाँ caller account प्राप्तकर्ता account से भिन्न है |
| 14 | 🔑 STS Federation Token Issuance | timeseries | GetFederationToken और GetSessionToken का पता लगाता है — दीर्घकालिक keys को स्थायी अस्थायी क्रेडेंशियल में बदल देता है |
| 15 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | OIDC trust दुरुपयोग का पता लगाता है (गलत-कॉन्फ़िगर sub claim / repo शर्त के बिना GitHub Actions) |
| 16 | 🆔 IAM Identity Center (SSO) Events | timeseries | AWS IAM Identity Center प्रबंधन क्रियाओं का पता लगाता है (CreatePermissionSet, CreateAccountAssignment, आदि) |
| 17 | 🔗 SAML / OIDC Provider Updates | timeseries | SAML/OIDC identity provider परिवर्तनों का पता लगाता है — हमलावर-नियंत्रित IdP के साथ SAML metadata अद्यतन करने से एक स्थायी प्रमाणीकरण बैकडोर बनता है |
| 18 | 🧐 IAM Access Analyzer Calls | timeseries | IAM Access Analyzer के किसी भी उपयोग का पता लगाता है — हमलावर कस्टम recon स्क्रिप्ट के बिना बाहरी रूप से सुलभ संसाधनों की गणना करने के लिए नेटिव analyzer का लाभ उठाते हैं |
| 19 | 🔄 Credential Report & Enumeration | timeseries | IAM गणना का पता लगाता है (GenerateCredentialReport, ListUsers, ListRoles, GetAccountAuthorizationDetails, आदि) |
| 20 | 🗝 Access Key Abuse | bar | 7 दिनों में 3+ अलग source IPs से उपयोग की गई access keys का पता लगाता है — key लीक का मजबूत संकेतक |
| 21 | 📰 AWS Organizations Account Creation | timeseries | Organizations account निर्माण और प्रत्यायोजित administrator परिवर्तनों का पता लगाता है (शैडो account परसिस्टेंस) |
| 22 | 👥 Cognito Unauthenticated Access | timeseries | allowUnauthenticatedIdentities=true वाले Cognito Identity Pools का पता लगाता है |
| 23 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | Glue DevEndpoint निर्माण (iam:PassRole + glue:CreateDevEndpoint = पास किए गए role की पूर्ण permissions के साथ चलने वाला SSH-सुलभ endpoint) और क्रेडेंशियल संग्रह के लिए connection गणना का पता लगाता है |
| 24 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | SageMaker notebook निर्माण और presigned URL जनरेशन का पता लगाता है — iam:PassRole + sagemaker:CreateNotebookInstance पास किए गए role की पूर्ण AWS permissions के साथ एक Jupyter वातावरण लॉन्च करता है |
| 25 | 🛠 Data Pipeline / CodeStar Privilege Escalation | timeseries | iam:PassRole वृद्धि के लिए उपयोग किए जाने वाले Data Pipeline और CodeStar संसाधन निर्माण का पता लगाता है (CreateProjectFromTemplate एक साइड इफेक्ट के रूप में एक admin IAM role बनाता है) |
| 26 | 🧩 Step Functions Privilege Escalation | timeseries | Step Functions state machine निर्माण का पता लगाता है (iam:PassRole + states:CreateStateMachine पास किए गए role के तहत Lambda/ECS कार्यों को निष्पादित करता है) |

### 🪣 Data & Storage

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | प्रति घंटे ≥50 DeleteObject/DeleteObjects कॉल करने वाली identities का पता लगाता है — ransomware / wiper डेटा विनाश पैटर्न |
| 2 | 🔥 AWS Backup Tampering | timeseries | Backup Vault / Plan / RecoveryPoint विलोपन और Vault Lock हटाने का पता लगाता है — रिकवरी विकल्पों को समाप्त करने के लिए ransomware का पहला कदम |
| 3 | 🔓 KMS Key Operations | timeseries | संवेदनशील KMS संचालन को फ़्लैग करता है (DisableKey, ScheduleKeyDeletion, CreateGrant, PutKeyPolicy, उच्च-वॉल्यूम Decrypt) |
| 4 | 🔓 S3 Public Access Block Disabled | — | S3 public access block सेटिंग्स को disable किए जाने का पता लगाता है — तत्काल डेटा एक्सपोज़र जोखिम |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | S3 bucket policy और ACL संशोधनों का पता लगाता है (Principal='*' के साथ PutBucketPolicy विशेष रूप से महत्वपूर्ण है) |
| 6 | 🪣 S3 Data Access Anomalies | bar | बल्क GetObject कॉल (≥100/घंटा) का पता लगाता है — स्वचालित डेटा एक्सफिल्ट्रेशन पैटर्न |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | एक घंटे में ≥10 अलग secrets प्राप्त करने वाली identities का पता लगाता है — क्रेडेंशियल संग्रह संकेत |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | secret विलोपन, PutResourcePolicy (cross-account साझाकरण), और CancelRotateSecret का पता लगाता है |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | एक घंटे में ≥20 parameters पढ़ने वाली identities का पता लगाता है — अक्सर अनदेखा किया जाने वाला एक्सफिल्ट्रेशन चैनल |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | बाहरी AWS accounts के साथ साझा किए गए RDS/Aurora snapshots का पता लगाता है (snapshot के माध्यम से database एक्सफिल्ट्रेशन) |
| 11 | 💣 RDS Deleted without Final Snapshot | — | skipFinalSnapshot=true के साथ RDS विलोपन का पता लगाता है — संभावित डेटा विनाश |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | publiclyAccessible=true के साथ बनाए या संशोधित किए गए RDS instances का पता लगाता है |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | ExportTableToPointInTime (GetItem DLP को बायपास करने वाला सर्वर-साइड फुल-टेबल export), DeleteTable, और PITR disable का पता लगाता है |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | EBS Direct API (ListSnapshotBlocks / GetSnapshotBlock) का पता लगाता है — Pacu ebs__download_snapshots EC2 के बिना कच्चे snapshot डेटा को स्ट्रीम करता है, ModifySnapshotAttribute डिटेक्शन को बायपास करता है |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | बाहरी S3 की ओर इशारा करने वाली Firehose delivery stream निर्माण/अद्यतन का पता लगाता है — नेटवर्क DLP के लिए अदृश्य रियल-टाइम डेटा पाइपलाइन |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | PutBucketReplication का पता लगाता है — अतिरिक्त GetObject इवेंट उत्पन्न किए बिना सभी नई objects को चुपचाप हमलावर-नियंत्रित bucket में कॉपी करता है |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | versioning निलंबन (स्थायी विलोपन सक्षम करता है) और server-access logging disable (साक्ष्य ट्रेल हटाता है) का पता लगाता है |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | SES receipt rule और identity कॉन्फ़िगरेशन परिवर्तनों का पता लगाता है — forwarding rules सभी इनबाउंड मेल को हमलावर पतों पर रिले करते हैं; verified identities फ़िशिंग अभियान सक्षम करती हैं |
| 19 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | बाहरी accounts को पहुँच प्रदान करने वाले SQS/SNS policy परिवर्तनों का पता लगाता है (हमलावर endpoints तक मौन संदेश स्ट्रीमिंग) |
| 20 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | सार्वजनिक रूप से साझा किए गए EBS snapshots या AMIs का पता लगाता है (group=all) — किसी को भी disk images कॉपी करने और डेटा निकालने की अनुमति देता है |
| 21 | 📧 Data Exfiltration Channels | bar | एकल identity से उच्च-वॉल्यूम SNS/SQS/SES/S3 PutObject कॉल (≥50/घंटा) का पता लगाता है |

### ⚡ Compute & Serverless

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | एक घंटे में ≥5 StopInstances/TerminateInstances करने वाली identities का पता लगाता है — ransomware / wiper संकेतक |
| 2 | 🖥️ SSM Session / Run Command | timeseries | SSM StartSession, SendCommand, और StartAutomationExecution का पता लगाता है — प्रबंधित instances के माध्यम से प्राथमिक लेटरल मूवमेंट पथ |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | SendSSHPublicKey और SendSerialConsoleSSHPublicKey का पता लगाता है — EC2 key pairs को बायपास करता है (60 सेकंड के लिए वैध, कोई SSH key आर्टिफैक्ट नहीं छोड़ता) |
| 4 | 📝 EC2 User Data Modification | timeseries | userData परिवर्तन के साथ ModifyInstanceAttribute का पता लगाता है — स्क्रिप्ट अगले बूट पर root के रूप में चलती है |
| 5 | ⚡ Lambda Function Tampering | timeseries | Lambda निर्माण, code अद्यतन (UpdateFunctionCode), और permission परिवर्तन (AddPermission) का पता लगाता है |
| 6 | 📦 Lambda Layer Addition | timeseries | Lambda layer प्रकाशन और wildcard principal के साथ AddLayerVersionPermission का पता लगाता है (सार्वजनिक आपूर्ति-श्रृंखला हमला) |
| 7 | 📦 ECS Task Definition  | timeseries | RegisterTaskDefinition / UpdateService का पता लगाता है — Pacu ecs__backdoor_task_def ECR को छुए बिना एक दुर्भावनापूर्ण sidecar container इंजेक्ट करता है |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | AssociateIamInstanceProfile / ReplaceIamInstanceProfileAssociation का पता लगाता है — लेटरल मूवमेंट सक्षम करने वाला एक विशेषाधिकार प्राप्त profile संलग्न करता है |
| 9 | 🖥 EC2 Instance Launches | timeseries | instance type, count, key name, और AMI सहित सभी RunInstances इवेंट को सूचीबद्ध करता है (cryptomining डिटेक्शन) |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | बड़े Spot Fleet अनुरोधों (ec2) और उच्च क्षमता के साथ Auto Scaling group निर्माण (autoscaling) का पता लगाता है — cryptomining वित्तीय-प्रभाव संकेतक |
| 11 | ☸️ EKS Cluster API Calls | timeseries | EKS cluster control-plane संशोधनों का पता लगाता है (सार्वजनिक API server एक्सपोज़र, दुष्ट Fargate profiles) |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | ECR repository/image इवेंट का पता लगाता है ('latest' टैग किया गया PutImage सभी बाद के deployments को विषाक्त करता है) |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | EventBridge rule और Scheduler संशोधनों का पता लगाता है (PutRule, CreateSchedule) — चालू प्रक्रिया के बिना परसिस्टेंस स्थापित करता है |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | Lightsail key पुनर्प्राप्ति, port एक्सपोज़र, और instance पहुँच का पता लगाता है — Pacu lightsail__download_ssh_keys / lightsail__generate_temp_access |

### 🌐 Network & Infrastructure

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 🌍 Security Group Opened to Internet | timeseries | 0.0.0.0/0 से ट्रैफ़िक की अनुमति देने वाले security group नियम खोजता है — प्रत्यक्ष सार्वजनिक एक्सपोज़र जोखिम |
| 2 | 🔥 Security Group Modifications | timeseries | सभी security group rule परिवर्तनों का पता लगाता है (AuthorizeSecurityGroupIngress, ModifySecurityGroupRules, आदि) |
| 3 | 🌊 VPC Flow Log Changes | timeseries | VPC Flow Logs के विलोपन का पता लगाता है — flow logs हटाने से प्राथमिक नेटवर्क फोरेंसिक साक्ष्य समाप्त हो जाता है |
| 4 | 🌐 CloudFront Distribution Tampering | timeseries | CloudFront origin परिवर्तनों का पता लगाता है जो सभी CDN ट्रैफ़िक को हमलावर-नियंत्रित servers पर रीडायरेक्ट करते हैं (MitM) |
| 5 | 🛡 Network Firewall / Shield Tampering | timeseries | Network Firewall और Shield सुरक्षा हटाने का पता लगाता है — पूरे subnet श्रेणियों को हमले ट्रैफ़िक के लिए उजागर करता है |
| 6 | 🧱 Network ACL Changes | timeseries | NACL entry निर्माण, विलोपन, और प्रतिस्थापन का पता लगाता है — NACLs subnet स्तर पर security groups को ओवरराइड करते हैं |
| 7 | 🛣️ Route Table Changes | timeseries | route table संशोधनों का पता लगाता है — हमलावर अवरोधन या C2 के लिए ट्रैफ़िक को दुर्भावनापूर्ण gateways पर रीडायरेक्ट करते हैं |
| 8 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | नए VPN connections और Transit Gateway attachments का पता लगाता है — C2 या एक्सफिल्ट्रेशन के लिए स्थायी Layer-3 नेटवर्क पथ बनाता है |
| 9 | 📡 Elastic IP Allocation / Association | timeseries | Elastic IP allocation/association का पता लगाता है — स्थिर C2 अवसंरचना के लिए समझौता किए गए instances को एक निश्चित सार्वजनिक IP असाइन करता है |
| 10 | 🗝️ EC2 Key Pair Creation | timeseries | CreateKeyPair और ImportKeyPair का पता लगाता है — हमलावर स्थायी instance पहुँच के लिए SSH keys बनाता है |
| 11 | 📡 Network Infrastructure Changes | timeseries | VPC / subnet / IGW / NAT Gateway / peering परिवर्तनों का पता लगाता है जो हमलावर-नियंत्रित अवसंरचना स्थापित कर सकते हैं |
| 12 | 🏷 ACM Certificate Operations | timeseries | ACM certificate अनुरोधों और विलोपन का पता लगाता है — समझौता किए गए accounts फ़िशिंग डोमेन के लिए TLS certs जारी कर सकते हैं |
| 13 | 🔑 API Gateway Key Creation & Management | timeseries | API Gateway key निर्माण और authorizer परिवर्तनों का पता लगाता है — Pacu api_gateway__create_api_keys स्थायी क्रेडेंशियल उत्पन्न करता है जो IAM key रोटेशन से बचे रहते हैं |
| 14 | 🚧 VPC Endpoint Access Denied | timeseries | VPC endpoints के माध्यम से access denied errors का पता लगाता है — गलत-कॉन्फ़िगर endpoint policy का संकेत दे सकता है |

### 🕵 Threat Patterns

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | उन callers की पहचान करता है जिन्होंने एक घंटे में 10+ अलग Describe*/List*/Get* APIs चलाए — सामान्य प्रारंभिक हमला चरण |
| 2 | 🤖 Unusual User Agents | bar | दुर्लभ user agents (<5 इवेंट) या ज्ञात हमलावर टूल (Pacu, curl, wget) को सूचीबद्ध करता है — हमला टूलिंग का संकेत दे सकता है |
| 3 | 🌍 Multi-Region Activity | bar | एक दिन में 3+ regions में राइट्स करने वाली identities का पता लगाता है — भौगोलिक प्रसार समझौते का संकेत दे सकता है |
| 4 | 🕵 First-Time API Calls (24h) | — | पिछले 24h में देखी गई लेकिन पहले कभी नहीं देखी गई API कॉल खोजता है — नवीन संचालन हमलावर टूलिंग का संकेत दे सकता है |

### 📊 Activity & Baseline

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | AWS console के माध्यम से की गई म्यूटेटिंग API कॉल की पहचान करता है — तब उपयोगी जब केवल CLI पहुँच अपेक्षित हो |
| 2 | 🔍 Events with Errors (24h) | timeseries | पिछले 24 घंटों में सभी error इवेंट को सूचीबद्ध करता है — क्या विफल हो रहा है या जाँचा जा रहा है इसका त्वरित अवलोकन |
| 3 | ❌ Error Spike Detection | — | वे 1-घंटे की विंडो खोजता है जहाँ error count दैनिक औसत से 3× अधिक हो |

### 🌍 GeoIP Analysis

> जनसंख्या के लिए GeoLite2 `.mmdb` फ़ाइलों की आवश्यकता है (यदि GeoIP के बिना ingest किया गया तो columns NULL होते हैं)।

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 🕵 Impossible Travel Detection | — | 2 घंटों के भीतर दूर के शहरों से APIs कॉल करने वाली समान identity का पता लगाता है — मजबूत क्रेडेंशियल समझौता संकेतक |
| 2 | ⚠ Identity Multi-Country Access | bar | 2+ देशों से API कॉल करने वाली identities खोजता है — वैध users शायद ही कभी एक साथ कई देशों से संचालन करते हैं |
| 3 | 🗺 Console Logins by Country | timeseries | console login इवेंट को उनके भौगोलिक मूल से मैप करता है — अप्रत्याशित देशों से लॉगिन उच्च-जोखिम हैं |
| 4 | 🚨 Unusual Country Access | bar | दुर्लभ country/identity संयोजनों का पता लगाता है (<10 इवेंट) — कम-वॉल्यूम विदेशी पहुँच हमलावर अवसंरचना हो सकती है |
| 5 | 🚫 Access Denied by Country | bar | access denied errors को source country द्वारा समूहित करता है — एक देश से केंद्रित denials एक हमले का संकेत दे सकते हैं |
| 6 | 🔍 Write Events by Country | bar | source country द्वारा समूहित म्यूटेटिंग API कॉल दिखाता है — अप्रत्याशित देशों से राइट्स reads की तुलना में मजबूत संकेत हैं |
| 7 | 🌍 Top Source Countries | bar | write-event और unique-identity विभाजन के साथ API कॉल वॉल्यूम द्वारा source countries को रैंक करता है |
| 8 | 🏢 Top ASN / Organizations | bar | API कॉल वॉल्यूम द्वारा autonomous systems (ISPs/cloud providers) को सूचीबद्ध करता है — VPN/hosting ASNs हमलावर अवसंरचना का संकेत दे सकते हैं |
| 9 | 📍 Top Source Cities | bar | इवेंट वॉल्यूम द्वारा source cities को रैंक करता है — city-स्तरीय डेटा विशिष्ट हमलावर अवसंरचना या कार्यालय स्थानों को इंगित करता है |
| 10 | 🌐 Private / Internal IP Summary | bar | private/loopback/AWS-internal IPs से इवेंट का सारांश देता है — अपेक्षित आंतरिक ट्रैफ़िक के लिए बेसलाइन |
| 11 | 📋 API Calls by Country (Event Name) | table | कॉल वॉल्यूम द्वारा शीर्ष (event_name, country) जोड़े — प्रकट करता है कि कौन से API संचालन अप्रत्याशित भौगोलिक क्षेत्रों से उत्पन्न होते हैं |
| 12 | 👤 Identities by Country (user_identity_arn) | table | कॉल वॉल्यूम द्वारा शीर्ष (user_identity_arn, country) जोड़े — first/last seen के साथ अप्रत्याशित देशों से सक्रिय IAM identities को सामने लाता है |

### ☁ IaC & Platform

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | CI/CD पाइपलाइन निर्माण और संशोधन का पता लगाता है (UpdateProject प्रत्येक बाद के build में दुर्भावनापूर्ण build steps इंजेक्ट करता है) |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | CloudFormation stack संचालन का पता लगाता है — हमलावर दुर्भावनापूर्ण अवसंरचना को तेजी से deploy करने के लिए IaC का उपयोग कर सकते हैं |

</details>

---

## 📊 डैशबोर्ड चार्ट — 80+ चार्ट

| टैब | चार्ट | यह क्या दिखाता है |
|-----|:------:|---------------|
| 🔑 Identity & Access | 9 | Console लॉगिन · MFA रुझान · login heatmap · संवेदनशील APIs · root उपयोग · IAM entity गतिविधि · विशेषाधिकार वृद्धि · SSO/privesc |
| 🎯 Threat Detection | 12 | इवेंट वॉल्यूम · read/write अनुपात · बचाव चोरी · access denied · error रुझान · SCP/Config/NACL/EventBridge छेड़छाड़ |
| 📊 API Activity | 7 | शीर्ष APIs · region वितरण · source IPs · user agents · secrets विसंगति · बाहरी AssumeRole · Route53 परिवर्तन |
| 🖥️ Computing | 5 | SSM निष्पादन · EC2 public snapshot · EKS/ECR इवेंट · ECS बैकडोर · EBS Direct API एक्सफिल्ट्रेशन |
| 🪣 S3 & RDS | 9 | S3 policy/ACL · बल्क download/deletion · versioning/logging disabled · cross-account replication · RDS snapshot share · Backup छेड़छाड़ |
| 🌍 GeoIP Intelligence | 6 | विश्व मानचित्र · अनुरोध वॉल्यूम द्वारा शीर्ष countries / cities / ASNs · event_name × country · identity × country |
| 🕒 Temporal Analysis | 6 | identity/IP/API/agent द्वारा first/last seen · निष्क्रिय accounts पुनः सक्रिय · velocity स्पाइक्स |
| 🚨 High-Risk API Monitor | 7 | HRM time series · शीर्ष calls/actors/IPs · बचाव चोरी/क्रेडेंशियल विवरण · region द्वारा |

<details markdown="1">
<summary>📋 पूरी सूची — सभी 80+ चार्ट (विस्तृत करने के लिए क्लिक करें)</summary>

## डैशबोर्ड चार्ट (Apache Superset — `dashboard/`)

### 🔑 Identity & Access

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | Console Login Activity | IAM identity द्वारा समूहित console sign-in इवेंट (DSH-08) |
| 2 | MFA-less Login Trend | MFA उपयोग द्वारा विभाजित दैनिक console लॉगिन (DSH-28) |
| 3 | Login Activity Heatmap (Hour × Day) | JST में day-of-week और hour-of-day द्वारा console login गणना (DSH-19) |
| 4 | Sensitive API Calls | ज्ञात सुरक्षा-संवेदनशील AWS API क्रियाओं का आह्वान (DSH-12) |
| 5 | Root Account Usage | AWS Root account द्वारा की गई सभी API कॉल (DSH-13) |
| 6 | IAM Entity Activity | write अनुपात और error दर के साथ कुल API कॉल द्वारा रैंक की गई शीर्ष 50 IAM entities |
| 7 | Privilege Escalation Timeline | event name द्वारा विशेषाधिकार-वृद्धि API कॉल की दैनिक गणना (DSH-30) |
| 8 | IAM Identity Center (SSO) Events | sso.amazonaws.com से AWS IAM Identity Center प्रबंधन इवेंट (DSH-44) |
| 9 | Glue & SageMaker Privilege Escalation | iam:PassRole के माध्यम से IAM विशेषाधिकार वृद्धि के लिए उपयोग किए जाने वाले Glue DevEndpoint और SageMaker Notebook इवेंट (DSH-50) |

### 🎯 Threat Detection

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | CloudTrail Events Over Time | समय के साथ प्रति घंटा Read बनाम Write इवेंट वॉल्यूम (DSH-01) |
| 2 | Write/Read Ratio Trend | read बनाम write API कॉल का प्रति घंटा विभाजन (DSH-20) |
| 3 | Throttling Exception Spikes | AWS service द्वारा प्रति घंटा throttling/rate-limit errors (DSH-21) |
| 4 | Defense Evasion Events | ज्ञात बचाव-चोरी तकनीकों से मेल खाने वाले सभी CloudTrail इवेंट (DSH-22) |
| 5 | Top Access Denied Actions | AccessDenied errors लौटाने वाली शीर्ष 20 API क्रियाएँ (DSH-09) |
| 6 | Error Event Trend | error_code द्वारा विभाजित प्रति घंटा error इवेंट (DSH-04) |
| 7 | Organizations / SCP Changes | SCP policy परिवर्तनों सहित AWS Organizations प्रबंधन इवेंट (DSH-24) |
| 8 | First-Time Service Sources | पहली उपस्थिति तिथि द्वारा क्रमबद्ध सभी अलग AWS service sources (DSH-26) |
| 9 | VPC Flow Log Changes | VPC Flow Log निर्माण और विलोपन इवेंट (DSH-42) |
| 10 | AWS Config Tampering | AWS Config recorder और rule छेड़छाड़ इवेंट (DSH-43) |
| 11 | Network ACL / Route Table Changes | NACL और route table संशोधन इवेंट (DSH-46) |
| 12 | EventBridge / CloudWatch Rule Tampering | EventBridge और CloudWatch Events rule छेड़छाड़ (DSH-47) |

### 📊 API Activity

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | Top 20 API Calls | 20 सबसे अधिक बार कॉल की जाने वाली AWS API क्रियाएँ (DSH-02) |
| 2 | Region Activity | AWS regions में CloudTrail इवेंट का वितरण (DSH-14) |
| 3 | Top Source IP Addresses | अनुरोध गणना द्वारा शीर्ष 100 बाहरी source IPs (DSH-05) |
| 4 | User Agent Analysis | error और write विभाजन के साथ अनुरोध गणना द्वारा शीर्ष 50 user agents (DSH-11) |
| 5 | Secrets Access Anomaly | एक घंटे में ≥10 बार Secrets Manager या SSM Parameter Store तक पहुँचने वाली identities |
| 6 | AssumedRole from External IP | सार्वजनिक (non-private) IP पतों से AssumeRole कॉल (DSH-27) |
| 7 | Route53 DNS Changes | Route 53 hosted-zone और resolver कॉन्फ़िगरेशन परिवर्तन (DSH-29) |

### 🖥️ Computing

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | SSM Session / Run Command Execution | AWS Systems Manager रिमोट-निष्पादन इवेंट (DSH-39) |
| 2 | EC2 Public Snapshot / AMI Sharing | EBS snapshot और AMI public-sharing इवेंट (DSH-41) |
| 3 | EKS / ECR Container Platform Events | EKS cluster और ECR container registry इवेंट (DSH-48) |
| 4 | ECS Task Definition | ECS task definition पंजीकरण और service update इवेंट — Pacu ecs__backdoor_task_def पैटर्न (DSH-49) |
| 5 | EBS Direct API Snapshot Exfiltration | EC2 के बिना snapshot डेटा स्ट्रीम करने के लिए उपयोग की जाने वाली EBS Direct API कॉल (ListSnapshotBlocks / GetSnapshotBlock) (DSH-51) |

### 🪣 S3 & RDS

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | S3 Protection Config Changes | bucket सुरक्षा स्थिति को कमजोर करने वाले S3 इवेंट (DSH-25) |
| 2 | S3 Bucket Policy / ACL Changes | S3 bucket policy और ACL संशोधन इवेंट (DSH-45) |
| 3 | RDS Snapshot Cross-Account Share | RDS और Aurora snapshot साझाकरण इवेंट (DSH-40) |
| 4 | S3 Bulk Download | प्रति घंटे ≥100 GetObject कॉल करने वाली identities — स्वचालित डेटा एक्सफिल्ट्रेशन पैटर्न (DSH-52) |
| 5 | S3 Bulk Object Deletion | प्रति घंटे ≥50 DeleteObject/DeleteObjects कॉल करने वाली identities — ransomware डेटा विनाश पैटर्न (DSH-53) |
| 6 | S3 Versioning / Logging Disabled | PutBucketVersioning (Suspended) और PutBucketLogging (disabled) — डेटा विनाश का anti-forensics पूर्ववर्ती (DSH-54) |
| 7 | S3 Cross-Account Replication | PutBucketReplication / DeleteBucketReplication — हमलावर-नियंत्रित account के लिए स्थायी मौन एक्सफिल्ट्रेशन चैनल (DSH-55) |
| 8 | RDS Deleted without Final Snapshot | skipFinalSnapshot=true के साथ DeleteDBInstance / DeleteDBCluster — अपूरणीय डेटा विनाश (DSH-56) |
| 9 | AWS Backup Tampering | Backup Vault / Plan / RecoveryPoint विलोपन और Vault Lock हटाना — रिकवरी विकल्पों को समाप्त करने के लिए ransomware का पहला कदम (DSH-57) |

### 🌍 GeoIP Intelligence

> GeoLite2 `.mmdb` फ़ाइलों की आवश्यकता है। यदि GeoIP के बिना ingest किया गया तो GeoIP columns NULL होते हैं।

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | Global Request Origin Map | CloudTrail API कॉल मूल के भौगोलिक वितरण को दिखाने वाला विश्व मानचित्र |
| 2 | Top Countries by Request Volume | write-event और unique-caller विभाजन के साथ API कॉल वॉल्यूम द्वारा शीर्ष 20 source countries |
| 3 | Top Cities by Request Volume | write-event और unique-caller विभाजन के साथ API कॉल वॉल्यूम द्वारा शीर्ष 25 cities |
| 4 | Top ASN Organizations by Request Volume | API कॉल वॉल्यूम द्वारा शीर्ष 25 ASN organizations |
| 5 | API Calls by Country (Event Name × GeoIP) | शीर्ष 50 (event_name, country) जोड़े — प्रकट करता है कि प्रत्येक भौगोलिक क्षेत्र से कौन से API संचालन कॉल किए जाते हैं (DSH-79) |
| 6 | Identities by Country (user_identity_arn × GeoIP) | शीर्ष 50 (user_identity_arn, country) जोड़े — write count और first/last seen के साथ अप्रत्याशित देशों से सक्रिय IAM identities को सामने लाता है (DSH-80) |

### 🕒 Temporal Analysis

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | First / Last Seen per IAM Identity | first/last seen टाइमस्टैम्प, इवेंट गणना, और अलग APIs के साथ IAM identities |
| 2 | First / Last Seen per Source IP | first/last seen, अलग identities, और अलग APIs के साथ source IPs |
| 3 | First / Last Seen per API Call | पहली उपस्थिति द्वारा क्रमबद्ध API क्रियाएँ — नई कॉल नवीन हमला टूलिंग का संकेत दे सकती हैं (DSH-33) |
| 4 | First / Last Seen per User Agent | पहली उपस्थिति द्वारा क्रमबद्ध user agents — नई टूलिंग डिटेक्शन (DSH-34) |
| 5 | Dormant Accounts Reactivated | 72+ घंटों के निष्क्रियता अंतराल वाली identities जिन्होंने गतिविधि फिर से शुरू की (DSH-37) |
| 6 | Event Velocity Spikes per Identity | प्रति घंटे 50+ इवेंट बर्स्ट गतिविधि वाली identities (DSH-38) |

### 🚨 High-Risk API Monitor (HRM)

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | High-Risk API Events Over Time | हमला अभियानों में सामान्यतः देखे जाने वाले APIs के लिए दैनिक कॉल वॉल्यूम (HRM-39) |
| 2 | Top High-Risk API Calls | कुल कॉल गणना द्वारा रैंक की गई high-risk watchlist से API क्रियाएँ (HRM-40) |
| 3 | Top Actors — High-Risk APIs | high-risk watchlist APIs को कुल कॉल द्वारा रैंक किए गए IAM principals (HRM-42) |
| 4 | Top Source IPs — High-Risk APIs | high-risk watchlist APIs को कुल कॉल द्वारा रैंक किए गए source IPs (HRM-43) |
| 5 | Defense Evasion API Events | ऑडिट नियंत्रणों को disable या छेड़छाड़ करने के लिए उपयोग किए जाने वाले APIs के लिए विस्तृत इवेंट लॉग (HRM-44) |
| 6 | Credential Access API Events | secrets और क्रेडेंशियल प्राप्त करने के लिए उपयोग किए जाने वाले APIs के लिए विस्तृत इवेंट लॉग (HRM-45) |
| 7 | High-Risk API Calls by Region | AWS region द्वारा वितरित high-risk watchlist API कॉल (HRM-46) |

</details>

---
