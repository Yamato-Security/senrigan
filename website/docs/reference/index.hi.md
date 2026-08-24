# बिल्ट-इन क्वेरी और डैशबोर्ड संदर्भ

> 💡 किसी SQL या गहन AWS ज्ञान की आवश्यकता नहीं — बस ड्रॉपडाउन से एक hunt चुनें और तुरंत परिणाम प्राप्त करें।

## 🎯 बिल्ट-इन Hunts — 139 क्वेरीज़

श्रेणियाँ DFIR triage प्राथमिकता के अनुसार क्रमबद्ध हैं — पहले डिटेक्शन-टूल छेड़छाड़ की जाँच करें, फिर पहचान दुरुपयोग, फिर डेटा प्रभाव।

| श्रेणी | क्वेरीज़ | कवर किए गए प्रमुख खतरे |
|----------|:-------:|---------------------|
| 🛡 Detection & Response | 14 | ऑडिट-सेवा छेड़छाड़ (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · SCP विलोपन · अलार्म दमन · लॉग एक्सफिल्ट्रेशन · रैनसमवेयर किल-चेन सहसंबंध |
| 🔑 Identity & Access | 36 | Root उपयोग · console लॉगिन/MFA · विशेषाधिकार वृद्धि · trust policy में बैकडोर · PassRole दुरुपयोग · cross-account AssumeRole · SSO/SAML/OIDC · क्रेडेंशियल गणना · IAM entity विलोपन · AssumeRoot टेकओवर · Cognito user-pool/token दुरुपयोग · Support केस दमन · रोल चेनिंग · सत्र क्रेडेंशियल ट्रेसिंग · GetCallerIdentity टोही · फ़ेडरेटेड कंसोल लॉगिन · Identity Center परमिशन सेट और प्रत्यायोजित व्यवस्थापक · बिना MFA के API कॉल |
| 🪣 Data & Storage | 31 | S3 बल्क विलोपन/डाउनलोड · secrets बल्क रीड · backup छेड़छाड़ · KMS ops · snapshot साझाकरण · EBS Direct API एक्सफिल्ट्रेशन · DynamoDB export · S3 cross-account replication · SSE-C ransomware एन्क्रिप्शन · lifecycle-ट्रिगर विलोपन · RDS Data API हेरफेर · प्रभाव के लिए storage पुनः-एन्क्रिप्शन · फिरौती नोट रखना · उल्लंघन अधिसूचना हेतु दायरा निर्धारण · क्रॉस-अकाउंट ऑब्जेक्ट कॉपी · प्रीसाइन्ड URL निर्माण |
| ⚡ Compute & Serverless | 17 | EC2 मास stop/terminate · SSM लेटरल मूवमेंट · Lambda/ECS/EKS/ECR छेड़छाड़ · EventBridge परसिस्टेंस · cryptomining · Lightsail दुरुपयोग · IMDS/SSRF कमजोर करना · AMI/snapshot विलोपन · WorkSpaces हाइजैकिंग |
| 🤖 AI & LLM Abuse | 10 | Bedrock invocation स्पाइक्स · model access सक्षमकरण · invocation-logging छेड़छाड़ · region-व्यापी recon · विफल invocation बर्स्ट · AgentCore टोकन वॉल्ट · गेटवे प्राधिकरण बायपास · मेमोरी अखंडता · सैंडबॉक्स नेटवर्क मोड परिवर्तन · ऑब्ज़र्वेबिलिटी छेड़छाड़ |
| 🌐 Network & Infrastructure | 13 | SG इंटरनेट के लिए खुला · VPC flow log विलोपन · CloudFront हाइजैक · गुप्त VPN/TGW टनल · Elastic IP C2 · API Gateway keys · Route 53/domain हाइजैक · DDoS सुरक्षा का कमजोर होना |
| 🕵 Threat Patterns | 11 | recon बर्स्ट · असामान्य user agents · multi-region प्रसार · पहली-बार API कॉल · पहली बार देखी गई region गतिविधि · कार्यसमय के बाहर गतिविधि · स्वयं विशेषाधिकार वृद्धि · दैनिक मात्रा विचलन · अप्रयुक्त क्षेत्रों में संसाधन निर्माण · उच्च-मात्रा API उपयोग |
| 📊 Activity & Baseline | 3 | Console राइट इवेंट · error स्पाइक्स · हाल की errors |
| 🌍 GeoIP Analysis | 2 | country के अनुसार console लॉगिन/denials/राइट्स · दुर्लभ-देश पहुँच |
| ☁ IaC & Platform | 2 | CI/CD आपूर्ति श्रृंखला · CloudFormation दुरुपयोग |

<details markdown="1">
<summary>📋 पूरी सूची — सभी 139 क्वेरीज़ (विस्तृत करने के लिए क्लिक करें)</summary>

## बिल्ट-इन Hunts

### 🛡 Detection & Response

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | CloudTrail को रोकने या संशोधित करने के किसी भी प्रयास का पता लगाता है। सबसे महत्वपूर्ण अलर्ट — कवर-अप का संकेत देता है। |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | GuardDuty disable, delete, और threat-intel हेरफेर का पता लगाता है। जाँच के बीच में कोई भी GuardDuty परिवर्तन एक महत्वपूर्ण संकेतक है। |
| 3 | ⛔ Security Hub Tampering | timeseries | Security Hub disable, standard disable, और finding दमन का पता लगाता है। Security Hub को मौन करने से सभी सुरक्षा findings के लिए केंद्रीय एकत्रीकरण बिंदु समाप्त हो जाता है। |
| 4 | ⚙️ AWS Config Tampering | timeseries | AWS Config recorder/rule विलोपन का पता लगाता है। Config को रोकने से पूरी region के लिए अनुपालन साक्ष्य और change-tracking समाप्त हो जाता है। |
| 5 | 🛡 Organizations Service Control Policy (SCP) Changes | timeseries | SCP निर्माण, संशोधन, और विलोपन का पता लगाता है। Deny SCP हटाने से प्रभावित OU के हर account में तुरंत guardrails समाप्त हो जाते हैं। |
| 6 | 🚫 AWS Macie Tampering | timeseries | Macie disable और finding-filter निर्माण का पता लगाता है। हमलावर S3 से संवेदनशील डेटा exfiltrate करने से पहले Macie findings को दबा देते हैं। |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | CloudWatch alarm विलोपन और disable का पता लगाता है। GuardDuty, CloudTrail metric filters, या billing thresholds से जुड़े alarms को मौन करना defense evasion का प्रमुख संकेतक है। |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | CW Logs subscription filter निर्माण/विलोपन और log group विलोपन का पता लगाता है। हमलावर logs को बाहरी destination पर स्ट्रीम करते हैं या सबूत को वहीं नष्ट कर देते हैं। |
| 9 | 🏹 WAF WebACL Changes | timeseries | WAF WebACL निर्माण, अद्यतन, और विलोपन का पता लगाता है। WebACL को हटाना या कमजोर करना SQLi, XSS, और DDoS हमलों के खिलाफ सुरक्षा को निष्क्रिय कर देता है। |
| 10 | 🔍 GuardDuty Findings Read | timeseries | केवल-पठनीय GuardDuty API कॉल का पता लगाता है। Pacu का guardduty__list_findings मॉड्यूल सक्रिय findings पढ़ता है ताकि यह समझा जा सके कि defender ने पहले से क्या पता लगाया है, जिससे हमलावर अपनी रणनीति अनुकूलित कर सके और नए alerts ट्रिगर करने से बच सके। |
| 11 | 🩺 Security Monitoring Posture Recon | timeseries | निगरानी स्टैक की स्वयं की केवल-पठन जाँच का पता लगाता है — क्या कोई ट्रेल चल रहा है, क्या GuardDuty चालू है, क्या Config रिकॉर्ड कर रहा है। यह रक्षा-चोरी से पहले का चरण है, और साफ़ लॉग छोड़ने वाला अंतिम चरण। |
| 12 | 💰 Budget / Cost Anomaly Changes | timeseries | AWS Budgets और Cost Anomaly monitors के विलोपन या संशोधन का पता लगाता है। हमलावर cryptomining या संसाधन-गहन operations छिपाने के लिए budget alerts हटा देते हैं। |
| 13 | 🚫 Access Denied Errors | bar | AccessDenied errors को identity और API के अनुसार समूहित करता है। शीर्ष अपराधी क्रेडेंशियल दुरुपयोग का संकेत दे सकते हैं। |
| 14 | ⛓ Ransomware Kill-Chain Sequence | bar | रैनसमवेयर के तीन चरणों — पुनर्प्राप्ति हटाना, सुरक्षा निष्क्रिय करना, डेटा नष्ट या एन्क्रिप्ट करना — को प्रिंसिपल और दिन के अनुसार सहसंबंधित करता है। अकेला हर चरण परिचालन शोर है; तीनों साथ हों तो नहीं। |

### 🔑 Identity & Access

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | root account द्वारा की गई किसी भी API कॉल का पता लगाता है। production में root का कभी उपयोग नहीं किया जाना चाहिए। |
| 2 | 🔓 Console Login without MFA | timeseries | उन console logins का पता लगाता है जहाँ MFA का उपयोग नहीं किया गया। account समझौते का उच्च-जोखिम संकेतक। |
| 3 | 🌐 Console Logins | timeseries | सभी console login प्रयासों को सूचीबद्ध करता है। Brute force = कई विफलताओं के बाद एक सफलता। |
| 4 | 🔐 MFA & Password Changes | timeseries | MFA निष्क्रियकरण और password reset का पता लगाता है। account टेकओवर का मजबूत संकेतक। |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | विशेषाधिकार वृद्धि के लिए उपयोग किए जाने वाले IAM policy attachment और role हेरफेर इवेंट का पता लगाता है। |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | UpdateAssumeRolePolicy कॉल का पता लगाता है। trust policy में बाहरी account principals जोड़ने से एक स्थायी बैकडोर बनता है। |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | permission boundary put/delete इवेंट का पता लगाता है। permission boundary हटाने से किसी principal की प्रभावी permissions तुरंत विस्तृत हो जाती हैं, जिससे विशेषाधिकार वृद्धि संभव होती है। |
| 8 | 👑 User Added to Admin Group | timeseries | नाम में 'admin' वाले groups में जोड़े गए users का पता लगाता है। क्लासिक विशेषाधिकार वृद्धि तकनीक। |
| 9 | 👥 IAM Group Membership Changes | timeseries | group नाम की परवाह किए बिना सभी AddUserToGroup और RemoveUserFromGroup इवेंट का पता लगाता है। कोई भी group जोड़ना group-इनहेरिटेड policies के माध्यम से विशेषाधिकार वृद्धि का संकेत दे सकता है। |
| 10 | 👤 New IAM Users / Keys | timeseries | IAM user और access key निर्माण इवेंट की पहचान करता है। अप्रत्याशित निर्माण persistence का संकेत दे सकता है। |
| 11 | 🎯 IAM PassRole Abuse | timeseries | iam:PassRole कॉल का पता लगाता है। EC2/Lambda/Glue/ECS/SageMaker को एक privileged role पास करना lateral विशेषाधिकार वृद्धि का सबसे सामान्य पथ है। |
| 12 | 🏢 Cross-Account Access | timeseries | वे इवेंट खोजता है जहाँ caller account प्राप्तकर्ता account से भिन्न है। lateral movement का संकेत। |
| 13 | 🔑 STS Federation Token Issuance | timeseries | GetFederationToken और GetSessionToken कॉल का पता लगाता है। हमलावर इनका उपयोग दीर्घकालिक keys को स्थायी अस्थायी क्रेडेंशियल में बदलने के लिए करते हैं। |
| 14 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | AssumeRoleWithWebIdentity कॉल का पता लगाता है। गलत-कॉन्फ़िगर OIDC trust (जैसे अत्यधिक व्यापक sub claim) का दुरुपयोग हमलावरों को उनके स्वयं के नियंत्रित tokens का उपयोग करके एक role को हाइजैक करने देता है। |
| 15 | 🆔 IAM Identity Center (SSO) Events | timeseries | AWS IAM Identity Center प्रबंधन क्रियाओं का पता लगाता है। हमलावर SSO का दुरुपयोग बैकडोर permission sets बनाने या accounts को हमलावर-नियंत्रित users को असाइन करने के लिए करते हैं। |
| 16 | 🔗 SAML / OIDC Provider Updates | timeseries | SAML/OIDC identity provider परिवर्तनों का पता लगाता है। हमलावर-नियंत्रित metadata के साथ SAML provider को अद्यतन करने से एक स्थायी प्रमाणीकरण बैकडोर बनता है। |
| 17 | 🧐 IAM Access Analyzer Calls | timeseries | IAM Access Analyzer के किसी भी उपयोग का पता लगाता है। हमलावर कस्टम recon स्क्रिप्ट लिखे बिना बाहरी रूप से सुलभ संसाधनों की गणना करने के लिए नेटिव AWS analyzer का उपयोग करते हैं। |
| 18 | 🔄 Credential Report & Enumeration | timeseries | उस IAM एन्युमरेशन का पता लगाता है जो यह मानचित्रित करता है कि कौन मौजूद है और वे क्या कर सकते हैं। इनका झुंड, विशेषकर AccessDenied के साथ, हमले का आरंभिक चरण है। |
| 19 | 🗝 Access Key Abuse | bar | 7 दिनों में 3+ अलग source IPs से उपयोग की गई access keys का पता लगाता है। key लीक का मजबूत संकेतक। |
| 20 | 📰 AWS Organizations Account Creation | timeseries | Organizations account निर्माण और प्रत्यायोजित administrator परिवर्तनों का पता लगाता है। हमलावर मुख्य account के बाहर स्थायी पकड़ स्थापित करने के लिए शैडो accounts बनाते हैं। |
| 21 | 👥 Cognito Unauthenticated Access | timeseries | unauthenticated access सक्षम वाले Cognito Identity Pools का पता लगाता है। इससे अनाम users unauthenticated IAM role की permissions के साथ AWS APIs कॉल कर सकते हैं। |
| 22 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | Glue development endpoint निर्माण और connection गणना का पता लगाता है। iam:PassRole + glue:CreateDevEndpoint SSH के माध्यम से पास किए गए role की पूर्ण permissions प्रदान करता है — सबसे अधिक अनदेखी की जाने वाली IAM विशेषाधिकार वृद्धि तकनीकों में से एक। |
| 23 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | SageMaker notebook instance निर्माण और presigned URL जनरेशन का पता लगाता है। iam:PassRole + sagemaker:CreateNotebookInstance पास किए गए role की पूर्ण AWS permissions के साथ एक Jupyter environment प्रदान करता है। अकेले CreatePresignedNotebookInstanceUrl एक मौजूदा notebook तक पहुँच प्रदान कर सकता है। |
| 24 | 🪓 IAM Entity Deletion | timeseries | IAM users, roles, policies, और MFA devices के विलोपन का पता लगाता है। हमलावर अपनी गतिविधि के निशान हटाने या defenders को बाहर बंद करने के लिए IAM entities हटाते हैं। |
| 25 | 👑 AssumeRoot Usage | timeseries | management account से member-account root में sts:AssumeRoot कॉल का पता लगाता है। एक समझौता किया गया management account इस तरह से हर member account पर कब्जा कर सकता है। |
| 26 | 🎫 Support Case Manipulation | timeseries | AWS Support केस बंद करने और comment गतिविधि का पता लगाता है। हमलावर एक समझौते के बारे में AWS सूचनाओं को दबाने के लिए abuse/support केस हल करते हैं। |
| 27 | 🪪 Cognito User Pool Manipulation | timeseries | Cognito user-pool और app-client परिवर्तनों का पता लगाता है: विस्तारित token वैधता, नए clients, और admin user निर्माण। हमलावर इनका दुरुपयोग दीर्घकालिक tokens बनाने या बैकडोर users बोने के लिए करते हैं। |
| 28 | 🔗 Role Chaining (Session → Role) | timeseries | पहले से ग्रहण किए गए रोल सत्र द्वारा एक और रोल ग्रहण करने का पता लगाता है। अकेले AssumeRole कॉल सामान्य लगते हैं; शृंखला ही वह रास्ता है जिससे हमलावर समझौता किए गए इंस्टेंस रोल से अपनी वांछित अनुमतियों तक पहुँचता है। |
| 29 | 🎫 Session Credential Trace | bar | बताता है कि प्रत्येक अस्थायी STS सत्र (ASIA… एक्सेस की) ने क्या किया: कॉल की संख्या, सेवाएँ, स्रोत IP और समयावधि। यही वह दायरा-प्रश्न है जिससे हर क्रेडेंशियल समझौता जाँच शुरू होती है। |
| 30 | 🌐 AssumeRole Target Account (roleArn) | timeseries | अनुरोधित roleArn से लक्ष्य खाता पढ़कर खाता-सीमा पार करने का पता लगाता है, जो तब भी काम करता है जब केवल कॉल करने वाले खाते के लॉग ही लिए गए हों। |
| 31 | 📊 AssumeRole Fan-In by Target Role | bar | रोल्स को इस आधार पर क्रमित करता है कि उन्हें कौन और कहाँ से ग्रहण करता है। सामान्यतः एक खाते द्वारा ग्रहण किया जाने वाला रोल जब अचानक दूसरा कॉलर पा जाए तो यहाँ उभरता है, जबकि कच्ची इवेंट सूची उसे दबा देती है। |
| 32 | 🔍 GetCallerIdentity Reconnaissance | bar | प्रिंसिपल और स्रोत IP के अनुसार GetCallerIdentity कॉल दिखाता है। चोरी किए गए क्रेडेंशियल के साथ चलाई जाने वाली यह पहली कमांड है — और एक ही कॉल, जहाँ मात्रा-सीमा आधारित टोही हंट कभी नहीं पहुँचते। |
| 33 | 🪪 Federated Console Logins | timeseries | बाहरी पहचान प्रदाता के माध्यम से आए कंसोल लॉगिन को प्रदाता के नाम और उद्गम के साथ सूचीबद्ध करता है। जब समझौता किया गया घटक IdP ही हो, तो AWS को केवल एक वैध लॉगिन दिखता है। |
| 34 | 🎟 Identity Center Permission Set Grants | timeseries | IAM Identity Center में परमिशन सेट निर्माण, नीति संलग्नक और खाता असाइनमेंट का पता लगाता है — संगठन के हर खाते में स्थायी व्यवस्थापक पहुँच तक का रास्ता। |
| 35 | 🧑 Identity Store User & Group Creation | timeseries | Identity Center के पहचान संग्रह में सीधे बनाए गए उपयोगकर्ता, समूह और सदस्यताओं का पता लगाता है — ऐसी दृढ़ता जो IAM में कभी नहीं दिखती और केवल IAM की निगरानी से छूट जाती है। |
| 36 | 👑 Delegated Administrator Registration | timeseries | किसी संगठन सेवा के लिए प्रत्यायोजित व्यवस्थापक के पंजीकरण का पता लगाता है। यही एकमात्र घटना है जिसे Identity Center प्लेबुक CRITICAL आँकता है: यह पूरे संगठन का नियंत्रण दूसरे खाते को सौंप देती है। |

### 🪣 Data & Storage

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | उच्च-वॉल्यूम DeleteObject/DeleteObjects कॉल (≥50/घंटा) का पता लगाता है। एक्सफिल्ट्रेशन से अलग — यह डेटा विनाश / ransomware पैटर्न है। |
| 2 | 🔥 AWS Backup Tampering | timeseries | Backup Vault/Plan/RecoveryPoint विलोपन का पता लगाता है। बैकअप को नष्ट करना ransomware हमलों में recovery रोकने का पहला कदम है। |
| 3 | 🔓 KMS Key Operations | timeseries | key विलोपन और उच्च-वॉल्यूम Decrypt कॉल सहित संवेदनशील KMS संचालन को फ़्लैग करता है। |
| 4 | 🔓 S3 Public Access Block Disabled | — | S3 सार्वजनिक-पहुँच सुरक्षा के निष्क्रिय किए जाने या पूरी तरह हटा दिए जाने का पता लगाता है। तत्काल डेटा-उजागर जोखिम। |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | S3 bucket policy और ACL संशोधनों का पता लगाता है। ये किसी bucket को सार्वजनिक रूप से पठनीय बना सकते हैं या हमलावर-नियंत्रित accounts को पहुँच प्रदान कर सकते हैं। |
| 6 | 🪣 S3 Data Access Anomalies | bar | बल्क GetObject कॉल (≥100/घंटा) का पता लगाता है जो डेटा एक्सफिल्ट्रेशन का संकेत दे सकते हैं। |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | secrets (DB passwords, API keys, आदि) के बल्क रिट्रीवल का पता लगाता है। एक घंटे में दस या अधिक GetSecretValue कॉल एक मजबूत क्रेडेंशियल-संग्रह संकेत है। |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | Secrets Manager secret विलोपन और cross-account resource policy परिवर्तनों का पता लगाता है। मौजूदा बल्क-रीड डिटेक्शन को विनाश और policy-एक्सफिल्ट्रेशन वेक्टरों के साथ पूरक करता है। |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | SSM Parameter Store प्रविष्टियों के बल्क रीड का पता लगाता है। Secrets Manager की तुलना में अक्सर अनदेखा किया जाने वाला एक्सफिल्ट्रेशन चैनल। |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | बाहरी AWS accounts के साथ साझा किए गए RDS/Aurora snapshots का पता लगाता है। snapshot साझाकरण के माध्यम से क्लासिक डेटा एक्सफिल्ट्रेशन। |
| 11 | 💣 RDS Deleted without Final Snapshot | — | skipFinalSnapshot=true के साथ RDS instance/cluster विलोपन का पता लगाता है। संभावित डेटा विनाश। |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | PubliclyAccessible=true के साथ बनाई या संशोधित की गई RDS instances का पता लगाता है। VPC सुरक्षा नियंत्रणों को बायपास करते हुए database को सीधे इंटरनेट पर उजागर करता है। |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | DynamoDB ExportTableToPointInTime (S3 में मौन पूर्ण-टेबल export) और table विलोपन का पता लगाता है। उच्च-जोखिम एक्सफिल्ट्रेशन और विनाश वेक्टर। |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | EBS Direct API कॉल (ListSnapshotBlocks / GetSnapshotBlock) का पता लगाता है। Pacu का ebs__download_snapshots इस API का उपयोग EC2 instances बनाए बिना कच्चे snapshot डेटा को स्ट्रीम करने के लिए करता है, जो पारंपरिक snapshot-साझाकरण डिटेक्शन को बायपास करता है। |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | बाहरी S3 की ओर इशारा करने वाली Kinesis Firehose delivery stream निर्माण/अद्यतन का पता लगाता है। रियल-टाइम डेटा पाइपलाइन एक्सफिल्ट्रेशन जो नेटवर्क DLP के लिए अदृश्य है। |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | PutBucketReplication और DeleteBucketReplication का पता लगाता है। cross-account replication चुपचाप सभी नई objects को हमलावर-नियंत्रित bucket में कॉपी कर देता है। |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | S3 versioning निलंबन और server access logging disable का पता लगाता है। versioning disable करने से डेटा विनाश संभव होता है; logging disable करने से पहुँच साक्ष्य ट्रेल मिट जाता है। |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | SES receipt rule और identity कॉन्फ़िगरेशन परिवर्तनों का पता लगाता है। forwarding rules सभी inbound मेल को हमलावर पतों पर स्वतः रिले कर सकते हैं; verified identities फ़िशिंग अभियानों को सक्षम करती हैं। |
| 19 | 📨 SES / SNS Sending Quota Abuse | timeseries | उस तैयारी का पता लगाता है जो स्पैम को लाभदायक बनाती है — SMS व्यय सीमा बढ़ाना, SES प्रेषण पुनः सक्षम करना, बल्क भेजने वाले API का उपयोग। ये सभी एकल, कम-मात्रा कॉल हैं जिन तक प्रति-घंटा सीमा कभी नहीं पहुँच सकती। |
| 20 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | SQS/SNS queue/topic policy परिवर्तनों का पता लगाता है जो बाहरी accounts को पहुँच प्रदान करते हैं। उच्च-वॉल्यूम भेजने के अलर्ट को ट्रिगर किए बिना एक मौन एक्सफिल्ट्रेशन चैनल बनाता है। |
| 21 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | सार्वजनिक रूप से साझा किए गए EBS snapshots या AMIs (group=all) का पता लगाता है। किसी को भी आपकी disk images कॉपी करने और डेटा निकालने की अनुमति देता है। |
| 22 | 📧 Data Exfiltration Channels | bar | उच्च-वॉल्यूम SNS/SQS/SES/S3 PutObject कॉल (≥50/घंटा) का पता लगाता है जो एक्सफिल्ट्रेशन का संकेत दे सकते हैं। |
| 23 | 🔐 S3 SSE-C Encryption (Ransomware) | timeseries | हमलावर-प्रदत्त SSE-C keys के साथ पुनः-एन्क्रिप्ट की गई S3 objects, साथ ही bucket default-encryption परिवर्तनों का पता लगाता है। customer key के बिना पीड़ित decrypt नहीं कर सकता — एक cloud-native ransomware पैटर्न। |
| 24 | ⏳ S3 Lifecycle-Triggered Deletion | timeseries | S3 lifecycle rules का पता लगाता है जो objects को expire करते हैं, साथ ही lifecycle-config विलोपन। हमलावर DeleteObject कॉल जारी किए बिना समय के साथ चुपचाप डेटा हटाने के लिए एक छोटी expiration सेट करते हैं। |
| 25 | 🗃 RDS Query & Instance Manipulation | timeseries | RDS Data API queries, master-password resets, और snapshot restores का पता लगाता है। हमलावर सीधे डेटा पढ़ते हैं, पहुँच प्राप्त करने के लिए क्रेडेंशियल रीसेट करते हैं, या snapshots को उनके नियंत्रित instances में restore करते हैं। |
| 26 | 🔎 S3 Bucket Enumeration | bar | उन callers का पता लगाता है जो bucket और object metadata को खंगालते हैं (एक घंटे में ≥10 List/GetBucket* reads)। एक्सफिल्ट्रेशन से पहले मूल्यवान डेटा का पता लगाने का एक सामान्य प्रारंभिक चरण। |
| 27 | 🔑 Storage Re-Encryption for Impact | timeseries | एक स्पष्ट KMS key के साथ पुनः-एन्क्रिप्ट किए गए EBS/RDS snapshots और volumes, साथ ही default EBS encryption को disable करने का पता लगाता है। हमलावर-नियंत्रित key के साथ पुनः-एन्क्रिप्शन डेटा को फिरौती के लिए रोकता है। |
| 28 | 📝 Ransom Note Placement | timeseries | उन PutObject कॉल का पता लगाता है जिनकी ऑब्जेक्ट कुंजी फिरौती नोट जैसी दिखती है। अन्य रैनसमवेयर हंट के विपरीत यह प्रभाव का संकेत नहीं, पुष्टि करता है — नोट का अर्थ है कि भुगतान की माँग पहले ही की जा चुकी है। |
| 29 | 📐 Data Access Scope (Breach Notification) | bar | मापता है कि प्रत्येक प्रिंसिपल ने प्रतिदिन क्या पढ़ा: छुए गए बकेट और अनुमानित विशिष्ट ऑब्जेक्ट संख्या। यह GDPR अनुच्छेद 33 द्वारा अपेक्षित «रिकॉर्ड की अनुमानित संख्या» देता है। |
| 30 | 📤 Cross-Account Object Copy | timeseries | बकेट के बीच कॉपी किए गए ऑब्जेक्ट का पता लगाता है, जिसमें x-amz-copy-source हेडर वाले PutObject कॉल भी शामिल हैं। जिस खाते पर आपका नियंत्रण नहीं, वहाँ डेटा रखने से केवल यही निशान बचता है। |
| 31 | 🔗 Presigned URL Generation | bar | प्रति प्रिंसिपल प्रीसाइन्ड URL निर्माण गिनता है। प्रीसाइन्ड URL लिंक रखने वाले किसी को भी डेटा सौंप देता है — बिना किसी और प्रमाणीकरण और बिना किसी और CloudTrail रिकॉर्ड के। |

### ⚡ Compute & Serverless

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | उच्च-वॉल्यूम EC2 StopInstances/TerminateInstances (एक घंटे में ≥5) का पता लगाता है। ransomware व्यवधान या एक विनाशकारी हमले का संकेत देता है। |
| 2 | 🖥️ SSM Session / Run Command | timeseries | SSM StartSession, SendCommand, और automation निष्पादन का पता लगाता है। प्रबंधित instances के माध्यम से प्राथमिक lateral movement पथ। |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | EC2 Instance Connect और Serial Console access का पता लगाता है, जो हमलावरों को SSH key या bastion host के बिना browser या CLI से एक instance तक पहुँचने देता है। SSH keys के बिना हमलावरों के लिए एक प्राथमिक lateral-movement पथ। |
| 4 | 📝 EC2 User Data Modification | timeseries | ModifyInstanceAttribute कॉल का पता लगाता है जो userData फ़ील्ड को बदलते हैं। user data स्क्रिप्ट अगले boot पर root के रूप में चलती हैं, जो एक स्थायी code-execution बैकडोर प्रदान करती हैं। |
| 5 | ⚡ Lambda Function Tampering | timeseries | Lambda निर्माण, code अद्यतन, और permission परिवर्तनों का पता लगाता है। हमलावर persistence के लिए Lambda का उपयोग करते हैं। |
| 6 | 📦 Lambda Layer Addition | timeseries | Lambda layer प्रकाशन और permission परिवर्तनों का पता लगाता है। एक दुर्भावनापूर्ण shared layer प्रकाशित करना और इसे production functions में जोड़ना dependency chain में हमलावर code इंजेक्ट करता है। |
| 7 | 📦 ECS Task Definition | timeseries | ECS task definition पंजीकरण और service अद्यतनों का पता लगाता है। Pacu का ecs__backdoor_task_def एक दुर्भावनापूर्ण container image की ओर इशारा करने वाला नया task definition संस्करण पंजीकृत करता है, फिर इसे तैनात करने के लिए service को अद्यतन करता है — यह सब ECR को छुए बिना। |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | IAM instance profile association और प्रतिस्थापन का पता लगाता है। एक privileged profile संलग्न करना instance को lateral movement के लिए बढ़ी हुई permissions देता है। |
| 9 | 🖥 EC2 Instance Launches | timeseries | सभी RunInstances इवेंट को सूचीबद्ध करता है। असामान्य regions में अप्रत्याशित launches cryptomining का संकेत दे सकते हैं। |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | बड़े Spot Fleet अनुरोधों, Reserved Instance खरीद, और उच्च क्षमता के साथ Auto Scaling group निर्माण का पता लगाता है। cryptomining वित्तीय-प्रभाव संकेतक। |
| 11 | ☸️ EKS Cluster API Calls | timeseries | EKS cluster control-plane संशोधनों का पता लगाता है। सार्वजनिक API server एक्सपोज़र या rogue Fargate profiles container platform टेकओवर को सक्षम करते हैं। |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | ECR repository निर्माण/विलोपन, policy परिवर्तनों, और image pushes का पता लगाता है। एक production repository में दुर्भावनापूर्ण images इंजेक्ट करना एक आपूर्ति-श्रृंखला persistence तकनीक है। |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | EventBridge rule और EventBridge Scheduler संशोधनों का पता लगाता है। हमलावर बिना किसी लंबे समय तक चलने वाली प्रक्रिया के persistence स्थापित करने के लिए scheduled rules का उपयोग करते हैं। |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | Lightsail instance पहुँच, key pair संचालन, और port एक्सपोज़र का पता लगाता है। Pacu के पास तीन समर्पित Lightsail मॉड्यूल हैं (enum, download_ssh_keys, generate_temp_access)। Lightsail संसाधन मानक EC2 सुरक्षा सीमा के बाहर काम करते हैं। |
| 15 | 🛰 IMDS Options Weakening | timeseries | ModifyInstanceMetadataOptions कॉल का पता लगाता है जो IMDSv2 को वैकल्पिक बनाते हैं या metadata endpoint को फिर से सक्षम करते हैं। IMDS को कमजोर करना instance-role क्रेडेंशियल चुराने के लिए SSRF पथ को फिर से खोल देता है। |
| 16 | 💥 AMI & Snapshot Deletion | bar | AMIs के बल्क deregistration और EBS snapshots के विलोपन (एक घंटे में ≥5) का पता लगाता है। golden images और backups को नष्ट करना एक विनाशकारी हमले के दौरान recovery विकल्पों को समाप्त कर देता है। |
| 17 | 🖥 WorkSpaces Hijacking | timeseries | Amazon WorkSpaces प्रावधान और pool निर्माण का पता लगाता है। हमलावर पीड़ित की कीमत पर desktops शुरू करते हैं — EC2 सीमा के बाहर एक कम-निगरानी वाला compute-हाइजैकिंग चैनल। |

### 🤖 AI & LLM Abuse

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 🤖 Bedrock Model Invocation Spike | timeseries | एक घंटे में 50+ बार Bedrock models को invoke करने वाले principals का पता लगाता है। चोरी की गई क्रेडेंशियल (LLMjacking) पर उच्च-वॉल्यूम inference पीड़ित को प्रतिदिन दसियों हज़ार डॉलर का नुकसान पहुँचा सकता है। |
| 2 | 🔓 Bedrock Model Access Enablement | timeseries | foundation-model access सक्षम किए जाने या provisioned capacity खरीदे जाने का पता लगाता है। उन organizations में जिन्होंने कभी Bedrock नहीं अपनाया, यह लगभग शून्य-शोर LLMjacking संकेतक है — हमलावर का विशिष्ट पहला लेखन। |
| 3 | 🙈 Bedrock Invocation Logging Tampering | timeseries | Bedrock model-invocation logging के विलोपन या संशोधन का पता लगाता है, साथ ही account का दुरुपयोग करने से पहले हमलावरों द्वारा यह जाँचना कि logging सक्षम है या नहीं (एक दस्तावेज़ीकृत LLMjacking IOC)। |
| 4 | 🧭 Bedrock Reconnaissance Sweep | bar | उन callers की पहचान करता है जो 2+ regions में Bedrock models की गणना करते हैं या एक घंटे में 10+ गणना कॉल करते हैं। चोरी की गई key रखने वाले यह जानने के लिए regions को खंगालते हैं कि models कहाँ उपयोग करने योग्य हैं। |
| 5 | ⛔ Failed Bedrock Invocations | bar | विफल Bedrock invocations (AccessDenied / ValidationException) के बर्स्ट खोजता है। चोरी की गई key का परीक्षण एक कार्यशील संयोजन मिलने से पहले models और regions में विफलता तूफान उत्पन्न करता है। |
| 6 | 🔑 AgentCore Token Vault Abuse | bar | AgentCore टोकन वॉल्ट से जारी करने को प्रिंसिपल और स्रोत के अनुसार समेटता है। ये कॉल तृतीय-पक्ष OAuth टोकन और API कुंजियाँ बाँटते हैं, इसलिए दुरुपयोग AWS के बाहर की सेवाओं तक पहुँचता है। |
| 7 | 🚪 AgentCore Gateway Authorization Bypass | timeseries | AgentCore गेटवे और नीति परिवर्तनों का पता लगाता है, जिसमें Cedar नीति इंजन का LOG_ONLY पर उतरना भी शामिल है। केवल लॉग करने वाला प्राधिकरण भी सफलता लौटाता है, इसलिए आगे कुछ भी गलत नहीं दिखता। |
| 8 | 🧠 AgentCore Memory Integrity | timeseries | AgentCore Memory और Registry परिवर्तनों का पता लगाता है, जिसमें मेमोरी स्ट्रीम का किसी अन्य खाते के Kinesis ARN की ओर मोड़ा जाना भी शामिल है। दूषित दीर्घकालिक मेमोरी एजेंट के आगे के हर सत्र में बनी रहती है। |
| 9 | 📦 AgentCore Sandbox Network Mode Drift | timeseries | AgentCore कोड इंटरप्रेटर और ब्राउज़र की लाइफ़साइकल घटनाओं को नेटवर्क मोड सहित सूचीबद्ध करता है। मोड संपादित नहीं हो सकता, इसलिए हटाकर फिर बनाना ही सैंडबॉक्स की नेटवर्क पहुँच बढ़ाने का एकमात्र तरीका है। |
| 10 | 🙈 AgentCore Observability Tampering | timeseries | AgentCore मूल्यांकनकर्ता परिवर्तनों तथा X-Ray सैंपलिंग या ट्रेस गंतव्य परिवर्तनों का पता लगाता है। हमलावर द्वारा बनाया गया मूल्यांकनकर्ता हर उस प्रतिक्रिया को पढ़ता है जिसे वह आँकता है, और वैध माध्यम से मॉडल आउटपुट बाहर भेजता है। |

### 🌐 Network & Infrastructure

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 🔥 Security Group Modifications | timeseries | security group rule परिवर्तनों का पता लगाता है, विशेष रूप से किसी भी port पर 0.0.0.0/0 की अनुमति देने वाले नियम। |
| 2 | 🌊 VPC Flow Log Changes | timeseries | VPC Flow Logs के विलोपन का पता लगाता है। flow logs हटाने से नेटवर्क-स्तरीय साक्ष्य समाप्त हो जाता है — एक महत्वपूर्ण defense evasion संकेतक। |
| 3 | 🌐 CloudFront Distribution Tampering | timeseries | CloudFront distribution निर्माण और origin परिवर्तनों का पता लगाता है। origins को संशोधित करना MitM अवरोधन या डेटा संग्रह के लिए CDN ट्रैफ़िक को हमलावर-नियंत्रित servers पर रीडायरेक्ट करता है। |
| 4 | 🧱 Network ACL Changes | timeseries | Network ACL entry निर्माण, विलोपन, और प्रतिस्थापन का पता लगाता है। NACLs security groups को ओवरराइड करते हैं और पूरे subnets को हमलावरों के लिए खोल सकते हैं। |
| 5 | 🛣️ Route Table Changes | timeseries | route table संशोधनों का पता लगाता है। routes जोड़ना या बदलना ट्रैफ़िक को हमलावर-नियंत्रित hosts (MitM, ट्रैफ़िक हाइजैकिंग) पर रीडायरेक्ट कर सकता है। |
| 6 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | नए VPN connections, Direct Connect, और Transit Gateway attachments का पता लगाता है। हमलावर स्थायी C2 या डेटा एक्सफिल्ट्रेशन चैनलों के लिए गुप्त नेटवर्क टनल बनाते हैं। |
| 7 | 📡 Elastic IP Allocation / Association | timeseries | Elastic IP allocation और association का पता लगाता है। हमलावर एक स्थिर C2 अवसंरचना बनाने के लिए एक समझौता किए गए instance को एक निश्चित सार्वजनिक IP असाइन करते हैं। |
| 8 | 🗝️ EC2 Key Pair Creation | timeseries | CreateKeyPair और ImportKeyPair इवेंट का पता लगाता है। हमलावर instance पहुँच बनाए रखने के लिए एक persistence तंत्र के रूप में SSH keys बनाते या import करते हैं। |
| 9 | 📡 Network Infrastructure Changes | timeseries | VPC और नेटवर्क-स्तरीय परिवर्तनों का पता लगाता है जो हमलावर-नियंत्रित अवसंरचना स्थापित कर सकते हैं। |
| 10 | 🏷 ACM Certificate Operations | timeseries | ACM certificate अनुरोधों और विलोपन का पता लगाता है। हमलावर फ़िशिंग अवसंरचना बनाने के लिए हमलावर-नियंत्रित domains के लिए TLS certificates जारी करने हेतु समझौता किए गए accounts का उपयोग करते हैं। |
| 11 | 🔑 API Gateway Key Creation & Management | timeseries | API Gateway key निर्माण और REST API प्रबंधन का पता लगाता है। Pacu का api_gateway__create_api_keys स्थायी API क्रेडेंशियल बनाता है जो IAM key rotation से बच जाते हैं। हमलावर पहुँच नियंत्रणों को कमजोर करने के लिए API authorizers को भी संशोधित करते हैं। |
| 12 | 🌐 Route 53 & Domain Changes | timeseries | DNS record संपादन, hosted-zone परिवर्तन, और domain पंजीकरण/स्थानांतरण का पता लगाता है। हमलावर ट्रैफ़िक को रीडायरेक्ट करते हैं, dangling subdomains को टेकओवर करते हैं, या फ़िशिंग के लिए lookalike domains पंजीकृत करते हैं। |
| 13 | 🛡 DDoS Protection Weakening | timeseries | एज सुरक्षा को हटाने के बजाय ढीला किए जाने का पता लगाता है: WebACL की डिफ़ॉल्ट क्रिया को अनुमति में बदलना, नियम समूह ढीले करना, Shield सुरक्षा हटाना, CloudFront मूल को पुनर्निर्देशित करना। |

### 🕵 Threat Patterns

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | उन callers की पहचान करता है जिन्होंने एक घंटे में 10+ अलग केवल-पठनीय API कॉल चलाईं। सामान्य प्रारंभिक हमला चरण। |
| 2 | 🤖 Unusual User Agents | bar | दुर्लभ user agents (<5 इवेंट) को सूचीबद्ध करता है। Pacu या curl जैसे कस्टम टूलिंग हमलावर टूलिंग का संकेत दे सकते हैं। |
| 3 | 🌍 Multi-Region Activity | bar | एक दिन में 3+ regions में राइट्स करने वाली identities का पता लगाता है। भौगोलिक प्रसार समझौते का संकेत दे सकता है। |
| 4 | 🧭 Single-API Multi-Region Fan-Out | bar | एक ही प्रिंसिपल द्वारा एक ही API को एक घंटे में कई क्षेत्रों में दोहराने को चिह्नित करता है। स्क्रिप्टेड स्वीप का हस्ताक्षर, जो अन्य क्षेत्रीय हंट्स को दिखाई नहीं देता। |
| 5 | 🕵 First-Time API Calls (24h) | — | पिछले 24h में देखी गई लेकिन पहले कभी नहीं देखी गई API कॉल खोजता है। नवीन संचालन हमलावर टूलिंग का संकेत दे सकते हैं। |
| 6 | 🗺 First-Seen Region Activity | bar | उन AWS regions को खोजता है जिनकी पहली-कभी गतिविधि dataset के अंतिम 24h में आती है। कभी उपयोग न की गई region में संचालन करना region-आधारित निगरानी से cryptomining या staging छिपाने का एक क्लासिक तरीका है। |
| 7 | 🌙 Off-Hours Activity | bar | विन्यास-योग्य कार्यसमय-बाह्य विंडो में गतिविधि को प्रिंसिपल और दिन के घंटे के अनुसार समूहित करता है। यह आंतरिक खतरा प्लेबुक का पहला संकेतक है, जिसे कोई अन्य हंट कवर नहीं करता। |
| 8 | 🪞 Self-Service Privilege Escalation | timeseries | किसी प्रिंसिपल द्वारा अपनी ही अनुमतियाँ बदलने का पता लगाता है — कॉल करने वाला ARN और लक्ष्य उपयोगकर्ता या रोल नाम समान होते हैं। मौजूदा वृद्धि हंट अनुदान तो देखते हैं पर यह चूक जाते हैं कि वह स्वयं पर लागू था। |
| 9 | 📈 Principal Daily Volume Deviation | bar | प्रत्येक प्रिंसिपल की दैनिक कॉल मात्रा की तुलना उसके अपने औसत से करता है, पठन और लेखन को अलग करते हुए। यह उस निष्कासन को पकड़ता है जो केवल अनुमत API उपयोग करता है, जहाँ विसंगति क्रिया नहीं मात्रा है। |
| 10 | 🗺 Resource Creation Outside Normal Regions | bar | उन क्षेत्रों में संसाधन निर्माण को चिह्नित करता है जिनका खाता शायद ही उपयोग करता है, जहाँ आधाररेखा हार्डकोड के बजाय डेटा से ली जाती है। क्रिप्टोमाइनिंग और निजी परियोजनाएँ दोनों यहीं दिखती हैं। |
| 11 | 📞 High-Volume API Calls per Principal | bar | 50 से अधिक सफल कॉल वाले प्रिंसिपल-API युग्मों को पहली और अंतिम कॉल सहित सूचीबद्ध करता है। गणना, थोक निष्कर्षण और थोक विलोपन — तीनों का यही आकार है। |

### 📊 Activity & Baseline

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | AWS console के माध्यम से की गई म्यूटेटिंग API कॉल की पहचान करता है। तब उपयोगी जब केवल CLI पहुँच अपेक्षित हो। |
| 2 | 🔍 Events with Errors (24h) | timeseries | पिछले 24 घंटों में सभी error इवेंट को सूचीबद्ध करता है। अभी क्या विफल हो रहा है इसका त्वरित अवलोकन। |
| 3 | ❌ Error Spike Detection | — | वे 1-घंटे की विंडो खोजता है जहाँ error count दैनिक औसत से 3× अधिक हो। scanning या outage का संकेत देता है। |

### 🌍 GeoIP Analysis

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 🚨 Unusual Country Access | bar | दुर्लभ country/identity संयोजन दिखाकर अप्रत्याशित देशों से API कॉल का पता लगाता है। |
| 2 | 🚫 Access Denied by Country | bar | access denied errors को source country द्वारा समूहित करता है। एक देश से केंद्रित denials एक हमले का संकेत दे सकते हैं। |

### ☁ IaC & Platform

| # | लेबल | चार्ट | विवरण |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | CI/CD pipeline निर्माण और संशोधन का पता लगाता है। दुर्भावनापूर्ण build steps इंजेक्ट करना या pipeline sources संशोधित करना सभी बाद के deployments को विषाक्त करता है। |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | CloudFormation stack संचालन का पता लगाता है। हमलावर दुर्भावनापूर्ण अवसंरचना को तेजी से deploy करने के लिए IaC का उपयोग कर सकते हैं। |

</details>

---

## 📊 डैशबोर्ड चार्ट — 118 चार्ट

| टैब | चार्ट | यह क्या दिखाता है |
|-----|:------:|---------------|
| 🚦 Overview | 10 | 9 triage KPI cards (इवेंट, principals, IPs, root, MFA-रहित logins, access denied, defense evasion, countries, regions) + वैश्विक इवेंट-वॉल्यूम रुझान |
| 🎯 Threat Detection | 16 | defense-evasion कैच-ऑल · logging gaps · VPC flow log/Config/EventBridge/WAF छेड़छाड़ · SCP/org-membership परिवर्तन · error और throttling रुझान · write/read अनुपात · P1/P2 वृद्धि ट्रिगर KPI कार्ड |
| 🔑 Identity & Access | 36 | console logins · MFA रुझान · login heatmap · failed→success auth अनुक्रम · root उपयोग · IAM entity गतिविधि/विलोपन · privilege-escalation timeline · नए principals · SSO · cross-account AssumeRole · AssumeRoot उपयोग |
| 🚨 High-Risk API Monitor | 5 | सुरक्षा-सेवा छेड़छाड़ & credential-retrieval API लॉग · शीर्ष high-risk calls · शीर्ष actors · समय के साथ high-risk call वॉल्यूम |
| 📊 API Activity | 6 | शीर्ष APIs · access-denied actions · region वितरण · error-code संरचना · source IPs · user agents |
| 🪣 S3 & RDS | 19 | S3 बल्क download/deletion · versioning/logging disabled · cross-account replication · bucket policy/ACL · enumeration · protection config · Backup vault विलोपन · KMS key विलोपन · RDS snapshot share / snapshot के बिना विलोपन · SSE-C ransomware एन्क्रिप्शन · lifecycle-triggered विलोपन · RDS query/instance हेरफेर · प्रभाव के लिए storage पुनः-एन्क्रिप्शन · उल्लंघन अधिसूचना हेतु पहुँच दायरा · क्रॉस-अकाउंट ऑब्जेक्ट कॉपी · फिरौती नोट रखना |
| 🖥️ Computing | 17 | EC2 launches/mass-stop/key pairs/instance profile/user-data/snapshot sharing/spot fleet · ECS/Lambda/SSM/EBS Direct API/EKS-ECR/CloudFormation · IMDS कमजोर करना · AMI/snapshot विलोपन · WorkSpaces हाइजैकिंग |
| 🤖 AI / LLM | 6 | Bedrock invocation रुझान · model access & logging परिवर्तन · विफल invocations · origin द्वारा callers (LLMjacking triage) · AgentCore टोकन जारी करना · गेटवे और नीति परिवर्तन |
| 🌐 Network | 5 | security group परिवर्तन · NACL/route table परिवर्तन · VPC अवसंरचना · VPC peering/Transit Gateway · Route53 DNS परिवर्तन |
| 🕒 Temporal Analysis | 8 | इवेंट velocity स्पाइक्स · पुनः सक्रिय dormant accounts · identity/IP/API/service source द्वारा first/last seen · कार्यसमय-बाह्य लेखन हीटमैप · प्रिंसिपल दैनिक पठन/लेखन मात्रा |
| 🌍 GeoIP Intelligence | 6 | impossible travel (multi-country principals) · शीर्ष countries/cities/ASNs · विश्व मानचित्र · event_name × country |

<details markdown="1">
<summary>📋 पूरी सूची — सभी 118 चार्ट (विस्तृत करने के लिए क्लिक करें)</summary>

## डैशबोर्ड चार्ट (Apache Superset — `dashboard/`)

### 🚦 Overview

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | Total Events | चयनित सीमा में CloudTrail इवेंट की कुल संख्या (KPI-81)। triage के लिए denominator — हर प्रति-principal या प्रति-IP अनुपात के लिए आधार। |
| 2 | Distinct Principals | चयनित सीमा में सक्रिय अद्वितीय IAM principal ARNs की गणना (KPI-82)। यह जानने के लिए उपयोग करें कि समीक्षाधीन गतिविधि में कितनी identities शामिल हैं। |
| 3 | Distinct Source IPs | चयनित सीमा में अद्वितीय caller source IP addresses की गणना (KPI-83)। बेसलाइन की तुलना में एक उछाल proxy/VPN rotation या distributed access का सुझाव देता है। |
| 4 | Root Account Events | account root identity द्वारा किए गए इवेंट की संख्या (KPI-84)। Root गतिविधि लगभग शून्य होनी चाहिए — कोई भी गैर-शून्य मान जाँच की गारंटी देता है। |
| 5 | MFA-less Console Logins | चयनित सीमा में बिना MFA के console logins की संख्या (KPI-85)। क्रेडेंशियल समझौते का प्रत्यक्ष संकेतक — MFA-less Login Trend में गहराई से जाएँ। |
| 6 | Access Denied Events | चयनित सीमा में authorization-विफलता इवेंट की संख्या (KPI-86)। एक स्पाइक recon या privilege probing का सुझाव देती है — principal/IP द्वारा pivot करें। |
| 7 | Defense-Evasion Hits | चयनित सीमा में audit/monitoring छेड़छाड़ इवेंट की संख्या (KPI-87)। उच्चतम-प्राथमिकता triage संकेत — कोई भी गैर-शून्य मान इसका अर्थ है कि detection अक्षम किया गया हो सकता है। Security Monitoring & Control Changes में गहराई से जाएँ। MITRE ATT&CK: TA0005 Defense Evasion। |
| 8 | Distinct Countries | चयनित सीमा में अद्वितीय source countries की गणना (KPI-88)। GeoIP संवर्धन की आवश्यकता है (docker/data/geoip/)। व्यापक प्रसार अप्रत्याशित भौगोलिक मूलों से पहुँच का सुझाव देता है। |
| 9 | Active Regions | चयनित सीमा में गतिविधि के साथ अलग AWS regions की गणना (KPI-89)। अप्रयुक्त regions में गतिविधि संसाधन दुरुपयोग या हमलावर staging का संकेत दे सकती है। |
| 10 | CloudTrail Events Over Time | समय के साथ प्रति घंटा Read बनाम Write इवेंट वॉल्यूम (DSH-01)। स्टैक किए गए bars Read/Write विभाजन दिखाते हैं: write_events में अचानक वृद्धि यह संकेत देती है कि एक हमलावर recon से सक्रिय शोषण की ओर बढ़ रहा है। गतिविधि स्पाइक्स और ऑफ-ऑवर्स संचालन की पहचान के लिए उपयोगी। |

### 🎯 Threat Detection

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | Security Monitoring & Control Changes | सभी defense-evasion इवेंट के लिए व्यापक कैच-ऑल (DSH-22)। CloudTrail छेड़छाड़ (StopLogging, DeleteTrail), GuardDuty disabling, AWS Config disabling, VPC Flow Log विलोपन, CloudWatch log विलोपन, और सुरक्षा सेवा disabling (SecurityHub, IAM Access Analyzer) को कवर करता है। यहाँ कोई भी इवेंट तत्काल जाँच की गारंटी देता है। गहन विश्लेषण के लिए समर्पित चार्ट का उपयोग करें: VPC Flow Log Changes (DSH-42), AWS Config Tampering (DSH-43), EventBridge/CW Tampering (DSH-47)। MITRE ATT&CK: TA0005 Defense Evasion। |
| 2 | CloudTrail Logging Gap (Hourly Volume) | प्रति घंटा CloudTrail इवेंट वॉल्यूम (DSH-91)। सक्रिय अवधियों के बीच शून्य पर अचानक गिरावट यह संकेत देती है कि logging disable किया गया था (StopLogging/DeleteTrail) या एक delivery blind spot मौजूद है। Security Monitoring & Control Changes तालिका के मुकाबले किसी भी अप्रत्याशित अंतराल की जाँच करें। MITRE ATT&CK: T1562.008 Impair Defenses — Disable Cloud Logs। |
| 3 | VPC Flow Log Changes | VPC Flow Log निर्माण और विलोपन इवेंट (DSH-42)। DeleteFlowLogs प्राथमिक नेटवर्क फोरेंसिक साक्ष्य स्रोत को समाप्त कर देता है, जिससे lateral movement और डेटा एक्सफिल्ट्रेशन का post-incident विश्लेषण असंभव हो जाता है। किसी घटना के दौरान CreateFlowLogs एक हमलावर-नियंत्रित S3 bucket में log redirection का संकेत दे सकता है। MITRE ATT&CK: TA0005 Defense Evasion। |
| 4 | AWS Config Recorder & Rule Changes | AWS Config recorder और rule छेड़छाड़ इवेंट (DSH-43): StopConfigurationRecorder, DeleteConfigurationRecorder, DeleteDeliveryChannel, DeleteConfigRule, और PutConfigRule। Config recorder को रोकना पूरी region के लिए अनुपालन साक्ष्य और change-tracking को समाप्त कर देता है, जिससे बाद के अवसंरचना परिवर्तन Config rules और Security Hub standards द्वारा अपरिचित रह जाते हैं। MITRE ATT&CK: TA0005 Defense Evasion। |
| 5 | EventBridge & CloudWatch Rule Modifications | EventBridge और CloudWatch Events rule छेड़छाड़ (DSH-47): DeleteRule, DisableRule (scheduled detection को मौन करना), CreateSchedule/UpdateSchedule (C2 beaconing के लिए हमलावर cron jobs), PutSubscriptionFilter (CloudTrail/VPC logs को हमलावर account पर रीडायरेक्ट करना), DeleteLogGroup (VPC Flow Log records को नष्ट करना)। DFIR के लिए संयुक्त monitoring-layer छेड़छाड़ चार्ट। MITRE ATT&CK: TA0003 Persistence / TA0005 Defense Evasion / TA0011 C2। |
| 6 | WAF Configuration Changes | AWS WAF v2 / WAF Classic कॉन्फ़िगरेशन परिवर्तन इवेंट (DSH-75)। WebACL निर्माण/अद्यतन/विलोपन, IP set हेरफेर, rule group परिवर्तन, logging कॉन्फ़िगरेशन परिवर्तन, और सुरक्षित संसाधनों के साथ WAF association/disassociation को कवर करता है। हमला जारी रहते हुए WAF rules या logging को disable करना defense-evasion का एक मजबूत संकेतक है। MITRE ATT&CK: TA0005 Defense Evasion / TA0003 Persistence। |
| 7 | Organizations / SCP Changes | SCP policy परिवर्तनों सहित AWS Organizations management-plane इवेंट (DSH-24)। master-account पहुँच वाला हमलावर पूरी AWS organization में निवारक नियंत्रणों को हटाने के लिए SCP guardrails disable कर सकता है। MITRE ATT&CK: TA0004 Privilege Escalation / TA0005 Defense Evasion। |
| 8 | Error Event Trend | error_code द्वारा विभाजित प्रति घंटा error इवेंट (DSH-04)। ThrottlingException स्पाइक्स automated scanning या attack tooling का संकेत देते हैं; AccessDenied / UnauthorizedAccess स्पाइक्स privilege probing का संकेत देते हैं; नए error codes का अचानक प्रकट होना नवीन attack techniques का संकेत दे सकता है। |
| 9 | Throttling Exception Spikes | AWS service द्वारा विभाजित प्रति घंटा throttling / rate-limit errors (DSH-21)। ThrottlingException स्पाइक्स संकेत देती हैं कि एक identity (या tool) अपेक्षा से कहीं अधिक तेजी से API कॉल जारी कर रही है, जो recon या enumeration करने वाले automated attack tooling की पहचान है। MITRE ATT&CK: TA0007 Discovery। |
| 10 | Write/Read Ratio Trend | read बनाम write API कॉल का प्रति घंटा विभाजन (DSH-20)। read_events के सापेक्ष write_events में निरंतर वृद्धि यह संकेत देती है कि एक हमलावर recon से सक्रिय शोषण की ओर बढ़ चुका है। MITRE ATT&CK: TA0040 Impact / TA0007 Discovery। |
| 11 | CloudTrail Events Over Time | समय के साथ प्रति घंटा Read बनाम Write इवेंट वॉल्यूम (DSH-01)। स्टैक किए गए bars Read/Write विभाजन दिखाते हैं: write_events में अचानक वृद्धि यह संकेत देती है कि एक हमलावर recon से सक्रिय शोषण की ओर बढ़ रहा है। गतिविधि स्पाइक्स और ऑफ-ऑवर्स संचालन की पहचान के लिए उपयोगी। |
| 12 | Organization Membership Changes | Organizations membership परिवर्तन जो accounts को guardrails से अलग करते हैं या उन्हें हमलावर-नियंत्रित organization के तहत ले जाते हैं। Threat Technique Catalog for AWS: T1666.A002 / T1666.A003। |
| 13 | P1 Escalation Triggers | TRIAGE_GUIDE के उन वृद्धि ट्रिगर से मेल खाती घटनाएँ जिनमें 15 मिनट के भीतर प्रतिक्रिया आवश्यक है: root उपयोग, लॉगिंग या पहचान से छेड़छाड़, फिरौती नोट, प्रत्यायोजित व्यवस्थापक पंजीकरण। शून्य से भिन्न का अर्थ है घड़ी शुरू। |
| 14 | P2 Escalation Triggers | TRIAGE_GUIDE की उन शर्तों से मेल खाती घटनाएँ जिनमें एक घंटे में प्रतिक्रिया चाहिए: क्रेडेंशियल निर्माण, विशेषाधिकार अनुदान, ट्रस्ट नीति संपादन और क्रॉस-अकाउंट रोल ग्रहण। इसे P1 कार्ड के साथ पढ़ें। |
| 15 | Security Monitoring Posture Recon | वे कॉल जो पूछती हैं कि खाता देखा जा रहा है या नहीं (DSH-116): DescribeTrails, GetTrailStatus, ListDetectors, DescribeConfigurationRecorders। यहाँ टोह लेने के बाद उसी प्रिंसिपल द्वारा DSH-22 में छेड़छाड़ — यही वह क्रम है जिसे एस्केलेट करना चाहिए। Threat Technique Catalog for AWS: T1087, T1562.008। |
| 16 | Single-API Multi-Region Fan-Out | वे प्रिंसिपल जो एक ही API नाम को 3+ क्षेत्रों में कॉल करते हैं (DSH-117)। यह Region Activity का पठन-सहित समकक्ष है, जो केवल लेखन गिनता है; वैश्विक सेवाएँ बाहर रखी गई हैं। Threat Technique Catalog for AWS: T1535। |

### 🔑 Identity & Access

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | Console Login Activity | IAM identity द्वारा समूहित AWS Management Console sign-in इवेंट (DSH-08)। सफल, विफल, और MFA-रहित login प्रयासों को ट्रैक करता है। उच्च failure-to-success अनुपात brute-force या credential stuffing का संकेत दे सकता है। mfa_less_count (MFAUsed = 'No') account समझौते का प्रत्यक्ष संकेतक है, हालाँकि यह केवल क्लासिक ConsoleLogin इवेंट पर लागू होता है — नया OAuth2 sign-in flow (CreateOAuth2Token / AuthorizeOAuth2Access) MFA स्थिति की रिपोर्ट नहीं करता। इवेंट को event_type = 'AwsConsoleSignIn' पर फ़िल्टर किया गया है। |
| 2 | MFA-less Login Trend | MFA उपयोग द्वारा विभाजित दैनिक console logins (DSH-28)। mfa_less_logins (MFAUsed = 'No') account समझौते या फ़िशिंग का प्रत्यक्ष संकेतक है; MFA-less logins में निरंतर वृद्धि से IAM authentication policies की तत्काल समीक्षा होनी चाहिए। MITRE ATT&CK: TA0001 Initial Access। |
| 3 | Failed -> Success Auth Sequence | प्रति principal + source IP console login विफलताएँ और सफलताएँ (DSH-93)। गैर-शून्य success_count के साथ जोड़ी गई एक बड़ी failure_count एक brute force / password spray का संकेत देती है जो अंततः सफल हुआ — सफलता को समझौता बिंदु मानें और source IP पर pivot करें। MITRE ATT&CK: T1110 Brute Force। |
| 4 | Login Activity Heatmap (Hour x Day) | JST में hour-of-day (X) बनाम day-of-week (Y) के heatmap के रूप में console login गणना (DSH-19)। देर रात (22:00-06:00 JST) के columns या सप्ताहांत की rows में चमकीली cells account समझौते या क्रेडेंशियल दुरुपयोग का एक मजबूत संकेतक हैं। MITRE ATT&CK: TA0001 Initial Access। |
| 5 | Root Account Usage | AWS Root account द्वारा की गई सभी API कॉल (DSH-13)। अच्छी तरह से प्रशासित वातावरण में Root account का उपयोग अत्यंत दुर्लभ होना चाहिए। कोई भी Root गतिविधि — विशेष रूप से CreateAccessKey, ConsoleLogin, या StopLogging — समझौते या policy उल्लंघन का एक महत्वपूर्ण संकेतक है। |
| 6 | IAM Entity Activity | कुल API कॉल द्वारा रैंक की गई शीर्ष 50 IAM entities, write अनुपात और error विभाजनों के साथ (DSH-03)। उच्च write_ratio_pct या total_events के सापेक्ष error_events वाली entities क्रेडेंशियल दुरुपयोग या विशेषाधिकार वृद्धि का संकेत दे सकती हैं। last_seen प्रत्येक entity के लिए सबसे हालिया गतिविधि टाइमस्टैम्प दिखाता है। |
| 7 | IAM Privilege Change Event Timeline | event name द्वारा विभाजित विशेषाधिकार-वृद्धि API कॉल की दैनिक गणना (DSH-30)। एक ही दिन पर एक स्पाइक एक लक्षित हमला अभियान का संकेत देती है; एक धीमी वृद्धि insider threat या स्थायी पकड़ वाले हमलावर का संकेत दे सकती है। MITRE ATT&CK: TA0004 Privilege Escalation। |
| 8 | New IAM Principal Creation Timeline | event type द्वारा स्टैक की गई दैनिक IAM principal और क्रेडेंशियल निर्माण इवेंट (DSH-95)। CreateAccessKey / CreateLoginProfile / CreateUser में एक स्पाइक initial access के बाद एक persistence संकेतक है — इसे acting principal और source IP के साथ सहसंबंधित करें। MITRE ATT&CK: T1136 Create Account / T1098 Account Manipulation। |
| 9 | Glue & SageMaker IAM Role Pass Events | IAM विशेषाधिकार वृद्धि के लिए उपयोग किए जाने वाले Glue DevEndpoint और SageMaker Notebook इवेंट (DSH-50)। iam:PassRole + glue:CreateDevEndpoint पास किए गए role की पूर्ण permissions के साथ एक SSH-सुलभ environment बनाता है। iam:PassRole + sagemaker:CreateNotebookInstance उसी प्रभाव के साथ एक Jupyter notebook प्रदान करता है। अकेले sagemaker:CreatePresignedNotebookInstanceUrl अंतर्निहित role का मालिक हुए बिना एक मौजूदा notebook तक पहुँच प्रदान कर सकता है। दोनों AWS-IAM-Privilege-Escalation repository में दस्तावेज़ीकृत हैं और Pacu के iam__privesc_scan मॉड्यूल में लागू हैं। MITRE ATT&CK: TA0004 Privilege Escalation। |
| 10 | AssumedRole from External IP | सार्वजनिक (non-private) IP addresses से उत्पन्न AssumedRole API कॉल (DSH-27)। EC2 instance metadata service (IMDS) क्रेडेंशियल आमतौर पर केवल VPC के भीतर से उपयोग की जाती हैं। बाहरी IPs से कॉल यह संकेत देते हैं कि अस्थायी क्रेडेंशियल लीक हो गई हैं — आमतौर पर SSRF, container escape, या key export के माध्यम से। MITRE ATT&CK: TA0008 Lateral Movement / TA0006 Credential Access। |
| 11 | Cross-Account AssumeRole | AssumeRole / AssumeRoleWithWebIdentity कॉल जहाँ recipient_account_id caller के account से भिन्न है (DSH-94)। अप्रत्याशित बाहरी account IDs trusted-relationship दुरुपयोग या accounts के बीच lateral movement का संकेत देते हैं — सत्यापित करें कि प्रत्येक गंतव्य account एक अनुमोदित trust है। MITRE ATT&CK: T1199 Trusted Relationship / TA0008 Lateral Movement। |
| 12 | Secrets Access Anomaly | एक घंटे में ≥10 बार Secrets Manager या SSM Parameter Store तक पहुँचने वाली identities (DSH-23)। बल्क क्रेडेंशियल reads एक post-exploitation संकेतक हैं: हमलावर अन्य सेवाओं या accounts में pivot करने के लिए संग्रहीत secrets एकत्र करते हैं। MITRE ATT&CK: TA0006 Credential Access / TA0010 Exfiltration। |
| 13 | Security-Relevant API Calls | ज्ञात सुरक्षा-संवेदनशील AWS API क्रियाओं का आह्वान (DSH-12)। IAM क्रेडेंशियल परिवर्तन, policy संशोधन, S3 bucket policy परिवर्तन, security group संशोधन, key management, STS token संचालन, सुरक्षा सेवा disabling, Secrets Manager reads, और Organizations management को कवर करता है। सामान्य संचालन में ये कॉल दुर्लभ होनी चाहिए; अप्रत्याशित घटनाएँ विशेषाधिकार वृद्धि, persistence, या डेटा एक्सफिल्ट्रेशन का संकेत दे सकती हैं। |
| 14 | IAM Identity Center (SSO) Events | sso.amazonaws.com, sso-directory.amazonaws.com, sso-oauth.amazonaws.com, और identitystore.amazonaws.com से AWS IAM Identity Center प्रबंधन इवेंट (DSH-44)। Identity Center बहु-account organizations में प्राथमिक प्रमाणीकरण पथ है। मुख्य खतरे: CreatePermissionSet (बैकडोर admin access), CreateAccountAssignment (accounts को हमलावर-नियंत्रित users को असाइन करना), और AttachManagedPolicyToPermissionSet (विशेषाधिकार वृद्धि)। MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence / TA0004 Privilege Escalation। |
| 15 | IAM Entity Deletion | IAM users, roles, policies, और MFA devices का विलोपन जो हमलावर-निर्मित identities के निशान मिटाने या defenders को बाहर बंद करने के लिए उपयोग किया जाता है। Threat Technique Catalog for AWS: T1070.A001। |
| 16 | AssumeRoot Usage | management account से member-account root में sts:AssumeRoot कॉल — एक पूर्ण member-account टेकओवर पथ। Threat Technique Catalog for AWS: AT1669। |
| 17 | Role Chaining (Session → Role) | रोल चेन हॉप — ग्रहण किया गया रोल सत्र एक और रोल ग्रहण करता है। गहराई ही संकेत है। इसके लिए प्रोन्नत session_issuer_arn कॉलम आवश्यक है। |
| 18 | Session Credential Trace (ASIA keys) | प्रत्येक अस्थायी STS सत्र ने क्या किया, ASIA एक्सेस की के अनुसार: कॉल संख्या, विशिष्ट API, स्रोत IP, क्षेत्र और समयावधि। कई स्रोत IP वाले सत्र से शुरू करें। |
| 19 | API Calls Without MFA | बिना MFA प्रमाणीकरण वाले सत्रों द्वारा किए गए लेखन कॉल। बिना MFA कंसोल लॉगिन कार्ड के विपरीत, यह केवल ConsoleLogin नहीं बल्कि हर API कॉल को कवर करता है। |
| 20 | Federated Console Logins by Provider & Origin | बाहरी पहचान प्रदाता के माध्यम से कंसोल लॉगिन, प्रदाता नाम, देश और ASN सहित। जब IdP ही समझौता किया गया हो, तो AWS को केवल वैध लॉगिन दिखता है। |
| 21 | Identity Center Permission Set Grants | इवेंट नाम के अनुसार दैनिक IAM Identity Center विशेषाधिकार अनुदान। परमिशन सेट संगठन-व्यापी होता है: एक असाइनमेंट कभी न छुए गए खाते में व्यवस्थापक अधिकार दे सकता है। |

### 🚨 High-Risk API Monitor

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | Security Service Modification API Events | audit नियंत्रणों को disable या छेड़छाड़ करने के लिए उपयोग की जाने वाली APIs के लिए विस्तृत इवेंट लॉग (HRM-44)। कवर करता है: DeleteTrail, StopLogging, UpdateTrail, PutEventSelectors (CloudTrail छेड़छाड़), DeletePolicy और DetachPolicy (IAM guardrails हटाना)। किसी अनुमोदित change window के बाहर कोई भी घटना तत्काल जाँच की गारंटी देती है। MITRE ATT&CK: TA0005 Defense Evasion। |
| 2 | Credential Retrieval API Events | secrets और क्रेडेंशियल प्राप्त करने के लिए उपयोग की जाने वाली APIs के लिए विस्तृत इवेंट लॉग (HRM-45)। कवर करता है: GetSecretValue (Secrets Manager), GetParameter / GetParameterHistory (SSM)। एक ही कॉल वैध हो सकती है; तेज़ क्रम में एक्सेस किए गए दर्जनों अद्वितीय secrets एक मजबूत हमलावर संकेत है। MITRE ATT&CK: TA0006 Credential Access। |
| 3 | Top High-Risk API Calls | कुल कॉल गणना द्वारा रैंक की गई high-risk watchlist से API क्रियाएँ (HRM-40)। recon APIs (ListUsers, GetCallerIdentity) की बार-बार उपस्थिति कई वातावरणों में अपेक्षित है; credential-access और defense-evasion APIs पर जाँच केंद्रित करें जो असामान्य वॉल्यूम के साथ या अप्रत्याशित principals से दिखाई देती हैं। |
| 4 | Top Actors — High-Risk APIs | high-risk watchlist APIs की कुल कॉल द्वारा रैंक किए गए IAM principals (HRM-42)। यह देखने के लिए attack-category चार्ट के साथ क्रॉस-रेफरेंस करें कि प्रत्येक principal कौन सी क्रियाएँ कर रहा है। बार-बार AssumeRole कॉल करने वाली service roles अपेक्षित हैं; बल्क में GetSecretValue या DeleteTrail कॉल करने वाले मानव users नहीं हैं। |
| 5 | High-Risk API Events Over Time | attack campaigns में सामान्यतः देखी जाने वाली APIs के लिए दैनिक कॉल वॉल्यूम (HRM-39)। DeleteTrail या GetSecretValue जैसी सामान्यतः दुर्लभ क्रियाओं में अचानक स्पाइक तत्काल जाँच की गारंटी देती है। ध्यान दें कि इनमें से कई APIs वैध workflows में भी कॉल की जाती हैं — केवल उपस्थिति के बजाय वॉल्यूम विसंगतियों को प्राथमिक संकेत के रूप में उपयोग करें। MITRE ATT&CK: TA0001 / TA0003 / TA0004 / TA0005 / TA0006 / TA0007 / TA0008। |

### 📊 API Activity

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | Top 20 API Calls | 20 सबसे अधिक बार कॉल की जाने वाली AWS API क्रियाएँ (DSH-02)। संवेदनशील क्रियाओं (जैसे AssumeRole, GetSecretValue) के लिए उच्च कॉल गणना automated tooling या recon का संकेत दे सकती है। |
| 2 | Top Access Denied Actions | AccessDenied या Client.UnauthorizedAccess errors लौटाने वाली शीर्ष 20 API क्रियाएँ (DSH-09)। संवेदनशील APIs (जैसे AssumeRole, GetSecretValue, PutBucketPolicy) के खिलाफ बार-बार access-denied इवेंट विशेषाधिकार वृद्धि प्रयासों या lateral movement के मजबूत संकेतक हैं। |
| 3 | Region Activity | AWS regions में CloudTrail इवेंट का वितरण (DSH-14)। write_ratio_pct असंगत रूप से उच्च write गतिविधि वाले regions को उजागर करता है — उच्च write अनुपात वाले अप्रत्याशित regions cryptomining EC2 instances, lateral movement, या कम-निगरानी वाले regions में डेटा एक्सफिल्ट्रेशन का संकेत दे सकते हैं। |
| 4 | Error-Code Composition Over Time | error_code द्वारा स्टैक किया गया दैनिक CloudTrail error वॉल्यूम (DSH-96)। बढ़ता हुआ AccessDenied / UnauthorizedOperation band recon या privilege probing का संकेत देता है; Throttling स्पाइक्स बड़े पैमाने पर enumeration का सुझाव देती हैं। MITRE ATT&CK: TA0007 Discovery। |
| 5 | Top Source IP Addresses | अनुरोध गणना द्वारा शीर्ष 100 बाहरी source IPs (DSH-05)। AWS-internal IP पैटर्न को बाहर रखता है (*.amazonaws.com)। request_count के सापेक्ष उच्च write_requests वाली IPs एक्सफिल्ट्रेशन, lateral movement, या automated attack tooling का संकेत दे सकती हैं। |
| 6 | User Agent Analysis | error और write विभाजन के साथ अनुरोध गणना द्वारा शीर्ष 50 user agents (DSH-11)। असामान्य या कस्टम user agents (जैसे Python/boto3, कस्टम scripts, Pacu, ScoutSuite) automated attack tooling का संकेत दे सकते हैं। AWS internal agents (console.amazonaws.com, signin.amazonaws.com) अपेक्षित हैं; अज्ञात strings जाँच की गारंटी देती हैं। |

### 🪣 S3 & RDS

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | S3 High-Volume Object Downloads | S3 बल्क GetObject कॉल (DSH-52): वे identities जिन्होंने एक ही घंटे में ≥100 GetObject अनुरोध किए, hour bucket, identity, और source IP द्वारा समूहित। उच्च-वॉल्यूम reads automated data exfiltration का संकेत देते हैं — हमलावर bucket सामग्री को नष्ट करने या फिरौती माँगने से पहले उसे डंप करते हैं। पूर्ण ransomware chain की पहचान करने के लिए S3 Bulk Deletion चार्ट के साथ जोड़ें: exfiltrate फिर destroy। MITRE ATT&CK: TA0010 Exfiltration। |
| 2 | S3 Bulk Object Deletion | S3 बल्क DeleteObject/DeleteObjects कॉल (DSH-53): वे identities जिन्होंने एक ही घंटे में ≥50 objects हटाईं, hour bucket, identity, और source IP द्वारा समूहित। उच्च-वॉल्यूम विलोपन ransomware हमले का डेटा विनाश चरण है — हमलावर पहले exfiltrate करता है (S3 Bulk Download चार्ट देखें), फिर पीड़ित को जबरन वसूली करने के लिए source bucket मिटा देता है। आकस्मिक मास-विलोपन को भी कवर करता है। MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction। |
| 3 | S3 Versioning / Logging Disabled | S3 versioning निलंबन और logging disable इवेंट (DSH-54): Status=Suspended के साथ PutBucketVersioning और खाली BucketLoggingStatus के साथ PutBucketLogging। हमलावर विलोपन के बाद object recovery रोकने के लिए versioning disable करते हैं, और access साक्ष्य ट्रेल मिटाने के लिए logging disable करते हैं। दोनों डेटा विनाश के anti-forensics पूर्ववर्ती हैं। MITRE ATT&CK: TA0005 Defense Evasion / T1070 Indicator Removal। |
| 4 | S3 Cross-Account Replication | S3 cross-account replication कॉन्फ़िगरेशन इवेंट (DSH-55): PutBucketReplication और DeleteBucketReplication। cross-account replication चुपचाप हर नई object को एक हमलावर-नियंत्रित bucket में कॉपी करता है, जिससे एक स्थायी एक्सफिल्ट्रेशन चैनल बनता है जो नेटवर्क DLP नियंत्रणों को बायपास करता है। किसी बाहरी account ID की ओर इशारा करने वाला कोई भी PutBucketReplication एक महत्वपूर्ण घटना संकेतक है। MITRE ATT&CK: TA0010 Exfiltration / T1537 Transfer Data to Cloud Account। |
| 5 | S3 Bucket Policy / ACL Changes | S3 bucket policy और ACL संशोधन इवेंट (DSH-45): PutBucketPolicy, DeleteBucketPolicy, PutBucketAcl, PutBucketCors, PutBucketWebsite, और DeleteBucketWebsite। ये परिवर्तन bucket सामग्री को सार्वजनिक रूप से उजागर कर सकते हैं या हमलावर-नियंत्रित accounts को पहुँच प्रदान कर सकते हैं। Principal='*' के साथ PutBucketPolicy एक तत्काल डेटा एक्सपोज़र संकेतक है। MITRE ATT&CK: TA0010 Exfiltration / TA0005 Defense Evasion। |
| 6 | S3 Bucket & Object List Activity | identity और source IP द्वारा समूहित S3 enumeration API कॉल (DSH-74)। ListBuckets (पूर्ण-account discovery), ListObjects / ListObjectsV2 (प्रति-bucket enumeration), ListObjectVersions, ListMultipartUploads, HeadBucket, और HeadObject को कवर करता है। एक नई identity या बाहरी IP से list कॉल में अचानक स्पाइक क्रेडेंशियल समझौते के बाद recon का दृढ़ता से सुझाव देती है। MITRE ATT&CK: TA0007 Discovery। |
| 7 | S3 Protection Config Changes | S3 इवेंट जो bucket सुरक्षा स्थिति को कमजोर करते हैं (DSH-25)। server-access logging disable करना audit trail हटाता है; public-access block हटाना डेटा को इंटरनेट पर उजागर करता है; bucket encryption या replication हटाना डेटा-at-rest सुरक्षा को कमजोर करता है। ये pre-exfiltration या कवर-अप क्रियाएँ हैं। MITRE ATT&CK: TA0005 Defense Evasion / TA0040 Impact। |
| 8 | AWS Backup Vault & Plan Deletion Events | AWS Backup Vault, Plan, और Recovery Point विलोपन इवेंट (DSH-57): DeleteBackupVault, DeleteBackupPlan, DeleteRecoveryPoint, DeleteBackupSelection, DisassociateRecoveryPoint, PutBackupVaultAccessPolicy, और DeleteBackupVaultLockConfiguration। बैकअप नष्ट करना ransomware अभियान का पहला कदम है — यह सुनिश्चित करता है कि फिरौती की माँग से पहले पीड़ित बैकअप से restore न कर सके। Vault Lock विलोपन (DeleteBackupVaultLockConfiguration) विशेष रूप से महत्वपूर्ण है क्योंकि यह vault से WORM immutability हटा देता है। MITRE ATT&CK: TA0040 Impact / T1490 Inhibit System Recovery। |
| 9 | KMS Key Deletion & Disable Events | KMS key विलोपन, disabling, और rotation management इवेंट (DSH-66)। ScheduleKeyDeletion — key विलोपन शेड्यूल करता है (रद्द करने के लिए 7-30 दिन की विंडो)। DisableKey — key के साथ encryption/decryption को तुरंत रोकता है। DeleteImportedKeyMaterial — imported keys के लिए key material को तुरंत नष्ट करता है। DisableKeyRotation — स्वचालित वार्षिक key rotation को रोकता है। इनमें से कोई भी इवेंट key के तहत एन्क्रिप्ट किए गए सभी डेटा को स्थायी रूप से अगम्य बना देता है। विलोपन तिथि से पहले ScheduleKeyDeletion को उलटने के लिए CancelKeyDeletion का उपयोग करें। MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction। |
| 10 | RDS Deleted without Final Snapshot | skipFinalSnapshot=true के साथ RDS instance और cluster विलोपन (DSH-56): DeleteDBInstance और DeleteDBCluster इवेंट जहाँ कोई final snapshot नहीं लिया गया। final snapshot को छोड़ना database को अपुनर्प्राप्य बना देता है — विलोपन के बाद कोई restore point मौजूद नहीं होता। Ransomware actors इसका उपयोग तब पीड़ित पर दबाव अधिकतम करने के लिए करते हैं जब AWS Backup भी disable किया गया हो। यहाँ कोई भी इवेंट एक महत्वपूर्ण घटना है। MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction। |
| 11 | RDS Snapshot Cross-Account Share | RDS और Aurora snapshot साझाकरण इवेंट (DSH-40): ModifyDBSnapshotAttribute और ModifyDBClusterSnapshotAttribute जहाँ किसी अन्य AWS account को restore permission दी गई (valuesToAdd)। हमलावर S3/नेटवर्क-आधारित DLP के बिना एक पूरे database को exfiltrate करने के लिए snapshots को अपने खुद के account में साझा करते हैं। restore attribute में कोई भी बाहरी account ID एक महत्वपूर्ण एक्सफिल्ट्रेशन संकेतक है। MITRE ATT&CK: TA0010 Exfiltration। |
| 12 | S3 SSE-C Ransomware Encryption | हमलावर-प्रदत्त SSE-C keys के साथ पुनः-एन्क्रिप्ट की गई S3 objects, साथ ही bucket default-encryption परिवर्तन — cloud-native ransomware। Threat Technique Catalog for AWS: T1486.A001। |
| 13 | S3 Lifecycle-Triggered Deletion | S3 lifecycle rules जो objects को expire करते हैं (और lifecycle-config विलोपन), जिनका उपयोग DeleteObject बर्स्ट के बिना चुपचाप डेटा हटाने के लिए किया जाता है। Threat Technique Catalog for AWS: T1485.001। |
| 14 | RDS Query & Instance Manipulation | RDS Data API queries और snapshot restores जिनका उपयोग सीधे डेटा पढ़ने या हमलावर-नियंत्रित instance में restore करने के लिए किया जाता है। Threat Technique Catalog for AWS: AT1023.001 / T1213.A013। |
| 15 | Storage Re-Encryption for Impact | एक स्पष्ट हमलावर-नियंत्रित KMS key के साथ पुनः-एन्क्रिप्ट किए गए EBS/RDS snapshots और volumes, साथ ही default-encryption disable। Threat Technique Catalog for AWS: T1486.A002 / T1486.A003। |
| 16 | Data Access Scope (Breach Notification) | प्रति प्रिंसिपल: S3 पठन कॉल, विशिष्ट बकेट और अनुमानित विशिष्ट ऑब्जेक्ट। GDPR अनुच्छेद 33 द्वारा अपेक्षित आँकड़ा देता है। बकेट पर CloudTrail डेटा इवेंट आवश्यक हैं। |
| 17 | Cross-Account Object Copy | S3 CopyObject कॉल और x-amz-copy-source हेडर वाले PutObject कॉल, स्रोत और गंतव्य सहित। प्रतिकृति चार्ट विन्यास को कवर करते हैं; यह व्यक्तिगत प्रतियों को। |
| 18 | Ransom Note Placement | वे PutObject कॉल जिनकी ऑब्जेक्ट कुंजी फिरौती नोट जैसी दिखती है। अन्य रैनसमवेयर पैनल के विपरीत यह प्रभाव की पुष्टि करता है — यहाँ कोई भी पंक्ति P1 है। |
| 19 | SES / SNS Sending Quota Abuse | प्रेषण कोटा और बल्क-भेजने की घटनाएँ (DSH-118): MonthlySpendLimit बढ़ाने वाला SetSMSAttributes, SES को पुनः सक्रिय करने वाला UpdateAccountSendingEnabled, SendRawEmail / SendBulkTemplatedEmail। हर एक अकेली कॉल है, इसलिए मात्रा-आधारित सीमाएँ इन तक कभी नहीं पहुँचतीं। Threat Technique Catalog for AWS: T1496.003, T1496.A001। |

### 🖥️ Computing

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | EC2 Instance Launches | सभी EC2 RunInstances इवेंट (DSH-58)। हमलावर crypto mining (GPU/spot), C2 relay, या lateral movement staging के लिए instances लॉन्च करते हैं — अक्सर detection से बचने के लिए अप्रत्याशित regions में। region-anomaly जाँच के लिए aws_region द्वारा फ़िल्टर करें; यह पता लगाने के लिए कि किस क्रेडेंशियल ने launch को ट्रिगर किया, user_identity_arn द्वारा फ़िल्टर करें। MITRE ATT&CK: TA0002 Execution / TA0040 Impact (Resource Hijacking)। |
| 2 | RunInstances Spike by Region | AWS region द्वारा स्टैक किया गया दैनिक EC2 RunInstances वॉल्यूम (DSH-97)। एक अचानक स्पाइक — विशेष रूप से सामान्य संचालन के बाहर के regions में — cryptomining या संसाधन दुरुपयोग का संकेत देती है। acting principal और source IP का क्रॉस-रेफरेंस करें। MITRE ATT&CK: T1496 Resource Hijacking। |
| 3 | EC2 Mass Stop / Terminate | EC2 StopInstances और TerminateInstances इवेंट (DSH-62)। एक ही API कॉल एक साथ दर्जनों instances को stop या terminate कर सकती है। Mass termination एक ransomware या sabotage हमले का विनाशकारी चरण है — जो production EC2 क्षमता को गिरा देता है। प्रभावित instanceIds की पूरी सूची के लिए request_parameters फ़ील्ड देखें। पूर्ण ransomware chain की पहचान करने के लिए AWS Backup Tampering और S3 Bulk Deletion चार्ट के साथ जोड़ें। MITRE ATT&CK: TA0040 Impact / T1489 Service Stop। |
| 4 | EC2 Key Pair Creation | EC2 key pair निर्माण और import इवेंट (DSH-59): CreateKeyPair, ImportKeyPair, DeleteKeyPair। हमलावर EC2 instances तक स्थायी SSH पहुँच स्थापित करने के लिए नए key pairs बनाते हैं जो IAM क्रेडेंशियल rotation से बच जाते हैं। ImportKeyPair AWS द्वारा जनरेट किए बिना सीधे एक हमलावर-नियंत्रित public key इंजेक्ट करता है। किसी अपरिचित identity या IP से कोई भी CreateKeyPair या ImportKeyPair एक persistence संकेतक है। MITRE ATT&CK: TA0003 Persistence। |
| 5 | EC2 Instance Profile Changes | EC2 instance profile और IAM instance profile management इवेंट (DSH-60)। IAM: CreateInstanceProfile, DeleteInstanceProfile, AddRoleToInstanceProfile, RemoveRoleFromInstanceProfile। EC2: AssociateIamInstanceProfile, DisassociateIamInstanceProfile, ReplaceIamInstanceProfileAssociation। instance profile बदलना उस IAM role को बदल देता है जो instance पर सभी code के लिए उपलब्ध है — एक सामान्य विशेषाधिकार वृद्धि पथ जब हमलावर एक instance को नियंत्रित करता है लेकिन एक उच्च-विशेषाधिकार role चाहता है। MITRE ATT&CK: TA0004 Privilege Escalation / TA0003 Persistence। |
| 6 | EC2 User Data Modification | EC2 user data संशोधन इवेंट (DSH-61): ModifyInstanceAttribute जहाँ userData attribute बदला गया है। EC2 user data हर instance (पुनः) start पर cloud-init द्वारा निष्पादित किया जाता है — एक दुर्भावनापूर्ण script इंजेक्ट करना एक स्थायी code execution प्रदान करता है जो reboots से बच जाता है। अक्सर निष्पादन को ट्रिगर करने के लिए एक stop/start क्रम (EC2 Mass Stop / Terminate चार्ट देखें) के साथ जोड़ा जाता है। MITRE ATT&CK: TA0003 Persistence / TA0002 Execution। |
| 7 | EC2 Public Snapshot / AMI Sharing | EC2 EBS snapshot और AMI public-sharing इवेंट (DSH-41): group 'all' को दी गई createVolumePermission के साथ ModifySnapshotAttribute, और group 'all' को दी गई launchPermission के साथ ModifyImageAttribute। एक public snapshot या AMI किसी भी AWS account को disk image कॉपी करने और volume पर संग्रहीत संवेदनशील डेटा, क्रेडेंशियल, और private keys निकालने की अनुमति देता है। MITRE ATT&CK: TA0010 Exfiltration। |
| 8 | EC2 Spot Fleet & Reserved Instance Purchases | EC2 Spot Fleet, Fleet, और Reserved Instance खरीद इवेंट (DSH-63): RequestSpotFleet, ModifySpotFleetRequest, CancelSpotFleetRequests, CreateFleet, DeleteFleet, PurchaseReservedInstancesOffering, RequestSpotInstances, CancelSpotInstanceRequests। हमलावर crypto mining के लिए बड़े GPU/CPU clusters लॉन्च करने के लिए Spot Fleets का उपयोग करते हैं, जिससे प्रति-instance detection thresholds के नीचे रहते हुए उच्च AWS बिल उत्पन्न होते हैं। कोई भी अप्रत्याशित Spot Fleet या Reserved Instance खरीद जाँच की गारंटी देती है। MITRE ATT&CK: TA0040 Impact / T1496 Resource Hijacking। |
| 9 | ECS Task Definition & Service Changes | ECS task definition पंजीकरण और service संशोधन इवेंट (DSH-49)। Pacu का ecs__backdoor_task_def एक नया task definition संशोधन पंजीकृत करता है जो एक क्रेडेंशियल-चुराने वाला sidecar container इंजेक्ट करता है, फिर इसे तैनात करने के लिए UpdateService जारी करता है — ECR image निगरानी को पूरी तरह से बायपास करते हुए। किसी अपरिचित caller या IP से कोई भी अप्रत्याशित RegisterTaskDefinition या UpdateService तत्काल जाँच की गारंटी देता है। MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0006 Credential Access। |
| 10 | Lambda Function Configuration & Permission Changes | Lambda function निर्माण, code अद्यतन, और permission इवेंट (DSH-64)। UpdateFunctionCode function code को एक दुर्भावनापूर्ण payload से बदल देता है। AddPermission cross-account या public Lambda invocation पहुँच प्रदान करता है। CreateFunctionUrlConfig सीधे C2 के लिए एक public HTTP endpoint बनाता है। CreateEventSourceMapping function को S3/DynamoDB/SQS पर ट्रिगर होने के लिए वायर करता है। PublishLayerVersion कई functions में एक दुर्भावनापूर्ण shared layer इंजेक्ट करता है। इनमें से किसी भी घटना का किसी अप्रत्याशित identity या IP से होना एक persistence/execution संकेतक है। MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0011 Command and Control। |
| 11 | SSM Session / Run Command Execution | AWS Systems Manager रिमोट-निष्पादन इवेंट (DSH-39): StartSession, TerminateSession, ResumeSession, SendCommand, और StartAutomationExecution। SSM Session Manager बिना खुले SSH/RDP ports के shell पहुँच प्रदान करता है और चोरी की गई IAM क्रेडेंशियल वाले हमलावरों के लिए प्राथमिक lateral-movement तंत्र है। किसी असामान्य IP या identity से कोई भी अप्रत्याशित session या command तत्काल जाँच की गारंटी देता है। MITRE ATT&CK: TA0008 Lateral Movement / TA0002 Execution। |
| 12 | EBS Direct API Snapshot Block Access | snapshot डेटा को exfiltrate करने के लिए उपयोग की जाने वाली EBS Direct API कॉल (DSH-51)। Pacu का ebs__download_snapshots एक पूर्ण EBS disk image को ब्लॉक-दर-ब्लॉक स्ट्रीम करने के लिए ListSnapshotBlocks और GetSnapshotBlock का उपयोग करता है, बिना कोई EC2 instance बनाए, snapshot copy का अनुरोध किए, या कोई ModifySnapshotAttribute इवेंट ट्रिगर किए — जिससे यह पारंपरिक snapshot-साझाकरण डिटेक्शन के लिए अदृश्य हो जाता है। किसी अप्रत्याशित identity या IP address से कोई भी GetSnapshotBlock या ListSnapshotBlocks कॉल एक महत्वपूर्ण एक्सफिल्ट्रेशन संकेतक है। MITRE ATT&CK: TA0010 Exfiltration / TA0009 Collection। |
| 13 | EKS / ECR Container Platform Events | EKS cluster और ECR container registry इवेंट (DSH-48)। EKS: UpdateClusterConfig (public API), CreateFargateProfile (दुर्भावनापूर्ण workloads), AssociateIdentityProviderConfig (rogue OIDC IdP)। ECR: PutImage (backdoored image push), SetRepositoryPolicy (cross-account access), PutRegistryPolicy (org-व्यापी registry exposure)। supply-chain हमलों और Kubernetes control-plane समझौते का पता लगाने के लिए Container platform इवेंट महत्वपूर्ण हैं। MITRE ATT&CK: TA0002 Execution / TA0003 Persistence / TA0010 Exfiltration। |
| 14 | CloudFormation Stack Changes | CloudFormation stack और change-set management इवेंट (DSH-65)। एक ही UpdateStack EC2 instances तैनात कर सकता है, IAM roles संशोधित कर सकता है, या networking को पुनः कॉन्फ़िगर कर सकता है — दर्जनों व्यक्तिगत API कॉल को एक इवेंट में समेकित करते हुए। CreateStackSet एक org के सभी accounts में हमलावर अवसंरचना तैनात करता है। ExecuteChangeSet एक पूर्व-तैयार परिवर्तन लागू करता है, जो प्रारंभिक समीक्षा से blast radius को छिपाता है। DeleteStack forensic साक्ष्य संसाधनों को नष्ट कर सकता है। MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0005 Defense Evasion। |
| 15 | IMDS Options Weakening | ModifyInstanceMetadataOptions कॉल जो IMDSv2 को वैकल्पिक बनाते हैं या metadata endpoint को फिर से सक्षम करते हैं, SSRF क्रेडेंशियल चोरी को फिर से खोलते हैं। Threat Technique Catalog for AWS: T1552.005। |
| 16 | AMI & Snapshot Deletion | AMIs का deregistration और EBS snapshots का विलोपन जो एक विनाशकारी हमले के दौरान recovery बेसलाइन को नष्ट कर देता है। Threat Technique Catalog for AWS: T1485.A002। |
| 17 | WorkSpaces Hijacking | EC2 सुरक्षा सीमा के बाहर compute-हाइजैकिंग के लिए उपयोग किया जाने वाला Amazon WorkSpaces प्रावधान। Threat Technique Catalog for AWS: T1496.A009। |

### 🤖 AI / LLM

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | Bedrock Model Invocation Trend | प्रति principal दैनिक Amazon Bedrock model invocation वॉल्यूम (DSH-98)। चोरी की गई क्रेडेंशियल (LLMjacking) पर उच्च-वॉल्यूम inference पीड़ित की कीमत पर reverse proxies के माध्यम से पुनर्विक्रय किया जाता है। किसी भी स्पाइक, किसी भी principal जिसने पहले कभी Bedrock को invoke नहीं किया, और किसी अप्रत्याशित origin से किसी भी invocation की जाँच करें। MITRE ATT&CK: TA0040 Impact (T1496 Resource Hijacking)। |
| 2 | Bedrock Model Access & Logging Changes | Foundation-model access सक्षमकरण और invocation-logging छेड़छाड़ (DSH-99)। चोरी की गई क्रेडेंशियल वाले हमलावर इसका दुरुपयोग करने से पहले खुद Bedrock model access सक्षम करते हैं, और model-invocation logging कॉन्फ़िगरेशन की जाँच करते हैं या हटाते हैं ताकि उनके prompts रिकॉर्ड न हों — दोनों दस्तावेज़ीकृत LLMjacking संकेतक हैं। किसी ऐसे org में कोई भी row जिसने कभी Bedrock नहीं अपनाया, तत्काल जाँच की गारंटी देती है। MITRE ATT&CK: TA0005 Defense Evasion / TA0040 Impact (T1496)। |
| 3 | Bedrock Failed Invocations | caller और error code द्वारा समूहित विफल Amazon Bedrock invocation प्रयास (DSH-100)। कई models और regions में AccessDenied / ValidationException errors के बर्स्ट यह संकेत देते हैं कि एक हमलावर जाँच रहा है कि एक चोरी की गई key कौन से models को invoke कर सकती है — LLMjacking का recon चरण। MITRE ATT&CK: TA0006 Credential Access / TA0007 Discovery। |
| 4 | Bedrock Callers by Origin | origin और model विविधता के साथ सभी Amazon Bedrock callers की सूची (DSH-101)। LLMjacking triage के लिए बेसलाइन दृश्य: अप्रत्याशित countries, hosting/VPN ASNs, या सामान्य scripting user agents (python-requests, curl) से उच्च कॉल वॉल्यूम के साथ कॉल करने वाले principals प्रमुख संदिग्ध हैं। MITRE ATT&CK: TA0040 Impact (T1496 Resource Hijacking)। |
| 5 | AgentCore Token Issuance (Daily) | संचालन के अनुसार दैनिक AgentCore टोकन वॉल्ट जारी करना। ये कॉल तृतीय-पक्ष OAuth टोकन और API कुंजियाँ बाँटते हैं, इसलिए दुरुपयोग AWS के बाहर तक पहुँचता है। |
| 6 | AgentCore Gateway & Policy Changes | AgentCore गेटवे, लक्ष्य और नीति परिवर्तन, Cedar नीति इंजन मोड सहित। ENFORCE से LOG_ONLY होने पर भी सफलता लौटती है, इसलिए आगे कुछ गलत नहीं दिखता। |

### 🌐 Network

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | Security Group Changes | EC2 security group rule परिवर्तन (DSH-76)। inbound/outbound rule authorization और revocation, security group निर्माण और विलोपन, और rule description अद्यतनों को कवर करता है। प्रशासनिक ports (22, 3389, आदि) पर 0.0.0.0/0 के लिए खोले गए Ingress rules बैकडोर access या misconfiguration का एक मजबूत संकेतक हैं। MITRE ATT&CK: TA0003 Persistence / TA0005 Defense Evasion। |
| 2 | Network ACL / Route Table Changes | Network ACL और route table संशोधन इवेंट (DSH-46)। NACL परिवर्तन (CreateNetworkAclEntry, DeleteNetworkAclEntry, ReplaceNetworkAclEntry) पूरे subnets के लिए security group प्रतिबंधों को बायपास कर सकते हैं। Route table परिवर्तन (CreateRoute, ReplaceRoute, DeleteRoute) अवरोधन के लिए ट्रैफ़िक को हमलावर-नियंत्रित अवसंरचना पर रीडायरेक्ट कर सकते हैं या मौन C2 संचार चैनल स्थापित कर सकते हैं। MITRE ATT&CK: TA0005 Defense Evasion / TA0011 Command and Control। |
| 3 | VPC Infrastructure Changes | VPC topology परिवर्तन इवेंट (DSH-77)। VPC निर्माण/विलोपन/संशोधन, subnet परिवर्तन, internet gateway attachment, NAT gateway निर्माण/विलोपन, VPC endpoint परिवर्तन, और Elastic IP allocation/association को कवर करता है। अप्रयुक्त regions में अप्रत्याशित IGW attachments या नए NAT gateways हमलावर-नियंत्रित एक्सफिल्ट्रेशन अवसंरचना के मजबूत संकेतक हैं। MITRE ATT&CK: TA0010 Exfiltration / TA0003 Persistence / TA0011 C2। |
| 4 | VPC Peering & Transit Gateway Changes | VPC peering connection और Transit Gateway परिवर्तन इवेंट (DSH-78)। VPC peering निर्माण/स्वीकृति/विलोपन और Transit Gateway निर्माण, VPC attachment, और peering attachment management को कवर करता है। अप्रत्याशित accounts से cross-account peering अनुरोध या नए Transit Gateway attachments AWS accounts के बीच lateral movement का संकेत देते हैं। MITRE ATT&CK: TA0008 Lateral Movement / TA0010 Exfiltration। |
| 5 | Route53 DNS Changes | Route 53 hosted-zone और resolver कॉन्फ़िगरेशन परिवर्तन (DSH-29)। DNS tunnelling DNS query payloads में डेटा exfiltrate करने के लिए TXT/CNAME records और बड़ी संख्या में subdomains का उपयोग करता है। नए hosted zones और अप्रत्याशित ChangeResourceRecordSets कॉल की तुरंत जाँच की जानी चाहिए। MITRE ATT&CK: TA0010 Exfiltration। |

### 🕒 Temporal Analysis

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | Event Velocity Spikes per Identity | प्रति घंटे 50+ इवेंट बर्स्ट गतिविधि अवधि वाली identities (DSH-38)। Credential stuffing, automated enumeration, या डेटा एक्सफिल्ट्रेशन सामान्य बेसलाइन से ऊपर तीव्र velocity स्पाइक्स बनाते हैं। प्रत्येक स्पाइक के लिए hour bucket, identity, और इवेंट गणना दिखाता है। MITRE ATT&CK: TA0006 Credential Access / TA0009 Collection / TA0010 Exfiltration। |
| 2 | Dormant Accounts Reactivated | 72+ घंटों के निष्क्रियता अंतराल वाली identities जिन्होंने गतिविधि फिर से शुरू की (DSH-37)। कम्प्रोमाइज़्ड dormant क्रेडेंशियल के हथियार बनाए जाने का एक क्लासिक पैटर्न। प्रति identity लगातार इवेंट के बीच घंटों/दिनों में अधिकतम अंतराल दिखाता है। MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence। |
| 3 | First / Last Seen per IAM Identity | first/last seen टाइमस्टैम्प, इवेंट गणना, अलग APIs, अलग IPs, और दिनों में active span के साथ IAM identities (DSH-31)। नई प्रकट हुई identities खोजने के लिए first_seen अवरोही क्रम में सॉर्ट करें। उच्च इवेंट गणना के साथ छोटे active spans कम्प्रोमाइज़्ड क्रेडेंशियल या automated हमलों का संकेत देते हैं। MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence। |
| 4 | First / Last Seen per Source IP | first/last seen, अलग identities, अलग APIs, और GeoIP संदर्भ के साथ source IPs (DSH-32)। dataset में देर से दिखाई देने वाली नई IPs lateral movement या नई हमलावर अवसंरचना का सुझाव देती हैं। MITRE ATT&CK: TA0001 Initial Access / TA0008 Lateral Movement। |
| 5 | First / Last Seen per API Call | पहली उपस्थिति द्वारा क्रमबद्ध API क्रियाएँ (DSH-33)। पहली बार प्रकट होने वाली नई API कॉल recon या विशेषाधिकार वृद्धि प्रयासों का सुझाव देती हैं। MITRE ATT&CK: TA0007 Discovery / TA0004 Privilege Escalation। |
| 6 | First / Last Seen per Service Source | हर अलग AWS service source के लिए first और last seen टाइमस्टैम्प (DSH-26)। नई शुरू की गई सेवाओं (संभावित हमलावर अवसंरचना) को उजागर करने के लिए first_seen अवरोही क्रम में सॉर्ट करें। खामोश हो चुकी सेवाओं (समझौते के बाद संभावित सफाई) को खोजने के लिए last_seen आरोही क्रम में सॉर्ट करें। MITRE ATT&CK: TA0003 Persistence / TA0007 Discovery। |
| 7 | Off-Hours Write Activity (Hour x Day) | JST में घंटे × सप्ताह-दिवस हीटमैप के रूप में लेखन इवेंट गणना। लॉगिन हीटमैप केवल ConsoleLogin कवर करता है; यह हर परिवर्तनकारी कॉल कवर करता है। |
| 8 | Principal Daily Volume (Read vs Write) | प्रति प्रिंसिपल दैनिक कॉल मात्रा, पठन और लेखन में विभाजित। हर प्रिंसिपल की तुलना स्वयं से करें: बिल्ड रोल की दस हज़ार कॉल सामान्य हैं, मनुष्य की दो सौ नहीं। |

### 🌍 GeoIP Intelligence

| # | चार्ट नाम | विवरण |
|---|------------|-------------|
| 1 | Impossible Travel (Multi-Country Principals) | अलग source countries, अलग source IPs, कुल इवेंट, और first/last seen द्वारा रैंक किए गए IAM principals (DSH-92)। किसी मानव principal के लिए distinct_countries >= 2 एक मजबूत account-समझौता संकेत है — समय विंडो और source IPs का क्रॉस-रेफरेंस करें। GeoIP संवर्धन की आवश्यकता है। MITRE ATT&CK: TA0001 Initial Access / T1078 Valid Accounts। |
| 2 | Top Countries by Request Volume | write-event और unique-caller विभाजन के साथ API कॉल वॉल्यूम द्वारा शीर्ष 20 source countries (DSH-15)। organization के संचालन से सामान्यतः असंबद्ध countries क्रेडेंशियल चोरी या हमलावर-नियंत्रित अवसंरचना का संकेत दे सकते हैं। GeoLite2 संवर्धन की आवश्यकता है — NULL rows को स्वतः बाहर रखा जाता है। |
| 3 | Top ASN Organizations by Request Volume | write-event और unique-caller विभाजन के साथ API कॉल वॉल्यूम द्वारा शीर्ष 25 ASN organizations (DSH-18)। अपेक्षित फुटप्रिंट के बाहर VPN providers, Tor exit nodes, hosting companies, या cloud providers से उत्पन्न ट्रैफ़िक anonymisation अवसंरचना के हमलावर उपयोग का संकेत दे सकता है। GeoLite2 संवर्धन की आवश्यकता है — NULL rows को स्वतः बाहर रखा जाता है। |
| 4 | Top Cities by Request Volume | write-event और unique-caller विभाजन के साथ API कॉल वॉल्यूम द्वारा शीर्ष 25 cities (DSH-17)। City-स्तरीय ग्रैन्युलैरिटी विशिष्ट data centre स्थानों को उजागर कर सकती है जो केवल country-स्तरीय विश्लेषण से छिपे रहेंगे। GeoLite2 संवर्धन की आवश्यकता है — NULL rows को स्वतः बाहर रखा जाता है। |
| 5 | Global Request Origin Map | CloudTrail API कॉल मूलों के भौगोलिक वितरण को दिखाने वाला विश्व मानचित्र (DSH-16)। Country रंग तीव्रता इवेंट गणना के समानुपाती है। organization के संचालन से सामान्यतः असंबद्ध countries क्रेडेंशियल चोरी या हमलावर-नियंत्रित अवसंरचना का संकेत दे सकते हैं। GeoLite2 संवर्धन की आवश्यकता है — NULL rows को स्वतः बाहर रखा जाता है। |
| 6 | API Calls by Country (Event Name × GeoIP) | API कॉल वॉल्यूम द्वारा शीर्ष 50 (event_name, country) जोड़े (DSH-79)। दिखाता है कि प्रत्येक भौगोलिक क्षेत्र से कौन से API operations कॉल किए जा रहे हैं। अप्रत्याशित countries से write operations क्रेडेंशियल समझौते का एक मजबूत संकेतक हैं। GeoLite2 संवर्धन की आवश्यकता है — private/internal IPs और NULL rows को बाहर रखा जाता है। |

</details>

---
