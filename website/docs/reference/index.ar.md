# مرجع الاستعلامات ولوحات المعلومات المدمجة

> 💡 لا حاجة إلى SQL أو معرفة عميقة بـ AWS — فقط اختر عملية تتبع من القائمة المنسدلة واحصل على النتائج فورًا.

## 🎯 عمليات التتبع المدمجة — 112 استعلامًا

تُرتَّب الفئات حسب أولوية الفرز في DFIR — تحقق أولًا من العبث بأدوات الكشف، ثم إساءة استخدام الهوية، ثم تأثير البيانات.

| الفئة | الاستعلامات | التهديدات الرئيسية المغطاة |
|----------|:-------:|---------------------|
| 🛡 Detection & Response | 12 | العبث بخدمة التدقيق (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · حذف SCP · إخماد الإنذارات · تسريب السجلات |
| 🔑 Identity & Access | 26 | استخدام الجذر · تسجيل الدخول إلى وحدة التحكم/MFA · تصعيد الامتيازات · باب خلفي في سياسة الثقة · إساءة استخدام PassRole · AssumeRole عبر الحسابات · SSO/SAML/OIDC · تعداد بيانات الاعتماد |
| 🪣 Data & Storage | 21 | حذف/تنزيل جماعي في S3 · قراءة جماعية للأسرار · العبث بالنسخ الاحتياطية · عمليات KMS · مشاركة اللقطات · تسريب EBS Direct API · تصدير DynamoDB · نسخ S3 عبر الحسابات |
| ⚡ Compute & Serverless | 14 | إيقاف/إنهاء جماعي لـ EC2 · حركة جانبية عبر SSM · العبث بـ Lambda/ECS/EKS/ECR · استمرارية EventBridge · تعدين العملات المشفرة · إساءة استخدام Lightsail |
| 🤖 AI & LLM Abuse | 6 | ارتفاعات استدعاء Bedrock · تفعيل الوصول إلى النماذج · العبث بتسجيل الاستدعاءات · استطلاع بمسح المناطق · دفعات الاستدعاءات الفاشلة · جرد المستدعين/الأصول (LLMjacking) |
| 🌐 Network & Infrastructure | 14 | SG مفتوحة للإنترنت · حذف سجل تدفق VPC · اختطاف CloudFront · أنفاق VPN/TGW سرية · Elastic IP للقيادة والتحكم · مفاتيح API Gateway |
| 🕵 Threat Patterns | 4 | دفعة استطلاع · وكلاء مستخدم غير معتادين · انتشار متعدد المناطق · استدعاءات API لأول مرة |
| 📊 Activity & Baseline | 3 | أحداث الكتابة في وحدة التحكم · ارتفاعات الأخطاء · الأخطاء الأخيرة |
| 🌍 GeoIP Analysis | 10 | تسجيلات الدخول/الرفض/الكتابة إلى وحدة التحكم حسب البلد · الوصول من بلد نادر · تفصيل البلد/ASN/المدينة · event_name × country · identity × country · خط أساس IP الخاص |
| ☁ IaC & Platform | 2 | سلسلة توريد CI/CD · إساءة استخدام CloudFormation |

<details markdown="1">
<summary>📋 القائمة الكاملة — جميع 112 استعلامًا (انقر للتوسيع)</summary>

## عمليات التتبع المدمجة

### 🛡 Detection & Response

| # | التسمية | المخطط | الوصف |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | يكتشف أي محاولة لإيقاف CloudTrail أو تعديله. التنبيه الأهم على الإطلاق — يشير إلى محاولة تستر. |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | يكتشف تعطيل GuardDuty وحذفه والتلاعب باستخبارات التهديدات. أي تغيير في GuardDuty أثناء التحقيق مؤشر حرج. |
| 3 | ⛔ Security Hub Tampering | timeseries | يكتشف تعطيل Security Hub وتعطيل المعايير وإخماد النتائج. إسكات Security Hub يزيل نقطة التجميع المركزية لكل النتائج الأمنية. |
| 4 | ⚙️ AWS Config Tampering | timeseries | يكتشف حذف مُسجِّل/قاعدة AWS Config. إيقاف Config يُزيل أدلة الامتثال وتتبع التغييرات لمنطقة بأكملها. |
| 5 | 🛡 Organizations Service Control Policy (SCP) Changes | timeseries | يكتشف إنشاء SCP وتعديله وحذفه. إزالة SCP من نوع Deny تُلغي فورًا الضوابط الواقية عبر كل حساب في وحدة OU المتأثرة. |
| 6 | 🚫 AWS Macie Tampering | timeseries | يكتشف تعطيل Macie وإنشاء مرشح النتائج. يُخمِد المهاجمون نتائج Macie قبل تسريب البيانات الحساسة من S3. |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | يكتشف حذف إنذارات CloudWatch وتعطيلها. إسكات الإنذارات المرتبطة بـ GuardDuty أو مرشحات مقاييس CloudTrail أو عتبات الفوترة مؤشر رئيسي على التهرب من الدفاع. |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | يكتشف إنشاء/حذف مرشح اشتراك CW Logs وحذف مجموعة السجلات. يبثّ المهاجمون السجلات إلى وجهة خارجية أو يدمّرون الأدلة في مكانها. |
| 9 | 🏹 WAF WebACL Changes | timeseries | يكتشف إنشاء WAF WebACL وتحديثه وحذفه. إزالة أو إضعاف WebACL يعطّل الحماية من هجمات SQLi وXSS وDDoS. |
| 10 | 🔍 GuardDuty Findings Read | timeseries | يكتشف استدعاءات API للقراءة فقط في GuardDuty. تقرأ وحدة guardduty__list_findings في Pacu النتائج النشطة لفهم ما اكتشفه المدافع بالفعل، مما يتيح للمهاجم تكييف أساليبه وتجنّب إثارة تنبيهات جديدة. |
| 11 | 💰 Budget / Cost Anomaly Changes | timeseries | يكتشف حذف أو تعديل ميزانيات AWS ومراقبات شذوذ التكلفة. يزيل المهاجمون تنبيهات الميزانية لإخفاء تعدين العملات المشفرة أو العمليات كثيفة الموارد. |
| 12 | 🚫 Access Denied Errors | bar | يجمّع أخطاء AccessDenied حسب الهوية وAPI. أبرز المخالفين قد يشيرون إلى إساءة استخدام بيانات الاعتماد. |

### 🔑 Identity & Access

| # | التسمية | المخطط | الوصف |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | يكتشف أي استدعاء API يُجريه حساب الجذر. لا ينبغي استخدام الجذر أبدًا في بيئة الإنتاج. |
| 2 | 🔓 Console Login without MFA | timeseries | يكتشف تسجيلات الدخول إلى وحدة التحكم التي لم يُستخدم فيها MFA. مؤشر عالي الخطورة على اختراق الحساب. |
| 3 | 🌐 Console Logins | timeseries | يسرد جميع محاولات تسجيل الدخول إلى وحدة التحكم. القوة الغاشمة = عدة إخفاقات تليها عملية نجاح. |
| 4 | 🔐 MFA & Password Changes | timeseries | يكتشف تعطيل MFA وإعادة تعيين كلمات المرور. مؤشر قوي على الاستيلاء على الحساب. |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | يكتشف إرفاق سياسات IAM والتلاعب بالأدوار المستخدَمة في تصعيد الامتيازات. |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | يكتشف استدعاءات UpdateAssumeRolePolicy. إضافة كيانات أساسية من حساب خارجي إلى سياسة الثقة تُنشئ بابًا خلفيًا مستمرًا. |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | يكتشف أحداث وضع/حذف حدود الأذونات. إزالة حد الأذونات توسّع فورًا الأذونات الفعلية للكيان الأساسي، مما يمكّن تصعيد الامتيازات. |
| 8 | 👑 User Added to Admin Group | timeseries | يكتشف المستخدمين المُضافين إلى مجموعات تحتوي على 'admin' في اسمها. تقنية تصعيد امتيازات كلاسيكية. |
| 9 | 👥 IAM Group Membership Changes | timeseries | يكتشف جميع أحداث AddUserToGroup وRemoveUserFromGroup بغض النظر عن اسم المجموعة. أي إضافة إلى مجموعة قد تشير إلى تصعيد امتيازات عبر السياسات الموروثة من المجموعة. |
| 10 | 👤 New IAM Users / Keys | timeseries | يحدد أحداث إنشاء مستخدمي IAM ومفاتيح الوصول. الإنشاء غير المتوقع قد يشير إلى الاستمرارية. |
| 11 | 🎯 IAM PassRole Abuse | timeseries | يكتشف استدعاءات iam:PassRole. تمرير دور ذي امتيازات إلى EC2/Lambda/Glue/ECS/SageMaker هو المسار الأكثر شيوعًا لتصعيد الامتيازات الجانبي. |
| 12 | 🔐 AssumeRole Cross-Account | timeseries | يعرض أحداث AssumeRole حيث يكون المستدعي والهدف في حسابات AWS مختلفة. يشير إلى حركة جانبية. |
| 13 | 🏢 Cross-Account Access | timeseries | يجد الأحداث حيث يختلف حساب المستدعي عن حساب المستلم. إشارة على الحركة الجانبية. |
| 14 | 🔑 STS Federation Token Issuance | timeseries | يكتشف استدعاءات GetFederationToken وGetSessionToken. يستخدمها المهاجمون لتحويل المفاتيح طويلة الأمد إلى بيانات اعتماد مؤقتة مستمرة. |
| 15 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | يكتشف استدعاءات AssumeRoleWithWebIdentity. إساءة استخدام ثقة OIDC خاطئة التهيئة (مثل مطالبة sub واسعة جدًا) تتيح للمهاجمين اختطاف دور باستخدام رموز يتحكمون فيها. |
| 16 | 🆔 IAM Identity Center (SSO) Events | timeseries | يكتشف إجراءات إدارة AWS IAM Identity Center. يسيء المهاجمون استخدام SSO لإنشاء مجموعات أذونات خلفية أو تعيين حسابات لمستخدمين يتحكمون فيهم. |
| 17 | 🔗 SAML / OIDC Provider Updates | timeseries | يكتشف تغييرات موفّر هوية SAML/OIDC. تحديث موفّر SAML ببيانات وصفية يتحكم فيها المهاجم يُنشئ بابًا خلفيًا مستمرًا للمصادقة. |
| 18 | 🧐 IAM Access Analyzer Calls | timeseries | يكتشف أي استخدام لـ IAM Access Analyzer. يستخدم المهاجمون المحلل الأصلي من AWS لتعداد الموارد المتاحة خارجيًا دون كتابة نصوص استطلاع مخصصة. |
| 19 | 🔄 Credential Report & Enumeration | timeseries | يكتشف نشاط تعداد IAM الذي يرسم خريطة كاملة لبيئة IAM. شائع في مراحل الهجوم المبكرة. |
| 20 | 🗝 Access Key Abuse | bar | يكتشف مفاتيح الوصول المستخدَمة من 3 عناوين IP مصدرية متمايزة أو أكثر خلال 7 أيام. مؤشر قوي على تسريب المفتاح. |
| 21 | 📰 AWS Organizations Account Creation | timeseries | يكتشف إنشاء حسابات Organizations وتغييرات المسؤول المفوَّض. ينشئ المهاجمون حسابات ظل لترسيخ مواطئ قدم مستمرة خارج الحساب الرئيسي. |
| 22 | 👥 Cognito Unauthenticated Access | timeseries | يكتشف مجمعات هوية Cognito التي يكون فيها الوصول غير المصادَق عليه مفعّلًا. يتيح للمستخدمين المجهولين استدعاء واجهات AWS بأذونات دور IAM غير المصادَق. |
| 23 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | يكتشف إنشاء نقطة نهاية تطوير Glue وتعداد الاتصالات. iam:PassRole + glue:CreateDevEndpoint يمنح أذونات الدور كاملة عبر SSH — إحدى أكثر تقنيات تصعيد امتيازات IAM إغفالًا. |
| 24 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | يكتشف إنشاء مثيل دفتر SageMaker وتوليد عنوان URL مُوقَّع مسبقًا. iam:PassRole + sagemaker:CreateNotebookInstance يوفّر بيئة Jupyter بكامل أذونات AWS للدور المُمرَّر. CreatePresignedNotebookInstanceUrl وحدها يمكن أن تمنح الوصول إلى دفتر موجود. |
| 25 | 🛠 Data Pipeline / CodeStar Privilege Escalation | timeseries | يكتشف إنشاء موارد Data Pipeline وCodeStar. كلاهما يقبل iam:PassRole ويمكنه تنفيذ شيفرة عشوائية بأذونات الدور المُمرَّر. CodeStar:CreateProjectFromTemplate واجهة API غير موثَّقة تُنشئ دور IAM للمسؤول. |
| 26 | 🧩 Step Functions Privilege Escalation | timeseries | يكتشف إنشاء آلة حالة Step Functions وتنفيذها. iam:PassRole + states:CreateStateMachine + states:StartExecution يتيح تشغيل مهام Lambda / ECS عشوائية تحت أذونات الدور المُمرَّر. |

### 🪣 Data & Storage

| # | التسمية | المخطط | الوصف |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | يكتشف استدعاءات DeleteObject/DeleteObjects عالية الحجم (50 أو أكثر في الساعة). يختلف عن التسريب — هذا نمط تدمير بيانات / برامج فدية. |
| 2 | 🔥 AWS Backup Tampering | timeseries | يكتشف حذف Backup Vault/Plan/RecoveryPoint. تدمير النسخ الاحتياطية هو الخطوة الأولى في هجمات برامج الفدية لمنع الاسترداد. |
| 3 | 🔓 KMS Key Operations | timeseries | يُعلِّم عمليات KMS الحساسة بما فيها حذف المفتاح واستدعاءات Decrypt عالية الحجم. |
| 4 | 🔓 S3 Public Access Block Disabled | — | يكتشف تعطيل إعدادات منع الوصول العام لـ S3. خطر تعرّض البيانات الفوري. |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | يكتشف تعديلات سياسة دلو S3 وACL. يمكن أن تجعل هذه التعديلات الدلو قابلًا للقراءة علنًا أو تمنح وصولًا لحسابات يتحكم فيها المهاجم. |
| 6 | 🪣 S3 Data Access Anomalies | bar | يكتشف استدعاءات GetObject الجماعية (100 أو أكثر في الساعة) التي قد تشير إلى تسريب البيانات. |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | يكتشف الاسترجاع الجماعي للأسرار (كلمات مرور قواعد البيانات، مفاتيح API، إلخ). عشرة استدعاءات GetSecretValue أو أكثر في ساعة واحدة إشارة قوية على جمع بيانات الاعتماد. |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | يكتشف حذف أسرار Secrets Manager وتغييرات سياسة الموارد عبر الحسابات. يكمّل كشف القراءة الجماعية الحالي بمتجهات التدمير وتسريب السياسات. |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | يكتشف القراءات الجماعية لإدخالات SSM Parameter Store. قناة تسريب غالبًا ما يُغفل عنها مقارنة بـ Secrets Manager. |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | يكتشف لقطات RDS/Aurora المشتركة مع حسابات AWS خارجية. تسريب بيانات كلاسيكي عبر مشاركة اللقطات. |
| 11 | 💣 RDS Deleted without Final Snapshot | — | يكتشف حذف مثيل/مجموعة RDS مع skipFinalSnapshot=true. احتمال تدمير البيانات. |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | يكتشف مثيلات RDS المُنشأة أو المعدَّلة مع PubliclyAccessible=true. يعرّض قاعدة البيانات مباشرة للإنترنت متجاوزًا ضوابط أمان VPC. |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | يكتشف ExportTableToPointInTime في DynamoDB (تصدير صامت لكامل الجدول إلى S3) وحذف الجدول. متجه تسريب وتدمير عالي الخطورة. |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | يكتشف استدعاءات EBS Direct API (ListSnapshotBlocks / GetSnapshotBlock). تستخدم وحدة ebs__download_snapshots في Pacu هذه الواجهة لبث بيانات اللقطة الخام دون إنشاء مثيلات EC2، متجاوزةً كشف مشاركة اللقطات التقليدي. |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | يكتشف إنشاء/تحديث تدفق تسليم Kinesis Firehose يشير إلى S3 خارجي. تسريب خط أنابيب بيانات في الوقت الفعلي غير مرئي لمنع تسرب بيانات الشبكة. |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | يكتشف PutBucketReplication وDeleteBucketReplication. النسخ عبر الحسابات ينسخ بصمت كل الكائنات الجديدة إلى دلو يتحكم فيه المهاجم. |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | يكتشف تعليق إصدارات S3 وتعطيل تسجيل وصول الخادم. تعطيل الإصدارات يتيح تدمير البيانات؛ تعطيل التسجيل يمحو أثر أدلة الوصول. |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | يكتشف تغييرات قاعدة استلام SES وتهيئة الهوية. يمكن لقواعد إعادة التوجيه ترحيل كل البريد الوارد تلقائيًا إلى عناوين المهاجم؛ الهويات المُتحقَّق منها تُمكِّن حملات التصيد. |
| 19 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | يكتشف تغييرات سياسة قائمة انتظار/موضوع SQS/SNS التي تمنح وصولًا لحسابات خارجية. تُنشئ قناة تسريب صامتة دون إثارة تنبيهات إرسال عالية الحجم. |
| 20 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | يكتشف لقطات EBS أو صور AMI المشتركة علنًا (group=all). يتيح لأي شخص نسخ صور القرص واستخراج البيانات. |
| 21 | 📧 Data Exfiltration Channels | bar | يكتشف استدعاءات SNS/SQS/SES/S3 PutObject عالية الحجم (50 أو أكثر في الساعة) التي قد تشير إلى التسريب. |

### ⚡ Compute & Serverless

| # | التسمية | المخطط | الوصف |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | يكتشف استدعاءات StopInstances/TerminateInstances عالية الحجم في EC2 (5 أو أكثر في ساعة واحدة). يشير إلى تعطيل عبر برامج فدية أو هجوم تخريبي. |
| 2 | 🖥️ SSM Session / Run Command | timeseries | يكتشف SSM StartSession وSendCommand وتنفيذات الأتمتة. المسار الأساسي للحركة الجانبية عبر المثيلات المُدارة. |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | يكتشف الوصول عبر EC2 Instance Connect ووحدة التحكم التسلسلية، مما يتيح للمهاجمين الوصول إلى مثيل من متصفح أو CLI دون مفتاح SSH أو مضيف تحصين. مسار أساسي للحركة الجانبية للمهاجمين الذين لا يملكون مفاتيح SSH. |
| 4 | 📝 EC2 User Data Modification | timeseries | يكتشف استدعاءات ModifyInstanceAttribute التي تغيّر حقل userData. تعمل نصوص بيانات المستخدم كجذر عند الإقلاع التالي، مما يوفّر بابًا خلفيًا مستمرًا لتنفيذ الشيفرة. |
| 5 | ⚡ Lambda Function Tampering | timeseries | يكتشف إنشاء Lambda وتحديثات الشيفرة وتغييرات الأذونات. يستخدم المهاجمون Lambda لتحقيق الاستمرارية. |
| 6 | 📦 Lambda Layer Addition | timeseries | يكتشف نشر طبقات Lambda وتغييرات الأذونات. نشر طبقة مشتركة خبيثة وإضافتها إلى دوال الإنتاج يحقن شيفرة المهاجم في سلسلة الاعتماديات. |
| 7 | 📦 ECS Task Definition | timeseries | يكتشف تسجيل تعريف مهمة ECS وتحديثات الخدمة. تُسجّل وحدة ecs__backdoor_task_def في Pacu إصدار تعريف مهمة جديد يشير إلى صورة حاوية خبيثة، ثم تحدّث الخدمة لنشرها — كل ذلك دون لمس ECR. |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | يكتشف ربط ملف تعريف مثيل IAM واستبداله. إرفاق ملف تعريف ذي امتيازات يمنح المثيل أذونات مرتفعة للحركة الجانبية. |
| 9 | 🖥 EC2 Instance Launches | timeseries | يسرد جميع أحداث RunInstances. عمليات الإطلاق غير المتوقعة في مناطق غير معتادة قد تشير إلى تعدين العملات المشفرة. |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | يكتشف طلبات Spot Fleet الكبيرة وعمليات شراء Reserved Instance وإنشاء مجموعة Auto Scaling بسعة عالية. مؤشر التأثير المالي لتعدين العملات المشفرة. |
| 11 | ☸️ EKS Cluster API Calls | timeseries | يكتشف تعديلات مستوى التحكم بمجموعة EKS. تعريض خادم API العام أو ملفات تعريف Fargate المارقة يمكّن الاستيلاء على منصة الحاويات. |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | يكتشف إنشاء/حذف مستودع ECR وتغييرات السياسة ودفعات الصور. حقن صور خبيثة في مستودع إنتاجي تقنية استمرارية لسلسلة التوريد. |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | يكتشف تعديلات قاعدة EventBridge وEventBridge Scheduler. يستخدم المهاجمون القواعد المجدولة لترسيخ الاستمرارية دون عملية طويلة التشغيل. |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | يكتشف الوصول إلى مثيلات Lightsail وعمليات زوج المفاتيح وتعريض المنافذ. لدى Pacu ثلاث وحدات مخصصة لـ Lightsail (enum, download_ssh_keys, generate_temp_access). تعمل موارد Lightsail خارج حدود أمان EC2 القياسية. |

### 🤖 AI & LLM Abuse

| # | التسمية | المخطط | الوصف |
|---|-------|:-----:|-------------|
| 1 | 🤖 Bedrock Model Invocation Spike | timeseries | يكتشف الكيانات الأساسية التي تستدعي نماذج Bedrock 50 مرة أو أكثر في ساعة واحدة. الاستدلال عالي الحجم على بيانات اعتماد مسروقة (LLMjacking) قد يكلّف الضحية عشرات آلاف الدولارات يوميًا. |
| 2 | 🔓 Bedrock Model Access Enablement | timeseries | يكتشف تفعيل الوصول إلى النماذج الأساسية أو شراء سعة مخصصة. في المؤسسات التي لم تتبنَّ Bedrock مطلقًا يُعدّ هذا مؤشرًا شبه خالٍ من الضوضاء على LLMjacking — أول عملية كتابة نموذجية من المهاجم. |
| 3 | 🙈 Bedrock Invocation Logging Tampering | timeseries | يكتشف حذف أو تعديل تسجيل استدعاءات نماذج Bedrock، إضافة إلى تحقق المهاجمين مما إذا كان التسجيل مفعّلًا قبل إساءة استخدام الحساب (مؤشر اختراق موثَّق لـ LLMjacking). |
| 4 | 🧭 Bedrock Reconnaissance Sweep | bar | يحدد المستدعين الذين يعدّدون نماذج Bedrock عبر منطقتين أو أكثر أو بـ 10 استدعاءات تعداد أو أكثر في ساعة واحدة. يقوم حائزو المفاتيح المسروقة بمسح المناطق لإيجاد أين يمكن استخدام النماذج. |
| 5 | ⛔ Failed Bedrock Invocations | bar | يجد دفعات استدعاءات Bedrock الفاشلة (AccessDenied / ValidationException). يُنتج اختبار المفاتيح المسروقة عواصف إخفاق عبر النماذج والمناطق قبل إيجاد توليفة عاملة. |
| 6 | 🌍 Bedrock Callers & Origins | — | يجرد كل كيان أساسي تعامل مع Bedrock على الإطلاق، مع IP المصدر وأصل GeoIP ووكيل المستخدم وتنوع النماذج. حدّد المستدعي أو الأصل الذي لا علاقة له إطلاقًا باستخدام Bedrock. |

### 🌐 Network & Infrastructure

| # | التسمية | المخطط | الوصف |
|---|-------|:-----:|-------------|
| 1 | 🌍 Security Group Opened to Internet | timeseries | يجد قواعد مجموعة الأمان التي تسمح بحركة المرور من 0.0.0.0/0. خطر التعرّض العام المباشر. |
| 2 | 🔥 Security Group Modifications | timeseries | يكتشف تغييرات قواعد مجموعة الأمان، ولا سيما القواعد التي تسمح بـ 0.0.0.0/0 على أي منفذ. |
| 3 | 🌊 VPC Flow Log Changes | timeseries | يكتشف حذف سجلات تدفق VPC. إزالة سجلات التدفق تلغي الأدلة على مستوى الشبكة — مؤشر حرج على التهرب من الدفاع. |
| 4 | 🌐 CloudFront Distribution Tampering | timeseries | يكتشف إنشاء توزيع CloudFront وتغييرات الأصل. تعديل الأصول يعيد توجيه حركة مرور CDN إلى خوادم يتحكم فيها المهاجم لاعتراض الوسيط أو جمع البيانات. |
| 5 | 🛡 Network Firewall / Shield Tampering | timeseries | يكتشف إزالة حماية Network Firewall وShield. حذف دفاعات طبقة الشبكة يعرّض شبكات VPC لحركة مرور الهجوم المباشرة. |
| 6 | 🧱 Network ACL Changes | timeseries | يكتشف إنشاء وحذف واستبدال إدخالات Network ACL. تتجاوز NACLs مجموعات الأمان ويمكن أن تفتح شبكات فرعية كاملة للمهاجمين. |
| 7 | 🛣️ Route Table Changes | timeseries | يكتشف تعديلات جدول التوجيه. يمكن أن تعيد إضافة أو استبدال المسارات توجيه حركة المرور إلى مضيفين يتحكم فيهم المهاجم (اعتراض الوسيط، اختطاف حركة المرور). |
| 8 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | يكتشف اتصالات VPN الجديدة وDirect Connect ومرفقات Transit Gateway. ينشئ المهاجمون أنفاق شبكة سرية لقنوات قيادة وتحكم أو تسريب بيانات مستمرة. |
| 9 | 📡 Elastic IP Allocation / Association | timeseries | يكتشف تخصيص وربط Elastic IP. يخصّص المهاجمون عنوان IP عامًا ثابتًا لمثيل مخترق لإنشاء بنية تحتية مستقرة للقيادة والتحكم. |
| 10 | 🗝️ EC2 Key Pair Creation | timeseries | يكتشف أحداث CreateKeyPair وImportKeyPair. ينشئ المهاجمون أو يستوردون مفاتيح SSH كآلية استمرارية للحفاظ على الوصول إلى المثيل. |
| 11 | 📡 Network Infrastructure Changes | timeseries | يكتشف تغييرات VPC ومستوى الشبكة التي قد تُنشئ بنية تحتية يتحكم فيها المهاجم. |
| 12 | 🏷 ACM Certificate Operations | timeseries | يكتشف طلبات وحذف شهادات ACM. يستخدم المهاجمون الحسابات المخترقة لإصدار شهادات TLS لنطاقات يتحكمون فيها لبناء بنية تحتية للتصيد. |
| 13 | 🔑 API Gateway Key Creation & Management | timeseries | يكتشف إنشاء مفتاح API Gateway وإدارة REST API. تُنشئ وحدة api_gateway__create_api_keys في Pacu بيانات اعتماد API مستمرة تنجو من تدوير مفاتيح IAM. كما يعدّل المهاجمون مُصرِّحي API لإضعاف ضوابط الوصول. |
| 14 | 🚧 VPC Endpoint Access Denied | timeseries | يكتشف أخطاء رفض الوصول عبر نقاط نهاية VPC. قد يشير إلى سياسة نقطة نهاية خاطئة التهيئة. |

### 🕵 Threat Patterns

| # | التسمية | المخطط | الوصف |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | يحدد المستدعين الذين نفّذوا 10 استدعاءات API متمايزة للقراءة فقط أو أكثر في ساعة واحدة. مرحلة هجوم مبكرة شائعة. |
| 2 | 🤖 Unusual User Agents | bar | يسرد وكلاء المستخدم النادرين (أقل من 5 أحداث). قد تشير الأدوات المخصصة مثل Pacu أو curl إلى أدوات هجومية. |
| 3 | 🌍 Multi-Region Activity | bar | يكتشف الهويات التي تنفّذ عمليات كتابة في 3 مناطق أو أكثر في يوم واحد. قد يشير الانتشار الجغرافي إلى الاختراق. |
| 4 | 🕵 First-Time API Calls (24h) | — | يجد استدعاءات API المُشاهَدة في الـ 24 ساعة الأخيرة ولكن لم تُشاهَد من قبل قط. قد تشير العمليات الجديدة إلى أدوات المهاجم. |

### 📊 Activity & Baseline

| # | التسمية | المخطط | الوصف |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | يحدد استدعاءات API المُعدِّلة المُجراة عبر وحدة تحكم AWS. مفيد عندما يُتوقَّع الوصول عبر CLI فقط. |
| 2 | 🔍 Events with Errors (24h) | timeseries | يسرد جميع أحداث الأخطاء في الـ 24 ساعة الماضية. نظرة عامة سريعة على ما يفشل حاليًا. |
| 3 | ❌ Error Spike Detection | — | يجد نوافذ مدتها ساعة واحدة حيث يتجاوز عدد الأخطاء المتوسط اليومي بمقدار 3 أضعاف. يشير إلى فحص أو انقطاع. |

### 🌍 GeoIP Analysis

| # | التسمية | المخطط | الوصف |
|---|-------|:-----:|-------------|
| 1 | 🗺 Console Logins by Country | timeseries | يربط أحداث تسجيل الدخول إلى وحدة التحكم بأصلها الجغرافي. تسجيلات الدخول من بلدان غير متوقعة عالية الخطورة. |
| 2 | 🚨 Unusual Country Access | bar | يكتشف استدعاءات API من بلدان غير متوقعة من خلال عرض مجموعات البلد/الهوية النادرة. |
| 3 | 🚫 Access Denied by Country | bar | يجمّع أخطاء رفض الوصول حسب البلد المصدري. قد تشير حالات الرفض المركزة من بلد واحد إلى هجوم. |
| 4 | 🔍 Write Events by Country | bar | يعرض استدعاءات API المُعدِّلة (الكتابة) مجمّعة حسب البلد. الكتابة من بلدان غير متوقعة ذات أولوية عالية. |
| 5 | 🌍 Top Source Countries | bar | يرتّب البلدان المصدرية حسب حجم استدعاءات API. يحدد التوزيع الجغرافي لكل النشاط. |
| 6 | 🏢 Top ASN / Organizations | bar | يسرد الأنظمة المستقلة (مزودو خدمة الإنترنت/الحوسبة السحابية) حسب حجم استدعاءات API. حدّد مزودي VPN/الاستضافة. |
| 7 | 📍 Top Source Cities | bar | يرتّب المدن المصدرية حسب حجم الأحداث. يحدد بدقة أكثر الأصول الجغرافية نشاطًا. |
| 8 | 📋 API Calls by Country (Event Name) | bar | يعرض عمليات API المُستدعاة من كل بلد. أحداث الكتابة من بلدان غير متوقعة تشير إلى اختراق بيانات الاعتماد. |
| 9 | 👤 Identities by Country (user_identity_arn) | bar | يعرض هويات IAM النشطة من كل بلد. ظهور هوية من بلد جديد مؤشر اختراق عالي الثقة. |
| 10 | 🌐 Private / Internal IP Summary | bar | يلخّص الأحداث من عناوين IP الخاصة والاسترجاعية والداخلية لـ AWS. خط أساس لحركة المرور الداخلية المتوقعة. |

### ☁ IaC & Platform

| # | التسمية | المخطط | الوصف |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | يكتشف إنشاء وتعديل خط أنابيب CI/CD. حقن خطوات بناء خبيثة أو تعديل مصادر خط الأنابيب يسمّم كل عمليات النشر اللاحقة. |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | يكتشف عمليات حزمة CloudFormation. قد يستخدم المهاجمون IaC لنشر بنية تحتية خبيثة بسرعة. |

</details>

---

## 📊 مخططات لوحة المعلومات — 91 مخططًا

| علامة التبويب | المخططات | ما تعرضه |
|-----|:------:|---------------|
| 🚦 Overview | 10 | 9 بطاقات KPI للفرز (الأحداث، الكيانات الأساسية، عناوين IP، الجذر، تسجيلات الدخول بدون MFA، رفض الوصول، التهرب من الدفاع، البلدان، المناطق) + اتجاه حجم الأحداث العالمي |
| 🎯 Threat Detection | 11 | تجميع شامل للتهرب من الدفاع · فجوات التسجيل · العبث بسجل تدفق VPC/Config/EventBridge/WAF · تغييرات SCP · اتجاهات الأخطاء والتقييد · نسبة الكتابة/القراءة |
| 🔑 Identity & Access | 14 | تسجيلات الدخول إلى وحدة التحكم · اتجاه MFA · خريطة حرارية لتسجيل الدخول · تسلسل مصادقة من الفشل إلى النجاح · استخدام الجذر · نشاط كيان IAM · الجدول الزمني لتصعيد الامتيازات · كيانات أساسية جديدة · SSO · AssumeRole عبر الحسابات |
| 🚨 High-Risk API Monitor | 5 | سجلات API للعبث بخدمات الأمان واسترجاع بيانات الاعتماد · أبرز الاستدعاءات عالية الخطورة · أبرز الجهات الفاعلة · حجم الاستدعاءات عالية الخطورة عبر الزمن |
| 📊 API Activity | 6 | أبرز واجهات API · إجراءات رفض الوصول · توزيع المناطق · تركيبة رموز الأخطاء · عناوين IP المصدرية · وكلاء المستخدم |
| 🪣 S3 & RDS | 11 | تنزيل/حذف جماعي في S3 · تعطيل الإصدارات/التسجيل · نسخ عبر الحسابات · سياسة/ACL الدلو · التعداد · تهيئة الحماية · حذف Backup vault · حذف مفتاح KMS · مشاركة لقطة RDS / الحذف بدون لقطة |
| 🖥️ Computing | 14 | عمليات إطلاق EC2/الإيقاف الجماعي/أزواج المفاتيح/ملف تعريف المثيل/بيانات المستخدم/مشاركة اللقطات/Spot Fleet · ECS/Lambda/SSM/EBS Direct API/EKS-ECR/CloudFormation |
| 🤖 AI / LLM | 4 | اتجاه استدعاءات Bedrock · تغييرات الوصول إلى النماذج والتسجيل · الاستدعاءات الفاشلة · المستدعون حسب الأصل (فرز LLMjacking) |
| 🌐 Network | 5 | تغييرات مجموعة الأمان · تغييرات NACL/جدول التوجيه · بنية VPC التحتية · تناظر VPC/Transit Gateway · تغييرات Route53 DNS |
| 🕒 Temporal Analysis | 6 | ارتفاعات سرعة الأحداث · إعادة تنشيط الحسابات الخاملة · أول/آخر مشاهدة حسب الهوية/IP/API/مصدر الخدمة |
| 🌍 GeoIP Intelligence | 6 | السفر المستحيل (كيانات أساسية متعددة البلدان) · أبرز البلدان/المدن/ASN · خريطة العالم · event_name × country |

<details markdown="1">
<summary>📋 القائمة الكاملة — جميع 91 مخططًا (انقر للتوسيع)</summary>

## مخططات لوحة المعلومات (Apache Superset — `dashboard/`)

### 🚦 Overview

| # | اسم المخطط | الوصف |
|---|------------|-------------|
| 1 | Total Events | إجمالي عدد أحداث CloudTrail في النطاق المحدد (KPI-81). المقام المستخدم في الفرز — نقطة الارتكاز لكل نسبة لكل كيان أساسي أو لكل IP. |
| 2 | Distinct Principals | عدد ARN الكيانات الأساسية الفريدة لـ IAM النشطة في النطاق المحدد (KPI-82). استخدمه لتحديد نطاق عدد الهويات المتورطة في النشاط قيد المراجعة. |
| 3 | Distinct Source IPs | عدد عناوين IP المصدرية الفريدة للمستدعين في النطاق المحدد (KPI-83). القفزة مقارنة بخط الأساس توحي بتدوير وكيل/VPN أو وصول موزّع. |
| 4 | Root Account Events | عدد الأحداث التي نفّذتها هوية حساب الجذر (KPI-84). ينبغي أن يكون نشاط الجذر شبه معدوم — أي قيمة غير صفرية تستدعي التحقيق. |
| 5 | MFA-less Console Logins | عدد تسجيلات الدخول إلى وحدة التحكم بدون MFA في النطاق المحدد (KPI-85). مؤشر مباشر على اختراق بيانات الاعتماد — تعمّق في اتجاه تسجيل الدخول بدون MFA. |
| 6 | Access Denied Events | عدد أحداث فشل التصريح في النطاق المحدد (KPI-86). الارتفاع المفاجئ يوحي بالاستطلاع أو سبر الامتيازات — تفرّع حسب الكيان الأساسي/IP. |
| 7 | Defense-Evasion Hits | عدد أحداث العبث بالتدقيق/المراقبة في النطاق المحدد (KPI-87). إشارة الفرز الأعلى أولوية — أي قيمة غير صفرية تعني أن الكشف ربما عُطِّل. تعمّق في تغييرات المراقبة والتحكم الأمني. MITRE ATT&CK: TA0005 Defense Evasion. |
| 8 | Distinct Countries | عدد البلدان المصدرية الفريدة في النطاق المحدد (KPI-88). يتطلب إثراء GeoIP (make ingest-geoip). الانتشار الواسع يوحي بالوصول من أصول جغرافية غير متوقعة. |
| 9 | Active Regions | عدد مناطق AWS المتمايزة ذات النشاط في النطاق المحدد (KPI-89). النشاط في مناطق غير مستخدمة قد يشير إلى إساءة استخدام الموارد أو تجهيز المهاجم. |
| 10 | CloudTrail Events Over Time | حجم أحداث القراءة مقابل الكتابة بالساعة عبر الزمن (DSH-01). تُظهر الأعمدة المكدّسة توزيع القراءة/الكتابة: الارتفاع المفاجئ في write_events يشير إلى انتقال المهاجم من الاستطلاع إلى الاستغلال الفعلي. مفيد لتحديد ارتفاعات النشاط والعمليات خارج ساعات العمل. |

### 🎯 Threat Detection

| # | اسم المخطط | الوصف |
|---|------------|-------------|
| 1 | Security Monitoring & Control Changes | تجميع شامل لكل أحداث التهرب من الدفاع (DSH-22). يغطي العبث بـ CloudTrail (StopLogging، DeleteTrail)، وتعطيل GuardDuty، وتعطيل AWS Config، وحذف VPC Flow Log، وحذف سجلات CloudWatch، وتعطيل خدمات الأمان (SecurityHub، IAM Access Analyzer). أي حدث هنا يستدعي تحقيقًا فوريًا. للتحليل الأعمق استخدم المخططات المخصصة: تغييرات VPC Flow Log (DSH-42)، العبث بـ AWS Config (DSH-43)، العبث بـ EventBridge/CW (DSH-47). MITRE ATT&CK: TA0005 Defense Evasion. |
| 2 | CloudTrail Logging Gap (Hourly Volume) | حجم أحداث CloudTrail بالساعة (DSH-91). الانخفاض المفاجئ إلى الصفر بين فترات النشاط يوحي بتعطيل التسجيل (StopLogging/DeleteTrail) أو وجود نقطة عمياء في التسليم. حقّق في أي فجوة غير متوقعة مقارنةً بجدول تغييرات المراقبة والتحكم الأمني. MITRE ATT&CK: T1562.008 Impair Defenses — Disable Cloud Logs. |
| 3 | VPC Flow Log Changes | أحداث إنشاء وحذف VPC Flow Log (DSH-42). يزيل DeleteFlowLogs مصدر الأدلة الجنائية الأساسي على مستوى الشبكة، مما يجعل تحليل الحركة الجانبية وتسريب البيانات بعد الحادثة مستحيلًا. قد يشير CreateFlowLogs أثناء حادثة إلى إعادة توجيه السجلات إلى دلو S3 يتحكم فيه المهاجم. MITRE ATT&CK: TA0005 Defense Evasion. |
| 4 | AWS Config Recorder & Rule Changes | أحداث العبث بمُسجِّل وقاعدة AWS Config (DSH-43): StopConfigurationRecorder وDeleteConfigurationRecorder وDeleteDeliveryChannel وDeleteConfigRule وPutConfigRule. إيقاف مُسجِّل Config يزيل أدلة الامتثال وتتبع التغييرات للمنطقة بأكملها، مما يتيح لتغييرات البنية التحتية اللاحقة أن تمر دون كشف من قواعد Config ومعايير Security Hub. MITRE ATT&CK: TA0005 Defense Evasion. |
| 5 | EventBridge & CloudWatch Rule Modifications | العبث بقاعدة EventBridge وCloudWatch Events (DSH-47): DeleteRule وDisableRule (إسكات الكشف المجدول)، وCreateSchedule/UpdateSchedule (مهام cron للمهاجم لبث إشارات القيادة والتحكم)، وPutSubscriptionFilter (إعادة توجيه سجلات CloudTrail/VPC إلى حساب المهاجم)، وDeleteLogGroup (تدمير سجلات VPC Flow Log). مخطط مدمج للعبث بطبقة المراقبة لأغراض DFIR. MITRE ATT&CK: TA0003 Persistence / TA0005 Defense Evasion / TA0011 C2. |
| 6 | WAF Configuration Changes | أحداث تغيير تهيئة AWS WAF v2 / WAF Classic (DSH-75). يغطي إنشاء/تحديث/حذف WebACL، والتلاعب بمجموعات IP، وتغييرات مجموعة القواعد، وتغييرات تهيئة التسجيل، وربط/فصل WAF بالموارد المحمية. تعطيل قواعد WAF أو التسجيل أثناء هجوم جارٍ مؤشر قوي على التهرب من الدفاع. MITRE ATT&CK: TA0005 Defense Evasion / TA0003 Persistence. |
| 7 | Organizations / SCP Changes | أحداث مستوى إدارة AWS Organizations بما فيها تغييرات سياسة SCP (DSH-24). قد يعطّل مهاجم يملك وصولًا إلى الحساب الرئيسي ضوابط SCP الواقية لإزالة الضوابط الوقائية عبر مؤسسة AWS بأكملها. MITRE ATT&CK: TA0004 Privilege Escalation / TA0005 Defense Evasion. |
| 8 | Error Event Trend | أحداث الأخطاء بالساعة مفصّلة حسب error_code (DSH-04). ارتفاعات ThrottlingException تشير إلى فحص آلي أو أدوات هجومية؛ ارتفاعات AccessDenied / UnauthorizedAccess تشير إلى سبر الامتيازات؛ الظهور المفاجئ لرموز أخطاء جديدة قد يشير إلى تقنيات هجوم مستحدثة. |
| 9 | Throttling Exception Spikes | أخطاء التحكم في المعدل/التقييد بالساعة مفصّلة حسب خدمة AWS (DSH-21). ارتفاعات ThrottlingException تشير إلى أن هوية (أو أداة) تصدر استدعاءات API أسرع بكثير من المتوقع، وهي سمة مميزة لأدوات الهجوم الآلية التي تنفّذ استطلاعًا أو تعدادًا. MITRE ATT&CK: TA0007 Discovery. |
| 10 | Write/Read Ratio Trend | تفصيل بالساعة لاستدعاءات API للقراءة مقابل الكتابة (DSH-20). الزيادة المستمرة في write_events نسبةً إلى read_events تشير إلى أن المهاجم انتقل من الاستطلاع إلى الاستغلال الفعلي. MITRE ATT&CK: TA0040 Impact / TA0007 Discovery. |
| 11 | CloudTrail Events Over Time | حجم أحداث القراءة مقابل الكتابة بالساعة عبر الزمن (DSH-01). تُظهر الأعمدة المكدّسة توزيع القراءة/الكتابة: الارتفاع المفاجئ في write_events يشير إلى انتقال المهاجم من الاستطلاع إلى الاستغلال الفعلي. مفيد لتحديد ارتفاعات النشاط والعمليات خارج ساعات العمل. |

### 🔑 Identity & Access

| # | اسم المخطط | الوصف |
|---|------------|-------------|
| 1 | Console Login Activity | أحداث تسجيل الدخول إلى AWS Management Console مجمّعة حسب هوية IAM (DSH-08). يتتبّع محاولات تسجيل الدخول الناجحة والفاشلة وبدون MFA. نسبة فشل إلى نجاح عالية قد تشير إلى القوة الغاشمة أو حشو بيانات الاعتماد. mfa_less_count (MFAUsed = 'No') مؤشر مباشر على اختراق الحساب، رغم أنه ينطبق فقط على أحداث ConsoleLogin الكلاسيكية -- تدفق تسجيل الدخول الأحدث عبر OAuth2 (CreateOAuth2Token / AuthorizeOAuth2Access) لا يُبلِّغ عن حالة MFA. الأحداث مُصفّاة إلى event_type = 'AwsConsoleSignIn'. |
| 2 | MFA-less Login Trend | تسجيلات الدخول اليومية إلى وحدة التحكم مقسّمة حسب استخدام MFA (DSH-28). mfa_less_logins (MFAUsed = 'No') مؤشر مباشر على اختراق الحساب أو التصيد؛ الارتفاع المستمر في تسجيلات الدخول بدون MFA ينبغي أن يستدعي مراجعة فورية لسياسات مصادقة IAM. MITRE ATT&CK: TA0001 Initial Access. |
| 3 | Failed -> Success Auth Sequence | إخفاقات ونجاحات تسجيل الدخول إلى وحدة التحكم لكل كيان أساسي + IP مصدري (DSH-93). عدد إخفاقات كبير مقترن بعدد نجاحات غير صفري يشير إلى قوة غاشمة / رش كلمات مرور نجح في النهاية — عامل النجاح كنقطة الاختراق وتفرّع حسب IP المصدر. MITRE ATT&CK: T1110 Brute Force. |
| 4 | Login Activity Heatmap (Hour x Day) | أعداد تسجيل الدخول إلى وحدة التحكم كخريطة حرارية لساعة اليوم (X) حسب يوم الأسبوع (Y) بتوقيت JST (DSH-19). الخلايا الساطعة في أعمدة ساعات الليل المتأخرة (22:00-06:00 بتوقيت JST) أو صفوف عطلة نهاية الأسبوع مؤشر قوي على اختراق الحساب أو إساءة استخدام بيانات الاعتماد. MITRE ATT&CK: TA0001 Initial Access. |
| 5 | Root Account Usage | جميع استدعاءات API التي أجراها حساب AWS Root (DSH-13). ينبغي أن يكون استخدام حساب الجذر نادرًا جدًا في البيئات جيدة الحوكمة. أي نشاط للجذر — خصوصًا CreateAccessKey أو ConsoleLogin أو StopLogging — مؤشر حرج على الاختراق أو انتهاك السياسة. |
| 6 | IAM Entity Activity | أبرز 50 كيان IAM مرتبة حسب إجمالي استدعاءات API، مع نسبة الكتابة وتفصيل الأخطاء (DSH-03). الكيانات ذات write_ratio_pct أو error_events مرتفعة نسبةً إلى total_events قد تشير إلى إساءة استخدام بيانات الاعتماد أو تصعيد الامتيازات. يعرض last_seen أحدث طابع زمني للنشاط لكل كيان. |
| 7 | IAM Privilege Change Event Timeline | الأعداد اليومية لاستدعاءات API لتصعيد الامتيازات مفصّلة حسب اسم الحدث (DSH-30). ارتفاع في يوم واحد يشير إلى حملة هجوم مستهدفة؛ الزيادة البطيئة قد تشير إلى تهديد داخلي أو مهاجم ذي موطئ قدم مستمر. MITRE ATT&CK: TA0004 Privilege Escalation. |
| 8 | New IAM Principal Creation Timeline | أحداث إنشاء الكيانات الأساسية وبيانات الاعتماد لـ IAM يوميًا، مكدّسة حسب نوع الحدث (DSH-95). ارتفاع في CreateAccessKey / CreateLoginProfile / CreateUser مؤشر استمرارية بعد الوصول الأولي — اربطه بالكيان الأساسي المُنفِّذ وIP المصدر. MITRE ATT&CK: T1136 Create Account / T1098 Account Manipulation. |
| 9 | Glue & SageMaker IAM Role Pass Events | أحداث Glue DevEndpoint وSageMaker Notebook المستخدمة لتصعيد امتيازات IAM (DSH-50). iam:PassRole + glue:CreateDevEndpoint ينشئ بيئة Python/Spark يمكن الوصول إليها عبر SSH بكامل أذونات الدور المُمرَّر. iam:PassRole + sagemaker:CreateNotebookInstance يوفّر دفتر Jupyter بنفس الأثر. sagemaker:CreatePresignedNotebookInstanceUrl وحدها يمكن أن تمنح الوصول إلى دفتر موجود دون امتلاك الدور الأساسي. كلاهما موثَّق في مستودع AWS-IAM-Privilege-Escalation ومطبَّق في وحدة iam__privesc_scan في Pacu. MITRE ATT&CK: TA0004 Privilege Escalation. |
| 10 | AssumedRole from External IP | استدعاءات AssumedRole الصادرة من عناوين IP عامة (غير خاصة) (DSH-27). عادةً ما تُستخدم بيانات اعتماد خدمة بيانات تعريف مثيل EC2 (IMDS) فقط من داخل VPC. الاستدعاءات من عناوين IP خارجية تشير إلى تسريب بيانات اعتماد مؤقتة — عادةً عبر SSRF أو الهروب من الحاوية أو تصدير المفتاح. MITRE ATT&CK: TA0008 Lateral Movement / TA0006 Credential Access. |
| 11 | Cross-Account AssumeRole | استدعاءات AssumeRole / AssumeRoleWithWebIdentity حيث يختلف recipient_account_id عن حساب المستدعي (DSH-94). معرّفات الحسابات الخارجية غير المتوقعة تشير إلى إساءة استخدام علاقة ثقة أو حركة جانبية بين الحسابات — تحقّق من أن كل حساب وجهة ثقة معتمدة. MITRE ATT&CK: T1199 Trusted Relationship / TA0008 Lateral Movement. |
| 12 | Secrets Access Anomaly | الهويات التي تصل إلى Secrets Manager أو SSM Parameter Store 10 مرات أو أكثر في ساعة واحدة (DSH-23). القراءات الجماعية لبيانات الاعتماد مؤشر ما بعد الاستغلال: يجمع المهاجمون الأسرار المخزّنة للتفرّع إلى خدمات أو حسابات أخرى. MITRE ATT&CK: TA0006 Credential Access / TA0010 Exfiltration. |
| 13 | Security-Relevant API Calls | استدعاءات إجراءات API الأمنية الحساسة المعروفة في AWS (DSH-12). يغطي تغييرات بيانات اعتماد IAM، وتعديلات السياسات، وتغييرات سياسة دلو S3، وتعديلات مجموعة الأمان، وإدارة المفاتيح، وعمليات رمز STS، وتعطيل خدمات الأمان، وقراءات Secrets Manager، وإدارة Organizations. ينبغي أن تكون هذه الاستدعاءات نادرة في العمليات العادية؛ الحالات غير المتوقعة قد تشير إلى تصعيد الامتيازات أو الاستمرارية أو تسريب البيانات. |
| 14 | IAM Identity Center (SSO) Events | أحداث إدارة AWS IAM Identity Center (DSH-44) من sso.amazonaws.com وsso-directory.amazonaws.com وsso-oauth.amazonaws.com وidentitystore.amazonaws.com. Identity Center هو مسار المصادقة الأساسي في المؤسسات متعددة الحسابات. التهديدات الرئيسية: CreatePermissionSet (وصول مسؤول خلفي)، وCreateAccountAssignment (تعيين حسابات لمستخدمين يتحكم فيهم المهاجم)، وAttachManagedPolicyToPermissionSet (تصعيد الامتيازات). MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence / TA0004 Privilege Escalation. |

### 🚨 High-Risk API Monitor

| # | اسم المخطط | الوصف |
|---|------------|-------------|
| 1 | Security Service Modification API Events | سجل أحداث مفصّل لواجهات API المستخدمة لتعطيل ضوابط التدقيق أو العبث بها (HRM-44). يغطي: DeleteTrail وStopLogging وUpdateTrail وPutEventSelectors (العبث بـ CloudTrail)، وDeletePolicy وDetachPolicy (إزالة ضوابط IAM الواقية). أي حدوث خارج نافذة تغيير معتمدة يستدعي تحقيقًا فوريًا. MITRE ATT&CK: TA0005 Defense Evasion. |
| 2 | Credential Retrieval API Events | سجل أحداث مفصّل لواجهات API المستخدمة لاسترجاع الأسرار وبيانات الاعتماد (HRM-45). يغطي: GetSecretValue (Secrets Manager)، وGetParameter / GetParameterHistory (SSM). استدعاء واحد قد يكون مشروعًا؛ الوصول إلى عشرات الأسرار المتمايزة بتتابع سريع إشارة قوية على مهاجم. MITRE ATT&CK: TA0006 Credential Access. |
| 3 | Top High-Risk API Calls | إجراءات API من قائمة المراقبة عالية الخطورة مرتبة حسب إجمالي عدد الاستدعاءات (HRM-40). يُتوقَّع الحضور المتكرر لواجهات الاستطلاع (ListUsers، GetCallerIdentity) في بيئات كثيرة؛ ركّز التحقيق على واجهات الوصول إلى بيانات الاعتماد والتهرب من الدفاع التي تظهر بحجم غير معتاد أو من كيانات أساسية غير متوقعة. |
| 4 | Top Actors — High-Risk APIs | كيانات IAM الأساسية مرتبة حسب إجمالي الاستدعاءات لواجهات قائمة المراقبة عالية الخطورة (HRM-42). قارن بمخطط فئة الهجوم لمعرفة الإجراءات التي ينفّذها كل كيان أساسي. أدوار الخدمة التي تجري استدعاءات AssumeRole متكررة أمر متوقع؛ أما المستخدمون البشريون الذين يستدعون GetSecretValue أو DeleteTrail بشكل جماعي فليس كذلك. |
| 5 | High-Risk API Events Over Time | حجم الاستدعاءات اليومي لواجهات API التي تُرصد عادةً في حملات الهجوم (HRM-39). الارتفاع المفاجئ في إجراءات نادرة عادةً مثل DeleteTrail أو GetSecretValue يستدعي تحقيقًا فوريًا. لاحظ أن كثيرًا من هذه الواجهات تُستدعى أيضًا في سير عمل مشروع — استخدم شذوذ الحجم كإشارة أساسية، لا مجرد الحضور. MITRE ATT&CK: TA0001 / TA0003 / TA0004 / TA0005 / TA0006 / TA0007 / TA0008. |

### 📊 API Activity

| # | اسم المخطط | الوصف |
|---|------------|-------------|
| 1 | Top 20 API Calls | الـ 20 إجراء API الأكثر استدعاءً في AWS (DSH-02). أعداد الاستدعاءات العالية للإجراءات الحساسة (مثل AssumeRole، GetSecretValue) قد تشير إلى أدوات آلية أو استطلاع. |
| 2 | Top Access Denied Actions | أبرز 20 إجراء API أرجع أخطاء AccessDenied أو Client.UnauthorizedAccess (DSH-09). أحداث رفض الوصول المتكررة تجاه واجهات حساسة (مثل AssumeRole، GetSecretValue، PutBucketPolicy) مؤشرات قوية على محاولات تصعيد امتيازات أو حركة جانبية. |
| 3 | Region Activity | توزيع أحداث CloudTrail عبر مناطق AWS (DSH-14). يبرز write_ratio_pct المناطق ذات نشاط الكتابة غير المتناسب — المناطق غير المتوقعة ذات نسب كتابة عالية قد تشير إلى مثيلات EC2 لتعدين العملات المشفرة أو حركة جانبية أو تسريب بيانات إلى مناطق أقل مراقبة. |
| 4 | Error-Code Composition Over Time | حجم أخطاء CloudTrail اليومي، مكدّس حسب error_code (DSH-96). نطاق متصاعد من AccessDenied / UnauthorizedOperation يشير إلى استطلاع أو سبر امتيازات؛ ارتفاعات Throttling توحي بتعداد على نطاق واسع. MITRE ATT&CK: TA0007 Discovery. |
| 5 | Top Source IP Addresses | أبرز 100 عنوان IP مصدري خارجي حسب عدد الطلبات (DSH-05). يستبعد أنماط IP الداخلية لـ AWS (*.amazonaws.com). عناوين IP ذات write_requests عالية نسبةً إلى request_count قد تشير إلى تسريب أو حركة جانبية أو أدوات هجوم آلية. |
| 6 | User Agent Analysis | أبرز 50 وكيل مستخدم حسب عدد الطلبات مع تفصيل الأخطاء والكتابة (DSH-11). وكلاء المستخدم غير المعتادين أو المخصصين (مثل Python/boto3، نصوص مخصصة، Pacu، ScoutSuite) قد يشيرون إلى أدوات هجوم آلية. وكلاء AWS الداخليون (console.amazonaws.com، signin.amazonaws.com) متوقعون؛ السلاسل غير المعروفة تستدعي التحقيق. |

### 🪣 S3 & RDS

| # | اسم المخطط | الوصف |
|---|------------|-------------|
| 1 | S3 High-Volume Object Downloads | استدعاءات GetObject الجماعية في S3 (DSH-52): الهويات التي نفّذت 100 طلب GetObject أو أكثر في ساعة واحدة، مجمّعة حسب فترة الساعة والهوية وIP المصدر. القراءات عالية الحجم تشير إلى تسريب بيانات آلي — يفرغ المهاجمون محتويات الدلو قبل تدميرها أو طلب فدية عليها. اجمعه مع مخطط الحذف الجماعي في S3 لتحديد سلسلة برامج الفدية الكاملة: التسريب ثم التدمير. MITRE ATT&CK: TA0010 Exfiltration. |
| 2 | S3 Bulk Object Deletion | استدعاءات DeleteObject/DeleteObjects الجماعية في S3 (DSH-53): الهويات التي حذفت 50 كائنًا أو أكثر في ساعة واحدة، مجمّعة حسب فترة الساعة والهوية وIP المصدر. عمليات الحذف عالية الحجم هي مرحلة تدمير البيانات في هجوم برامج الفدية — يسرّب المهاجم أولًا (انظر مخطط التنزيل الجماعي في S3)، ثم يمحو الدلو المصدر لابتزاز الضحية. يغطي أيضًا الحذف الجماعي العرضي. MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction. |
| 3 | S3 Versioning / Logging Disabled | أحداث تعليق إصدارات S3 وتعطيل التسجيل (DSH-54): PutBucketVersioning مع Status=Suspended وPutBucketLogging مع BucketLoggingStatus فارغ. يعطّل المهاجمون الإصدارات لمنع استرداد الكائنات بعد الحذف، ويعطّلون التسجيل لمحو أثر أدلة الوصول. كلاهما مقدمة لمكافحة الأدلة الجنائية تسبق تدمير البيانات. MITRE ATT&CK: TA0005 Defense Evasion / T1070 Indicator Removal. |
| 4 | S3 Cross-Account Replication | أحداث تهيئة النسخ عبر الحسابات في S3 (DSH-55): PutBucketReplication وDeleteBucketReplication. النسخ عبر الحسابات ينسخ بصمت كل كائن جديد إلى دلو يتحكم فيه المهاجم، منشئًا قناة تسريب مستمرة تتجاوز ضوابط منع تسرب بيانات الشبكة. أي PutBucketReplication يشير إلى معرّف حساب خارجي مؤشر حادثة حرجة. MITRE ATT&CK: TA0010 Exfiltration / T1537 Transfer Data to Cloud Account. |
| 5 | S3 Bucket Policy / ACL Changes | أحداث تعديل سياسة دلو S3 وACL (DSH-45): PutBucketPolicy وDeleteBucketPolicy وPutBucketAcl وPutBucketCors وPutBucketWebsite وDeleteBucketWebsite. يمكن أن تعرّض هذه التغييرات محتويات الدلو للعامة أو تمنح وصولًا لحسابات يتحكم فيها المهاجم. PutBucketPolicy مع Principal='*' مؤشر تعرّض بيانات فوري. MITRE ATT&CK: TA0010 Exfiltration / TA0005 Defense Evasion. |
| 6 | S3 Bucket & Object List Activity | استدعاءات API لتعداد S3 مجمّعة حسب الهوية وIP المصدر (DSH-74). يغطي ListBuckets (اكتشاف الحساب بأكمله)، وListObjects / ListObjectsV2 (تعداد لكل دلو)، وListObjectVersions، وListMultipartUploads، وHeadBucket، وHeadObject. الارتفاع المفاجئ في استدعاءات القائمة من هوية جديدة أو IP خارجي يوحي بقوة باستطلاع بعد اختراق بيانات اعتماد. MITRE ATT&CK: TA0007 Discovery. |
| 7 | S3 Protection Config Changes | أحداث S3 التي تُضعف وضع أمان الدلو (DSH-25). تعطيل تسجيل وصول الخادم يزيل أثر التدقيق؛ إزالة منع الوصول العام يعرّض البيانات للإنترنت؛ حذف تشفير الدلو أو النسخ يُضعف حماية البيانات الساكنة. هذه إجراءات سابقة للتسريب أو للتستر. MITRE ATT&CK: TA0005 Defense Evasion / TA0040 Impact. |
| 8 | AWS Backup Vault & Plan Deletion Events | أحداث حذف AWS Backup Vault وPlan وRecovery Point (DSH-57): DeleteBackupVault وDeleteBackupPlan وDeleteRecoveryPoint وDeleteBackupSelection وDisassociateRecoveryPoint وPutBackupVaultAccessPolicy وDeleteBackupVaultLockConfiguration. تدمير النسخ الاحتياطية هو الخطوة الأولى في حملة برامج فدية — يضمن أن الضحية لا يمكنه الاستعادة من النسخ الاحتياطية قبل تقديم طلب الفدية. حذف Vault Lock (DeleteBackupVaultLockConfiguration) حرج بشكل خاص لأنه يزيل ثبات WORM عن الخزنة. MITRE ATT&CK: TA0040 Impact / T1490 Inhibit System Recovery. |
| 9 | KMS Key Deletion & Disable Events | أحداث حذف مفتاح KMS وتعطيله (DSH-66). ScheduleKeyDeletion — يجدول حذف المفتاح (نافذة 7-30 يومًا للإلغاء). DisableKey — يوقف فورًا التشفير/فك التشفير بالمفتاح. DeleteImportedKeyMaterial — يدمّر مادة المفتاح للمفاتيح المستوردة فورًا. DisableKeyRotation — يمنع التدوير السنوي التلقائي للمفتاح. أي من هذه الأحداث يجعل كل البيانات المشفَّرة بالمفتاح غير قابلة للوصول بشكل دائم. استخدم CancelKeyDeletion لعكس ScheduleKeyDeletion قبل تاريخ الحذف. MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction. |
| 10 | RDS Deleted without Final Snapshot | حذف مثيل ومجموعة RDS مع skipFinalSnapshot=true (DSH-56): أحداث DeleteDBInstance وDeleteDBCluster حيث لم تُؤخذ لقطة نهائية. تخطي اللقطة النهائية يجعل قاعدة البيانات غير قابلة للاسترداد — لا توجد نقطة استعادة بعد الحذف. تستخدم جهات برامج الفدية هذا لتعظيم الضغط على الضحية عند تعطيل AWS Backup أيضًا. أي حدث هنا حادثة حرجة. MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction. |
| 11 | RDS Snapshot Cross-Account Share | أحداث مشاركة لقطة RDS وAurora (DSH-40): ModifyDBSnapshotAttribute وModifyDBClusterSnapshotAttribute حيث مُنح إذن الاستعادة لحساب AWS آخر (valuesToAdd). يشارك المهاجمون اللقطات إلى حسابهم الخاص لتسريب قاعدة بيانات كاملة دون منع تسرب بيانات قائم على S3/الشبكة. أي معرّف حساب خارجي في سمة الاستعادة مؤشر تسريب حرج. MITRE ATT&CK: TA0010 Exfiltration. |

### 🖥️ Computing

| # | اسم المخطط | الوصف |
|---|------------|-------------|
| 1 | EC2 Instance Launches | جميع أحداث RunInstances في EC2 (DSH-58). يطلق المهاجمون مثيلات لتعدين العملات المشفرة (GPU/spot)، أو ترحيل القيادة والتحكم، أو تجهيز الحركة الجانبية — غالبًا في مناطق غير متوقعة لتجنب الكشف. صفِّ حسب aws_region للتحقيق في شذوذ المنطقة؛ صفِّ حسب user_identity_arn لتتبع بيانات الاعتماد التي أطلقت المثيل. MITRE ATT&CK: TA0002 Execution / TA0040 Impact (Resource Hijacking). |
| 2 | RunInstances Spike by Region | حجم RunInstances اليومي في EC2، مكدّس حسب منطقة AWS (DSH-97). الارتفاع المفاجئ — خصوصًا في مناطق خارج التشغيل العادي — يشير إلى تعدين العملات المشفرة أو إساءة استخدام الموارد. قارن بالكيان الأساسي المُنفِّذ وIP المصدر. MITRE ATT&CK: T1496 Resource Hijacking. |
| 3 | EC2 Mass Stop / Terminate | أحداث StopInstances وTerminateInstances في EC2 (DSH-62). استدعاء API واحد يمكن أن يوقف أو ينهي عشرات المثيلات في آن واحد. الإنهاء الجماعي هو المرحلة التخريبية لهجوم برامج فدية أو تخريب — يُسقط سعة EC2 الإنتاجية. تحقق من حقل request_parameters للحصول على القائمة الكاملة لمعرّفات المثيلات المتأثرة. اجمعه مع مخططي العبث بـ AWS Backup والحذف الجماعي في S3 لتحديد سلسلة برامج الفدية الكاملة. MITRE ATT&CK: TA0040 Impact / T1489 Service Stop. |
| 4 | EC2 Key Pair Creation | أحداث إنشاء واستيراد زوج مفاتيح EC2 (DSH-59): CreateKeyPair وImportKeyPair وDeleteKeyPair. ينشئ المهاجمون أزواج مفاتيح جديدة لترسيخ وصول SSH مستمر إلى مثيلات EC2 ينجو من تدوير بيانات اعتماد IAM. يحقن ImportKeyPair مفتاحًا عامًا يتحكم فيه المهاجم مباشرةً دون أن تولّده AWS. أي CreateKeyPair أو ImportKeyPair من هوية أو IP غير مألوف مؤشر استمرارية. MITRE ATT&CK: TA0003 Persistence. |
| 5 | EC2 Instance Profile Changes | أحداث إدارة ملف تعريف مثيل EC2 وملف تعريف مثيل IAM (DSH-60). IAM: CreateInstanceProfile وDeleteInstanceProfile وAddRoleToInstanceProfile وRemoveRoleFromInstanceProfile. EC2: AssociateIamInstanceProfile وDisassociateIamInstanceProfile وReplaceIamInstanceProfileAssociation. تغيير ملف تعريف المثيل يستبدل دور IAM المتاح لكل الشيفرة على المثيل — مسار شائع لتصعيد الامتيازات عندما يتحكم المهاجم في مثيل لكنه يريد دورًا ذا امتيازات أعلى. MITRE ATT&CK: TA0004 Privilege Escalation / TA0003 Persistence. |
| 6 | EC2 User Data Modification | أحداث تعديل بيانات مستخدم EC2 (DSH-61): ModifyInstanceAttribute حيث يُغيَّر سمة userData. يُنفَّذ سكريبت بيانات مستخدم EC2 بواسطة cloud-init عند كل (إعادة) تشغيل للمثيل — حقن سكريبت خبيث يوفّر تنفيذ شيفرة مستمرًا ينجو من إعادة التشغيل. غالبًا ما يقترن بتسلسل إيقاف/تشغيل (انظر مخطط الإيقاف/الإنهاء الجماعي لـ EC2) لإثارة التنفيذ. MITRE ATT&CK: TA0003 Persistence / TA0002 Execution. |
| 7 | EC2 Public Snapshot / AMI Sharing | أحداث مشاركة لقطة EBS وصورة AMI علنًا في EC2 (DSH-41): ModifySnapshotAttribute مع منح createVolumePermission للمجموعة 'all'، وModifyImageAttribute مع منح launchPermission للمجموعة 'all'. اللقطة أو الصورة العامة تتيح لأي حساب AWS نسخ صورة القرص واستخراج البيانات الحساسة وبيانات الاعتماد والمفاتيح الخاصة المخزّنة على المستوى. MITRE ATT&CK: TA0010 Exfiltration. |
| 8 | EC2 Spot Fleet & Reserved Instance Purchases | أحداث شراء Spot Fleet وFleet وReserved Instance في EC2 (DSH-63): RequestSpotFleet وModifySpotFleetRequest وCancelSpotFleetRequests وCreateFleet وDeleteFleet وPurchaseReservedInstancesOffering وRequestSpotInstances وCancelSpotInstanceRequests. يستخدم المهاجمون Spot Fleets لإطلاق مجموعات GPU/CPU كبيرة لتعدين العملات المشفرة، مولّدين فواتير AWS مرتفعة مع البقاء تحت عتبات الكشف لكل مثيل. أي شراء Spot Fleet أو Reserved Instance غير متوقع يستدعي التحقيق. MITRE ATT&CK: TA0040 Impact / T1496 Resource Hijacking. |
| 9 | ECS Task Definition & Service Changes | أحداث تسجيل تعريف مهمة ECS وتعديل الخدمة (DSH-49). تُسجّل وحدة ecs__backdoor_task_def في Pacu مراجعة تعريف مهمة جديدة تحقن حاوية جانبية لسرقة بيانات الاعتماد، ثم تصدر UpdateService لنشرها — متجاوزةً مراقبة صور ECR كليًا. أي RegisterTaskDefinition أو UpdateService غير متوقع من مستدعٍ أو IP غير مألوف يستدعي تحقيقًا فوريًا. MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0006 Credential Access. |
| 10 | Lambda Function Configuration & Permission Changes | أحداث تهيئة وأذونات دالة Lambda (DSH-64). يستبدل UpdateFunctionCode شيفرة الدالة بحمولة خبيثة. يمنح AddPermission وصول استدعاء Lambda عبر الحسابات أو علنًا. ينشئ CreateFunctionUrlConfig نقطة نهاية HTTP عامة للقيادة والتحكم المباشر. يربط CreateEventSourceMapping الدالة لتُطلَق عند S3/DynamoDB/SQS. يحقن PublishLayerVersion طبقة مشتركة خبيثة عبر عدة دوال. أي من هذه من هوية أو IP غير متوقع مؤشر استمرارية/تنفيذ. MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0011 Command and Control. |
| 11 | SSM Session / Run Command Execution | أحداث تنفيذ AWS Systems Manager عن بُعد (DSH-39): StartSession وTerminateSession وResumeSession وSendCommand وStartAutomationExecution. يوفّر SSM Session Manager وصول shell دون فتح منافذ SSH/RDP وهو الآلية الأساسية للحركة الجانبية للمهاجمين ببيانات اعتماد IAM مسروقة. أي جلسة أو أمر غير متوقع من IP أو هوية غير معتادة يستدعي تحقيقًا فوريًا. MITRE ATT&CK: TA0008 Lateral Movement / TA0002 Execution. |
| 12 | EBS Direct API Snapshot Block Access | استدعاءات EBS Direct API المستخدمة لتسريب بيانات اللقطة (DSH-51). تستخدم وحدة ebs__download_snapshots في Pacu ListSnapshotBlocks وGetSnapshotBlock لبث صورة قرص EBS كاملة كتلةً كتلةً دون إنشاء مثيل EC2، أو طلب نسخة لقطة، أو إثارة حدث ModifySnapshotAttribute — مما يجعلها غير مرئية لكشف مشاركة اللقطات التقليدي. أي استدعاء GetSnapshotBlock أو ListSnapshotBlocks من هوية أو عنوان IP غير متوقع مؤشر تسريب حرج. MITRE ATT&CK: TA0010 Exfiltration / TA0009 Collection. |
| 13 | EKS / ECR Container Platform Events | أحداث مجموعة EKS وسجل حاويات ECR (DSH-48). EKS: UpdateClusterConfig (واجهة API عامة)، وCreateFargateProfile (أحمال عمل خبيثة)، وAssociateIdentityProviderConfig (موفّر هوية OIDC مارق). ECR: PutImage (دفع صورة مزروعة بباب خلفي)، وSetRepositoryPolicy (وصول عبر الحسابات)، وPutRegistryPolicy (تعريض السجل على مستوى المؤسسة). أحداث منصة الحاويات حرجة لكشف هجمات سلسلة التوريد واختراق مستوى تحكم Kubernetes. MITRE ATT&CK: TA0002 Execution / TA0003 Persistence / TA0010 Exfiltration. |
| 14 | CloudFormation Stack Changes | أحداث إدارة حزمة ومجموعة تغيير CloudFormation (DSH-65). يمكن لـ UpdateStack واحد نشر مثيلات EC2 أو تعديل أدوار IAM أو إعادة تهيئة الشبكة — موحّدًا عشرات استدعاءات API الفردية في حدث واحد. ينشر CreateStackSet بنية تحتية للمهاجم عبر كل الحسابات في مؤسسة. يطبّق ExecuteChangeSet تغييرًا مُجهَّزًا مسبقًا، مخفيًا نطاق التأثير عن المراجعة الأولية. يمكن لـ DeleteStack تدمير موارد الأدلة الجنائية. MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0005 Defense Evasion. |

### 🤖 AI / LLM

| # | اسم المخطط | الوصف |
|---|------------|-------------|
| 1 | Bedrock Model Invocation Trend | حجم استدعاء نماذج Amazon Bedrock اليومي لكل كيان أساسي (DSH-98). يُعاد بيع الاستدلال عالي الحجم على بيانات اعتماد مسروقة (LLMjacking) عبر وكلاء عكسيين على حساب الضحية. حقّق في أي ارتفاع، وأي كيان أساسي لم يستدعِ Bedrock من قبل، وأي استدعاء من أصل غير متوقع. MITRE ATT&CK: TA0040 Impact (T1496 Resource Hijacking). |
| 2 | Bedrock Model Access & Logging Changes | تفعيل الوصول إلى النماذج الأساسية والعبث بتسجيل الاستدعاءات (DSH-99). يفعّل المهاجمون ببيانات اعتماد مسروقة الوصول إلى نماذج Bedrock بأنفسهم قبل إساءة استخدامها، ويتحققون من تهيئة تسجيل استدعاءات النماذج أو يحذفونها حتى لا تُسجَّل مطالباتهم — كلاهما مؤشران موثَّقان على LLMjacking. أي صف في مؤسسة لم تتبنَّ Bedrock مطلقًا يستدعي تحقيقًا فوريًا. MITRE ATT&CK: TA0005 Defense Evasion / TA0040 Impact (T1496). |
| 3 | Bedrock Failed Invocations | محاولات استدعاء Amazon Bedrock الفاشلة مجمّعة حسب المستدعي ورمز الخطأ (DSH-100). دفعات أخطاء AccessDenied / ValidationException عبر نماذج ومناطق متعددة تشير إلى مهاجم يسبر أي النماذج يمكن لمفتاح مسروق استدعاءها — مرحلة الاستطلاع في LLMjacking. MITRE ATT&CK: TA0006 Credential Access / TA0007 Discovery. |
| 4 | Bedrock Callers by Origin | جرد لكل مستدعي Amazon Bedrock مع الأصل وتنوع النماذج (DSH-101). عرض خط أساس لفرز LLMjacking: الكيانات الأساسية التي تستدعي من بلدان غير متوقعة، أو ASN استضافة/VPN، أو وكلاء مستخدم برمجة عامة (python-requests، curl) بحجم استدعاء عالٍ هي المشتبه بها الرئيسية. MITRE ATT&CK: TA0040 Impact (T1496 Resource Hijacking). |

### 🌐 Network

| # | اسم المخطط | الوصف |
|---|------------|-------------|
| 1 | Security Group Changes | تغييرات قواعد مجموعة الأمان في EC2 (DSH-76). يغطي تفويض وإلغاء قواعد الدخول/الخروج، وإنشاء وحذف مجموعة الأمان، وتحديثات وصف القاعدة. قواعد الدخول المفتوحة لـ 0.0.0.0/0 على منافذ إدارية (22، 3389، إلخ) مؤشر قوي على وصول خلفي أو خطأ تهيئة. MITRE ATT&CK: TA0003 Persistence / TA0005 Defense Evasion. |
| 2 | Network ACL / Route Table Changes | أحداث تعديل Network ACL وجدول التوجيه (DSH-46). تغييرات NACL (CreateNetworkAclEntry، DeleteNetworkAclEntry، ReplaceNetworkAclEntry) يمكن أن تتجاوز قيود مجموعة الأمان لشبكات فرعية كاملة. تغييرات جدول التوجيه (CreateRoute، ReplaceRoute، DeleteRoute) يمكن أن تعيد توجيه حركة المرور إلى بنية تحتية يتحكم فيها المهاجم للاعتراض أو إنشاء قنوات اتصال صامتة للقيادة والتحكم. MITRE ATT&CK: TA0005 Defense Evasion / TA0011 Command and Control. |
| 3 | VPC Infrastructure Changes | أحداث تغيير طوبولوجيا VPC (DSH-77). يغطي إنشاء/حذف/تعديل VPC، وتغييرات الشبكة الفرعية، وإرفاق بوابة الإنترنت، وإنشاء/حذف بوابة NAT، وتغييرات نقطة نهاية VPC، وتخصيص/ربط Elastic IP. إرفاقات IGW غير المتوقعة أو بوابات NAT جديدة في مناطق غير مستخدمة مؤشرات قوية على بنية تحتية للتسريب يتحكم فيها المهاجم. MITRE ATT&CK: TA0010 Exfiltration / TA0003 Persistence / TA0011 C2. |
| 4 | VPC Peering & Transit Gateway Changes | أحداث تغيير تناظر VPC وTransit Gateway (DSH-78). يغطي إنشاء/قبول/حذف تناظر VPC وإنشاء Transit Gateway، وإرفاق VPC، وإدارة إرفاق التناظر. طلبات التناظر عبر الحسابات أو إرفاقات Transit Gateway الجديدة من حسابات غير متوقعة تشير إلى حركة جانبية بين حسابات AWS. MITRE ATT&CK: TA0008 Lateral Movement / TA0010 Exfiltration. |
| 5 | Route53 DNS Changes | تغييرات تهيئة المنطقة المستضافة والمحلِّل في Route 53 (DSH-29). يستخدم نفق DNS سجلات TXT/CNAME وأعدادًا كبيرة من النطاقات الفرعية لتسريب البيانات في حمولات استعلام DNS. ينبغي التحقيق فورًا في المناطق المستضافة الجديدة واستدعاءات ChangeResourceRecordSets غير المتوقعة. MITRE ATT&CK: TA0010 Exfiltration. |

### 🕒 Temporal Analysis

| # | اسم المخطط | الوصف |
|---|------------|-------------|
| 1 | Event Velocity Spikes per Identity | الهويات ذات 50 حدثًا أو أكثر في الساعة خلال فترات نشاط متفجرة (DSH-38). حشو بيانات الاعتماد، أو التعداد الآلي، أو تسريب البيانات يُنشئ ارتفاعات سرعة حادة فوق خطوط الأساس العادية. يعرض فترة الساعة والهوية وعدد الأحداث لكل ارتفاع. MITRE ATT&CK: TA0006 Credential Access / TA0009 Collection / TA0010 Exfiltration. |
| 2 | Dormant Accounts Reactivated | الهويات ذات فجوات الخمول لمدة 72 ساعة أو أكثر التي استأنفت النشاط (DSH-37). نمط كلاسيكي لتسليح بيانات اعتماد خاملة مخترقة. يعرض أكبر فجوة بالساعات/الأيام بين أحداث متتالية لكل هوية. MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence. |
| 3 | First / Last Seen per IAM Identity | هويات IAM مع طوابع أول/آخر مشاهدة، وأعداد الأحداث، وواجهات API المتمايزة، وعناوين IP المتمايزة، ومدة النشاط بالأيام (DSH-31). رتّب حسب first_seen تنازليًا للعثور على الهويات الحديثة الظهور. مدد النشاط القصيرة مع أعداد أحداث عالية تشير إلى بيانات اعتماد مخترقة أو هجمات آلية. MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence. |
| 4 | First / Last Seen per Source IP | عناوين IP المصدرية مع أول/آخر مشاهدة، والهويات المتمايزة، وواجهات API المتمايزة، وسياق GeoIP (DSH-32). عناوين IP الجديدة التي تظهر متأخرة في مجموعة البيانات توحي بحركة جانبية أو بنية تحتية جديدة للمهاجم. MITRE ATT&CK: TA0001 Initial Access / TA0008 Lateral Movement. |
| 5 | First / Last Seen per API Call | إجراءات API مرتبة حسب الظهور الأول (DSH-33). استدعاءات API الجديدة التي تظهر للمرة الأولى توحي بمحاولات استطلاع أو تصعيد امتيازات. MITRE ATT&CK: TA0007 Discovery / TA0004 Privilege Escalation. |
| 6 | First / Last Seen per Service Source | طوابع أول وآخر مشاهدة لكل مصدر خدمة AWS متمايز (DSH-26). رتّب حسب first_seen تنازليًا لإبراز الخدمات المُدخلة حديثًا (بنية تحتية محتملة للمهاجم). رتّب حسب last_seen تصاعديًا للعثور على الخدمات التي صمتت (تنظيف محتمل بعد الاختراق). MITRE ATT&CK: TA0003 Persistence / TA0007 Discovery. |

### 🌍 GeoIP Intelligence

| # | اسم المخطط | الوصف |
|---|------------|-------------|
| 1 | Impossible Travel (Multi-Country Principals) | كيانات IAM الأساسية مرتبة حسب البلدان المصدرية المتمايزة، مع عناوين IP المصدرية المتمايزة، وإجمالي الأحداث، وأول/آخر مشاهدة (DSH-92). distinct_countries >= 2 لكيان أساسي بشري إشارة قوية على اختراق الحساب — قارن بالنافذة الزمنية وعناوين IP المصدرية. يتطلب إثراء GeoIP. MITRE ATT&CK: TA0001 Initial Access / T1078 Valid Accounts. |
| 2 | Top Countries by Request Volume | أبرز 20 بلدًا مصدريًا حسب حجم استدعاءات API، مع تفصيل أحداث الكتابة والمستدعين الفريدين (DSH-15). البلدان غير المرتبطة عادةً بعمليات المؤسسة قد تشير إلى سرقة بيانات اعتماد أو بنية تحتية يتحكم فيها المهاجم. يتطلب إثراء GeoLite2 — تُستبعد الصفوف الفارغة (NULL) تلقائيًا. |
| 3 | Top ASN Organizations by Request Volume | أبرز 25 مؤسسة ASN حسب حجم استدعاءات API مع تفصيل أحداث الكتابة والمستدعين الفريدين (DSH-18). حركة المرور الصادرة من مزودي VPN أو عقد خروج Tor أو شركات الاستضافة أو مزودي الحوسبة السحابية خارج البصمة المتوقعة قد تشير إلى استخدام المهاجم لبنية تحتية لإخفاء الهوية. يتطلب إثراء GeoLite2 — تُستبعد الصفوف الفارغة (NULL) تلقائيًا. |
| 4 | Top Cities by Request Volume | أبرز 25 مدينة حسب حجم استدعاءات API مع تفصيل أحداث الكتابة والمستدعين الفريدين (DSH-17). الدقة على مستوى المدينة يمكن أن تكشف عن مواقع مراكز بيانات محددة تستخدمها الجهات الفاعلة في التهديد كانت لتُحجب بتحليل على مستوى البلد فقط. يتطلب إثراء GeoLite2 — تُستبعد الصفوف الفارغة (NULL) تلقائيًا. |
| 5 | Global Request Origin Map | خريطة عالمية تعرض التوزيع الجغرافي لأصول استدعاءات API في CloudTrail (DSH-16). شدة لون البلد تتناسب مع عدد الأحداث. البلدان غير المرتبطة عادةً بعمليات المؤسسة قد تشير إلى سرقة بيانات اعتماد أو بنية تحتية يتحكم فيها المهاجم. يتطلب إثراء GeoLite2 — تُستبعد الصفوف الفارغة (NULL) تلقائيًا. |
| 6 | API Calls by Country (Event Name × GeoIP) | أبرز 50 زوجًا من (event_name, country) حسب حجم استدعاءات API (DSH-79). يكشف عن عمليات API التي تُستدعى من كل منطقة جغرافية. عمليات الكتابة من بلدان غير متوقعة مؤشر قوي على اختراق بيانات الاعتماد. يتطلب إثراء GeoLite2 — تُستبعد عناوين IP الخاصة/الداخلية والصفوف الفارغة (NULL). |

</details>

---
