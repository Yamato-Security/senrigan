# เอกสารอ้างอิง Query และ Dashboard ในตัว

> 💡 ไม่ต้องใช้ SQL หรือความรู้เชิงลึกเกี่ยวกับ AWS — เพียงเลือก hunt จาก dropdown แล้วรับผลลัพธ์ได้ทันที

## 🎯 Hunts ในตัว — 151 queries

หมวดหมู่ถูกจัดเรียงตามลำดับความสำคัญของการ triage แบบ DFIR — ตรวจสอบการดัดแปลงเครื่องมือตรวจจับก่อน จากนั้นจึงตรวจสอบการใช้อัตลักษณ์ในทางมิชอบ แล้วตามด้วยผลกระทบต่อข้อมูล

| หมวดหมู่ | จำนวน Query | ภัยคุกคามสำคัญที่ครอบคลุม |
|----------|:-------:|---------------------|
| 🛡 Detection & Response | 13 | การดัดแปลงบริการตรวจสอบ (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · การลบ SCP · การระงับสัญญาณเตือน · การลักลอบนำ log ออก · การเชื่อมโยงห่วงโซ่การโจมตีแรนซัมแวร์ |
| 🔑 Identity & Access | 44 | การใช้งาน root · การล็อกอินคอนโซล/MFA · การยกระดับสิทธิ์ · แบ็คดอร์ผ่าน trust policy · การใช้ PassRole ในทางมิชอบ · AssumeRole ข้ามบัญชี · SSO/SAML/OIDC · การแจกแจงข้อมูลประจำตัว · การลบ IAM entity · การยึดครองผ่าน AssumeRoot · การใช้ user pool/token ของ Cognito ในทางมิชอบ · การระงับ support case · การเชื่อมต่อบทบาท · การติดตามข้อมูลรับรองเซสชัน · การสอดแนมด้วย GetCallerIdentity · การเข้าสู่ระบบคอนโซลแบบเฟเดอเรต · ชุดสิทธิ์ Identity Center และผู้ดูแลที่ได้รับมอบหมาย · การเชื่อมต่อบทบาท · การติดตามข้อมูลรับรองเซสชัน · การเรียก API โดยไม่มี MFA · การเข้าสู่ระบบแบบเฟเดอเรต · ชุดสิทธิ์ Identity Center |
| 🪣 Data & Storage | 30 | การลบ/ดาวน์โหลด S3 จำนวนมาก · การอ่าน secrets จำนวนมาก · การดัดแปลงการสำรองข้อมูล · การดำเนินการ KMS · การแชร์ snapshot · การลักลอบนำข้อมูลออกผ่าน EBS Direct API · การ export DynamoDB · การจำลอง S3 ข้ามบัญชี · การเข้ารหัส SSE-C แบบ ransomware · การลบที่กระตุ้นโดย lifecycle · การจัดการ RDS Data API · การเข้ารหัสที่จัดเก็บข้อมูลใหม่เพื่อสร้างผลกระทบ · การวางข้อความเรียกค่าไถ่ · การกำหนดขอบเขตสำหรับการแจ้งเหตุละเมิด · การคัดลอกอ็อบเจกต์ข้ามบัญชี · การสร้าง URL แบบลงนามล่วงหน้า |
| ⚡ Compute & Serverless | 17 | การหยุด/ยกเลิก EC2 จำนวนมาก · การเคลื่อนที่ด้านข้างผ่าน SSM · การดัดแปลง Lambda/ECS/EKS/ECR · การคงอยู่ผ่าน EventBridge · cryptomining · การใช้ Lightsail ในทางมิชอบ · การลดความเข้มงวดของ IMDS/SSRF · การลบ AMI/snapshot · การยึดครอง WorkSpaces |
| 🤖 AI & LLM Abuse | 11 | การพุ่งสูงของการเรียกใช้โมเดล Bedrock · การเปิดใช้งานการเข้าถึงโมเดล · การดัดแปลงการบันทึก log การเรียกใช้ · การสอดแนมแบบกวาดทั่วภูมิภาค · การพุ่งสูงของการเรียกใช้ที่ล้มเหลว · บัญชีรายชื่อผู้เรียก/แหล่งที่มา (LLMjacking) · ที่เก็บโทเค็น AgentCore · การข้ามการอนุญาตเกตเวย์ · ความสมบูรณ์ของหน่วยความจำ · การเปลี่ยนโหมดเครือข่ายแซนด์บ็อกซ์ · การแก้ไขระบบสังเกตการณ์ |
| 🌐 Network & Infrastructure | 16 | SG เปิดสู่อินเทอร์เน็ต · การลบ VPC flow log · การยึด CloudFront · อุโมงค์ VPN/TGW แอบแฝง · Elastic IP สำหรับ C2 · คีย์ API Gateway · การยึดครอง Route 53/โดเมน · การลดทอนการป้องกัน DDoS |
| 🕵 Threat Patterns | 10 | การพุ่งของการสอดแนม · user agents ที่ผิดปกติ · การกระจายข้ามหลายภูมิภาค · การเรียก API ครั้งแรก · กิจกรรมภูมิภาคที่พบครั้งแรก · กิจกรรมนอกเวลาทำการ · การยกระดับสิทธิ์ให้ตนเอง · ความเบี่ยงเบนของปริมาณรายวัน · การสร้างทรัพยากรในภูมิภาคที่ไม่ได้ใช้ · การเรียก API ปริมาณมาก |
| 📊 Activity & Baseline | 3 | เหตุการณ์การเขียนผ่านคอนโซล · การพุ่งขึ้นของ error · error ล่าสุด |
| 🌍 GeoIP Analysis | 10 | การล็อกอิน/การปฏิเสธ/การเขียนผ่านคอนโซลจัดอันดับตามประเทศ · การเข้าถึงจากประเทศที่พบยาก · การแยกย่อยตามประเทศ/ASN/เมือง · event_name × country · identity × country · เส้นฐาน private-IP |
| ☁ IaC & Platform | 2 | การโจมตี supply chain ของ CI/CD · การใช้ CloudFormation ในทางมิชอบ |

<details markdown="1">
<summary>📋 รายการทั้งหมด — ทุก query ทั้ง 151 รายการ (คลิกเพื่อขยาย)</summary>

## Hunts ในตัว

### 🛡 Detection & Response

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | ตรวจจับความพยายามใด ๆ ที่จะหยุดหรือแก้ไข CloudTrail — สัญญาณเตือนที่สำคัญที่สุด บ่งชี้การปกปิดร่องรอย |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | ตรวจจับการปิดใช้งาน การลบ และการบิดเบือน threat-intel ของ GuardDuty การเปลี่ยนแปลงใด ๆ ต่อ GuardDuty ระหว่างการสืบสวนถือเป็นตัวบ่งชี้ที่สำคัญ |
| 3 | ⛔ Security Hub Tampering | timeseries | ตรวจจับการปิดใช้งาน Security Hub การปิดใช้งาน standard และการระงับ finding การปิดเสียง Security Hub เป็นการขจัดจุดรวมศูนย์ของ finding ด้านความปลอดภัยทั้งหมด |
| 4 | ⚙️ AWS Config Tampering | timeseries | ตรวจจับการลบ recorder/rule ของ AWS Config การหยุด Config จะขจัดหลักฐานการปฏิบัติตามข้อกำหนดและการติดตามการเปลี่ยนแปลงของทั้งภูมิภาค |
| 5 | 🛡 Organizations Service Control Policy (SCP) Changes | timeseries | ตรวจจับการสร้าง การแก้ไข และการลบ SCP การลบ Deny SCP จะขจัด guardrail ในทุกบัญชีของ OU ที่ได้รับผลกระทบทันที |
| 6 | 🚫 AWS Macie Tampering | timeseries | ตรวจจับการปิดใช้งาน Macie และการสร้าง finding-filter ผู้โจมตีระงับ finding ของ Macie ก่อนที่จะลักลอบนำข้อมูลที่ละเอียดอ่อนออกจาก S3 |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | ตรวจจับการลบและการปิดใช้งาน alarm ของ CloudWatch การปิดเสียง alarm ที่ผูกกับ GuardDuty, ตัวกรอง metric ของ CloudTrail หรือเกณฑ์ค่าใช้จ่ายเป็นตัวบ่งชี้การหลบเลี่ยงการป้องกันที่สำคัญ |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | ตรวจจับการสร้าง/ลบ subscription filter ของ CW Logs และการลบ log group ผู้โจมตีสตรีม log ไปยังปลายทางภายนอกหรือทำลายหลักฐานในที่เกิดเหตุ |
| 9 | 🏹 WAF WebACL Changes | timeseries | ตรวจจับการสร้าง การอัปเดต และการลบ WAF WebACL การลบหรือลดความเข้มงวดของ WebACL ปิดการป้องกันจาก SQLi, XSS และการโจมตี DDoS |
| 10 | 🔍 GuardDuty Findings Read | timeseries | ตรวจจับการเรียก API แบบอ่านอย่างเดียวของ GuardDuty โมดูล guardduty__list_findings ของ Pacu อ่าน finding ที่ใช้งานอยู่เพื่อทำความเข้าใจว่าผู้ป้องกันตรวจพบอะไรไปแล้ว ทำให้ผู้โจมตีปรับกลยุทธ์และหลีกเลี่ยงการกระตุ้นสัญญาณเตือนใหม่ |
| 11 | 💰 Budget / Cost Anomaly Changes | timeseries | ตรวจจับการลบหรือแก้ไข AWS Budgets และตัวตรวจสอบ Cost Anomaly ผู้โจมตีลบสัญญาณเตือนงบประมาณเพื่อซ่อน cryptomining หรือการดำเนินการที่ใช้ทรัพยากรมาก |
| 12 | 🚫 Access Denied Errors | bar | จัดกลุ่ม error AccessDenied ตามอัตลักษณ์และ API ผู้กระทำผิดอันดับต้นอาจบ่งชี้การใช้ credential ในทางมิชอบ |
| 13 | ⛓ Ransomware Kill-Chain Sequence | bar | เชื่อมโยงสามระยะของแรนซัมแวร์ — ลบช่องทางกู้คืน ปิดการป้องกัน ทำลายหรือเข้ารหัสข้อมูล — ตามหลักการและวัน แต่ละระยะโดยลำพังคือสัญญาณรบกวนจากการปฏิบัติงาน แต่ทั้งสามรวมกันไม่ใช่ |

### 🔑 Identity & Access

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | ตรวจจับการเรียก API ใด ๆ ที่ทำโดยบัญชี root ไม่ควรใช้ root ใน production เลย |
| 2 | 🔓 Console Login without MFA | timeseries | ตรวจจับการล็อกอินคอนโซลที่ไม่ได้ใช้ MFA ตัวบ่งชี้ความเสี่ยงสูงของการถูกบุกรุกบัญชี |
| 3 | 🌐 Console Logins | timeseries | แสดงรายการความพยายามล็อกอินคอนโซลทั้งหมด การโจมตีแบบ brute force = ความล้มเหลวหลายครั้งตามด้วยความสำเร็จ |
| 4 | 🔐 MFA & Password Changes | timeseries | ตรวจจับการปิดใช้งาน MFA และการรีเซ็ตรหัสผ่าน ตัวบ่งชี้ที่ชัดเจนของการยึดบัญชี |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | ตรวจจับเหตุการณ์การแนบ IAM policy และการบิดเบือน role ที่ใช้สำหรับการยกระดับสิทธิ์ |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | ตรวจจับการเรียก UpdateAssumeRolePolicy การเพิ่ม principal จากบัญชีภายนอกเข้าไปใน trust policy สร้างแบ็คดอร์แบบถาวร |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | ตรวจจับเหตุการณ์ put/delete ของ permission boundary การลบ permission boundary จะขยายสิทธิ์ที่มีผลของ principal ทันที ทำให้เกิดการยกระดับสิทธิ์ |
| 8 | 👑 User Added to Admin Group | timeseries | ตรวจจับผู้ใช้ที่ถูกเพิ่มเข้ากลุ่มที่มีคำว่า 'admin' ในชื่อ เทคนิคการยกระดับสิทธิ์แบบคลาสสิก |
| 9 | 👥 IAM Group Membership Changes | timeseries | ตรวจจับเหตุการณ์ AddUserToGroup และ RemoveUserFromGroup ทั้งหมดโดยไม่คำนึงถึงชื่อกลุ่ม การเพิ่มเข้ากลุ่มใด ๆ อาจบ่งชี้การยกระดับสิทธิ์ผ่าน policy ที่สืบทอดจากกลุ่ม |
| 10 | 👤 New IAM Users / Keys | timeseries | ระบุเหตุการณ์การสร้างผู้ใช้ IAM และ access key การสร้างที่ไม่คาดคิดอาจบ่งชี้การคงอยู่ |
| 11 | 🎯 IAM PassRole Abuse | timeseries | ตรวจจับการเรียก iam:PassRole การส่ง role ที่มีสิทธิ์สูงไปยัง EC2/Lambda/Glue/ECS/SageMaker เป็นเส้นทางการยกระดับสิทธิ์แบบเคลื่อนที่ด้านข้างที่พบบ่อยที่สุด |
| 12 | 🔐 AssumeRole Cross-Account | timeseries | แสดงเหตุการณ์ AssumeRole ที่ผู้เรียกและเป้าหมายอยู่ในบัญชี AWS ต่างกัน บ่งชี้การเคลื่อนที่ด้านข้าง |
| 13 | 🏢 Cross-Account Access | timeseries | ค้นหาเหตุการณ์ที่บัญชีผู้เรียกต่างจากบัญชีผู้รับ สัญญาณของการเคลื่อนที่ด้านข้าง |
| 14 | 🔑 STS Federation Token Issuance | timeseries | ตรวจจับการเรียก GetFederationToken และ GetSessionToken ผู้โจมตีใช้สิ่งนี้เพื่อแปลงคีย์อายุยาวให้เป็น credential ชั่วคราวแบบถาวร |
| 15 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | ตรวจจับการเรียก AssumeRoleWithWebIdentity การใช้ OIDC trust ที่ตั้งค่าผิดในทางมิชอบ (เช่น sub claim ที่กว้างเกินไป) ทำให้ผู้โจมตีสามารถยึด role โดยใช้ token ที่ผู้โจมตีควบคุม |
| 16 | 🆔 IAM Identity Center (SSO) Events | timeseries | ตรวจจับการดำเนินการจัดการ AWS IAM Identity Center ผู้โจมตีใช้ SSO ในทางมิชอบเพื่อสร้าง permission set แบบแบ็คดอร์หรือกำหนดบัญชีให้กับผู้ใช้ที่ผู้โจมตีควบคุม |
| 17 | 🔗 SAML / OIDC Provider Updates | timeseries | ตรวจจับการเปลี่ยนแปลง identity provider ของ SAML/OIDC การอัปเดต SAML provider ด้วย metadata ที่ผู้โจมตีควบคุมสร้างแบ็คดอร์การยืนยันตัวตนแบบถาวร |
| 18 | 🧐 IAM Access Analyzer Calls | timeseries | ตรวจจับการใช้ IAM Access Analyzer ใด ๆ ผู้โจมตีใช้ analyzer ในตัวของ AWS เพื่อแจกแจงทรัพยากรที่เข้าถึงได้จากภายนอกโดยไม่ต้องเขียนสคริปต์ recon เอง |
| 19 | 🔄 Credential Report & Enumeration | timeseries | ตรวจจับกิจกรรมการแจกแจง IAM ที่สำรวจภูมิทัศน์ IAM ทั้งหมด พบบ่อยในช่วงต้นของการโจมตี |
| 20 | 🗝 Access Key Abuse | bar | ตรวจจับ access key ที่ใช้จาก source IP ที่แตกต่างกัน 3 แห่งขึ้นไปภายใน 7 วัน ตัวบ่งชี้ที่ชัดเจนของการรั่วไหลของคีย์ |
| 21 | 📰 AWS Organizations Account Creation | timeseries | ตรวจจับการสร้างบัญชี Organizations และการเปลี่ยนแปลง delegated administrator ผู้โจมตีสร้างบัญชีเงาเพื่อสร้างฐานที่มั่นถาวรนอกบัญชีหลัก |
| 22 | 👥 Cognito Unauthenticated Access | timeseries | ตรวจจับ Cognito Identity Pools ที่เปิดใช้งานการเข้าถึงแบบไม่ยืนยันตัวตน ทำให้ผู้ใช้ไม่ระบุตัวตนสามารถเรียก AWS API ด้วยสิทธิ์ของ IAM role แบบไม่ยืนยันตัวตน |
| 23 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | ตรวจจับการสร้าง Glue development endpoint และการแจกแจง connection iam:PassRole + glue:CreateDevEndpoint ให้สิทธิ์ role เต็มรูปแบบผ่าน SSH — หนึ่งในเทคนิคการยกระดับสิทธิ์ IAM ที่มักถูกมองข้ามที่สุด |
| 24 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | ตรวจจับการสร้าง SageMaker notebook instance และการสร้าง presigned URL iam:PassRole + sagemaker:CreateNotebookInstance ให้ environment Jupyter ที่มีสิทธิ์ AWS เต็มรูปแบบของ role ที่ส่งมา CreatePresignedNotebookInstanceUrl เพียงอย่างเดียวก็สามารถให้สิทธิ์เข้าถึง notebook ที่มีอยู่แล้วได้ |
| 25 | 🛠 Data Pipeline / CodeStar Privilege Escalation | timeseries | ตรวจจับการสร้างทรัพยากร Data Pipeline และ CodeStar ทั้งสองรับ iam:PassRole และสามารถรันโค้ดตามอำเภอใจด้วยสิทธิ์ของ role ที่ส่งมา CodeStar:CreateProjectFromTemplate เป็น API ที่ไม่มีเอกสารซึ่งสร้าง IAM role ระดับ admin |
| 26 | 🧩 Step Functions Privilege Escalation | timeseries | ตรวจจับการสร้างและการรัน state machine ของ Step Functions iam:PassRole + states:CreateStateMachine + states:StartExecution ทำให้สามารถรัน Lambda/ECS task ตามอำเภอใจภายใต้สิทธิ์ของ role ที่ส่งมา |
| 27 | 🪓 IAM Entity Deletion | timeseries | ตรวจจับการลบผู้ใช้ IAM, role, policy และอุปกรณ์ MFA ผู้โจมตีลบ IAM entity เพื่อลบร่องรอยกิจกรรมของตนหรือล็อกผู้ป้องกันออก |
| 28 | 👑 AssumeRoot Usage | timeseries | ตรวจจับการเรียก sts:AssumeRoot จากบัญชี management ไปยัง root ของ member account บัญชี management ที่ถูกบุกรุกสามารถยึดครองทุก member account ได้ด้วยวิธีนี้ |
| 29 | 🎫 Support Case Manipulation | timeseries | ตรวจจับการปิดและการแสดงความคิดเห็นใน AWS Support case ผู้โจมตีปิด case การละเมิด/การสนับสนุนเพื่อระงับการแจ้งเตือนของ AWS เกี่ยวกับการถูกบุกรุก |
| 30 | 🪪 Cognito User Pool Manipulation | timeseries | ตรวจจับการเปลี่ยนแปลง user pool และ app client ของ Cognito: การขยายอายุ token, ไคลเอนต์ใหม่ และการสร้างผู้ใช้ admin ผู้โจมตีใช้สิ่งเหล่านี้ในทางมิชอบเพื่อสร้าง token ที่มีอายุยาวหรือฝังผู้ใช้แบ็คดอร์ |
| 31 | 🔗 Role Chaining (Session → Role) | timeseries | ตรวจจับเซสชันบทบาทที่รับมาแล้วไปรับบทบาทอื่นต่อ การเรียก AssumeRole เดี่ยวๆ ดูปกติ แต่ห่วงโซ่คือเส้นทางที่ผู้โจมตีเดินจากบทบาทอินสแตนซ์ที่ถูกยึดไปสู่สิทธิ์ที่ต้องการจริง |
| 32 | 🎫 Session Credential Trace | bar | สรุปว่าแต่ละเซสชัน STS ชั่วคราว (คีย์การเข้าถึง ASIA…) ทำอะไรบ้าง: จำนวนการเรียก บริการ IP ต้นทาง และช่วงเวลา นี่คือคำถามเรื่องขอบเขตที่การสืบสวนข้อมูลรับรองรั่วไหลทุกครั้งเริ่มต้น |
| 33 | 🌐 AssumeRole Target Account (roleArn) | timeseries | ตรวจจับการข้ามขอบเขตบัญชีโดยอ่านบัญชีปลายทางจาก roleArn ที่ร้องขอ ซึ่งใช้ได้แม้นำเข้าเฉพาะบันทึกของบัญชีผู้เรียกเท่านั้น |
| 34 | 📊 AssumeRole Fan-In by Target Role | bar | จัดอันดับบทบาทตามว่าใครรับและมาจากที่ใด บทบาทที่ปกติมีเพียงบัญชีเดียวรับแล้วจู่ๆ มีผู้เรียกรายที่สองจะโดดเด่นที่นี่ ขณะที่รายการเหตุการณ์ดิบกลบมันไว้ |
| 35 | 🔍 GetCallerIdentity Reconnaissance | bar | แสดงการเรียก GetCallerIdentity ตามหลักการและ IP ต้นทาง เป็นคำสั่งแรกที่ถูกรันด้วยข้อมูลรับรองที่ขโมยมา และเป็นการเรียกเพียงครั้งเดียวที่การล่าเชิงลาดตระเวนแบบใช้เกณฑ์ปริมาณไม่มีวันไปถึง |
| 36 | 🪪 Federated Console Logins | timeseries | แสดงรายการเข้าสู่ระบบคอนโซลที่มาผ่านผู้ให้บริการข้อมูลประจำตัวภายนอก พร้อมชื่อผู้ให้บริการและแหล่งที่มา เมื่อ IdP คือส่วนที่ถูกเจาะ AWS จะเห็นเพียงการเข้าสู่ระบบที่ถูกต้อง |
| 37 | 🎟 Identity Center Permission Set Grants | timeseries | ตรวจจับการสร้างชุดสิทธิ์ การผูกนโยบาย และการกำหนดบัญชีใน IAM Identity Center — เส้นทางสู่สิทธิ์ผู้ดูแลถาวรในทุกบัญชีขององค์กร |
| 38 | 🧑 Identity Store User & Group Creation | timeseries | ตรวจจับผู้ใช้ กลุ่ม และการเป็นสมาชิกที่สร้างโดยตรงในที่เก็บข้อมูลประจำตัวของ Identity Center — การคงอยู่ที่ไม่ปรากฏใน IAM เลย จึงหลุดรอดการเฝ้าระวังที่ดูเฉพาะ IAM |
| 39 | 👑 Delegated Administrator Registration | timeseries | ตรวจจับการลงทะเบียนผู้ดูแลที่ได้รับมอบหมายสำหรับบริการขององค์กร เป็นเหตุการณ์เดียวที่คู่มือ Identity Center จัดระดับเป็น CRITICAL เพราะมันมอบการควบคุมทั้งองค์กรให้บัญชีอื่น |

### 🪣 Data & Storage

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | ตรวจจับการเรียก DeleteObject/DeleteObjects ปริมาณสูง (≥50/ชั่วโมง) ต่างจากการลักลอบนำข้อมูลออก — นี่คือรูปแบบการทำลายข้อมูล/ransomware |
| 2 | 🔥 AWS Backup Tampering | timeseries | ตรวจจับการลบ Backup Vault/Plan/RecoveryPoint การทำลายการสำรองข้อมูลเป็นขั้นตอนแรกของการโจมตีแบบ ransomware เพื่อป้องกันการกู้คืน |
| 3 | 🔓 KMS Key Operations | timeseries | ตั้งค่าสถานะการดำเนินการ KMS ที่ละเอียดอ่อน รวมถึงการลบคีย์และการเรียก Decrypt ปริมาณสูง |
| 4 | 🔓 S3 Public Access Block Disabled | — | ตรวจจับการปิดใช้งานการตั้งค่า public access block ของ S3 ความเสี่ยงในการเปิดเผยข้อมูลทันที |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | ตรวจจับการแก้ไข policy และ ACL ของ S3 bucket สิ่งเหล่านี้อาจทำให้ bucket อ่านได้แบบสาธารณะหรือให้สิทธิ์เข้าถึงแก่บัญชีที่ผู้โจมตีควบคุม |
| 6 | 🪣 S3 Data Access Anomalies | bar | ตรวจจับการเรียก GetObject จำนวนมาก (≥100/ชั่วโมง) ที่อาจบ่งชี้การลักลอบนำข้อมูลออก |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | ตรวจจับการดึงข้อมูลลับจำนวนมาก (รหัสผ่านฐานข้อมูล, API key ฯลฯ) การเรียก GetSecretValue ตั้งแต่สิบครั้งขึ้นไปในหนึ่งชั่วโมงเป็นสัญญาณการเก็บเกี่ยว credential ที่ชัดเจน |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | ตรวจจับการลบ secret ของ Secrets Manager และการเปลี่ยนแปลง resource policy ข้ามบัญชี เสริมการตรวจจับการอ่านจำนวนมากที่มีอยู่ด้วยเวกเตอร์การทำลายและการลักลอบนำออกผ่าน policy |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | ตรวจจับการอ่านรายการ SSM Parameter Store จำนวนมาก ช่องทางการลักลอบนำข้อมูลออกที่มักถูกมองข้ามเมื่อเทียบกับ Secrets Manager |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | ตรวจจับ snapshot ของ RDS/Aurora ที่แชร์ไปยังบัญชี AWS ภายนอก การลักลอบนำข้อมูลออกแบบคลาสสิกผ่านการแชร์ snapshot |
| 11 | 💣 RDS Deleted without Final Snapshot | — | ตรวจจับการลบ RDS instance/cluster ที่มี skipFinalSnapshot=true อาจเป็นการทำลายข้อมูล |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | ตรวจจับ RDS instance ที่ถูกสร้างหรือแก้ไขด้วย PubliclyAccessible=true เปิดเผยฐานข้อมูลสู่อินเทอร์เน็ตโดยตรง ข้ามการควบคุมความปลอดภัยของ VPC |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | ตรวจจับ DynamoDB ExportTableToPointInTime (การ export ทั้งตารางไปยัง S3 อย่างเงียบ ๆ) และการลบตาราง เวกเตอร์การลักลอบนำออกและการทำลายที่มีความเสี่ยงสูง |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | ตรวจจับการเรียก EBS Direct API (ListSnapshotBlocks / GetSnapshotBlock) ebs__download_snapshots ของ Pacu ใช้ API นี้เพื่อสตรีมข้อมูล snapshot ดิบโดยไม่สร้าง EC2 instance หลบเลี่ยงการตรวจจับการแชร์ snapshot แบบดั้งเดิม |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | ตรวจจับการสร้าง/อัปเดต delivery stream ของ Kinesis Firehose ที่ชี้ไปยัง S3 ภายนอก การลักลอบนำข้อมูลออกผ่าน pipeline ข้อมูลแบบเรียลไทม์ที่ DLP เครือข่ายมองไม่เห็น |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | ตรวจจับ PutBucketReplication และ DeleteBucketReplication การจำลองข้ามบัญชีจะคัดลอก object ใหม่ทั้งหมดไปยัง bucket ที่ผู้โจมตีควบคุมอย่างเงียบ ๆ |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | ตรวจจับการระงับ versioning ของ S3 และการปิดใช้งาน server access logging การปิด versioning เปิดทางให้ทำลายข้อมูล การปิด logging ลบร่องรอยหลักฐานการเข้าถึง |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | ตรวจจับการเปลี่ยนแปลง receipt rule และการตั้งค่า identity ของ SES forwarding rule สามารถส่งต่อเมลขาเข้าทั้งหมดไปยังที่อยู่ของผู้โจมตีโดยอัตโนมัติ identity ที่ยืนยันแล้วเปิดทางให้แคมเปญ phishing |
| 19 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | ตรวจจับการเปลี่ยนแปลง policy ของ queue/topic ของ SQS/SNS ที่ให้สิทธิ์เข้าถึงบัญชีภายนอก สร้างช่องทางการลักลอบนำออกอย่างเงียบ ๆ โดยไม่กระตุ้นสัญญาณเตือนการส่งปริมาณสูง |
| 20 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | ตรวจจับ EBS snapshot หรือ AMI ที่แชร์สู่สาธารณะ (group=all) ทำให้ทุกคนสามารถคัดลอก disk image และดึงข้อมูลของคุณได้ |
| 21 | 📧 Data Exfiltration Channels | bar | ตรวจจับการเรียก SNS/SQS/SES/S3 PutObject ปริมาณสูง (≥50/ชั่วโมง) ที่อาจบ่งชี้การลักลอบนำข้อมูลออก |
| 22 | 🔐 S3 SSE-C Encryption (Ransomware) | timeseries | ตรวจจับ object ของ S3 ที่ถูกเข้ารหัสใหม่ด้วยคีย์ SSE-C ที่ผู้โจมตีจัดหาให้ รวมถึงการเปลี่ยนแปลงการเข้ารหัสเริ่มต้นของ bucket หากไม่มีคีย์ของลูกค้า เหยื่อจะไม่สามารถถอดรหัสได้ — รูปแบบ ransomware ที่เกิดขึ้นบนคลาวด์โดยเฉพาะ |
| 23 | ⏳ S3 Lifecycle-Triggered Deletion | timeseries | ตรวจจับ lifecycle rule ของ S3 ที่ทำให้ object หมดอายุ รวมถึงการลบการตั้งค่า lifecycle ผู้โจมตีตั้งค่าการหมดอายุระยะสั้นเพื่อกำจัดข้อมูลอย่างเงียบ ๆ เมื่อเวลาผ่านไปโดยไม่ต้องเรียก DeleteObject |
| 24 | 🗃 RDS Query & Instance Manipulation | timeseries | ตรวจจับ query ของ RDS Data API, การรีเซ็ตรหัสผ่าน master และการกู้คืน snapshot ผู้โจมตีอ่านข้อมูลโดยตรง รีเซ็ต credential เพื่อเข้าถึง หรือกู้คืน snapshot ไปยัง instance ที่ตนควบคุม |
| 25 | 🔎 S3 Bucket Enumeration | bar | ตรวจจับผู้เรียกที่กวาด metadata ของ bucket และ object (การอ่าน List/GetBucket* ≥10 ครั้งในหนึ่งชั่วโมง) ขั้นตอนแรกที่พบบ่อยในการค้นหาข้อมูลที่มีค่าก่อนการลักลอบนำออก |
| 26 | 🔑 Storage Re-Encryption for Impact | timeseries | ตรวจจับ snapshot และ volume ของ EBS/RDS ที่ถูกเข้ารหัสใหม่ด้วยคีย์ KMS ที่ระบุอย่างชัดเจน รวมถึงการปิดใช้งานการเข้ารหัสเริ่มต้นของ EBS การเข้ารหัสใหม่ด้วยคีย์ที่ผู้โจมตีถือครองเป็นการยึดข้อมูลไว้เรียกค่าไถ่ |
| 27 | 📝 Ransom Note Placement | timeseries | ตรวจจับการเรียก PutObject ที่คีย์อ็อบเจกต์ดูเหมือนข้อความเรียกค่าไถ่ ต่างจากการล่าแรนซัมแวร์อื่น รายการนี้ยืนยันผลกระทบแทนที่จะบอกใบ้ — การมีข้อความหมายความว่ามีการเรียกค่าไถ่แล้ว |
| 28 | 📐 Data Access Scope (Breach Notification) | bar | วัดปริมาณสิ่งที่แต่ละหลักการอ่านต่อวัน: บักเก็ตที่แตะและจำนวนอ็อบเจกต์ไม่ซ้ำโดยประมาณ ให้ตัวเลข «จำนวนระเบียนโดยประมาณ» ที่ GDPR มาตรา 33 ต้องการ |
| 29 | 📤 Cross-Account Object Copy | timeseries | ตรวจจับอ็อบเจกต์ที่ถูกคัดลอกระหว่างบักเก็ต รวมถึงการเรียก PutObject ที่มีส่วนหัว x-amz-copy-source การพักข้อมูลไว้ในบัญชีที่คุณไม่ได้ควบคุมทิ้งร่องรอยไว้เพียงแบบนี้เท่านั้น |
| 30 | 🔗 Presigned URL Generation | bar | นับการสร้าง URL แบบลงนามล่วงหน้าต่อหลักการ URL แบบลงนามล่วงหน้าส่งข้อมูลให้ใครก็ตามที่ถือลิงก์ โดยไม่ต้องยืนยันตัวตนเพิ่มและไม่มีบันทึก CloudTrail เพิ่มอีก |

### ⚡ Compute & Serverless

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | ตรวจจับ EC2 StopInstances/TerminateInstances ปริมาณสูง (≥5 ครั้งในหนึ่งชั่วโมง) บ่งชี้การขัดขวางแบบ ransomware หรือการโจมตีเชิงทำลาย |
| 2 | 🖥️ SSM Session / Run Command | timeseries | ตรวจจับ SSM StartSession, SendCommand และการรัน automation เส้นทางหลักของการเคลื่อนที่ด้านข้างผ่าน managed instance |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | ตรวจจับการเข้าถึง EC2 Instance Connect และ Serial Console ซึ่งทำให้ผู้โจมตีเข้าถึง instance จากเบราว์เซอร์หรือ CLI โดยไม่ต้องใช้ SSH key หรือ bastion host เส้นทางการเคลื่อนที่ด้านข้างหลักสำหรับผู้โจมตีที่ไม่มี SSH key |
| 4 | 📝 EC2 User Data Modification | timeseries | ตรวจจับการเรียก ModifyInstanceAttribute ที่เปลี่ยนแปลงฟิลด์ userData สคริปต์ user data ทำงานเป็น root เมื่อบูตครั้งถัดไป เป็นแบ็คดอร์การรันโค้ดแบบถาวร |
| 5 | ⚡ Lambda Function Tampering | timeseries | ตรวจจับการสร้าง Lambda การอัปเดตโค้ด และการเปลี่ยนแปลงสิทธิ์ ผู้โจมตีใช้ Lambda เพื่อการคงอยู่ |
| 6 | 📦 Lambda Layer Addition | timeseries | ตรวจจับการเผยแพร่ Lambda layer และการเปลี่ยนแปลงสิทธิ์ การเผยแพร่ layer ที่ใช้ร่วมกันซึ่งเป็นอันตรายและเพิ่มเข้าไปในฟังก์ชัน production จะแทรกโค้ดของผู้โจมตีเข้าไปในสายโซ่ dependency |
| 7 | 📦 ECS Task Definition | timeseries | ตรวจจับการลงทะเบียน ECS task definition และการอัปเดต service ecs__backdoor_task_def ของ Pacu ลงทะเบียน task definition เวอร์ชันใหม่ที่ชี้ไปยัง container image ที่เป็นอันตราย จากนั้นอัปเดต service เพื่อ deploy — ทั้งหมดโดยไม่แตะ ECR |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | ตรวจจับการเชื่อมโยงและการแทนที่ IAM instance profile การแนบ profile ที่มีสิทธิ์สูงทำให้ instance ได้รับสิทธิ์ที่สูงขึ้นสำหรับการเคลื่อนที่ด้านข้าง |
| 9 | 🖥 EC2 Instance Launches | timeseries | แสดงรายการเหตุการณ์ RunInstances ทั้งหมด การเปิดใช้งานที่ไม่คาดคิดในภูมิภาคที่ผิดปกติอาจบ่งชี้ cryptomining |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | ตรวจจับคำขอ Spot Fleet ขนาดใหญ่ การซื้อ Reserved Instance และการสร้าง Auto Scaling group ที่มี capacity สูง ตัวบ่งชี้ผลกระทบทางการเงินจาก cryptomining |
| 11 | ☸️ EKS Cluster API Calls | timeseries | ตรวจจับการแก้ไข control-plane ของ EKS cluster การเปิดเผย API server สาธารณะหรือ Fargate profile ปลอมทำให้ยึดแพลตฟอร์ม container ได้ |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | ตรวจจับการสร้าง/ลบ repository ของ ECR การเปลี่ยนแปลง policy และการ push image การแทรก image ที่เป็นอันตรายเข้าไปใน production repository เป็นเทคนิคการคงอยู่แบบ supply-chain |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | ตรวจจับการแก้ไข rule ของ EventBridge และ EventBridge Scheduler ผู้โจมตีใช้ rule ที่มีกำหนดการเพื่อสร้างการคงอยู่โดยไม่ต้องมีโปรเซสที่ทำงานต่อเนื่อง |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | ตรวจจับการเข้าถึง Lightsail instance การดำเนินการ key pair และการเปิดพอร์ต Pacu มีโมดูล Lightsail เฉพาะสามโมดูล (enum, download_ssh_keys, generate_temp_access) ทรัพยากร Lightsail ทำงานนอกขอบเขตความปลอดภัยมาตรฐานของ EC2 |
| 15 | 🛰 IMDS Options Weakening | timeseries | ตรวจจับการเรียก ModifyInstanceMetadataOptions ที่ทำให้ IMDSv2 เป็นทางเลือกหรือเปิดใช้งาน metadata endpoint อีกครั้ง การลดความเข้มงวดของ IMDS เปิดเส้นทาง SSRF อีกครั้งเพื่อขโมย credential ของ instance role |
| 16 | 💥 AMI & Snapshot Deletion | bar | ตรวจจับการยกเลิกการลงทะเบียน AMI จำนวนมากและการลบ snapshot ของ EBS (≥5 ครั้งในหนึ่งชั่วโมง) การทำลาย golden image และการสำรองข้อมูลขจัดทางเลือกในการกู้คืนระหว่างการโจมตีเชิงทำลาย |
| 17 | 🖥 WorkSpaces Hijacking | timeseries | ตรวจจับการจัดสรร Amazon WorkSpaces และการสร้าง pool ผู้โจมตีเปิดใช้งาน desktop โดยให้เหยื่อเป็นผู้รับภาระค่าใช้จ่าย ช่องทางการยึดครองการประมวลผลที่ถูกตรวจสอบน้อยอยู่นอกขอบเขตของ EC2 |

### 🤖 AI & LLM Abuse

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 🤖 Bedrock Model Invocation Spike | timeseries | ตรวจจับ principal ที่เรียกใช้โมเดล Bedrock 50 ครั้งขึ้นไปในหนึ่งชั่วโมง การอนุมานปริมาณสูงด้วย credential ที่ถูกขโมย (LLMjacking) อาจทำให้เหยื่อสูญเสียเงินหลายหมื่นดอลลาร์ต่อวัน |
| 2 | 🔓 Bedrock Model Access Enablement | timeseries | ตรวจจับการเปิดใช้งานการเข้าถึง foundation model หรือการซื้อ provisioned capacity ในองค์กรที่ไม่เคยใช้ Bedrock มาก่อน นี่คือตัวบ่งชี้ LLMjacking ที่แทบไม่มีสัญญาณรบกวน — เป็นการเขียนครั้งแรกตามแบบฉบับของผู้โจมตี |
| 3 | 🙈 Bedrock Invocation Logging Tampering | timeseries | ตรวจจับการลบหรือแก้ไขการบันทึก log การเรียกใช้โมเดลของ Bedrock รวมถึงผู้โจมตีที่ตรวจสอบว่า logging เปิดใช้งานอยู่หรือไม่ก่อนใช้บัญชีในทางมิชอบ (IOC ของ LLMjacking ที่มีการบันทึกไว้) |
| 4 | 🧭 Bedrock Reconnaissance Sweep | bar | ระบุผู้เรียกที่แจกแจงโมเดล Bedrock ใน 2 ภูมิภาคขึ้นไป หรือมีการเรียกแจกแจง 10 ครั้งขึ้นไปในหนึ่งชั่วโมง ผู้ถือคีย์ที่ถูกขโมยกวาดภูมิภาคเพื่อค้นหาว่าโมเดลใช้งานได้ที่ไหน |
| 5 | ⛔ Failed Bedrock Invocations | bar | ค้นหาการพุ่งสูงของการเรียกใช้ Bedrock ที่ล้มเหลว (AccessDenied / ValidationException) การทดสอบคีย์ที่ถูกขโมยสร้างพายุความล้มเหลวข้ามโมเดลและภูมิภาคก่อนที่จะพบชุดค่าผสมที่ใช้งานได้ |
| 6 | 🌍 Bedrock Callers & Origins | — | จัดทำบัญชีรายชื่อ principal ทุกรายที่เคยแตะต้อง Bedrock พร้อม source IP, แหล่งที่มาตาม GeoIP, user agent และความหลากหลายของโมเดล ค้นหาผู้เรียกหรือแหล่งที่มาที่ไม่ควรใช้ Bedrock เลย |
| 7 | 🔑 AgentCore Token Vault Abuse | bar | รวมยอดการออกโทเค็นจากที่เก็บโทเค็น AgentCore ตามหลักการและแหล่งที่มา การเรียกเหล่านี้แจกโทเค็น OAuth และคีย์ API ของบุคคลที่สาม การใช้ในทางที่ผิดจึงลามไปถึงบริการนอก AWS |
| 8 | 🚪 AgentCore Gateway Authorization Bypass | timeseries | ตรวจจับการเปลี่ยนแปลงเกตเวย์และนโยบายของ AgentCore รวมถึงเอนจินนโยบาย Cedar ที่ถูกลดเป็น LOG_ONLY การอนุญาตที่เพียงบันทึกยังคงคืนค่าสำเร็จ ปลายทางจึงไม่เห็นสิ่งผิดปกติใด |
| 9 | 🧠 AgentCore Memory Integrity | timeseries | ตรวจจับการเปลี่ยนแปลง Memory และ Registry ของ AgentCore รวมถึงสตรีมหน่วยความจำที่ถูกชี้ไปยัง ARN ของ Kinesis ในบัญชีอื่น หน่วยความจำระยะยาวที่ถูกวางยาจะคงอยู่ในทุกเซสชันถัดไปของเอเจนต์ |
| 10 | 📦 AgentCore Sandbox Network Mode Drift | timeseries | แสดงเหตุการณ์วงจรชีวิตของโค้ดอินเทอร์พรีเตอร์และเบราว์เซอร์ของ AgentCore พร้อมโหมดเครือข่าย โหมดแก้ไขไม่ได้ การลบแล้วสร้างใหม่จึงเป็นวิธีเดียวที่จะขยายการเข้าถึงเครือข่ายของแซนด์บ็อกซ์ |
| 11 | 🙈 AgentCore Observability Tampering | timeseries | ตรวจจับการเปลี่ยนแปลงตัวประเมินของ AgentCore และการเปลี่ยนการสุ่มตัวอย่างหรือปลายทางการติดตามของ X-Ray ตัวประเมินที่ผู้โจมตีสร้างจะอ่านทุกคำตอบที่มันให้คะแนน แล้วส่งออกผลลัพธ์ของโมเดลผ่านช่องทางที่ถูกต้อง |

### 🌐 Network & Infrastructure

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 🌍 Security Group Opened to Internet | timeseries | ค้นหา rule ของ security group ที่อนุญาต traffic จาก 0.0.0.0/0 ความเสี่ยงการเปิดเผยสู่สาธารณะโดยตรง |
| 2 | 🔥 Security Group Modifications | timeseries | ตรวจจับการเปลี่ยนแปลง rule ของ security group โดยเฉพาะ rule ที่อนุญาต 0.0.0.0/0 บนพอร์ตใด ๆ |
| 3 | 🌊 VPC Flow Log Changes | timeseries | ตรวจจับการลบ VPC Flow Logs การลบ flow log ขจัดหลักฐานระดับเครือข่าย — ตัวบ่งชี้การหลบเลี่ยงการป้องกันที่สำคัญ |
| 4 | 🌐 CloudFront Distribution Tampering | timeseries | ตรวจจับการสร้าง CloudFront distribution และการเปลี่ยน origin การแก้ไข origin เปลี่ยนเส้นทาง traffic ของ CDN ไปยังเซิร์ฟเวอร์ที่ผู้โจมตีควบคุมเพื่อดักจับแบบ MitM หรือเก็บข้อมูล |
| 5 | 🛡 Network Firewall / Shield Tampering | timeseries | ตรวจจับการลบการป้องกันของ Network Firewall และ Shield การลบการป้องกันระดับเครือข่ายเปิดเผย VPC ต่อ traffic การโจมตีโดยตรง |
| 6 | 🧱 Network ACL Changes | timeseries | ตรวจจับการสร้าง ลบ และแทนที่ entry ของ Network ACL NACL ลบล้าง security group และสามารถเปิดทั้ง subnet ให้กับผู้โจมตี |
| 7 | 🛣️ Route Table Changes | timeseries | ตรวจจับการแก้ไข route table การเพิ่มหรือแทนที่ route สามารถเปลี่ยนเส้นทาง traffic ไปยังโฮสต์ที่ผู้โจมตีควบคุม (MitM, การขโมย traffic) |
| 8 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | ตรวจจับการเชื่อมต่อ VPN ใหม่ Direct Connect และการแนบ Transit Gateway ผู้โจมตีสร้างอุโมงค์เครือข่ายแอบแฝงสำหรับ C2 แบบถาวรหรือช่องทางลักลอบนำข้อมูลออก |
| 9 | 📡 Elastic IP Allocation / Association | timeseries | ตรวจจับการจัดสรรและการเชื่อมโยง Elastic IP ผู้โจมตีกำหนด public IP คงที่ให้กับ instance ที่ถูกบุกรุกเพื่อสร้างโครงสร้างพื้นฐาน C2 ที่เสถียร |
| 10 | 🗝️ EC2 Key Pair Creation | timeseries | ตรวจจับเหตุการณ์ CreateKeyPair และ ImportKeyPair ผู้โจมตีสร้างหรือนำเข้า SSH key เป็นกลไกการคงอยู่เพื่อรักษาการเข้าถึง instance |
| 11 | 📡 Network Infrastructure Changes | timeseries | ตรวจจับการเปลี่ยนแปลงระดับ VPC และเครือข่ายที่อาจสร้างโครงสร้างพื้นฐานที่ผู้โจมตีควบคุม |
| 12 | 🏷 ACM Certificate Operations | timeseries | ตรวจจับคำขอและการลบใบรับรอง ACM ผู้โจมตีใช้บัญชีที่ถูกบุกรุกออกใบรับรอง TLS สำหรับโดเมนที่ผู้โจมตีควบคุมเพื่อสร้างโครงสร้างพื้นฐาน phishing |
| 13 | 🔑 API Gateway Key Creation & Management | timeseries | ตรวจจับการสร้างคีย์ API Gateway และการจัดการ REST API api_gateway__create_api_keys ของ Pacu สร้าง credential API ถาวรที่อยู่รอดจากการหมุนคีย์ IAM ผู้โจมตียังแก้ไข API authorizer เพื่อลดความเข้มงวดของการควบคุมการเข้าถึง |
| 14 | 🚧 VPC Endpoint Access Denied | timeseries | ตรวจจับ error access denied ผ่าน VPC endpoint อาจบ่งชี้ endpoint policy ที่ตั้งค่าผิด |
| 15 | 🌐 Route 53 & Domain Changes | timeseries | ตรวจจับการแก้ไข DNS record, การเปลี่ยนแปลง hosted zone และการลงทะเบียน/โอนย้ายโดเมน ผู้โจมตีเปลี่ยนเส้นทาง traffic ยึดครอง subdomain ที่ถูกทิ้งร้าง หรือลงทะเบียนโดเมนที่คล้ายกันเพื่อ phishing |
| 16 | 🛡 DDoS Protection Weakening | timeseries | ตรวจจับการป้องกันที่ขอบซึ่งถูกผ่อนคลายแทนที่จะถูกลบ: การกระทำเริ่มต้นของ WebACL เปลี่ยนเป็นอนุญาต กลุ่มกฎถูกผ่อนปรน การป้องกันของ Shield ถูกลบ ต้นทาง CloudFront ถูกชี้ใหม่ |

### 🕵 Threat Patterns

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | ระบุผู้เรียกที่รัน API แบบอ่านอย่างเดียวที่แตกต่างกัน 10 รายการขึ้นไปในหนึ่งชั่วโมง ระยะแรกของการโจมตีที่พบบ่อย |
| 2 | 🤖 Unusual User Agents | bar | แสดงรายการ user agent ที่พบยาก (น้อยกว่า 5 เหตุการณ์) เครื่องมือแบบกำหนดเองอย่าง Pacu หรือ curl อาจบ่งชี้เครื่องมือของผู้โจมตี |
| 3 | 🌍 Multi-Region Activity | bar | ตรวจจับอัตลักษณ์ที่เขียนใน 3 ภูมิภาคขึ้นไปในหนึ่งวัน การกระจายทางภูมิศาสตร์อาจบ่งชี้การถูกบุกรุก |
| 4 | 🕵 First-Time API Calls (24h) | — | ค้นหาการเรียก API ที่พบใน 24 ชั่วโมงที่ผ่านมาแต่ไม่เคยพบมาก่อน การดำเนินการใหม่อาจบ่งชี้เครื่องมือของผู้โจมตี |
| 5 | 🗺 First-Seen Region Activity | bar | ค้นหาภูมิภาค AWS ที่กิจกรรมแรกสุดตกอยู่ใน 24 ชั่วโมงสุดท้ายของชุดข้อมูล การดำเนินการในภูมิภาคที่ไม่เคยใช้มาก่อนเป็นวิธีคลาสสิกในการซ่อน cryptomining หรือการเตรียมการจากการตรวจสอบที่จำกัดขอบเขตตามภูมิภาค |
| 6 | 🌙 Off-Hours Activity | bar | จัดกลุ่มกิจกรรมตามหลักการและชั่วโมงของวันภายในช่วงนอกเวลาทำการที่กำหนดค่าได้ เป็นตัวบ่งชี้แรกที่คู่มือภัยคุกคามจากภายในระบุไว้ และไม่มีการล่ารายการอื่นครอบคลุม |
| 7 | 🪞 Self-Service Privilege Escalation | timeseries | ตรวจจับหลักการที่แก้ไขสิทธิ์ของตนเอง — ARN ผู้เรียกกับชื่อผู้ใช้หรือบทบาทเป้าหมายตรงกัน การล่าการยกระดับสิทธิ์ที่มีอยู่เห็นการให้สิทธิ์ แต่พลาดข้อเท็จจริงว่ามันถูกใช้กับตนเอง |
| 8 | 📈 Principal Daily Volume Deviation | bar | เปรียบเทียบปริมาณการเรียกรายวันของแต่ละหลักการกับค่าเฉลี่ยของตัวเอง โดยแยกการอ่านออกจากการเขียน จับการลักลอบนำข้อมูลออกที่ใช้เพียง API ที่ได้รับอนุญาต ซึ่งความผิดปกติอยู่ที่ปริมาณไม่ใช่การกระทำ |
| 9 | 🗺 Resource Creation Outside Normal Regions | bar | ทำเครื่องหมายการสร้างทรัพยากรในภูมิภาคที่บัญชีแทบไม่ได้ใช้ โดยเส้นฐานได้มาจากข้อมูลแทนการกำหนดตายตัว ทั้งการขุดคริปโตและโครงการส่วนตัวต่างปรากฏที่นี่ |
| 10 | 📞 High-Volume API Calls per Principal | bar | แสดงคู่หลักการกับ API ที่มีการเรียกสำเร็จเกิน 50 ครั้ง พร้อมการเรียกครั้งแรกและครั้งสุดท้าย การแจกแจง การดึงข้อมูลจำนวนมาก และการลบจำนวนมาก ล้วนมีรูปแบบเดียวกันนี้ |

### 📊 Activity & Baseline

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | ระบุการเรียก API ที่เปลี่ยนแปลงข้อมูลซึ่งทำผ่านคอนโซล AWS มีประโยชน์เมื่อคาดว่าจะมีการเข้าถึงผ่าน CLI เท่านั้น |
| 2 | 🔍 Events with Errors (24h) | timeseries | แสดงรายการเหตุการณ์ error ทั้งหมดใน 24 ชั่วโมงที่ผ่านมา ภาพรวมอย่างรวดเร็วของสิ่งที่กำลังล้มเหลวในขณะนี้ |
| 3 | ❌ Error Spike Detection | — | ค้นหาช่วงเวลา 1 ชั่วโมงที่จำนวน error เกินค่าเฉลี่ยรายวัน 3 เท่า สัญญาณของการสแกนหรือ outage |

### 🌍 GeoIP Analysis

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 🗺 Console Logins by Country | timeseries | แมปเหตุการณ์ล็อกอินคอนโซลกับแหล่งที่มาทางภูมิศาสตร์ การล็อกอินจากประเทศที่ไม่คาดคิดมีความเสี่ยงสูง |
| 2 | 🚨 Unusual Country Access | bar | ตรวจจับการเรียก API จากประเทศที่ไม่คาดคิดโดยแสดงชุดผสมประเทศ/อัตลักษณ์ที่พบยาก |
| 3 | 🚫 Access Denied by Country | bar | จัดกลุ่ม error access denied ตามประเทศต้นทาง การปฏิเสธที่กระจุกตัวจากประเทศเดียวอาจส่งสัญญาณการโจมตี |
| 4 | 🔍 Write Events by Country | bar | แสดงการเรียก API ที่เปลี่ยนแปลงข้อมูล (write) จัดกลุ่มตามประเทศ การเขียนจากประเทศที่ไม่คาดคิดมีความสำคัญสูง |
| 5 | 🌍 Top Source Countries | bar | จัดอันดับประเทศต้นทางตามปริมาณการเรียก API ระบุการกระจายทางภูมิศาสตร์ของกิจกรรมทั้งหมด |
| 6 | 🏢 Top ASN / Organizations | bar | แสดงรายการ autonomous system (ISP/ผู้ให้บริการคลาวด์) ตามปริมาณการเรียก API สังเกตผู้ให้บริการ VPN/hosting |
| 7 | 📍 Top Source Cities | bar | จัดอันดับเมืองต้นทางตามปริมาณเหตุการณ์ ระบุแหล่งที่มาทางภูมิศาสตร์ที่มีกิจกรรมมากที่สุด |
| 8 | 📋 API Calls by Country (Event Name) | bar | แสดงว่าการดำเนินการ API ใดถูกเรียกจากแต่ละประเทศ เหตุการณ์การเขียนจากประเทศที่ไม่คาดคิดบ่งชี้การถูกบุกรุก credential |
| 9 | 👤 Identities by Country (user_identity_arn) | bar | แสดงว่า IAM identity ใดใช้งานอยู่จากแต่ละประเทศ identity ที่ปรากฏจากประเทศใหม่เป็นตัวบ่งชี้การถูกบุกรุกที่มีความน่าเชื่อถือสูง |
| 10 | 🌐 Private / Internal IP Summary | bar | สรุปเหตุการณ์จาก IP แบบ private, loopback และภายใน AWS เส้นฐานสำหรับ traffic ภายในที่คาดหวัง |

### ☁ IaC & Platform

| # | ป้ายชื่อ | Chart | คำอธิบาย |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | ตรวจจับการสร้างและแก้ไข pipeline ของ CI/CD การแทรกขั้นตอน build ที่เป็นอันตรายหรือแก้ไขแหล่งที่มาของ pipeline จะทำให้การ deploy ครั้งต่อ ๆ ไปทั้งหมดเป็นพิษ |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | ตรวจจับการดำเนินการ stack ของ CloudFormation ผู้โจมตีอาจใช้ IaC เพื่อ deploy โครงสร้างพื้นฐานที่เป็นอันตรายอย่างรวดเร็ว |

</details>

---

## 📊 Dashboard Charts — 115 charts

| แท็บ | จำนวนแผนภูมิ | สิ่งที่แสดง |
|-----|:------:|---------------|
| 🚦 Overview | 10 | การ์ด KPI สำหรับ triage 9 รายการ (เหตุการณ์, principal, IP, root, การล็อกอินไม่มี MFA, access denied, การหลบเลี่ยงการป้องกัน, ประเทศ, ภูมิภาค) + แนวโน้มปริมาณเหตุการณ์ทั่วโลก |
| 🎯 Threat Detection | 14 | จุดรวมการหลบเลี่ยงการป้องกัน · ช่องว่างของ logging · การดัดแปลง VPC flow log/Config/EventBridge/WAF · การเปลี่ยนแปลง SCP/สมาชิกภาพองค์กร · แนวโน้ม error และ throttling · อัตราส่วน write/read · การ์ด KPI ตัวกระตุ้นการยกระดับ P1/P2 |
| 🔑 Identity & Access | 16 | การล็อกอินคอนโซล · แนวโน้ม MFA · heatmap การล็อกอิน · ลำดับเหตุการณ์ auth ล้มเหลว→สำเร็จ · การใช้ root · กิจกรรม/การลบของ IAM entity · ไทม์ไลน์การยกระดับสิทธิ์ · principal ใหม่ · SSO · AssumeRole ข้ามบัญชี · การใช้ AssumeRoot |
| 🚨 High-Risk API Monitor | 5 | log เหตุการณ์การดัดแปลงบริการความปลอดภัยและการดึง credential · การเรียกความเสี่ยงสูงอันดับต้น · ผู้กระทำอันดับต้น · ปริมาณการเรียกความเสี่ยงสูงตามเวลา |
| 📊 API Activity | 6 | API อันดับต้น · การกระทำที่ถูก access-denied · การกระจายตามภูมิภาค · องค์ประกอบของ error-code · source IP · user agent |
| 🪣 S3 & RDS | 18 | การดาวน์โหลด/ลบ S3 จำนวนมาก · การปิดใช้งาน versioning/logging · การจำลองข้ามบัญชี · policy/ACL ของ bucket · การแจกแจง · การตั้งค่าการป้องกัน · การลบ Backup vault · การลบคีย์ KMS · การแชร์ snapshot RDS / การลบ RDS โดยไม่มี snapshot · การเข้ารหัส SSE-C แบบ ransomware · การลบที่กระตุ้นโดย lifecycle · การจัดการ query/instance ของ RDS · การเข้ารหัสที่จัดเก็บข้อมูลใหม่เพื่อสร้างผลกระทบ · ขอบเขตการเข้าถึงสำหรับการแจ้งเหตุละเมิด · การคัดลอกอ็อบเจกต์ข้ามบัญชี · การวางข้อความเรียกค่าไถ่ |
| 🖥️ Computing | 17 | การเปิดใช้งาน EC2/หยุดจำนวนมาก/key pair/instance profile/user-data/การแชร์ snapshot/spot fleet · ECS/Lambda/SSM/EBS Direct API/EKS-ECR/CloudFormation · การลดความเข้มงวดของ IMDS · การลบ AMI/snapshot · การยึดครอง WorkSpaces |
| 🤖 AI / LLM | 6 | แนวโน้มการเรียกใช้ Bedrock · การเปลี่ยนแปลงการเข้าถึงโมเดลและ logging · การเรียกใช้ที่ล้มเหลว · ผู้เรียกจัดกลุ่มตามแหล่งที่มา (triage สำหรับ LLMjacking) · การออกโทเค็น AgentCore · การเปลี่ยนแปลงเกตเวย์และนโยบาย |
| 🌐 Network | 5 | การเปลี่ยนแปลง security group · การเปลี่ยนแปลง NACL/route table · โครงสร้างพื้นฐาน VPC · VPC peering/Transit Gateway · การเปลี่ยนแปลง DNS ของ Route53 |
| 🕒 Temporal Analysis | 8 | การพุ่งสูงของความเร็วเหตุการณ์ · บัญชีที่ไม่ใช้งานถูกเปิดใช้ใหม่ · การพบครั้งแรก/ครั้งสุดท้ายตาม identity/IP/API/แหล่งบริการ · ฮีตแมปการเขียนนอกเวลาทำการ · ปริมาณอ่าน/เขียนรายวันต่อหลักการ |
| 🌍 GeoIP Intelligence | 6 | การเดินทางที่เป็นไปไม่ได้ (principal หลายประเทศ) · ประเทศ/เมือง/ASN อันดับต้น · แผนที่โลก · event_name × country |

<details markdown="1">
<summary>📋 รายการทั้งหมด — ทุก chart ทั้ง 115 รายการ (คลิกเพื่อขยาย)</summary>

## Dashboard Charts (Apache Superset — `dashboard/`)

### 🚦 Overview

| # | ชื่อแผนภูมิ | คำอธิบาย |
|---|------------|-------------|
| 1 | Total Events | จำนวนเหตุการณ์ CloudTrail ทั้งหมดในช่วงที่เลือก (KPI-81) ตัวส่วนสำหรับการ triage — เป็นจุดยึดสำหรับอัตราส่วนต่อ principal หรือต่อ IP ทุกรายการ |
| 2 | Distinct Principals | จำนวน IAM principal ARN ที่ไม่ซ้ำกันซึ่งใช้งานในช่วงที่เลือก (KPI-82) ใช้เพื่อกำหนดขอบเขตว่ามีอัตลักษณ์กี่รายที่เกี่ยวข้องกับกิจกรรมที่กำลังตรวจสอบ |
| 3 | Distinct Source IPs | จำนวน source IP ของผู้เรียกที่ไม่ซ้ำกันในช่วงที่เลือก (KPI-83) การเพิ่มขึ้นเทียบกับเส้นฐานบ่งชี้การหมุนเวียน proxy/VPN หรือการเข้าถึงแบบกระจาย |
| 4 | Root Account Events | จำนวนเหตุการณ์ที่ดำเนินการโดยอัตลักษณ์ root ของบัญชี (KPI-84) กิจกรรมของ root ควรใกล้เคียงศูนย์ — ค่าใด ๆ ที่ไม่ใช่ศูนย์สมควรได้รับการตรวจสอบ |
| 5 | MFA-less Console Logins | จำนวนการล็อกอินคอนโซลที่ไม่มี MFA ในช่วงที่เลือก (KPI-85) ตัวบ่งชี้โดยตรงของการถูกบุกรุก credential — เจาะลึกเข้าไปที่ MFA-less Login Trend |
| 6 | Access Denied Events | จำนวนเหตุการณ์ที่การอนุญาตล้มเหลวในช่วงที่เลือก (KPI-86) การพุ่งสูงบ่งชี้การสอดแนมหรือการทดสอบสิทธิ์ — ไล่ตามด้วย principal/IP |
| 7 | Defense-Evasion Hits | จำนวนเหตุการณ์การดัดแปลงระบบตรวจสอบ/ติดตามในช่วงที่เลือก (KPI-87) สัญญาณ triage ที่มีความสำคัญสูงสุด — ค่าใด ๆ ที่ไม่ใช่ศูนย์หมายความว่าการตรวจจับอาจถูกปิดใช้งาน เจาะลึกเข้าไปที่ Security Monitoring & Control Changes MITRE ATT&CK: TA0005 Defense Evasion |
| 8 | Distinct Countries | จำนวนประเทศต้นทางที่ไม่ซ้ำกันในช่วงที่เลือก (KPI-88) ต้องใช้การเติมข้อมูล GeoIP (docker/data/geoip/) การกระจายที่กว้างบ่งชี้การเข้าถึงจากแหล่งที่มาทางภูมิศาสตร์ที่ไม่คาดคิด |
| 9 | Active Regions | จำนวนภูมิภาค AWS ที่แตกต่างกันซึ่งมีกิจกรรมในช่วงที่เลือก (KPI-89) กิจกรรมในภูมิภาคที่ไม่ได้ใช้งานอาจบ่งชี้การใช้ทรัพยากรในทางมิชอบหรือการเตรียมการของผู้โจมตี |
| 10 | CloudTrail Events Over Time | ปริมาณเหตุการณ์ Read เทียบกับ Write รายชั่วโมงตามเวลา (DSH-01) แท่งกราฟแบบซ้อนแสดงสัดส่วน Read/Write การเพิ่มขึ้นอย่างฉับพลันของ write_events ส่งสัญญาณว่าผู้โจมตีกำลังเปลี่ยนจากการสอดแนมไปสู่การโจมตีเชิงรุก มีประโยชน์สำหรับระบุการพุ่งสูงของกิจกรรมและการดำเนินการนอกเวลาทำการ |

### 🎯 Threat Detection

| # | ชื่อแผนภูมิ | คำอธิบาย |
|---|------------|-------------|
| 1 | Security Monitoring & Control Changes | จุดรวมที่ครอบคลุมสำหรับเหตุการณ์การหลบเลี่ยงการป้องกันทั้งหมด (DSH-22) ครอบคลุมการดัดแปลง CloudTrail (StopLogging, DeleteTrail), การปิดใช้งาน GuardDuty, การปิดใช้งาน AWS Config, การลบ VPC Flow Log, การลบ log ของ CloudWatch และการปิดใช้งานบริการความปลอดภัย (SecurityHub, IAM Access Analyzer) เหตุการณ์ใด ๆ ที่นี่สมควรได้รับการตรวจสอบทันที สำหรับการวิเคราะห์เชิงลึกเพิ่มเติม ใช้แผนภูมิเฉพาะ: VPC Flow Log Changes (DSH-42), AWS Config Tampering (DSH-43), EventBridge/CW Tampering (DSH-47) MITRE ATT&CK: TA0005 Defense Evasion |
| 2 | CloudTrail Logging Gap (Hourly Volume) | ปริมาณเหตุการณ์ CloudTrail รายชั่วโมง (DSH-91) การลดลงอย่างฉับพลันสู่ศูนย์ระหว่างช่วงที่มีกิจกรรมบ่งชี้ว่า logging ถูกปิดใช้งาน (StopLogging/DeleteTrail) หรือมีจุดบอดในการส่งข้อมูล ตรวจสอบช่องว่างที่ไม่คาดคิดใด ๆ เทียบกับตาราง Security Monitoring & Control Changes MITRE ATT&CK: T1562.008 Impair Defenses — Disable Cloud Logs |
| 3 | VPC Flow Log Changes | เหตุการณ์การสร้างและลบ VPC Flow Log (DSH-42) DeleteFlowLogs ขจัดแหล่งหลักฐานทางนิติวิทยาศาสตร์เครือข่ายหลัก ทำให้การวิเคราะห์หลังเหตุการณ์เกี่ยวกับการเคลื่อนที่ด้านข้างและการลักลอบนำข้อมูลออกเป็นไปไม่ได้ CreateFlowLogs ระหว่างเหตุการณ์อาจบ่งชี้การเปลี่ยนเส้นทาง log ไปยัง S3 bucket ที่ผู้โจมตีควบคุม MITRE ATT&CK: TA0005 Defense Evasion |
| 4 | AWS Config Recorder & Rule Changes | เหตุการณ์การดัดแปลง recorder และ rule ของ AWS Config (DSH-43): StopConfigurationRecorder, DeleteConfigurationRecorder, DeleteDeliveryChannel, DeleteConfigRule และ PutConfigRule การหยุด Config recorder ขจัดหลักฐานการปฏิบัติตามข้อกำหนดและการติดตามการเปลี่ยนแปลงของทั้งภูมิภาค ทำให้การเปลี่ยนแปลงโครงสร้างพื้นฐานในภายหลังไม่ถูกตรวจพบโดย Config rule และมาตรฐานของ Security Hub MITRE ATT&CK: TA0005 Defense Evasion |
| 5 | EventBridge & CloudWatch Rule Modifications | การดัดแปลง rule ของ EventBridge และ CloudWatch Events (DSH-47): DeleteRule, DisableRule (ปิดเสียงการตรวจจับตามกำหนดการ), CreateSchedule/UpdateSchedule (cron job ของผู้โจมตีสำหรับ C2 beaconing), PutSubscriptionFilter (เปลี่ยนเส้นทาง log ของ CloudTrail/VPC ไปยังบัญชีของผู้โจมตี), DeleteLogGroup (ทำลายบันทึก VPC Flow Log) แผนภูมิรวมการดัดแปลงชั้น monitoring สำหรับ DFIR MITRE ATT&CK: TA0003 Persistence / TA0005 Defense Evasion / TA0011 C2 |
| 6 | WAF Configuration Changes | เหตุการณ์การเปลี่ยนแปลงการตั้งค่าของ AWS WAF v2 / WAF Classic (DSH-75) ครอบคลุมการสร้าง/อัปเดต/ลบ WebACL, การจัดการ IP set, การเปลี่ยนแปลง rule group, การเปลี่ยนแปลงการตั้งค่า logging และการเชื่อมโยง/ยกเลิกการเชื่อมโยง WAF กับทรัพยากรที่ได้รับการป้องกัน การปิดใช้งาน rule ของ WAF หรือ logging ระหว่างที่มีการโจมตีเกิดขึ้นเป็นตัวบ่งชี้การหลบเลี่ยงการป้องกันที่ชัดเจน MITRE ATT&CK: TA0005 Defense Evasion / TA0003 Persistence |
| 7 | Organizations / SCP Changes | เหตุการณ์ management-plane ของ AWS Organizations รวมถึงการเปลี่ยนแปลง policy ของ SCP (DSH-24) ผู้โจมตีที่มีสิทธิ์เข้าถึงบัญชีหลักอาจปิดใช้งาน guardrail ของ SCP เพื่อขจัดการควบคุมเชิงป้องกันในทุกบัญชีของ AWS organization MITRE ATT&CK: TA0004 Privilege Escalation / TA0005 Defense Evasion |
| 8 | Error Event Trend | เหตุการณ์ error รายชั่วโมงแยกย่อยตาม error_code (DSH-04) การพุ่งสูงของ ThrottlingException บ่งชี้การสแกนหรือเครื่องมือโจมตีอัตโนมัติ การพุ่งสูงของ AccessDenied / UnauthorizedAccess บ่งชี้การทดสอบสิทธิ์ การปรากฏขึ้นอย่างฉับพลันของ error code ใหม่อาจบ่งชี้เทคนิคการโจมตีแบบใหม่ |
| 9 | Throttling Exception Spikes | error การจำกัดอัตรา/throttling รายชั่วโมงแยกย่อยตามบริการ AWS (DSH-21) การพุ่งสูงของ ThrottlingException บ่งชี้ว่าอัตลักษณ์ (หรือเครื่องมือ) กำลังส่งการเรียก API เร็วกว่าที่คาดไว้มาก ซึ่งเป็นลักษณะเฉพาะของเครื่องมือโจมตีอัตโนมัติที่ทำการสอดแนมหรือแจกแจง MITRE ATT&CK: TA0007 Discovery |
| 10 | Write/Read Ratio Trend | การแยกย่อยรายชั่วโมงของการเรียก API แบบอ่านเทียบกับเขียน (DSH-20) การเพิ่มขึ้นอย่างต่อเนื่องของ write_events เทียบกับ read_events บ่งชี้ว่าผู้โจมตีได้เปลี่ยนจากการสอดแนมไปสู่การโจมตีเชิงรุก MITRE ATT&CK: TA0040 Impact / TA0007 Discovery |
| 11 | CloudTrail Events Over Time | ปริมาณเหตุการณ์ Read เทียบกับ Write รายชั่วโมงตามเวลา (DSH-01) แท่งกราฟแบบซ้อนแสดงสัดส่วน Read/Write การเพิ่มขึ้นอย่างฉับพลันของ write_events ส่งสัญญาณว่าผู้โจมตีกำลังเปลี่ยนจากการสอดแนมไปสู่การโจมตีเชิงรุก มีประโยชน์สำหรับระบุการพุ่งสูงของกิจกรรมและการดำเนินการนอกเวลาทำการ |
| 12 | Organization Membership Changes | การเปลี่ยนแปลงสมาชิกภาพของ Organizations ที่แยกบัญชีออกจาก guardrail หรือย้ายไปอยู่ภายใต้ organization ที่ผู้โจมตีควบคุม Threat Technique Catalog for AWS: T1666.A002 / T1666.A003 |
| 13 | P1 Escalation Triggers | เหตุการณ์ที่ตรงกับตัวกระตุ้นการยกระดับของ TRIAGE_GUIDE ซึ่งต้องตอบสนองภายใน 15 นาที: การใช้ root, การแก้ไขบันทึกหรือการตรวจจับ, ข้อความเรียกค่าไถ่, การลงทะเบียนผู้ดูแลที่ได้รับมอบหมาย ค่าที่ไม่เป็นศูนย์หมายถึงเริ่มจับเวลา |
| 14 | P2 Escalation Triggers | เหตุการณ์ที่ตรงกับเงื่อนไขของ TRIAGE_GUIDE สำหรับการตอบสนองภายในหนึ่งชั่วโมง: การสร้างข้อมูลรับรอง การให้สิทธิ์ การแก้ไขนโยบายความเชื่อถือ และการรับบทบาทข้ามบัญชี ควรอ่านคู่กับการ์ด P1 |

### 🔑 Identity & Access

| # | ชื่อแผนภูมิ | คำอธิบาย |
|---|------------|-------------|
| 1 | Console Login Activity | เหตุการณ์ sign-in ผ่านคอนโซล AWS Management จัดกลุ่มตามอัตลักษณ์ IAM (DSH-08) ติดตามความพยายามล็อกอินที่สำเร็จ ล้มเหลว และไม่มี MFA อัตราส่วนความล้มเหลวต่อความสำเร็จที่สูงอาจบ่งชี้ brute-force หรือ credential stuffing mfa_less_count (MFAUsed = 'No') เป็นตัวบ่งชี้การถูกบุกรุกบัญชีโดยตรง แม้ว่าจะใช้ได้เฉพาะกับเหตุการณ์ ConsoleLogin แบบดั้งเดิมเท่านั้น — flow การล็อกอินแบบ OAuth2 ใหม่ (CreateOAuth2Token / AuthorizeOAuth2Access) ไม่รายงานสถานะ MFA เหตุการณ์ถูกกรองให้เฉพาะ event_type = 'AwsConsoleSignIn' |
| 2 | MFA-less Login Trend | การล็อกอินคอนโซลรายวันแยกตามการใช้ MFA (DSH-28) mfa_less_logins (MFAUsed = 'No') เป็นตัวบ่งชี้โดยตรงของการถูกบุกรุกบัญชีหรือ phishing การเพิ่มขึ้นอย่างต่อเนื่องของการล็อกอินที่ไม่มี MFA ควรกระตุ้นให้มีการทบทวน policy การยืนยันตัวตนของ IAM ทันที MITRE ATT&CK: TA0001 Initial Access |
| 3 | Failed -> Success Auth Sequence | ความล้มเหลวและความสำเร็จของการล็อกอินคอนโซลต่อ principal + source IP (DSH-93) failure_count ที่สูงคู่กับ success_count ที่ไม่ใช่ศูนย์บ่งชี้การโจมตีแบบ brute force / password spray ที่ในที่สุดก็สำเร็จ — ถือว่าความสำเร็จเป็นจุดที่ถูกบุกรุกและไล่ตามด้วย source IP MITRE ATT&CK: T1110 Brute Force |
| 4 | Login Activity Heatmap (Hour x Day) | จำนวนการล็อกอินคอนโซลในรูปแบบ heatmap ของชั่วโมงในวัน (X) เทียบกับวันในสัปดาห์ (Y) ตามเวลา JST (DSH-19) เซลล์ที่สว่างในคอลัมน์ช่วงดึก (22:00-06:00 JST) หรือแถววันหยุดสุดสัปดาห์เป็นตัวบ่งชี้ที่ชัดเจนของการถูกบุกรุกบัญชีหรือการใช้ credential ในทางมิชอบ MITRE ATT&CK: TA0001 Initial Access |
| 5 | Root Account Usage | การเรียก API ทั้งหมดที่ทำโดยบัญชี AWS Root (DSH-13) การใช้งานบัญชี Root ควรเกิดขึ้นได้ยากมากในสภาพแวดล้อมที่มีการกำกับดูแลที่ดี กิจกรรมของ Root ใด ๆ — โดยเฉพาะ CreateAccessKey, ConsoleLogin หรือ StopLogging — เป็นตัวบ่งชี้ที่สำคัญของการถูกบุกรุกหรือการละเมิด policy |
| 6 | IAM Entity Activity | IAM entity อันดับต้น 50 รายการจัดอันดับตามจำนวนการเรียก API ทั้งหมด พร้อมอัตราส่วนการเขียนและการแยกย่อย error (DSH-03) entity ที่มี write_ratio_pct หรือ error_events สูงเทียบกับ total_events อาจบ่งชี้การใช้ credential ในทางมิชอบหรือการยกระดับสิทธิ์ last_seen แสดง timestamp ของกิจกรรมล่าสุดสำหรับแต่ละ entity |
| 7 | IAM Privilege Change Event Timeline | จำนวนการเรียก API การยกระดับสิทธิ์รายวันแยกย่อยตามชื่อเหตุการณ์ (DSH-30) การพุ่งสูงในวันเดียวบ่งชี้แคมเปญการโจมตีแบบเฉพาะเจาะจง การเพิ่มขึ้นอย่างช้า ๆ อาจบ่งชี้ภัยคุกคามจากภายในหรือผู้โจมตีที่มีฐานที่มั่นถาวร MITRE ATT&CK: TA0004 Privilege Escalation |
| 8 | New IAM Principal Creation Timeline | เหตุการณ์การสร้าง IAM principal และ credential รายวัน ซ้อนตามประเภทเหตุการณ์ (DSH-95) การพุ่งสูงของ CreateAccessKey / CreateLoginProfile / CreateUser เป็นตัวบ่งชี้การคงอยู่หลังจากการเข้าถึงเริ่มต้น — เชื่อมโยงกับ principal ที่ดำเนินการและ source IP MITRE ATT&CK: T1136 Create Account / T1098 Account Manipulation |
| 9 | Glue & SageMaker IAM Role Pass Events | เหตุการณ์ Glue DevEndpoint และ SageMaker Notebook ที่ใช้สำหรับการยกระดับสิทธิ์ IAM (DSH-50) iam:PassRole + glue:CreateDevEndpoint สร้าง environment Python/Spark ที่เข้าถึงผ่าน SSH ได้ด้วยสิทธิ์เต็มของ role ที่ส่งมา iam:PassRole + sagemaker:CreateNotebookInstance ให้ notebook Jupyter ที่มีผลเช่นเดียวกัน sagemaker:CreatePresignedNotebookInstanceUrl เพียงอย่างเดียวก็สามารถให้สิทธิ์เข้าถึง notebook ที่มีอยู่แล้วได้โดยไม่ต้องเป็นเจ้าของ role พื้นฐาน ทั้งสองรายการมีการบันทึกไว้ใน repository AWS-IAM-Privilege-Escalation และนำไปใช้ในโมดูล iam__privesc_scan ของ Pacu MITRE ATT&CK: TA0004 Privilege Escalation |
| 10 | AssumedRole from External IP | การเรียก AssumedRole API ที่มาจาก IP สาธารณะ (ไม่ใช่ private) (DSH-27) credential ของ EC2 instance metadata service (IMDS) โดยปกติจะใช้จากภายใน VPC เท่านั้น การเรียกจาก IP ภายนอกบ่งชี้ว่า credential ชั่วคราวรั่วไหล — โดยทั่วไปผ่าน SSRF, การหลุดออกจาก container หรือการ export คีย์ MITRE ATT&CK: TA0008 Lateral Movement / TA0006 Credential Access |
| 11 | Cross-Account AssumeRole | การเรียก AssumeRole / AssumeRoleWithWebIdentity ที่ recipient_account_id ต่างจากบัญชีของผู้เรียก (DSH-94) ID บัญชีภายนอกที่ไม่คาดคิดบ่งชี้การใช้ trusted-relationship ในทางมิชอบหรือการเคลื่อนที่ด้านข้างระหว่างบัญชี — ตรวจสอบว่าบัญชีปลายทางแต่ละบัญชีเป็น trust ที่ได้รับการอนุมัติ MITRE ATT&CK: T1199 Trusted Relationship / TA0008 Lateral Movement |
| 12 | Secrets Access Anomaly | อัตลักษณ์ที่เข้าถึง Secrets Manager หรือ SSM Parameter Store ≥10 ครั้งในหนึ่งชั่วโมง (DSH-23) การอ่าน credential จำนวนมากเป็นตัวบ่งชี้หลังการโจมตี — ผู้โจมตีเก็บเกี่ยวข้อมูลลับที่จัดเก็บไว้เพื่อเคลื่อนที่ไปยังบริการหรือบัญชีอื่น MITRE ATT&CK: TA0006 Credential Access / TA0010 Exfiltration |
| 13 | Security-Relevant API Calls | การเรียกใช้การกระทำ API ของ AWS ที่ทราบว่าละเอียดอ่อนด้านความปลอดภัย (DSH-12) ครอบคลุมการเปลี่ยนแปลง credential ของ IAM, การแก้ไข policy, การเปลี่ยนแปลง policy ของ S3 bucket, การแก้ไข security group, การจัดการคีย์, การดำเนินการ token ของ STS, การปิดใช้งานบริการความปลอดภัย, การอ่าน Secrets Manager และการจัดการ Organizations การเรียกเหล่านี้ควรเกิดขึ้นได้ยากในการดำเนินงานปกติ การเกิดขึ้นที่ไม่คาดคิดอาจบ่งชี้การยกระดับสิทธิ์ การคงอยู่ หรือการลักลอบนำข้อมูลออก |
| 14 | IAM Identity Center (SSO) Events | เหตุการณ์การจัดการ AWS IAM Identity Center (DSH-44) จาก sso.amazonaws.com, sso-directory.amazonaws.com, sso-oauth.amazonaws.com และ identitystore.amazonaws.com Identity Center เป็นเส้นทางการยืนยันตัวตนหลักในองค์กรที่มีหลายบัญชี ภัยคุกคามสำคัญ: CreatePermissionSet (การเข้าถึง admin แบบแบ็คดอร์), CreateAccountAssignment (การกำหนดบัญชีให้กับผู้ใช้ที่ผู้โจมตีควบคุม) และ AttachManagedPolicyToPermissionSet (การยกระดับสิทธิ์) MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence / TA0004 Privilege Escalation |
| 15 | IAM Entity Deletion | การลบผู้ใช้ IAM, role, policy และอุปกรณ์ MFA ที่ใช้ลบร่องรอยของอัตลักษณ์ที่ผู้โจมตีสร้างขึ้นหรือล็อกผู้ป้องกันออก Threat Technique Catalog for AWS: T1070.A001 |
| 16 | AssumeRoot Usage | การเรียก sts:AssumeRoot จากบัญชี management ไปยัง root ของ member account — เส้นทางการยึดครอง member account แบบเต็มรูปแบบ Threat Technique Catalog for AWS: AT1669 |
| 17 | Role Chaining (Session → Role) | การกระโดดของห่วงโซ่บทบาท — เซสชันบทบาทที่รับมาแล้วไปรับบทบาทอื่นต่อ ความลึกคือสัญญาณ ต้องใช้คอลัมน์ session_issuer_arn ที่เลื่อนขึ้นมา |
| 18 | Session Credential Trace (ASIA keys) | สิ่งที่แต่ละเซสชัน STS ชั่วคราวทำ โดยแยกตามคีย์การเข้าถึง ASIA: จำนวนการเรียก, API ที่ไม่ซ้ำ, IP ต้นทาง, ภูมิภาค และช่วงเวลา เริ่มจากเซสชันที่ครอบคลุมหลาย IP ต้นทาง |
| 19 | API Calls Without MFA | การเรียกเขียนจากเซสชันที่ไม่ได้ยืนยันตัวตนด้วย MFA ต่างจากการ์ดการเข้าสู่ระบบคอนโซลโดยไม่มี MFA ตรงที่ครอบคลุมทุกการเรียก API ไม่ใช่แค่ ConsoleLogin |
| 20 | Federated Console Logins by Provider & Origin | การเข้าสู่ระบบคอนโซลผ่านผู้ให้บริการข้อมูลประจำตัวภายนอก พร้อมชื่อผู้ให้บริการ ประเทศ และ ASN เมื่อ IdP คือส่วนที่ถูกเจาะ AWS จะเห็นเพียงการเข้าสู่ระบบที่ถูกต้อง |
| 21 | Identity Center Permission Set Grants | การให้สิทธิ์ IAM Identity Center รายวันตามชื่อเหตุการณ์ ชุดสิทธิ์มีขอบเขตทั้งองค์กร การกำหนดเพียงครั้งเดียวอาจให้สิทธิ์ผู้ดูแลในบัญชีที่ผู้โจมตีไม่เคยแตะ |

### 🚨 High-Risk API Monitor

| # | ชื่อแผนภูมิ | คำอธิบาย |
|---|------------|-------------|
| 1 | Security Service Modification API Events | log เหตุการณ์โดยละเอียดสำหรับ API ที่ใช้ปิดใช้งานหรือดัดแปลงการควบคุมการตรวจสอบ (HRM-44) ครอบคลุม: DeleteTrail, StopLogging, UpdateTrail, PutEventSelectors (การดัดแปลง CloudTrail), DeletePolicy และ DetachPolicy (การลบ guardrail ของ IAM) การเกิดขึ้นใด ๆ นอกช่วงเวลาการเปลี่ยนแปลงที่ได้รับอนุญาตสมควรได้รับการตรวจสอบทันที MITRE ATT&CK: TA0005 Defense Evasion |
| 2 | Credential Retrieval API Events | log เหตุการณ์โดยละเอียดสำหรับ API ที่ใช้ดึงข้อมูลลับและ credential (HRM-45) ครอบคลุม: GetSecretValue (Secrets Manager), GetParameter / GetParameterHistory (SSM) การเรียกครั้งเดียวอาจถูกต้องตามกฎหมาย แต่การเข้าถึงข้อมูลลับที่แตกต่างกันหลายสิบรายการอย่างรวดเร็วเป็นสัญญาณของผู้โจมตีที่ชัดเจน MITRE ATT&CK: TA0006 Credential Access |
| 3 | Top High-Risk API Calls | การกระทำ API จาก watchlist ความเสี่ยงสูงจัดอันดับตามจำนวนการเรียกทั้งหมด (HRM-40) การปรากฏบ่อยของ API การสอดแนม (ListUsers, GetCallerIdentity) เป็นเรื่องปกติในหลายสภาพแวดล้อม ให้เน้นการสืบสวนไปที่ API การเข้าถึง credential และการหลบเลี่ยงการป้องกันที่ปรากฏด้วยปริมาณผิดปกติหรือจาก principal ที่ไม่คาดคิด |
| 4 | Top Actors — High-Risk APIs | IAM principal จัดอันดับตามจำนวนการเรียกทั้งหมดไปยัง API ใน watchlist ความเสี่ยงสูง (HRM-42) เปรียบเทียบกับแผนภูมิหมวดหมู่การโจมตีเพื่อดูว่าแต่ละ principal กำลังทำอะไร service role ที่เรียก AssumeRole บ่อย ๆ ถือเป็นเรื่องปกติ แต่ผู้ใช้ที่เป็นมนุษย์เรียก GetSecretValue หรือ DeleteTrail จำนวนมากไม่ปกติ |
| 5 | High-Risk API Events Over Time | ปริมาณการเรียกรายวันสำหรับ API ที่มักพบในแคมเปญการโจมตี (HRM-39) การพุ่งสูงอย่างฉับพลันของการกระทำที่ปกติหาได้ยาก เช่น DeleteTrail หรือ GetSecretValue สมควรได้รับการตรวจสอบทันที โปรดทราบว่า API หลายรายการเหล่านี้ยังถูกเรียกใน workflow ที่ถูกต้องตามกฎหมายด้วย — ใช้ความผิดปกติของปริมาณเป็นสัญญาณหลัก ไม่ใช่เพียงการปรากฏตัว MITRE ATT&CK: TA0001 / TA0003 / TA0004 / TA0005 / TA0006 / TA0007 / TA0008 |

### 📊 API Activity

| # | ชื่อแผนภูมิ | คำอธิบาย |
|---|------------|-------------|
| 1 | Top 20 API Calls | การกระทำ API ของ AWS ที่ถูกเรียกบ่อยที่สุด 20 รายการ (DSH-02) จำนวนการเรียกที่สูงสำหรับการกระทำที่ละเอียดอ่อน (เช่น AssumeRole, GetSecretValue) อาจบ่งชี้เครื่องมืออัตโนมัติหรือการสอดแนม |
| 2 | Top Access Denied Actions | การกระทำ API อันดับต้น 20 รายการที่คืน error AccessDenied หรือ Client.UnauthorizedAccess (DSH-09) เหตุการณ์ access-denied ที่เกิดซ้ำต่อ API ที่ละเอียดอ่อน (เช่น AssumeRole, GetSecretValue, PutBucketPolicy) เป็นตัวบ่งชี้ที่ชัดเจนของความพยายามยกระดับสิทธิ์หรือการเคลื่อนที่ด้านข้าง |
| 3 | Region Activity | การกระจายของเหตุการณ์ CloudTrail ทั่วภูมิภาค AWS (DSH-14) write_ratio_pct เน้นภูมิภาคที่มีกิจกรรมการเขียนไม่สมส่วน — ภูมิภาคที่ไม่คาดคิดซึ่งมีอัตราส่วนการเขียนสูงอาจบ่งชี้ EC2 instance สำหรับ crypto-mining, การเคลื่อนที่ด้านข้าง หรือการลักลอบนำข้อมูลออกไปยังภูมิภาคที่ถูกตรวจสอบน้อยกว่า |
| 4 | Error-Code Composition Over Time | ปริมาณ error รายวันของ CloudTrail ซ้อนตาม error_code (DSH-96) แถบ AccessDenied / UnauthorizedOperation ที่เพิ่มขึ้นบ่งชี้การสอดแนมหรือการทดสอบสิทธิ์ การพุ่งสูงของ Throttling บ่งชี้การแจกแจงในระดับใหญ่ MITRE ATT&CK: TA0007 Discovery |
| 5 | Top Source IP Addresses | source IP ภายนอกอันดับต้น 100 รายการตามจำนวนคำขอ (DSH-05) ไม่รวมรูปแบบ IP ภายในของ AWS (*.amazonaws.com) IP ที่มี write_requests สูงเทียบกับ request_count อาจบ่งชี้การลักลอบนำข้อมูลออก การเคลื่อนที่ด้านข้าง หรือเครื่องมือโจมตีอัตโนมัติ |
| 6 | User Agent Analysis | user agent อันดับต้น 50 รายการตามจำนวนคำขอ พร้อมการแยกย่อย error และการเขียน (DSH-11) user agent ที่ผิดปกติหรือกำหนดเอง (เช่น Python/boto3, สคริปต์กำหนดเอง, Pacu, ScoutSuite) อาจบ่งชี้เครื่องมือโจมตีอัตโนมัติ agent ภายในของ AWS (console.amazonaws.com, signin.amazonaws.com) ถือเป็นเรื่องปกติ ส่วนสตริงที่ไม่รู้จักสมควรได้รับการตรวจสอบ |

### 🪣 S3 & RDS

| # | ชื่อแผนภูมิ | คำอธิบาย |
|---|------------|-------------|
| 1 | S3 High-Volume Object Downloads | การเรียก GetObject จำนวนมากของ S3 (DSH-52): อัตลักษณ์ที่ทำคำขอ GetObject ≥100 ครั้งในหนึ่งชั่วโมง จัดกลุ่มตามช่วงชั่วโมง อัตลักษณ์ และ source IP การอ่านปริมาณสูงบ่งชี้การลักลอบนำข้อมูลออกแบบอัตโนมัติ — ผู้โจมตีดัมพ์เนื้อหา bucket ก่อนที่จะทำลายหรือเรียกค่าไถ่ ผสานกับแผนภูมิ S3 Bulk Deletion เพื่อระบุสายโซ่ ransomware ทั้งหมด: ลักลอบนำออกแล้วทำลาย MITRE ATT&CK: TA0010 Exfiltration |
| 2 | S3 Bulk Object Deletion | การเรียก DeleteObject/DeleteObjects จำนวนมากของ S3 (DSH-53): อัตลักษณ์ที่ลบ object ≥50 รายการในหนึ่งชั่วโมง จัดกลุ่มตามช่วงชั่วโมง อัตลักษณ์ และ source IP การลบปริมาณสูงเป็นขั้นตอนการทำลายข้อมูลของการโจมตีแบบ ransomware — ผู้โจมตีลักลอบนำออกก่อน (ดูแผนภูมิ S3 Bulk Download) แล้วจึงล้าง bucket ต้นทางเพื่อเรียกค่าไถ่จากเหยื่อ ยังครอบคลุมการลบจำนวนมากโดยไม่ตั้งใจ MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction |
| 3 | S3 Versioning / Logging Disabled | เหตุการณ์การระงับ versioning และการปิดใช้งาน logging ของ S3 (DSH-54): PutBucketVersioning ที่มี Status=Suspended และ PutBucketLogging ที่มี BucketLoggingStatus ว่างเปล่า ผู้โจมตีปิดใช้งาน versioning เพื่อป้องกันการกู้คืน object หลังการลบ และปิด logging เพื่อลบร่องรอยหลักฐานการเข้าถึง ทั้งสองอย่างเป็นการเตรียมการต่อต้านนิติวิทยาศาสตร์ก่อนการทำลายข้อมูล MITRE ATT&CK: TA0005 Defense Evasion / T1070 Indicator Removal |
| 4 | S3 Cross-Account Replication | เหตุการณ์การตั้งค่าการจำลองข้ามบัญชีของ S3 (DSH-55): PutBucketReplication และ DeleteBucketReplication การจำลองข้ามบัญชีคัดลอก object ใหม่ทุกรายการไปยัง bucket ที่ผู้โจมตีควบคุมอย่างเงียบ ๆ สร้างช่องทางการลักลอบนำออกแบบถาวรที่ข้ามการควบคุม DLP ของเครือข่าย PutBucketReplication ใด ๆ ที่ชี้ไปยัง account ID ภายนอกเป็นตัวบ่งชี้เหตุการณ์ที่สำคัญ MITRE ATT&CK: TA0010 Exfiltration / T1537 Transfer Data to Cloud Account |
| 5 | S3 Bucket Policy / ACL Changes | เหตุการณ์การแก้ไข policy และ ACL ของ S3 bucket (DSH-45): PutBucketPolicy, DeleteBucketPolicy, PutBucketAcl, PutBucketCors, PutBucketWebsite และ DeleteBucketWebsite การเปลี่ยนแปลงเหล่านี้สามารถเปิดเผยเนื้อหา bucket สู่สาธารณะหรือให้สิทธิ์เข้าถึงแก่บัญชีที่ผู้โจมตีควบคุม PutBucketPolicy ที่มี Principal='*' เป็นตัวบ่งชี้การเปิดเผยข้อมูลทันที MITRE ATT&CK: TA0010 Exfiltration / TA0005 Defense Evasion |
| 6 | S3 Bucket & Object List Activity | การเรียก API การแจกแจงของ S3 จัดกลุ่มตามอัตลักษณ์และ source IP (DSH-74) ครอบคลุม ListBuckets (การค้นพบทั้งบัญชี), ListObjects / ListObjectsV2 (การแจกแจงต่อ bucket), ListObjectVersions, ListMultipartUploads, HeadBucket และ HeadObject การพุ่งสูงอย่างฉับพลันของการเรียก list จากอัตลักษณ์ใหม่หรือ IP ภายนอกบ่งชี้การสอดแนมอย่างชัดเจนหลังจากการถูกบุกรุก credential MITRE ATT&CK: TA0007 Discovery |
| 7 | S3 Protection Config Changes | เหตุการณ์ S3 ที่ลดทอนท่าทีความปลอดภัยของ bucket (DSH-25) การปิดใช้งาน server-access logging ลบ audit trail การลบ public-access block เปิดเผยข้อมูลสู่อินเทอร์เน็ต การลบการเข้ารหัสหรือการจำลองของ bucket ลดทอนการป้องกันข้อมูลขณะพัก การกระทำเหล่านี้เป็นการกระทำก่อนการลักลอบนำออกหรือการปกปิด MITRE ATT&CK: TA0005 Defense Evasion / TA0040 Impact |
| 8 | AWS Backup Vault & Plan Deletion Events | เหตุการณ์การลบ AWS Backup Vault, Plan และ Recovery Point (DSH-57): DeleteBackupVault, DeleteBackupPlan, DeleteRecoveryPoint, DeleteBackupSelection, DisassociateRecoveryPoint, PutBackupVaultAccessPolicy และ DeleteBackupVaultLockConfiguration การทำลายการสำรองข้อมูลเป็นขั้นตอนแรกในแคมเปญ ransomware — เพื่อให้แน่ใจว่าเหยื่อไม่สามารถกู้คืนจากการสำรองข้อมูลได้ก่อนที่จะเรียกร้องค่าไถ่ การลบ Vault Lock (DeleteBackupVaultLockConfiguration) มีความสำคัญเป็นพิเศษเนื่องจากขจัดความไม่เปลี่ยนแปลงแบบ WORM ออกจาก vault MITRE ATT&CK: TA0040 Impact / T1490 Inhibit System Recovery |
| 9 | KMS Key Deletion & Disable Events | เหตุการณ์การลบ ปิดใช้งาน และการจัดการการหมุนคีย์ KMS (DSH-66) ScheduleKeyDeletion — กำหนดเวลาการลบคีย์ (หน้าต่าง 7-30 วันเพื่อยกเลิก) DisableKey — หยุดการเข้ารหัส/ถอดรหัสด้วยคีย์ทันที DeleteImportedKeyMaterial — ทำลายเนื้อหาคีย์สำหรับคีย์ที่นำเข้าทันที DisableKeyRotation — ป้องกันการหมุนคีย์รายปีอัตโนมัติ เหตุการณ์ใด ๆ เหล่านี้ทำให้ข้อมูลทั้งหมดที่เข้ารหัสด้วยคีย์นั้นไม่สามารถเข้าถึงได้อย่างถาวร ใช้ CancelKeyDeletion เพื่อย้อนกลับ ScheduleKeyDeletion ก่อนวันที่กำหนดลบ MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction |
| 10 | RDS Deleted without Final Snapshot | การลบ RDS instance และ cluster ด้วย skipFinalSnapshot=true (DSH-56): เหตุการณ์ DeleteDBInstance และ DeleteDBCluster ที่ไม่มีการสร้าง snapshot สุดท้าย การข้าม snapshot สุดท้ายทำให้ฐานข้อมูลไม่สามารถกู้คืนได้ — ไม่มีจุดกู้คืนหลงเหลืออยู่หลังการลบ ผู้ก่อการ ransomware ใช้วิธีนี้เพื่อเพิ่มแรงกดดันต่อเหยื่อสูงสุดเมื่อ AWS Backup ก็ถูกปิดใช้งานด้วยเช่นกัน เหตุการณ์ใด ๆ ที่นี่ถือเป็นเหตุการณ์ที่สำคัญ MITRE ATT&CK: TA0040 Impact / T1485 Data Destruction |
| 11 | RDS Snapshot Cross-Account Share | เหตุการณ์การแชร์ snapshot ของ RDS และ Aurora (DSH-40): ModifyDBSnapshotAttribute และ ModifyDBClusterSnapshotAttribute ที่ได้รับสิทธิ์การกู้คืนให้กับบัญชี AWS อื่น (valuesToAdd) ผู้โจมตีแชร์ snapshot ไปยังบัญชีของตนเองเพื่อลักลอบนำฐานข้อมูลทั้งหมดออกโดยไม่ต้องใช้ DLP ที่อิงกับ S3/เครือข่าย account ID ภายนอกใด ๆ ในแอตทริบิวต์การกู้คืนเป็นตัวบ่งชี้การลักลอบนำออกที่สำคัญ MITRE ATT&CK: TA0010 Exfiltration |
| 12 | S3 SSE-C Ransomware Encryption | object ของ S3 ที่ถูกเข้ารหัสใหม่ด้วยคีย์ SSE-C ที่ผู้โจมตีจัดหาให้ รวมถึงการเปลี่ยนแปลงการเข้ารหัสเริ่มต้นของ bucket — ransomware ที่เกิดขึ้นบนคลาวด์โดยเฉพาะ Threat Technique Catalog for AWS: T1486.A001 |
| 13 | S3 Lifecycle-Triggered Deletion | lifecycle rule ของ S3 ที่ทำให้ object หมดอายุ (และการลบการตั้งค่า lifecycle) ที่ใช้กำจัดข้อมูลอย่างเงียบ ๆ โดยไม่มีการเรียก DeleteObject จำนวนมาก Threat Technique Catalog for AWS: T1485.001 |
| 14 | RDS Query & Instance Manipulation | query ของ RDS Data API และการกู้คืน snapshot ที่ใช้อ่านข้อมูลโดยตรงหรือกู้คืนไปยัง instance ที่ผู้โจมตีควบคุม Threat Technique Catalog for AWS: AT1023.001 / T1213.A013 |
| 15 | Storage Re-Encryption for Impact | snapshot และ volume ของ EBS/RDS ที่ถูกเข้ารหัสใหม่ด้วยคีย์ KMS ที่ผู้โจมตีควบคุมอย่างชัดเจน รวมถึงการปิดใช้งานการเข้ารหัสเริ่มต้น Threat Technique Catalog for AWS: T1486.A002 / T1486.A003 |
| 16 | Data Access Scope (Breach Notification) | ต่อหลักการ: การเรียกอ่าน S3, บักเก็ตไม่ซ้ำ และอ็อบเจกต์ไม่ซ้ำโดยประมาณ ให้ตัวเลขที่ GDPR มาตรา 33 ต้องการ ต้องเปิดเหตุการณ์ข้อมูล CloudTrail บนบักเก็ต |
| 17 | Cross-Account Object Copy | การเรียก CopyObject ของ S3 และ PutObject ที่มีส่วนหัว x-amz-copy-source พร้อมต้นทางและปลายทาง แผนภูมิการจำลองครอบคลุมการตั้งค่า ส่วนนี้ครอบคลุมการคัดลอกแต่ละครั้ง |
| 18 | Ransom Note Placement | การเรียก PutObject ที่คีย์อ็อบเจกต์ดูเหมือนข้อความเรียกค่าไถ่ ต่างจากแผงแรนซัมแวร์อื่นตรงที่ยืนยันผลกระทบ — มีแถวใดแถวหนึ่งที่นี่ก็เป็น P1 |

### 🖥️ Computing

| # | ชื่อแผนภูมิ | คำอธิบาย |
|---|------------|-------------|
| 1 | EC2 Instance Launches | เหตุการณ์ EC2 RunInstances ทั้งหมด (DSH-58) ผู้โจมตีเปิดใช้งาน instance เพื่อ crypto mining (GPU/spot), การรีเลย์ C2 หรือการเตรียมการเคลื่อนที่ด้านข้าง — มักอยู่ในภูมิภาคที่ไม่คาดคิดเพื่อหลีกเลี่ยงการตรวจจับ กรองตาม aws_region สำหรับการสืบสวนความผิดปกติของภูมิภาค กรองตาม user_identity_arn เพื่อติดตามว่า credential ใดเป็นผู้เปิดใช้งาน MITRE ATT&CK: TA0002 Execution / TA0040 Impact (Resource Hijacking) |
| 2 | RunInstances Spike by Region | ปริมาณ EC2 RunInstances รายวัน ซ้อนตามภูมิภาค AWS (DSH-97) การพุ่งสูงอย่างฉับพลัน — โดยเฉพาะในภูมิภาคที่อยู่นอกการดำเนินงานปกติ — บ่งชี้ cryptomining หรือการใช้ทรัพยากรในทางมิชอบ เปรียบเทียบกับ principal ที่ดำเนินการและ source IP MITRE ATT&CK: T1496 Resource Hijacking |
| 3 | EC2 Mass Stop / Terminate | เหตุการณ์ EC2 StopInstances และ TerminateInstances (DSH-62) การเรียก API เพียงครั้งเดียวสามารถหยุดหรือยกเลิก instance หลายสิบตัวพร้อมกันได้ การยกเลิกจำนวนมากคือขั้นตอนการทำลายของการโจมตีแบบ ransomware หรือการก่อวินาศกรรม — ทำให้ EC2 capacity ของ production ล่ม ตรวจสอบฟิลด์ request_parameters เพื่อดูรายการ instanceId ที่ได้รับผลกระทบทั้งหมด ผสานกับแผนภูมิ AWS Backup Tampering และ S3 Bulk Deletion เพื่อระบุสายโซ่ ransomware ทั้งหมด MITRE ATT&CK: TA0040 Impact / T1489 Service Stop |
| 4 | EC2 Key Pair Creation | เหตุการณ์การสร้างและนำเข้า EC2 key pair (DSH-59): CreateKeyPair, ImportKeyPair, DeleteKeyPair ผู้โจมตีสร้าง key pair ใหม่เพื่อสร้างการเข้าถึง SSH แบบถาวรไปยัง EC2 instance ที่อยู่รอดจากการหมุน credential ของ IAM ImportKeyPair แทรก public key ที่ผู้โจมตีควบคุมโดยตรงโดยไม่ต้องให้ AWS สร้างขึ้น CreateKeyPair หรือ ImportKeyPair ใด ๆ จากอัตลักษณ์หรือ IP ที่ไม่คุ้นเคยเป็นตัวบ่งชี้การคงอยู่ MITRE ATT&CK: TA0003 Persistence |
| 5 | EC2 Instance Profile Changes | เหตุการณ์การจัดการ EC2 instance profile และ IAM instance profile (DSH-60) IAM: CreateInstanceProfile, DeleteInstanceProfile, AddRoleToInstanceProfile, RemoveRoleFromInstanceProfile EC2: AssociateIamInstanceProfile, DisassociateIamInstanceProfile, ReplaceIamInstanceProfileAssociation การเปลี่ยน instance profile จะแทนที่ IAM role ที่ใช้ได้กับโค้ดทั้งหมดบน instance — เส้นทางการยกระดับสิทธิ์ที่พบบ่อยเมื่อผู้โจมตีควบคุม instance แต่ต้องการ role ที่มีสิทธิ์สูงกว่า MITRE ATT&CK: TA0004 Privilege Escalation / TA0003 Persistence |
| 6 | EC2 User Data Modification | เหตุการณ์การแก้ไข user data ของ EC2 (DSH-61): ModifyInstanceAttribute ที่มีการเปลี่ยนแปลงแอตทริบิวต์ userData user data ของ EC2 จะถูกรันโดย cloud-init ทุกครั้งที่ instance (re)start — การแทรกสคริปต์ที่เป็นอันตรายให้การรันโค้ดแบบถาวรที่อยู่รอดจากการรีบูต มักผสมกับลำดับ stop/start (ดูแผนภูมิ EC2 Mass Stop / Terminate) เพื่อกระตุ้นการทำงาน MITRE ATT&CK: TA0003 Persistence / TA0002 Execution |
| 7 | EC2 Public Snapshot / AMI Sharing | เหตุการณ์การแชร์สาธารณะของ EC2 EBS snapshot และ AMI (DSH-41): ModifySnapshotAttribute ที่มี createVolumePermission ให้กับกลุ่ม 'all' และ ModifyImageAttribute ที่มี launchPermission ให้กับกลุ่ม 'all' snapshot หรือ AMI สาธารณะทำให้บัญชี AWS ใดก็ตามสามารถคัดลอก disk image และดึงข้อมูลที่ละเอียดอ่อน credential และ private key ที่จัดเก็บบน volume ได้ MITRE ATT&CK: TA0010 Exfiltration |
| 8 | EC2 Spot Fleet & Reserved Instance Purchases | เหตุการณ์การซื้อ EC2 Spot Fleet, Fleet และ Reserved Instance (DSH-63): RequestSpotFleet, ModifySpotFleetRequest, CancelSpotFleetRequests, CreateFleet, DeleteFleet, PurchaseReservedInstancesOffering, RequestSpotInstances, CancelSpotInstanceRequests ผู้โจมตีใช้ Spot Fleet เพื่อเปิดใช้งาน cluster GPU/CPU ขนาดใหญ่สำหรับ crypto mining สร้างบิล AWS ที่สูงในขณะที่อยู่ต่ำกว่าเกณฑ์การตรวจจับต่อ instance การซื้อ Spot Fleet หรือ Reserved Instance ที่ไม่คาดคิดใด ๆ สมควรได้รับการตรวจสอบ MITRE ATT&CK: TA0040 Impact / T1496 Resource Hijacking |
| 9 | ECS Task Definition & Service Changes | เหตุการณ์การลงทะเบียน ECS task definition และการแก้ไข service (DSH-49) ecs__backdoor_task_def ของ Pacu ลงทะเบียน task definition revision ใหม่ที่แทรก sidecar container สำหรับขโมย credential จากนั้นออกคำสั่ง UpdateService เพื่อ deploy — ข้ามการตรวจสอบ image ของ ECR ไปโดยสิ้นเชิง RegisterTaskDefinition หรือ UpdateService ที่ไม่คาดคิดใด ๆ จากผู้เรียกหรือ IP ที่ไม่คุ้นเคยสมควรได้รับการตรวจสอบทันที MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0006 Credential Access |
| 10 | Lambda Function Configuration & Permission Changes | เหตุการณ์การสร้าง Lambda function การอัปเดตโค้ด และสิทธิ์ (DSH-64) UpdateFunctionCode แทนที่โค้ดฟังก์ชันด้วย payload ที่เป็นอันตราย AddPermission ให้สิทธิ์การเรียก Lambda ข้ามบัญชีหรือสาธารณะ CreateFunctionUrlConfig สร้าง endpoint HTTP สาธารณะสำหรับ C2 โดยตรง CreateEventSourceMapping เชื่อมโยงฟังก์ชันให้ทำงานเมื่อ S3/DynamoDB/SQS มีการเปลี่ยนแปลง PublishLayerVersion แทรก layer ที่ใช้ร่วมกันซึ่งเป็นอันตรายเข้าไปในหลายฟังก์ชัน สิ่งเหล่านี้จากอัตลักษณ์หรือ IP ที่ไม่คาดคิดเป็นตัวบ่งชี้การคงอยู่/การรันโค้ด MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0011 Command and Control |
| 11 | SSM Session / Run Command Execution | เหตุการณ์การรันระยะไกลของ AWS Systems Manager (DSH-39): StartSession, TerminateSession, ResumeSession, SendCommand และ StartAutomationExecution SSM Session Manager ให้การเข้าถึง shell โดยไม่ต้องเปิดพอร์ต SSH/RDP และเป็นกลไกการเคลื่อนที่ด้านข้างหลักสำหรับผู้โจมตีที่มี credential ของ IAM ที่ถูกขโมย session หรือคำสั่งที่ไม่คาดคิดใด ๆ จาก IP หรืออัตลักษณ์ที่ผิดปกติสมควรได้รับการตรวจสอบทันที MITRE ATT&CK: TA0008 Lateral Movement / TA0002 Execution |
| 12 | EBS Direct API Snapshot Block Access | การเรียก EBS Direct API ที่ใช้ลักลอบนำข้อมูล snapshot ออก (DSH-51) ebs__download_snapshots ของ Pacu ใช้ ListSnapshotBlocks และ GetSnapshotBlock เพื่อสตรีมภาพ disk ของ EBS ทั้งหมดทีละ block โดยไม่ต้องสร้าง EC2 instance ขอสำเนา snapshot หรือกระตุ้นเหตุการณ์ ModifySnapshotAttribute — ทำให้มองไม่เห็นจากการตรวจจับการแชร์ snapshot แบบดั้งเดิม การเรียก GetSnapshotBlock หรือ ListSnapshotBlocks ใด ๆ จากอัตลักษณ์หรือ IP ที่ไม่คาดคิดเป็นตัวบ่งชี้การลักลอบนำออกที่สำคัญ MITRE ATT&CK: TA0010 Exfiltration / TA0009 Collection |
| 13 | EKS / ECR Container Platform Events | เหตุการณ์ EKS cluster และ ECR container registry (DSH-48) EKS: UpdateClusterConfig (API สาธารณะ), CreateFargateProfile (workload ที่เป็นอันตราย), AssociateIdentityProviderConfig (OIDC IdP ปลอม) ECR: PutImage (การ push image ที่มีแบ็คดอร์), SetRepositoryPolicy (การเข้าถึงข้ามบัญชี), PutRegistryPolicy (การเปิดเผย registry ทั้งองค์กร) เหตุการณ์แพลตฟอร์ม container มีความสำคัญสำหรับการตรวจจับการโจมตี supply-chain และการถูกบุกรุก control-plane ของ Kubernetes MITRE ATT&CK: TA0002 Execution / TA0003 Persistence / TA0010 Exfiltration |
| 14 | CloudFormation Stack Changes | เหตุการณ์การจัดการ CloudFormation stack และ change-set (DSH-65) UpdateStack เพียงครั้งเดียวสามารถ deploy EC2 instance แก้ไข IAM role หรือกำหนดค่าเครือข่ายใหม่ได้ — รวมการเรียก API แยกกันหลายสิบครั้งเป็นเหตุการณ์เดียว CreateStackSet deploy โครงสร้างพื้นฐานของผู้โจมตีไปทั่วทุกบัญชีในองค์กร ExecuteChangeSet ใช้การเปลี่ยนแปลงที่เตรียมไว้ล่วงหน้า ซ่อนขอบเขตผลกระทบจากการทบทวนเบื้องต้น DeleteStack สามารถทำลายทรัพยากรหลักฐานทางนิติวิทยาศาสตร์ MITRE ATT&CK: TA0003 Persistence / TA0002 Execution / TA0005 Defense Evasion |
| 15 | IMDS Options Weakening | การเรียก ModifyInstanceMetadataOptions ที่ทำให้ IMDSv2 เป็นทางเลือกหรือเปิดใช้งาน metadata endpoint อีกครั้ง เปิดการขโมย credential ผ่าน SSRF อีกครั้ง Threat Technique Catalog for AWS: T1552.005 |
| 16 | AMI & Snapshot Deletion | การยกเลิกการลงทะเบียน AMI และการลบ snapshot ของ EBS ที่ทำลายเส้นฐานการกู้คืนระหว่างการโจมตีเชิงทำลาย Threat Technique Catalog for AWS: T1485.A002 |
| 17 | WorkSpaces Hijacking | การจัดสรร Amazon WorkSpaces ที่ใช้สำหรับการยึดครองการประมวลผลนอกขอบเขตความปลอดภัยของ EC2 Threat Technique Catalog for AWS: T1496.A009 |

### 🤖 AI / LLM

| # | ชื่อแผนภูมิ | คำอธิบาย |
|---|------------|-------------|
| 1 | Bedrock Model Invocation Trend | ปริมาณการเรียกใช้โมเดล Amazon Bedrock รายวันต่อ principal (DSH-98) การอนุมานปริมาณสูงด้วย credential ที่ถูกขโมย (LLMjacking) ถูกขายต่อผ่าน reverse proxy โดยเหยื่อเป็นผู้รับภาระค่าใช้จ่าย ตรวจสอบการพุ่งสูงใด ๆ, principal ที่ไม่เคยเรียกใช้ Bedrock มาก่อน และการเรียกใช้จากแหล่งที่มาที่ไม่คาดคิด MITRE ATT&CK: TA0040 Impact (T1496 Resource Hijacking) |
| 2 | Bedrock Model Access & Logging Changes | การเปิดใช้งานการเข้าถึง foundation model และการดัดแปลงการบันทึก log การเรียกใช้ (DSH-99) ผู้โจมตีที่มี credential ที่ถูกขโมยเปิดใช้งานการเข้าถึงโมเดล Bedrock ด้วยตนเองก่อนใช้ในทางมิชอบ และตรวจสอบหรือลบการตั้งค่า logging การเรียกใช้โมเดลเพื่อไม่ให้ prompt ของตนถูกบันทึก — ทั้งสองอย่างเป็นตัวบ่งชี้ LLMjacking ที่มีการบันทึกไว้ แถวใด ๆ ในองค์กรที่ไม่เคยใช้ Bedrock มาก่อนสมควรได้รับการตรวจสอบทันที MITRE ATT&CK: TA0005 Defense Evasion / TA0040 Impact (T1496) |
| 3 | Bedrock Failed Invocations | ความพยายามเรียกใช้ Amazon Bedrock ที่ล้มเหลว จัดกลุ่มตามผู้เรียกและ error code (DSH-100) การพุ่งสูงของ error AccessDenied / ValidationException ข้ามหลายโมเดลและภูมิภาคบ่งชี้ว่าผู้โจมตีกำลังทดสอบว่าคีย์ที่ถูกขโมยเรียกใช้โมเดลใดได้บ้าง — ระยะการสอดแนมของ LLMjacking MITRE ATT&CK: TA0006 Credential Access / TA0007 Discovery |
| 4 | Bedrock Callers by Origin | บัญชีรายชื่อผู้เรียก Amazon Bedrock ทั้งหมดพร้อมแหล่งที่มาและความหลากหลายของโมเดล (DSH-101) มุมมองเส้นฐานสำหรับการ triage LLMjacking: principal ที่เรียกจากประเทศที่ไม่คาดคิด ASN ของ hosting/VPN หรือ user agent สคริปต์ทั่วไป (python-requests, curl) ที่มีปริมาณการเรียกสูงเป็นผู้ต้องสงสัยหลัก MITRE ATT&CK: TA0040 Impact (T1496 Resource Hijacking) |
| 5 | AgentCore Token Issuance (Daily) | การออกโทเค็นจากที่เก็บโทเค็น AgentCore รายวันตามการดำเนินการ การเรียกเหล่านี้แจกโทเค็น OAuth และคีย์ API ของบุคคลที่สาม การใช้ในทางที่ผิดจึงลามไปนอก AWS |
| 6 | AgentCore Gateway & Policy Changes | การเปลี่ยนแปลงเกตเวย์ เป้าหมาย และนโยบายของ AgentCore พร้อมแสดงโหมดเอนจินนโยบาย Cedar เมื่อเปลี่ยนจาก ENFORCE เป็น LOG_ONLY ก็ยังคืนค่าสำเร็จ ปลายทางจึงไม่เห็นสิ่งผิดปกติ |

### 🌐 Network

| # | ชื่อแผนภูมิ | คำอธิบาย |
|---|------------|-------------|
| 1 | Security Group Changes | การเปลี่ยนแปลง rule ของ EC2 security group (DSH-76) ครอบคลุมการอนุญาตและเพิกถอน rule ขาเข้า/ขาออก การสร้างและลบ security group และการอัปเดตคำอธิบาย rule rule ขาเข้าที่เปิดสู่ 0.0.0.0/0 บนพอร์ตของผู้ดูแลระบบ (22, 3389 ฯลฯ) เป็นตัวบ่งชี้ที่ชัดเจนของการเข้าถึงแบบแบ็คดอร์หรือการตั้งค่าผิดพลาด MITRE ATT&CK: TA0003 Persistence / TA0005 Defense Evasion |
| 2 | Network ACL / Route Table Changes | เหตุการณ์การแก้ไข Network ACL และ route table (DSH-46) การเปลี่ยนแปลง NACL (CreateNetworkAclEntry, DeleteNetworkAclEntry, ReplaceNetworkAclEntry) สามารถข้ามข้อจำกัดของ security group สำหรับทั้ง subnet ได้ การเปลี่ยนแปลง route table (CreateRoute, ReplaceRoute, DeleteRoute) สามารถเปลี่ยนเส้นทาง traffic ไปยังโครงสร้างพื้นฐานที่ผู้โจมตีควบคุมเพื่อการดักจับ หรือสร้างช่องทางการสื่อสาร C2 แบบเงียบ MITRE ATT&CK: TA0005 Defense Evasion / TA0011 Command and Control |
| 3 | VPC Infrastructure Changes | เหตุการณ์การเปลี่ยนแปลง topology ของ VPC (DSH-77) ครอบคลุมการสร้าง/ลบ/แก้ไข VPC การเปลี่ยนแปลง subnet การแนบ internet gateway การสร้าง/ลบ NAT gateway การเปลี่ยนแปลง VPC endpoint และการจัดสรร/เชื่อมโยง Elastic IP การแนบ IGW ที่ไม่คาดคิดหรือ NAT gateway ใหม่ในภูมิภาคที่ไม่ได้ใช้งานเป็นตัวบ่งชี้ที่ชัดเจนของโครงสร้างพื้นฐานการลักลอบนำออกที่ผู้โจมตีควบคุม MITRE ATT&CK: TA0010 Exfiltration / TA0003 Persistence / TA0011 C2 |
| 4 | VPC Peering & Transit Gateway Changes | เหตุการณ์การเปลี่ยนแปลงการเชื่อมต่อ VPC peering และ Transit Gateway (DSH-78) ครอบคลุมการสร้าง/ยอมรับ/ลบ VPC peering และการสร้าง Transit Gateway การแนบ VPC และการจัดการการแนบ peering คำขอ peering ข้ามบัญชีหรือการแนบ Transit Gateway ใหม่จากบัญชีที่ไม่คาดคิดบ่งชี้การเคลื่อนที่ด้านข้างระหว่างบัญชี AWS MITRE ATT&CK: TA0008 Lateral Movement / TA0010 Exfiltration |
| 5 | Route53 DNS Changes | การเปลี่ยนแปลงการตั้งค่า hosted-zone และ resolver ของ Route 53 (DSH-29) DNS tunnelling ใช้ record TXT/CNAME และ subdomain จำนวนมากเพื่อลักลอบนำข้อมูลออกใน payload ของ DNS query hosted zone ใหม่และการเรียก ChangeResourceRecordSets ที่ไม่คาดคิดควรได้รับการตรวจสอบทันที MITRE ATT&CK: TA0010 Exfiltration |

### 🕒 Temporal Analysis

| # | ชื่อแผนภูมิ | คำอธิบาย |
|---|------------|-------------|
| 1 | Event Velocity Spikes per Identity | อัตลักษณ์ที่มีช่วงกิจกรรมพุ่งสูง 50 เหตุการณ์ขึ้นไปต่อชั่วโมง (DSH-38) credential stuffing การแจกแจงอัตโนมัติ หรือการลักลอบนำข้อมูลออกสร้างการพุ่งสูงของความเร็วอย่างชัดเจนเหนือเส้นฐานปกติ แสดงช่วงชั่วโมง อัตลักษณ์ และจำนวนเหตุการณ์สำหรับการพุ่งสูงแต่ละครั้ง MITRE ATT&CK: TA0006 Credential Access / TA0009 Collection / TA0010 Exfiltration |
| 2 | Dormant Accounts Reactivated | อัตลักษณ์ที่มีช่วงไม่มีกิจกรรม 72 ชั่วโมงขึ้นไปแล้วกลับมามีกิจกรรมอีกครั้ง (DSH-37) รูปแบบคลาสสิกของ credential ที่ไม่ใช้งานซึ่งถูกบุกรุกและนำมาใช้เป็นอาวุธ แสดงช่วงว่างสูงสุดเป็นชั่วโมง/วันระหว่างเหตุการณ์ที่ต่อเนื่องกันของแต่ละอัตลักษณ์ MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence |
| 3 | First / Last Seen per IAM Identity | IAM identity พร้อม timestamp ที่พบครั้งแรก/ครั้งสุดท้าย จำนวนเหตุการณ์ API ที่แตกต่างกัน IP ที่แตกต่างกัน และช่วงเวลาที่ใช้งานเป็นวัน (DSH-31) จัดเรียงตาม first_seen จากมากไปน้อยเพื่อค้นหาอัตลักษณ์ที่ปรากฏใหม่ ช่วงเวลาใช้งานสั้นพร้อมจำนวนเหตุการณ์สูงบ่งชี้ credential ที่ถูกบุกรุกหรือการโจมตีอัตโนมัติ MITRE ATT&CK: TA0001 Initial Access / TA0003 Persistence |
| 4 | First / Last Seen per Source IP | source IP พร้อมการพบครั้งแรก/ครั้งสุดท้าย อัตลักษณ์ที่แตกต่างกัน API ที่แตกต่างกัน และบริบท GeoIP (DSH-32) IP ใหม่ที่ปรากฏช้าในชุดข้อมูลบ่งชี้การเคลื่อนที่ด้านข้างหรือโครงสร้างพื้นฐานใหม่ของผู้โจมตี MITRE ATT&CK: TA0001 Initial Access / TA0008 Lateral Movement |
| 5 | First / Last Seen per API Call | การกระทำ API เรียงตามการปรากฏครั้งแรก (DSH-33) การเรียก API ใหม่ที่ปรากฏเป็นครั้งแรกบ่งชี้ความพยายามสอดแนมหรือยกระดับสิทธิ์ MITRE ATT&CK: TA0007 Discovery / TA0004 Privilege Escalation |
| 6 | First / Last Seen per Service Source | timestamp ที่พบครั้งแรกและครั้งสุดท้ายสำหรับแหล่งบริการ AWS ที่แตกต่างกันทุกรายการ (DSH-26) จัดเรียงตาม first_seen จากมากไปน้อยเพื่อค้นหาบริการที่เพิ่งนำมาใช้ใหม่ (โครงสร้างพื้นฐานที่อาจเป็นของผู้โจมตี) จัดเรียงตาม last_seen จากน้อยไปมากเพื่อค้นหาบริการที่หยุดนิ่ง (อาจเป็นการล้างร่องรอยหลังการถูกบุกรุก) MITRE ATT&CK: TA0003 Persistence / TA0007 Discovery |
| 7 | Off-Hours Write Activity (Hour x Day) | จำนวนเหตุการณ์เขียนเป็นฮีตแมปชั่วโมงของวัน × วันในสัปดาห์ตามเวลา JST ฮีตแมปการเข้าสู่ระบบครอบคลุมเฉพาะ ConsoleLogin ส่วนนี้ครอบคลุมทุกการเรียกที่เปลี่ยนแปลงข้อมูล |
| 8 | Principal Daily Volume (Read vs Write) | ปริมาณการเรียกรายวันต่อหลักการ แยกเป็นการอ่านและการเขียน ประเมินแต่ละหลักการเทียบกับตัวเอง: บทบาทบิลด์เรียกหนึ่งหมื่นครั้งต่อวันถือว่าปกติ แต่มนุษย์สองร้อยครั้งไม่ใช่ |

### 🌍 GeoIP Intelligence

| # | ชื่อแผนภูมิ | คำอธิบาย |
|---|------------|-------------|
| 1 | Impossible Travel (Multi-Country Principals) | IAM principal จัดอันดับตามจำนวนประเทศต้นทางที่แตกต่างกัน พร้อม source IP ที่แตกต่างกัน จำนวนเหตุการณ์ทั้งหมด และการพบครั้งแรก/ครั้งสุดท้าย (DSH-92) distinct_countries >= 2 สำหรับ principal ที่เป็นมนุษย์เป็นสัญญาณการถูกบุกรุกบัญชีที่ชัดเจน — เปรียบเทียบกับช่วงเวลาและ source IP ต้องใช้การเติมข้อมูล GeoIP MITRE ATT&CK: TA0001 Initial Access / T1078 Valid Accounts |
| 2 | Top Countries by Request Volume | ประเทศต้นทางอันดับต้น 20 รายการตามปริมาณการเรียก API พร้อมการแยกย่อยเหตุการณ์การเขียนและผู้เรียกที่ไม่ซ้ำกัน (DSH-15) ประเทศที่โดยปกติไม่เกี่ยวข้องกับการดำเนินงานขององค์กรอาจบ่งชี้การขโมย credential หรือโครงสร้างพื้นฐานที่ผู้โจมตีควบคุม ต้องใช้การเติมข้อมูล GeoLite2 — แถวที่เป็น NULL จะถูกยกเว้นโดยอัตโนมัติ |
| 3 | Top ASN Organizations by Request Volume | องค์กร ASN อันดับต้น 25 รายการตามปริมาณการเรียก API พร้อมการแยกย่อยเหตุการณ์การเขียนและผู้เรียกที่ไม่ซ้ำกัน (DSH-18) traffic ที่มาจากผู้ให้บริการ VPN, Tor exit node, บริษัท hosting หรือผู้ให้บริการคลาวด์ที่อยู่นอกขอบเขตที่คาดไว้อาจบ่งชี้การใช้โครงสร้างพื้นฐานปกปิดตัวตนของผู้โจมตี ต้องใช้การเติมข้อมูล GeoLite2 — แถวที่เป็น NULL จะถูกยกเว้นโดยอัตโนมัติ |
| 4 | Top Cities by Request Volume | เมืองอันดับต้น 25 รายการตามปริมาณการเรียก API พร้อมการแยกย่อยเหตุการณ์การเขียนและผู้เรียกที่ไม่ซ้ำกัน (DSH-17) รายละเอียดระดับเมืองสามารถเผยตำแหน่ง data center เฉพาะที่ผู้ก่อภัยคุกคามใช้ ซึ่งจะถูกซ่อนไว้หากวิเคราะห์เพียงระดับประเทศ ต้องใช้การเติมข้อมูล GeoLite2 — แถวที่เป็น NULL จะถูกยกเว้นโดยอัตโนมัติ |
| 5 | Global Request Origin Map | แผนที่โลกแสดงการกระจายทางภูมิศาสตร์ของแหล่งที่มาการเรียก API ของ CloudTrail (DSH-16) ความเข้มของสีประเทศเป็นสัดส่วนกับจำนวนเหตุการณ์ ประเทศที่โดยปกติไม่เกี่ยวข้องกับการดำเนินงานขององค์กรอาจบ่งชี้การขโมย credential หรือโครงสร้างพื้นฐานที่ผู้โจมตีควบคุม ต้องใช้การเติมข้อมูล GeoLite2 — แถวที่เป็น NULL จะถูกยกเว้นโดยอัตโนมัติ |
| 6 | API Calls by Country (Event Name × GeoIP) | คู่ (event_name, country) อันดับต้น 50 รายการตามปริมาณการเรียก API (DSH-79) เผยให้เห็นว่าการดำเนินการ API ใดถูกเรียกจากแต่ละภูมิภาคทางภูมิศาสตร์ การดำเนินการเขียนจากประเทศที่ไม่คาดคิดเป็นตัวบ่งชี้ที่ชัดเจนของการถูกบุกรุก credential ต้องใช้การเติมข้อมูล GeoLite2 — IP แบบ private/internal และแถวที่เป็น NULL จะถูกยกเว้น |

</details>

---
