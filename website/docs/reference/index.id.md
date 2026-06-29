# Referensi Kueri & Dashboard Bawaan

> 💡 Tidak memerlukan SQL atau pengetahuan AWS yang mendalam — cukup pilih sebuah perburuan dari menu dropdown dan dapatkan hasilnya secara instan.

## 🎯 Perburuan Bawaan — 100+ kueri

Kategori diurutkan berdasarkan prioritas triase DFIR — periksa terlebih dahulu manipulasi alat deteksi, lalu penyalahgunaan identitas, kemudian dampak terhadap data.

| Kategori | Kueri | Ancaman Utama yang Dicakup |
|----------|:-------:|---------------------|
| 🛡 Detection & Response | 12 | Manipulasi layanan audit (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · penghapusan SCP · penonaktifan alarm · eksfiltrasi log |
| 🔑 Identity & Access | 26 | Penggunaan root · login konsol/MFA · eskalasi hak istimewa · backdoor trust policy · penyalahgunaan PassRole · AssumeRole lintas-akun · SSO/SAML/OIDC · enumerasi kredensial |
| 🪣 Data & Storage | 21 | Penghapusan/unduhan massal S3 · pembacaan massal secrets · manipulasi backup · operasi KMS · berbagi snapshot · eksfiltrasi EBS Direct API · ekspor DynamoDB · replikasi lintas-akun S3 |
| ⚡ Compute & Serverless | 14 | Penghentian/terminasi massal EC2 · pergerakan lateral SSM · manipulasi Lambda/ECS/EKS/ECR · persistensi EventBridge · cryptomining · penyalahgunaan Lightsail |
| 🌐 Network & Infrastructure | 14 | SG terbuka ke internet · penghapusan VPC flow log · pembajakan CloudFront · terowongan VPN/TGW tersembunyi · Elastic IP C2 · kunci API Gateway |
| 🕵 Threat Patterns | 5 | Penulisan di luar jam kerja · ledakan recon · penyebaran multi-region · user agent tidak biasa · panggilan API pertama kali |
| 📊 Activity & Baseline | 3 | Event penulisan konsol · lonjakan error · error terbaru |
| 🌍 GeoIP Analysis ✦ | 12 | Perjalanan mustahil · kredensial multi-negara · login/penolakan/penulisan terurut secara geo · rincian negara/kota/ASN · event_name × country · identity × country |
| ☁ IaC & Platform | 2 | Rantai pasok CI/CD · penyalahgunaan CloudFormation |

<details>
<summary>📋 Daftar lengkap — semua 100+ kueri (klik untuk membuka)</summary>

## Perburuan Bawaan

### 🛡 Detection & Response

| # | Label | Chart | Deskripsi |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | Mendeteksi segala upaya untuk menghentikan atau memodifikasi CloudTrail — indikator penyamaran jejak yang paling kritis |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | Mendeteksi penonaktifan, penghapusan GuardDuty, dan manipulasi threat-intel |
| 3 | ⛔ Security Hub Tampering | timeseries | Mendeteksi penonaktifan Security Hub, penonaktifan standar, dan penekanan temuan |
| 4 | ⚙️ AWS Config Tampering | timeseries | Mendeteksi penghapusan recorder/rule AWS Config (menghilangkan bukti kepatuhan) |
| 5 | 🛡 Organizations SCP Changes | timeseries | Mendeteksi pembuatan, pembaruan, dan penghapusan SCP — menghapus Deny SCP menghilangkan guardrail di seluruh akun dalam OU |
| 6 | 🚫 AWS Macie Tampering | timeseries | Mendeteksi penonaktifan Macie dan pembuatan finding-filter (penghindaran pertahanan pra-eksfiltrasi) |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | Mendeteksi penghapusan alarm dan DisableAlarmActions — membungkam peringatan keamanan tanpa menghapus alarm |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | Mendeteksi pembuatan/penghapusan subscription filter CW Logs (eksfiltrasi log secara real-time ke Kinesis/Lambda penyerang) |
| 9 | 🏹 WAF WebACL Changes | timeseries | Mendeteksi pembuatan, pembaruan, dan penghapusan WAF WebACL di seluruh WAFv2/WAF Classic |
| 10 | 🔍 GuardDuty Findings Read | timeseries | Mendeteksi ListFindings / GetFindings — penyerang membaca temuan aktif untuk memahami apa yang telah dideteksi SOC |
| 11 | 💰 Budget / Cost Anomaly Changes | timeseries | Mendeteksi penghapusan Budget/AnomalyMonitor (menyembunyikan biaya cryptomining) |
| 12 | 🚫 Access Denied Errors | bar | Mengelompokkan error AccessDenied berdasarkan identitas dan API — pelanggar teratas menandakan penyalahgunaan kredensial |

### 🔑 Identity & Access

| # | Label | Chart | Deskripsi |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | Mendeteksi setiap panggilan API yang dilakukan oleh akun root — root tidak boleh pernah digunakan di produksi |
| 2 | 🔓 Console Login without MFA | timeseries | Mendeteksi login konsol di mana MFA tidak digunakan — indikator berisiko tinggi atas kompromi akun |
| 3 | 🌐 Console Logins | timeseries | Mencantumkan semua upaya login konsol termasuk keberhasilan dan kegagalan (deteksi brute force) |
| 4 | 🔐 MFA & Password Changes | timeseries | Mendeteksi penonaktifan MFA dan reset kata sandi — indikator kuat pengambilalihan akun |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | Mendeteksi pelampiran kebijakan IAM dan manipulasi role (PutUserPolicy, AttachRolePolicy, CreatePolicyVersion, dll.) |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | Mendeteksi UpdateAssumeRolePolicy — menambahkan principal eksternal ke trust policy menciptakan backdoor persisten |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | Mendeteksi event put/delete permission boundary — menghapus boundary langsung memperluas izin efektif |
| 8 | 👑 User Added to Admin Group | timeseries | Mendeteksi pengguna yang ditambahkan ke grup dengan kata 'admin' di namanya — eskalasi hak istimewa klasik |
| 9 | 👥 IAM Group Membership Changes | timeseries | Mendeteksi semua event AddUserToGroup / RemoveUserFromGroup / CreateGroup / DeleteGroup terlepas dari nama grup |
| 10 | 👤 New IAM Users / Keys | timeseries | Mengidentifikasi event pembuatan pengguna IAM dan access key — pembuatan yang tak terduga dapat menandakan persistensi |
| 11 | 🎯 IAM PassRole Abuse | timeseries | Mendeteksi penggunaan iam:PassRole dengan memeriksa event layanan penerima (RunInstances, CreateFunction, CreateNotebookInstance, dll.) di mana sebuah ARN role diteruskan |
| 12 | 🔐 AssumeRole Cross-Account | timeseries | Menampilkan event AssumeRole di mana pemanggil dan target berada di akun AWS yang berbeda (pergerakan lateral) |
| 13 | 🏢 Cross-Account Access | timeseries | Menemukan semua event di mana akun pemanggil berbeda dari akun penerima |
| 14 | 🔑 STS Federation Token Issuance | timeseries | Mendeteksi GetFederationToken dan GetSessionToken — mengubah kunci jangka panjang menjadi kredensial sementara yang persisten |
| 15 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | Mendeteksi penyalahgunaan OIDC trust (klaim sub yang salah konfigurasi / GitHub Actions tanpa kondisi repo) |
| 16 | 🆔 IAM Identity Center (SSO) Events | timeseries | Mendeteksi tindakan manajemen AWS IAM Identity Center (CreatePermissionSet, CreateAccountAssignment, dll.) |
| 17 | 🔗 SAML / OIDC Provider Updates | timeseries | Mendeteksi perubahan penyedia identitas SAML/OIDC — memperbarui metadata SAML dengan IdP yang dikendalikan penyerang menciptakan backdoor autentikasi persisten |
| 18 | 🧐 IAM Access Analyzer Calls | timeseries | Mendeteksi penggunaan IAM Access Analyzer apa pun — penyerang memanfaatkan analyzer native untuk menghitung sumber daya yang dapat diakses secara eksternal tanpa skrip recon khusus |
| 19 | 🔄 Credential Report & Enumeration | timeseries | Mendeteksi enumerasi IAM (GenerateCredentialReport, ListUsers, ListRoles, GetAccountAuthorizationDetails, dll.) |
| 20 | 🗝 Access Key Abuse | bar | Mendeteksi access key yang digunakan dari 3+ IP sumber berbeda dalam 7 hari — indikator kuat kebocoran kunci |
| 21 | 📰 AWS Organizations Account Creation | timeseries | Mendeteksi pembuatan akun Organizations dan perubahan administrator yang didelegasikan (persistensi akun bayangan) |
| 22 | 👥 Cognito Unauthenticated Access | timeseries | Mendeteksi Cognito Identity Pools dengan allowUnauthenticatedIdentities=true |
| 23 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | Mendeteksi pembuatan Glue DevEndpoint (iam:PassRole + glue:CreateDevEndpoint = endpoint yang dapat diakses via SSH yang berjalan dengan izin penuh role yang diteruskan) dan enumerasi koneksi untuk panen kredensial |
| 24 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | Mendeteksi pembuatan notebook SageMaker dan pembuatan presigned URL — iam:PassRole + sagemaker:CreateNotebookInstance meluncurkan lingkungan Jupyter dengan izin AWS penuh role yang diteruskan |
| 25 | 🛠 Data Pipeline / CodeStar Privilege Escalation | timeseries | Mendeteksi pembuatan sumber daya Data Pipeline dan CodeStar yang digunakan untuk eskalasi iam:PassRole (CreateProjectFromTemplate membuat role IAM admin sebagai efek samping) |
| 26 | 🧩 Step Functions Privilege Escalation | timeseries | Mendeteksi pembuatan state machine Step Functions (iam:PassRole + states:CreateStateMachine menjalankan tugas Lambda/ECS dengan role yang diteruskan) |

### 🪣 Data & Storage

| # | Label | Chart | Deskripsi |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | Mendeteksi identitas yang melakukan ≥50 panggilan DeleteObject/DeleteObjects per jam — pola penghancuran data ransomware / wiper |
| 2 | 🔥 AWS Backup Tampering | timeseries | Mendeteksi penghapusan Backup Vault / Plan / RecoveryPoint dan penghapusan Vault Lock — langkah pertama ransomware untuk menghilangkan opsi pemulihan |
| 3 | 🔓 KMS Key Operations | timeseries | Menandai operasi KMS sensitif (DisableKey, ScheduleKeyDeletion, CreateGrant, PutKeyPolicy, Decrypt volume tinggi) |
| 4 | 🔓 S3 Public Access Block Disabled | — | Mendeteksi pengaturan public access block S3 yang dinonaktifkan — risiko paparan data langsung |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | Mendeteksi modifikasi kebijakan bucket S3 dan ACL (PutBucketPolicy dengan Principal='*' sangat kritis) |
| 6 | 🪣 S3 Data Access Anomalies | bar | Mendeteksi panggilan GetObject massal (≥100/jam) — pola eksfiltrasi data otomatis |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | Mendeteksi identitas yang mengambil ≥10 secret berbeda dalam satu jam — sinyal panen kredensial |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | Mendeteksi penghapusan secret, PutResourcePolicy (berbagi lintas-akun), dan CancelRotateSecret |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | Mendeteksi identitas yang membaca ≥20 parameter dalam satu jam — saluran eksfiltrasi yang sering terabaikan |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | Mendeteksi snapshot RDS/Aurora yang dibagikan ke akun AWS eksternal (eksfiltrasi database via snapshot) |
| 11 | 💣 RDS Deleted without Final Snapshot | — | Mendeteksi penghapusan RDS dengan skipFinalSnapshot=true — potensi penghancuran data |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | Mendeteksi instance RDS yang dibuat atau dimodifikasi dengan publiclyAccessible=true |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | Mendeteksi ExportTableToPointInTime (ekspor seluruh tabel sisi server yang melewati DLP GetItem), DeleteTable, dan penonaktifan PITR |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | Mendeteksi EBS Direct API (ListSnapshotBlocks / GetSnapshotBlock) — Pacu ebs__download_snapshots melakukan streaming data snapshot mentah tanpa EC2, melewati deteksi ModifySnapshotAttribute |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | Mendeteksi pembuatan/pembaruan delivery stream Firehose yang mengarah ke S3 eksternal — pipeline data real-time yang tak terlihat oleh DLP jaringan |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | Mendeteksi PutBucketReplication — diam-diam menyalin semua objek baru ke bucket yang dikendalikan penyerang tanpa menghasilkan event GetObject tambahan |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | Mendeteksi penangguhan versioning (memungkinkan penghapusan permanen) dan penonaktifan server-access logging (menghapus jejak bukti) |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | Mendeteksi perubahan receipt rule SES dan konfigurasi identitas — forwarding rule meneruskan semua surat masuk ke alamat penyerang; identitas terverifikasi memungkinkan kampanye phishing |
| 19 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | Mendeteksi perubahan kebijakan SQS/SNS yang memberikan akses ke akun eksternal (streaming pesan diam-diam ke endpoint penyerang) |
| 20 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | Mendeteksi snapshot EBS atau AMI yang dibagikan secara publik (group=all) — memungkinkan siapa pun menyalin image disk dan mengekstrak data |
| 21 | 📧 Data Exfiltration Channels | bar | Mendeteksi panggilan PutObject SNS/SQS/SES/S3 volume tinggi (≥50/jam) dari satu identitas |

### ⚡ Compute & Serverless

| # | Label | Chart | Deskripsi |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | Mendeteksi identitas yang melakukan ≥5 StopInstances/TerminateInstances dalam satu jam — indikator ransomware / wiper |
| 2 | 🖥️ SSM Session / Run Command | timeseries | Mendeteksi SSM StartSession, SendCommand, dan StartAutomationExecution — jalur pergerakan lateral utama melalui instance yang dikelola |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | Mendeteksi SendSSHPublicKey dan SendSerialConsoleSSHPublicKey — melewati key pair EC2 (berlaku 60 detik, tidak meninggalkan artefak kunci SSH) |
| 4 | 📝 EC2 User Data Modification | timeseries | Mendeteksi ModifyInstanceAttribute dengan perubahan userData — skrip berjalan sebagai root pada boot berikutnya |
| 5 | ⚡ Lambda Function Tampering | timeseries | Mendeteksi pembuatan Lambda, pembaruan kode (UpdateFunctionCode), dan perubahan izin (AddPermission) |
| 6 | 📦 Lambda Layer Addition | timeseries | Mendeteksi publikasi layer Lambda dan AddLayerVersionPermission dengan principal wildcard (serangan rantai pasok publik) |
| 7 | 📦 ECS Task Definition  | timeseries | Mendeteksi RegisterTaskDefinition / UpdateService — Pacu ecs__backdoor_task_def menyuntikkan container sidecar berbahaya tanpa menyentuh ECR |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | Mendeteksi AssociateIamInstanceProfile / ReplaceIamInstanceProfileAssociation — melampirkan profil yang berhak istimewa yang memungkinkan pergerakan lateral |
| 9 | 🖥 EC2 Instance Launches | timeseries | Mencantumkan semua event RunInstances termasuk tipe instance, jumlah, nama kunci, dan AMI (deteksi cryptomining) |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | Mendeteksi permintaan Spot Fleet besar (ec2) dan pembuatan grup Auto Scaling dengan kapasitas tinggi (autoscaling) — indikator dampak finansial cryptomining |
| 11 | ☸️ EKS Cluster API Calls | timeseries | Mendeteksi modifikasi control-plane cluster EKS (paparan API server publik, profil Fargate jahat) |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | Mendeteksi event repository/image ECR (PutImage dengan tag 'latest' meracuni semua deployment berikutnya) |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | Mendeteksi modifikasi rule EventBridge dan Scheduler (PutRule, CreateSchedule) — membangun persistensi tanpa proses yang berjalan |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | Mendeteksi pengambilan kunci Lightsail, paparan port, dan akses instance — Pacu lightsail__download_ssh_keys / lightsail__generate_temp_access |

### 🌐 Network & Infrastructure

| # | Label | Chart | Deskripsi |
|---|-------|:-----:|-------------|
| 1 | 🌍 Security Group Opened to Internet | timeseries | Menemukan rule security group yang mengizinkan lalu lintas dari 0.0.0.0/0 — risiko paparan publik langsung |
| 2 | 🔥 Security Group Modifications | timeseries | Mendeteksi semua perubahan rule security group (AuthorizeSecurityGroupIngress, ModifySecurityGroupRules, dll.) |
| 3 | 🌊 VPC Flow Log Changes | timeseries | Mendeteksi penghapusan VPC Flow Log — menghapus flow log menghilangkan bukti forensik jaringan utama |
| 4 | 🌐 CloudFront Distribution Tampering | timeseries | Mendeteksi perubahan origin CloudFront yang mengarahkan semua lalu lintas CDN ke server yang dikendalikan penyerang (MitM) |
| 5 | 🛡 Network Firewall / Shield Tampering | timeseries | Mendeteksi penghapusan proteksi Network Firewall dan Shield — memaparkan seluruh rentang subnet ke lalu lintas serangan |
| 6 | 🧱 Network ACL Changes | timeseries | Mendeteksi pembuatan, penghapusan, dan penggantian entri NACL — NACL menimpa security group di tingkat subnet |
| 7 | 🛣️ Route Table Changes | timeseries | Mendeteksi modifikasi route table — penyerang mengarahkan lalu lintas ke gateway berbahaya untuk intersepsi atau C2 |
| 8 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | Mendeteksi koneksi VPN baru dan attachment Transit Gateway — menciptakan jalur jaringan Layer-3 persisten untuk C2 atau eksfiltrasi |
| 9 | 📡 Elastic IP Allocation / Association | timeseries | Mendeteksi alokasi/asosiasi Elastic IP — menetapkan IP publik tetap ke instance yang terkompromi untuk infrastruktur C2 yang stabil |
| 10 | 🗝️ EC2 Key Pair Creation | timeseries | Mendeteksi CreateKeyPair dan ImportKeyPair — penyerang membuat kunci SSH untuk akses instance persisten |
| 11 | 📡 Network Infrastructure Changes | timeseries | Mendeteksi perubahan VPC / subnet / IGW / NAT Gateway / peering yang dapat membangun infrastruktur yang dikendalikan penyerang |
| 12 | 🏷 ACM Certificate Operations | timeseries | Mendeteksi permintaan dan penghapusan sertifikat ACM — akun yang terkompromi dapat menerbitkan sertifikat TLS untuk domain phishing |
| 13 | 🔑 API Gateway Key Creation & Management | timeseries | Mendeteksi pembuatan kunci API Gateway dan perubahan authorizer — Pacu api_gateway__create_api_keys menghasilkan kredensial persisten yang bertahan dari rotasi kunci IAM |
| 14 | 🚧 VPC Endpoint Access Denied | timeseries | Mendeteksi error access denied via VPC endpoint — dapat menandakan kebijakan endpoint yang salah konfigurasi |

### 🕵 Threat Patterns

| # | Label | Chart | Deskripsi |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | Mengidentifikasi pemanggil yang menjalankan 10+ API Describe*/List*/Get* berbeda dalam satu jam — fase awal serangan yang umum |
| 2 | 🤖 Unusual User Agents | bar | Mencantumkan user agent langka (<5 event) atau alat penyerang yang dikenal (Pacu, curl, wget) — dapat menandakan tooling serangan |
| 3 | 🌍 Multi-Region Activity | bar | Mendeteksi identitas yang melakukan penulisan di 3+ region dalam satu hari — penyebaran geografis dapat menandakan kompromi |
| 4 | 🕵 First-Time API Calls (24h) | — | Menemukan panggilan API yang terlihat dalam 24 jam terakhir tetapi tidak pernah sebelumnya — operasi baru dapat menandakan tooling penyerang |

### 📊 Activity & Baseline

| # | Label | Chart | Deskripsi |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | Mengidentifikasi panggilan API mutasi yang dilakukan via konsol AWS — berguna saat akses hanya-CLI diharapkan |
| 2 | 🔍 Events with Errors (24h) | timeseries | Mencantumkan semua event error dalam 24 jam terakhir — gambaran cepat tentang apa yang gagal atau sedang diuji |
| 3 | ❌ Error Spike Detection | — | Menemukan jendela 1 jam di mana jumlah error melebihi rata-rata harian sebesar 3× |

### 🌍 GeoIP Analysis

> Memerlukan file GeoLite2 `.mmdb` untuk pengisian (kolom bernilai NULL jika diingesti tanpa GeoIP).

| # | Label | Chart | Deskripsi |
|---|-------|:-----:|-------------|
| 1 | 🕵 Impossible Travel Detection | — | Mendeteksi identitas yang sama memanggil API dari kota yang berjauhan dalam 2 jam — indikator kuat kompromi kredensial |
| 2 | ⚠ Identity Multi-Country Access | bar | Menemukan identitas yang melakukan panggilan API dari 2+ negara — pengguna sah jarang beroperasi dari beberapa negara secara bersamaan |
| 3 | 🗺 Console Logins by Country | timeseries | Memetakan event login konsol ke asal geografisnya — login dari negara yang tak terduga berisiko tinggi |
| 4 | 🚨 Unusual Country Access | bar | Mendeteksi kombinasi negara/identitas yang langka (<10 event) — akses asing volume rendah dapat berupa infrastruktur penyerang |
| 5 | 🚫 Access Denied by Country | bar | Mengelompokkan error access denied berdasarkan negara sumber — penolakan terkonsentrasi dari satu negara dapat menandakan serangan |
| 6 | 🔍 Write Events by Country | bar | Menampilkan panggilan API mutasi yang dikelompokkan berdasarkan negara sumber — penulisan dari negara tak terduga merupakan sinyal yang lebih kuat daripada pembacaan |
| 7 | 🌍 Top Source Countries | bar | Mengurutkan negara sumber berdasarkan volume panggilan API dengan rincian event penulisan dan identitas unik |
| 8 | 🏢 Top ASN / Organizations | bar | Mencantumkan autonomous system (ISP/penyedia cloud) berdasarkan volume panggilan API — ASN VPN/hosting dapat menandakan infrastruktur penyerang |
| 9 | 📍 Top Source Cities | bar | Mengurutkan kota sumber berdasarkan volume event — data tingkat kota menunjukkan secara tepat infrastruktur penyerang atau lokasi kantor tertentu |
| 10 | 🌐 Private / Internal IP Summary | bar | Merangkum event dari IP privat/loopback/internal-AWS — baseline untuk lalu lintas internal yang diharapkan |
| 11 | 📋 API Calls by Country (Event Name) | table | Pasangan (event_name, country) teratas berdasarkan volume panggilan — mengungkapkan operasi API mana yang berasal dari wilayah geografis tak terduga |
| 12 | 👤 Identities by Country (user_identity_arn) | table | Pasangan (user_identity_arn, country) teratas berdasarkan volume panggilan — memunculkan identitas IAM yang aktif dari negara tak terduga dengan first/last seen |

### ☁ IaC & Platform

| # | Label | Chart | Deskripsi |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | Mendeteksi pembuatan dan modifikasi pipeline CI/CD (UpdateProject menyuntikkan langkah build berbahaya ke setiap build berikutnya) |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | Mendeteksi operasi stack CloudFormation — penyerang dapat menggunakan IaC untuk dengan cepat menerapkan infrastruktur berbahaya |

</details>

---

## 📊 Chart Dashboard — 80+ chart

| Tab | Charts | Apa yang Ditampilkan |
|-----|:------:|---------------|
| 🔑 Identity & Access | 9 | Login konsol · tren MFA · heatmap login · API sensitif · penggunaan root · aktivitas entitas IAM · eskalasi hak istimewa · SSO/privesc |
| 🎯 Threat Detection | 12 | Volume event · rasio baca/tulis · penghindaran pertahanan · access denied · tren error · manipulasi SCP/Config/NACL/EventBridge |
| 📊 API Activity | 7 | API teratas · distribusi region · IP sumber · user agent · anomali secrets · AssumeRole eksternal · perubahan Route53 |
| 🖥️ Computing | 5 | Eksekusi SSM · snapshot publik EC2 · event EKS/ECR · backdoor ECS · eksfiltrasi EBS Direct API |
| 🪣 S3 & RDS | 9 | Kebijakan/ACL S3 · unduhan/penghapusan massal · versioning/logging dinonaktifkan · replikasi lintas-akun · berbagi snapshot RDS · manipulasi Backup |
| 🌍 GeoIP Intelligence | 6 | Peta dunia · negara / kota / ASN teratas berdasarkan volume permintaan · event_name × country · identity × country |
| 🕒 Temporal Analysis | 6 | First/last seen berdasarkan identitas/IP/API/agent · akun dorman yang diaktifkan kembali · lonjakan velositas |
| 🚨 High-Risk API Monitor | 7 | Time series HRM · panggilan/aktor/IP teratas · detail penghindaran pertahanan/akses kredensial · berdasarkan region |

<details>
<summary>📋 Daftar lengkap — semua 80+ chart (klik untuk membuka)</summary>

## Chart Dashboard (Apache Superset — `dashboard/`)

### 🔑 Identity & Access

| # | Chart Name | Deskripsi |
|---|------------|-------------|
| 1 | Console Login Activity | Event sign-in konsol yang dikelompokkan berdasarkan identitas IAM (DSH-08) |
| 2 | MFA-less Login Trend | Login konsol harian yang dipisahkan berdasarkan penggunaan MFA (DSH-28) |
| 3 | Login Activity Heatmap (Hour × Day) | Jumlah login konsol berdasarkan hari dalam minggu dan jam dalam hari di JST (DSH-19) |
| 4 | Sensitive API Calls | Invokasi tindakan API AWS yang dikenal sensitif terhadap keamanan (DSH-12) |
| 5 | Root Account Usage | Semua panggilan API yang dilakukan oleh akun Root AWS (DSH-13) |
| 6 | IAM Entity Activity | 50 entitas IAM teratas yang diurutkan berdasarkan total panggilan API, dengan rasio penulisan dan tingkat error |
| 7 | Privilege Escalation Timeline | Jumlah harian panggilan API eskalasi hak istimewa berdasarkan nama event (DSH-30) |
| 8 | IAM Identity Center (SSO) Events | Event manajemen AWS IAM Identity Center dari sso.amazonaws.com (DSH-44) |
| 9 | Glue & SageMaker Privilege Escalation | Event Glue DevEndpoint dan SageMaker Notebook yang digunakan untuk eskalasi hak istimewa IAM via iam:PassRole (DSH-50) |

### 🎯 Threat Detection

| # | Chart Name | Deskripsi |
|---|------------|-------------|
| 1 | CloudTrail Events Over Time | Volume event Read vs Write per jam dari waktu ke waktu (DSH-01) |
| 2 | Write/Read Ratio Trend | Rincian per jam panggilan API baca vs tulis (DSH-20) |
| 3 | Throttling Exception Spikes | Error throttling/rate-limit per jam berdasarkan layanan AWS (DSH-21) |
| 4 | Defense Evasion Events | Semua event CloudTrail yang cocok dengan teknik penghindaran pertahanan yang dikenal (DSH-22) |
| 5 | Top Access Denied Actions | 20 tindakan API teratas yang mengembalikan error AccessDenied (DSH-09) |
| 6 | Error Event Trend | Event error per jam yang dirinci berdasarkan error_code (DSH-04) |
| 7 | Organizations / SCP Changes | Event manajemen AWS Organizations termasuk perubahan kebijakan SCP (DSH-24) |
| 8 | First-Time Service Sources | Semua sumber layanan AWS berbeda yang diurutkan berdasarkan tanggal kemunculan pertama (DSH-26) |
| 9 | VPC Flow Log Changes | Event pembuatan dan penghapusan VPC Flow Log (DSH-42) |
| 10 | AWS Config Tampering | Event manipulasi recorder dan rule AWS Config (DSH-43) |
| 11 | Network ACL / Route Table Changes | Event modifikasi NACL dan route table (DSH-46) |
| 12 | EventBridge / CloudWatch Rule Tampering | Manipulasi rule EventBridge dan CloudWatch Events (DSH-47) |

### 📊 API Activity

| # | Chart Name | Deskripsi |
|---|------------|-------------|
| 1 | Top 20 API Calls | 20 tindakan API AWS yang paling sering dipanggil (DSH-02) |
| 2 | Region Activity | Distribusi event CloudTrail di seluruh region AWS (DSH-14) |
| 3 | Top Source IP Addresses | 100 IP sumber eksternal teratas berdasarkan jumlah permintaan (DSH-05) |
| 4 | User Agent Analysis | 50 user agent teratas berdasarkan jumlah permintaan dengan rincian error dan penulisan (DSH-11) |
| 5 | Secrets Access Anomaly | Identitas yang mengakses Secrets Manager atau SSM Parameter Store ≥10 kali dalam satu jam |
| 6 | AssumedRole from External IP | Panggilan AssumeRole dari alamat IP publik (non-privat) (DSH-27) |
| 7 | Route53 DNS Changes | Perubahan konfigurasi hosted-zone dan resolver Route 53 (DSH-29) |

### 🖥️ Computing

| # | Chart Name | Deskripsi |
|---|------------|-------------|
| 1 | SSM Session / Run Command Execution | Event eksekusi jarak jauh AWS Systems Manager (DSH-39) |
| 2 | EC2 Public Snapshot / AMI Sharing | Event berbagi publik snapshot EBS dan AMI (DSH-41) |
| 3 | EKS / ECR Container Platform Events | Event cluster EKS dan registry container ECR (DSH-48) |
| 4 | ECS Task Definition | Event registrasi task definition ECS dan pembaruan service — pola Pacu ecs__backdoor_task_def (DSH-49) |
| 5 | EBS Direct API Snapshot Exfiltration | Panggilan EBS Direct API (ListSnapshotBlocks / GetSnapshotBlock) yang digunakan untuk streaming data snapshot tanpa EC2 (DSH-51) |

### 🪣 S3 & RDS

| # | Chart Name | Deskripsi |
|---|------------|-------------|
| 1 | S3 Protection Config Changes | Event S3 yang melemahkan postur keamanan bucket (DSH-25) |
| 2 | S3 Bucket Policy / ACL Changes | Event modifikasi kebijakan bucket S3 dan ACL (DSH-45) |
| 3 | RDS Snapshot Cross-Account Share | Event berbagi snapshot RDS dan Aurora (DSH-40) |
| 4 | S3 Bulk Download | Identitas yang melakukan ≥100 panggilan GetObject per jam — pola eksfiltrasi data otomatis (DSH-52) |
| 5 | S3 Bulk Object Deletion | Identitas yang melakukan ≥50 panggilan DeleteObject/DeleteObjects per jam — pola penghancuran data ransomware (DSH-53) |
| 6 | S3 Versioning / Logging Disabled | PutBucketVersioning (Suspended) dan PutBucketLogging (disabled) — prekursor anti-forensik untuk penghancuran data (DSH-54) |
| 7 | S3 Cross-Account Replication | PutBucketReplication / DeleteBucketReplication — saluran eksfiltrasi diam-diam persisten ke akun yang dikendalikan penyerang (DSH-55) |
| 8 | RDS Deleted without Final Snapshot | DeleteDBInstance / DeleteDBCluster dengan skipFinalSnapshot=true — penghancuran data yang tak dapat dipulihkan (DSH-56) |
| 9 | AWS Backup Tampering | Penghapusan Backup Vault / Plan / RecoveryPoint dan penghapusan Vault Lock — langkah pertama ransomware untuk menghilangkan opsi pemulihan (DSH-57) |

### 🌍 GeoIP Intelligence

> Memerlukan file GeoLite2 `.mmdb`. Kolom GeoIP bernilai NULL jika diingesti tanpa GeoIP.

| # | Chart Name | Deskripsi |
|---|------------|-------------|
| 1 | Global Request Origin Map | Peta dunia yang menampilkan distribusi geografis asal panggilan API CloudTrail |
| 2 | Top Countries by Request Volume | 20 negara sumber teratas berdasarkan volume panggilan API dengan rincian event penulisan dan pemanggil unik |
| 3 | Top Cities by Request Volume | 25 kota teratas berdasarkan volume panggilan API dengan rincian event penulisan dan pemanggil unik |
| 4 | Top ASN Organizations by Request Volume | 25 organisasi ASN teratas berdasarkan volume panggilan API |
| 5 | API Calls by Country (Event Name × GeoIP) | 50 pasangan (event_name, country) teratas — mengungkapkan operasi API mana yang dipanggil dari setiap wilayah geografis (DSH-79) |
| 6 | Identities by Country (user_identity_arn × GeoIP) | 50 pasangan (user_identity_arn, country) teratas — memunculkan identitas IAM yang aktif dari negara tak terduga dengan jumlah penulisan dan first/last seen (DSH-80) |

### 🕒 Temporal Analysis

| # | Chart Name | Deskripsi |
|---|------------|-------------|
| 1 | First / Last Seen per IAM Identity | Identitas IAM dengan timestamp first/last seen, jumlah event, dan API berbeda |
| 2 | First / Last Seen per Source IP | IP sumber dengan first/last seen, identitas berbeda, dan API berbeda |
| 3 | First / Last Seen per API Call | Tindakan API yang diurutkan berdasarkan kemunculan pertama — panggilan baru dapat menandakan tooling serangan baru (DSH-33) |
| 4 | First / Last Seen per User Agent | User agent yang diurutkan berdasarkan kemunculan pertama — deteksi tooling baru (DSH-34) |
| 5 | Dormant Accounts Reactivated | Identitas dengan jeda ketidakaktifan 72+ jam yang melanjutkan aktivitas (DSH-37) |
| 6 | Event Velocity Spikes per Identity | Identitas dengan aktivitas ledakan 50+ event per jam (DSH-38) |

### 🚨 High-Risk API Monitor (HRM)

| # | Chart Name | Deskripsi |
|---|------------|-------------|
| 1 | High-Risk API Events Over Time | Volume panggilan harian untuk API yang umum diamati dalam kampanye serangan (HRM-39) |
| 2 | Top High-Risk API Calls | Tindakan API dari watchlist berisiko tinggi yang diurutkan berdasarkan total jumlah panggilan (HRM-40) |
| 3 | Top Actors — High-Risk APIs | Principal IAM yang diurutkan berdasarkan total panggilan ke API watchlist berisiko tinggi (HRM-42) |
| 4 | Top Source IPs — High-Risk APIs | IP sumber yang diurutkan berdasarkan total panggilan ke API watchlist berisiko tinggi (HRM-43) |
| 5 | Defense Evasion API Events | Log event terperinci untuk API yang digunakan untuk menonaktifkan atau memanipulasi kontrol audit (HRM-44) |
| 6 | Credential Access API Events | Log event terperinci untuk API yang digunakan untuk mengambil secret dan kredensial (HRM-45) |
| 7 | High-Risk API Calls by Region | Panggilan API watchlist berisiko tinggi yang didistribusikan berdasarkan region AWS (HRM-46) |

</details>

---
