# Yerleşik Sorgu ve Pano Referansı

> 💡 SQL veya derin AWS bilgisi gerekmez — açılır menüden bir av seçin ve sonuçları anında alın.

## 🎯 Yerleşik Avlar — 100'den fazla sorgu

Kategoriler DFIR triyaj önceliğine göre sıralanmıştır — önce tespit aracı kurcalamasını, ardından kimlik istismarını, sonra veri etkisini kontrol edin.

| Kategori | Sorgular | Kapsanan Başlıca Tehditler |
|----------|:-------:|---------------------|
| 🛡 Tespit ve Müdahale | 12 | Denetim hizmeti kurcalaması (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · SCP silme · alarm bastırma · log sızdırma |
| 🔑 Kimlik ve Erişim | 26 | Root kullanımı · konsol oturum açma/MFA · ayrıcalık yükseltme · güven politikası arka kapısı · PassRole istismarı · hesaplar arası AssumeRole · SSO/SAML/OIDC · kimlik bilgisi numaralandırma |
| 🪣 Veri ve Depolama | 21 | S3 toplu silme/indirme · gizli bilgilerin toplu okunması · yedek kurcalama · KMS işlemleri · anlık görüntü paylaşımı · EBS Direct API sızdırma · DynamoDB dışa aktarma · S3 hesaplar arası çoğaltma |
| ⚡ Bilişim ve Sunucusuz | 14 | EC2 toplu durdurma/sonlandırma · SSM yanal hareket · Lambda/ECS/EKS/ECR kurcalama · EventBridge kalıcılığı · kripto madenciliği · Lightsail istismarı |
| 🌐 Ağ ve Altyapı | 14 | SG'nin internete açılması · VPC akış logu silme · CloudFront ele geçirme · gizli VPN/TGW tünelleri · Elastic IP C2 · API Gateway anahtarları |
| 🕵 Tehdit Kalıpları | 5 | Mesai dışı yazma işlemleri · keşif patlaması · çok bölgeli yayılma · olağandışı kullanıcı aracıları · ilk kez yapılan API çağrıları |
| 📊 Etkinlik ve Temel Çizgi | 3 | Konsol yazma olayları · hata sıçramaları · son hatalar |
| 🌍 GeoIP Analizi ✦ | 12 | İmkânsız seyahat · çok ülkeli kimlik bilgileri · coğrafi sıralı oturum açmalar/redler/yazmalar · ülke/şehir/ASN dökümü · event_name × ülke · kimlik × ülke |
| ☁ IaC ve Platform | 2 | CI/CD tedarik zinciri · CloudFormation istismarı |

<details>
<summary>📋 Tam liste — 100'den fazla sorgunun tamamı (genişletmek için tıklayın)</summary>

## Yerleşik Avlar

### 🛡 Tespit ve Müdahale

| # | Etiket | Grafik | Açıklama |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Kurcalaması | timeseries | CloudTrail'i durdurma veya değiştirme girişimlerini tespit eder — en kritik örtbas göstergesi |
| 2 | 🛡️ GuardDuty Dedektör Kurcalaması | timeseries | GuardDuty devre dışı bırakma, silme ve tehdit istihbaratı manipülasyonunu tespit eder |
| 3 | ⛔ Security Hub Kurcalaması | timeseries | Security Hub devre dışı bırakma, standart devre dışı bırakma ve bulgu bastırmayı tespit eder |
| 4 | ⚙️ AWS Config Kurcalaması | timeseries | AWS Config kaydedici/kural silmeyi tespit eder (uyumluluk kanıtlarını ortadan kaldırır) |
| 5 | 🛡 Organizations SCP Değişiklikleri | timeseries | SCP oluşturma, güncelleme ve silmeyi tespit eder — bir Deny SCP'sinin kaldırılması, OU'daki her hesaptaki korkulukları ortadan kaldırır |
| 6 | 🚫 AWS Macie Kurcalaması | timeseries | Macie devre dışı bırakma ve bulgu filtresi oluşturmayı tespit eder (sızdırma öncesi savunma atlatma) |
| 7 | 🚨 CloudWatch Alarm Silme / Devre Dışı Bırakma | timeseries | Alarm silme ve DisableAlarmActions işlemlerini tespit eder — alarmı silmeden güvenlik uyarılarını susturur |
| 8 | 📜 CloudWatch Logs Abonelik Değişiklikleri | timeseries | CW Logs abonelik filtresi oluşturma/silmeyi tespit eder (saldırgan Kinesis/Lambda'ya gerçek zamanlı log sızdırma) |
| 9 | 🏹 WAF WebACL Değişiklikleri | timeseries | WAFv2/WAF Classic genelinde WAF WebACL oluşturma, güncelleme ve silmeyi tespit eder |
| 10 | 🔍 GuardDuty Bulgularının Okunması | timeseries | ListFindings / GetFindings işlemlerini tespit eder — saldırgan, SOC'nin neyi zaten tespit ettiğini anlamak için aktif bulguları okur |
| 11 | 💰 Bütçe / Maliyet Anomalisi Değişiklikleri | timeseries | Budget/AnomalyMonitor silmeyi tespit eder (kripto madenciliği maliyetlerini gizleme) |
| 12 | 🚫 Erişim Reddedildi Hataları | bar | AccessDenied hatalarını kimliğe ve API'ye göre gruplar — en çok ihlal yapanlar kimlik bilgisi kötüye kullanımına işaret eder |

### 🔑 Kimlik ve Erişim

| # | Etiket | Grafik | Açıklama |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Hesap Etkinliği | timeseries | Root hesabı tarafından yapılan herhangi bir API çağrısını tespit eder — root, üretimde asla kullanılmamalıdır |
| 2 | 🔓 MFA'sız Konsol Oturum Açma | timeseries | MFA kullanılmayan konsol oturum açmalarını tespit eder — hesap ele geçirilmesinin yüksek riskli göstergesi |
| 3 | 🌐 Konsol Oturum Açmaları | timeseries | Başarılı ve başarısız tüm konsol oturum açma denemelerini listeler (kaba kuvvet tespiti) |
| 4 | 🔐 MFA ve Parola Değişiklikleri | timeseries | MFA devre dışı bırakma ve parola sıfırlamalarını tespit eder — hesap ele geçirilmesinin güçlü göstergesi |
| 5 | 🔄 Ayrıcalık Yükseltme (IAM) | timeseries | IAM politika ekleme ve rol manipülasyonunu tespit eder (PutUserPolicy, AttachRolePolicy, CreatePolicyVersion vb.) |
| 6 | 🔄 IAM Rol Güven Politikası Değişiklikleri | timeseries | UpdateAssumeRolePolicy işlemini tespit eder — bir güven politikasına harici principal eklemek kalıcı bir arka kapı oluşturur |
| 7 | 🚧 IAM İzin Sınırı Değişiklikleri | timeseries | İzin sınırı put/delete olaylarını tespit eder — bir sınırın kaldırılması etkin izinleri anında genişletir |
| 8 | 👑 Admin Grubuna Eklenen Kullanıcı | timeseries | Adında 'admin' bulunan gruplara eklenen kullanıcıları tespit eder — klasik ayrıcalık yükseltme |
| 9 | 👥 IAM Grup Üyeliği Değişiklikleri | timeseries | Grup adından bağımsız olarak tüm AddUserToGroup / RemoveUserFromGroup / CreateGroup / DeleteGroup olaylarını tespit eder |
| 10 | 👤 Yeni IAM Kullanıcıları / Anahtarları | timeseries | IAM kullanıcı ve erişim anahtarı oluşturma olaylarını tanımlar — beklenmedik oluşturma kalıcılığa işaret edebilir |
| 11 | 🎯 IAM PassRole İstismarı | timeseries | Bir rol ARN'sinin geçirildiği alıcı hizmet olaylarını (RunInstances, CreateFunction, CreateNotebookInstance vb.) inceleyerek iam:PassRole kullanımını tespit eder |
| 12 | 🔐 AssumeRole Hesaplar Arası | timeseries | Çağıranın ve hedefin farklı AWS hesaplarında olduğu AssumeRole olaylarını gösterir (yanal hareket) |
| 13 | 🏢 Hesaplar Arası Erişim | timeseries | Çağıran hesabın alıcı hesaptan farklı olduğu tüm olayları bulur |
| 14 | 🔑 STS Federasyon Token Verilmesi | timeseries | GetFederationToken ve GetSessionToken işlemlerini tespit eder — uzun ömürlü anahtarları kalıcı geçici kimlik bilgilerine dönüştürür |
| 15 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | OIDC güven istismarını tespit eder (yanlış yapılandırılmış sub talebi / repo koşulu olmayan GitHub Actions) |
| 16 | 🆔 IAM Identity Center (SSO) Olayları | timeseries | AWS IAM Identity Center yönetim işlemlerini tespit eder (CreatePermissionSet, CreateAccountAssignment vb.) |
| 17 | 🔗 SAML / OIDC Sağlayıcı Güncellemeleri | timeseries | SAML/OIDC kimlik sağlayıcı değişikliklerini tespit eder — SAML meta verisini saldırgan kontrolündeki IdP ile güncellemek kalıcı bir kimlik doğrulama arka kapısı oluşturur |
| 18 | 🧐 IAM Access Analyzer Çağrıları | timeseries | IAM Access Analyzer'ın herhangi bir kullanımını tespit eder — saldırganlar, özel keşif betikleri olmadan harici erişilebilir kaynakları numaralandırmak için yerel analizörden yararlanır |
| 19 | 🔄 Kimlik Bilgisi Raporu ve Numaralandırma | timeseries | IAM numaralandırmasını tespit eder (GenerateCredentialReport, ListUsers, ListRoles, GetAccountAuthorizationDetails vb.) |
| 20 | 🗝 Erişim Anahtarı İstismarı | bar | 7 gün içinde 3 veya daha fazla farklı kaynak IP'den kullanılan erişim anahtarlarını tespit eder — anahtar sızıntısının güçlü göstergesi |
| 21 | 📰 AWS Organizations Hesap Oluşturma | timeseries | Organizations hesap oluşturma ve delege edilmiş yönetici değişikliklerini tespit eder (gölge hesap kalıcılığı) |
| 22 | 👥 Cognito Kimlik Doğrulamasız Erişim | timeseries | allowUnauthenticatedIdentities=true olan Cognito Identity Pools'u tespit eder |
| 23 | 🧪 Glue DevEndpoint Ayrıcalık Yükseltme | timeseries | Glue DevEndpoint oluşturmayı (iam:PassRole + glue:CreateDevEndpoint = geçirilen rolün tüm izinleriyle çalışan SSH erişilebilir uç nokta) ve kimlik bilgisi toplamak için bağlantı numaralandırmasını tespit eder |
| 24 | 🧪 SageMaker Notebook Ayrıcalık Yükseltme | timeseries | SageMaker notebook oluşturma ve önceden imzalanmış URL üretimini tespit eder — iam:PassRole + sagemaker:CreateNotebookInstance, geçirilen rolün tüm AWS izinleriyle bir Jupyter ortamı başlatır |
| 25 | 🛠 Data Pipeline / CodeStar Ayrıcalık Yükseltme | timeseries | iam:PassRole yükseltmesi için kullanılan Data Pipeline ve CodeStar kaynak oluşturmayı tespit eder (CreateProjectFromTemplate yan etki olarak bir admin IAM rolü oluşturur) |
| 26 | 🧩 Step Functions Ayrıcalık Yükseltme | timeseries | Step Functions durum makinesi oluşturmayı tespit eder (iam:PassRole + states:CreateStateMachine, geçirilen rol altında Lambda/ECS görevlerini çalıştırır) |

### 🪣 Veri ve Depolama

| # | Etiket | Grafik | Açıklama |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Toplu Nesne Silme | bar | Saatte ≥50 DeleteObject/DeleteObjects çağrısı yapan kimlikleri tespit eder — fidye yazılımı / silici veri imha kalıbı |
| 2 | 🔥 AWS Backup Kurcalaması | timeseries | Backup Vault / Plan / RecoveryPoint silme ve Vault Lock kaldırmayı tespit eder — fidye yazılımının kurtarma seçeneklerini ortadan kaldırmak için attığı ilk adım |
| 3 | 🔓 KMS Anahtar İşlemleri | timeseries | Hassas KMS işlemlerini işaretler (DisableKey, ScheduleKeyDeletion, CreateGrant, PutKeyPolicy, yüksek hacimli Decrypt) |
| 4 | 🔓 S3 Genel Erişim Engelinin Devre Dışı Bırakılması | — | S3 genel erişim engeli ayarlarının devre dışı bırakılmasını tespit eder — anında veri açığa çıkması riski |
| 5 | 🪣 S3 Bucket Politikası / ACL Değişiklikleri | timeseries | S3 bucket politikası ve ACL değişikliklerini tespit eder (Principal='*' içeren PutBucketPolicy özellikle kritiktir) |
| 6 | 🪣 S3 Veri Erişim Anomalileri | bar | Toplu GetObject çağrılarını (≥100/saat) tespit eder — otomatik veri sızdırma kalıbı |
| 7 | 🔐 Secrets Manager Toplu GetSecretValue | bar | Bir saat içinde ≥10 farklı gizli bilgiyi alan kimlikleri tespit eder — kimlik bilgisi toplama sinyali |
| 8 | 🗝 Secrets Manager Silme ve Hesaplar Arası Politika | timeseries | Gizli bilgi silme, PutResourcePolicy (hesaplar arası paylaşım) ve CancelRotateSecret işlemlerini tespit eder |
| 9 | 🔐 SSM Parameter Store Toplu Okuma | bar | Bir saat içinde ≥20 parametre okuyan kimlikleri tespit eder — sıklıkla göz ardı edilen bir sızdırma kanalı |
| 10 | 💾 RDS Anlık Görüntü Hesaplar Arası Paylaşım | timeseries | Harici AWS hesaplarıyla paylaşılan RDS/Aurora anlık görüntülerini tespit eder (anlık görüntü yoluyla veritabanı sızdırma) |
| 11 | 💣 Son Anlık Görüntü Olmadan Silinen RDS | — | skipFinalSnapshot=true ile RDS silmeyi tespit eder — olası veri imhası |
| 12 | 💽 RDS Genel Erişilebilirlik Etkin | timeseries | publiclyAccessible=true ile oluşturulan veya değiştirilen RDS örneklerini tespit eder |
| 13 | 🗄 DynamoDB Dışa Aktarma / Toplu Sızdırma | timeseries | ExportTableToPointInTime (GetItem DLP'sini atlayan sunucu tarafı tam tablo dışa aktarma), DeleteTable ve PITR devre dışı bırakmayı tespit eder |
| 14 | 💾 EBS Direct API Anlık Görüntü Sızdırma | timeseries | EBS Direct API'yi (ListSnapshotBlocks / GetSnapshotBlock) tespit eder — Pacu ebs__download_snapshots, EC2 olmadan ham anlık görüntü verisini akış olarak gönderir ve ModifySnapshotAttribute tespitini atlar |
| 15 | 🌊 Kinesis Firehose / Stream Sızdırma Kanalı | timeseries | Harici S3'e işaret eden Firehose teslim akışı oluşturma/güncellemeyi tespit eder — ağ DLP'sine görünmeyen gerçek zamanlı veri hattı |
| 16 | 🔁 S3 Hesaplar Arası Çoğaltma | timeseries | PutBucketReplication işlemini tespit eder — ek GetObject olayları oluşturmadan tüm yeni nesneleri saldırgan kontrolündeki bucket'a sessizce kopyalar |
| 17 | 📂 S3 Sürüm Oluşturma / Loglama Devre Dışı | timeseries | Sürüm oluşturmanın askıya alınmasını (kalıcı silmeyi etkinleştirir) ve sunucu erişim loglamasının devre dışı bırakılmasını (kanıt izini kaldırır) tespit eder |
| 18 | 📧 SES Kimlik ve Yönlendirme Yapılandırma Değişiklikleri | timeseries | SES alım kuralı ve kimlik yapılandırma değişikliklerini tespit eder — yönlendirme kuralları tüm gelen postayı saldırgan adreslerine iletir; doğrulanmış kimlikler kimlik avı kampanyalarını mümkün kılar |
| 19 | 📡 SQS / SNS Hesaplar Arası Politika Değişiklikleri | timeseries | Harici hesaplara erişim veren SQS/SNS politika değişikliklerini tespit eder (saldırgan uç noktalarına sessiz mesaj akışı) |
| 20 | 📸 EC2 Genel Anlık Görüntü / AMI Paylaşımı | timeseries | Herkese açık paylaşılan EBS anlık görüntülerini veya AMI'leri (group=all) tespit eder — herkesin disk görüntülerini kopyalayıp veri çıkarmasına izin verir |
| 21 | 📧 Veri Sızdırma Kanalları | bar | Tek bir kimlikten yüksek hacimli SNS/SQS/SES/S3 PutObject çağrılarını (≥50/saat) tespit eder |

### ⚡ Bilişim ve Sunucusuz

| # | Etiket | Grafik | Açıklama |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Toplu Durdurma / Sonlandırma | timeseries | Bir saat içinde ≥5 StopInstances/TerminateInstances yapan kimlikleri tespit eder — fidye yazılımı / silici göstergesi |
| 2 | 🖥️ SSM Oturum / Run Command | timeseries | SSM StartSession, SendCommand ve StartAutomationExecution işlemlerini tespit eder — yönetilen örnekler üzerinden birincil yanal hareket yolu |
| 3 | 🔑 EC2 Instance Connect / Serial Console Erişimi | timeseries | SendSSHPublicKey ve SendSerialConsoleSSHPublicKey işlemlerini tespit eder — EC2 anahtar çiftlerini atlar (60 saniye geçerli, SSH anahtarı izi bırakmaz) |
| 4 | 📝 EC2 User Data Değişikliği | timeseries | userData değişikliği içeren ModifyInstanceAttribute işlemini tespit eder — betik, bir sonraki önyüklemede root olarak çalışır |
| 5 | ⚡ Lambda İşlevi Kurcalaması | timeseries | Lambda oluşturma, kod güncellemeleri (UpdateFunctionCode) ve izin değişikliklerini (AddPermission) tespit eder |
| 6 | 📦 Lambda Layer Eklenmesi | timeseries | Lambda layer yayımlamayı ve joker karakterli principal içeren AddLayerVersionPermission işlemini tespit eder (genel tedarik zinciri saldırısı) |
| 7 | 📦 ECS Task Definition  | timeseries | RegisterTaskDefinition / UpdateService işlemlerini tespit eder — Pacu ecs__backdoor_task_def, ECR'ye dokunmadan kötü amaçlı bir yan araç (sidecar) konteyneri enjekte eder |
| 8 | 👤 EC2 Instance Profile Değişiklikleri | timeseries | AssociateIamInstanceProfile / ReplaceIamInstanceProfileAssociation işlemlerini tespit eder — yanal hareketi mümkün kılan ayrıcalıklı bir profil ekler |
| 9 | 🖥 EC2 Örnek Başlatmaları | timeseries | Örnek türü, sayısı, anahtar adı ve AMI dahil tüm RunInstances olaylarını listeler (kripto madenciliği tespiti) |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance İstismarı | timeseries | Büyük Spot Fleet isteklerini (ec2) ve yüksek kapasiteli Auto Scaling grubu oluşturmayı (autoscaling) tespit eder — kripto madenciliği finansal etki göstergesi |
| 11 | ☸️ EKS Cluster API Çağrıları | timeseries | EKS cluster kontrol düzlemi değişikliklerini tespit eder (genel API sunucusu açığa çıkması, sahte Fargate profilleri) |
| 12 | 🐳 ECR Repository / Image Değişiklikleri | timeseries | ECR repository/image olaylarını tespit eder ('latest' etiketli PutImage, sonraki tüm dağıtımları zehirler) |
| 13 | 📅 EventBridge / CloudWatch Kural Değişiklikleri | timeseries | EventBridge kuralı ve Scheduler değişikliklerini tespit eder (PutRule, CreateSchedule) — çalışan bir süreç olmadan kalıcılık sağlar |
| 14 | 💡 Lightsail Örnek ve Anahtar İstismarı | timeseries | Lightsail anahtar alma, port açma ve örnek erişimini tespit eder — Pacu lightsail__download_ssh_keys / lightsail__generate_temp_access |

### 🌐 Ağ ve Altyapı

| # | Etiket | Grafik | Açıklama |
|---|-------|:-----:|-------------|
| 1 | 🌍 İnternete Açılan Security Group | timeseries | 0.0.0.0/0'dan gelen trafiğe izin veren security group kurallarını bulur — doğrudan genel erişim riski |
| 2 | 🔥 Security Group Değişiklikleri | timeseries | Tüm security group kural değişikliklerini tespit eder (AuthorizeSecurityGroupIngress, ModifySecurityGroupRules vb.) |
| 3 | 🌊 VPC Akış Logu Değişiklikleri | timeseries | VPC Akış Loglarının silinmesini tespit eder — akış loglarının kaldırılması birincil ağ adli kanıtını ortadan kaldırır |
| 4 | 🌐 CloudFront Distribution Kurcalaması | timeseries | Tüm CDN trafiğini saldırgan kontrolündeki sunuculara yönlendiren CloudFront kaynak değişikliklerini tespit eder (MitM) |
| 5 | 🛡 Network Firewall / Shield Kurcalaması | timeseries | Network Firewall ve Shield koruma kaldırmayı tespit eder — tüm alt ağ aralıklarını saldırı trafiğine maruz bırakır |
| 6 | 🧱 Network ACL Değişiklikleri | timeseries | NACL girişi oluşturma, silme ve değiştirmeyi tespit eder — NACL'ler alt ağ düzeyinde security group'ları geçersiz kılar |
| 7 | 🛣️ Route Table Değişiklikleri | timeseries | Route table değişikliklerini tespit eder — saldırganlar, ele geçirme veya C2 için trafiği kötü amaçlı ağ geçitlerine yönlendirir |
| 8 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | Yeni VPN bağlantılarını ve Transit Gateway eklerini tespit eder — C2 veya sızdırma için kalıcı Layer-3 ağ yolları oluşturur |
| 9 | 📡 Elastic IP Tahsisi / İlişkilendirmesi | timeseries | Elastic IP tahsisini/ilişkilendirmesini tespit eder — kararlı C2 altyapısı için ele geçirilmiş örneklere sabit genel IP atar |
| 10 | 🗝️ EC2 Anahtar Çifti Oluşturma | timeseries | CreateKeyPair ve ImportKeyPair işlemlerini tespit eder — saldırgan, kalıcı örnek erişimi için SSH anahtarları oluşturur |
| 11 | 📡 Ağ Altyapısı Değişiklikleri | timeseries | Saldırgan kontrolündeki altyapıyı oluşturabilecek VPC / alt ağ / IGW / NAT Gateway / peering değişikliklerini tespit eder |
| 12 | 🏷 ACM Sertifika İşlemleri | timeseries | ACM sertifika isteklerini ve silmelerini tespit eder — ele geçirilmiş hesaplar kimlik avı alanları için TLS sertifikaları verebilir |
| 13 | 🔑 API Gateway Anahtar Oluşturma ve Yönetimi | timeseries | API Gateway anahtarı oluşturma ve yetkilendirici değişikliklerini tespit eder — Pacu api_gateway__create_api_keys, IAM anahtar rotasyonundan sağ çıkan kalıcı kimlik bilgileri üretir |
| 14 | 🚧 VPC Endpoint Erişim Reddedildi | timeseries | VPC endpoint'leri üzerinden erişim reddedildi hatalarını tespit eder — yanlış yapılandırılmış endpoint politikasına işaret edebilir |

### 🕵 Tehdit Kalıpları

| # | Etiket | Grafik | Açıklama |
|---|-------|:-----:|-------------|
| 1 | 🔍 Keşif Kalıbı | bar | Bir saat içinde 10 veya daha fazla farklı Describe*/List*/Get* API'si çalıştıran çağıranları tanımlar — yaygın erken saldırı aşaması |
| 2 | 🤖 Olağandışı Kullanıcı Aracıları | bar | Nadir kullanıcı aracılarını (<5 olay) veya bilinen saldırgan araçlarını (Pacu, curl, wget) listeler — saldırı araçlarına işaret edebilir |
| 3 | 🌍 Çok Bölgeli Etkinlik | bar | Bir günde 3 veya daha fazla bölgede yazma işlemi yapan kimlikleri tespit eder — coğrafi yayılma ele geçirilmeye işaret edebilir |
| 4 | 🕵 İlk Kez Yapılan API Çağrıları (24s) | — | Son 24 saatte görülen ancak daha önce hiç görülmeyen API çağrılarını bulur — yeni işlemler saldırgan araçlarına işaret edebilir |

### 📊 Etkinlik ve Temel Çizgi

| # | Etiket | Grafik | Açıklama |
|---|-------|:-----:|-------------|
| 1 | 🖥 Management Console'dan Yazma Olayları | timeseries | AWS konsolu üzerinden yapılan değiştirici API çağrılarını tanımlar — yalnızca CLI erişimi beklendiğinde kullanışlıdır |
| 2 | 🔍 Hatalı Olaylar (24s) | timeseries | Son 24 saatteki tüm hata olaylarını listeler — neyin başarısız olduğuna veya araştırıldığına hızlı bir genel bakış |
| 3 | ❌ Hata Sıçraması Tespiti | — | Hata sayısının günlük ortalamayı 3 kat aştığı 1 saatlik pencereleri bulur |

### 🌍 GeoIP Analizi

> Doldurma için GeoLite2 `.mmdb` dosyaları gerektirir (GeoIP olmadan içeri alınırsa sütunlar NULL olur).

| # | Etiket | Grafik | Açıklama |
|---|-------|:-----:|-------------|
| 1 | 🕵 İmkânsız Seyahat Tespiti | — | Aynı kimliğin 2 saat içinde uzak şehirlerden API çağırmasını tespit eder — güçlü kimlik bilgisi ele geçirilme göstergesi |
| 2 | ⚠ Kimlik Çok Ülkeli Erişim | bar | 2 veya daha fazla ülkeden API çağrısı yapan kimlikleri bulur — meşru kullanıcılar nadiren aynı anda birden fazla ülkeden işlem yapar |
| 3 | 🗺 Ülkeye Göre Konsol Oturum Açmaları | timeseries | Konsol oturum açma olaylarını coğrafi kökenleriyle eşler — beklenmedik ülkelerden oturum açmalar yüksek risklidir |
| 4 | 🚨 Olağandışı Ülke Erişimi | bar | Nadir ülke/kimlik kombinasyonlarını (<10 olay) tespit eder — düşük hacimli yabancı erişim saldırgan altyapısı olabilir |
| 5 | 🚫 Ülkeye Göre Erişim Reddedildi | bar | Erişim reddedildi hatalarını kaynak ülkeye göre gruplar — tek bir ülkeden yoğun redler bir saldırıya işaret edebilir |
| 6 | 🔍 Ülkeye Göre Yazma Olayları | bar | Değiştirici API çağrılarını kaynak ülkeye göre gruplandırarak gösterir — beklenmedik ülkelerden yazmalar, okumalardan daha güçlü bir sinyaldir |
| 7 | 🌍 En Çok Kaynak Ülkeler | bar | Kaynak ülkeleri, yazma olayı ve benzersiz kimlik dökümleriyle API çağrı hacmine göre sıralar |
| 8 | 🏢 En Çok ASN / Kuruluş | bar | Otonom sistemleri (ISP'ler/bulut sağlayıcıları) API çağrı hacmine göre listeler — VPN/barındırma ASN'leri saldırgan altyapısına işaret edebilir |
| 9 | 📍 En Çok Kaynak Şehirler | bar | Kaynak şehirleri olay hacmine göre sıralar — şehir düzeyindeki veriler belirli saldırgan altyapısını veya ofis konumlarını saptar |
| 10 | 🌐 Özel / Dahili IP Özeti | bar | Özel/loopback/AWS-dahili IP'lerden gelen olayları özetler — beklenen dahili trafik için temel çizgi |
| 11 | 📋 Ülkeye Göre API Çağrıları (Event Name) | table | Çağrı hacmine göre en çok (event_name, ülke) çiftleri — hangi API işlemlerinin beklenmedik coğrafi bölgelerden geldiğini ortaya çıkarır |
| 12 | 👤 Ülkeye Göre Kimlikler (user_identity_arn) | table | Çağrı hacmine göre en çok (user_identity_arn, ülke) çiftleri — beklenmedik ülkelerden aktif olan IAM kimliklerini ilk/son görülmeyle birlikte ortaya çıkarır |

### ☁ IaC ve Platform

| # | Etiket | Grafik | Açıklama |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Tedarik Zinciri Saldırısı | timeseries | CI/CD hattı oluşturma ve değiştirmeyi tespit eder (UpdateProject, sonraki her derlemeye kötü amaçlı derleme adımları enjekte eder) |
| 2 | 🏗 CloudFormation / IaC İstismarı | timeseries | CloudFormation yığını işlemlerini tespit eder — saldırganlar kötü amaçlı altyapıyı hızla dağıtmak için IaC kullanabilir |

</details>

---

## 📊 Pano Grafikleri — 80'den fazla grafik

| Sekme | Grafikler | Ne Gösterir |
|-----|:------:|---------------|
| 🔑 Kimlik ve Erişim | 9 | Konsol oturum açmaları · MFA trendi · oturum açma ısı haritası · hassas API'ler · root kullanımı · IAM varlık etkinliği · ayrıcalık yükseltme · SSO/privesc |
| 🎯 Tehdit Tespiti | 12 | Olay hacmi · okuma/yazma oranı · savunma atlatma · erişim reddedildi · hata trendi · SCP/Config/NACL/EventBridge kurcalaması |
| 📊 API Etkinliği | 7 | En çok API'ler · bölge dağılımı · kaynak IP'ler · kullanıcı aracıları · gizli bilgi anomalisi · harici AssumeRole · Route53 değişiklikleri |
| 🖥️ Bilişim | 5 | SSM yürütme · EC2 genel anlık görüntü · EKS/ECR olayları · ECS arka kapı · EBS Direct API sızdırma |
| 🪣 S3 ve RDS | 9 | S3 politika/ACL · toplu indirme/silme · sürüm oluşturma/loglama devre dışı · hesaplar arası çoğaltma · RDS anlık görüntü paylaşımı · Backup kurcalaması |
| 🌍 GeoIP İstihbaratı | 6 | Dünya haritası · istek hacmine göre en çok ülkeler / şehirler / ASN'ler · event_name × ülke · kimlik × ülke |
| 🕒 Zamansal Analiz | 6 | Kimlik/IP/API/aracıya göre ilk/son görülme · yeniden etkinleşen uykudaki hesaplar · hız sıçramaları |
| 🚨 Yüksek Riskli API İzleyici | 7 | HRM zaman serisi · en çok çağrılar/aktörler/IP'ler · savunma atlatma/kimlik bilgisi detayı · bölgeye göre |

<details>
<summary>📋 Tam liste — 80'den fazla grafiğin tamamı (genişletmek için tıklayın)</summary>

## Pano Grafikleri (Apache Superset — `dashboard/`)

### 🔑 Kimlik ve Erişim

| # | Grafik Adı | Açıklama |
|---|------------|-------------|
| 1 | Console Login Activity | IAM kimliğine göre gruplandırılmış konsol oturum açma olayları (DSH-08) |
| 2 | MFA-less Login Trend | MFA kullanımına göre ayrılmış günlük konsol oturum açmaları (DSH-28) |
| 3 | Login Activity Heatmap (Hour × Day) | JST'de haftanın günü ve günün saatine göre konsol oturum açma sayıları (DSH-19) |
| 4 | Sensitive API Calls | Bilinen güvenlik açısından hassas AWS API işlemlerinin çağrıları (DSH-12) |
| 5 | Root Account Usage | AWS Root hesabı tarafından yapılan tüm API çağrıları (DSH-13) |
| 6 | IAM Entity Activity | Yazma oranı ve hata oranıyla birlikte toplam API çağrısına göre sıralanan en çok 50 IAM varlığı |
| 7 | Privilege Escalation Timeline | Olay adına göre ayrıcalık yükseltme API çağrılarının günlük sayıları (DSH-30) |
| 8 | IAM Identity Center (SSO) Events | sso.amazonaws.com'dan gelen AWS IAM Identity Center yönetim olayları (DSH-44) |
| 9 | Glue & SageMaker Privilege Escalation | iam:PassRole yoluyla IAM ayrıcalık yükseltme için kullanılan Glue DevEndpoint ve SageMaker Notebook olayları (DSH-50) |

### 🎯 Tehdit Tespiti

| # | Grafik Adı | Açıklama |
|---|------------|-------------|
| 1 | CloudTrail Events Over Time | Zaman içinde saatlik Okuma ve Yazma olay hacmi (DSH-01) |
| 2 | Write/Read Ratio Trend | Okuma ve yazma API çağrılarının saatlik dökümü (DSH-20) |
| 3 | Throttling Exception Spikes | AWS hizmetine göre saatlik kısıtlama/hız sınırı hataları (DSH-21) |
| 4 | Defense Evasion Events | Bilinen savunma atlatma tekniklerine uyan tüm CloudTrail olayları (DSH-22) |
| 5 | Top Access Denied Actions | AccessDenied hatası döndüren en çok 20 API işlemi (DSH-09) |
| 6 | Error Event Trend | error_code'a göre ayrılmış saatlik hata olayları (DSH-04) |
| 7 | Organizations / SCP Changes | SCP politika değişiklikleri dahil AWS Organizations yönetim olayları (DSH-24) |
| 8 | First-Time Service Sources | İlk görünme tarihine göre sıralanmış tüm farklı AWS hizmet kaynakları (DSH-26) |
| 9 | VPC Flow Log Changes | VPC Akış Logu oluşturma ve silme olayları (DSH-42) |
| 10 | AWS Config Tampering | AWS Config kaydedici ve kural kurcalama olayları (DSH-43) |
| 11 | Network ACL / Route Table Changes | NACL ve route table değişiklik olayları (DSH-46) |
| 12 | EventBridge / CloudWatch Rule Tampering | EventBridge ve CloudWatch Events kural kurcalaması (DSH-47) |

### 📊 API Etkinliği

| # | Grafik Adı | Açıklama |
|---|------------|-------------|
| 1 | Top 20 API Calls | En sık çağrılan 20 AWS API işlemi (DSH-02) |
| 2 | Region Activity | AWS bölgeleri genelinde CloudTrail olaylarının dağılımı (DSH-14) |
| 3 | Top Source IP Addresses | İstek sayısına göre en çok 100 harici kaynak IP (DSH-05) |
| 4 | User Agent Analysis | Hata ve yazma dökümleriyle birlikte istek sayısına göre en çok 50 kullanıcı aracısı (DSH-11) |
| 5 | Secrets Access Anomaly | Bir saat içinde Secrets Manager veya SSM Parameter Store'a ≥10 kez erişen kimlikler |
| 6 | AssumedRole from External IP | Genel (özel olmayan) IP adreslerinden gelen AssumeRole çağrıları (DSH-27) |
| 7 | Route53 DNS Changes | Route 53 barındırılan bölge ve resolver yapılandırma değişiklikleri (DSH-29) |

### 🖥️ Bilişim

| # | Grafik Adı | Açıklama |
|---|------------|-------------|
| 1 | SSM Session / Run Command Execution | AWS Systems Manager uzaktan yürütme olayları (DSH-39) |
| 2 | EC2 Public Snapshot / AMI Sharing | EBS anlık görüntü ve AMI genel paylaşım olayları (DSH-41) |
| 3 | EKS / ECR Container Platform Events | EKS cluster ve ECR konteyner kayıt defteri olayları (DSH-48) |
| 4 | ECS Task Definition | ECS task definition kaydı ve hizmet güncelleme olayları — Pacu ecs__backdoor_task_def kalıbı (DSH-49) |
| 5 | EBS Direct API Snapshot Exfiltration | EC2 olmadan anlık görüntü verisini akış olarak göndermek için kullanılan EBS Direct API çağrıları (ListSnapshotBlocks / GetSnapshotBlock) (DSH-51) |

### 🪣 S3 ve RDS

| # | Grafik Adı | Açıklama |
|---|------------|-------------|
| 1 | S3 Protection Config Changes | Bucket güvenlik duruşunu zayıflatan S3 olayları (DSH-25) |
| 2 | S3 Bucket Policy / ACL Changes | S3 bucket politikası ve ACL değişiklik olayları (DSH-45) |
| 3 | RDS Snapshot Cross-Account Share | RDS ve Aurora anlık görüntü paylaşım olayları (DSH-40) |
| 4 | S3 Bulk Download | Saatte ≥100 GetObject çağrısı yapan kimlikler — otomatik veri sızdırma kalıbı (DSH-52) |
| 5 | S3 Bulk Object Deletion | Saatte ≥50 DeleteObject/DeleteObjects çağrısı yapan kimlikler — fidye yazılımı veri imha kalıbı (DSH-53) |
| 6 | S3 Versioning / Logging Disabled | PutBucketVersioning (Suspended) ve PutBucketLogging (devre dışı) — veri imhasının adli karşıtı öncülü (DSH-54) |
| 7 | S3 Cross-Account Replication | PutBucketReplication / DeleteBucketReplication — saldırgan kontrolündeki hesaba kalıcı sessiz sızdırma kanalı (DSH-55) |
| 8 | RDS Deleted without Final Snapshot | skipFinalSnapshot=true ile DeleteDBInstance / DeleteDBCluster — kurtarılamaz veri imhası (DSH-56) |
| 9 | AWS Backup Tampering | Backup Vault / Plan / RecoveryPoint silme ve Vault Lock kaldırma — fidye yazılımının kurtarma seçeneklerini ortadan kaldırmak için attığı ilk adım (DSH-57) |

### 🌍 GeoIP İstihbaratı

> GeoLite2 `.mmdb` dosyaları gerektirir. GeoIP olmadan içeri alınırsa GeoIP sütunları NULL olur.

| # | Grafik Adı | Açıklama |
|---|------------|-------------|
| 1 | Global Request Origin Map | CloudTrail API çağrı kökenlerinin coğrafi dağılımını gösteren dünya haritası |
| 2 | Top Countries by Request Volume | Yazma olayı ve benzersiz çağıran dökümleriyle API çağrı hacmine göre en çok 20 kaynak ülke |
| 3 | Top Cities by Request Volume | Yazma olayı ve benzersiz çağıran dökümleriyle API çağrı hacmine göre en çok 25 şehir |
| 4 | Top ASN Organizations by Request Volume | API çağrı hacmine göre en çok 25 ASN kuruluşu |
| 5 | API Calls by Country (Event Name × GeoIP) | En çok 50 (event_name, ülke) çifti — hangi API işlemlerinin her coğrafi bölgeden çağrıldığını ortaya çıkarır (DSH-79) |
| 6 | Identities by Country (user_identity_arn × GeoIP) | En çok 50 (user_identity_arn, ülke) çifti — beklenmedik ülkelerden aktif olan IAM kimliklerini yazma sayısı ve ilk/son görülmeyle birlikte ortaya çıkarır (DSH-80) |

### 🕒 Zamansal Analiz

| # | Grafik Adı | Açıklama |
|---|------------|-------------|
| 1 | First / Last Seen per IAM Identity | İlk/son görülme zaman damgaları, olay sayıları ve farklı API'lerle IAM kimlikleri |
| 2 | First / Last Seen per Source IP | İlk/son görülme, farklı kimlikler ve farklı API'lerle kaynak IP'ler |
| 3 | First / Last Seen per API Call | İlk görünmeye göre sıralanmış API işlemleri — yeni çağrılar yeni saldırı araçlarına işaret edebilir (DSH-33) |
| 4 | First / Last Seen per User Agent | İlk görünmeye göre sıralanmış kullanıcı aracıları — yeni araç tespiti (DSH-34) |
| 5 | Dormant Accounts Reactivated | 72+ saatlik hareketsizlik boşluğu olup etkinliğe devam eden kimlikler (DSH-37) |
| 6 | Event Velocity Spikes per Identity | Saatte 50+ olay patlama etkinliği gösteren kimlikler (DSH-38) |

### 🚨 Yüksek Riskli API İzleyici (HRM)

| # | Grafik Adı | Açıklama |
|---|------------|-------------|
| 1 | High-Risk API Events Over Time | Saldırı kampanyalarında yaygın olarak görülen API'ler için günlük çağrı hacmi (HRM-39) |
| 2 | Top High-Risk API Calls | Toplam çağrı sayısına göre sıralanan yüksek riskli izleme listesindeki API işlemleri (HRM-40) |
| 3 | Top Actors — High-Risk APIs | Yüksek riskli izleme listesindeki API'lere yapılan toplam çağrıya göre sıralanan IAM principal'leri (HRM-42) |
| 4 | Top Source IPs — High-Risk APIs | Yüksek riskli izleme listesindeki API'lere yapılan toplam çağrıya göre sıralanan kaynak IP'ler (HRM-43) |
| 5 | Defense Evasion API Events | Denetim kontrollerini devre dışı bırakmak veya kurcalamak için kullanılan API'ler için ayrıntılı olay logu (HRM-44) |
| 6 | Credential Access API Events | Gizli bilgileri ve kimlik bilgilerini almak için kullanılan API'ler için ayrıntılı olay logu (HRM-45) |
| 7 | High-Risk API Calls by Region | AWS bölgesine göre dağıtılan yüksek riskli izleme listesi API çağrıları (HRM-46) |

</details>

---
