# Référence des requêtes et tableaux de bord intégrés

> 💡 Aucune connaissance SQL ou approfondie d'AWS requise — sélectionnez simplement une chasse dans la liste déroulante et obtenez des résultats instantanément.

## 🎯 Chasses intégrées — plus de 100 requêtes

Les catégories sont classées par priorité de triage DFIR — vérifiez d'abord la falsification des outils de détection, puis l'abus d'identité, puis l'impact sur les données.

| Catégorie | Requêtes | Principales menaces couvertes |
|----------|:-------:|---------------------|
| 🛡 Détection et réponse | 12 | Falsification du service d'audit (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · suppression de SCP · suppression d'alarme · exfiltration de journaux |
| 🔑 Identité et accès | 26 | Utilisation du root · connexion console/MFA · élévation de privilèges · porte dérobée de politique de confiance · abus de PassRole · AssumeRole inter-comptes · SSO/SAML/OIDC · énumération d'identifiants |
| 🪣 Données et stockage | 21 | Suppression/téléchargement en masse S3 · lecture en masse de secrets · falsification de sauvegarde · opérations KMS · partage de snapshot · exfiltration via EBS Direct API · export DynamoDB · réplication inter-comptes S3 |
| ⚡ Calcul et serverless | 14 | Arrêt/terminaison en masse EC2 · mouvement latéral SSM · falsification Lambda/ECS/EKS/ECR · persistance EventBridge · cryptominage · abus de Lightsail |
| 🌐 Réseau et infrastructure | 14 | SG ouvert sur Internet · suppression de journaux de flux VPC · détournement CloudFront · tunnels VPN/TGW dissimulés · IP élastique C2 · clés API Gateway |
| 🕵 Schémas de menace | 5 | Écritures hors heures · rafale de reconnaissance · propagation multi-régions · agents utilisateurs inhabituels · premiers appels d'API |
| 📊 Activité et référence | 3 | Événements d'écriture console · pics d'erreurs · erreurs récentes |
| 🌍 Analyse GeoIP ✦ | 12 | Voyage impossible · identifiants multi-pays · connexions/refus/écritures classés par géo · répartition par pays/ville/ASN · event_name × country · identity × country |
| ☁ IaC et plateforme | 2 | Chaîne d'approvisionnement CI/CD · abus de CloudFormation |

<details markdown="1">
<summary>📋 Liste complète — toutes les 100+ requêtes (cliquez pour développer)</summary>

## Chasses intégrées

### 🛡 Détection et réponse

| # | Libellé | Graphique | Description |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | Détecte toute tentative d'arrêt ou de modification de CloudTrail — l'indicateur de dissimulation le plus critique |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | Détecte la désactivation, la suppression et la manipulation de threat-intel de GuardDuty |
| 3 | ⛔ Security Hub Tampering | timeseries | Détecte la désactivation de Security Hub, la désactivation de standard et la suppression de découvertes |
| 4 | ⚙️ AWS Config Tampering | timeseries | Détecte la suppression d'enregistreur/règle AWS Config (élimine les preuves de conformité) |
| 5 | 🛡 Organizations SCP Changes | timeseries | Détecte la création, la mise à jour et la suppression de SCP — supprimer un SCP Deny élimine les garde-fous sur chaque compte de l'OU |
| 6 | 🚫 AWS Macie Tampering | timeseries | Détecte la désactivation de Macie et la création de filtre de découvertes (évasion de défense pré-exfiltration) |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | Détecte la suppression d'alarme et DisableAlarmActions — réduit au silence l'alerte de sécurité sans supprimer l'alarme |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | Détecte la création/suppression de filtre d'abonnement CW Logs (exfiltration de journaux en temps réel vers le Kinesis/Lambda de l'attaquant) |
| 9 | 🏹 WAF WebACL Changes | timeseries | Détecte la création, la mise à jour et la suppression de WAF WebACL sur WAFv2/WAF Classic |
| 10 | 🔍 GuardDuty Findings Read | timeseries | Détecte ListFindings / GetFindings — l'attaquant lit les découvertes actives pour comprendre ce que le SOC a déjà détecté |
| 11 | 💰 Budget / Cost Anomaly Changes | timeseries | Détecte la suppression de Budget/AnomalyMonitor (masque les coûts de cryptominage) |
| 12 | 🚫 Access Denied Errors | bar | Regroupe les erreurs AccessDenied par identité et API — les principaux contrevenants indiquent un usage abusif d'identifiants |

### 🔑 Identité et accès

| # | Libellé | Graphique | Description |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | Détecte tout appel d'API effectué par le compte root — le root ne devrait jamais être utilisé en production |
| 2 | 🔓 Console Login without MFA | timeseries | Détecte les connexions console où le MFA n'a pas été utilisé — indicateur à haut risque de compromission de compte |
| 3 | 🌐 Console Logins | timeseries | Liste toutes les tentatives de connexion console, y compris les succès et les échecs (détection de force brute) |
| 4 | 🔐 MFA & Password Changes | timeseries | Détecte la désactivation du MFA et les réinitialisations de mot de passe — indicateur fort de prise de contrôle de compte |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | Détecte l'attachement de politique IAM et la manipulation de rôle (PutUserPolicy, AttachRolePolicy, CreatePolicyVersion, etc.) |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | Détecte UpdateAssumeRolePolicy — l'ajout de principaux externes à une politique de confiance crée une porte dérobée persistante |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | Détecte les événements put/delete de limite de permission — supprimer une limite étend immédiatement les permissions effectives |
| 8 | 👑 User Added to Admin Group | timeseries | Détecte les utilisateurs ajoutés à des groupes dont le nom contient « admin » — élévation de privilèges classique |
| 9 | 👥 IAM Group Membership Changes | timeseries | Détecte tous les événements AddUserToGroup / RemoveUserFromGroup / CreateGroup / DeleteGroup quel que soit le nom du groupe |
| 10 | 👤 New IAM Users / Keys | timeseries | Identifie les événements de création d'utilisateur IAM et de clé d'accès — une création inattendue peut indiquer une persistance |
| 11 | 🎯 IAM PassRole Abuse | timeseries | Détecte l'usage de iam:PassRole en inspectant les événements de service récepteur (RunInstances, CreateFunction, CreateNotebookInstance, etc.) où un ARN de rôle est transmis |
| 12 | 🔐 AssumeRole Cross-Account | timeseries | Affiche les événements AssumeRole où l'appelant et la cible sont dans des comptes AWS différents (mouvement latéral) |
| 13 | 🏢 Cross-Account Access | timeseries | Trouve tous les événements où le compte appelant diffère du compte destinataire |
| 14 | 🔑 STS Federation Token Issuance | timeseries | Détecte GetFederationToken et GetSessionToken — convertit des clés à longue durée de vie en identifiants temporaires persistants |
| 15 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | Détecte l'abus de confiance OIDC (revendication sub mal configurée / GitHub Actions sans condition de dépôt) |
| 16 | 🆔 IAM Identity Center (SSO) Events | timeseries | Détecte les actions de gestion d'AWS IAM Identity Center (CreatePermissionSet, CreateAccountAssignment, etc.) |
| 17 | 🔗 SAML / OIDC Provider Updates | timeseries | Détecte les changements de fournisseur d'identité SAML/OIDC — mettre à jour les métadonnées SAML avec un IdP contrôlé par l'attaquant crée une porte dérobée d'authentification persistante |
| 18 | 🧐 IAM Access Analyzer Calls | timeseries | Détecte tout usage d'IAM Access Analyzer — les attaquants exploitent l'analyseur natif pour énumérer les ressources accessibles depuis l'extérieur sans scripts de reconnaissance personnalisés |
| 19 | 🔄 Credential Report & Enumeration | timeseries | Détecte l'énumération IAM (GenerateCredentialReport, ListUsers, ListRoles, GetAccountAuthorizationDetails, etc.) |
| 20 | 🗝 Access Key Abuse | bar | Détecte les clés d'accès utilisées depuis 3+ adresses IP source distinctes en 7 jours — indicateur fort de fuite de clé |
| 21 | 📰 AWS Organizations Account Creation | timeseries | Détecte la création de compte Organizations et les changements d'administrateur délégué (persistance par compte fantôme) |
| 22 | 👥 Cognito Unauthenticated Access | timeseries | Détecte les pools d'identités Cognito avec allowUnauthenticatedIdentities=true |
| 23 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | Détecte la création de Glue DevEndpoint (iam:PassRole + glue:CreateDevEndpoint = endpoint accessible par SSH s'exécutant avec les permissions complètes du rôle transmis) et l'énumération de connexions pour la collecte d'identifiants |
| 24 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | Détecte la création de notebook SageMaker et la génération d'URL présignée — iam:PassRole + sagemaker:CreateNotebookInstance lance un environnement Jupyter avec les permissions AWS complètes du rôle transmis |
| 25 | 🛠 Data Pipeline / CodeStar Privilege Escalation | timeseries | Détecte la création de ressources Data Pipeline et CodeStar utilisées pour l'élévation via iam:PassRole (CreateProjectFromTemplate crée un rôle IAM admin comme effet secondaire) |
| 26 | 🧩 Step Functions Privilege Escalation | timeseries | Détecte la création de machine d'état Step Functions (iam:PassRole + states:CreateStateMachine exécute des tâches Lambda/ECS sous le rôle transmis) |

### 🪣 Données et stockage

| # | Libellé | Graphique | Description |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | Détecte les identités effectuant ≥50 appels DeleteObject/DeleteObjects par heure — schéma de destruction de données par rançongiciel / wiper |
| 2 | 🔥 AWS Backup Tampering | timeseries | Détecte la suppression de Backup Vault / Plan / RecoveryPoint et le retrait de Vault Lock — première étape du rançongiciel pour éliminer les options de récupération |
| 3 | 🔓 KMS Key Operations | timeseries | Signale les opérations KMS sensibles (DisableKey, ScheduleKeyDeletion, CreateGrant, PutKeyPolicy, Decrypt à fort volume) |
| 4 | 🔓 S3 Public Access Block Disabled | — | Détecte la désactivation des paramètres de blocage d'accès public S3 — risque d'exposition immédiate des données |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | Détecte les modifications de politique de bucket et d'ACL S3 (PutBucketPolicy avec Principal='*' est particulièrement critique) |
| 6 | 🪣 S3 Data Access Anomalies | bar | Détecte les appels GetObject en masse (≥100/heure) — schéma d'exfiltration de données automatisée |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | Détecte les identités récupérant ≥10 secrets distincts en une heure — signal de collecte d'identifiants |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | Détecte la suppression de secret, PutResourcePolicy (partage inter-comptes) et CancelRotateSecret |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | Détecte les identités lisant ≥20 paramètres en une heure — un canal d'exfiltration souvent négligé |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | Détecte les snapshots RDS/Aurora partagés avec des comptes AWS externes (exfiltration de base de données via snapshot) |
| 11 | 💣 RDS Deleted without Final Snapshot | — | Détecte la suppression RDS avec skipFinalSnapshot=true — destruction potentielle de données |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | Détecte les instances RDS créées ou modifiées avec publiclyAccessible=true |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | Détecte ExportTableToPointInTime (export complet de table côté serveur contournant la DLP GetItem), DeleteTable et la désactivation de PITR |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | Détecte l'EBS Direct API (ListSnapshotBlocks / GetSnapshotBlock) — Pacu ebs__download_snapshots diffuse des données brutes de snapshot sans EC2, contournant la détection ModifySnapshotAttribute |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | Détecte la création/mise à jour de flux de livraison Firehose pointant vers un S3 externe — pipeline de données en temps réel invisible à la DLP réseau |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | Détecte PutBucketReplication — copie silencieusement tous les nouveaux objets vers un bucket contrôlé par l'attaquant sans générer d'événements GetObject supplémentaires |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | Détecte la suspension du versioning (permet la suppression permanente) et la désactivation de la journalisation d'accès serveur (supprime la piste de preuves) |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | Détecte les changements de règle de réception et de configuration d'identité SES — les règles de transfert relaient tout le courrier entrant vers les adresses de l'attaquant ; les identités vérifiées permettent des campagnes de phishing |
| 19 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | Détecte les changements de politique SQS/SNS accordant l'accès à des comptes externes (diffusion silencieuse de messages vers les endpoints de l'attaquant) |
| 20 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | Détecte les snapshots EBS ou AMI partagés publiquement (group=all) — permet à quiconque de copier des images disque et d'extraire des données |
| 21 | 📧 Data Exfiltration Channels | bar | Détecte les appels SNS/SQS/SES/S3 PutObject à fort volume (≥50/heure) depuis une seule identité |

### ⚡ Calcul et serverless

| # | Libellé | Graphique | Description |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | Détecte les identités effectuant ≥5 StopInstances/TerminateInstances en une heure — indicateur de rançongiciel / wiper |
| 2 | 🖥️ SSM Session / Run Command | timeseries | Détecte SSM StartSession, SendCommand et StartAutomationExecution — principale voie de mouvement latéral via les instances gérées |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | Détecte SendSSHPublicKey et SendSerialConsoleSSHPublicKey — contourne les paires de clés EC2 (valides 60 secondes, ne laissent aucun artefact de clé SSH) |
| 4 | 📝 EC2 User Data Modification | timeseries | Détecte ModifyInstanceAttribute avec un changement de userData — le script s'exécute en tant que root au prochain démarrage |
| 5 | ⚡ Lambda Function Tampering | timeseries | Détecte la création de Lambda, les mises à jour de code (UpdateFunctionCode) et les changements de permission (AddPermission) |
| 6 | 📦 Lambda Layer Addition | timeseries | Détecte la publication de couche Lambda et AddLayerVersionPermission avec un principal joker (attaque de chaîne d'approvisionnement publique) |
| 7 | 📦 ECS Task Definition  | timeseries | Détecte RegisterTaskDefinition / UpdateService — Pacu ecs__backdoor_task_def injecte un conteneur sidecar malveillant sans toucher à ECR |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | Détecte AssociateIamInstanceProfile / ReplaceIamInstanceProfileAssociation — attache un profil privilégié permettant le mouvement latéral |
| 9 | 🖥 EC2 Instance Launches | timeseries | Liste tous les événements RunInstances, y compris le type d'instance, le nombre, le nom de clé et l'AMI (détection de cryptominage) |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | Détecte les requêtes Spot Fleet importantes (ec2) et la création de groupe Auto Scaling à forte capacité (autoscaling) — indicateur d'impact financier de cryptominage |
| 11 | ☸️ EKS Cluster API Calls | timeseries | Détecte les modifications du plan de contrôle de cluster EKS (exposition publique du serveur API, profils Fargate malveillants) |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | Détecte les événements de dépôt/image ECR (PutImage tagué 'latest' empoisonne tous les déploiements ultérieurs) |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | Détecte les modifications de règle EventBridge et de Scheduler (PutRule, CreateSchedule) — établit une persistance sans processus en cours d'exécution |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | Détecte la récupération de clé, l'exposition de port et l'accès d'instance Lightsail — Pacu lightsail__download_ssh_keys / lightsail__generate_temp_access |

### 🌐 Réseau et infrastructure

| # | Libellé | Graphique | Description |
|---|-------|:-----:|-------------|
| 1 | 🌍 Security Group Opened to Internet | timeseries | Trouve les règles de groupe de sécurité autorisant le trafic depuis 0.0.0.0/0 — risque d'exposition publique directe |
| 2 | 🔥 Security Group Modifications | timeseries | Détecte tous les changements de règle de groupe de sécurité (AuthorizeSecurityGroupIngress, ModifySecurityGroupRules, etc.) |
| 3 | 🌊 VPC Flow Log Changes | timeseries | Détecte la suppression des journaux de flux VPC — supprimer les journaux de flux élimine la principale preuve forensique réseau |
| 4 | 🌐 CloudFront Distribution Tampering | timeseries | Détecte les changements d'origine CloudFront qui redirigent tout le trafic CDN vers des serveurs contrôlés par l'attaquant (MitM) |
| 5 | 🛡 Network Firewall / Shield Tampering | timeseries | Détecte le retrait de protection Network Firewall et Shield — expose des plages de sous-réseaux entières au trafic d'attaque |
| 6 | 🧱 Network ACL Changes | timeseries | Détecte la création, la suppression et le remplacement d'entrée NACL — les NACL prévalent sur les groupes de sécurité au niveau du sous-réseau |
| 7 | 🛣️ Route Table Changes | timeseries | Détecte les modifications de table de routage — les attaquants redirigent le trafic vers des passerelles malveillantes pour l'interception ou le C2 |
| 8 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | Détecte les nouvelles connexions VPN et les attachements Transit Gateway — crée des chemins réseau de couche 3 persistants pour le C2 ou l'exfiltration |
| 9 | 📡 Elastic IP Allocation / Association | timeseries | Détecte l'allocation/association d'IP élastique — attribue une IP publique fixe aux instances compromises pour une infrastructure C2 stable |
| 10 | 🗝️ EC2 Key Pair Creation | timeseries | Détecte CreateKeyPair et ImportKeyPair — l'attaquant crée des clés SSH pour un accès persistant aux instances |
| 11 | 📡 Network Infrastructure Changes | timeseries | Détecte les changements VPC / sous-réseau / IGW / NAT Gateway / peering pouvant établir une infrastructure contrôlée par l'attaquant |
| 12 | 🏷 ACM Certificate Operations | timeseries | Détecte les demandes et suppressions de certificat ACM — les comptes compromis peuvent émettre des certificats TLS pour des domaines de phishing |
| 13 | 🔑 API Gateway Key Creation & Management | timeseries | Détecte la création de clé API Gateway et les changements d'autorisateur — Pacu api_gateway__create_api_keys génère des identifiants persistants qui survivent à la rotation des clés IAM |
| 14 | 🚧 VPC Endpoint Access Denied | timeseries | Détecte les erreurs d'accès refusé via les endpoints VPC — peut indiquer une politique d'endpoint mal configurée |

### 🕵 Schémas de menace

| # | Libellé | Graphique | Description |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | Identifie les appelants ayant exécuté 10+ API Describe*/List*/Get* distinctes en une heure — phase précoce d'attaque courante |
| 2 | 🤖 Unusual User Agents | bar | Liste les agents utilisateurs rares (<5 événements) ou les outils d'attaquant connus (Pacu, curl, wget) — peut indiquer un outillage d'attaque |
| 3 | 🌍 Multi-Region Activity | bar | Détecte les identités effectuant des écritures dans 3+ régions en un jour — la dispersion géographique peut indiquer une compromission |
| 4 | 🕵 First-Time API Calls (24h) | — | Trouve les appels d'API vus au cours des dernières 24h mais jamais auparavant — des opérations inédites peuvent indiquer un outillage d'attaquant |

### 📊 Activité et référence

| # | Libellé | Graphique | Description |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | Identifie les appels d'API mutateurs effectués via la console AWS — utile lorsqu'un accès CLI uniquement est attendu |
| 2 | 🔍 Events with Errors (24h) | timeseries | Liste tous les événements d'erreur des dernières 24 heures — aperçu rapide de ce qui échoue ou est sondé |
| 3 | ❌ Error Spike Detection | — | Trouve les fenêtres d'une heure où le nombre d'erreurs dépasse de 3× la moyenne quotidienne |

### 🌍 Analyse GeoIP

> Nécessite des fichiers GeoLite2 `.mmdb` pour le peuplement (les colonnes sont NULL si ingérées sans GeoIP).

| # | Libellé | Graphique | Description |
|---|-------|:-----:|-------------|
| 1 | 🕵 Impossible Travel Detection | — | Détecte une même identité appelant des API depuis des villes distantes en moins de 2 heures — indicateur fort de compromission d'identifiants |
| 2 | ⚠ Identity Multi-Country Access | bar | Trouve les identités effectuant des appels d'API depuis 2+ pays — les utilisateurs légitimes opèrent rarement depuis plusieurs pays simultanément |
| 3 | 🗺 Console Logins by Country | timeseries | Cartographie les événements de connexion console vers leur origine géographique — les connexions depuis des pays inattendus sont à haut risque |
| 4 | 🚨 Unusual Country Access | bar | Détecte les combinaisons rares pays/identité (<10 événements) — un accès étranger à faible volume peut être une infrastructure d'attaquant |
| 5 | 🚫 Access Denied by Country | bar | Regroupe les erreurs d'accès refusé par pays source — des refus concentrés depuis un pays peuvent signaler une attaque |
| 6 | 🔍 Write Events by Country | bar | Affiche les appels d'API mutateurs regroupés par pays source — les écritures depuis des pays inattendus sont un signal plus fort que les lectures |
| 7 | 🌍 Top Source Countries | bar | Classe les pays sources par volume d'appels d'API avec répartition des événements d'écriture et des identités uniques |
| 8 | 🏢 Top ASN / Organizations | bar | Liste les systèmes autonomes (FAI/fournisseurs cloud) par volume d'appels d'API — les ASN VPN/hébergement peuvent indiquer une infrastructure d'attaquant |
| 9 | 📍 Top Source Cities | bar | Classe les villes sources par volume d'événements — les données au niveau de la ville localisent précisément l'infrastructure d'attaquant ou les sites de bureaux |
| 10 | 🌐 Private / Internal IP Summary | bar | Synthétise les événements provenant d'IP privées/loopback/internes AWS — référence pour le trafic interne attendu |
| 11 | 📋 API Calls by Country (Event Name) | table | Principales paires (event_name, country) par volume d'appels — révèle quelles opérations d'API proviennent de régions géographiques inattendues |
| 12 | 👤 Identities by Country (user_identity_arn) | table | Principales paires (user_identity_arn, country) par volume d'appels — fait ressortir les identités IAM actives depuis des pays inattendus avec première/dernière apparition |

### ☁ IaC et plateforme

| # | Libellé | Graphique | Description |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | Détecte la création et la modification de pipeline CI/CD (UpdateProject injecte des étapes de build malveillantes dans chaque build ultérieur) |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | Détecte les opérations de pile CloudFormation — les attaquants peuvent utiliser l'IaC pour déployer rapidement une infrastructure malveillante |

</details>

---

## 📊 Graphiques des tableaux de bord — plus de 80 graphiques

| Onglet | Graphiques | Ce qu'il montre |
|-----|:------:|---------------|
| 🔑 Identité et accès | 9 | Connexions console · tendance MFA · heatmap de connexion · API sensibles · usage du root · activité d'entité IAM · élévation de privilèges · SSO/privesc |
| 🎯 Détection de menace | 12 | Volume d'événements · ratio lecture/écriture · évasion de défense · accès refusé · tendance d'erreurs · falsification SCP/Config/NACL/EventBridge |
| 📊 Activité d'API | 7 | Top API · distribution par région · IP sources · agents utilisateurs · anomalie de secrets · AssumeRole externe · changements Route53 |
| 🖥️ Calcul | 5 | Exécution SSM · snapshot public EC2 · événements EKS/ECR · porte dérobée ECS · exfiltration via EBS Direct API |
| 🪣 S3 et RDS | 9 | Politique/ACL S3 · téléchargement/suppression en masse · versioning/journalisation désactivés · réplication inter-comptes · partage de snapshot RDS · falsification de Backup |
| 🌍 Renseignement GeoIP | 6 | Carte du monde · top pays / villes / ASN par volume de requêtes · event_name × country · identity × country |
| 🕒 Analyse temporelle | 6 | Première/dernière apparition par identité/IP/API/agent · comptes dormants réactivés · pics de vélocité |
| 🚨 Moniteur d'API à haut risque | 7 | Série temporelle HRM · top appels/acteurs/IP · détail évasion de défense/accès aux identifiants · par région |

<details markdown="1">
<summary>📋 Liste complète — tous les 80+ graphiques (cliquez pour développer)</summary>

## Graphiques des tableaux de bord (Apache Superset — `dashboard/`)

### 🔑 Identité et accès

| # | Nom du graphique | Description |
|---|------------|-------------|
| 1 | Console Login Activity | Événements de connexion console regroupés par identité IAM (DSH-08) |
| 2 | MFA-less Login Trend | Connexions console quotidiennes réparties par usage du MFA (DSH-28) |
| 3 | Login Activity Heatmap (Hour × Day) | Nombre de connexions console par jour de la semaine et heure de la journée en JST (DSH-19) |
| 4 | Sensitive API Calls | Invocations d'actions d'API AWS connues comme sensibles pour la sécurité (DSH-12) |
| 5 | Root Account Usage | Tous les appels d'API effectués par le compte root AWS (DSH-13) |
| 6 | IAM Entity Activity | Top 50 des entités IAM classées par total d'appels d'API, avec ratio d'écriture et taux d'erreur |
| 7 | Privilege Escalation Timeline | Nombres quotidiens d'appels d'API d'élévation de privilèges par nom d'événement (DSH-30) |
| 8 | IAM Identity Center (SSO) Events | Événements de gestion d'AWS IAM Identity Center depuis sso.amazonaws.com (DSH-44) |
| 9 | Glue & SageMaker Privilege Escalation | Événements Glue DevEndpoint et SageMaker Notebook utilisés pour l'élévation de privilèges IAM via iam:PassRole (DSH-50) |

### 🎯 Détection de menace

| # | Nom du graphique | Description |
|---|------------|-------------|
| 1 | CloudTrail Events Over Time | Volume horaire d'événements de lecture vs écriture au fil du temps (DSH-01) |
| 2 | Write/Read Ratio Trend | Répartition horaire des appels d'API de lecture vs écriture (DSH-20) |
| 3 | Throttling Exception Spikes | Erreurs horaires de throttling/limite de débit par service AWS (DSH-21) |
| 4 | Defense Evasion Events | Tous les événements CloudTrail correspondant à des techniques d'évasion de défense connues (DSH-22) |
| 5 | Top Access Denied Actions | Top 20 des actions d'API renvoyant des erreurs AccessDenied (DSH-09) |
| 6 | Error Event Trend | Événements d'erreur horaires ventilés par error_code (DSH-04) |
| 7 | Organizations / SCP Changes | Événements de gestion d'AWS Organizations, y compris les changements de politique SCP (DSH-24) |
| 8 | First-Time Service Sources | Toutes les sources de service AWS distinctes classées par date de première apparition (DSH-26) |
| 9 | VPC Flow Log Changes | Événements de création et de suppression de journaux de flux VPC (DSH-42) |
| 10 | AWS Config Tampering | Événements de falsification d'enregistreur et de règle AWS Config (DSH-43) |
| 11 | Network ACL / Route Table Changes | Événements de modification de NACL et de table de routage (DSH-46) |
| 12 | EventBridge / CloudWatch Rule Tampering | Falsification de règle EventBridge et CloudWatch Events (DSH-47) |

### 📊 Activité d'API

| # | Nom du graphique | Description |
|---|------------|-------------|
| 1 | Top 20 API Calls | Les 20 actions d'API AWS les plus fréquemment appelées (DSH-02) |
| 2 | Region Activity | Distribution des événements CloudTrail entre les régions AWS (DSH-14) |
| 3 | Top Source IP Addresses | Top 100 des IP sources externes par nombre de requêtes (DSH-05) |
| 4 | User Agent Analysis | Top 50 des agents utilisateurs par nombre de requêtes avec répartition des erreurs et écritures (DSH-11) |
| 5 | Secrets Access Anomaly | Identités accédant à Secrets Manager ou SSM Parameter Store ≥10 fois en une heure |
| 6 | AssumedRole from External IP | Appels AssumeRole depuis des adresses IP publiques (non privées) (DSH-27) |
| 7 | Route53 DNS Changes | Changements de configuration de zone hébergée et de résolveur Route 53 (DSH-29) |

### 🖥️ Calcul

| # | Nom du graphique | Description |
|---|------------|-------------|
| 1 | SSM Session / Run Command Execution | Événements d'exécution à distance AWS Systems Manager (DSH-39) |
| 2 | EC2 Public Snapshot / AMI Sharing | Événements de partage public de snapshot EBS et d'AMI (DSH-41) |
| 3 | EKS / ECR Container Platform Events | Événements de cluster EKS et de registre de conteneurs ECR (DSH-48) |
| 4 | ECS Task Definition | Événements d'enregistrement de définition de tâche ECS et de mise à jour de service — schéma Pacu ecs__backdoor_task_def (DSH-49) |
| 5 | EBS Direct API Snapshot Exfiltration | Appels EBS Direct API (ListSnapshotBlocks / GetSnapshotBlock) utilisés pour diffuser des données de snapshot sans EC2 (DSH-51) |

### 🪣 S3 et RDS

| # | Nom du graphique | Description |
|---|------------|-------------|
| 1 | S3 Protection Config Changes | Événements S3 qui affaiblissent la posture de sécurité du bucket (DSH-25) |
| 2 | S3 Bucket Policy / ACL Changes | Événements de modification de politique de bucket et d'ACL S3 (DSH-45) |
| 3 | RDS Snapshot Cross-Account Share | Événements de partage de snapshot RDS et Aurora (DSH-40) |
| 4 | S3 Bulk Download | Identités effectuant ≥100 appels GetObject par heure — schéma d'exfiltration de données automatisée (DSH-52) |
| 5 | S3 Bulk Object Deletion | Identités effectuant ≥50 appels DeleteObject/DeleteObjects par heure — schéma de destruction de données par rançongiciel (DSH-53) |
| 6 | S3 Versioning / Logging Disabled | PutBucketVersioning (Suspended) et PutBucketLogging (disabled) — précurseur anti-forensique de la destruction de données (DSH-54) |
| 7 | S3 Cross-Account Replication | PutBucketReplication / DeleteBucketReplication — canal d'exfiltration silencieux persistant vers un compte contrôlé par l'attaquant (DSH-55) |
| 8 | RDS Deleted without Final Snapshot | DeleteDBInstance / DeleteDBCluster avec skipFinalSnapshot=true — destruction de données irrécupérable (DSH-56) |
| 9 | AWS Backup Tampering | Suppression de Backup Vault / Plan / RecoveryPoint et retrait de Vault Lock — première étape du rançongiciel pour éliminer les options de récupération (DSH-57) |

### 🌍 Renseignement GeoIP

> Nécessite des fichiers GeoLite2 `.mmdb`. Les colonnes GeoIP sont NULL si ingérées sans GeoIP.

| # | Nom du graphique | Description |
|---|------------|-------------|
| 1 | Global Request Origin Map | Carte du monde montrant la distribution géographique des origines des appels d'API CloudTrail |
| 2 | Top Countries by Request Volume | Top 20 des pays sources par volume d'appels d'API avec répartition des événements d'écriture et des appelants uniques |
| 3 | Top Cities by Request Volume | Top 25 des villes par volume d'appels d'API avec répartition des événements d'écriture et des appelants uniques |
| 4 | Top ASN Organizations by Request Volume | Top 25 des organisations ASN par volume d'appels d'API |
| 5 | API Calls by Country (Event Name × GeoIP) | Top 50 des paires (event_name, country) — révèle quelles opérations d'API sont appelées depuis chaque région géographique (DSH-79) |
| 6 | Identities by Country (user_identity_arn × GeoIP) | Top 50 des paires (user_identity_arn, country) — fait ressortir les identités IAM actives depuis des pays inattendus avec nombre d'écritures et première/dernière apparition (DSH-80) |

### 🕒 Analyse temporelle

| # | Nom du graphique | Description |
|---|------------|-------------|
| 1 | First / Last Seen per IAM Identity | Identités IAM avec horodatages de première/dernière apparition, nombre d'événements et API distinctes |
| 2 | First / Last Seen per Source IP | IP sources avec première/dernière apparition, identités distinctes et API distinctes |
| 3 | First / Last Seen per API Call | Actions d'API classées par première apparition — les nouveaux appels peuvent indiquer un outillage d'attaque inédit (DSH-33) |
| 4 | First / Last Seen per User Agent | Agents utilisateurs classés par première apparition — détection de nouvel outillage (DSH-34) |
| 5 | Dormant Accounts Reactivated | Identités avec des périodes d'inactivité de 72+ heures qui ont repris leur activité (DSH-37) |
| 6 | Event Velocity Spikes per Identity | Identités avec une activité en rafale de 50+ événements par heure (DSH-38) |

### 🚨 Moniteur d'API à haut risque (HRM)

| # | Nom du graphique | Description |
|---|------------|-------------|
| 1 | High-Risk API Events Over Time | Volume d'appels quotidien pour les API couramment observées dans les campagnes d'attaque (HRM-39) |
| 2 | Top High-Risk API Calls | Actions d'API de la liste de surveillance à haut risque classées par nombre total d'appels (HRM-40) |
| 3 | Top Actors — High-Risk APIs | Principaux IAM classés par total d'appels aux API de la liste de surveillance à haut risque (HRM-42) |
| 4 | Top Source IPs — High-Risk APIs | IP sources classées par total d'appels aux API de la liste de surveillance à haut risque (HRM-43) |
| 5 | Defense Evasion API Events | Journal d'événements détaillé pour les API utilisées pour désactiver ou falsifier les contrôles d'audit (HRM-44) |
| 6 | Credential Access API Events | Journal d'événements détaillé pour les API utilisées pour récupérer des secrets et des identifiants (HRM-45) |
| 7 | High-Risk API Calls by Region | Appels d'API de la liste de surveillance à haut risque distribués par région AWS (HRM-46) |

</details>

---
