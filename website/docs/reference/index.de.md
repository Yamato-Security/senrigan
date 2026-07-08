# Referenz zu integrierten Abfragen und Dashboards

> 💡 Keine SQL- oder tiefgehenden AWS-Kenntnisse erforderlich — einfach eine Suche aus dem Dropdown-Menü auswählen und sofort Ergebnisse erhalten.

## 🎯 Integrierte Suchen — über 100 Abfragen

Die Kategorien sind nach DFIR-Triage-Priorität geordnet — prüfen Sie zuerst Manipulationen an Erkennungswerkzeugen, dann Identitätsmissbrauch und schließlich Auswirkungen auf Daten.

| Kategorie | Abfragen | Abgedeckte zentrale Bedrohungen |
|----------|:-------:|---------------------|
| 🛡 Detection & Response | 12 | Manipulation von Audit-Diensten (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · SCP-Löschung · Alarmunterdrückung · Log-Exfiltration |
| 🔑 Identity & Access | 26 | Root-Nutzung · Konsolen-Login/MFA · Rechteausweitung · Backdoor in Vertrauensrichtlinie · PassRole-Missbrauch · kontoübergreifendes AssumeRole · SSO/SAML/OIDC · Anmeldeinformations-Enumeration |
| 🪣 Data & Storage | 21 | S3-Massenlöschung/-Download · Massenlesen von Secrets · Backup-Manipulation · KMS-Operationen · Snapshot-Freigabe · EBS-Direct-API-Exfiltration · DynamoDB-Export · S3-kontoübergreifende Replikation |
| ⚡ Compute & Serverless | 14 | EC2-Massenstopp/-Terminierung · SSM-Lateralbewegung · Lambda/ECS/EKS/ECR-Manipulation · EventBridge-Persistenz · Cryptomining · Lightsail-Missbrauch |
| 🌐 Network & Infrastructure | 14 | SG für das Internet geöffnet · Löschung von VPC-Flow-Logs · CloudFront-Hijack · verdeckte VPN/TGW-Tunnel · Elastic-IP-C2 · API-Gateway-Schlüssel |
| 🕵 Threat Patterns | 5 | Schreibvorgänge außerhalb der Geschäftszeiten · Aufklärungs-Burst · Multi-Region-Ausbreitung · ungewöhnliche User Agents · erstmalige API-Aufrufe |
| 📊 Activity & Baseline | 3 | Konsolen-Schreibereignisse · Fehlerspitzen · jüngste Fehler |
| 🌍 GeoIP Analysis ✦ | 12 | Unmögliche Reisen · Anmeldeinformationen aus mehreren Ländern · geografisch eingestufte Logins/Verweigerungen/Schreibvorgänge · Aufschlüsselung nach Land/Stadt/ASN · event_name × Land · Identität × Land |
| ☁ IaC & Platform | 2 | CI/CD-Lieferkette · CloudFormation-Missbrauch |

<details markdown="1">
<summary>📋 Vollständige Liste — alle über 100 Abfragen (zum Aufklappen anklicken)</summary>

## Integrierte Suchen

### 🛡 Detection & Response

| # | Bezeichnung | Diagramm | Beschreibung |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | Erkennt jeden Versuch, CloudTrail zu stoppen oder zu verändern — der kritischste Indikator für eine Vertuschung |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | Erkennt das Deaktivieren, Löschen und die Manipulation von Threat-Intel bei GuardDuty |
| 3 | ⛔ Security Hub Tampering | timeseries | Erkennt das Deaktivieren von Security Hub, das Deaktivieren von Standards und die Unterdrückung von Findings |
| 4 | ⚙️ AWS Config Tampering | timeseries | Erkennt die Löschung von AWS-Config-Recordern/-Regeln (beseitigt Compliance-Nachweise) |
| 5 | 🛡 Organizations SCP Changes | timeseries | Erkennt Erstellung, Aktualisierung und Löschung von SCPs — das Entfernen einer Deny-SCP beseitigt die Schutzmaßnahmen über jedes Konto in der OU hinweg |
| 6 | 🚫 AWS Macie Tampering | timeseries | Erkennt das Deaktivieren von Macie und die Erstellung von Finding-Filtern (Defense Evasion vor der Exfiltration) |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | Erkennt die Löschung von Alarmen und DisableAlarmActions — bringt Sicherheitswarnungen zum Schweigen, ohne den Alarm zu löschen |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | Erkennt die Erstellung/Löschung von CW-Logs-Subscription-Filtern (Echtzeit-Log-Exfiltration zu Angreifer-Kinesis/-Lambda) |
| 9 | 🏹 WAF WebACL Changes | timeseries | Erkennt Erstellung, Aktualisierung und Löschung von WAF-WebACLs über WAFv2/WAF Classic hinweg |
| 10 | 🔍 GuardDuty Findings Read | timeseries | Erkennt ListFindings / GetFindings — ein Angreifer liest aktive Findings, um zu verstehen, was das SOC bereits erkannt hat |
| 11 | 💰 Budget / Cost Anomaly Changes | timeseries | Erkennt die Löschung von Budget/AnomalyMonitor (verbirgt Cryptomining-Kosten) |
| 12 | 🚫 Access Denied Errors | bar | Gruppiert AccessDenied-Fehler nach Identität und API — die Hauptverursacher deuten auf Missbrauch von Anmeldeinformationen hin |

### 🔑 Identity & Access

| # | Bezeichnung | Diagramm | Beschreibung |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | Erkennt jeden API-Aufruf des Root-Kontos — Root sollte in der Produktion niemals verwendet werden |
| 2 | 🔓 Console Login without MFA | timeseries | Erkennt Konsolen-Logins, bei denen kein MFA verwendet wurde — hochriskanter Indikator für eine Kontokompromittierung |
| 3 | 🌐 Console Logins | timeseries | Listet alle Konsolen-Login-Versuche einschließlich Erfolgen und Fehlern auf (Brute-Force-Erkennung) |
| 4 | 🔐 MFA & Password Changes | timeseries | Erkennt die Deaktivierung von MFA und Passwort-Resets — starker Indikator für eine Kontoübernahme |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | Erkennt das Anhängen von IAM-Richtlinien und Rollenmanipulation (PutUserPolicy, AttachRolePolicy, CreatePolicyVersion usw.) |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | Erkennt UpdateAssumeRolePolicy — das Hinzufügen externer Principals zu einer Vertrauensrichtlinie schafft eine dauerhafte Backdoor |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | Erkennt Put-/Delete-Ereignisse für Berechtigungsgrenzen — das Entfernen einer Grenze erweitert sofort die effektiven Berechtigungen |
| 8 | 👑 User Added to Admin Group | timeseries | Erkennt Benutzer, die zu Gruppen mit 'admin' im Namen hinzugefügt wurden — klassische Rechteausweitung |
| 9 | 👥 IAM Group Membership Changes | timeseries | Erkennt alle AddUserToGroup- / RemoveUserFromGroup- / CreateGroup- / DeleteGroup-Ereignisse unabhängig vom Gruppennamen |
| 10 | 👤 New IAM Users / Keys | timeseries | Identifiziert Erstellungsereignisse für IAM-Benutzer und Access Keys — unerwartete Erstellung kann auf Persistenz hindeuten |
| 11 | 🎯 IAM PassRole Abuse | timeseries | Erkennt die Nutzung von iam:PassRole durch Untersuchung der Ereignisse empfangender Dienste (RunInstances, CreateFunction, CreateNotebookInstance usw.), bei denen eine Rollen-ARN übergeben wird |
| 12 | 🔐 AssumeRole Cross-Account | timeseries | Zeigt AssumeRole-Ereignisse, bei denen Aufrufer und Ziel in unterschiedlichen AWS-Konten liegen (Lateralbewegung) |
| 13 | 🏢 Cross-Account Access | timeseries | Findet alle Ereignisse, bei denen sich das Aufruferkonto vom Empfängerkonto unterscheidet |
| 14 | 🔑 STS Federation Token Issuance | timeseries | Erkennt GetFederationToken und GetSessionToken — wandelt langlebige Schlüssel in dauerhafte temporäre Anmeldeinformationen um |
| 15 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | Erkennt Missbrauch von OIDC-Vertrauen (falsch konfigurierter sub-Claim / GitHub Actions ohne Repo-Bedingung) |
| 16 | 🆔 IAM Identity Center (SSO) Events | timeseries | Erkennt Verwaltungsaktionen im AWS IAM Identity Center (CreatePermissionSet, CreateAccountAssignment usw.) |
| 17 | 🔗 SAML / OIDC Provider Updates | timeseries | Erkennt Änderungen an SAML/OIDC-Identitätsanbietern — das Aktualisieren von SAML-Metadaten mit einem vom Angreifer kontrollierten IdP schafft eine dauerhafte Authentifizierungs-Backdoor |
| 18 | 🧐 IAM Access Analyzer Calls | timeseries | Erkennt jede Nutzung des IAM Access Analyzer — Angreifer nutzen den nativen Analyzer, um extern zugängliche Ressourcen ohne eigene Aufklärungsskripte zu enumerieren |
| 19 | 🔄 Credential Report & Enumeration | timeseries | Erkennt IAM-Enumeration (GenerateCredentialReport, ListUsers, ListRoles, GetAccountAuthorizationDetails usw.) |
| 20 | 🗝 Access Key Abuse | bar | Erkennt Access Keys, die innerhalb von 7 Tagen von 3+ verschiedenen Quell-IPs verwendet wurden — starker Indikator für ein Schlüsselleck |
| 21 | 📰 AWS Organizations Account Creation | timeseries | Erkennt die Erstellung von Organizations-Konten und Änderungen an delegierten Administratoren (Schattenkonto-Persistenz) |
| 22 | 👥 Cognito Unauthenticated Access | timeseries | Erkennt Cognito-Identity-Pools mit allowUnauthenticatedIdentities=true |
| 23 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | Erkennt die Erstellung von Glue-DevEndpoints (iam:PassRole + glue:CreateDevEndpoint = per SSH zugänglicher Endpunkt, der mit den vollen Berechtigungen der übergebenen Rolle läuft) und die Enumeration von Verbindungen zum Sammeln von Anmeldeinformationen |
| 24 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | Erkennt die Erstellung von SageMaker-Notebooks und die Generierung von Presigned URLs — iam:PassRole + sagemaker:CreateNotebookInstance startet eine Jupyter-Umgebung mit den vollen AWS-Berechtigungen der übergebenen Rolle |
| 25 | 🛠 Data Pipeline / CodeStar Privilege Escalation | timeseries | Erkennt die Erstellung von Data-Pipeline- und CodeStar-Ressourcen, die zur iam:PassRole-Eskalation genutzt werden (CreateProjectFromTemplate erstellt als Nebeneffekt eine Admin-IAM-Rolle) |
| 26 | 🧩 Step Functions Privilege Escalation | timeseries | Erkennt die Erstellung von Step-Functions-State-Machines (iam:PassRole + states:CreateStateMachine führt Lambda-/ECS-Tasks unter der übergebenen Rolle aus) |

### 🪣 Data & Storage

| # | Bezeichnung | Diagramm | Beschreibung |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | Erkennt Identitäten, die ≥50 DeleteObject/DeleteObjects-Aufrufe pro Stunde durchführen — Muster für Ransomware-/Wiper-Datenvernichtung |
| 2 | 🔥 AWS Backup Tampering | timeseries | Erkennt die Löschung von Backup Vault / Plan / RecoveryPoint und das Entfernen von Vault Lock — erster Schritt bei Ransomware, um Wiederherstellungsoptionen zu beseitigen |
| 3 | 🔓 KMS Key Operations | timeseries | Kennzeichnet sensible KMS-Operationen (DisableKey, ScheduleKeyDeletion, CreateGrant, PutKeyPolicy, hochvolumiges Decrypt) |
| 4 | 🔓 S3 Public Access Block Disabled | — | Erkennt das Deaktivieren der S3-Public-Access-Block-Einstellungen — unmittelbares Risiko der Datenexposition |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | Erkennt Änderungen an S3-Bucket-Richtlinien und -ACLs (PutBucketPolicy mit Principal='*' ist besonders kritisch) |
| 6 | 🪣 S3 Data Access Anomalies | bar | Erkennt massenhafte GetObject-Aufrufe (≥100/Stunde) — Muster für automatisierte Datenexfiltration |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | Erkennt Identitäten, die ≥10 verschiedene Secrets in einer Stunde abrufen — Signal für das Sammeln von Anmeldeinformationen |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | Erkennt das Löschen von Secrets, PutResourcePolicy (kontoübergreifende Freigabe) und CancelRotateSecret |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | Erkennt Identitäten, die ≥20 Parameter in einer Stunde lesen — ein oft übersehener Exfiltrationskanal |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | Erkennt RDS/Aurora-Snapshots, die für externe AWS-Konten freigegeben wurden (Datenbank-Exfiltration über Snapshot) |
| 11 | 💣 RDS Deleted without Final Snapshot | — | Erkennt RDS-Löschung mit skipFinalSnapshot=true — potenzielle Datenvernichtung |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | Erkennt RDS-Instanzen, die mit publiclyAccessible=true erstellt oder geändert wurden |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | Erkennt ExportTableToPointInTime (serverseitiger vollständiger Tabellenexport, der GetItem-DLP umgeht), DeleteTable und das Deaktivieren von PITR |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | Erkennt EBS Direct API (ListSnapshotBlocks / GetSnapshotBlock) — Pacu ebs__download_snapshots streamt rohe Snapshot-Daten ohne EC2 und umgeht die ModifySnapshotAttribute-Erkennung |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | Erkennt die Erstellung/Aktualisierung von Firehose-Delivery-Streams, die auf externes S3 zeigen — Echtzeit-Datenpipeline, unsichtbar für Netzwerk-DLP |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | Erkennt PutBucketReplication — kopiert stillschweigend alle neuen Objekte in einen vom Angreifer kontrollierten Bucket, ohne zusätzliche GetObject-Ereignisse zu erzeugen |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | Erkennt das Aussetzen der Versionierung (ermöglicht dauerhafte Löschung) und das Deaktivieren des Server-Access-Loggings (entfernt die Beweisspur) |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | Erkennt Änderungen an SES-Empfangsregeln und Identitätskonfigurationen — Weiterleitungsregeln leiten alle eingehenden Mails an Angreiferadressen weiter; verifizierte Identitäten ermöglichen Phishing-Kampagnen |
| 19 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | Erkennt SQS/SNS-Richtlinienänderungen, die externen Konten Zugriff gewähren (stilles Nachrichten-Streaming zu Angreiferendpunkten) |
| 20 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | Erkennt EBS-Snapshots oder AMIs, die öffentlich freigegeben wurden (group=all) — ermöglicht jedem, Festplattenabbilder zu kopieren und Daten zu extrahieren |
| 21 | 📧 Data Exfiltration Channels | bar | Erkennt hochvolumige SNS/SQS/SES/S3-PutObject-Aufrufe (≥50/Stunde) von einer einzelnen Identität |

### ⚡ Compute & Serverless

| # | Bezeichnung | Diagramm | Beschreibung |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | Erkennt Identitäten, die ≥5 StopInstances/TerminateInstances in einer Stunde durchführen — Ransomware-/Wiper-Indikator |
| 2 | 🖥️ SSM Session / Run Command | timeseries | Erkennt SSM StartSession, SendCommand und StartAutomationExecution — primärer Lateralbewegungspfad über verwaltete Instanzen |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | Erkennt SendSSHPublicKey und SendSerialConsoleSSHPublicKey — umgeht EC2-Schlüsselpaare (60 Sekunden gültig, hinterlässt keine SSH-Schlüsselartefakte) |
| 4 | 📝 EC2 User Data Modification | timeseries | Erkennt ModifyInstanceAttribute mit userData-Änderung — das Skript läuft beim nächsten Start als Root |
| 5 | ⚡ Lambda Function Tampering | timeseries | Erkennt die Erstellung von Lambda, Code-Updates (UpdateFunctionCode) und Berechtigungsänderungen (AddPermission) |
| 6 | 📦 Lambda Layer Addition | timeseries | Erkennt die Veröffentlichung von Lambda-Layern und AddLayerVersionPermission mit Wildcard-Principal (öffentlicher Lieferketten-Angriff) |
| 7 | 📦 ECS Task Definition  | timeseries | Erkennt RegisterTaskDefinition / UpdateService — Pacu ecs__backdoor_task_def injiziert einen bösartigen Sidecar-Container, ohne ECR zu berühren |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | Erkennt AssociateIamInstanceProfile / ReplaceIamInstanceProfileAssociation — hängt ein privilegiertes Profil an und ermöglicht Lateralbewegung |
| 9 | 🖥 EC2 Instance Launches | timeseries | Listet alle RunInstances-Ereignisse einschließlich Instanztyp, Anzahl, Schlüsselname und AMI auf (Cryptomining-Erkennung) |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | Erkennt große Spot-Fleet-Anfragen (ec2) und die Erstellung von Auto-Scaling-Gruppen mit hoher Kapazität (autoscaling) — Indikator für finanzielle Auswirkungen durch Cryptomining |
| 11 | ☸️ EKS Cluster API Calls | timeseries | Erkennt Änderungen an der EKS-Cluster-Control-Plane (Exposition des öffentlichen API-Servers, betrügerische Fargate-Profile) |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | Erkennt ECR-Repository-/Image-Ereignisse (PutImage mit Tag 'latest' vergiftet alle nachfolgenden Bereitstellungen) |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | Erkennt Änderungen an EventBridge-Regeln und Scheduler (PutRule, CreateSchedule) — etabliert Persistenz ohne laufenden Prozess |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | Erkennt das Abrufen von Lightsail-Schlüsseln, die Port-Exposition und den Instanzzugriff — Pacu lightsail__download_ssh_keys / lightsail__generate_temp_access |

### 🌐 Network & Infrastructure

| # | Bezeichnung | Diagramm | Beschreibung |
|---|-------|:-----:|-------------|
| 1 | 🌍 Security Group Opened to Internet | timeseries | Findet Security-Group-Regeln, die Datenverkehr von 0.0.0.0/0 zulassen — Risiko direkter öffentlicher Exposition |
| 2 | 🔥 Security Group Modifications | timeseries | Erkennt alle Änderungen an Security-Group-Regeln (AuthorizeSecurityGroupIngress, ModifySecurityGroupRules usw.) |
| 3 | 🌊 VPC Flow Log Changes | timeseries | Erkennt die Löschung von VPC-Flow-Logs — das Entfernen von Flow-Logs beseitigt primäre forensische Netzwerkbeweise |
| 4 | 🌐 CloudFront Distribution Tampering | timeseries | Erkennt CloudFront-Origin-Änderungen, die den gesamten CDN-Datenverkehr auf vom Angreifer kontrollierte Server umleiten (MitM) |
| 5 | 🛡 Network Firewall / Shield Tampering | timeseries | Erkennt das Entfernen von Network-Firewall- und Shield-Schutz — setzt ganze Subnetzbereiche dem Angriffsdatenverkehr aus |
| 6 | 🧱 Network ACL Changes | timeseries | Erkennt die Erstellung, Löschung und Ersetzung von NACL-Einträgen — NACLs setzen Security Groups auf Subnetzebene außer Kraft |
| 7 | 🛣️ Route Table Changes | timeseries | Erkennt Änderungen an Routing-Tabellen — Angreifer leiten Datenverkehr zu bösartigen Gateways um, um ihn abzufangen oder für C2 zu nutzen |
| 8 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | Erkennt neue VPN-Verbindungen und Transit-Gateway-Anhänge — schafft dauerhafte Layer-3-Netzwerkpfade für C2 oder Exfiltration |
| 9 | 📡 Elastic IP Allocation / Association | timeseries | Erkennt die Zuweisung/Zuordnung von Elastic IPs — weist kompromittierten Instanzen eine feste öffentliche IP für stabile C2-Infrastruktur zu |
| 10 | 🗝️ EC2 Key Pair Creation | timeseries | Erkennt CreateKeyPair und ImportKeyPair — ein Angreifer erstellt SSH-Schlüssel für dauerhaften Instanzzugriff |
| 11 | 📡 Network Infrastructure Changes | timeseries | Erkennt Änderungen an VPC / Subnetz / IGW / NAT Gateway / Peering, die eine vom Angreifer kontrollierte Infrastruktur etablieren könnten |
| 12 | 🏷 ACM Certificate Operations | timeseries | Erkennt ACM-Zertifikatsanfragen und -löschungen — kompromittierte Konten können TLS-Zertifikate für Phishing-Domains ausstellen |
| 13 | 🔑 API Gateway Key Creation & Management | timeseries | Erkennt die Erstellung von API-Gateway-Schlüsseln und Authorizer-Änderungen — Pacu api_gateway__create_api_keys erzeugt dauerhafte Anmeldeinformationen, die eine IAM-Schlüsselrotation überdauern |
| 14 | 🚧 VPC Endpoint Access Denied | timeseries | Erkennt Access-Denied-Fehler über VPC-Endpunkte — kann auf eine falsch konfigurierte Endpunkt-Richtlinie hindeuten |

### 🕵 Threat Patterns

| # | Bezeichnung | Diagramm | Beschreibung |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | Identifiziert Aufrufer, die 10+ verschiedene Describe*/List*/Get*-APIs in einer Stunde ausgeführt haben — häufige frühe Angriffsphase |
| 2 | 🤖 Unusual User Agents | bar | Listet seltene User Agents (<5 Ereignisse) oder bekannte Angreifer-Tools (Pacu, curl, wget) auf — kann auf Angriffswerkzeuge hindeuten |
| 3 | 🌍 Multi-Region Activity | bar | Erkennt Identitäten, die an einem Tag Schreibvorgänge in 3+ Regionen durchführen — geografische Verteilung kann auf eine Kompromittierung hindeuten |
| 4 | 🕵 First-Time API Calls (24h) | — | Findet API-Aufrufe, die in den letzten 24 Stunden, aber nie zuvor beobachtet wurden — neuartige Operationen können auf Angriffswerkzeuge hindeuten |

### 📊 Activity & Baseline

| # | Bezeichnung | Diagramm | Beschreibung |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | Identifiziert verändernde API-Aufrufe, die über die AWS-Konsole erfolgen — nützlich, wenn nur CLI-Zugriff erwartet wird |
| 2 | 🔍 Events with Errors (24h) | timeseries | Listet alle Fehlerereignisse der letzten 24 Stunden auf — schneller Überblick darüber, was fehlschlägt oder sondiert wird |
| 3 | ❌ Error Spike Detection | — | Findet 1-Stunden-Fenster, in denen die Fehleranzahl den Tagesdurchschnitt um das 3-Fache übersteigt |

### 🌍 GeoIP Analysis

> Erfordert GeoLite2-`.mmdb`-Dateien zur Befüllung (Spalten sind NULL, wenn ohne GeoIP eingelesen wird).

| # | Bezeichnung | Diagramm | Beschreibung |
|---|-------|:-----:|-------------|
| 1 | 🕵 Impossible Travel Detection | — | Erkennt dieselbe Identität, die innerhalb von 2 Stunden APIs aus weit entfernten Städten aufruft — starker Indikator für eine Kompromittierung von Anmeldeinformationen |
| 2 | ⚠ Identity Multi-Country Access | bar | Findet Identitäten, die API-Aufrufe aus 2+ Ländern tätigen — legitime Benutzer agieren selten gleichzeitig aus mehreren Ländern |
| 3 | 🗺 Console Logins by Country | timeseries | Ordnet Konsolen-Login-Ereignisse ihrem geografischen Ursprung zu — Logins aus unerwarteten Ländern sind hochriskant |
| 4 | 🚨 Unusual Country Access | bar | Erkennt seltene Land/Identität-Kombinationen (<10 Ereignisse) — Zugriff aus dem Ausland mit geringem Volumen kann Angreiferinfrastruktur sein |
| 5 | 🚫 Access Denied by Country | bar | Gruppiert Access-Denied-Fehler nach Quellland — konzentrierte Verweigerungen aus einem Land können auf einen Angriff hindeuten |
| 6 | 🔍 Write Events by Country | bar | Zeigt verändernde API-Aufrufe gruppiert nach Quellland — Schreibvorgänge aus unerwarteten Ländern sind ein stärkeres Signal als Lesevorgänge |
| 7 | 🌍 Top Source Countries | bar | Ordnet Quellländer nach API-Aufrufvolumen mit Aufschlüsselungen nach Schreibereignissen und eindeutigen Identitäten |
| 8 | 🏢 Top ASN / Organizations | bar | Listet autonome Systeme (ISPs/Cloud-Anbieter) nach API-Aufrufvolumen auf — VPN-/Hosting-ASNs können auf Angreiferinfrastruktur hindeuten |
| 9 | 📍 Top Source Cities | bar | Ordnet Quellstädte nach Ereignisvolumen — Daten auf Stadtebene lokalisieren spezifische Angreiferinfrastruktur oder Bürostandorte |
| 10 | 🌐 Private / Internal IP Summary | bar | Fasst Ereignisse von privaten/Loopback-/AWS-internen IPs zusammen — Baseline für erwarteten internen Datenverkehr |
| 11 | 📋 API Calls by Country (Event Name) | table | Top-(event_name, Land)-Paare nach Aufrufvolumen — zeigt, welche API-Operationen aus unerwarteten geografischen Regionen stammen |
| 12 | 👤 Identities by Country (user_identity_arn) | table | Top-(user_identity_arn, Land)-Paare nach Aufrufvolumen — bringt IAM-Identitäten zum Vorschein, die aus unerwarteten Ländern aktiv sind, mit erstem/letztem Auftreten |

### ☁ IaC & Platform

| # | Bezeichnung | Diagramm | Beschreibung |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | Erkennt die Erstellung und Änderung von CI/CD-Pipelines (UpdateProject injiziert bösartige Build-Schritte in jeden nachfolgenden Build) |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | Erkennt CloudFormation-Stack-Operationen — Angreifer können IaC nutzen, um schnell bösartige Infrastruktur bereitzustellen |

</details>

---

## 📊 Dashboard-Diagramme — über 80 Diagramme

| Tab | Diagramme | Was es zeigt |
|-----|:------:|---------------|
| 🔑 Identity & Access | 9 | Konsolen-Logins · MFA-Trend · Login-Heatmap · sensible APIs · Root-Nutzung · IAM-Entitätsaktivität · Rechteausweitung · SSO/Privesc |
| 🎯 Threat Detection | 12 | Ereignisvolumen · Lese-/Schreibverhältnis · Defense Evasion · Access Denied · Fehlertrend · SCP/Config/NACL/EventBridge-Manipulation |
| 📊 API Activity | 7 | Top-APIs · Regionsverteilung · Quell-IPs · User Agents · Secrets-Anomalie · externes AssumeRole · Route53-Änderungen |
| 🖥️ Computing | 5 | SSM-Ausführung · EC2 Public Snapshot · EKS/ECR-Ereignisse · ECS-Backdoor · EBS-Direct-API-Exfiltration |
| 🪣 S3 & RDS | 9 | S3-Richtlinie/ACL · Massendownload/-löschung · Versionierung/Logging deaktiviert · kontoübergreifende Replikation · RDS-Snapshot-Freigabe · Backup-Manipulation |
| 🌍 GeoIP Intelligence | 6 | Weltkarte · Top-Länder / -Städte / -ASNs nach Anfragevolumen · event_name × Land · Identität × Land |
| 🕒 Temporal Analysis | 6 | Erstes/letztes Auftreten nach Identität/IP/API/Agent · reaktivierte ruhende Konten · Geschwindigkeitsspitzen |
| 🚨 High-Risk API Monitor | 7 | HRM-Zeitreihe · Top-Aufrufe/-Akteure/-IPs · Defense-Evasion-/Credential-Detail · nach Region |

<details markdown="1">
<summary>📋 Vollständige Liste — alle über 80 Diagramme (zum Aufklappen anklicken)</summary>

## Dashboard-Diagramme (Apache Superset — `dashboard/`)

### 🔑 Identity & Access

| # | Diagrammname | Beschreibung |
|---|------------|-------------|
| 1 | Console Login Activity | Konsolen-Anmeldeereignisse gruppiert nach IAM-Identität (DSH-08) |
| 2 | MFA-less Login Trend | Tägliche Konsolen-Logins aufgeteilt nach MFA-Nutzung (DSH-28) |
| 3 | Login Activity Heatmap (Hour × Day) | Konsolen-Login-Zahlen nach Wochentag und Tageszeit in JST (DSH-19) |
| 4 | Sensitive API Calls | Aufrufe bekannter sicherheitsrelevanter AWS-API-Aktionen (DSH-12) |
| 5 | Root Account Usage | Alle API-Aufrufe des AWS-Root-Kontos (DSH-13) |
| 6 | IAM Entity Activity | Top 50 der IAM-Entitäten nach gesamten API-Aufrufen, mit Schreibverhältnis und Fehlerrate |
| 7 | Privilege Escalation Timeline | Tägliche Anzahl von Rechteausweitungs-API-Aufrufen nach Ereignisname (DSH-30) |
| 8 | IAM Identity Center (SSO) Events | AWS-IAM-Identity-Center-Verwaltungsereignisse von sso.amazonaws.com (DSH-44) |
| 9 | Glue & SageMaker Privilege Escalation | Glue-DevEndpoint- und SageMaker-Notebook-Ereignisse, die zur IAM-Rechteausweitung über iam:PassRole genutzt werden (DSH-50) |

### 🎯 Threat Detection

| # | Diagrammname | Beschreibung |
|---|------------|-------------|
| 1 | CloudTrail Events Over Time | Stündliches Lese- vs. Schreibereignisvolumen im Zeitverlauf (DSH-01) |
| 2 | Write/Read Ratio Trend | Stündliche Aufschlüsselung von Lese- vs. Schreib-API-Aufrufen (DSH-20) |
| 3 | Throttling Exception Spikes | Stündliche Throttling-/Ratenbegrenzungsfehler nach AWS-Dienst (DSH-21) |
| 4 | Defense Evasion Events | Alle CloudTrail-Ereignisse, die bekannten Defense-Evasion-Techniken entsprechen (DSH-22) |
| 5 | Top Access Denied Actions | Top 20 der API-Aktionen, die AccessDenied-Fehler zurückgeben (DSH-09) |
| 6 | Error Event Trend | Stündliche Fehlerereignisse aufgeschlüsselt nach error_code (DSH-04) |
| 7 | Organizations / SCP Changes | AWS-Organizations-Verwaltungsereignisse einschließlich SCP-Richtlinienänderungen (DSH-24) |
| 8 | First-Time Service Sources | Alle verschiedenen AWS-Dienstquellen geordnet nach Datum des ersten Auftretens (DSH-26) |
| 9 | VPC Flow Log Changes | Erstellungs- und Löschereignisse von VPC-Flow-Logs (DSH-42) |
| 10 | AWS Config Tampering | Manipulationsereignisse von AWS-Config-Recordern und -Regeln (DSH-43) |
| 11 | Network ACL / Route Table Changes | NACL- und Routing-Tabellen-Änderungsereignisse (DSH-46) |
| 12 | EventBridge / CloudWatch Rule Tampering | Manipulation von EventBridge- und CloudWatch-Events-Regeln (DSH-47) |

### 📊 API Activity

| # | Diagrammname | Beschreibung |
|---|------------|-------------|
| 1 | Top 20 API Calls | Die 20 am häufigsten aufgerufenen AWS-API-Aktionen (DSH-02) |
| 2 | Region Activity | Verteilung von CloudTrail-Ereignissen über AWS-Regionen (DSH-14) |
| 3 | Top Source IP Addresses | Top 100 der externen Quell-IPs nach Anfragenanzahl (DSH-05) |
| 4 | User Agent Analysis | Top 50 der User Agents nach Anfragenanzahl mit Fehler- und Schreibaufschlüsselungen (DSH-11) |
| 5 | Secrets Access Anomaly | Identitäten, die in einer Stunde ≥10-mal auf Secrets Manager oder SSM Parameter Store zugreifen |
| 6 | AssumedRole from External IP | AssumeRole-Aufrufe von öffentlichen (nicht-privaten) IP-Adressen (DSH-27) |
| 7 | Route53 DNS Changes | Änderungen an Route-53-Hosted-Zones und Resolver-Konfigurationen (DSH-29) |

### 🖥️ Computing

| # | Diagrammname | Beschreibung |
|---|------------|-------------|
| 1 | SSM Session / Run Command Execution | AWS-Systems-Manager-Remote-Ausführungsereignisse (DSH-39) |
| 2 | EC2 Public Snapshot / AMI Sharing | EBS-Snapshot- und AMI-Public-Sharing-Ereignisse (DSH-41) |
| 3 | EKS / ECR Container Platform Events | EKS-Cluster- und ECR-Container-Registry-Ereignisse (DSH-48) |
| 4 | ECS Task Definition | Registrierungs- und Service-Update-Ereignisse von ECS-Task-Definitionen — Pacu-ecs__backdoor_task_def-Muster (DSH-49) |
| 5 | EBS Direct API Snapshot Exfiltration | EBS-Direct-API-Aufrufe (ListSnapshotBlocks / GetSnapshotBlock), die zum Streamen von Snapshot-Daten ohne EC2 genutzt werden (DSH-51) |

### 🪣 S3 & RDS

| # | Diagrammname | Beschreibung |
|---|------------|-------------|
| 1 | S3 Protection Config Changes | S3-Ereignisse, die die Sicherheitslage von Buckets schwächen (DSH-25) |
| 2 | S3 Bucket Policy / ACL Changes | S3-Bucket-Richtlinien- und ACL-Änderungsereignisse (DSH-45) |
| 3 | RDS Snapshot Cross-Account Share | RDS- und Aurora-Snapshot-Freigabeereignisse (DSH-40) |
| 4 | S3 Bulk Download | Identitäten, die ≥100 GetObject-Aufrufe pro Stunde durchführen — Muster für automatisierte Datenexfiltration (DSH-52) |
| 5 | S3 Bulk Object Deletion | Identitäten, die ≥50 DeleteObject/DeleteObjects-Aufrufe pro Stunde durchführen — Muster für Ransomware-Datenvernichtung (DSH-53) |
| 6 | S3 Versioning / Logging Disabled | PutBucketVersioning (Suspended) und PutBucketLogging (deaktiviert) — Anti-Forensik-Vorbote der Datenvernichtung (DSH-54) |
| 7 | S3 Cross-Account Replication | PutBucketReplication / DeleteBucketReplication — dauerhafter stiller Exfiltrationskanal zu einem vom Angreifer kontrollierten Konto (DSH-55) |
| 8 | RDS Deleted without Final Snapshot | DeleteDBInstance / DeleteDBCluster mit skipFinalSnapshot=true — nicht wiederherstellbare Datenvernichtung (DSH-56) |
| 9 | AWS Backup Tampering | Löschung von Backup Vault / Plan / RecoveryPoint und Entfernen von Vault Lock — erster Schritt bei Ransomware, um Wiederherstellungsoptionen zu beseitigen (DSH-57) |

### 🌍 GeoIP Intelligence

> Erfordert GeoLite2-`.mmdb`-Dateien. GeoIP-Spalten sind NULL, wenn ohne GeoIP eingelesen wird.

| # | Diagrammname | Beschreibung |
|---|------------|-------------|
| 1 | Global Request Origin Map | Weltkarte, die die geografische Verteilung der Ursprünge von CloudTrail-API-Aufrufen zeigt |
| 2 | Top Countries by Request Volume | Top 20 der Quellländer nach API-Aufrufvolumen mit Aufschlüsselungen nach Schreibereignissen und eindeutigen Aufrufern |
| 3 | Top Cities by Request Volume | Top 25 der Städte nach API-Aufrufvolumen mit Aufschlüsselungen nach Schreibereignissen und eindeutigen Aufrufern |
| 4 | Top ASN Organizations by Request Volume | Top 25 der ASN-Organisationen nach API-Aufrufvolumen |
| 5 | API Calls by Country (Event Name × GeoIP) | Top-50-(event_name, Land)-Paare — zeigt, welche API-Operationen aus jeder geografischen Region aufgerufen werden (DSH-79) |
| 6 | Identities by Country (user_identity_arn × GeoIP) | Top-50-(user_identity_arn, Land)-Paare — bringt IAM-Identitäten zum Vorschein, die aus unerwarteten Ländern aktiv sind, mit Schreibanzahl und erstem/letztem Auftreten (DSH-80) |

### 🕒 Temporal Analysis

| # | Diagrammname | Beschreibung |
|---|------------|-------------|
| 1 | First / Last Seen per IAM Identity | IAM-Identitäten mit Zeitstempeln für erstes/letztes Auftreten, Ereigniszahlen und verschiedenen APIs |
| 2 | First / Last Seen per Source IP | Quell-IPs mit erstem/letztem Auftreten, verschiedenen Identitäten und verschiedenen APIs |
| 3 | First / Last Seen per API Call | API-Aktionen geordnet nach erstem Auftreten — neue Aufrufe können auf neuartige Angriffswerkzeuge hindeuten (DSH-33) |
| 4 | First / Last Seen per User Agent | User Agents geordnet nach erstem Auftreten — Erkennung neuer Werkzeuge (DSH-34) |
| 5 | Dormant Accounts Reactivated | Identitäten mit Inaktivitätslücken von 72+ Stunden, die ihre Aktivität wieder aufgenommen haben (DSH-37) |
| 6 | Event Velocity Spikes per Identity | Identitäten mit Burst-Aktivität von 50+ Ereignissen pro Stunde (DSH-38) |

### 🚨 High-Risk API Monitor (HRM)

| # | Diagrammname | Beschreibung |
|---|------------|-------------|
| 1 | High-Risk API Events Over Time | Tägliches Aufrufvolumen für APIs, die häufig in Angriffskampagnen beobachtet werden (HRM-39) |
| 2 | Top High-Risk API Calls | API-Aktionen von der Hochrisiko-Watchlist, eingestuft nach gesamter Aufrufanzahl (HRM-40) |
| 3 | Top Actors — High-Risk APIs | IAM-Principals, eingestuft nach gesamten Aufrufen von Hochrisiko-Watchlist-APIs (HRM-42) |
| 4 | Top Source IPs — High-Risk APIs | Quell-IPs, eingestuft nach gesamten Aufrufen von Hochrisiko-Watchlist-APIs (HRM-43) |
| 5 | Defense Evasion API Events | Detailliertes Ereignisprotokoll für APIs, die zum Deaktivieren oder Manipulieren von Audit-Kontrollen genutzt werden (HRM-44) |
| 6 | Credential Access API Events | Detailliertes Ereignisprotokoll für APIs, die zum Abrufen von Secrets und Anmeldeinformationen genutzt werden (HRM-45) |
| 7 | High-Risk API Calls by Region | Hochrisiko-Watchlist-API-Aufrufe verteilt nach AWS-Region (HRM-46) |

</details>

---
