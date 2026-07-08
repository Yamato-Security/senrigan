# Referencia de consultas y paneles integrados

> 💡 No se requiere SQL ni conocimientos profundos de AWS — simplemente selecciona una búsqueda del menú desplegable y obtén resultados al instante.

## 🎯 Búsquedas integradas — más de 100 consultas

Las categorías están ordenadas por prioridad de triaje DFIR — primero verifica la manipulación de herramientas de detección, luego el abuso de identidad y, por último, el impacto sobre los datos.

| Categoría | Consultas | Principales amenazas cubiertas |
|----------|:-------:|---------------------|
| 🛡 Detección y respuesta | 12 | Manipulación de servicios de auditoría (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · eliminación de SCP · supresión de alarmas · exfiltración de registros |
| 🔑 Identidad y acceso | 26 | Uso de root · inicio de sesión en consola/MFA · escalada de privilegios · puerta trasera en política de confianza · abuso de PassRole · AssumeRole entre cuentas · SSO/SAML/OIDC · enumeración de credenciales |
| 🪣 Datos y almacenamiento | 21 | Eliminación/descarga masiva en S3 · lectura masiva de secretos · manipulación de copias de seguridad · operaciones de KMS · uso compartido de instantáneas · exfiltración por EBS Direct API · exportación de DynamoDB · replicación entre cuentas de S3 |
| ⚡ Cómputo y serverless | 14 | Detención/terminación masiva de EC2 · movimiento lateral por SSM · manipulación de Lambda/ECS/EKS/ECR · persistencia por EventBridge · criptominería · abuso de Lightsail |
| 🌐 Red e infraestructura | 14 | SG abierto a Internet · eliminación de registros de flujo de VPC · secuestro de CloudFront · túneles encubiertos VPN/TGW · IP elástica para C2 · claves de API Gateway |
| 🕵 Patrones de amenaza | 5 | Escrituras fuera de horario · ráfaga de reconocimiento · propagación multirregión · agentes de usuario inusuales · primeras llamadas a la API |
| 📊 Actividad y línea base | 3 | Eventos de escritura en consola · picos de errores · errores recientes |
| 🌍 Análisis GeoIP ✦ | 12 | Viaje imposible · credenciales en varios países · inicios de sesión/denegaciones/escrituras clasificados por geografía · desglose por país/ciudad/ASN · event_name × país · identidad × país |
| ☁ IaC y plataforma | 2 | Cadena de suministro CI/CD · abuso de CloudFormation |

<details markdown="1">
<summary>📋 Lista completa — todas las más de 100 consultas (haz clic para expandir)</summary>

## Búsquedas integradas

### 🛡 Detección y respuesta

| # | Etiqueta | Gráfico | Descripción |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | Detecta cualquier intento de detener o modificar CloudTrail — el indicador de encubrimiento más crítico |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | Detecta la desactivación, eliminación y manipulación de inteligencia de amenazas de GuardDuty |
| 3 | ⛔ Security Hub Tampering | timeseries | Detecta la desactivación de Security Hub, la desactivación de estándares y la supresión de hallazgos |
| 4 | ⚙️ AWS Config Tampering | timeseries | Detecta la eliminación de grabadores/reglas de AWS Config (elimina evidencia de cumplimiento) |
| 5 | 🛡 Organizations SCP Changes | timeseries | Detecta la creación, actualización y eliminación de SCP — eliminar una SCP de tipo Deny elimina las barreras de protección en todas las cuentas de la OU |
| 6 | 🚫 AWS Macie Tampering | timeseries | Detecta la desactivación de Macie y la creación de filtros de hallazgos (evasión de defensas previa a la exfiltración) |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | Detecta la eliminación de alarmas y DisableAlarmActions — silencia las alertas de seguridad sin eliminar la alarma |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | Detecta la creación/eliminación de filtros de suscripción de CW Logs (exfiltración de registros en tiempo real a Kinesis/Lambda del atacante) |
| 9 | 🏹 WAF WebACL Changes | timeseries | Detecta la creación, actualización y eliminación de WAF WebACL en WAFv2/WAF Classic |
| 10 | 🔍 GuardDuty Findings Read | timeseries | Detecta ListFindings / GetFindings — el atacante lee los hallazgos activos para entender qué ha detectado ya el SOC |
| 11 | 💰 Budget / Cost Anomaly Changes | timeseries | Detecta la eliminación de Budget/AnomalyMonitor (ocultar costos de criptominería) |
| 12 | 🚫 Access Denied Errors | bar | Agrupa los errores AccessDenied por identidad y API — los principales infractores indican uso indebido de credenciales |

### 🔑 Identidad y acceso

| # | Etiqueta | Gráfico | Descripción |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | Detecta cualquier llamada a la API realizada por la cuenta root — root nunca debería usarse en producción |
| 2 | 🔓 Console Login without MFA | timeseries | Detecta inicios de sesión en consola donde no se usó MFA — indicador de alto riesgo de compromiso de la cuenta |
| 3 | 🌐 Console Logins | timeseries | Lista todos los intentos de inicio de sesión en consola, incluidos éxitos y fallos (detección de fuerza bruta) |
| 4 | 🔐 MFA & Password Changes | timeseries | Detecta la desactivación de MFA y los restablecimientos de contraseña — fuerte indicador de toma de control de la cuenta |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | Detecta la asociación de políticas de IAM y la manipulación de roles (PutUserPolicy, AttachRolePolicy, CreatePolicyVersion, etc.) |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | Detecta UpdateAssumeRolePolicy — agregar entidades principales externas a una política de confianza crea una puerta trasera persistente |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | Detecta eventos de creación/eliminación de límites de permisos — eliminar un límite expande de inmediato los permisos efectivos |
| 8 | 👑 User Added to Admin Group | timeseries | Detecta usuarios agregados a grupos con 'admin' en el nombre — escalada de privilegios clásica |
| 9 | 👥 IAM Group Membership Changes | timeseries | Detecta todos los eventos AddUserToGroup / RemoveUserFromGroup / CreateGroup / DeleteGroup independientemente del nombre del grupo |
| 10 | 👤 New IAM Users / Keys | timeseries | Identifica eventos de creación de usuarios IAM y claves de acceso — una creación inesperada puede indicar persistencia |
| 11 | 🎯 IAM PassRole Abuse | timeseries | Detecta el uso de iam:PassRole inspeccionando los eventos del servicio receptor (RunInstances, CreateFunction, CreateNotebookInstance, etc.) donde se pasa un ARN de rol |
| 12 | 🔐 AssumeRole Cross-Account | timeseries | Muestra eventos AssumeRole donde el llamante y el destino están en cuentas de AWS diferentes (movimiento lateral) |
| 13 | 🏢 Cross-Account Access | timeseries | Encuentra todos los eventos donde la cuenta del llamante difiere de la cuenta destinataria |
| 14 | 🔑 STS Federation Token Issuance | timeseries | Detecta GetFederationToken y GetSessionToken — convierte claves de larga duración en credenciales temporales persistentes |
| 15 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | Detecta el abuso de confianza OIDC (reclamo sub mal configurado / GitHub Actions sin condición de repositorio) |
| 16 | 🆔 IAM Identity Center (SSO) Events | timeseries | Detecta acciones de administración de AWS IAM Identity Center (CreatePermissionSet, CreateAccountAssignment, etc.) |
| 17 | 🔗 SAML / OIDC Provider Updates | timeseries | Detecta cambios en proveedores de identidad SAML/OIDC — actualizar los metadatos SAML con un IdP controlado por el atacante crea una puerta trasera de autenticación persistente |
| 18 | 🧐 IAM Access Analyzer Calls | timeseries | Detecta cualquier uso de IAM Access Analyzer — los atacantes aprovechan el analizador nativo para enumerar recursos accesibles externamente sin scripts de reconocimiento personalizados |
| 19 | 🔄 Credential Report & Enumeration | timeseries | Detecta la enumeración de IAM (GenerateCredentialReport, ListUsers, ListRoles, GetAccountAuthorizationDetails, etc.) |
| 20 | 🗝 Access Key Abuse | bar | Detecta claves de acceso usadas desde 3 o más IP de origen distintas en 7 días — fuerte indicador de filtración de claves |
| 21 | 📰 AWS Organizations Account Creation | timeseries | Detecta la creación de cuentas de Organizations y los cambios de administrador delegado (persistencia mediante cuentas en la sombra) |
| 22 | 👥 Cognito Unauthenticated Access | timeseries | Detecta grupos de identidades de Cognito con allowUnauthenticatedIdentities=true |
| 23 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | Detecta la creación de Glue DevEndpoint (iam:PassRole + glue:CreateDevEndpoint = endpoint accesible por SSH que se ejecuta con todos los permisos del rol pasado) y la enumeración de conexiones para recolección de credenciales |
| 24 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | Detecta la creación de notebooks de SageMaker y la generación de URL prefirmadas — iam:PassRole + sagemaker:CreateNotebookInstance lanza un entorno Jupyter con todos los permisos de AWS del rol pasado |
| 25 | 🛠 Data Pipeline / CodeStar Privilege Escalation | timeseries | Detecta la creación de recursos de Data Pipeline y CodeStar usada para escalada mediante iam:PassRole (CreateProjectFromTemplate crea un rol de IAM de administrador como efecto secundario) |
| 26 | 🧩 Step Functions Privilege Escalation | timeseries | Detecta la creación de máquinas de estado de Step Functions (iam:PassRole + states:CreateStateMachine ejecuta tareas de Lambda/ECS bajo el rol pasado) |

### 🪣 Datos y almacenamiento

| # | Etiqueta | Gráfico | Descripción |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | Detecta identidades que realizan ≥50 llamadas DeleteObject/DeleteObjects por hora — patrón de destrucción de datos por ransomware / wiper |
| 2 | 🔥 AWS Backup Tampering | timeseries | Detecta la eliminación de Backup Vault / Plan / RecoveryPoint y la eliminación de Vault Lock — primer paso del ransomware para eliminar opciones de recuperación |
| 3 | 🔓 KMS Key Operations | timeseries | Marca operaciones sensibles de KMS (DisableKey, ScheduleKeyDeletion, CreateGrant, PutKeyPolicy, Decrypt de alto volumen) |
| 4 | 🔓 S3 Public Access Block Disabled | — | Detecta la desactivación de la configuración de bloqueo de acceso público de S3 — riesgo inmediato de exposición de datos |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | Detecta modificaciones de políticas y ACL de buckets de S3 (PutBucketPolicy con Principal='*' es especialmente crítico) |
| 6 | 🪣 S3 Data Access Anomalies | bar | Detecta llamadas masivas GetObject (≥100/hora) — patrón de exfiltración de datos automatizada |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | Detecta identidades que recuperan ≥10 secretos distintos en una hora — señal de recolección de credenciales |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | Detecta la eliminación de secretos, PutResourcePolicy (uso compartido entre cuentas) y CancelRotateSecret |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | Detecta identidades que leen ≥20 parámetros en una hora — un canal de exfiltración a menudo pasado por alto |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | Detecta instantáneas de RDS/Aurora compartidas con cuentas de AWS externas (exfiltración de bases de datos mediante instantáneas) |
| 11 | 💣 RDS Deleted without Final Snapshot | — | Detecta la eliminación de RDS con skipFinalSnapshot=true — posible destrucción de datos |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | Detecta instancias de RDS creadas o modificadas con publiclyAccessible=true |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | Detecta ExportTableToPointInTime (exportación completa de tabla del lado del servidor que evita el DLP de GetItem), DeleteTable y la desactivación de PITR |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | Detecta EBS Direct API (ListSnapshotBlocks / GetSnapshotBlock) — Pacu ebs__download_snapshots transmite datos brutos de instantáneas sin EC2, evitando la detección de ModifySnapshotAttribute |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | Detecta la creación/actualización de flujos de entrega de Firehose que apuntan a S3 externo — canal de datos en tiempo real invisible al DLP de red |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | Detecta PutBucketReplication — copia silenciosamente todos los objetos nuevos a un bucket controlado por el atacante sin generar eventos GetObject adicionales |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | Detecta la suspensión del control de versiones (habilita la eliminación permanente) y la desactivación del registro de acceso al servidor (elimina el rastro de evidencia) |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | Detecta cambios en las reglas de recepción y la configuración de identidades de SES — las reglas de reenvío retransmiten todo el correo entrante a direcciones del atacante; las identidades verificadas habilitan campañas de phishing |
| 19 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | Detecta cambios de políticas de SQS/SNS que otorgan acceso a cuentas externas (transmisión silenciosa de mensajes a endpoints del atacante) |
| 20 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | Detecta instantáneas de EBS o AMI compartidas públicamente (group=all) — permite que cualquiera copie las imágenes de disco y extraiga datos |
| 21 | 📧 Data Exfiltration Channels | bar | Detecta llamadas de alto volumen SNS/SQS/SES/S3 PutObject (≥50/hora) desde una sola identidad |

### ⚡ Cómputo y serverless

| # | Etiqueta | Gráfico | Descripción |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | Detecta identidades que realizan ≥5 StopInstances/TerminateInstances en una hora — indicador de ransomware / wiper |
| 2 | 🖥️ SSM Session / Run Command | timeseries | Detecta SSM StartSession, SendCommand y StartAutomationExecution — vía principal de movimiento lateral mediante instancias administradas |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | Detecta SendSSHPublicKey y SendSerialConsoleSSHPublicKey — evita los pares de claves de EC2 (válidos 60 segundos, no deja artefactos de claves SSH) |
| 4 | 📝 EC2 User Data Modification | timeseries | Detecta ModifyInstanceAttribute con cambio de userData — el script se ejecuta como root en el siguiente arranque |
| 5 | ⚡ Lambda Function Tampering | timeseries | Detecta la creación de Lambda, las actualizaciones de código (UpdateFunctionCode) y los cambios de permisos (AddPermission) |
| 6 | 📦 Lambda Layer Addition | timeseries | Detecta la publicación de capas de Lambda y AddLayerVersionPermission con entidad principal comodín (ataque público a la cadena de suministro) |
| 7 | 📦 ECS Task Definition  | timeseries | Detecta RegisterTaskDefinition / UpdateService — Pacu ecs__backdoor_task_def inyecta un contenedor sidecar malicioso sin tocar ECR |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | Detecta AssociateIamInstanceProfile / ReplaceIamInstanceProfileAssociation — adjunta un perfil privilegiado que habilita el movimiento lateral |
| 9 | 🖥 EC2 Instance Launches | timeseries | Lista todos los eventos RunInstances incluyendo tipo de instancia, cantidad, nombre de clave y AMI (detección de criptominería) |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | Detecta solicitudes grandes de Spot Fleet (ec2) y la creación de grupos de Auto Scaling con alta capacidad (autoscaling) — indicador de impacto financiero por criptominería |
| 11 | ☸️ EKS Cluster API Calls | timeseries | Detecta modificaciones del plano de control de clústeres de EKS (exposición del servidor de API público, perfiles de Fargate fraudulentos) |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | Detecta eventos de repositorios/imágenes de ECR (PutImage etiquetado como 'latest' envenena todas las implementaciones posteriores) |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | Detecta modificaciones de reglas de EventBridge y Scheduler (PutRule, CreateSchedule) — establece persistencia sin un proceso en ejecución |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | Detecta la recuperación de claves de Lightsail, la exposición de puertos y el acceso a instancias — Pacu lightsail__download_ssh_keys / lightsail__generate_temp_access |

### 🌐 Red e infraestructura

| # | Etiqueta | Gráfico | Descripción |
|---|-------|:-----:|-------------|
| 1 | 🌍 Security Group Opened to Internet | timeseries | Encuentra reglas de grupos de seguridad que permiten tráfico desde 0.0.0.0/0 — riesgo de exposición pública directa |
| 2 | 🔥 Security Group Modifications | timeseries | Detecta todos los cambios de reglas de grupos de seguridad (AuthorizeSecurityGroupIngress, ModifySecurityGroupRules, etc.) |
| 3 | 🌊 VPC Flow Log Changes | timeseries | Detecta la eliminación de registros de flujo de VPC — eliminar los registros de flujo elimina la evidencia forense de red principal |
| 4 | 🌐 CloudFront Distribution Tampering | timeseries | Detecta cambios de origen de CloudFront que redirigen todo el tráfico de la CDN a servidores controlados por el atacante (MitM) |
| 5 | 🛡 Network Firewall / Shield Tampering | timeseries | Detecta la eliminación de la protección de Network Firewall y Shield — expone rangos completos de subredes al tráfico de ataque |
| 6 | 🧱 Network ACL Changes | timeseries | Detecta la creación, eliminación y reemplazo de entradas de NACL — las NACL anulan los grupos de seguridad a nivel de subred |
| 7 | 🛣️ Route Table Changes | timeseries | Detecta modificaciones de tablas de rutas — los atacantes redirigen el tráfico a gateways maliciosos para interceptación o C2 |
| 8 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | Detecta nuevas conexiones VPN y asociaciones de Transit Gateway — crea rutas de red persistentes de capa 3 para C2 o exfiltración |
| 9 | 📡 Elastic IP Allocation / Association | timeseries | Detecta la asignación/asociación de IP elásticas — asigna una IP pública fija a instancias comprometidas para una infraestructura de C2 estable |
| 10 | 🗝️ EC2 Key Pair Creation | timeseries | Detecta CreateKeyPair e ImportKeyPair — el atacante crea claves SSH para acceso persistente a instancias |
| 11 | 📡 Network Infrastructure Changes | timeseries | Detecta cambios de VPC / subred / IGW / NAT Gateway / emparejamiento que pueden establecer infraestructura controlada por el atacante |
| 12 | 🏷 ACM Certificate Operations | timeseries | Detecta solicitudes y eliminaciones de certificados de ACM — las cuentas comprometidas pueden emitir certificados TLS para dominios de phishing |
| 13 | 🔑 API Gateway Key Creation & Management | timeseries | Detecta la creación de claves de API Gateway y los cambios de autorizadores — Pacu api_gateway__create_api_keys genera credenciales persistentes que sobreviven a la rotación de claves de IAM |
| 14 | 🚧 VPC Endpoint Access Denied | timeseries | Detecta errores de acceso denegado mediante endpoints de VPC — puede indicar una política de endpoint mal configurada |

### 🕵 Patrones de amenaza

| # | Etiqueta | Gráfico | Descripción |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | Identifica llamantes que ejecutaron 10 o más API Describe*/List*/Get* distintas en una hora — fase temprana común de un ataque |
| 2 | 🤖 Unusual User Agents | bar | Lista agentes de usuario raros (<5 eventos) o herramientas de atacante conocidas (Pacu, curl, wget) — puede indicar herramientas de ataque |
| 3 | 🌍 Multi-Region Activity | bar | Detecta identidades que realizan escrituras en 3 o más regiones en un día — la dispersión geográfica puede indicar compromiso |
| 4 | 🕵 First-Time API Calls (24h) | — | Encuentra llamadas a la API vistas en las últimas 24 h pero nunca antes — operaciones novedosas pueden indicar herramientas de atacante |

### 📊 Actividad y línea base

| # | Etiqueta | Gráfico | Descripción |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | Identifica llamadas a la API que mutan estado realizadas mediante la consola de AWS — útil cuando se espera acceso solo por CLI |
| 2 | 🔍 Events with Errors (24h) | timeseries | Lista todos los eventos de error de las últimas 24 horas — vista rápida de qué está fallando o siendo sondeado |
| 3 | ❌ Error Spike Detection | — | Encuentra ventanas de 1 hora donde el recuento de errores supera el promedio diario en 3× |

### 🌍 Análisis GeoIP

> Requiere archivos GeoLite2 `.mmdb` para la población (las columnas son NULL si se ingieren sin GeoIP).

| # | Etiqueta | Gráfico | Descripción |
|---|-------|:-----:|-------------|
| 1 | 🕵 Impossible Travel Detection | — | Detecta la misma identidad llamando a la API desde ciudades distantes en menos de 2 horas — fuerte indicador de compromiso de credenciales |
| 2 | ⚠ Identity Multi-Country Access | bar | Encuentra identidades que realizan llamadas a la API desde 2 o más países — los usuarios legítimos rara vez operan desde varios países simultáneamente |
| 3 | 🗺 Console Logins by Country | timeseries | Mapea los eventos de inicio de sesión en consola a su origen geográfico — los inicios de sesión desde países inesperados son de alto riesgo |
| 4 | 🚨 Unusual Country Access | bar | Detecta combinaciones raras de país/identidad (<10 eventos) — el acceso extranjero de bajo volumen puede ser infraestructura del atacante |
| 5 | 🚫 Access Denied by Country | bar | Agrupa los errores de acceso denegado por país de origen — denegaciones concentradas desde un país pueden señalar un ataque |
| 6 | 🔍 Write Events by Country | bar | Muestra las llamadas a la API que mutan estado agrupadas por país de origen — las escrituras desde países inesperados son una señal más fuerte que las lecturas |
| 7 | 🌍 Top Source Countries | bar | Clasifica los países de origen por volumen de llamadas a la API con desgloses de eventos de escritura e identidades únicas |
| 8 | 🏢 Top ASN / Organizations | bar | Lista los sistemas autónomos (ISP/proveedores de nube) por volumen de llamadas a la API — los ASN de VPN/hosting pueden indicar infraestructura del atacante |
| 9 | 📍 Top Source Cities | bar | Clasifica las ciudades de origen por volumen de eventos — los datos a nivel de ciudad identifican infraestructura específica del atacante o ubicaciones de oficinas |
| 10 | 🌐 Private / Internal IP Summary | bar | Resume los eventos desde IP privadas/loopback/internas de AWS — línea base del tráfico interno esperado |
| 11 | 📋 API Calls by Country (Event Name) | table | Principales pares (event_name, país) por volumen de llamadas — revela qué operaciones de la API se originan desde regiones geográficas inesperadas |
| 12 | 👤 Identities by Country (user_identity_arn) | table | Principales pares (user_identity_arn, país) por volumen de llamadas — saca a la luz identidades de IAM activas desde países inesperados con primera/última vez vistas |

### ☁ IaC y plataforma

| # | Etiqueta | Gráfico | Descripción |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | Detecta la creación y modificación de pipelines CI/CD (UpdateProject inyecta pasos de compilación maliciosos en cada compilación posterior) |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | Detecta operaciones de pilas de CloudFormation — los atacantes pueden usar IaC para implementar rápidamente infraestructura maliciosa |

</details>

---

## 📊 Gráficos de panel — más de 80 gráficos

| Pestaña | Gráficos | Lo que muestra |
|-----|:------:|---------------|
| 🔑 Identidad y acceso | 9 | Inicios de sesión en consola · tendencia de MFA · mapa de calor de inicios de sesión · API sensibles · uso de root · actividad de entidades de IAM · escalada de privilegios · SSO/privesc |
| 🎯 Detección de amenazas | 12 | Volumen de eventos · relación lectura/escritura · evasión de defensas · acceso denegado · tendencia de errores · manipulación de SCP/Config/NACL/EventBridge |
| 📊 Actividad de la API | 7 | Principales API · distribución por región · IP de origen · agentes de usuario · anomalía de secretos · AssumeRole externo · cambios de Route53 |
| 🖥️ Cómputo | 5 | Ejecución de SSM · instantánea pública de EC2 · eventos de EKS/ECR · puerta trasera de ECS · exfiltración por EBS Direct API |
| 🪣 S3 y RDS | 9 | Política/ACL de S3 · descarga/eliminación masiva · control de versiones/registro desactivado · replicación entre cuentas · uso compartido de instantáneas de RDS · manipulación de copias de seguridad |
| 🌍 Inteligencia GeoIP | 6 | Mapa mundial · principales países / ciudades / ASN por volumen de solicitudes · event_name × país · identidad × país |
| 🕒 Análisis temporal | 6 | Primera/última vez visto por identidad/IP/API/agente · cuentas inactivas reactivadas · picos de velocidad |
| 🚨 Monitor de API de alto riesgo | 7 | Serie temporal de HRM · principales llamadas/actores/IP · detalle de evasión de defensas/acceso a credenciales · por región |

<details markdown="1">
<summary>📋 Lista completa — todos los más de 80 gráficos (haz clic para expandir)</summary>

## Gráficos de panel (Apache Superset — `dashboard/`)

### 🔑 Identidad y acceso

| # | Nombre del gráfico | Descripción |
|---|------------|-------------|
| 1 | Console Login Activity | Eventos de inicio de sesión en consola agrupados por identidad de IAM (DSH-08) |
| 2 | MFA-less Login Trend | Inicios de sesión diarios en consola divididos por uso de MFA (DSH-28) |
| 3 | Login Activity Heatmap (Hour × Day) | Recuentos de inicios de sesión en consola por día de la semana y hora del día en JST (DSH-19) |
| 4 | Sensitive API Calls | Invocaciones de acciones conocidas de la API de AWS sensibles a la seguridad (DSH-12) |
| 5 | Root Account Usage | Todas las llamadas a la API realizadas por la cuenta Root de AWS (DSH-13) |
| 6 | IAM Entity Activity | Las 50 principales entidades de IAM clasificadas por total de llamadas a la API, con relación de escritura y tasa de error |
| 7 | Privilege Escalation Timeline | Recuentos diarios de llamadas a la API de escalada de privilegios por nombre de evento (DSH-30) |
| 8 | IAM Identity Center (SSO) Events | Eventos de administración de AWS IAM Identity Center desde sso.amazonaws.com (DSH-44) |
| 9 | Glue & SageMaker Privilege Escalation | Eventos de Glue DevEndpoint y SageMaker Notebook usados para escalada de privilegios de IAM mediante iam:PassRole (DSH-50) |

### 🎯 Detección de amenazas

| # | Nombre del gráfico | Descripción |
|---|------------|-------------|
| 1 | CloudTrail Events Over Time | Volumen de eventos de lectura vs escritura por hora a lo largo del tiempo (DSH-01) |
| 2 | Write/Read Ratio Trend | Desglose por hora de llamadas a la API de lectura vs escritura (DSH-20) |
| 3 | Throttling Exception Spikes | Errores de limitación/límite de tasa por hora por servicio de AWS (DSH-21) |
| 4 | Defense Evasion Events | Todos los eventos de CloudTrail que coinciden con técnicas conocidas de evasión de defensas (DSH-22) |
| 5 | Top Access Denied Actions | Las 20 principales acciones de la API que devuelven errores AccessDenied (DSH-09) |
| 6 | Error Event Trend | Eventos de error por hora desglosados por error_code (DSH-04) |
| 7 | Organizations / SCP Changes | Eventos de administración de AWS Organizations incluyendo cambios de políticas SCP (DSH-24) |
| 8 | First-Time Service Sources | Todas las fuentes de servicios de AWS distintas ordenadas por fecha de primera aparición (DSH-26) |
| 9 | VPC Flow Log Changes | Eventos de creación y eliminación de registros de flujo de VPC (DSH-42) |
| 10 | AWS Config Tampering | Eventos de manipulación de grabadores y reglas de AWS Config (DSH-43) |
| 11 | Network ACL / Route Table Changes | Eventos de modificación de NACL y tablas de rutas (DSH-46) |
| 12 | EventBridge / CloudWatch Rule Tampering | Manipulación de reglas de EventBridge y CloudWatch Events (DSH-47) |

### 📊 Actividad de la API

| # | Nombre del gráfico | Descripción |
|---|------------|-------------|
| 1 | Top 20 API Calls | Las 20 acciones de la API de AWS llamadas con mayor frecuencia (DSH-02) |
| 2 | Region Activity | Distribución de eventos de CloudTrail entre regiones de AWS (DSH-14) |
| 3 | Top Source IP Addresses | Las 100 principales IP de origen externas por recuento de solicitudes (DSH-05) |
| 4 | User Agent Analysis | Los 50 principales agentes de usuario por recuento de solicitudes con desgloses de errores y escrituras (DSH-11) |
| 5 | Secrets Access Anomaly | Identidades que acceden a Secrets Manager o SSM Parameter Store ≥10 veces en una hora |
| 6 | AssumedRole from External IP | Llamadas AssumeRole desde direcciones IP públicas (no privadas) (DSH-27) |
| 7 | Route53 DNS Changes | Cambios de configuración de zonas alojadas y resolutores de Route 53 (DSH-29) |

### 🖥️ Cómputo

| # | Nombre del gráfico | Descripción |
|---|------------|-------------|
| 1 | SSM Session / Run Command Execution | Eventos de ejecución remota de AWS Systems Manager (DSH-39) |
| 2 | EC2 Public Snapshot / AMI Sharing | Eventos de uso compartido público de instantáneas de EBS y AMI (DSH-41) |
| 3 | EKS / ECR Container Platform Events | Eventos de clústeres de EKS y registro de contenedores de ECR (DSH-48) |
| 4 | ECS Task Definition | Eventos de registro de definiciones de tareas de ECS y actualización de servicios — patrón Pacu ecs__backdoor_task_def (DSH-49) |
| 5 | EBS Direct API Snapshot Exfiltration | Llamadas a EBS Direct API (ListSnapshotBlocks / GetSnapshotBlock) usadas para transmitir datos de instantáneas sin EC2 (DSH-51) |

### 🪣 S3 y RDS

| # | Nombre del gráfico | Descripción |
|---|------------|-------------|
| 1 | S3 Protection Config Changes | Eventos de S3 que debilitan la postura de seguridad del bucket (DSH-25) |
| 2 | S3 Bucket Policy / ACL Changes | Eventos de modificación de políticas y ACL de buckets de S3 (DSH-45) |
| 3 | RDS Snapshot Cross-Account Share | Eventos de uso compartido de instantáneas de RDS y Aurora (DSH-40) |
| 4 | S3 Bulk Download | Identidades que realizan ≥100 llamadas GetObject por hora — patrón de exfiltración de datos automatizada (DSH-52) |
| 5 | S3 Bulk Object Deletion | Identidades que realizan ≥50 llamadas DeleteObject/DeleteObjects por hora — patrón de destrucción de datos por ransomware (DSH-53) |
| 6 | S3 Versioning / Logging Disabled | PutBucketVersioning (Suspended) y PutBucketLogging (desactivado) — precursor antiforense de la destrucción de datos (DSH-54) |
| 7 | S3 Cross-Account Replication | PutBucketReplication / DeleteBucketReplication — canal de exfiltración silencioso persistente hacia una cuenta controlada por el atacante (DSH-55) |
| 8 | RDS Deleted without Final Snapshot | DeleteDBInstance / DeleteDBCluster con skipFinalSnapshot=true — destrucción de datos irrecuperable (DSH-56) |
| 9 | AWS Backup Tampering | Eliminación de Backup Vault / Plan / RecoveryPoint y eliminación de Vault Lock — primer paso del ransomware para eliminar opciones de recuperación (DSH-57) |

### 🌍 Inteligencia GeoIP

> Requiere archivos GeoLite2 `.mmdb`. Las columnas de GeoIP son NULL si se ingieren sin GeoIP.

| # | Nombre del gráfico | Descripción |
|---|------------|-------------|
| 1 | Global Request Origin Map | Mapa mundial que muestra la distribución geográfica de los orígenes de las llamadas a la API de CloudTrail |
| 2 | Top Countries by Request Volume | Los 20 principales países de origen por volumen de llamadas a la API con desgloses de eventos de escritura y llamantes únicos |
| 3 | Top Cities by Request Volume | Las 25 principales ciudades por volumen de llamadas a la API con desgloses de eventos de escritura y llamantes únicos |
| 4 | Top ASN Organizations by Request Volume | Las 25 principales organizaciones ASN por volumen de llamadas a la API |
| 5 | API Calls by Country (Event Name × GeoIP) | Los 50 principales pares (event_name, país) — revela qué operaciones de la API se llaman desde cada región geográfica (DSH-79) |
| 6 | Identities by Country (user_identity_arn × GeoIP) | Los 50 principales pares (user_identity_arn, país) — saca a la luz identidades de IAM activas desde países inesperados con recuento de escrituras y primera/última vez vistas (DSH-80) |

### 🕒 Análisis temporal

| # | Nombre del gráfico | Descripción |
|---|------------|-------------|
| 1 | First / Last Seen per IAM Identity | Identidades de IAM con marcas de tiempo de primera/última vez vistas, recuentos de eventos y API distintas |
| 2 | First / Last Seen per Source IP | IP de origen con primera/última vez vistas, identidades distintas y API distintas |
| 3 | First / Last Seen per API Call | Acciones de la API ordenadas por primera aparición — las nuevas llamadas pueden indicar herramientas de ataque novedosas (DSH-33) |
| 4 | First / Last Seen per User Agent | Agentes de usuario ordenados por primera aparición — detección de herramientas nuevas (DSH-34) |
| 5 | Dormant Accounts Reactivated | Identidades con brechas de inactividad de 72+ horas que reanudaron la actividad (DSH-37) |
| 6 | Event Velocity Spikes per Identity | Identidades con actividad en ráfaga de 50+ eventos por hora (DSH-38) |

### 🚨 Monitor de API de alto riesgo (HRM)

| # | Nombre del gráfico | Descripción |
|---|------------|-------------|
| 1 | High-Risk API Events Over Time | Volumen diario de llamadas para API observadas comúnmente en campañas de ataque (HRM-39) |
| 2 | Top High-Risk API Calls | Acciones de la API de la lista de vigilancia de alto riesgo clasificadas por recuento total de llamadas (HRM-40) |
| 3 | Top Actors — High-Risk APIs | Entidades principales de IAM clasificadas por total de llamadas a las API de la lista de vigilancia de alto riesgo (HRM-42) |
| 4 | Top Source IPs — High-Risk APIs | IP de origen clasificadas por total de llamadas a las API de la lista de vigilancia de alto riesgo (HRM-43) |
| 5 | Defense Evasion API Events | Registro detallado de eventos para API usadas para desactivar o manipular controles de auditoría (HRM-44) |
| 6 | Credential Access API Events | Registro detallado de eventos para API usadas para recuperar secretos y credenciales (HRM-45) |
| 7 | High-Risk API Calls by Region | Llamadas a la API de la lista de vigilancia de alto riesgo distribuidas por región de AWS (HRM-46) |

</details>

---
