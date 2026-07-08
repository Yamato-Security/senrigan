# Referência de Consultas e Painéis Integrados

> 💡 Não é necessário SQL nem conhecimento avançado de AWS — basta selecionar uma caça no menu suspenso e obter resultados instantaneamente.

## 🎯 Caças Integradas — mais de 100 consultas

As categorias são ordenadas por prioridade de triagem DFIR — verifique primeiro a adulteração de ferramentas de detecção, depois o abuso de identidade e, em seguida, o impacto sobre os dados.

| Categoria | Consultas | Principais Ameaças Cobertas |
|----------|:-------:|---------------------|
| 🛡 Detecção e Resposta | 12 | Adulteração de serviços de auditoria (CloudTrail/GuardDuty/Config/SecurityHub/Macie) · exclusão de SCP · supressão de alarmes · exfiltração de logs |
| 🔑 Identidade e Acesso | 26 | Uso de root · login no console/MFA · escalonamento de privilégios · backdoor em política de confiança · abuso de PassRole · AssumeRole entre contas · SSO/SAML/OIDC · enumeração de credenciais |
| 🪣 Dados e Armazenamento | 21 | Exclusão/download em massa no S3 · leitura em massa de segredos · adulteração de backup · operações de KMS · compartilhamento de snapshots · exfiltração via EBS Direct API · exportação do DynamoDB · replicação entre contas no S3 |
| ⚡ Computação e Serverless | 14 | Parada/encerramento em massa de EC2 · movimentação lateral via SSM · adulteração de Lambda/ECS/EKS/ECR · persistência via EventBridge · cryptomining · abuso do Lightsail |
| 🌐 Rede e Infraestrutura | 14 | SG aberto à internet · exclusão de logs de fluxo da VPC · sequestro de CloudFront · túneis VPN/TGW ocultos · Elastic IP para C2 · chaves do API Gateway |
| 🕵 Padrões de Ameaça | 5 | Escritas fora do horário · rajada de reconhecimento · disseminação em várias regiões · user agents incomuns · primeiras chamadas de API |
| 📊 Atividade e Linha de Base | 3 | Eventos de escrita no console · picos de erros · erros recentes |
| 🌍 Análise GeoIP ✦ | 12 | Viagem impossível · credenciais em vários países · logins/negações/escritas classificados por geografia · detalhamento por país/cidade/ASN · event_name × país · identidade × país |
| ☁ IaC e Plataforma | 2 | Cadeia de suprimentos de CI/CD · abuso de CloudFormation |

<details markdown="1">
<summary>📋 Lista completa — todas as mais de 100 consultas (clique para expandir)</summary>

## Caças Integradas

### 🛡 Detecção e Resposta

| # | Rótulo | Gráfico | Descrição |
|---|-------|:-----:|-------------|
| 1 | 🛑 CloudTrail Tampering | timeseries | Detecta qualquer tentativa de parar ou modificar o CloudTrail — o indicador de encobrimento mais crítico |
| 2 | 🛡️ GuardDuty Detector Tampering | timeseries | Detecta desativação, exclusão e manipulação de inteligência de ameaças do GuardDuty |
| 3 | ⛔ Security Hub Tampering | timeseries | Detecta desativação do Security Hub, desativação de padrões e supressão de descobertas |
| 4 | ⚙️ AWS Config Tampering | timeseries | Detecta exclusão de gravador/regra do AWS Config (elimina evidências de conformidade) |
| 5 | 🛡 Organizations SCP Changes | timeseries | Detecta criação, atualização e exclusão de SCP — remover uma SCP de Deny elimina as barreiras de proteção em todas as contas da OU |
| 6 | 🚫 AWS Macie Tampering | timeseries | Detecta desativação do Macie e criação de filtro de descobertas (evasão de defesa pré-exfiltração) |
| 7 | 🚨 CloudWatch Alarm Deletion / Disable | timeseries | Detecta exclusão de alarmes e DisableAlarmActions — silencia o alerta de segurança sem excluir o alarme |
| 8 | 📜 CloudWatch Logs Subscription Changes | timeseries | Detecta criação/exclusão de filtro de assinatura de CW Logs (exfiltração de logs em tempo real para Kinesis/Lambda do atacante) |
| 9 | 🏹 WAF WebACL Changes | timeseries | Detecta criação, atualização e exclusão de WAF WebACL em WAFv2/WAF Classic |
| 10 | 🔍 GuardDuty Findings Read | timeseries | Detecta ListFindings / GetFindings — o atacante lê descobertas ativas para entender o que o SOC já detectou |
| 11 | 💰 Budget / Cost Anomaly Changes | timeseries | Detecta exclusão de Budget/AnomalyMonitor (ocultando custos de cryptomining) |
| 12 | 🚫 Access Denied Errors | bar | Agrupa erros AccessDenied por identidade e API — os principais infratores indicam uso indevido de credenciais |

### 🔑 Identidade e Acesso

| # | Rótulo | Gráfico | Descrição |
|---|-------|:-----:|-------------|
| 1 | 🔑 Root Account Activity | timeseries | Detecta qualquer chamada de API feita pela conta root — root nunca deve ser usado em produção |
| 2 | 🔓 Console Login without MFA | timeseries | Detecta logins no console em que o MFA não foi usado — indicador de alto risco de comprometimento de conta |
| 3 | 🌐 Console Logins | timeseries | Lista todas as tentativas de login no console, incluindo sucessos e falhas (detecção de força bruta) |
| 4 | 🔐 MFA & Password Changes | timeseries | Detecta desativação de MFA e redefinições de senha — forte indicador de tomada de conta |
| 5 | 🔄 Privilege Escalation (IAM) | timeseries | Detecta anexação de política IAM e manipulação de função (PutUserPolicy, AttachRolePolicy, CreatePolicyVersion, etc.) |
| 6 | 🔄 IAM Role Trust Policy Changes | timeseries | Detecta UpdateAssumeRolePolicy — adicionar entidades externas a uma política de confiança cria um backdoor persistente |
| 7 | 🚧 IAM Permission Boundary Changes | timeseries | Detecta eventos de criação/exclusão de limite de permissão — remover um limite expande imediatamente as permissões efetivas |
| 8 | 👑 User Added to Admin Group | timeseries | Detecta usuários adicionados a grupos com 'admin' no nome — escalonamento de privilégios clássico |
| 9 | 👥 IAM Group Membership Changes | timeseries | Detecta todos os eventos AddUserToGroup / RemoveUserFromGroup / CreateGroup / DeleteGroup independentemente do nome do grupo |
| 10 | 👤 New IAM Users / Keys | timeseries | Identifica eventos de criação de usuário IAM e chave de acesso — criação inesperada pode indicar persistência |
| 11 | 🎯 IAM PassRole Abuse | timeseries | Detecta o uso de iam:PassRole inspecionando eventos do serviço receptor (RunInstances, CreateFunction, CreateNotebookInstance, etc.) onde um ARN de função é passado |
| 12 | 🔐 AssumeRole Cross-Account | timeseries | Mostra eventos AssumeRole em que o chamador e o destino estão em contas AWS diferentes (movimentação lateral) |
| 13 | 🏢 Cross-Account Access | timeseries | Encontra todos os eventos em que a conta do chamador difere da conta destinatária |
| 14 | 🔑 STS Federation Token Issuance | timeseries | Detecta GetFederationToken e GetSessionToken — converte chaves de longa duração em credenciais temporárias persistentes |
| 15 | 🧩 STS AssumeRoleWithWebIdentity | timeseries | Detecta abuso de confiança OIDC (claim sub mal configurada / GitHub Actions sem condição de repositório) |
| 16 | 🆔 IAM Identity Center (SSO) Events | timeseries | Detecta ações de gerenciamento do AWS IAM Identity Center (CreatePermissionSet, CreateAccountAssignment, etc.) |
| 17 | 🔗 SAML / OIDC Provider Updates | timeseries | Detecta alterações de provedor de identidade SAML/OIDC — atualizar metadados SAML com um IdP controlado pelo atacante cria um backdoor de autenticação persistente |
| 18 | 🧐 IAM Access Analyzer Calls | timeseries | Detecta qualquer uso do IAM Access Analyzer — atacantes aproveitam o analisador nativo para enumerar recursos acessíveis externamente sem scripts de reconhecimento personalizados |
| 19 | 🔄 Credential Report & Enumeration | timeseries | Detecta enumeração de IAM (GenerateCredentialReport, ListUsers, ListRoles, GetAccountAuthorizationDetails, etc.) |
| 20 | 🗝 Access Key Abuse | bar | Detecta chaves de acesso usadas de mais de 3 IPs de origem distintos em 7 dias — forte indicador de vazamento de chave |
| 21 | 📰 AWS Organizations Account Creation | timeseries | Detecta criação de conta no Organizations e alterações de administrador delegado (persistência por conta sombra) |
| 22 | 👥 Cognito Unauthenticated Access | timeseries | Detecta Cognito Identity Pools com allowUnauthenticatedIdentities=true |
| 23 | 🧪 Glue DevEndpoint Privilege Escalation | timeseries | Detecta criação de Glue DevEndpoint (iam:PassRole + glue:CreateDevEndpoint = endpoint acessível por SSH executando com as permissões completas da função passada) e enumeração de conexões para coleta de credenciais |
| 24 | 🧪 SageMaker Notebook Privilege Escalation | timeseries | Detecta criação de notebook SageMaker e geração de URL pré-assinada — iam:PassRole + sagemaker:CreateNotebookInstance inicia um ambiente Jupyter com as permissões AWS completas da função passada |
| 25 | 🛠 Data Pipeline / CodeStar Privilege Escalation | timeseries | Detecta criação de recursos do Data Pipeline e CodeStar usados para escalonamento via iam:PassRole (CreateProjectFromTemplate cria uma função IAM administradora como efeito colateral) |
| 26 | 🧩 Step Functions Privilege Escalation | timeseries | Detecta criação de máquina de estado do Step Functions (iam:PassRole + states:CreateStateMachine executa tarefas Lambda/ECS sob a função passada) |

### 🪣 Dados e Armazenamento

| # | Rótulo | Gráfico | Descrição |
|---|-------|:-----:|-------------|
| 1 | 💣 S3 Bulk Object Deletion | bar | Detecta identidades realizando ≥50 chamadas DeleteObject/DeleteObjects por hora — padrão de destruição de dados de ransomware / wiper |
| 2 | 🔥 AWS Backup Tampering | timeseries | Detecta exclusão de Backup Vault / Plan / RecoveryPoint e remoção de Vault Lock — primeiro passo do ransomware para eliminar opções de recuperação |
| 3 | 🔓 KMS Key Operations | timeseries | Sinaliza operações sensíveis do KMS (DisableKey, ScheduleKeyDeletion, CreateGrant, PutKeyPolicy, Decrypt de alto volume) |
| 4 | 🔓 S3 Public Access Block Disabled | — | Detecta a desativação das configurações de bloqueio de acesso público do S3 — risco imediato de exposição de dados |
| 5 | 🪣 S3 Bucket Policy / ACL Changes | timeseries | Detecta modificações de política e ACL de bucket S3 (PutBucketPolicy com Principal='*' é especialmente crítico) |
| 6 | 🪣 S3 Data Access Anomalies | bar | Detecta chamadas GetObject em massa (≥100/hora) — padrão automatizado de exfiltração de dados |
| 7 | 🔐 Secrets Manager Bulk GetSecretValue | bar | Detecta identidades recuperando ≥10 segredos distintos em uma hora — sinal de coleta de credenciais |
| 8 | 🗝 Secrets Manager Deletion & Cross-Account Policy | timeseries | Detecta exclusão de segredo, PutResourcePolicy (compartilhamento entre contas) e CancelRotateSecret |
| 9 | 🔐 SSM Parameter Store Bulk Read | bar | Detecta identidades lendo ≥20 parâmetros em uma hora — um canal de exfiltração frequentemente negligenciado |
| 10 | 💾 RDS Snapshot Cross-Account Share | timeseries | Detecta snapshots RDS/Aurora compartilhados com contas AWS externas (exfiltração de banco de dados via snapshot) |
| 11 | 💣 RDS Deleted without Final Snapshot | — | Detecta exclusão de RDS com skipFinalSnapshot=true — possível destruição de dados |
| 12 | 💽 RDS Public Accessibility Enabled | timeseries | Detecta instâncias RDS criadas ou modificadas com publiclyAccessible=true |
| 13 | 🗄 DynamoDB Export / Bulk Exfiltration | timeseries | Detecta ExportTableToPointInTime (exportação completa de tabela do lado do servidor contornando o DLP de GetItem), DeleteTable e desativação de PITR |
| 14 | 💾 EBS Direct API Snapshot Exfiltration | timeseries | Detecta EBS Direct API (ListSnapshotBlocks / GetSnapshotBlock) — Pacu ebs__download_snapshots transmite dados brutos de snapshot sem EC2, contornando a detecção de ModifySnapshotAttribute |
| 15 | 🌊 Kinesis Firehose / Stream Exfiltration Channel | timeseries | Detecta criação/atualização de delivery stream do Firehose apontando para S3 externo — pipeline de dados em tempo real invisível ao DLP de rede |
| 16 | 🔁 S3 Cross-Account Replication | timeseries | Detecta PutBucketReplication — copia silenciosamente todos os novos objetos para um bucket controlado pelo atacante sem gerar eventos GetObject adicionais |
| 17 | 📂 S3 Versioning / Logging Disabled | timeseries | Detecta suspensão de versionamento (permite exclusão permanente) e desativação de log de acesso ao servidor (remove o rastro de evidências) |
| 18 | 📧 SES Identity & Forwarding Config Changes | timeseries | Detecta alterações de regra de recebimento e configuração de identidade do SES — regras de encaminhamento retransmitem todo o e-mail recebido para endereços do atacante; identidades verificadas habilitam campanhas de phishing |
| 19 | 📡 SQS / SNS Cross-Account Policy Changes | timeseries | Detecta alterações de política SQS/SNS concedendo acesso a contas externas (streaming silencioso de mensagens para endpoints do atacante) |
| 20 | 📸 EC2 Public Snapshot / AMI Sharing | timeseries | Detecta snapshots EBS ou AMIs compartilhados publicamente (group=all) — permite que qualquer pessoa copie imagens de disco e extraia dados |
| 21 | 📧 Data Exfiltration Channels | bar | Detecta chamadas de alto volume SNS/SQS/SES/S3 PutObject (≥50/hora) de uma única identidade |

### ⚡ Computação e Serverless

| # | Rótulo | Gráfico | Descrição |
|---|-------|:-----:|-------------|
| 1 | 💥 EC2 Mass Stop / Terminate | timeseries | Detecta identidades realizando ≥5 StopInstances/TerminateInstances em uma hora — indicador de ransomware / wiper |
| 2 | 🖥️ SSM Session / Run Command | timeseries | Detecta SSM StartSession, SendCommand e StartAutomationExecution — principal caminho de movimentação lateral via instâncias gerenciadas |
| 3 | 🔑 EC2 Instance Connect / Serial Console Access | timeseries | Detecta SendSSHPublicKey e SendSerialConsoleSSHPublicKey — contorna os pares de chaves do EC2 (válidos por 60 segundos, não deixam artefatos de chave SSH) |
| 4 | 📝 EC2 User Data Modification | timeseries | Detecta ModifyInstanceAttribute com alteração de userData — o script é executado como root na próxima inicialização |
| 5 | ⚡ Lambda Function Tampering | timeseries | Detecta criação de Lambda, atualizações de código (UpdateFunctionCode) e alterações de permissão (AddPermission) |
| 6 | 📦 Lambda Layer Addition | timeseries | Detecta publicação de layer Lambda e AddLayerVersionPermission com entidade curinga (ataque público à cadeia de suprimentos) |
| 7 | 📦 ECS Task Definition  | timeseries | Detecta RegisterTaskDefinition / UpdateService — Pacu ecs__backdoor_task_def injeta um contêiner sidecar malicioso sem tocar no ECR |
| 8 | 👤 EC2 Instance Profile Changes | timeseries | Detecta AssociateIamInstanceProfile / ReplaceIamInstanceProfileAssociation — anexa um perfil privilegiado que permite movimentação lateral |
| 9 | 🖥 EC2 Instance Launches | timeseries | Lista todos os eventos RunInstances incluindo tipo de instância, contagem, nome da chave e AMI (detecção de cryptomining) |
| 10 | 💰 EC2 Spot Fleet / Reserved Instance Abuse | timeseries | Detecta grandes solicitações de Spot Fleet (ec2) e criação de grupo de Auto Scaling com alta capacidade (autoscaling) — indicador de impacto financeiro de cryptomining |
| 11 | ☸️ EKS Cluster API Calls | timeseries | Detecta modificações no plano de controle de cluster EKS (exposição pública do servidor de API, perfis Fargate fraudulentos) |
| 12 | 🐳 ECR Repository / Image Changes | timeseries | Detecta eventos de repositório/imagem do ECR (PutImage com tag 'latest' envenena todas as implantações subsequentes) |
| 13 | 📅 EventBridge / CloudWatch Rule Changes | timeseries | Detecta modificações de regra do EventBridge e Scheduler (PutRule, CreateSchedule) — estabelece persistência sem um processo em execução |
| 14 | 💡 Lightsail Instance & Key Abuse | timeseries | Detecta recuperação de chave, exposição de porta e acesso a instância do Lightsail — Pacu lightsail__download_ssh_keys / lightsail__generate_temp_access |

### 🌐 Rede e Infraestrutura

| # | Rótulo | Gráfico | Descrição |
|---|-------|:-----:|-------------|
| 1 | 🌍 Security Group Opened to Internet | timeseries | Encontra regras de grupo de segurança que permitem tráfego de 0.0.0.0/0 — risco de exposição pública direta |
| 2 | 🔥 Security Group Modifications | timeseries | Detecta todas as alterações de regra de grupo de segurança (AuthorizeSecurityGroupIngress, ModifySecurityGroupRules, etc.) |
| 3 | 🌊 VPC Flow Log Changes | timeseries | Detecta exclusão de Logs de Fluxo da VPC — remover logs de fluxo elimina a principal evidência forense de rede |
| 4 | 🌐 CloudFront Distribution Tampering | timeseries | Detecta alterações de origem do CloudFront que redirecionam todo o tráfego de CDN para servidores controlados pelo atacante (MitM) |
| 5 | 🛡 Network Firewall / Shield Tampering | timeseries | Detecta remoção de proteção do Network Firewall e Shield — expõe faixas inteiras de sub-rede ao tráfego de ataque |
| 6 | 🧱 Network ACL Changes | timeseries | Detecta criação, exclusão e substituição de entrada de NACL — NACLs sobrepõem-se a grupos de segurança no nível da sub-rede |
| 7 | 🛣️ Route Table Changes | timeseries | Detecta modificações de tabela de rotas — atacantes redirecionam o tráfego para gateways maliciosos para interceptação ou C2 |
| 8 | 🧱 VPN / Direct Connect / Transit Gateway | timeseries | Detecta novas conexões VPN e anexações de Transit Gateway — cria caminhos de rede de Camada 3 persistentes para C2 ou exfiltração |
| 9 | 📡 Elastic IP Allocation / Association | timeseries | Detecta alocação/associação de Elastic IP — atribui um IP público fixo a instâncias comprometidas para infraestrutura de C2 estável |
| 10 | 🗝️ EC2 Key Pair Creation | timeseries | Detecta CreateKeyPair e ImportKeyPair — o atacante cria chaves SSH para acesso persistente à instância |
| 11 | 📡 Network Infrastructure Changes | timeseries | Detecta alterações de VPC / sub-rede / IGW / NAT Gateway / peering que podem estabelecer infraestrutura controlada pelo atacante |
| 12 | 🏷 ACM Certificate Operations | timeseries | Detecta solicitações e exclusões de certificado ACM — contas comprometidas podem emitir certificados TLS para domínios de phishing |
| 13 | 🔑 API Gateway Key Creation & Management | timeseries | Detecta criação de chave do API Gateway e alterações de authorizer — Pacu api_gateway__create_api_keys gera credenciais persistentes que sobrevivem à rotação de chaves IAM |
| 14 | 🚧 VPC Endpoint Access Denied | timeseries | Detecta erros de acesso negado via endpoints da VPC — pode indicar política de endpoint mal configurada |

### 🕵 Padrões de Ameaça

| # | Rótulo | Gráfico | Descrição |
|---|-------|:-----:|-------------|
| 1 | 🔍 Reconnaissance Pattern | bar | Identifica chamadores que executaram mais de 10 APIs Describe*/List*/Get* distintas em uma hora — fase comum no início de um ataque |
| 2 | 🤖 Unusual User Agents | bar | Lista user agents raros (<5 eventos) ou ferramentas conhecidas de atacantes (Pacu, curl, wget) — pode indicar ferramental de ataque |
| 3 | 🌍 Multi-Region Activity | bar | Detecta identidades realizando escritas em mais de 3 regiões em um dia — disseminação geográfica pode indicar comprometimento |
| 4 | 🕵 First-Time API Calls (24h) | — | Encontra chamadas de API vistas nas últimas 24h mas nunca antes — operações inéditas podem indicar ferramental de atacante |

### 📊 Atividade e Linha de Base

| # | Rótulo | Gráfico | Descrição |
|---|-------|:-----:|-------------|
| 1 | 🖥 Write Events from Management Console | timeseries | Identifica chamadas de API que alteram estado feitas via console da AWS — útil quando se espera apenas acesso via CLI |
| 2 | 🔍 Events with Errors (24h) | timeseries | Lista todos os eventos de erro nas últimas 24 horas — visão geral rápida do que está falhando ou sendo sondado |
| 3 | ❌ Error Spike Detection | — | Encontra janelas de 1 hora em que a contagem de erros excede a média diária em 3× |

### 🌍 Análise GeoIP

> Requer arquivos GeoLite2 `.mmdb` para preenchimento (as colunas ficam NULL se ingeridas sem GeoIP).

| # | Rótulo | Gráfico | Descrição |
|---|-------|:-----:|-------------|
| 1 | 🕵 Impossible Travel Detection | — | Detecta a mesma identidade chamando APIs de cidades distantes em até 2 horas — forte indicador de comprometimento de credenciais |
| 2 | ⚠ Identity Multi-Country Access | bar | Encontra identidades fazendo chamadas de API de mais de 2 países — usuários legítimos raramente operam de vários países simultaneamente |
| 3 | 🗺 Console Logins by Country | timeseries | Mapeia eventos de login no console à sua origem geográfica — logins de países inesperados são de alto risco |
| 4 | 🚨 Unusual Country Access | bar | Detecta combinações raras de país/identidade (<10 eventos) — acesso estrangeiro de baixo volume pode ser infraestrutura de atacante |
| 5 | 🚫 Access Denied by Country | bar | Agrupa erros de acesso negado por país de origem — negações concentradas de um país podem sinalizar um ataque |
| 6 | 🔍 Write Events by Country | bar | Mostra chamadas de API que alteram estado agrupadas por país de origem — escritas de países inesperados são um sinal mais forte do que leituras |
| 7 | 🌍 Top Source Countries | bar | Classifica os países de origem por volume de chamadas de API com detalhamento de eventos de escrita e identidades únicas |
| 8 | 🏢 Top ASN / Organizations | bar | Lista sistemas autônomos (ISPs/provedores de nuvem) por volume de chamadas de API — ASNs de VPN/hospedagem podem indicar infraestrutura de atacante |
| 9 | 📍 Top Source Cities | bar | Classifica as cidades de origem por volume de eventos — dados em nível de cidade apontam para infraestrutura específica do atacante ou locais de escritório |
| 10 | 🌐 Private / Internal IP Summary | bar | Resume eventos de IPs privados/loopback/internos da AWS — linha de base para o tráfego interno esperado |
| 11 | 📋 API Calls by Country (Event Name) | table | Principais pares (event_name, país) por volume de chamadas — revela quais operações de API se originam de regiões geográficas inesperadas |
| 12 | 👤 Identities by Country (user_identity_arn) | table | Principais pares (user_identity_arn, país) por volume de chamadas — expõe identidades IAM ativas de países inesperados com primeira/última observação |

### ☁ IaC e Plataforma

| # | Rótulo | Gráfico | Descrição |
|---|-------|:-----:|-------------|
| 1 | 🛠 CodeBuild / CodePipeline Supply Chain Attack | timeseries | Detecta criação e modificação de pipeline de CI/CD (UpdateProject injeta etapas de build maliciosas em cada build subsequente) |
| 2 | 🏗 CloudFormation / IaC Abuse | timeseries | Detecta operações de stack do CloudFormation — atacantes podem usar IaC para implantar rapidamente infraestrutura maliciosa |

</details>

---

## 📊 Gráficos de Painel — mais de 80 gráficos

| Aba | Gráficos | O Que Mostra |
|-----|:------:|---------------|
| 🔑 Identidade e Acesso | 9 | Logins no console · tendência de MFA · mapa de calor de login · APIs sensíveis · uso de root · atividade de entidades IAM · escalonamento de privilégios · SSO/privesc |
| 🎯 Detecção de Ameaças | 12 | Volume de eventos · proporção leitura/escrita · evasão de defesa · acesso negado · tendência de erros · adulteração de SCP/Config/NACL/EventBridge |
| 📊 Atividade de API | 7 | Principais APIs · distribuição por região · IPs de origem · user agents · anomalia de segredos · AssumeRole externo · alterações de Route53 |
| 🖥️ Computação | 5 | Execução de SSM · snapshot público de EC2 · eventos EKS/ECR · backdoor de ECS · exfiltração via EBS Direct API |
| 🪣 S3 e RDS | 9 | Política/ACL do S3 · download/exclusão em massa · versionamento/log desativado · replicação entre contas · compartilhamento de snapshot RDS · adulteração de Backup |
| 🌍 Inteligência GeoIP | 6 | Mapa-múndi · principais países / cidades / ASNs por volume de requisições · event_name × país · identidade × país |
| 🕒 Análise Temporal | 6 | Primeira/última observação por identidade/IP/API/agente · contas dormentes reativadas · picos de velocidade |
| 🚨 Monitor de APIs de Alto Risco | 7 | Série temporal de HRM · principais chamadas/atores/IPs · detalhe de evasão de defesa/acesso a credenciais · por região |

<details markdown="1">
<summary>📋 Lista completa — todos os mais de 80 gráficos (clique para expandir)</summary>

## Gráficos de Painel (Apache Superset — `dashboard/`)

### 🔑 Identidade e Acesso

| # | Nome do Gráfico | Descrição |
|---|------------|-------------|
| 1 | Console Login Activity | Eventos de login no console agrupados por identidade IAM (DSH-08) |
| 2 | MFA-less Login Trend | Logins diários no console divididos por uso de MFA (DSH-28) |
| 3 | Login Activity Heatmap (Hour × Day) | Contagens de login no console por dia da semana e hora do dia em JST (DSH-19) |
| 4 | Sensitive API Calls | Invocações de ações de API da AWS conhecidas como sensíveis à segurança (DSH-12) |
| 5 | Root Account Usage | Todas as chamadas de API feitas pela conta Root da AWS (DSH-13) |
| 6 | IAM Entity Activity | Top 50 entidades IAM classificadas por total de chamadas de API, com proporção de escrita e taxa de erro |
| 7 | Privilege Escalation Timeline | Contagens diárias de chamadas de API de escalonamento de privilégios por nome de evento (DSH-30) |
| 8 | IAM Identity Center (SSO) Events | Eventos de gerenciamento do AWS IAM Identity Center de sso.amazonaws.com (DSH-44) |
| 9 | Glue & SageMaker Privilege Escalation | Eventos de Glue DevEndpoint e SageMaker Notebook usados para escalonamento de privilégios IAM via iam:PassRole (DSH-50) |

### 🎯 Detecção de Ameaças

| # | Nome do Gráfico | Descrição |
|---|------------|-------------|
| 1 | CloudTrail Events Over Time | Volume horário de eventos de Leitura vs Escrita ao longo do tempo (DSH-01) |
| 2 | Write/Read Ratio Trend | Detalhamento horário de chamadas de API de leitura vs escrita (DSH-20) |
| 3 | Throttling Exception Spikes | Erros horários de throttling/limite de taxa por serviço da AWS (DSH-21) |
| 4 | Defense Evasion Events | Todos os eventos do CloudTrail que correspondem a técnicas conhecidas de evasão de defesa (DSH-22) |
| 5 | Top Access Denied Actions | Top 20 ações de API que retornam erros AccessDenied (DSH-09) |
| 6 | Error Event Trend | Eventos de erro horários detalhados por error_code (DSH-04) |
| 7 | Organizations / SCP Changes | Eventos de gerenciamento do AWS Organizations incluindo alterações de política SCP (DSH-24) |
| 8 | First-Time Service Sources | Todas as origens de serviço da AWS distintas ordenadas pela data de primeira aparição (DSH-26) |
| 9 | VPC Flow Log Changes | Eventos de criação e exclusão de Logs de Fluxo da VPC (DSH-42) |
| 10 | AWS Config Tampering | Eventos de adulteração de gravador e regra do AWS Config (DSH-43) |
| 11 | Network ACL / Route Table Changes | Eventos de modificação de NACL e tabela de rotas (DSH-46) |
| 12 | EventBridge / CloudWatch Rule Tampering | Adulteração de regra do EventBridge e CloudWatch Events (DSH-47) |

### 📊 Atividade de API

| # | Nome do Gráfico | Descrição |
|---|------------|-------------|
| 1 | Top 20 API Calls | As 20 ações de API da AWS mais frequentemente chamadas (DSH-02) |
| 2 | Region Activity | Distribuição de eventos do CloudTrail entre regiões da AWS (DSH-14) |
| 3 | Top Source IP Addresses | Top 100 IPs de origem externos por contagem de requisições (DSH-05) |
| 4 | User Agent Analysis | Top 50 user agents por contagem de requisições com detalhamento de erro e escrita (DSH-11) |
| 5 | Secrets Access Anomaly | Identidades acessando o Secrets Manager ou SSM Parameter Store ≥10 vezes em uma hora |
| 6 | AssumedRole from External IP | Chamadas AssumeRole de endereços IP públicos (não privados) (DSH-27) |
| 7 | Route53 DNS Changes | Alterações de configuração de zona hospedada e resolver do Route 53 (DSH-29) |

### 🖥️ Computação

| # | Nome do Gráfico | Descrição |
|---|------------|-------------|
| 1 | SSM Session / Run Command Execution | Eventos de execução remota do AWS Systems Manager (DSH-39) |
| 2 | EC2 Public Snapshot / AMI Sharing | Eventos de compartilhamento público de snapshot EBS e AMI (DSH-41) |
| 3 | EKS / ECR Container Platform Events | Eventos de cluster EKS e registro de contêineres ECR (DSH-48) |
| 4 | ECS Task Definition | Eventos de registro de definição de tarefa ECS e atualização de serviço — padrão Pacu ecs__backdoor_task_def (DSH-49) |
| 5 | EBS Direct API Snapshot Exfiltration | Chamadas EBS Direct API (ListSnapshotBlocks / GetSnapshotBlock) usadas para transmitir dados de snapshot sem EC2 (DSH-51) |

### 🪣 S3 e RDS

| # | Nome do Gráfico | Descrição |
|---|------------|-------------|
| 1 | S3 Protection Config Changes | Eventos do S3 que enfraquecem a postura de segurança do bucket (DSH-25) |
| 2 | S3 Bucket Policy / ACL Changes | Eventos de modificação de política e ACL de bucket S3 (DSH-45) |
| 3 | RDS Snapshot Cross-Account Share | Eventos de compartilhamento de snapshot RDS e Aurora (DSH-40) |
| 4 | S3 Bulk Download | Identidades realizando ≥100 chamadas GetObject por hora — padrão automatizado de exfiltração de dados (DSH-52) |
| 5 | S3 Bulk Object Deletion | Identidades realizando ≥50 chamadas DeleteObject/DeleteObjects por hora — padrão de destruição de dados de ransomware (DSH-53) |
| 6 | S3 Versioning / Logging Disabled | PutBucketVersioning (Suspended) e PutBucketLogging (disabled) — precursor anti-forense de destruição de dados (DSH-54) |
| 7 | S3 Cross-Account Replication | PutBucketReplication / DeleteBucketReplication — canal de exfiltração silenciosa persistente para conta controlada pelo atacante (DSH-55) |
| 8 | RDS Deleted without Final Snapshot | DeleteDBInstance / DeleteDBCluster com skipFinalSnapshot=true — destruição irrecuperável de dados (DSH-56) |
| 9 | AWS Backup Tampering | Exclusão de Backup Vault / Plan / RecoveryPoint e remoção de Vault Lock — primeiro passo do ransomware para eliminar opções de recuperação (DSH-57) |

### 🌍 Inteligência GeoIP

> Requer arquivos GeoLite2 `.mmdb`. As colunas de GeoIP ficam NULL se ingeridas sem GeoIP.

| # | Nome do Gráfico | Descrição |
|---|------------|-------------|
| 1 | Global Request Origin Map | Mapa-múndi mostrando a distribuição geográfica das origens de chamadas de API do CloudTrail |
| 2 | Top Countries by Request Volume | Top 20 países de origem por volume de chamadas de API com detalhamento de eventos de escrita e chamadores únicos |
| 3 | Top Cities by Request Volume | Top 25 cidades por volume de chamadas de API com detalhamento de eventos de escrita e chamadores únicos |
| 4 | Top ASN Organizations by Request Volume | Top 25 organizações de ASN por volume de chamadas de API |
| 5 | API Calls by Country (Event Name × GeoIP) | Top 50 pares (event_name, país) — revela quais operações de API são chamadas de cada região geográfica (DSH-79) |
| 6 | Identities by Country (user_identity_arn × GeoIP) | Top 50 pares (user_identity_arn, país) — expõe identidades IAM ativas de países inesperados com contagem de escrita e primeira/última observação (DSH-80) |

### 🕒 Análise Temporal

| # | Nome do Gráfico | Descrição |
|---|------------|-------------|
| 1 | First / Last Seen per IAM Identity | Identidades IAM com timestamps de primeira/última observação, contagens de eventos e APIs distintas |
| 2 | First / Last Seen per Source IP | IPs de origem com primeira/última observação, identidades distintas e APIs distintas |
| 3 | First / Last Seen per API Call | Ações de API ordenadas pela primeira aparição — novas chamadas podem indicar ferramental de ataque inédito (DSH-33) |
| 4 | First / Last Seen per User Agent | User agents ordenados pela primeira aparição — detecção de novo ferramental (DSH-34) |
| 5 | Dormant Accounts Reactivated | Identidades com lacunas de inatividade de mais de 72 horas que retomaram a atividade (DSH-37) |
| 6 | Event Velocity Spikes per Identity | Identidades com rajada de atividade de mais de 50 eventos por hora (DSH-38) |

### 🚨 Monitor de APIs de Alto Risco (HRM)

| # | Nome do Gráfico | Descrição |
|---|------------|-------------|
| 1 | High-Risk API Events Over Time | Volume diário de chamadas para APIs comumente observadas em campanhas de ataque (HRM-39) |
| 2 | Top High-Risk API Calls | Ações de API da lista de observação de alto risco classificadas pela contagem total de chamadas (HRM-40) |
| 3 | Top Actors — High-Risk APIs | Entidades IAM classificadas pelo total de chamadas a APIs da lista de observação de alto risco (HRM-42) |
| 4 | Top Source IPs — High-Risk APIs | IPs de origem classificados pelo total de chamadas a APIs da lista de observação de alto risco (HRM-43) |
| 5 | Defense Evasion API Events | Log de eventos detalhado para APIs usadas para desativar ou adulterar controles de auditoria (HRM-44) |
| 6 | Credential Access API Events | Log de eventos detalhado para APIs usadas para recuperar segredos e credenciais (HRM-45) |
| 7 | High-Risk API Calls by Region | Chamadas de API da lista de observação de alto risco distribuídas por região da AWS (HRM-46) |

</details>

---
