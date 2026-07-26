# Primeiros Passos

## Pré-requisitos

| Requisito                             | Detalhes                                           |
|---------------------------------------|----------------------------------------------------|
| **Docker**                            | Docker Desktop ou Docker Engine + Compose v2       |
| **make**                              | GNU Make (pré-instalado no macOS)                  |
| **Recursos**                          | 16 GB de RAM no mínimo, SSD recomendado            |
| **Logs do CloudTrail**                | Arquivos `.json` ou `.json.gz` exportados da AWS   |
| *(Opcional)* **Snapshots do AWS Config** | Arquivos `.json` ou `.json.gz` para o grafo de recursos da AWS |
| *(Opcional)* **Chave de API da OpenAI** | Necessária para a geração de consultas por IA      |
| *(Opcional)* **MaxMind GeoLite2**     | Arquivos `.mmdb` para enriquecimento de GeoIP      |

---

## Início Rápido

**Passo 1.** Baixe os logs do CloudTrail do S3.

```bash
aws s3 cp s3://<your-bucket-prefix> <local-output-dir>/ --recursive --include "*.json.gz"
```

**Passo 2.** Clone o repositório e coloque seus dados no lugar.

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded CloudTrail logs here
cp -r <local-output-dir>/ docker/logs/
```

Os dois diretórios opcionais abaixo são detectados automaticamente. Preencha-os **antes** do próximo passo — não há comando adicional a executar.

| Diretório | Conteúdo | O que acrescenta |
|---|---|---|
| `docker/data/geoip/` | [GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | Resolve os IPs de origem em país, cidade e ASN |
| `docker/data/config-snapshots/` | Arquivos `.json` de snapshot do AWS Config | Constrói o grafo de recursos do AWS Config |

**Passo 3.** Ingira os logs e inicie os serviços.

```bash
make ingest
make up
```

**Passo 4.** 🪽 Abra o seu navegador e comece a caçar!🪽

- http://localhost:8501 — Consultas integradas e Chat com IA
- http://localhost:8088 — Dashboard (`admin` / `admin`)
- http://localhost:8502 — Grafo de recursos do AWS Config

---

## Comandos do dia a dia

`make` sem argumentos imprime esta lista. `make help-all` mostra todos os alvos.

| Comando | O que faz |
|---|---|
| `make ingest` | Carregar os logs do CloudTrail de `docker/logs/` no DuckDB |
| `make up` | Iniciar a interface, o dashboard e o grafo de recursos |
| `make down` | Parar tudo |
| `make logs` | Acompanhar os logs dos serviços (`SERVICE=agent` para apenas um) |
| `make reset` | Excluir o banco de dados e começar de novo |

---

## Proxy Corporativo / Certificado de CA Personalizado

Se você estiver atrás de um proxy corporativo que inspeciona TLS, consulte [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) para obter instruções de configuração.
