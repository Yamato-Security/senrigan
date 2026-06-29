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

**Passo 2.** Clone o repositório, ingira os logs e inicie todos os serviços.

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded logs into the Docker logs directory
cp -r <local-output-dir>/ docker/logs/

# Ingest CloudTrail logs into DuckDB
make ingest

# Start all services (agent + dashboard)
make up
```

**Passo 3.** 🪽 Abra o seu navegador e comece a caçar!🪽

- http://localhost:8501 — Consultas integradas e Chat com IA
- http://localhost:8088 — Dashboard (`admin` / `admin`)
- http://localhost:8502 — Grafo de recursos do AWS Config

**(Opcional)** Enriquecimento de GeoIP.
Coloque os [arquivos GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) em `docker/data/geoip/` e, em seguida:

```bash
make ingest-geoip
```

**(Opcional)** Ingestão de snapshots do AWS Config para visualização do grafo de recursos.
Coloque os arquivos de snapshot do AWS Config em `docker/logs/config/` e, em seguida:
```bash
make ingest-config
```
---

## Proxy Corporativo / Certificado de CA Personalizado

Se você estiver atrás de um proxy corporativo que inspeciona TLS, consulte [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) para obter instruções de configuração.
