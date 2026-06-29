# Getting Started

## Prerequisites

| Requirement                           | Details                                            |
|---------------------------------------|----------------------------------------------------|
| **Docker**                            | Docker Desktop or Docker Engine + Compose v2       |
| **make**                              | GNU Make (pre-installed on macOS)                  |
| **Resources**                         | 16 GB RAM minimum, SSD recommended                 |
| **CloudTrail logs**                   | `.json` or `.json.gz` files exported from AWS      |
| *(Optional)* **AWS Config snapshots** | `.json` or `.json.gz` files for AWS resource graph |
| *(Optional)* **OpenAI API key**       | Required for AI query generation                   |
| *(Optional)* **MaxMind GeoLite2**     | `.mmdb` files for GeoIP enrichment                 |

---

## Quick Start

**Step 1.** Download CloudTrail logs from S3.

```bash
aws s3 cp s3://<your-bucket-prefix> <local-output-dir>/ --recursive --include "*.json.gz"
```

**Step 2.** Clone the repository, ingest logs, and start all services.

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

**Step 3.** 🪽 Open your browser and start hunting!🪽

- http://localhost:8501 — Built-in queries and AI Chat
- http://localhost:8088 — Dashboard (`admin` / `admin`)
- http://localhost:8502 — AWS Config resource graph

**(Optional)** GeoIP enrichment.
Place [GeoLite2 `.mmdb` files](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) in `docker/data/geoip/`, then:

```bash
make ingest-geoip
```

**(Optional)** AWS Config snapshot ingestion for resource graph visualization.
Place AWS Config snapshot files in `docker/logs/config/`, then:
```bash
make ingest-config
```
---

## Corporate Proxy / Custom CA Certificate

If you are behind a TLS-inspecting corporate proxy, see [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) for setup instructions.
