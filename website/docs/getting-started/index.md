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

**Step 2.** Clone the repository and put your data in place.

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded CloudTrail logs here
cp -r <local-output-dir>/ docker/logs/
```

The two optional directories below are detected automatically. Fill them in **before** the next step — there is no extra command to run.

| Directory | Contents | What it adds |
|---|---|---|
| `docker/data/geoip/` | [GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | Resolves source IPs to country, city, and ASN |
| `docker/data/config-snapshots/` | AWS Config snapshot `.json` files | Builds the AWS Config resource graph |

**Step 3.** Ingest the logs and start the services.

```bash
make ingest
make up
```

**Step 4.** 🪽 Open your browser and start hunting!🪽

- http://localhost:8501 — Built-in queries and AI Chat
- http://localhost:8088 — Dashboard (`admin` / `admin`)
- http://localhost:8502 — AWS Config resource graph

---

## Everyday commands

Running `make` with no arguments prints this list. `make help-all` shows every target.

| Command | What it does |
|---|---|
| `make ingest` | Load CloudTrail logs from `docker/logs/` into DuckDB |
| `make up` | Start the UI, dashboard, and resource graph |
| `make down` | Stop everything |
| `make logs` | Tail service logs (`SERVICE=agent` for just one) |
| `make reset` | Delete the database and start over |

---

## Corporate Proxy / Custom CA Certificate

If you are behind a TLS-inspecting corporate proxy, see [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) for setup instructions.
