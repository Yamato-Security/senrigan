# Erste Schritte

## Voraussetzungen

| Anforderung                           | Details                                            |
|---------------------------------------|----------------------------------------------------|
| **Docker**                            | Docker Desktop oder Docker Engine + Compose v2     |
| **make**                              | GNU Make (unter macOS vorinstalliert)              |
| **Ressourcen**                        | mindestens 16 GB RAM, SSD empfohlen                |
| **CloudTrail-Logs**                   | aus AWS exportierte `.json`- oder `.json.gz`-Dateien |
| *(Optional)* **AWS Config-Snapshots** | `.json`- oder `.json.gz`-Dateien für den AWS-Ressourcengraphen |
| *(Optional)* **OpenAI-API-Schlüssel** | Erforderlich für die KI-gestützte Abfragegenerierung |
| *(Optional)* **MaxMind GeoLite2**     | `.mmdb`-Dateien für die GeoIP-Anreicherung         |

---

## Schnellstart

**Schritt 1.** Laden Sie die CloudTrail-Logs aus S3 herunter.

```bash
aws s3 cp s3://<your-bucket-prefix> <local-output-dir>/ --recursive --include "*.json.gz"
```

**Schritt 2.** Klonen Sie das Repository, importieren Sie die Logs und starten Sie alle Dienste.

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

**Schritt 3.** 🪽 Öffnen Sie Ihren Browser und beginnen Sie mit der Jagd!🪽

- http://localhost:8501 — Integrierte Abfragen und KI-Chat
- http://localhost:8088 — Dashboard (`admin` / `admin`)
- http://localhost:8502 — AWS Config-Ressourcengraph

**(Optional)** GeoIP-Anreicherung.
Legen Sie die [GeoLite2 `.mmdb`-Dateien](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) in `docker/data/geoip/` ab, dann:

```bash
make ingest-geoip
```

**(Optional)** Import von AWS Config-Snapshots zur Visualisierung des Ressourcengraphen.
Legen Sie die AWS Config-Snapshot-Dateien in `docker/logs/config/` ab, dann:
```bash
make ingest-config
```
---

## Unternehmens-Proxy / Benutzerdefiniertes CA-Zertifikat

Wenn Sie sich hinter einem TLS-inspizierenden Unternehmens-Proxy befinden, lesen Sie die Einrichtungsanweisungen unter [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate).
