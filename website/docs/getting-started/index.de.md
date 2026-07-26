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

**Schritt 2.** Klonen Sie das Repository und legen Sie Ihre Daten ab.

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded CloudTrail logs here
cp -r <local-output-dir>/ docker/logs/
```

Die beiden folgenden optionalen Verzeichnisse werden automatisch erkannt. Befüllen Sie sie **vor** dem nächsten Schritt — ein zusätzlicher Befehl ist nicht nötig.

| Verzeichnis | Inhalt | Was es ergänzt |
|---|---|---|
| `docker/data/geoip/` | [GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | Löst Quell-IPs zu Land, Stadt und ASN auf |
| `docker/data/config-snapshots/` | AWS Config-Snapshot-`.json`-Dateien | Erstellt den AWS Config-Ressourcengraphen |

**Schritt 3.** Importieren Sie die Logs und starten Sie die Dienste.

```bash
make ingest
make up
```

**Schritt 4.** 🪽 Öffnen Sie Ihren Browser und beginnen Sie mit der Jagd!🪽

- http://localhost:8501 — Integrierte Abfragen und KI-Chat
- http://localhost:8088 — Dashboard (`admin` / `admin`)
- http://localhost:8502 — AWS Config-Ressourcengraph

---

## Alltägliche Befehle

`make` ohne Argumente gibt diese Liste aus. `make help-all` zeigt alle Targets.

| Befehl | Funktion |
|---|---|
| `make ingest` | CloudTrail-Logs aus `docker/logs/` in DuckDB laden |
| `make up` | UI, Dashboard und Ressourcengraph starten |
| `make down` | Alles stoppen |
| `make logs` | Dienst-Logs verfolgen (`SERVICE=agent` für einen einzelnen) |
| `make reset` | Datenbank löschen und neu beginnen |

---

## Unternehmens-Proxy / Benutzerdefiniertes CA-Zertifikat

Wenn Sie sich hinter einem TLS-inspizierenden Unternehmens-Proxy befinden, lesen Sie die Einrichtungsanweisungen unter [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate).
