# Prise en main

## Prérequis

| Exigence                              | Détails                                            |
|---------------------------------------|----------------------------------------------------|
| **Docker**                            | Docker Desktop ou Docker Engine + Compose v2       |
| **make**                              | GNU Make (préinstallé sur macOS)                  |
| **Ressources**                        | 16 Go de RAM minimum, SSD recommandé                 |
| **Journaux CloudTrail**               | Fichiers `.json` ou `.json.gz` exportés depuis AWS      |
| *(Optionnel)* **Instantanés AWS Config** | Fichiers `.json` ou `.json.gz` pour le graphe de ressources AWS |
| *(Optionnel)* **Clé API OpenAI**       | Requise pour la génération de requêtes par IA                   |
| *(Optionnel)* **MaxMind GeoLite2**     | Fichiers `.mmdb` pour l'enrichissement GeoIP                 |

---

## Démarrage rapide

**Étape 1.** Téléchargez les journaux CloudTrail depuis S3.

```bash
aws s3 cp s3://<your-bucket-prefix> <local-output-dir>/ --recursive --include "*.json.gz"
```

**Étape 2.** Clonez le dépôt, ingérez les journaux et démarrez tous les services.

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

**Étape 3.** 🪽 Ouvrez votre navigateur et commencez la chasse !🪽

- http://localhost:8501 — Requêtes intégrées et Chat IA
- http://localhost:8088 — Tableau de bord (`admin` / `admin`)
- http://localhost:8502 — Graphe de ressources AWS Config

**(Optionnel)** Enrichissement GeoIP.
Placez les [fichiers `.mmdb` GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) dans `docker/data/geoip/`, puis :

```bash
make ingest-geoip
```

**(Optionnel)** Ingestion d'instantanés AWS Config pour la visualisation du graphe de ressources.
Placez les fichiers d'instantanés AWS Config dans `docker/logs/config/`, puis :
```bash
make ingest-config
```
---

## Proxy d'entreprise / Certificat CA personnalisé

Si vous êtes derrière un proxy d'entreprise effectuant une inspection TLS, consultez [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) pour les instructions de configuration.
