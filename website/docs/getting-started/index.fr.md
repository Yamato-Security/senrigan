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

**Étape 2.** Clonez le dépôt et mettez vos données en place.

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded CloudTrail logs here
cp -r <local-output-dir>/ docker/logs/
```

Les deux répertoires optionnels ci-dessous sont détectés automatiquement. Remplissez-les **avant** l'étape suivante — aucune commande supplémentaire n'est nécessaire.

| Répertoire | Contenu | Ce que cela ajoute |
|---|---|---|
| `docker/data/geoip/` | [GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | Résout les IP sources en pays, ville et ASN |
| `docker/data/config-snapshots/` | Fichiers `.json` d'instantanés AWS Config | Construit le graphe de ressources AWS Config |

**Étape 3.** Ingérez les journaux et démarrez les services.

```bash
make ingest
make up
```

**Étape 4.** 🪽 Ouvrez votre navigateur et commencez la chasse !🪽

- http://localhost:8501 — Requêtes intégrées et Chat IA
- http://localhost:8088 — Tableau de bord (`admin` / `admin`)
- http://localhost:8502 — Graphe de ressources AWS Config

---

## Commandes du quotidien

`make` sans argument affiche cette liste. `make help-all` montre toutes les cibles.

| Commande | Rôle |
|---|---|
| `make ingest` | Charger les journaux CloudTrail de `docker/logs/` dans DuckDB |
| `make up` | Démarrer l'interface, le tableau de bord et le graphe de ressources |
| `make down` | Tout arrêter |
| `make logs` | Suivre les journaux des services (`SERVICE=agent` pour un seul) |
| `make reset` | Supprimer la base de données et recommencer |

---

## Proxy d'entreprise / Certificat CA personnalisé

Si vous êtes derrière un proxy d'entreprise effectuant une inspection TLS, consultez [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) pour les instructions de configuration.
