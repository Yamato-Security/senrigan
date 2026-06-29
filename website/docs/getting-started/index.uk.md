# Початок роботи

## Передумови

| Вимога                                | Деталі                                             |
|---------------------------------------|----------------------------------------------------|
| **Docker**                            | Docker Desktop або Docker Engine + Compose v2      |
| **make**                              | GNU Make (попередньо встановлено на macOS)         |
| **Ресурси**                           | мінімум 16 ГБ оперативної пам'яті, рекомендовано SSD |
| **Журнали CloudTrail**                | файли `.json` або `.json.gz`, експортовані з AWS   |
| *(Необов'язково)* **Знімки AWS Config** | файли `.json` або `.json.gz` для графу ресурсів AWS |
| *(Необов'язково)* **Ключ API OpenAI** | потрібен для генерації запитів за допомогою ШІ      |
| *(Необов'язково)* **MaxMind GeoLite2** | файли `.mmdb` для збагачення GeoIP                 |

---

## Швидкий старт

**Крок 1.** Завантажте журнали CloudTrail з S3.

```bash
aws s3 cp s3://<your-bucket-prefix> <local-output-dir>/ --recursive --include "*.json.gz"
```

**Крок 2.** Клонуйте репозиторій, завантажте журнали та запустіть усі служби.

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

**Крок 3.** 🪽 Відкрийте браузер і починайте полювання!🪽

- http://localhost:8501 — Вбудовані запити та AI Chat
- http://localhost:8088 — Інформаційна панель (`admin` / `admin`)
- http://localhost:8502 — Граф ресурсів AWS Config

**(Необов'язково)** Збагачення GeoIP.
Розмістіть [файли GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) у `docker/data/geoip/`, а потім:

```bash
make ingest-geoip
```

**(Необов'язково)** Завантаження знімків AWS Config для візуалізації графу ресурсів.
Розмістіть файли знімків AWS Config у `docker/logs/config/`, а потім:
```bash
make ingest-config
```
---

## Корпоративний проксі / користувацький сертифікат CA

Якщо ви перебуваєте за корпоративним проксі з інспекцією TLS, перегляньте [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) для отримання інструкцій з налаштування.
