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

**Крок 2.** Клонуйте репозиторій і розмістіть свої дані.

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded CloudTrail logs here
cp -r <local-output-dir>/ docker/logs/
```

Два необов'язкові каталоги нижче виявляються автоматично. Заповніть їх **перед** наступним кроком — жодної додаткової команди виконувати не потрібно.

| Каталог | Вміст | Що додає |
|---|---|---|
| `docker/data/geoip/` | [GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | Визначає країну, місто та ASN за вихідними IP-адресами |
| `docker/data/config-snapshots/` | Файли `.json` знімків AWS Config | Будує граф ресурсів AWS Config |

**Крок 3.** Завантажте журнали та запустіть служби.

```bash
make ingest
make up
```

**Крок 4.** 🪽 Відкрийте браузер і починайте полювання!🪽

- http://localhost:8501 — Вбудовані запити та AI Chat
- http://localhost:8088 — Інформаційна панель (`admin` / `admin`)
- http://localhost:8502 — Граф ресурсів AWS Config

---

## Щоденні команди

`make` без аргументів виводить цей перелік. `make help-all` показує всі цілі.

| Команда | Призначення |
|---|---|
| `make ingest` | Завантажити журнали CloudTrail з `docker/logs/` у DuckDB |
| `make up` | Запустити інтерфейс, інформаційну панель і граф ресурсів |
| `make down` | Зупинити все |
| `make logs` | Стежити за журналами служб (`SERVICE=agent` для однієї) |
| `make reset` | Видалити базу даних і почати спочатку |

---

## Корпоративний проксі / користувацький сертифікат CA

Якщо ви перебуваєте за корпоративним проксі з інспекцією TLS, перегляньте [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) для отримання інструкцій з налаштування.
