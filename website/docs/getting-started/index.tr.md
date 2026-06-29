# Başlarken

## Ön Koşullar

| Gereksinim                            | Ayrıntılar                                         |
|---------------------------------------|----------------------------------------------------|
| **Docker**                            | Docker Desktop veya Docker Engine + Compose v2     |
| **make**                              | GNU Make (macOS'ta önceden yüklü)                  |
| **Kaynaklar**                         | En az 16 GB RAM, SSD önerilir                      |
| **CloudTrail günlükleri**             | AWS'den dışa aktarılan `.json` veya `.json.gz` dosyaları |
| *(İsteğe bağlı)* **AWS Config anlık görüntüleri** | AWS kaynak grafiği için `.json` veya `.json.gz` dosyaları |
| *(İsteğe bağlı)* **OpenAI API anahtarı** | AI sorgu üretimi için gereklidir                |
| *(İsteğe bağlı)* **MaxMind GeoLite2** | GeoIP zenginleştirmesi için `.mmdb` dosyaları      |

---

## Hızlı Başlangıç

**Adım 1.** CloudTrail günlüklerini S3'ten indirin.

```bash
aws s3 cp s3://<your-bucket-prefix> <local-output-dir>/ --recursive --include "*.json.gz"
```

**Adım 2.** Depoyu klonlayın, günlükleri içe aktarın ve tüm hizmetleri başlatın.

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

**Adım 3.** 🪽 Tarayıcınızı açın ve avlanmaya başlayın!🪽

- http://localhost:8501 — Yerleşik sorgular ve AI Chat
- http://localhost:8088 — Dashboard (`admin` / `admin`)
- http://localhost:8502 — AWS Config kaynak grafiği

**(İsteğe bağlı)** GeoIP zenginleştirmesi.
[GeoLite2 `.mmdb` dosyalarını](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) `docker/data/geoip/` dizinine yerleştirin, ardından:

```bash
make ingest-geoip
```

**(İsteğe bağlı)** Kaynak grafiği görselleştirmesi için AWS Config anlık görüntüsü içe aktarımı.
AWS Config anlık görüntü dosyalarını `docker/logs/config/` dizinine yerleştirin, ardından:
```bash
make ingest-config
```
---

## Kurumsal Proxy / Özel CA Sertifikası

TLS denetimi yapan bir kurumsal proxy arkasındaysanız, kurulum talimatları için [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) belgesine bakın.
