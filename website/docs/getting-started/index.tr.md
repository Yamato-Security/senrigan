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

**Adım 2.** Depoyu klonlayın ve verilerinizi yerleştirin.

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded CloudTrail logs here
cp -r <local-output-dir>/ docker/logs/
```

Aşağıdaki iki isteğe bağlı dizin otomatik olarak algılanır. Bir sonraki adımdan **önce** doldurun — çalıştırmanız gereken ek bir komut yoktur.

| Dizin | İçerik | Sağladığı |
|---|---|---|
| `docker/data/geoip/` | [GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | Kaynak IP'leri ülke, şehir ve ASN bilgisine çözümler |
| `docker/data/config-snapshots/` | AWS Config anlık görüntü `.json` dosyaları | AWS Config kaynak grafiğini oluşturur |

**Adım 3.** Günlükleri içe aktarın ve hizmetleri başlatın.

```bash
make ingest
make up
```

**Adım 4.** 🪽 Tarayıcınızı açın ve avlanmaya başlayın!🪽

- http://localhost:8501 — Yerleşik sorgular ve AI Chat
- http://localhost:8088 — Dashboard (`admin` / `admin`)
- http://localhost:8502 — AWS Config kaynak grafiği

---

## Günlük komutlar

Argümansız `make` bu listeyi yazdırır. `make help-all` tüm hedefleri gösterir.

| Komut | İşlevi |
|---|---|
| `make ingest` | `docker/logs/` içindeki CloudTrail günlüklerini DuckDB'ye yükler |
| `make up` | Arayüzü, panoyu ve kaynak grafiğini başlatır |
| `make down` | Her şeyi durdurur |
| `make logs` | Hizmet günlüklerini izler (tek hizmet için `SERVICE=agent`) |
| `make reset` | Veritabanını siler ve baştan başlar |

---

## Kurumsal Proxy / Özel CA Sertifikası

TLS denetimi yapan bir kurumsal proxy arkasındaysanız, kurulum talimatları için [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) belgesine bakın.
