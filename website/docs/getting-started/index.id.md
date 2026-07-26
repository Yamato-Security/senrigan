# Memulai

## Prasyarat

| Persyaratan                           | Detail                                             |
|---------------------------------------|----------------------------------------------------|
| **Docker**                            | Docker Desktop atau Docker Engine + Compose v2     |
| **make**                              | GNU Make (sudah terpasang di macOS)                |
| **Sumber Daya**                       | RAM minimum 16 GB, SSD direkomendasikan            |
| **CloudTrail logs**                   | File `.json` atau `.json.gz` yang diekspor dari AWS |
| *(Opsional)* **AWS Config snapshots** | File `.json` atau `.json.gz` untuk grafik sumber daya AWS |
| *(Opsional)* **OpenAI API key**       | Diperlukan untuk pembuatan kueri AI                |
| *(Opsional)* **MaxMind GeoLite2**     | File `.mmdb` untuk pengayaan GeoIP                 |

---

## Mulai Cepat

**Langkah 1.** Unduh CloudTrail logs dari S3.

```bash
aws s3 cp s3://<your-bucket-prefix> <local-output-dir>/ --recursive --include "*.json.gz"
```

**Langkah 2.** Klon repositori, masukkan log, dan jalankan semua layanan.

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

**Langkah 3.** 🪽 Buka peramban Anda dan mulai berburu!🪽

- http://localhost:8501 — Kueri bawaan dan AI Chat
- http://localhost:8088 — Dashboard (`admin` / `admin`)
- http://localhost:8502 — Grafik sumber daya AWS Config

**(Opsional)** Pengayaan GeoIP.
Tempatkan [file GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) di `docker/data/geoip/`, lalu:

```bash
make ingest-geoip
```

**(Opsional)** Pemasukan snapshot AWS Config untuk visualisasi grafik sumber daya.
Tempatkan file snapshot AWS Config di `docker/data/config-snapshots/`, lalu:
```bash
make ingest-config
```
---

## Proxy Perusahaan / Sertifikat CA Kustom

Jika Anda berada di belakang proxy perusahaan yang melakukan inspeksi TLS, lihat [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) untuk petunjuk penyiapan.
