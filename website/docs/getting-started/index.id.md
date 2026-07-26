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

**Langkah 2.** Klon repositori dan tempatkan data Anda.

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded CloudTrail logs here
cp -r <local-output-dir>/ docker/logs/
```

Dua direktori opsional di bawah ini terdeteksi secara otomatis. Isi **sebelum** langkah berikutnya — tidak ada perintah tambahan yang perlu dijalankan.

| Direktori | Isi | Yang ditambahkan |
|---|---|---|
| `docker/data/geoip/` | [GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | Menerjemahkan IP sumber menjadi negara, kota, dan ASN |
| `docker/data/config-snapshots/` | File `.json` snapshot AWS Config | Membangun grafik sumber daya AWS Config |

**Langkah 3.** Masukkan log dan jalankan layanan.

```bash
make ingest
make up
```

**Langkah 4.** 🪽 Buka peramban Anda dan mulai berburu!🪽

- http://localhost:8501 — Kueri bawaan dan AI Chat
- http://localhost:8088 — Dashboard (`admin` / `admin`)
- http://localhost:8502 — Grafik sumber daya AWS Config

---

## Perintah sehari-hari

Menjalankan `make` tanpa argumen akan menampilkan daftar ini. `make help-all` menampilkan semua target.

| Perintah | Fungsi |
|---|---|
| `make ingest` | Memuat CloudTrail logs dari `docker/logs/` ke DuckDB |
| `make up` | Menjalankan UI, dashboard, dan grafik sumber daya |
| `make down` | Menghentikan semuanya |
| `make logs` | Memantau log layanan (`SERVICE=agent` untuk satu layanan) |
| `make reset` | Menghapus basis data dan memulai dari awal |

---

## Proxy Perusahaan / Sertifikat CA Kustom

Jika Anda berada di belakang proxy perusahaan yang melakukan inspeksi TLS, lihat [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) untuk petunjuk penyiapan.
