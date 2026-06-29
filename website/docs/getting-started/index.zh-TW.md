# 開始使用

## 先決條件

| 需求                                  | 詳細說明                                           |
|---------------------------------------|----------------------------------------------------|
| **Docker**                            | Docker Desktop 或 Docker Engine + Compose v2       |
| **make**                              | GNU Make（macOS 已預先安裝）                       |
| **資源**                              | 至少 16 GB RAM，建議使用 SSD                       |
| **CloudTrail 日誌**                   | 從 AWS 匯出的 `.json` 或 `.json.gz` 檔案           |
| *(選用)* **AWS Config 快照**          | 用於 AWS 資源圖的 `.json` 或 `.json.gz` 檔案       |
| *(選用)* **OpenAI API 金鑰**          | AI 查詢產生功能所需                                 |
| *(選用)* **MaxMind GeoLite2**         | 用於 GeoIP 強化的 `.mmdb` 檔案                     |

---

## 快速開始

**步驟 1.** 從 S3 下載 CloudTrail 日誌。

```bash
aws s3 cp s3://<your-bucket-prefix> <local-output-dir>/ --recursive --include "*.json.gz"
```

**步驟 2.** 複製儲存庫、匯入日誌並啟動所有服務。

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

**步驟 3.** 🪽 開啟瀏覽器並開始狩獵！🪽

- http://localhost:8501 — 內建查詢與 AI Chat
- http://localhost:8088 — 儀表板（`admin` / `admin`）
- http://localhost:8502 — AWS Config 資源圖

**（選用）** GeoIP 強化。
將 [GeoLite2 `.mmdb` 檔案](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) 放置於 `docker/data/geoip/`，然後：

```bash
make ingest-geoip
```

**（選用）** 用於資源圖視覺化的 AWS Config 快照匯入。
將 AWS Config 快照檔案放置於 `docker/logs/config/`，然後：
```bash
make ingest-config
```
---

## 企業代理伺服器 / 自訂 CA 憑證

如果您位於進行 TLS 檢測的企業代理伺服器之後，請參閱 [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) 以取得設定說明。
