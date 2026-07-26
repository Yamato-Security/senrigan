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

**步驟 2.** 複製儲存庫並放置您的資料。

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded CloudTrail logs here
cp -r <local-output-dir>/ docker/logs/
```

以下兩個選用目錄會被自動偵測。請在下一步**之前**放入檔案 — 不需要執行額外的指令。

| 目錄 | 放置內容 | 啟用的功能 |
|---|---|---|
| `docker/data/geoip/` | [GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | 將來源 IP 解析為國家、城市與 ASN |
| `docker/data/config-snapshots/` | AWS Config 快照 `.json` 檔案 | 建立 AWS Config 資源圖 |

**步驟 3.** 匯入日誌並啟動服務。

```bash
make ingest
make up
```

**步驟 4.** 🪽 開啟瀏覽器並開始狩獵！🪽

- http://localhost:8501 — 內建查詢與 AI Chat
- http://localhost:8088 — 儀表板（`admin` / `admin`）
- http://localhost:8502 — AWS Config 資源圖

---

## 日常指令

不加參數執行 `make` 會印出這份清單。`make help-all` 會顯示所有目標。

| 指令 | 作用 |
|---|---|
| `make ingest` | 將 `docker/logs/` 的 CloudTrail 日誌匯入 DuckDB |
| `make up` | 啟動 UI、儀表板與資源圖 |
| `make down` | 停止所有服務 |
| `make logs` | 追蹤服務日誌（只看單一服務用 `SERVICE=agent`） |
| `make reset` | 刪除資料庫並重新開始 |

---

## 企業代理伺服器 / 自訂 CA 憑證

如果您位於進行 TLS 檢測的企業代理伺服器之後，請參閱 [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) 以取得設定說明。
