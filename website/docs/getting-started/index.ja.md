# はじめに

## 前提条件

| 要件                                  | 詳細                                               |
|---------------------------------------|----------------------------------------------------|
| **Docker**                            | Docker Desktop または Docker Engine + Compose v2   |
| **make**                              | GNU Make（macOS にはプリインストール済み）         |
| **リソース**                          | 最低 16 GB RAM、SSD 推奨                            |
| **CloudTrail ログ**                   | AWS からエクスポートした `.json` または `.json.gz` ファイル |
| *(任意)* **AWS Config スナップショット** | AWS リソースグラフ用の `.json` または `.json.gz` ファイル |
| *(任意)* **OpenAI API キー**          | AI クエリ生成に必要                                 |
| *(任意)* **MaxMind GeoLite2**         | GeoIP エンリッチメント用の `.mmdb` ファイル        |

---

## クイックスタート

**ステップ 1.** S3 から CloudTrail ログをダウンロードします。

```bash
aws s3 cp s3://<your-bucket-prefix> <local-output-dir>/ --recursive --include "*.json.gz"
```

**ステップ 2.** リポジトリをクローンし、ログを取り込み、すべてのサービスを起動します。

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

**ステップ 3.** 🪽 ブラウザを開いてハンティングを始めましょう！🪽

- http://localhost:8501 — 組み込みクエリと AI Chat
- http://localhost:8088 — ダッシュボード（`admin` / `admin`）
- http://localhost:8502 — AWS Config リソースグラフ

**(任意)** GeoIP エンリッチメント。
[GeoLite2 `.mmdb` ファイル](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) を `docker/data/geoip/` に配置してから、次を実行します。

```bash
make ingest-geoip
```

**(任意)** リソースグラフ可視化のための AWS Config スナップショットの取り込み。
AWS Config スナップショットファイルを `docker/logs/config/` に配置してから、次を実行します。
```bash
make ingest-config
```
---

## 企業プロキシ / カスタム CA 証明書

TLS インスペクションを行う企業プロキシの背後にいる場合は、セットアップ手順について [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) を参照してください。
