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

**ステップ 2.** リポジトリをクローンし、データを配置します。

```bash
# Clone the repository
git clone https://github.com/Yamato-Security/senrigan.git
cd senrigan

# Place the downloaded CloudTrail logs here
cp -r <local-output-dir>/ docker/logs/
```

以下の 2 つの任意ディレクトリは自動的に検出されます。次のステップの**前**に配置してください。追加のコマンドは不要です。

| ディレクトリ | 配置するもの | 有効になる機能 |
|---|---|---|
| `docker/data/geoip/` | [GeoLite2 `.mmdb`](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) | 送信元 IP を国・都市・ASN に解決します |
| `docker/data/config-snapshots/` | AWS Config スナップショットの `.json` ファイル | AWS Config リソースグラフを構築します |

**ステップ 3.** ログを取り込み、サービスを起動します。

```bash
make ingest
make up
```

**ステップ 4.** 🪽 ブラウザを開いてハンティングを始めましょう！🪽

- http://localhost:8501 — 組み込みクエリと AI Chat
- http://localhost:8088 — ダッシュボード（`admin` / `admin`）
- http://localhost:8502 — AWS Config リソースグラフ

---

## 日常的に使うコマンド

引数なしで `make` を実行するとこの一覧が表示されます。すべてのターゲットは `make help-all` で確認できます。

| コマンド | 説明 |
|---|---|
| `make ingest` | `docker/logs/` の CloudTrail ログを DuckDB に取り込む |
| `make up` | UI・ダッシュボード・リソースグラフを起動する |
| `make down` | すべて停止する |
| `make logs` | サービスのログを追跡する（1 つだけなら `SERVICE=agent`） |
| `make reset` | データベースを削除して最初からやり直す |

---

## 企業プロキシ / カスタム CA 証明書

TLS インスペクションを行う企業プロキシの背後にいる場合は、セットアップ手順について [doc/DEVELOPMENT.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/DEVELOPMENT.md#6-corporate-proxy--custom-ca-certificate) を参照してください。
