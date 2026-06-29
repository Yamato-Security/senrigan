# モジュール

| モジュール | 言語 | 役割 | README |
|--------|----------|------|--------|
| `ingester` | Rust 1.85+ | CloudTrail ログの取り込み (READ_WRITE) | [ingester/README.md](https://github.com/Yamato-Security/senrigan/blob/main/ingester/README.md) |
| `agent` | Python 3.14+ / Streamlit | 脅威ハンティングのための AI 支援対話型チャット (READ_ONLY) | [agent/README.md](https://github.com/Yamato-Security/senrigan/blob/main/agent/README.md) |
| `dashboard` | Apache Superset 6.1 | BI 可視化 (READ_ONLY) | [dashboard/README.md](https://github.com/Yamato-Security/senrigan/blob/main/dashboard/README.md) |
| `config_viz` | FastAPI + React | AWS Config の可視化 (READ_ONLY) | [config_viz/README.md](https://github.com/Yamato-Security/senrigan/blob/main/config_viz/README.md) |
