# Arsitektur

Empat kontainer Docker berbagi satu berkas DuckDB melalui bind mount (`docker/data/db/`).

```
┌────────────────────────────────────────────────────────────────────────┐
│                             Docker Compose                             │
│                                                                        │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  ┌─────────────┐  │
│  │   ingester   │  │    agent     │  │  config_viz │  │  dashboard  │  │
│  │  (Rust)      │  │  (Streamlit) │  │  (FastAPI+  │  │  (Superset) │  │
│  │              │  │              │  │   React)    │  │             │  │
│  │ CloudTrail   │  │  AI Chat     │  │   Resource  │  │  Visualiz   │  │
│  │ AWS Config   │  │  SQL gen/exec│  │    Graph    │  │             │  │
│  │ ingest       │  │  READ_ONLY   │  │   READ_ONLY │  │   READ_ONLY │  │
│  │ READ_WRITE   │  │              │  │             │  │             │  │
│  └──────┬───────┘  └──────┬───────┘  └────┬────────┘  └─────┬───────┘  │
│         └─────────────────┴───────────────┴─────────────────┘          │
│                                │                                       │
│                         ┌──────▼───────┐                               │
│                         │   DuckDB     │                               │
│                         │ (Bind Mount) │                               │
│                         │   (SSD)      │                               │
│                         └──────────────┘                               │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Diagram Urutan End-to-End

Lihat [doc/ARCHITECTURE.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/ARCHITECTURE.md#end-to-end-sequence-diagram) untuk diagram urutan siklus hidup lengkap.

---
