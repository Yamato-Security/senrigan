# Architektur

Vier Docker-Container teilen sich eine DuckDB-Datei über einen Bind Mount (`docker/data/db/`).

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

## End-to-End-Sequenzdiagramm

Das vollständige Sequenzdiagramm des Lebenszyklus finden Sie unter [doc/ARCHITECTURE.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/ARCHITECTURE.md#end-to-end-sequence-diagram).

---
