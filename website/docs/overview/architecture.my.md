# ဗိသုကာ (Architecture)

Docker container လေးခုသည် bind mount (`docker/data/db/`) တစ်ခုမှတစ်ဆင့် DuckDB file တစ်ခုကို မျှဝေအသုံးပြုကြသည်။

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

## အစအဆုံး အစီအစဉ်ပြ ဇယား (End-to-End Sequence Diagram)

အပြည့်အစုံ lifecycle အစီအစဉ်ပြ ဇယားအတွက် [doc/ARCHITECTURE.md](https://github.com/Yamato-Security/senrigan/blob/main/doc/ARCHITECTURE.md#end-to-end-sequence-diagram) ကို ကြည့်ရှုပါ။

---
