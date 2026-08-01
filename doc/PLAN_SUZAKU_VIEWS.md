# PLAN: Suzaku result visualization (agent + dashboard)

> **Status: implemented; §3 guideline 1 revised.** Everything here shipped. The guideline
> "give `aws-ct-summary` / `aws-ct-metrics` dashboards and *do not* build agent pages for them"
> was later narrowed: it is right about **chat** pages, not about agent pages in general. Both
> commands now also have an agent *explorer* page, which generates no SQL — see
> [PLAN_SUZAKU_EXPLORERS.md](PLAN_SUZAKU_EXPLORERS.md) §1, which also closes open question 3
> below.

Add visualization and query capabilities for [Suzaku](https://github.com/Yamato-Security/suzaku)
output to Senrigan. Suzaku is Yamato Security's CloudTrail DFIR engine; since it can emit
DuckDB files directly, Senrigan can read those files as-is — no re-ingestion, no schema
migration of `threat_hunting.db`.

Scope:

- **agent** — a second Streamlit page for `aws-ct-timeline`, with the same affordances as the
  existing hunting page (built-in queries, date filter, session clear, Markdown/HTML report,
  result-presence + keyword filters, AI chat and AI analysis).
- **dashboard** — one Superset dashboard per Suzaku command. `aws-ct-timeline` shipped as an
  **empty template** in this plan; its charts landed later — see
  [PLAN_SUZAKU_TIMELINE_DASHBOARD.md](PLAN_SUZAKU_TIMELINE_DASHBOARD.md). `aws-ct-summary` and
  `aws-ct-metrics` get full layouts here.
- **detection** — the Suzaku command that produced a `.duckdb` file is inferred from its
  schema, not from its filename.

---

## 1. Current state (verified 2026-07-26)

### 1.1 What already exists

| Fact | Consequence for this plan |
|------|---------------------------|
| Four containers share **one** DuckDB file (`docker/data/db/threat_hunting.db`), 1 writer / N readers | Suzaku DBs are *additional* read-only files in the same mounted directory — no compose change needed |
| `agent`, `superset`, `superset-init`, `config-viz` all mount `${DUCKDB_HOST_PATH:-./data/db}` → `/data/db:ro` | Copying `*.duckdb` into `docker/data/db/` makes them visible to every reader immediately |
| `.gitignore` ignores `*.db` / `*.db.wal` — **not** `*.duckdb` | The 247 MB `sample/suzaku/sample-aws-ct-timeline.duckdb` would be committed. Must be fixed in Phase 0 |
| `agent/query.py::connect_duckdb` sets `enable_external_access=false` + `lock_configuration=true` | `ATTACH` of a second database is blocked. **Use one connection per DuckDB file**, never ATTACH |
| `agent` is a single page (`app.py::main` → `_chat_page`) | Needs `st.navigation` with two pages. The deleted `agent/views/` package used exactly this pattern |
| Superset has **one** registered database (`CloudTrail DuckDB`, fixed UUID `a1b2c3d4-…`) created by `dashboard/init/register_duckdb.py`, URI `duckdb+duckdb_engine:////data/db/threat_hunting.db`, `connect_args.read_only=true` | Each Suzaku DB needs its own Superset database object, because a `sqlalchemy_uri` names exactly one file |
| Asset bundles are directories (`dashboard/assets/cloudtrail_default/{metadata,dashboard}.yaml + databases/ datasets/ charts/`) compiled to a ZIP by `rebuild_zip.py`, imported by the one-shot `superset-init` container | New bundles follow the same shape; the "edit YAML → rebuild ZIP → re-import" rule applies to them too |
| duckdb versions: superset image **1.5.4**, `agent/requirements.txt` `duckdb>=1.5.2`, host CLI 1.5.2 | All three sample files open read-only in both readers — verified |
| Branches `feature/dashboard-suzaku-timeline` / `feature/dashboard-suzaku-detections` implement an **`ingester suzaku-import`** subcommand (CSV/JSONL → `threat_hunting.db`) | Overlapping, older approach. See §7.1 — a decision is required before either merges |

### 1.2 Where the agent is coupled to `cloudtrail_events`

Reusing the hunting UI for a different table requires breaking five hard-coded assumptions:

| Location | Hard-coded assumption |
|----------|----------------------|
| `agent/schema.py` | `CLOUDTRAIL_COLUMNS` + `get_schema_description()` — one table only |
| `agent/prompts/system_prompt.py` | Table name `cloudtrail_events`, snake_case columns, `json_extract_string` idioms |
| `agent/query.py::apply_date_filter` | Rewrites `cloudtrail_events` → `_ct_filtered`, filters `event_time` as a real `TIMESTAMP` |
| `agent/app.py` + `agent/handlers.py` | Flat `st.session_state` keys (`messages`, `query_history`, `last_sql`, …) shared by a single page |
| `agent/geo.py` | Joins `geo_*` columns **stored on `cloudtrail_events`** |

---

## 2. Input contract

Verified against the three sample databases.

### 2.1 `aws-ct-timeline` — table `timeline` (1,206,049 rows in the sample)

```
Timestamp TIMESTAMP        RuleTitle RuleAuthor  Level suzaku_level (ENUM)
EventName ErrorCode ErrorMessage EventSource AwsRegion SrcIP UserAgent
UserName UserType UserAccountID UserARN UserPrincipalID UserAccessKeyID EventID
Tactics VARCHAR[]  TechniqueIDs VARCHAR[]  OtherTags VARCHAR[]  RuleID
```

Characteristics that drive the design:

- `Timestamp` is a real **TIMESTAMP**, in the zone named by `suzaku_meta.timestamp_tz`. No CAST
  anywhere.
- Every column is PascalCase → all identifiers must be double-quoted in generated SQL. This must
  be stated in the system prompt and honoured by every built-in query.
- `Level` is the ordered ENUM `suzaku_level`: `informational < low < medium < high < critical`.
  `ORDER BY "Level" DESC` is severity order, but DuckDB compares an ENUM against a bare string
  literal *as text*, so a threshold must cast: `"Level" >= 'high'::suzaku_level`. The sample
  skews low: low 858,105 / informational 194,247 / medium 148,169 / high 5,525 / **critical 3**.
  → default views must be Top-N and severity-biased, never "all rows".
- ATT&CK data is three `VARCHAR[]` columns — `Tactics`, `TechniqueIDs`, `OtherTags` — empty
  lists rather than NULL, so `unnest` and `list_contains` need no guard.
- Absent values are `NULL`, not `'-'`.
- No geo columns unless Suzaku ran with `--geo-ip`. Sample spans 2017-02-12 → 2024-08-18.

### 2.2 `aws-ct-summary` — three tables

```
summary            (UserARN, NumOfEvents, FirstTimestamp, LastTimestamp, UserTypes VARCHAR[])   22 rows
summary_api_calls  (UserARN, IsAbused BOOLEAN, Outcome ENUM, API, EventSource,
                    Description, Count, FirstSeen, LastSeen)                                 2,667 rows
summary_attributes (UserARN, Attribute, Value, Count, FirstSeen, LastSeen)                  18,127 rows
```

- `IsAbused` × `Outcome` (`success | failed`) is the analytic centre of gravity — the abused/other
  split, now two orthogonal columns instead of one packed `Category` string.
- `API` is the action alone and `EventSource` the service; `Description` is Suzaku's human
  explanation of *why* the API is abusable — surface it, it is the highest-value column in the file.
- `Attribute` ∈ `UserAgent | SrcIP | AwsRegion | UserAccessKeyID`, named after the timeline columns.
- Identity-centric, tiny (22 identities). Perfect dashboard material, poor chat material.

### 2.3 `aws-ct-metrics` — table `metrics` (1,344 rows)

```
Field TimelineColumn Value Count FieldTotal Percent FirstSeen LastSeen
[SrcASN SrcCity SrcCountry — only under --geo-ip]
```

- `Field` is **whatever field the analyst passed to Suzaku** (`eventName` in the sample; only one
  value present), and `TimelineColumn` is the same field under its `timeline` column name
  (`EventName`). The dashboard must therefore be *field-agnostic*: a native filter on `Field`,
  never a chart that assumes `eventName`.
- `Percent` is full-precision and `FieldTotal` is the denominator it came from, so a filtered
  share can be recomputed exactly.
- `SrcASN` / `SrcCity` / `SrcCountry` exist **only** when Suzaku ran with `--geo-ip`. The
  `suzaku_metrics` dataset selects them, so the metrics dashboard requires an enriched run.

### 2.4 Detection specification

Every Suzaku DuckDB file carries a one-row `suzaku_meta` table, so a file is classified by
**reading `suzaku_meta.command`** — no table-name heuristic.

| Kind | `suzaku_meta.command` | Payload tables |
|------|-----------------------|----------------|
| `aws-ct-timeline` | `aws-ct-timeline` | `timeline` |
| `aws-ct-summary` | `aws-ct-summary` | `summary`, `summary_api_calls`, `summary_attributes` |
| `aws-ct-metrics` | `aws-ct-metrics` | `metrics` |

Rules:

1. `suzaku_meta.schema_version` is checked first. A version above the one the reader was written
   against (`SUPPORTED_SCHEMA_VERSION`) is **refused** with an explanation, not read — that is
   what the version exists for.
2. A file containing `cloudtrail_events` is Senrigan's own DB → `UNKNOWN`, whatever its metadata
   claims. (In practice the `.duckdb` vs `.db` extension already separates them; do not rely on
   that alone.)
3. A file with no `suzaku_meta` table → `UNKNOWN`, with a hint naming the table, because that is
   what pre-`schema_version`-1 output looks like.
4. An unknown command (Suzaku's Azure subcommands) → `UNKNOWN`.
5. Unopenable file → a typed error carrying the DuckDB message. Two cases must be distinguished
   and explained in the UI, because both are operator mistakes, not bugs:
   - written by a newer DuckDB than the reader ("…is not a valid DuckDB database file" /
     version mismatch) → upgrade `duckdb` in the reader,
   - a stale `<file>.wal` next to it on a read-only mount → checkpoint before copying.

The schema behind all of this — and the record of which Senrigan workarounds each upstream change
removed — is [PLAN_SUZAKU_SCHEMA.md](PLAN_SUZAKU_SCHEMA.md), §11 in particular.

---

## 3. Design guidance: agent vs dashboard

The rule of thumb Senrigan already follows implicitly, made explicit for Suzaku data:

| | `agent` (Streamlit) | `dashboard` (Superset) |
|---|---|---|
| Question shape | "What happened to *this* principal?" — unknown, evolving | "What does this dataset look like?" — known, fixed |
| Interaction | Ask → SQL → read → refine → ask again | Scan → filter → drill down |
| Output | A narrative: report entries, analyst notes, Markdown/HTML deliverable | A picture: KPI row, Top-N bars, trend, composition |
| Latency budget | Seconds per query, one query at a time | Sub-second per chart, ~15 charts at once |
| Fits Suzaku | `aws-ct-timeline` — 1.9 M rows, high cardinality, needs pivoting mid-investigation | all three, especially `aws-ct-summary` / `aws-ct-metrics`, which are already *pre-aggregated by Suzaku* |

Three concrete guidelines that follow from this:

1. **Pre-aggregated output belongs on the dashboard.** `aws-ct-summary` (22 identities) and
   `aws-ct-metrics` (1,344 rows) are Suzaku's own aggregations. Re-aggregating them through an
   LLM adds cost and a hallucination surface while removing nothing. Give them dashboards and
   *do not* build agent pages for them. Raw, wide, high-cardinality output (`aws-ct-timeline`)
   is where ad-hoc SQL and AI narration earn their keep — hence the single agent page requested.
2. **The agent discovers at runtime; the dashboard registers at init.** Streamlit can glob
   `/data/db/*.duckdb` on every rerun and pick a DB from a selectbox. Superset cannot: a
   `sqlalchemy_uri` is stored metadata, resolved once by `superset-init`. So detection must run
   in **both** places — dynamically in the agent, once at bootstrap for Superset — and the two
   implementations must agree. Keep one canonical signature table per module and add a
   repository-level test in root `tests/` asserting the two constant tables are identical
   (this is exactly what `tests/test_docs.py` already does for docs ↔ Makefile drift).
3. **Never let one module write what the other reads.** Suzaku DBs are third-party artifacts:
   both modules open them read-only, neither migrates them, and `ingester` must not touch them.
   That keeps the 1-writer/N-reader invariant intact and means a user can re-run Suzaku, drop in
   a new file, and restart — no re-ingest.

Corollary for the report feature: only the agent produces reports, so anything that must appear
in a deliverable (the `aws-ct-summary` identity triage table, for instance) should be reachable
as a **built-in query on the timeline page** as well — do not push analysts to screenshot
Superset. Where the same insight is wanted in both places, keep the SQL in the agent's hunts YAML
and mirror it as a Superset virtual dataset, never as a third copy.

---

## 4. agent module

### 4.1 Dataset profile abstraction

Introduce `agent/profiles.py` — one frozen dataclass describing a queryable table, so the whole
chat pipeline becomes table-agnostic without duplicating it:

```python
@dataclass(frozen=True)
class DatasetProfile:
    key: str                    # "cloudtrail" | "suzaku_timeline"
    label: str                  # sidebar / nav label
    table: str                  # "cloudtrail_events" | "timeline"
    time_column: str            # "event_time" | "Timestamp"
    time_is_varchar: bool       # True → CAST(col AS TIMESTAMP) inside the filter CTE
                                #   (no profile sets it: both tables are typed)
    filter_alias: str           # "_ct_filtered" | "_sz_filtered"
    quote_identifiers: bool     # True for Suzaku (PascalCase columns)
    columns: list[dict]         # schema.py-shaped column metadata
    hunts_path: Path            # builtin_hunts.yaml | suzaku_timeline_hunts.yaml
    supports_geo_enrich: bool   # False for Suzaku (no geo_* columns)
    state_prefix: str           # "" | "sz_"
    default_row_limit: int      # 100 | 200
```

`CLOUDTRAIL_PROFILE` reproduces today's behaviour exactly; `SUZAKU_TIMELINE_PROFILE` describes
`timeline`. Every function that currently hard-codes the table takes `profile` as a
**keyword argument defaulting to `CLOUDTRAIL_PROFILE`**, so all ~469 existing agent tests keep
passing untouched — that default is what makes this refactor safely incremental:

- `query.apply_date_filter(sql, start, end, *, profile=CLOUDTRAIL_PROFILE)` — CTE name, table
  name and the `CAST` come from the profile.
- `schema.get_schema_description(profile=...)`, `schema.get_column_names(profile=...)`.
- `llm.build_system_prompt(profile=...)`, `generate_sql(..., profile=...)`,
  `fix_sql_with_llm(..., profile=...)`, `generate_analysis(..., profile=...)`.
- `handlers._handle_user_query(user_input, db_path, *, profile=...)`, likewise
  `_handle_direct_sql`, `_handle_edit_rerun_sql`, `_analyze_entry_results`, `_maybe_enrich_geo`
  (returns the frame unchanged when `supports_geo_enrich` is False).
- Session state: a tiny `state_key(profile, name)` helper prefixes keys, so the two pages keep
  independent history, notes, filters and reports (`sz_messages`, `sz_query_history`, …).
  `_init_session_state(profile)` seeds only that page's namespace.

A second system prompt (`agent/prompts/suzaku_timeline_prompt.py`) carries the Suzaku idioms:
always double-quote identifiers, `unnest("TechniqueIDs")` / `list_contains("Tactics", …)` for
ATT&CK data, `"Level" >= 'high'::suzaku_level` for a severity threshold (a bare literal would
compare alphabetically), and a hard rule to always `ORDER BY` + `LIMIT` because the table has
millions of rows.

### 4.2 Suzaku DB discovery

`agent/suzaku_db.py` (pure, no Streamlit):

- `SUZAKU_TABLES` / `SUPPORTED_SCHEMA_VERSION` — the §2.4 table, the module's single source of truth.
- `detect_kind(command: str | None) -> SuzakuKind | None` — pure, trivially testable.
- `inspect_db(path) -> DbInfo` — opens read-only, reads `information_schema` and `suzaku_meta`,
  returns `DbInfo(path, kind, tables, row_counts, error, hint)`; never raises for a bad file.
- `discover(directory=Path("/data/db")) -> list[DbInfo]` — globs `*.duckdb`, sorted by mtime
  descending so the newest run wins when two files share a kind.
- Env overrides `SUZAKU_TIMELINE_DB` / `SUZAKU_SUMMARY_DB` / `SUZAKU_METRICS_DB` take precedence
  over discovery (needed for tests, and for an analyst keeping several runs side by side).

### 4.3 The Suzaku Timeline page

`agent/views/suzaku_timeline.py`, wired via `st.navigation` in `main()` alongside the existing
chat page (`app.py` keeps ownership of `st.set_page_config`).

Sidebar (same components as today, driven by the profile):

- **DB selector** — one entry per discovered `aws-ct-timeline` file, with `path`, row count and
  detected kind as a caption. Empty state: an explicit "no Suzaku timeline DB found in
  `/data/db` — see the setup steps" panel, not an exception.
- **Preset hunts** — from `agent/suzaku_timeline_hunts.yaml`, grouped by category, with the
  existing "Run All" / per-category bulk execution and progress bar.
- **Top-N control** — the profile's `default_row_limit` (200) surfaced as the existing
  *Result Limit* number input. Every hunt SQL carries its own `ORDER BY … LIMIT`; the row cap
  still wraps it as a backstop.
- **Date range** — reuses the calendar widgets; the injected CTE casts `Timestamp`.
- **Severity filter** — a Suzaku-specific multiselect (`critical`/`high`/`medium` by default,
  `low`/`informational` off) injected into the same CTE. This is what keeps the page usable at
  1.9 M rows.
- **Report / Session** — Markdown + HTML download and Clear, using the `sz_`-namespaced history
  so a Suzaku report never mixes with a CloudTrail one.
- Geo toggle hidden (`supports_geo_enrich=False`).

Main area: identical to `render_chat()` — result-presence + keyword filter bar, chat history with
result cards, bulk "Query Results" section, Edit & Re-run SQL, chat input, per-card "Ask AI".

### 4.4 Built-in timeline hunts (`agent/suzaku_timeline_hunts.yaml`)

Same YAML schema as `builtin_hunts.yaml` (`category`, `label`, `description`, `techniques`,
`chart`, `prompt`, `sql`), so the sidebar and report code need no changes. Initial set (~15),
every one Top-N and severity-aware:

| Category | Hunt |
|----------|------|
| Triage | Critical & High detections (latest N) |
| Triage | Detection volume by `Level` (composition chart) |
| Triage | Detection trend per day (timeseries chart) |
| Rules | Top rules by hits (medium+) |
| Rules | Rules seen only once — rare-event / bottom-N view |
| Rules | Rule onset: first/last seen per `RuleTitle` |
| Identity | Top principals (`UserARN`) by medium+ detections |
| Identity | Root-account detections |
| Identity | Detections per `UserAccessKeyID` (long-lived key abuse) |
| Origin | Top `SrcIP` by distinct rules triggered (medium+) |
| Origin | Top `UserAgent` (SDK/CLI anomalies) |
| Origin | Principals active in an unusual number of `"AWS-Region"` per day |
| Failure | Detections with a non-empty `ErrorCode` (probing / brute force) |
| ATT&CK | Technique-tag exposure — `unnest(string_split("Tags", ' ¦ '))`, technique IDs only |
| ATT&CK | Rule × technique matrix for medium+ |

### 4.5 agent test list (TDD, Red first)

`agent/tests/test_suzaku_db.py`

1. `detect_kinds` returns `{TIMELINE}` for the timeline signature.
2. …`{SUMMARY}` only when all three summary tables are present; two of three → `UNKNOWN`.
3. …`{METRICS}` for the metrics signature.
4. Extra tables and extra columns still match (forward compatibility).
5. Column matching is case-insensitive; missing required column → `UNKNOWN`.
6. A DB containing `cloudtrail_events` → `UNKNOWN`.
7. Multiple kinds in one file → both returned.
8. `inspect_db` on a non-DuckDB file → `DbInfo.error` set, no exception.
9. `discover` globs only `*.duckdb`, skips `threat_hunting.db`, orders newest-first.
10. `SUZAKU_TIMELINE_DB` overrides discovery.

`agent/tests/test_profiles.py`

11. `CLOUDTRAIL_PROFILE` reproduces today's table/time column/alias values.
12. `state_key` namespaces per profile and leaves the cloudtrail profile keys unprefixed.

`agent/tests/test_query.py` (additions)

13. `apply_date_filter(..., profile=SUZAKU_TIMELINE_PROFILE)` rewrites `timeline` → `_sz_filtered`
    and casts `"Timestamp"`.
14. Existing cloudtrail cases unchanged with no `profile` argument.
15. Severity filter injection produces valid SQL and composes with the date CTE.
16. A quoted string literal containing `timeline` is not rewritten (existing
    `_sub_outside_string_literals` guarantee, re-asserted for the new table).

`agent/tests/test_schema.py` / `test_prompts.py` (additions)

17. `get_schema_description(profile=SUZAKU_TIMELINE_PROFILE)` lists all 20 timeline columns.
18. The Suzaku system prompt names `timeline`, never `cloudtrail_events`, and mandates quoting.

`agent/tests/test_suzaku_timeline_hunts.py`

19. Every hunt has the required keys and a unique label.
20. Every `sql` parses via `EXPLAIN` against the sample DB **and** returns ≤ the declared limit.
21. Every `sql` references only real `timeline` columns.
22. Every `sql` has both `ORDER BY` and `LIMIT`.
23. Every hunt referencing an ATT&CK technique carries a valid `tid`.

`agent/tests/test_suzaku_timeline_view.py`

24. Empty state renders a guidance panel when no Suzaku DB is discovered.
25. Report generation from `sz_` history produces Markdown and HTML with the Suzaku title.
26. Clear resets only the `sz_` namespace, leaving cloudtrail history intact.
27. Geo enrichment is skipped for the Suzaku profile even when the toggle is on.
28. `_handle_user_query` with no API key surfaces the same warning (no OpenAI call — mock `llm.OpenAI`).

Fixtures: build **small** DuckDB files in `tmp_path` for signature tests (a handful of rows,
milliseconds); use the committed trimmed sample only for the SQL-executes-and-limits tests.

---

## 5. dashboard module

### 5.1 Database registration by discovery

New `dashboard/init/register_suzaku_dbs.py`, run from `bootstrap.sh` before the dataset step:

- Scan `/data/db/*.duckdb` using its own copy of the §2.4 signature table (the superset image
  cannot import `agent/`), and register **one Superset `Database` per detected kind** with a
  fixed name and fixed UUID:

  | Kind | Superset database name |
  |------|------------------------|
  | `aws-ct-timeline` | `Suzaku Timeline DuckDB` |
  | `aws-ct-summary` | `Suzaku Summary DuckDB` |
  | `aws-ct-metrics` | `Suzaku Metrics DuckDB` |

- URI form and flags copy `register_duckdb.py` exactly: `duckdb+duckdb_engine:///<path>`,
  `connect_args.read_only=true`, `allow_dml=False`, `allow_run_async` left at False (no Celery —
  the existing `test_init_scripts.py` regression guard applies to the new script too).
- Idempotent: existing connection with a changed path → update the URI; unchanged → skip.
- Fixed UUIDs are the linchpin: dataset and chart YAMLs reference the database by UUID, so an
  analyst renaming their Suzaku output file changes only the stored URI, never the assets.
- Absent kind → skip registration *and* skip that bundle's ZIP import, so a user with only a
  timeline file does not get two dashboards full of errors.

### 5.2 Virtual datasets rename Suzaku's columns

Suzaku's DuckDB output is typed at the source, so the datasets no longer cast anything. Two
reasons to stay virtual remain: the columns are PascalCase, and the multi-value ones are
`VARCHAR[]`, which Superset cannot group by. Rather than mutating third-party files, each
bundle's dataset YAML is a **virtual dataset** (`sql:`) that renames and flattens, e.g.

```sql
SELECT "Timestamp" AS event_time,
       "RuleTitle" AS rule_title, "Level"::VARCHAR AS level, "RuleID" AS rule_id,
       "EventName" AS event_name, "EventSource" AS event_source,
       "AwsRegion" AS aws_region, "SrcIP" AS src_ip, "UserAgent" AS user_agent,
       "UserARN" AS user_arn, "UserType" AS user_type,
       "UserAccessKeyID" AS user_access_key_id, "ErrorCode" AS error_code,
       array_to_string("TechniqueIDs", ', ') AS technique_ids
FROM timeline
```

with `main_dttm_col: event_time`. Charts then look like the existing CloudTrail charts, and
`register_dataset.py`'s column/metric sync logic is reused rather than forked.

`suzaku_metrics` additionally selects `SrcASN` / `SrcCity` / `SrcCountry`, which exist only for a
`--geo-ip` run — so that bundle requires one (§2.3).

### 5.3 Bundles

```
dashboard/assets/
  suzaku_timeline/    # EMPTY TEMPLATE ONLY (charts land in the separate PR)
    metadata.yaml  dashboard.yaml  databases/Suzaku_Timeline_DuckDB.yaml
    datasets/suzaku_timeline.yaml
    charts/.gitkeep
  suzaku_summary/
    …  charts/*.yaml
  suzaku_metrics/
    …  charts/*.yaml
```

**`suzaku_timeline`** — dashboard.yaml with title, UUID, one empty tab and no chart references,
so the bundle imports cleanly and the separate PR only adds charts + position entries.

> **Retired.** That follow-up has landed: the bundle now ships three virtual datasets and 50
> charts across six tabs, and the empty-template test has been replaced by one asserting every
> bundle has charts. See [PLAN_SUZAKU_TIMELINE_DASHBOARD.md](PLAN_SUZAKU_TIMELINE_DASHBOARD.md).

**`suzaku_summary`** — identity-centric, layout borrowed from `cloudtrail_default` (KPI row on
top, then tabs):

- KPI row: identities, total events, distinct abused APIs, failed-abuse attempts, distinct
  source IPs, distinct access keys.
- *Identities* tab: triage table (`UserARN`, `UserTypes`, `NumOfEvents`, first/last seen, abused
  success/failed counts), Top identities by events, activity span Gantt-style table,
  `UserTypes` composition.
- *API abuse* tab: Top abused APIs (success vs failed, stacked), abused-vs-other ratio per
  identity, the full abused-API table **with Suzaku's `Description`**, Top failed APIs
  (permission probing).
- *Attributes* tab: one Top-N panel per `Attribute` value (`src_ip`, `user_agent`, `aws_region`,
  `access_key_id`) plus a rare-value panel (bottom-N by `Count`), driven by a native filter on
  `Attribute` so new attribute kinds appear without a chart change.
- Native filters: `UserARN`, `Category`, `Attribute`, time range on `FirstSeen`/`LastSeen`.

**`suzaku_metrics`** — field-agnostic:

- KPI row: distinct fields, distinct values, total count, top value's share.
- Charts: Top values by `Count` (bar), `Percent` composition (pie/treemap), value first/last seen
  table, **rare values** (bottom-N — the same "rare = interesting" idea as `cloudtrail_rare`),
  and a country/ASN pair that renders only when Suzaku's geo columns are populated.
- Native filters: `Field` (required, defaults to the first value), `Value` search, `SrcCountry`.

### 5.4 ZIP build

`rebuild_zip.py` and `rebuild_rare_zip.py` are bundle-specific scripts with explicit FILE_MAPs.
Extract the shared mechanics into `dashboard/assets/zip_builder.py`
(`build_zip(source_dir, output_zip, file_map)`, deterministic ZipInfo timestamps, stable YAML
dump) and add three thin scripts (`rebuild_suzaku_timeline_zip.py`, `…_summary_…`, `…_metrics_…`).
Keep explicit FILE_MAPs — they control arc names, which Superset's v1 import format cares about.
`bootstrap.sh` then imports each ZIP via `DASHBOARD_ZIP=…` only when the matching database was
registered.

The CLAUDE.md rule extends unchanged: **edit YAML → rebuild the ZIP → re-run `superset-init`**.

### 5.5 dashboard test list (TDD)

`dashboard/tests/test_suzaku_signatures.py`

1. The signature table in `register_suzaku_dbs.py` classifies each of the three sample DBs correctly.
2. A two-of-three summary DB is not classified as `aws-ct-summary`.
3. Registration is skipped (not crashed) when `/data/db` holds no `.duckdb` file.
4. A path change updates the existing database's URI in place, keeping the UUID.

`dashboard/tests/test_suzaku_bundles.py` (parametrized over the three bundles)

5. Every bundle has `metadata.yaml`, `dashboard.yaml`, exactly one `databases/*.yaml`, ≥1 dataset.
6. Every `databases/*.yaml` uses `duckdb+duckdb_engine://`, `read_only: true`, no
   `allow_run_async: true` (matching the existing DU-06/DU-13 guards).
7. Database and dataset UUIDs are unique across **all** bundles including `cloudtrail_default`.
8. Every chart's `dataset_uuid` resolves to a dataset in the same bundle.
9. Every chart YAML is referenced by its `dashboard.yaml` position, and vice versa.
10. ~~`suzaku_timeline/charts/` is empty and `dashboard.yaml` references no chart~~ — flipped by
    the follow-up PR into "every bundle ships charts".
11. Every virtual dataset's `sql` executes against the corresponding sample DB and its
    `main_dttm_col` comes back as a real timestamp.
12. `suzaku_metrics` charts never filter on a literal `eventName` (field-agnostic contract).

`dashboard/tests/test_rebuild_suzaku_zips.py`

13. Each rebuild script produces a ZIP whose entries match its FILE_MAP.
14. Rebuilding twice is byte-identical (determinism, so `git diff` stays empty).
15. Every source YAML in a bundle appears in its FILE_MAP (no silently unshipped chart).

`dashboard/tests/test_init_scripts.py` (additions)

16. `bootstrap.sh` calls `register_suzaku_dbs.py` before `register_dataset.py`.
17. `bootstrap.sh` guards each Suzaku ZIP import with a file-existence check.

Root `tests/test_suzaku_detection_parity.py`

18. The signature tables in `agent/suzaku_db.py` and `dashboard/init/register_suzaku_dbs.py` are
    identical (kinds, tables, required columns) — the drift guard for §3 guideline 2.

---

## 6. Setup, docs, and ops

### 6.1 Operator workflow to document

```bash
# 1. Run Suzaku, emitting DuckDB
suzaku aws-ct-timeline -d <cloudtrail-logs> -o timeline.duckdb
suzaku aws-ct-summary  -d <cloudtrail-logs> -o summary.duckdb
suzaku aws-ct-metrics  -d <cloudtrail-logs> -f eventName -o metrics.duckdb --geo-ip  # --geo-ip is required

# 2. Copy the results next to Senrigan's own database
cp *.duckdb docker/data/db/

# 3. Restart so superset-init re-registers the new databases
make up
```

Notes to include, all of them earned from §1/§2:

- The exact Suzaku flags must be verified against the Suzaku release Senrigan documents — this
  plan's flag spellings are illustrative until checked (§8, open question 1).
- Copy files only after Suzaku exits. A leftover `<file>.wal` cannot be replayed from a
  read-only mount; checkpoint or re-export first.
- Filenames are free — detection is by schema. Two files of the same kind: the newest wins in the
  agent's selector, and `SUZAKU_*_DB` pins a specific one.
- The reader's DuckDB must be at least as new as the Suzaku build that wrote the file
  (Senrigan ships 1.5.2+ / superset image 1.5.4).

Placement: setup steps in `agent/README.md` and `dashboard/README.md`; a new
`website/docs/reference/suzaku.md` for the dashboards and hunts; one line in the
getting-started pages only if the flow becomes part of the quick start — that file exists in
15 locales and `tests/test_docs.py` enforces parity across all of them, so touching it means
touching all 15.

Also update, in the same PR: `CLAUDE.md` (agent is no longer single-page; the Suzaku files are
extra read-only DBs; new test counts), `AGENTS.md`, `agent/AGENTS.md`, `doc/ARCHITECTURE.md`.

### 6.2 Makefile

- Extend `status` with a Suzaku line: for each `*.duckdb` in `$(DUCKDB_HOST_PATH)`, print the
  detected kind and row count, or `none` — the same "the filesystem is the configuration"
  principle as `PLAN_MAKEFILE_UX.md` §2.3. Add the target's tests to `tests/test_makefile_ops.py`.
- `make up` prints the Suzaku dashboard URLs only when at least one Suzaku DB is present.
- `reset` keeps deleting only `threat_hunting.db` by explicit name — it must **never** remove a
  `*.duckdb` the analyst copied in. Add a regression test for that.
- No new `make` verb for Suzaku: copying a file is the whole workflow.

### 6.3 Sample data

- Add `*.duckdb` to `.gitignore` **before** anything else (Phase 0), then commit deliberately
  trimmed fixtures under `sample/suzaku/` with `git add -f` — the 247 MB timeline file must not
  enter git history. Target: a few MB total (e.g. ~20 k timeline rows preserving every `Level`,
  the full summary DB, the full metrics DB), generated by a committed script so it is reproducible.
- Keep the full-size files out of the repo; if they are needed for manual QA, publish them as a
  GitHub release asset and document the download.

---

## 7. Relationship to the in-flight Suzaku branches

### 7.1 Decision required

`feature/dashboard-suzaku-timeline` and `feature/dashboard-suzaku-detections` add an
`ingester suzaku-import` subcommand (~1,700 lines of Rust across `suzaku_parser.rs`,
`suzaku_import.rs`, `suzaku_db.rs`) that parses Suzaku CSV/JSONL into `threat_hunting.db`, plus
Superset bundles built on that imported table. This plan reads Suzaku's native DuckDB output
instead. The two cannot both be the documented path without confusing every user.

Recommendation: **prefer the native-DuckDB path** and retire the importer.

- No Rust code, no schema migration, no re-ingest when Suzaku is re-run.
- No duplication of Suzaku's parsing rules, which drift with each Suzaku release.
- Preserves the 1-writer invariant — nothing writes the third-party file.
- Cost: Superset needs multiple database connections (§5.1) instead of one, and the timeline
  charts drafted in the other PR must be re-pointed at the virtual dataset. That is YAML-level
  work, far cheaper than maintaining a parser.

Keep the importer only if Suzaku's DuckDB output turns out to be unavailable in a version
Senrigan must support, in which case this plan's dashboard bundles sit on the imported table and
only §5.1 changes.

### 7.2 Removed agent code as prior art

`agent/suzaku_summary.py`, `agent/suzaku_report.py` and `agent/views/suzaku_ct_summary.py` (an
upload-a-JSON page for `aws-ct-summary`, removed pending redesign — see
`doc/PRD_SUZAKU_SUMMARY.md`) are worth reading before writing §4.3: they establish the
`agent/views/` + `st.navigation` structure and the "page stays thin, logic stays pure and
testable" split this plan follows. Their *feature* is superseded — `aws-ct-summary` goes to the
dashboard per §3 guideline 1, not back into the agent.

---

## 8. Phases

Each phase is independently mergeable, ends green (`make check`), and follows Red → Green →
Refactor per test item.

| Phase | Deliverable | Done when |
|-------|-------------|-----------|
| **P0 Fixtures** | `.gitignore` `*.duckdb`; trimmed sample DBs + generator script | Samples are a few MB; `make test-repo` green |
| **P1 Detection** | `agent/suzaku_db.py` + tests 1–10 | Three sample DBs classified; bad files return errors, never raise |
| **P2 Profiles** | `agent/profiles.py`, parameterized `query`/`schema`/`llm`/`handlers` + tests 11–18 | All pre-existing agent tests pass **unmodified** |
| **P3 Agent page** | `agent/views/suzaku_timeline.py`, `st.navigation`, hunts YAML + tests 19–28 | Page runs the 15 hunts, filters, date range, severity, report, AI chat |
| **P4 Superset plumbing** | `register_suzaku_dbs.py`, `zip_builder.py`, `bootstrap.sh` wiring, `suzaku_timeline` empty template + tests 1–4, 13–18 | Three connections appear in Superset; empty timeline dashboard imports |
| **P5 Summary dashboard** | `suzaku_summary` bundle + tests 5–12 | KPI row + three tabs render against the sample DB |
| **P6 Metrics dashboard** | `suzaku_metrics` bundle | Field-agnostic charts render; `Field` filter drives everything |
| **P7 Docs & ops** | READMEs, website reference page, `make status`, count updates in CLAUDE.md / AGENTS.md | A newcomer can follow §6.1 end-to-end on a clean machine |

---

## 9. Risks

| Risk | Mitigation |
|------|-----------|
| 247 MB sample committed to git history | P0 gates everything else; `.gitignore` + trimmed fixtures + generator script |
| Suzaku schema drift between releases | Detection matches a required *subset*; datasets list columns explicitly; document the Suzaku version the fixtures came from and add a fixture-regeneration script |
| DuckDB storage-format skew (file newer than reader) | Verified today (writer ≤ 1.5.4 readers). Detect the specific open error and tell the operator to upgrade, rather than showing a stack trace |
| Stale `.wal` on a read-only mount | Detect the sibling `.wal` during discovery and explain it in the UI |
| 1.9 M-row timeline table makes the agent page sluggish | Severity multiselect defaults to medium+, every hunt is `ORDER BY … LIMIT`, row cap wraps as a backstop, no un-`LIMIT`ed default view |
| Two detection implementations drift | Root-level parity test (test 18) |
| Superset connection sprawl (4 DuckDB connections) | Fixed names + fixed UUIDs, `expose_in_sqllab` on, all `read_only`; registration skipped when a kind is absent |
| Chart YAML edited without rebuilding ZIPs | Existing repo rule + determinism tests (13–14) make an unrebuilt ZIP visible in `git diff` |

---

## 10. Open questions

1. **Suzaku CLI flag spellings** for DuckDB output (`-o out.duckdb`? a `--duckdb` flag? a fixed
   default filename?) and whether one invocation can emit several kinds into one file. The
   detector already returns a set of kinds, so a combined file is supported either way — but §6.1
   must quote the real commands. Verify against the Suzaku release Senrigan targets.
2. **Does `aws-ct-metrics` ever contain multiple `Field` values in one file?** The sample has one.
   Field-agnostic charts cover both, so this only affects the default filter value.
3. **`aws-ct-summary` on the timeline page** — should the identity triage table also exist as a
   built-in hunt so it can appear in reports (§3 corollary)? That would mean the agent page reads
   *two* Suzaku DBs. Recommendation: defer; revisit once the summary dashboard has been used.
4. **Retire the importer or keep both?** §7.1 — decide before either in-flight branch merges.
