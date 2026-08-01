# PLAN: Interactive Suzaku explorers in the agent (`aws-ct-summary` / `aws-ct-metrics`)

> **Status: implemented (2026-08-01).** All seven phases shipped; the agent suite went
> from 761 to 825 tests. Two deviations from the plan as written, both noted in §5.3
> and §5.6: the timeline pivot reuses the chat page's existing direct-SQL hook instead
> of introducing a pending-prompt path (so it needs no API key), and the shared sidebar
> blocks were extracted from `render_sidebar` rather than gated inside it. Revises one
> guideline in [PLAN_SUZAKU_VIEWS.md](PLAN_SUZAKU_VIEWS.md) §3 — see §1.
>
> §7 (docs) shipped against the newer documentation convention that landed meanwhile:
> `CLAUDE.md` / `AGENTS.md` now point at [ARCHITECTURE.md](ARCHITECTURE.md) as the single
> owner of the page-split explanation instead of linking `PLAN_*` documents, so the
> explorer/chat distinction is written there rather than indexed from the root files.

Add two **interactive exploration pages** to the `agent` Streamlit app, one per remaining Suzaku
command:

| Page | Suzaku command | Reads |
|------|----------------|-------|
| 👤 **Suzaku Summary** | `aws-ct-summary` | `summary`, `summary_api_calls`, `summary_attributes` |
| 📊 **Suzaku Metrics** | `aws-ct-metrics` | `metrics` |

Both dashboards already exist in Superset (`dashboard/assets/suzaku_summary/`,
`suzaku_metrics/`). This plan does **not** duplicate them: Superset answers *"what does this run
look like?"*, and these pages answer *"walk me through this identity / this field, one decision at
a time, and put what I found into my report."* §4 states exactly what "interactive" has to mean
for the pages to earn their place.

The `aws-ct-summary` layout follows the earlier JSON-upload prototype, screenshotted in
[img-suzaku-summary.png](img-suzaku-summary.png): identity selector → identity KPI row → abused
APIs split succeeded/failed as paired bar chart + table. The input changes — DuckDB read from the
mounted directory, never an upload — and the interaction grows (§5.4).

Related: [PLAN_SUZAKU_VIEWS.md](PLAN_SUZAKU_VIEWS.md) (the profile/detection foundation this
builds on), [PLAN_SUZAKU_MULTI_DB.md](PLAN_SUZAKU_MULTI_DB.md) (which file wins),
[PLAN_SUZAKU_SCHEMA.md](PLAN_SUZAKU_SCHEMA.md) (the Suzaku-side contract),
[PRD_SUZAKU_SUMMARY.md](PRD_SUZAKU_SUMMARY.md) (the retired JSON prototype's requirements).

---

## 1. This revises a decision, and says so

[PLAN_SUZAKU_VIEWS.md](PLAN_SUZAKU_VIEWS.md) §3 guideline 1 reads: *"Give them dashboards and do
not build agent pages for them."* That guideline was written against one specific idea of an agent
page — **the chat pipeline**, where an LLM writes SQL over a wide raw table. It is still right
about that: re-aggregating 22 identities through an LLM adds cost and a hallucination surface and
removes nothing.

What it got wrong is treating "agent page" and "LLM chat page" as the same thing. The agent module
also owns three things Superset structurally cannot do, and all three apply to pre-aggregated data:

1. **Selection-driven drill-down.** Superset filters a fixed grid of charts. A page can branch:
   pick an identity → its APIs → pick an API → the IPs and keys that used it, each step deciding
   what the next step even shows.
2. **The report.** Only the agent produces a Markdown/HTML deliverable
   ([`report.py`](../agent/report.py)). Today an analyst who finds the answer in the summary
   dashboard has to screenshot it — PLAN_SUZAKU_VIEWS.md §3 named this exact gap as a corollary and
   left it unsolved.
3. **Set operations and pivots.** "Which APIs did these two identities share?" and "now hunt this
   identity in the timeline" are one click here and impossible there.

So the revision is narrow and should be recorded in `PLAN_SUZAKU_VIEWS.md` §3 as part of this work:
**pre-aggregated Suzaku output gets an explorer page, not a chat page.** No hunts YAML, no system
prompt, no generated SQL. Every query on these pages is a reviewed, parameterized statement in the
repository (§5.2).

---

## 2. Current state (verified 2026-08-01)

### 2.1 What already exists and is reused as-is

| Fact | Consequence |
|------|-------------|
| `agent/suzaku_db.py` discovers, fitness-checks and ranks Suzaku files, and already knows `SUMMARY` / `METRICS` (`REQUIRED_COLUMNS`, `SUZAKU_TABLES`, `ENV_OVERRIDES`) | Zero detection work. Both pages call the same `select()` the dashboards call |
| `app.py::_discover_suzaku_dbs` (30 s `st.cache_data`) + `_render_suzaku_db_selector(profile, kind)` render the picker, the "the dashboard is on a different run" warning and the unfit-file reasons | The sidebar's database block is one call per page, already tested |
| `profiles.DatasetProfile.state_key()` namespaces session state; `SHARED_STATE_KEYS` keeps `api_key` / `model` / `row_limit` global | Four pages can coexist without touching each other's history |
| `report.ReportEntry(sql, results, analysis, description, chart_config, analyst_note, label, category, source, techniques)` + `generate_report` / `generate_html_report` are profile-agnostic | Pinning a panel into a report is appending a dataclass — no report code changes |
| `llm.generate_analysis(sql, results, api_key, model)` takes a frame and SQL only — no profile, no schema | AI narration of a panel works on these pages unchanged |
| `query.duckdb_connection(path)` opens read-only with `enable_external_access=false` + `lock_configuration=true` | One connection per Suzaku file, never `ATTACH` (PLAN_SUZAKU_VIEWS.md §1.1) |
| `views/suzaku_timeline.py` is 99 lines: empty state + delegate | The shape to copy — page thin, logic in a pure module |
| `app.py::build_pages()` returns two `st.Page`s; `test_suzaku_timeline_view.py::test_navigation_exposes_both_pages` asserts exactly `["senrigan", "suzaku-timeline"]` | That test is the Red step for Phase 1 |

### 2.2 What the Superset dashboards already cover

Not to be re-implemented — the pages must add interaction, not a second copy of these.

| Bundle | Charts |
|--------|--------|
| `suzaku_summary` (19) | 6 KPIs (identities, total events, abused APIs, failed abuse, source IPs, access keys), `identity_triage`, `top_identities_by_events`, `identity_activity_span`, `identity_type_composition`, `top_abused_apis`, `abused_apis_by_service`, `abused_vs_other_per_identity`, `abused_api_catalogue`, `top_failed_apis`, `top_attribute_values`, `rare_attribute_values`, `attribute_first_last_seen`, `run_info` |
| `suzaku_metrics` (15) | 6 KPIs (fields, values, occurrences, top share, singletons, countries), `top_values`, `value_share_composition`, `value_frequency_table`, `rare_values`, `newest_values`, `top_countries`, `top_asns`, `geo_value_matrix`, `run_info` |

### 2.3 Prior art

`agent/views/suzaku_ct_summary.py`, `agent/suzaku_summary.py`, `agent/suzaku_report.py` (removed;
last seen at `d7d46ca`) implement the screenshot against uploaded JSON. Read them for the layout —
the identity selectbox label format, the paired succeeded/failed columns, the per-panel CSV — and
discard the input half: the JSON path, `st.file_uploader`, the `"-"` sentinel handling and the
regex-parsed GeoIP-in-a-string are all obsolete against typed DuckDB columns.

`sample/img-suzaku-summary.png` is an untracked, lower-resolution duplicate of the tracked
`doc/img-suzaku-summary.png`. Reference the `doc/` copy; do not commit the second one.

---

## 3. Input contract (verified against `sample/suzaku/fixtures/`)

### 3.1 `aws-ct-summary`

```
summary            UserARN, NumOfEvents BIGINT, FirstTimestamp/LastTimestamp TIMESTAMP,
                   UserTypes VARCHAR[]                                                22 rows
summary_api_calls  UserARN, IsAbused BOOLEAN, Outcome ENUM('success','failed'), API,
                   EventSource, Description, Count, FirstSeen, LastSeen            2,667 rows
summary_attributes UserARN, Attribute, Value, Count, FirstSeen, LastSeen          18,127 rows
```

Facts that drive the design:

- `IsAbused` × `Outcome` is a 2×2, and it is **not balanced**: abused/success 150, abused/failed 71,
  other/success 1,155, other/failed 1,291. The 221 abused rows are the whole point of the page and
  must never be paginated behind the 2,446 others.
- `Description` is Suzaku's explanation of *why* an API is abusable. It is the highest-value column
  in the file and belongs in the table next to the bar chart, exactly as the screenshot has it.
- `API` is the action, `EventSource` the service. The screenshot's `RunInstances (ec2.amazonaws.com)`
  label is `API || ' (' || EventSource || ')'` — display only; group by the two columns.
- `Attribute` ∈ `UserAgent` (10,827 rows / 8,705 distinct), `SrcIP` (7,180 / 5,733),
  `AwsRegion` (86 / 16), `UserAccessKeyID` (34 / 17). Cardinality differs by three orders of
  magnitude, so a fixed Top-N is wrong for at least two of them → the N is a control (§4).
- `UserTypes` is `VARCHAR[]`. Render with `array_to_string(…, ', ')`; never group by it raw.
- 22 identities means the identity selector can be a plain selectbox with a rich label, and the
  triage table can be rendered whole with no paging.

### 3.2 `aws-ct-metrics`

```
metrics  Field, TimelineColumn, Value, Count BIGINT, FieldTotal BIGINT, Percent DOUBLE,
         FirstSeen, LastSeen, SrcASN, SrcCity, SrcCountry                          1,344 rows
```

- The fixture holds **one** `Field` (`eventName` → `TimelineColumn` `EventName`), 1,344 values,
  1,972,588 occurrences. A file may hold several fields → every query is parameterized on `Field`,
  never on a literal.
- 225 of 1,344 values have `Count = 1` (17%). Singletons are the interesting tail, not an error.
- **`SrcASN` / `SrcCity` / `SrcCountry` are present but entirely NULL in the fixture.**
  `suzaku_db.REQUIRED_COLUMNS` gates on the columns *existing* (a `--geo-ip` run), which is not the
  same as them being *populated*. The geo panel must therefore check for non-NULL values at render
  time and explain its absence rather than draw three empty charts. This is a real, verified case —
  the Superset geo charts render blank against this same file.
- `Percent` is full precision and `FieldTotal` is its denominator, so any filtered subset can show
  both "share of the filtered set" and "share of the whole field" exactly.

### 3.3 Provenance

Both pages show a **Suzaku Run Info** line (file name, `suzaku_version`, `generated_at`,
`command_line`, `scanned_files` / `scanned_events` / `output_rows`) from the `DbInfo` the selector
already produced — matching the `run_info` card every Suzaku dashboard carries, so the two UIs are
comparable at a glance.

---

## 4. What "interactive" has to mean

Five affordances. Each is something the Superset bundle cannot do, and each is testable.

| # | Affordance | Why Superset cannot | Applies to |
|---|-----------|---------------------|------------|
| I-1 | **Selection cascade** — the chosen identity (or field/value) parameterizes every panel below it, including which panels exist | Superset filters charts; it cannot make a panel's *existence* depend on a selection | both |
| I-2 | **Live Top-N / threshold controls** — N, "count ≥ x", "singletons only", regex value search, all recomputed per keystroke | Chart `row_limit` is stored metadata; an analyst cannot sweep it | both |
| I-3 | **Comparison** — pick 2 identities (or 2 fields) → shared / only-A / only-B for APIs, IPs, user agents, keys | Set operations across two filter values are not a Superset chart | both |
| I-4 | **Pin to report** — any panel becomes a `ReportEntry` (label, SQL, frame, analyst note, optional AI narration), exported as Markdown/HTML | Superset has no report deliverable | both |
| I-5 | **Pivot to the timeline page** — "hunt this identity / this value in `aws-ct-timeline`" hands a prepared query to the existing chat page | Different tool, different database file | both |

Anything not on this list is a dashboard chart in disguise. If a proposed panel is a static Top-N
with no control, no drill-down and no pin button, it belongs in the Superset bundle instead.

---

## 5. Design

### 5.1 Profiles: one registry, two page shapes

`DatasetProfile` today assumes a chat pipeline (columns for the LLM, hunts YAML, system prompt).
Rather than a parallel registry, extend it with two fields whose defaults preserve every existing
behaviour — the same incremental-safety argument PLAN_SUZAKU_VIEWS.md §4.1 used, and the reason all
current agent tests keep passing untouched:

```python
@dataclass(frozen=True)
class DatasetProfile:
    ...
    chat_enabled: bool = True            # False → explorer page: no hunts, no prompt, no LLM SQL
    suzaku_kind: SuzakuKind | None = None  # the file this profile reads, for the DB selector
```

```python
SUZAKU_SUMMARY_PROFILE = DatasetProfile(
    key="suzaku_summary", label="Suzaku Summary", icon="👤",
    table="summary", time_column="FirstTimestamp",
    columns=(), hunts_filename="", quote_identifiers=True,
    supports_geo_enrich=False, chat_enabled=False,
    suzaku_kind=SuzakuKind.SUMMARY, state_prefix="szs_",
)

SUZAKU_METRICS_PROFILE = DatasetProfile(
    key="suzaku_metrics", label="Suzaku Metrics", icon="📊",
    table="metrics", time_column="FirstSeen",
    columns=(), hunts_filename="", quote_identifiers=True,
    supports_geo_enrich=False, chat_enabled=False,
    suzaku_kind=SuzakuKind.METRICS, state_prefix="szm_",
)
```

Rules a test pins down (§6): `hunts_path` and `build_system_prompt()` **raise** on a
`chat_enabled=False` profile rather than returning something empty — an explorer profile reaching
the chat pipeline is a bug, and it should fail loudly in a test rather than quietly ship an empty
prompt to OpenAI. `_init_session_state` / `_clear_session` seed and clear the `szs_` / `szm_`
namespaces like any other.

`profiles.py` gains an import of `suzaku_db.SuzakuKind`; `suzaku_db` imports nothing from `agent`,
so there is no cycle.

### 5.2 Query layer — pure, parameterized, testable

Two new modules with **no Streamlit import**, mirroring `suzaku_db.py`'s discipline. Every function
takes an open read-only connection plus plain arguments and returns a `pandas.DataFrame`; every
value from the data (`UserARN`, `Field`, a search string) is a **bound `?` parameter**, never
interpolated. Only the Top-N integers are formatted in, after `int()`.

`agent/suzaku_summary_queries.py`

| Function | Returns |
|----------|---------|
| `identity_overview(conn)` | one row per identity: ARN, types, events, first/last, abused success/failed counts, distinct IPs / UAs / regions / keys — the triage landing table |
| `identity_facts(conn, arn)` | the single-identity header row (screenshot's Type / Total events / First seen / Last seen) |
| `api_calls(conn, arn, *, abused, outcome, limit)` | API, EventSource, Description, Count, FirstSeen, LastSeen for one quadrant of the `IsAbused` × `Outcome` matrix |
| `attribute_values(conn, arn, attribute, *, limit, ascending, search)` | Value, Count, FirstSeen, LastSeen — `ascending=True` is the rare-value view |
| `attribute_kinds(conn)` | the `Attribute` values actually present, so a new Suzaku attribute appears without a code change |
| `identities_sharing(conn, attribute, value)` | every identity that used one IP / UA / key — the drill-down that makes I-1 worth having |
| `compare_identities(conn, arn_a, arn_b, dimension)` | shared / only-A / only-B rows for `api` \| `SrcIP` \| `UserAgent` \| `UserAccessKeyID` (I-3) |

`agent/suzaku_metrics_queries.py`

| Function | Returns |
|----------|---------|
| `fields(conn)` | `Field`, `TimelineColumn`, distinct values, total count — drives the field selector |
| `values(conn, field, *, limit, ascending, min_count, search, seen_after)` | Value, Count, Percent, FirstSeen, LastSeen with the §4 I-2 controls applied in SQL |
| `value_stats(conn, field)` | distinct values, total occurrences, top-value share, singleton count, span |
| `pareto(conn, field, limit)` | Count plus cumulative share — "how many values cover 90% of traffic?" |
| `geo_breakdown(conn, field, column, limit)` | Top `SrcCountry` / `SrcCity` / `SrcASN` |
| `has_geo_data(conn, field)` | `False` when all three geo columns are NULL → the panel explains itself instead of drawing blanks (§3.2) |
| `compare_fields(conn, field_a, field_b)` | value overlap between two fields in one file (I-3) |

Each function also returns (or exposes via a `sql` attribute) the statement it ran, because
`ReportEntry.sql` and the AI narration both need it. Simplest shape that stays pure: return
`tuple[str, pd.DataFrame]`, and let the view decide what to show.

Caching: `st.cache_data(ttl=…)` wrappers live in the **view**, keyed on
`(db_path, mtime, *params)` — the pure module stays cache-free so tests call it directly.

### 5.3 Shared explorer kit

`agent/views/explorer.py` — the parts both pages repeat, so neither page grows a second copy:

- `render_panel(profile, *, label, category, sql, df, chart=…, key=…)` — heading, chart, dataframe,
  **📌 Pin to report**, **⬇ CSV**, and **🤖 Explain** (calls `llm.generate_analysis`, disabled with
  a caption when no API key is set). Pinning appends a `ReportEntry` to the profile's
  `query_history`, so `render_sidebar`'s existing Report/Session block works untouched.
- `render_run_info(info)` — the §3.3 provenance line from a `DbInfo`.
- `render_empty_state(kind, directory, extra)` — the timeline page's panel, parameterized; the
  metrics variant carries the `--geo-ip` requirement in `extra`.
- `handoff_to_timeline(profile, prompt)` — writes `sz_pending_prompt` into the timeline profile's
  namespace and calls `st.switch_page` (I-5).

`render_chat` gains one small behaviour to make I-5 land: at the top of a rerun, if
`profile.state_key("pending_prompt")` is set, pop it and run it as if typed. That is a five-line
change with its own test, and it is the only edit to the existing chat path.

The sidebar for an explorer page is `render_sidebar(profile)` with the chat-only blocks skipped —
gate the preset-hunts and model blocks on `profile.chat_enabled`. API key, Report and Session stay:
the report is the point (I-4), and the API key drives 🤖 Explain.

### 5.4 The Suzaku Summary page (`agent/views/suzaku_summary.py`)

Layout follows [img-suzaku-summary.png](img-suzaku-summary.png), with the interaction added.

**Sidebar** — 🗄️ Suzaku Database (existing selector, `SuzakuKind.SUMMARY`) · Run info · Identity
scope (`All` / a specific ARN) · Top-N slider (default 10, 1–100) · Report (Markdown / HTML) ·
Session (Export JSON / Clear).

**Landing view — 🧭 Identity triage** (shown when no identity is picked):

- The `identity_overview` table, sorted by abused-success desc, then events desc, rendered with
  `st.dataframe(selection_mode="single-row")` so **clicking a row selects the identity** — the F2
  behaviour the JSON prototype specified and never got.
- Above it, four KPIs for the whole run: identities, total events, abused APIs, failed abuse
  attempts. (Same numbers as the dashboard KPIs on purpose — an analyst should be able to confirm
  the two UIs are on the same file.)

**👤 Inspect identity** (the screenshot):

1. Selectbox, label `{ARN} — {types} · {events:,} events · abused {n}✅/{m}❌`.
2. KPI row: Type · Total events · First seen · Last seen.
3. 🔴 **Abused APIs** — two columns, ✅ Succeeded / ❌ Failed. Each is a horizontal bar chart
   (Top-N by `Count`) over a table carrying `Description`. Both are pinnable panels.
4. ⚪ **Other APIs** — same pair inside `st.expander`, collapsed (2,446 of 2,667 rows live here).
5. 🌐 **Attributes** — one `st.tabs` per value from `attribute_kinds(conn)`, so a new Suzaku
   attribute needs no code change. Each tab: Top-N bar + full table, a **Rare values** toggle
   (ascending, `Count = 1` first), and a search box (I-2). Selecting a row runs
   `identities_sharing()` → *"3 other identities used this IP"*, which is the drill-down that turns
   the summary from a report into an investigation (I-1).
6. ⚖️ **Compare with…** — a second identity selectbox; shared / only-A / only-B across APIs, IPs,
   user agents and access keys (I-3).
7. 🕒 **Hunt in the timeline** — button per identity (and per selected IP/key) that pivots to the
   timeline page with a prepared question (I-5).

### 5.5 The Suzaku Metrics page (`agent/views/suzaku_metrics.py`)

**Sidebar** — database selector (`SuzakuKind.METRICS`) · Run info · **Field** selectbox (from
`fields(conn)`, never a literal) · Top-N · `Count ≥` · `FirstSeen after` · Report · Session.

**Main:**

1. KPI row for the selected field: distinct values · total occurrences · top value's share ·
   singleton values · observed span.
2. 📈 **Top values** — bar chart + table (`Value`, `Count`, `Percent`, `FirstSeen`, `LastSeen`),
   driven live by the sidebar controls. `Percent` is shown both as-is (share of the field, from
   `FieldTotal`) and recomputed over the filtered subset, since both are meaningful and the
   difference is exactly what the filter did.
3. 🪶 **Rare values** — ascending, singletons first. The `cloudtrail_rare` idea, but with the
   threshold as a control instead of a fixed bottom-N.
4. 📉 **Concentration** — Pareto curve + *"the top 12 of 1,344 values cover 90% of 1,972,588
   occurrences"*. One sentence that tells an analyst whether the field is worth reading at all.
5. 🆕 **Newly seen** — values whose `FirstSeen` is after the sidebar cut-off, sorted by `FirstSeen`.
   The cut-off being a control is the entire feature (I-2).
6. 🌐 **Geo** — Top countries / cities / ASNs, rendered only when `has_geo_data()` is true;
   otherwise a caption stating that the columns exist but are empty and that Suzaku must be re-run
   with `--geo-ip` (§3.2).
7. 🔀 **Compare fields** — shown only when the file holds more than one `Field` (I-1 again: the
   panel's existence depends on the data).
8. 🕒 **Hunt in the timeline** — a selected value pivots to the timeline page as
   `TimelineColumn = Value`, which is precisely what `TimelineColumn` is for.

### 5.6 Failure and degraded states

| Situation | Behaviour |
|-----------|-----------|
| No usable file of the kind | The timeline page's empty state, parameterized: the `suzaku aws-ct-summary` / `aws-ct-metrics` command, the copy step, the `.wal` warning. Metrics adds `--geo-ip` |
| File declares the kind but is unfit | Already handled by `_render_suzaku_db_selector` — reason shown per file, page renders its empty state |
| Selected file ≠ the file the dashboards serve | Existing selector warning, unchanged |
| Geo columns present but all NULL | §3.2 — panel hidden with an explanation, never blank charts |
| An `Attribute` value Senrigan has never seen | Rendered as its own tab, because the tab list comes from the data |
| No `OPENAI_API_KEY` | Every panel renders; only 🤖 Explain is disabled, with a caption saying why |
| Timeline page is on a different Suzaku run than the summary page | The handoff (I-5) warns before switching: the two files may cover different periods |

---

## 6. Test list (TDD — Red first, one item at a time)

`agent/tests/test_profiles.py` (additions)

1. `SUZAKU_SUMMARY_PROFILE` / `SUZAKU_METRICS_PROFILE` carry the expected table, kind, prefix and
   `chat_enabled=False`.
2. `state_key` for the three Suzaku profiles never collides, and shared keys stay shared.
3. `build_system_prompt()` and `hunts_path` raise on a `chat_enabled=False` profile.
4. `CLOUDTRAIL_PROFILE` and `SUZAKU_TIMELINE_PROFILE` are unchanged (`chat_enabled` defaults True).

`agent/tests/test_suzaku_summary_queries.py` (against the committed fixture)

5. `identity_overview` returns 22 rows, one per ARN, sorted abused-first.
6. Abused/failed counts per identity match a hand-written control query over `summary_api_calls`.
7. `api_calls` splits the `IsAbused` × `Outcome` matrix: the four quadrants sum to 2,667 and the
   abused pair sums to 221.
8. `api_calls` respects `limit` and orders by `Count` desc; `Description` is always present.
9. `attribute_kinds` returns exactly the four attributes in the fixture, from the data.
10. `attribute_values(ascending=True)` returns the rare tail; `search` filters case-insensitively.
11. `identities_sharing` finds every identity for a known shared IP (control query).
12. `compare_identities` partitions correctly: `shared + only_a` = A's set, and the three parts are
    disjoint.
13. An ARN that does not exist returns empty frames, never raises.
14. Every function binds its parameters: an ARN containing `'` returns empty rather than erroring
    (SQL-injection regression guard).
15. `UserTypes` comes back as a joined string, never a Python list.

`agent/tests/test_suzaku_metrics_queries.py`

16. `fields` returns one row for the fixture (`eventName` / `EventName`) with 1,344 values and
    1,972,588 occurrences.
17. `values` applies `limit`, `min_count`, `search` and `seen_after`, and composes them.
18. `values(ascending=True)` surfaces the 225 singletons first.
19. `pareto` is monotonically increasing and ends at ~100%.
20. `value_stats` matches control queries for distinct values, total, top share and singletons.
21. `has_geo_data` is **False** for the fixture (columns present, values NULL) — the §3.2 case.
22. `geo_breakdown` returns an empty frame rather than raising for that file.
23. Every query is parameterized on `Field`; a field name with a quote returns empty.

`agent/tests/test_suzaku_explorer_views.py`

24. `build_pages()` returns four pages, url paths `["senrigan", "suzaku-timeline",
    "suzaku-summary", "suzaku-metrics"]`, CloudTrail still default. *(Rewrites the existing
    two-page assertion — the Red step.)*
25. Each page renders its empty state when discovery finds no file of its kind, and does not open a
    connection.
26. `render_panel`'s pin button appends one `ReportEntry` with label, category, SQL and frame to the
    right profile's namespace, and `generate_report` / `generate_html_report` render it.
27. `Clear` on the summary page empties only `szs_`, leaving `sz_`, `szm_` and CloudTrail history.
28. 🤖 Explain is disabled without an API key, and calls `llm.generate_analysis` exactly once with
    the panel's SQL and frame when a key is set (mock `llm.OpenAI` — never a real call).
29. `handoff_to_timeline` seeds `sz_pending_prompt` and switches pages; `render_chat` consumes the
    pending prompt exactly once (it is cleared before the query runs, so a rerun does not re-fire).
30. Geo panel is absent for the fixture and present for a synthetic file with populated geo columns.
31. Explorer pages never call `llm.generate_sql` — the "no generated SQL here" contract (patch it
    and assert not called).

Root `tests/`

32. `doc/PLAN_SUZAKU_EXPLORERS.md` is linked from `CLAUDE.md` and `AGENTS.md`, and the agent tree
    entries for the new modules exist (`tests/test_doc_structure.py` already enforces the mechanism;
    the new files just have to be added to the trees).

Fixtures: the committed `sample/suzaku/fixtures/suzaku-aws-ct-{summary,metrics}.duckdb` cover
everything except the geo case (test 30), which builds a three-row DuckDB file in `tmp_path`.

---

## 7. Docs and ops

In the same PR:

- `CLAUDE.md` / `AGENTS.md` — the agent is now **four** pages, not two; add
  `PLAN_SUZAKU_EXPLORERS.md` to both doc lists and the new modules to both repository trees; update
  the agent test count (`≈ 761` → new total) in both files, and run `make test-repo`, which is
  what checks the trees and links still resolve.
- `agent/AGENTS.md` — the page inventory and the explorer/chat split (§1).
- `agent/README.md` — a short section per page with the Suzaku command that produces its input.
- `doc/ARCHITECTURE.md` — the agent row's page list.
- `doc/PLAN_SUZAKU_VIEWS.md` — **do not rewrite §3 or open question 3.** A `PLAN_*` is a
  point-in-time record (CLAUDE.md, *Documentation*); add a `> **Status: …**` line under its title
  naming this document as the revision of §3 guideline 1, in the style of
  [PLAN_SUZAKU_SCHEMA.md](PLAN_SUZAKU_SCHEMA.md) and
  [PLAN_SUZAKU_TIMELINE_DASHBOARD.md](PLAN_SUZAKU_TIMELINE_DASHBOARD.md).
- `website/docs/reference/suzaku.md` — the two pages next to the two dashboards, stating which tool
  to reach for. Getting-started pages are untouched: 15 locales, `tests/test_docs.py` parity.
- No `make`, compose or Docker change. Copying a `.duckdb` into `docker/data/db/` is still the whole
  workflow, and `make status` already reports what was detected.

---

## 8. Phases

Each phase is independently mergeable and ends green (`make check`).

| Phase | Deliverable | Done when |
|-------|-------------|-----------|
| **P1 Profiles & nav** | `chat_enabled` / `suzaku_kind`, two profiles, four-page navigation, two stub pages rendering only their empty state + run info · tests 1–4, 24–25 | Both pages reachable; all pre-existing agent tests pass unmodified except the rewritten nav assertion |
| **P2 Summary queries** | `suzaku_summary_queries.py` · tests 5–15 | Every function verified against the fixture by a control query |
| **P3 Explorer kit** | `views/explorer.py` (panel, pin, CSV, Explain, run info, empty state) · tests 26–28, 31 | A pinned panel appears in the Markdown **and** HTML report |
| **P4 Summary page** | `views/suzaku_summary.py` — triage, identity inspect, attributes, drill-down · test 27 | The screenshot's layout works against the fixture, with I-1/I-2 live |
| **P5 Metrics queries + page** | `suzaku_metrics_queries.py`, `views/suzaku_metrics.py` · tests 16–23, 30 | Field-agnostic; geo panel correctly absent for the fixture |
| **P6 Compare & pivot** | `compare_identities` / `compare_fields` panels, `handoff_to_timeline`, `render_chat` pending-prompt · test 29 | Two identities diff in one click; an identity pivots into the timeline page |
| **P7 Docs** | §7 in full · test 32 | Counts updated; `make test-repo` green |

P1–P4 deliver the screenshot; P5 delivers metrics; P6 is what makes the pages more than a second
dashboard. If the work has to be cut short, cut P6 last, not first.

---

## 9. Risks

| Risk | Mitigation |
|------|-----------|
| The pages become a slower copy of the dashboards | §4 is the acceptance bar: a panel with no control, no drill-down and no pin button belongs in Superset. Reviewers check every panel against I-1…I-5 |
| Two more `st.session_state` namespaces collide with the existing two | `state_key` + test 2; every widget key already carries `profile.key` |
| `summary_attributes` at 18k rows (8.7k distinct user agents) makes a tab sluggish | Every query is `ORDER BY … LIMIT n` in SQL, never a full fetch then a pandas slice; results cached on `(path, mtime, params)` |
| An explorer profile leaks into the chat pipeline | Test 3 (raises) + test 31 (`generate_sql` never called) |
| Analyst compares a summary file and a timeline file from different runs | The handoff warns; both pages already show `generated_at` and the selector already flags a divergence from the dashboards |
| Geo columns present but empty — blank panels, as the dashboard has today | `has_geo_data()` + test 21/22/30. Consider a follow-up making the Superset geo charts state the same thing |
| Identity/field values interpolated into SQL | Bound parameters everywhere; tests 14 and 23 are the regression guards |
| Agent test count grows past what CLAUDE.md claims | §7 updates both files in the same PR — a stale count reads as a regression in a later session |

---

## 10. Open questions

1. **Landing view for the summary page** — triage table first (this plan) or straight into the
   highest-risk identity? Recommendation: triage first. The screenshot opens on an identity because
   the prototype had just parsed one file; with 22 identities the ranking *is* the first question.
2. **Should the identity triage table also become a `builtin_hunts.yaml`-style entry** so the
   CloudTrail report can carry it? Deferred: `ReportEntry` pinning (I-4) already gets it into a
   report, from the page that owns the data.
3. **Does any real `aws-ct-metrics` file carry several `Field` values?** The fixture has one. Every
   query is parameterized either way, so this only decides whether the §5.5 compare panel is
   commonly visible or a rarity.
4. **Sharing the explorer kit with the CloudTrail page** — `render_panel` overlaps
   `_render_result_card` in `app.py`. Kept separate here deliberately: unifying them touches the
   most-tested code in the agent for no user-visible gain. Revisit once both have settled.
