# PLAN: Suzaku Detection Timeline Dashboard

> **Status: implemented, then trimmed.** The bundle shipped three virtual datasets and 50 charts,
> all verified rendering non-empty results through Superset's `/api/v1/chart/data` endpoint against
> `sample/suzaku/sample-timeline.duckdb`. A later DFIR review cut four of them — see §9.2 — leaving
> **46**. The drafts in `sample/charts/` this plan was written against have been deleted — each
> shipped chart keeps its `SZK-nn` id in its header comment.

Plan for filling `dashboard/assets/suzaku_timeline/`, which shipped as an intentionally
chart-free template (see [PLAN_SUZAKU_VIEWS.md](PLAN_SUZAKU_VIEWS.md) §5.3), with the charts
drafted in `sample/charts/`.

This was the "follow-up PR" that `dashboard/tests/test_suzaku_bundles.py::test_chartless_bundle_stays_empty`
was written to gate — that test is now replaced by `test_every_bundle_ships_charts`.

---

## 1. Goal

| | Before | After |
|---|---|---|
| Bundle | database + virtual dataset + empty shell | 3 virtual datasets + 50 charts across 6 tabs |
| `suzaku_timeline/charts/` | empty | 50 YAML files |
| `CHARTLESS_BUNDLES` in `test_suzaku_bundles.py` | `{"suzaku_timeline"}` | `set()` |
| `dashboard/README.md` | "0 — empty template" | "50 across Overview / Rules / ATT&CK / Identities / Sources & Timing / Detail" |

Non-goals: changing `register_suzaku_dbs.py`, the agent's Suzaku Timeline page, or
anything Suzaku writes. The dashboard reads `aws-ct-timeline` output **as-is**.

---

## 2. Source material and why it cannot be copied verbatim

`sample/charts/` holds 56 draft chart YAMLs (`SZK-01` … `SZK-56`). They are well-written —
descriptions, `# SQL used to power this chart` footers, `optionName` discipline — and their
analytic content is what this plan adopts. But they were drafted against a **different data
model**: a hypothetical *imported, multi-cloud* `suzaku_detections` table plus a companion
`suzaku_detection_tags` table (dataset UUIDs `7c1f9d2a-…` and `3e8a5c47-…`).

Senrigan never imports Suzaku output. The bundle's dataset is a **virtual view over Suzaku's own
`timeline` table** (`suzaku_timeline`, UUID `5a021002-0000-4000-8000-000000000001`). Three
consequences drive the whole plan:

### 2.1 Column renames

| `sample/charts/` column | `suzaku_timeline` column | Note |
|---|---|---|
| `detected_at` | `event_time` | also every `granularity_sqla` |
| `source_ip` | `src_ip` | |
| `account_id` | `user_account_id` | |
| `access_key_id` | `user_access_key_id` | |
| `tags` (SZK-17) | `other_tags` | |
| `outcome` | — | **must be added** to the dataset SQL (§4.1) |
| `cloud_provider`, `source_path`, `record_type`, `category`, `target_object` | — | do not exist; charts using them are dropped or reworked (§3) |
| `src_country`, `src_city`, `src_asn` | — | **do not exist in `timeline` at all** (§2.2) |

### 2.2 There is no geo data in `timeline` — at all

`PLAN_SUZAKU_SCHEMA.md` P8: `metrics` carries `SrcASN`/`SrcCity`/`SrcCountry`; **`timeline` has
no geo columns even under `--geo-ip`**. Confirmed against both fixtures:

```
timeline : Timestamp RuleTitle RuleAuthor Level EventName ErrorCode ErrorMessage EventSource
           AwsRegion SrcIP UserAgent UserName UserType UserAccountID UserARN UserPrincipalID
           UserAccessKeyID EventID Tactics TechniqueIDs OtherTags RuleID          ← no geo
metrics  : … SrcASN SrcCity SrcCountry                                            ← geo here
```

A virtual dataset is one fixed SQL string: naming a non-existent column does not degrade
gracefully, it makes **every chart in the bundle** fail. So the seven geo charts are dropped
rather than guarded, and the geo columns are stripped from the multi-column tables that mention
them (SZK-12/39/48/56). Geographic analysis stays where the data is: the **Suzaku Field Metrics**
dashboard, which already documents its `--geo-ip` requirement.

### 2.3 Tactics/techniques are lists, and `array_to_string` is the wrong shape for charting

`Tactics` / `TechniqueIDs` / `OtherTags` are `VARCHAR[]`. The current dataset flattens them with
`array_to_string(…, ', ')`, so `GROUP BY tactics` groups by the *combination*
(`"Persis, PrivEsc, Stealth"`), not by tactic — useless for SZK-21…27. The draft charts solved
this with a second dataset, and so does this plan: a `suzaku_timeline_tags` virtual dataset that
`UNNEST`s the three arrays into `(tag_type, tag_value)` rows (§4.2). The nine `3e8a5c47-…` charts
then port almost verbatim.

---

## 3. Verdict for all 56 drafts

**Ported: 49. Dropped: 7. Added: 1 (SZK-57). Shipped: 50 charts; 46 after the §9.2 DFIR trim.**

| Verdict | Charts | Action |
|---|---|---|
| **Port as-is** (rename columns only) | 01–05, 07–11, 13–18, 28–31, 33, 34, 40, 43–47, 49, 50, 52 | mechanical rename per §2.1 |
| **Port, drop geo columns** | 12, 39, 48, 56 | remove `src_country`/`src_city`/`src_asn` from `groupby`; SZK-39/48 keep `src_ip` + `user_agent`/`user_name` context |
| **Port, needs `outcome`** | 51, 53 | requires the derived column in §4.1 |
| **Port, needs `user_account_id`** | 32, 35 | SZK-35 loses `cloud_provider` (AWS-only source) |
| **Port onto the tags dataset** | 19–27 | `tag_type`/`tag_value` come from §4.2; SZK-27 (`tag_type = 'group'`) renders empty until a rule set ships `attack.gNNNN` tags — the fixture's `OtherTags` is `[]` everywhere |
| **Rework** | 55 | provenance-by-`source_path` is meaningless without an importer → becomes **Suzaku Run Info** over `suzaku_meta` (§4.3): command line, generation time, rules version, scanned files/events, rows, deduped rows |
| **Drop — no geo in `timeline`** | 06, 36, 37, 38, 41, 42 | covered by Suzaku Field Metrics instead |
| **Drop — AWS-only source** | 54 (Azure/M365 workload) | `aws-ct-timeline` never produces these columns |
| **New** | **57 Distinct Events** | fills the KPI slot freed by SZK-06; `COUNT(DISTINCT event_id)` vs `COUNT(*)` is the one number that tells an analyst how much of the volume is multi-rule fan-out (fixture: 12,003 detections) |

---

## 4. Dataset work

### 4.1 `suzaku_timeline` — add one derived column

Add to the existing `datasets/suzaku_timeline.yaml` SQL, plus a matching `columns:` entry
(`verbose_name: Outcome`, `groupby: true`, `filterable: true`):

```sql
CASE WHEN "ErrorCode" IS NULL THEN 'Success' ELSE 'Failed' END AS outcome,
```

Nothing else changes: `level_rank`, the metrics (`severe_count`, `distinct_events`,
`failed_count`, `distinct_principals`, …) and the array flattening all stay. `COALESCE(user_arn,
user_name)` stays an ad-hoc metric expression in the charts that need it — no `principal` column.

### 4.2 `suzaku_timeline_tags` — new virtual dataset (UUID `5a021002-0000-4000-8000-000000000006`)

One row per (detection × tag). Verified against `sample/suzaku/fixtures/suzaku-aws-ct-timeline.duckdb`:
26,587 `tactic` rows, 19,517 `technique` rows, 0 `group`/`other` rows.

```sql
WITH base AS (
    SELECT "Timestamp"                       AS event_time,
           "Level"::VARCHAR                  AS level,
           CASE "Level" WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
                        WHEN 'low' THEN 2 ELSE 1 END AS level_rank,
           "RuleTitle"    AS rule_title,   "RuleID"        AS rule_id,
           "RuleAuthor"   AS rule_author,  "EventName"     AS event_name,
           "UserName"     AS user_name,    "UserARN"       AS user_arn,
           "UserAccountID" AS user_account_id, "EventID"   AS event_id,
           "Tactics" AS tactics, "TechniqueIDs" AS technique_ids, "OtherTags" AS other_tags
    FROM timeline
)
SELECT event_time, level, level_rank, rule_title, rule_id, rule_author, event_name,
       user_name, user_arn, user_account_id, event_id,
       'tactic' AS tag_type, unnest(tactics) AS tag_value
FROM base
UNION ALL
SELECT event_time, level, level_rank, rule_title, rule_id, rule_author, event_name,
       user_name, user_arn, user_account_id, event_id,
       'technique' AS tag_type, unnest(technique_ids) AS tag_value
FROM base
UNION ALL
SELECT event_time, level, level_rank, rule_title, rule_id, rule_author, event_name,
       user_name, user_arn, user_account_id, event_id,
       CASE WHEN regexp_matches(tag_value, '^[Gg][0-9]{4}$') THEN 'group' ELSE 'other' END
           AS tag_type,
       tag_value
FROM (SELECT base.*, unnest(other_tags) AS tag_value FROM base)
```

`main_dttm_col: event_time`. Metrics: `count`, `distinct_detections`
(`COUNT(DISTINCT event_id)`), `distinct_rules`, `distinct_tag_values`.

> Fan-out warning to put in the file header: a detection with three tactics contributes three
> rows, so `COUNT(*)` here is **tag occurrences**, not detections. Charts that must say
> "detections" use `COUNT(DISTINCT event_id)`.

### 4.3 `suzaku_timeline_meta` — new virtual dataset (UUID `5a021002-0000-4000-8000-000000000007`)

One row. Powers the reworked SZK-55.

```sql
SELECT command, command_line, generated_at, timestamp_tz, suzaku_version,
       rules_version, rules_count, scanned_files, scanned_events,
       output_rows, duplicate_rows_removed, schema_version
FROM suzaku_meta
```

`main_dttm_col: generated_at` (`TIMESTAMP WITH TIME ZONE` — satisfies
`test_main_dttm_col_is_really_temporal`).

> **Filter-scope trap:** `generated_at` is when Suzaku *ran*, not when detections happened. A
> dashboard-wide `filter_time` with `targets: [{}]` would blank this chart whenever the analyst
> picks a range that excludes "now". The Date Range native filter therefore excludes the Run Info
> chart through `scope.excluded`, which takes **chart ids** (the `chartId` in the position tree),
> not tab ids — so only that one chart escapes the filter, and Detection Detail on the same tab
> still obeys it.

---

## 5. Dashboard

### 5.1 UUID allocation

The bundles use a positional scheme: `5a021001-*` databases, `5a021002-*` datasets,
`5a021003-*` dashboards, `5a021004-*` summary charts, `5a021005-*` metrics charts. Timeline
charts take the next free block:

```
5a021006-0000-4000-8000-0000000000NN     where NN == the SZK number (01 … 57)
```

Traceable both ways: a chart's UUID names its draft in `sample/charts/`, and the block cannot
collide (`test_uuids_are_unique_across_all_bundles`).

### 5.2 Tabs and charts (50)

File names are the `sample/charts/` names, unchanged where the chart is ported.

| Tab | Charts |
|---|---|
| 🚦 **Overview** (12) | KPI rows: 01 Total Detections, 02 Critical + High, **57 Distinct Events**, 03 Distinct Rules / 04 Principals, 05 Source IPs, 07 Accounts, 08 Active Days. Then 09 Detections Over Time (stacked by severity), 10 Severity Breakdown, 11 Top Rules, 12 Detection Timeline |
| 🧩 **Rules** (5) | 13 Rule Summary, 14 Rule Activity Over Time, 15 Rare Rules, ~~16 Detections by Rule Author~~ (cut, §9.2), 17 Rule Catalog, 18 Newly Firing Rules |
| 🎯 **ATT&CK** (9) | 19 Tactics Covered, 20 Techniques Covered, 21 Tactic Distribution, 22 Technique Distribution, 23 Tactics Over Time, 24 Tactic × Severity, 25 Techniques and Their Rules, 26 Tactic × Principal, 27 Attributed Threat Groups — all on `suzaku_timeline_tags` |
| 👤 **Identities** (6) | 28 Top Principals, 29 Identity Type Breakdown, 30 Principal Summary, 31 Principal × Rule, 32 Access Key Activity, 35 Detections by Account, ~~47 First / Last Seen per Principal~~ (cut, §9.2) |
| 🌐 **Sources & Timing** (12) | 33 Top User Agents, 34 Rare User Agents, 39 Top Source IPs, ~~48 First / Last Seen per Source IP~~ (cut, §9.2), 40 Detections by AWS Region, 49 Top API Actions, 50 Detections by Service, 51 Success vs Failure, 52 Error Codes, 53 Action × Rule, 43 Heatmap (hour × day), ~~44 Detections by Hour~~ (cut, §9.2), 45 Detection Bursts, 46 Daily Severity Trend |
| 🔍 **Detail** (2) | 56 Detection Detail, **55′ Suzaku Run Info** (`suzaku_timeline_meta`) |

Each tab opens with a `MARKDOWN-hdr-*` block explaining what the tab answers, matching
`suzaku_metrics/dashboard.yaml`. Keep the two-`COUNT` habit from the drafts (`detections` +
`distinct_rules`, `MAX(level_rank)`) — it is what makes the tables triage-ready.

### 5.3 Native filters

Superset native filters target **one dataset**, so the timeline and tags datasets need parallel
entries — exactly how `suzaku_summary` handles its three datasets.

| Filter | Type | Target | Scope |
|---|---|---|---|
| Date Range | `filter_time` | `targets: [{}]` | ROOT, `excluded: [<Run Info chartId>]` (§4.3) |
| Severity | `filter_select` | `level` @ timeline | ROOT |
| Severity (ATT&CK) | `filter_select` | `level` @ tags | `rootPath: [TAB-attack]` |
| Rule | `filter_select` | `rule_title` @ timeline | ROOT |
| Principal | `filter_select` | `user_arn` @ timeline | ROOT |
| Account | `filter_select` | `user_account_id` @ timeline | ROOT |
| AWS Region | `filter_select` | `aws_region` @ timeline | ROOT |
| Tag Type | `filter_select` | `tag_type` @ tags | `rootPath: [TAB-attack]` |

`cross_filters_enabled: true`, `color_scheme: supersetColors`, and a `metadata.charts:` list
(slice_name / viz_type / description) mirroring `suzaku_summary/dashboard.yaml`.

### 5.4 Build

`rebuild_suzaku_timeline_zip.py`: remove the `# charts/: intentionally empty` comment, add the
two dataset entries and 50 explicit `charts/<file>.yaml → charts/<Slice_Name>.yaml` entries
(explicit, per PLAN_SUZAKU_VIEWS §5.4 — arc names are part of the import format). Update the
module docstring, which currently describes an empty template.

```bash
cd dashboard/assets && python3 rebuild_suzaku_timeline_zip.py
cd ../../docker && docker compose run --rm superset-init
```

---

## 6. Test list (TDD — write these first)

Most coverage is free: `test_suzaku_bundles.py` is parametrized over every bundle, so the 50
charts are immediately checked for placement, unique slice names, resolvable `dataset_uuid`,
executable metric/filter SQL against the fixture, existing `groupby` columns, and a declared
`row_limit`. Run it red before writing any YAML.

New/changed tests, all in `dashboard/tests/test_suzaku_bundles.py` unless noted:

1. `test_every_bundle_ships_charts` replaces `test_chartless_bundle_stays_empty`, and the
   `CHARTLESS_BUNDLES` constant is gone — a chartless bundle is a regression now, not a milestone.
2. `test_timeline_bundle_never_references_a_geo_column` — no chart or dataset in the bundle may
   name `src_country` / `src_city` / `src_asn` outside a comment (§2.2). This is the guard that
   stops a later copy-paste from a geo-carrying schema breaking every chart at once.
3. `test_timeline_tags_dataset_emits_only_known_tag_types` — the `UNION ALL` produces only
   `tactic` / `technique` / `group` / `other`, and the fixture really yields the first two.
4. `test_tag_charts_filter_on_a_known_tag_type` — a typo'd `tag_type = '...'` renders empty
   rather than erroring, so the literals are checked against the same domain.
5. `test_tag_charts_count_detections_distinctly` — a metric labelled "detections" on the tags
   dataset must use `COUNT(DISTINCT event_id)` (§4.2 fan-out).
6. `test_timeline_outcome_is_success_or_failed` — pins the two literals charts filter on.
7. `test_run_info_chart_is_outside_the_date_range_filter` — verified by mutation: putting the
   chart back in scope fails the test.

Two existing tests needed widening rather than new cases: `test_chart_groupby_columns_exist`
crashed on ad-hoc (dict) `groupby` entries such as the heatmap's `EXTRACT(HOUR FROM …)`, and
`_chart_sql_expressions` did not collect ad-hoc `groupby` / `x_axis` SQL — so those expressions
were never executed against the fixture. Both are fixed, which is what makes the heatmap and
hour-of-day charts genuinely covered.

`test_rebuild_suzaku_zips.py` needed no change: test 15 (every source YAML appears in the
FILE_MAP) and the stale-ZIP test cover the 53 new files automatically.

---

## 7. Docs and counts to update in the same PR

- `dashboard/README.md` — Suzaku table row (`0 — empty template` → `50 across …`), the
  `assets/` tree comment (`charts/ empty by design` → `3 virtual datasets, 50 charts`), and a
  note that geographic analysis lives on the Metrics dashboard because `timeline` has no geo
  columns.
- `doc/PLAN_SUZAKU_VIEWS.md` §5.3 — mark the empty-template contract as retired, pointing here.
- `CLAUDE.md` + `AGENTS.md` — dashboard test count (currently ≈ 749) and the Suzaku bundle
  description.
- `sample/charts/` — decide its fate (§9).

---

## 8. How it was verified

1. `make test-dashboard` — 757 tests green (was 749; the seven new cases above plus the widened
   ones). `make test-repo` — 115 green.
2. `python3 assets/rebuild_suzaku_timeline_zip.py` → 56 entries, then
   `docker compose run --rm superset-init`: all five dashboards import, and the timeline
   dashboard reports 46 charts through `/api/v1/dashboard/suzaku-detection-timeline/charts`
   (50 before the §9.2 DFIR trim).
3. Every chart's stored `query_context` was POSTed to `/api/v1/chart/data` against
   `sample/suzaku/sample-timeline.duckdb`: **50 of 50 returned rows, none empty, none errored**.
   Structural tests cannot catch a chart that is valid but blank, which is why this step exists.

---

## 9. Resolved decisions

1. **`sample/charts/` is deleted.** Every shipped chart keeps its `SZK-nn` id in the header
   comment, which is where an implementer looks; the drafts themselves described a schema
   Senrigan does not have and would have misled the next reader.
2. **50 charts on one dashboard** was roughly triple `suzaku_summary` (18). **The predicted cuts
   were made in a later DFIR review — the bundle is now 46 charts.** Removed:

   | Chart | Why it went |
   |---|---|
   | SZK-16 Detections by Rule Author | Sigma-rule provenance, not evidence. Says who wrote the detection content, never anything about the environment or the adversary. |
   | SZK-44 Detections by Hour of Day | The heatmap (SZK-43) collapsed onto one axis. SZK-43 answers the same off-hours question and keeps the weekday dimension. |
   | SZK-47 First / Last Seen per Principal | Columns already in SZK-30 Principal Summary, which also carries max severity, rule breadth and IP breadth. Its one unique column, `active_span_minutes`, was folded into SZK-30. |
   | SZK-48 First / Last Seen per Source IP | Same relationship to SZK-39 Top Source IPs; `active_span_minutes` folded into SZK-39. |

   The remaining large matrices SZK-31 / SZK-53 were kept — unlike the four above they are the
   only place their cross-tab exists. SZK-24 and SZK-26 became `heatmap` in the same review,
   because a named "matrix" of one metric over two dimensions is what a heatmap is for.
3. **SZK-27 threat groups is kept** even though it renders empty for rule sets without
   `attack.gNNNN` tags — its description says so, so it does not read as a broken chart.
