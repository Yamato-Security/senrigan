# PLAN: Suzaku DuckDB schema improvements (upstream proposal — shipped)

> **Status: adopted upstream.** Suzaku [PR #180](https://github.com/Yamato-Security/suzaku/pull/180)
> implements P1–P8 and ships them as DuckDB `schema_version = 1`. This document is kept as the
> reference for *why* the schema looks the way it does, and as the record of what Senrigan
> stopped working around — §11 lists what was actually removed. Sections 2–9 are written in the
> proposal's original future tense; read them as a description of the current schema.
>
> Everything below §0 was measured against the pre-#180 samples. The current samples are
> `sample/suzaku/sample-{timeline,summary,metrics}.duckdb`.

Findings and proposed changes for the DuckDB output of
[Suzaku](https://github.com/Yamato-Security/suzaku), measured against the sample databases
Senrigan consumes. Written to be usable as-is for an upstream issue or PR discussion.

**Audience:** Suzaku maintainers. **Consumer of record:** Senrigan's `agent` and `dashboard`
modules — see [PLAN_SUZAKU_VIEWS.md](PLAN_SUZAKU_VIEWS.md), whose §4.1 profile flags and §5.2
virtual datasets exist *only* to work around items P2, P3, P5 and P6 below. Every one of those
workarounds can be deleted if the schema changes.

**Nothing here blocks Senrigan.** All three files are readable and every issue has a consumer-side
workaround. The argument is that the workarounds are being paid for by every downstream tool,
repeatedly, and that some of them (P2, P4) fail silently when forgotten.

---

## 0. What was measured

| Item | Value |
|------|-------|
| Sample files | `sample/suzaku/sample-aws-ct-{timeline,summary,metrics}.duckdb` (pre-#180) |
| Measured on | 2026-07-26 |
| Reader | DuckDB CLI 1.5.2 (also verified: Python `duckdb` 1.5.2, Superset image `duckdb` 1.5.4) |
| Timeline rows | 1,925,150 (236.2 MiB on disk, 20 columns, all VARCHAR) |
| Summary rows | `summary` 22, `summary_api_calls` 2,667, `summary_attributes` 18,127 |
| Metrics rows | 1,344 (single `Field` value: `eventName`) |
| Source logs | flaws.cloud-style CloudTrail corpus spanning 2017-02-12 → 2024-08-18 |

Every number below is reproducible with the queries in [Appendix A](#appendix-a-reproduction).
The Suzaku version that produced these files is unknown — which is finding **P1**.

---

## 1. Summary of findings

| # | Finding | Evidence | Impact if unchanged |
|---|---------|----------|---------------------|
| **P1** | No self-describing metadata table | 0 metadata tables in all 3 files | Consumers must guess the producing command from table names; no provenance in DFIR reports; breaking schema changes are undetectable |
| **P2** | `-` used as a NULL sentinel | `ErrorCode` 421,514 rows = `-`, 0 NULL, 0 `''`; `UserName` 117,336 rows = `-`; `UserAccessKeyID` mixes `-` and `''` (49) | `IS NULL` silently wrong; `count(DISTINCT)` off by one; `-` appears as a category in every BI filter |
| **P3** | Every column is VARCHAR, including timestamps and severity | `Timestamp` VARCHAR(19) × 1,925,150; `Level` 5 distinct values; `First/LastSeen` VARCHAR | Every consumer casts; temporal correctness depends on the format staying lexicographic; severity ordering needs a hand-written `CASE` rank |
| **P4** | 37% of timeline rows are exact duplicates | 1,925,150 rows → `SELECT DISTINCT *` = 1,206,049; one `(EventID, RuleID)` repeated 8× with all fields identical | Every count and Top-N inflated ~1.6×; schema offers no way to tell re-delivered log records from double-counting |
| **P5** | Multi-value and composite values packed into single strings | `Tags` = `'PrivEsc ¦ InitAccess ¦ Persis ¦ Stealth ¦ T1078.004'`; `API` = `'RunInstances (ec2.amazonaws.com)'` (2,667/2,667 rows); `Category` = `'abused_success'` | String parsing required for tag, service and outcome analytics; tactics and ATT&CK technique IDs are indistinguishable without a heuristic |
| **P6** | Naming is inconsistent across commands, and one column needs quoting | `"AWS-Region"` (hyphen); `metrics.Field` value `eventName` vs timeline column `EventName`; `summary_attributes.Attribute` value `src_ip` vs timeline column `SrcIP` | Identifiers must be quoted in all generated SQL; the same concept has three spellings across three commands |
| **P7** | `Percent` stores a rounded derived value | `sum(Percent)` = 99.03, `max` = 67.07 | Re-aggregation compounds rounding error; the value is derivable from `Count` + a total that is not stored |
| **P8** | Geo columns are asymmetric | `metrics` has `SrcASN`/`SrcCity`/`SrcCountry`, all NULL in 1,344/1,344 rows; `timeline` has no geo columns at all | Geo analytics are impossible on the richest table; the columns that do exist look broken |
| **P9** | No constraints, no documented grain | `duckdb_constraints()` and `duckdb_indexes()` both return 0 rows; `EventID` has 1,139,102 distinct values over 1,925,150 rows | Consumers cannot know the row grain; joins and dedup are guesswork |
| **P10** | No explicit `CHECKPOINT` guarantee documented | Samples are clean (`wal_size` 0 bytes) | A leftover `<file>.wal` cannot be replayed from a read-only mount, which is how every Senrigan reader opens the file |

Deliberately **not** claimed: a query-performance benefit. A time-range `count(*)` over the
1.9 M-row table completes in ~0.01 s both as-is and after a typed + time-sorted rewrite. At this
scale the case for typing rests on correctness and ergonomics, not speed.

---

## 2. P1 — Add a self-describing metadata table

**Highest value single change.** With no metadata, a consumer cannot answer "which Suzaku, which
command, which ruleset, which timezone?" from the file itself. Senrigan currently infers the
producing command from a table-name + required-column signature
([PLAN_SUZAKU_VIEWS.md §2.4](PLAN_SUZAKU_VIEWS.md)) — a heuristic standing in for a fact the
writer knows for certain.

```sql
CREATE TABLE suzaku_meta (
    schema_version  INTEGER   NOT NULL,  -- bump on any breaking change
    suzaku_version  VARCHAR   NOT NULL,  -- '2.1.0'
    command         VARCHAR   NOT NULL,  -- 'aws-ct-timeline' | 'aws-ct-summary' | 'aws-ct-metrics'
    command_line    VARCHAR,             -- full invocation: DFIR provenance
    generated_at    TIMESTAMP WITH TIME ZONE NOT NULL,
    timestamp_tz    VARCHAR,             -- timezone of Timestamp/*Seen columns (currently unknowable)
    rules_version   VARCHAR,             -- ruleset revision or commit
    rules_count     INTEGER,
    scanned_files   BIGINT,
    scanned_events  BIGINT
);
```

Why each field earns its place:

- `command` turns detection from inference into a lookup, and makes a future single-file,
  multi-command output unambiguous.
- `schema_version` lets a consumer refuse a file it does not understand instead of
  mis-visualizing it. Without it, a renamed column becomes a silent empty chart.
- `command_line`, `rules_version`, `rules_count`, `scanned_files`, `scanned_events` are what an
  incident report must cite to be reproducible. Senrigan generates Markdown/HTML DFIR reports and
  today cannot state which ruleset produced a detection.
- `timestamp_tz` resolves a genuine ambiguity: the sample's `Timestamp` values carry no offset, so
  no consumer can correlate them with another timezone's evidence with confidence.

A single-row table is fine; a key/value shape (`suzaku_meta(key, value)`) is equally acceptable
and more extensible. Either is a strict improvement over none.

---

## 3. P2 — Use NULL, not `-`

```
ErrorCode:        421,514 rows = '-',  0 NULL,  0 ''
UserName:         117,336 rows = '-'
UserAccessKeyID:  '-' and '' (49 rows) both present
```

`-` is a CSV/TSV presentation convention that has leaked into a typed columnar store. The
consequences are concrete:

- "Did this API call fail?" cannot be written `ErrorCode IS NOT NULL`. It must be
  `ErrorCode <> '-'`, and every consumer that forgets is wrong by 421,514 rows.
- `count(DISTINCT UserName)` is inflated by one, permanently.
- BI tools offer `-` as a filter value in every dropdown.
- Two sentinels (`-` and `''`) coexist, so handling only one is a live bug.

**Proposal:** write `NULL` in the DuckDB output; keep rendering `-` in the CSV/TSV writers, where
it belongs. If a placeholder must stay for compatibility, use exactly one and document it in
`suzaku_meta`.

---

## 4. P3 — Give columns real types

```
Timestamp                                 VARCHAR, always 19 chars, 1,925,150/1,925,150 rows
FirstSeen / LastSeen / First/LastTimestamp VARCHAR (summary, metrics)
Level                                     VARCHAR, 5 distinct values
```

Proposed:

```sql
Timestamp  TIMESTAMP           -- or TIMESTAMP WITH TIME ZONE, paired with suzaku_meta.timestamp_tz
Level      ENUM('informational', 'low', 'medium', 'high', 'critical')
FirstSeen  TIMESTAMP           -- and LastSeen / FirstTimestamp / LastTimestamp
```

- `Timestamp` sorting and `BETWEEN` work today only because the chosen format happens to be
  lexicographic. That is a side effect, not a contract: adding an ISO 8601 `T`, a `Z`, or an
  offset breaks every downstream range filter at once. A `TIMESTAMP` column cannot break that way.
  Superset additionally requires a temporal column, so Senrigan wraps the table in a virtual
  dataset purely to `CAST` it ([PLAN_SUZAKU_VIEWS.md §5.2](PLAN_SUZAKU_VIEWS.md)).
- `Level` as an `ENUM` puts severity order in the type: `ORDER BY Level DESC` replaces the
  `CASE WHEN Level = 'critical' THEN 5 …` rank every consumer writes by hand. It also makes an
  invalid severity a write-time error instead of a silent new category.
- Measured cost/benefit of a typed + `ORDER BY Timestamp` rewrite of the sample:
  **236.2 MiB → 201.7 MiB (−15%)**, 1,925,150 rows preserved. Storage is a side benefit; the
  point is that the types stop being a downstream problem.

Already correctly typed and worth keeping: `Count BIGINT`, `Percent DOUBLE`, `NumOfEvents BIGINT`.

---

## 5. P4 — Resolve the 37% duplicate rows

```
total rows                                  1,925,150
SELECT DISTINCT *                           1,206,049   → 719,101 exact duplicates (37.4%)
max repeats of one (EventID, RuleID)                8   (all 20 columns identical)
distinct rules matched per event             1 → 1,072,195 events
                                             2 →    66,868
                                             3 →        38
                                             4 →         1
```

The multi-rule fan-out is legitimate: one event matching several rules *should* produce several
rows, so the grain `event × rule match` is right. The problem sits on top of it — the same
`(EventID, RuleID)` pair repeats up to 8 times with every field byte-identical. Example:

```
2019-10-16 16:37:01 | API Call From Hacking Distro | GetPolicy | 217.254.3.250 | Level6 | ×8
```

Consequence: every count, Top-N and trend derived from this file is inflated by roughly 1.6×.
A dashboard reading it reports wrong numbers with no indication anything is off.

The root cause may well be upstream of Suzaku — CloudTrail corpora frequently contain the same
record in overlapping exports, and this corpus is a public teaching dataset. That is exactly the
issue: **the schema gives the consumer no way to tell "the log contained this record twice" from
"the tool emitted it twice."** Either resolution is fine:

1. **Deduplicate on write** on `(EventID, RuleID)`, or
2. **Add provenance columns** — `SourceFile VARCHAR`, `RecordIndex BIGINT` — so a consumer can
   distinguish re-delivery from double counting, and dedupe correctly itself.

Whichever is chosen, document the uniqueness guarantee (see P9). Option 2 is more informative and
also serves incident reporting ("which file did this detection come from?"). Note that Senrigan's
own ingester already SHA-256-deduplicates input *files*, so record-level duplicates surviving into
a tool's output is a familiar failure mode in this domain.

---

## 6. P5 — Stop packing multi-value and composite data into strings

DuckDB has `LIST` (`VARCHAR[]`) and `STRUCT`, so delimiter packing buys nothing here.

### 6.1 `timeline.Tags`

```
'PrivEsc ¦ InitAccess ¦ Persis ¦ Stealth ¦ T1078.004'      -- separator is " ¦ " (U+00A6)
'Disc ¦ T1526'
```

Two distinct problems: it is multi-value, and it mixes **tactic short names with ATT&CK technique
IDs in one field**. A consumer wanting technique coverage must `string_split` on a non-ASCII
separator, `unnest`, then apply a "starts with T + digits" heuristic to separate the two kinds.

```sql
Tactics       VARCHAR[]   -- ['PrivEsc', 'InitAccess', 'Persis', 'Stealth']
TechniqueIDs  VARCHAR[]   -- ['T1078.004']
```

A side table (`timeline_tags(EventID, RuleID, Tag, TagKind)`) is equally good and joins more
naturally in BI tools. Either way, drop the packed string or keep it only as a CSV-layer rendering.

### 6.2 `summary_api_calls.API`

```
'RunInstances (ec2.amazonaws.com)'    -- 2,667 of 2,667 rows use this exact shape
```

Service and action are already separate columns in `timeline` (`EventName`, `EventSource`), so
this is an **internal inconsistency within one product**. Split into `API` + `EventSource`.

### 6.3 `summary_api_calls.Category`

```
abused_success | abused_failed | other_success | other_failed
```

Two orthogonal axes in one column, forcing `LIKE 'abused%'` for one and `LIKE '%failed'` for the
other:

```sql
IsAbused  BOOLEAN
Outcome   ENUM('success', 'failed')
```

### 6.4 `summary.UserTypes`

Plural name, but all 22 sample rows hold a single value (`Root`, `AssumedRole`, `IAMUser`). Either
make it `VARCHAR[]` (if an identity really can have several) or rename it `UserType`. As it stands
a consumer must defensively parse for a delimiter that may never appear.

`summary_api_calls.Description` — Suzaku's plain-language explanation of why an API is abusable
(max length 57 in the sample) — deserves a mention as the **most valuable column in these files**.
It should stay, and ideally appear in the timeline output too, keyed by rule.

---

## 7. P6 — Make naming consistent

| Issue | Detail | Proposal |
|-------|--------|----------|
| Hyphenated identifier | `"AWS-Region"` must be double-quoted in every SQL statement, in every consumer, forever | `AwsRegion` (or `Region`) |
| Same concept, three spellings | timeline column `EventName` (PascalCase) vs `metrics.Field` value `eventName` (lowerCamel, the raw CloudTrail field name) vs `summary_attributes.Attribute` value `src_ip` (snake_case) vs timeline column `SrcIP` | Pick one convention for column names and one for field-name *values*, and state which is which |
| Case convention | PascalCase columns are harmless inside DuckDB (identifiers are case-insensitive) but create friction once results reach pandas / Superset / JSON | `snake_case` preferred; secondary to the two issues above |

The hyphen is the one that costs real money: it makes correct SQL depend on remembering to quote,
in a tool whose primary consumers are ad-hoc queries and LLM-generated SQL.

---

## 8. P7–P10 — Smaller items

**P7 · `metrics.Percent` is a rounded derived value.** `sum(Percent)` = 99.03 (not 100),
`max` = 67.07 — two-decimal rounding. Re-aggregating rounded percentages compounds the error.
Either store full precision, or drop the column and store the denominator (total event count) in
`suzaku_meta` so consumers derive it exactly from `Count`.

**P8 · Geo columns are asymmetric.** `metrics` carries `SrcASN`/`SrcCity`/`SrcCountry`, NULL in
1,344/1,344 sample rows, while `timeline` — which has `SrcIP` and 9,303 distinct source IPs — has
no geo columns at all. Adding `SrcCountry`/`SrcASN` to `timeline` when enrichment is enabled would
make geographic detection analytics possible in one step. Conversely, if enrichment was off,
consider omitting the columns rather than emitting all-NULL ones that read as broken.

**P9 · Declare the grain.** `duckdb_constraints()` and `duckdb_indexes()` both return zero rows.
Primary keys buy little performance in DuckDB, but they document intent, and intent is currently
undocumented: `EventID` has 1,139,102 distinct values across 1,925,150 rows, so a reader who
assumes `EventID` is unique is wrong 750,406 times. State plainly — in the docs and ideally as a
constraint — that a timeline row is one `(event × rule match)`, and what the uniqueness key is
after P4 is resolved.

**P10 · `CHECKPOINT` before exit, and document it.** The samples are clean (`wal_size` 0 bytes),
so this is preventive. A `.duckdb` file left with an un-checkpointed `<file>.wal` cannot be opened
from a read-only mount — which is precisely how Senrigan's `agent`, `superset` and `config-viz`
containers open it (`/data/db:ro`, `read_only=true`). An explicit checkpoint on exit, plus a
documented "copy only after Suzaku exits" note, avoids a confusing failure.

---

## 9. Proposed target schemas

Illustrative consolidation of the above. Column order preserved from the current output so a diff
stays readable.

```sql
-- aws-ct-timeline
CREATE TABLE timeline (
    Timestamp        TIMESTAMP NOT NULL,     -- P3
    RuleTitle        VARCHAR   NOT NULL,
    RuleAuthor       VARCHAR,
    Level            ENUM('informational','low','medium','high','critical') NOT NULL,  -- P3
    EventName        VARCHAR   NOT NULL,
    ErrorCode        VARCHAR,                -- P2: NULL, not '-'
    ErrorMessage     VARCHAR,                -- P2
    EventSource      VARCHAR   NOT NULL,
    AwsRegion        VARCHAR,                -- P6: was "AWS-Region"
    SrcIP            VARCHAR,
    SrcCountry       VARCHAR,                -- P8 (when enrichment is enabled)
    SrcASN           VARCHAR,                -- P8
    UserAgent        VARCHAR,
    UserName         VARCHAR,                -- P2
    UserType         VARCHAR,
    UserAccountID    VARCHAR,
    UserARN          VARCHAR,
    UserPrincipalID  VARCHAR,
    UserAccessKeyID  VARCHAR,                -- P2
    EventID          VARCHAR   NOT NULL,
    Tactics          VARCHAR[],              -- P5: was packed into Tags
    TechniqueIDs     VARCHAR[],              -- P5
    RuleID           VARCHAR   NOT NULL,
    SourceFile       VARCHAR,                -- P4 (if not deduplicating on write)
    RecordIndex      BIGINT                  -- P4
);

-- aws-ct-summary
CREATE TABLE summary (
    UserARN         VARCHAR NOT NULL,
    NumOfEvents     BIGINT  NOT NULL,
    FirstTimestamp  TIMESTAMP,               -- P3
    LastTimestamp   TIMESTAMP,               -- P3
    UserTypes       VARCHAR[]                -- P5: or rename to UserType
);

CREATE TABLE summary_api_calls (
    UserARN      VARCHAR NOT NULL,
    IsAbused     BOOLEAN NOT NULL,           -- P5: was Category
    Outcome      ENUM('success','failed') NOT NULL,  -- P5
    API          VARCHAR NOT NULL,           -- P5: action only
    EventSource  VARCHAR NOT NULL,           -- P5: split out of API
    Description  VARCHAR,
    Count        BIGINT  NOT NULL,
    FirstSeen    TIMESTAMP,                  -- P3
    LastSeen     TIMESTAMP                   -- P3
);

CREATE TABLE summary_attributes (
    UserARN    VARCHAR NOT NULL,
    Attribute  VARCHAR NOT NULL,             -- P6: align spelling with timeline columns
    Value      VARCHAR NOT NULL,
    Count      BIGINT  NOT NULL,
    FirstSeen  TIMESTAMP,                    -- P3
    LastSeen   TIMESTAMP                     -- P3
);

-- aws-ct-metrics
CREATE TABLE metrics (
    Field       VARCHAR NOT NULL,            -- P6: same spelling as the timeline column it names
    Value       VARCHAR NOT NULL,
    Count       BIGINT  NOT NULL,
    Percent     DOUBLE,                      -- P7: full precision, or drop and store the total in suzaku_meta
    FirstSeen   TIMESTAMP,                   -- P3
    LastSeen    TIMESTAMP,                   -- P3
    SrcASN      VARCHAR,
    SrcCity     VARCHAR,
    SrcCountry  VARCHAR
);
```

Plus `suzaku_meta` from §2 in every file.

---

## 10. Compatibility and sequencing

Most of these are breaking changes for existing consumers, so sequence matters:

1. **Ship `suzaku_meta` first (P1), additively.** It breaks nothing, and it is what lets every
   later change be *detectable* rather than silent. Set `schema_version = 1` for today's layout.
2. **Then the silent-failure fixes (P2, P4).** These change results, not shapes — consumers whose
   numbers were quietly wrong start being right. Call them out in release notes; bump
   `schema_version`.
3. **Then typing and renaming (P3, P6) together, in one `schema_version` bump.** Both require
   consumer edits; doing them in one release means one migration, not two.
4. **Then structural changes (P5, P8).** Optionally transitional: add `Tactics`/`TechniqueIDs`
   *alongside* `Tags`, deprecate `Tags` one release later.
5. **P7, P9, P10** are independent and can ride along anywhere.

Two general points:

- **The DuckDB output is a data interface; the CSV/JSONL outputs are presentation.** Several
  findings (P2's `-`, P5's packed strings, P7's rounding) are text-output conventions applied to a
  typed store. Letting the two formats diverge — placeholders and packing in text, NULLs and
  LISTs in DuckDB — resolves them without changing anyone's existing CSV pipeline.
- **A single file holding several commands' output** would be welcome operationally (one file to
  copy, one Superset connection). Senrigan's detector returns a *set* of kinds precisely so that
  a combined file works, and `suzaku_meta.command` would generalize to a row per command.

---

## 11. What Senrigan deleted when this landed

Recorded so the workarounds do not outlive their cause
(see [PLAN_SUZAKU_VIEWS.md](PLAN_SUZAKU_VIEWS.md)):

| Upstream fix | Senrigan code removed |
|--------------|-----------------------|
| P1 `suzaku_meta` | The table-signature detector in `agent/suzaku_db.py` and `dashboard/init/register_suzaku_dbs.py` — both now read `suzaku_meta.command`, and refuse a `schema_version` above the one they were written against. The parity test survives, guarding a much smaller pair of constants |
| P2 NULLs | `nullif(x, '-')` in every virtual dataset; `<> '-'` in every built-in hunt, replaced by `IS NOT NULL` |
| P3 `TIMESTAMP` | `SUZAKU_TIMELINE_PROFILE.time_is_varchar` (the flag stays on `DatasetProfile` for a future dataset, but no profile sets it) and every `CAST(... AS TIMESTAMP)` in the hunts and datasets |
| P3 `Level` ENUM | `DatasetProfile.level_rank_sql()`, and the severity `CASE` rank in the hunts YAML and the system prompt — replaced by `ORDER BY "Level" DESC` and `>= 'high'::suzaku_level` |
| P4 dedup | Nothing to remove: Suzaku now dedups on write and reports it in `suzaku_meta.duplicate_rows_removed` |
| P5 `Tactics`/`TechniqueIDs` | `string_split("Tags", ' ¦ ')`, the `unnest` + `T`-prefix heuristic in the ATT&CK hunts, the `Category LIKE 'abused%'` split and the `regexp_extract` that unpacked `API` |
| P6 `AwsRegion` | The `"AWS-Region"` special case in the prompt, the schema and the datasets. `quote_identifiers` stays — the columns are still PascalCase |
| P7 `FieldTotal` | The "shares sum to ~99, not 100" caveat on the metrics dataset |
| P8 metrics geo | The `nullif(x, '')` on the geo columns. The columns are now present only under `--geo-ip`, which the metrics dashboard therefore requires |

What did **not** become removable: the virtual datasets themselves. They still rename PascalCase
to snake_case and join the new `VARCHAR[]` columns into strings, because Superset cannot group by
a list.

---

## Appendix A: Reproduction

Run from the Senrigan repository root with DuckDB ≥ 1.5.2.

```bash
# P1 — no metadata table anywhere
for f in sample/suzaku/*.duckdb; do echo "$f"; duckdb -readonly "$f" -c "SHOW TABLES;"; done

# P2 — the '-' sentinel
duckdb -readonly sample/suzaku/sample-aws-ct-timeline.duckdb -c "
SELECT count(*) FILTER (WHERE ErrorCode IS NULL)  AS ec_null,
       count(*) FILTER (WHERE ErrorCode = '')     AS ec_empty,
       count(*) FILTER (WHERE ErrorCode = '-')    AS ec_dash,
       count(*) FILTER (WHERE UserName  = '-')    AS un_dash,
       count(*) FILTER (WHERE UserAccessKeyID = '') AS ak_empty
FROM timeline;"

# P3 — types and cardinality
duckdb -readonly sample/suzaku/sample-aws-ct-timeline.duckdb -c "DESCRIBE timeline;" -c "
SELECT length(Timestamp) AS len, count(*) FROM timeline GROUP BY 1;" -c "
SELECT count(DISTINCT Level) AS levels, count(DISTINCT \"AWS-Region\") AS regions FROM timeline;"

# P3 — typed + sorted rewrite, then compare PRAGMA database_size (236.2 → 201.7 MiB)
duckdb /tmp/typed.duckdb -c "
ATTACH 'sample/suzaku/sample-aws-ct-timeline.duckdb' AS src (READ_ONLY);
CREATE TABLE timeline AS
  SELECT CAST(Timestamp AS TIMESTAMP) AS Timestamp, RuleTitle, RuleAuthor,
         CAST(Level AS ENUM('informational','low','medium','high','critical')) AS Level,
         EventName, nullif(ErrorCode,'-') AS ErrorCode, nullif(ErrorMessage,'-') AS ErrorMessage,
         EventSource, \"AWS-Region\", SrcIP, UserAgent, nullif(UserName,'-') AS UserName,
         UserType, UserAccountID, UserARN, UserPrincipalID,
         nullif(UserAccessKeyID,'-') AS UserAccessKeyID, EventID, Tags, RuleID
  FROM src.timeline ORDER BY Timestamp;
CHECKPOINT;"

# P4 — duplicate rows and the multi-rule fan-out
duckdb -readonly sample/suzaku/sample-aws-ct-timeline.duckdb -c "
SELECT count(*) AS total, (SELECT count(*) FROM (SELECT DISTINCT * FROM timeline)) AS distinct_rows
FROM timeline;" -c "
SELECT max(c) AS max_repeats FROM (SELECT count(*) c FROM timeline GROUP BY EventID, RuleID);" -c "
SELECT c AS rules_per_event, count(*) AS events
FROM (SELECT EventID, count(DISTINCT RuleID) c FROM timeline GROUP BY 1) GROUP BY 1 ORDER BY 1;"

# P5 — packed values
duckdb -readonly sample/suzaku/sample-aws-ct-timeline.duckdb -c "
SELECT DISTINCT Tags FROM timeline LIMIT 5;"
duckdb -readonly sample/suzaku/sample-aws-ct-summary.duckdb -c "
SELECT count(*) AS rows_not_matching_shape FROM summary_api_calls WHERE API NOT LIKE '% (%)';" -c "
SELECT DISTINCT Category FROM summary_api_calls;" -c "SELECT DISTINCT UserTypes FROM summary;"

# P7 / P8 — rounded percent, empty geo columns, single Field value
duckdb -readonly sample/suzaku/sample-aws-ct-metrics.duckdb -c "
SELECT min(Percent), max(Percent), sum(Percent) FROM metrics;" -c "
SELECT count(*) FILTER (WHERE SrcASN IS NULL) AS asn_null, count(*) AS total FROM metrics;" -c "
SELECT DISTINCT Field FROM metrics;"

# P9 / P10 — no constraints or indexes; WAL state
duckdb -readonly sample/suzaku/sample-aws-ct-timeline.duckdb -c "SELECT * FROM duckdb_constraints();" \
  -c "SELECT * FROM duckdb_indexes();" -c "PRAGMA database_size;"
```
