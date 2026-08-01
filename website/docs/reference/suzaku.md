# Suzaku Integration Reference

[Suzaku](https://github.com/Yamato-Security/suzaku) is Yamato Security's CloudTrail
detection engine. Senrigan visualizes its DuckDB output directly — nothing is
imported, nothing is converted, and the files are only ever opened read-only.

## Setup

Run Suzaku with DuckDB output, then copy the result next to Senrigan's own database:

```bash
# 1. Run Suzaku against your CloudTrail logs
suzaku aws-ct-timeline -d <cloudtrail-logs> -o timeline.duckdb
suzaku aws-ct-summary  -d <cloudtrail-logs> -o summary.duckdb
suzaku aws-ct-metrics  -d <cloudtrail-logs> -f eventName -o metrics.duckdb --geo-ip  # --geo-ip is required

# 2. Copy them into the database directory
cp *.duckdb docker/data/db/

# 3. Restart so the dashboard registers the new databases
make up
```

`aws-ct-metrics` must run with `--geo-ip`: Suzaku writes the `SrcASN` /
`SrcCity` / `SrcCountry` columns only for a GeoIP-enriched run, and the
Suzaku Field Metrics(aws-ct-metrics) dashboard selects them.

`make status` reports which Suzaku files it can see.

!!! note "The file name does not matter"
    Senrigan detects which Suzaku command produced a file **from its schema**, so
    you can name the files anything. When two files match the same command the
    newest wins; set `SUZAKU_TIMELINE_DB`, `SUZAKU_SUMMARY_DB` or
    `SUZAKU_METRICS_DB` to pin a specific one.

!!! warning "Copy only after Suzaku has finished"
    A `.duckdb` file left with an un-checkpointed `.wal` sibling cannot be opened
    from the read-only mount the containers use. Let Suzaku exit first; the agent
    tells you explicitly when it finds a stale `.wal`.

## Where each command's output is visualized

| Suzaku command | Agent page | Superset dashboard |
|----------------|------------|--------------------|
| `aws-ct-timeline` | 🕒 **Suzaku Timeline** — 16 built-in hunts, AI chat, reports | Suzaku Detection Timeline(aws-ct-timeline) (46 charts) |
| `aws-ct-summary` | — | Suzaku Identity Summary(aws-ct-summary) (19 charts) |
| `aws-ct-metrics` | — | Suzaku Field Metrics(aws-ct-metrics) (15 charts) |

Each chart count includes that dashboard's **Suzaku Run Info** card. When the mounted
directory holds several files for the same command, that card is how you tell which one
the dashboard picked; `make status` prints the same choice before you open a browser.

The split is deliberate. `aws-ct-timeline` is raw, high-cardinality detection data —
exactly what ad-hoc SQL and AI narration are for. `aws-ct-summary` and
`aws-ct-metrics` are **already aggregated by Suzaku**, so they go straight to
dashboards; re-aggregating them through an LLM would add cost and a hallucination
surface while removing nothing.

## Agent — 🕒 Suzaku Timeline page

The page reuses the whole hunting UI: built-in hunts, date range, result-presence
and keyword filters, Markdown/HTML report, session export, AI chat and AI analysis.
Its session state is separate from the CloudTrail page, so two investigations never
interfere; the API key, model and row cap are shared.

Two things are specific to Suzaku data:

- **Severity filter** — `low` and `informational` are around 87% of a real timeline,
  so the sidebar defaults to `critical` / `high` / `medium`. Turn them on when you
  want the full picture.
- **Database selector** — every `*.duckdb` in the mounted directory whose schema
  matches `aws-ct-timeline`, newest first, with its row count.

### Built-in hunts

| Category | Hunts |
|----------|-------|
| 🚨 Triage | Critical & High detections · detection volume by severity · detection trend per day |
| 📜 Rules | Top rules (medium+) · rare rules (fired once) · rule onset (first/last seen) |
| 🔑 Identity | Top principals by severe detections · root-account detections · access keys behind detections |
| 🌍 Origin | Top source IPs by distinct rules · top user agents · multi-region activity per principal |
| ⚠ Failures | Failed API calls in detections |
| 🧬 ATT&CK | Technique coverage · tactic breakdown · rule × technique matrix |

Every hunt runs without an API key, carries an explicit `ORDER BY` and `LIMIT`, and
is executed against a real Suzaku fixture in CI.

## Dashboards

### Suzaku Identity Summary(aws-ct-summary)

| Tab | Content |
|-----|---------|
| 🚦 Overview | Profiled identities · total events · distinct abused APIs · failed abuse attempts · distinct source IPs · distinct access keys |
| 👤 Identities | Identity triage table · top identities by volume · abused vs other calls per identity · identity type composition · activity span |
| ⚠️ API Abuse | Top abused APIs · top failed calls · abused APIs by AWS service · abused API catalogue with Suzaku's own explanation of each |
| 🔎 Attributes | Top values for the selected attribute · rare values · first/last seen |

### Suzaku Field Metrics(aws-ct-metrics)

| Tab | Content |
|-----|---------|
| 🚦 Overview | Fields counted · distinct values · total occurrences · top value share · values seen once · source countries |
| 📊 Distribution | Top values · share composition · full frequency table |
| 💎 Rare & Temporal | Rare values (bottom-N) · newest values · value activity span |
| 🌍 GeoIP | Top countries · top ASNs · value × location matrix |

This dashboard is **field-agnostic**: Suzaku counts whichever field it was given
with `-f`, so no chart assumes `eventName` and the `Field` filter drives everything.

### Suzaku Detection Timeline(aws-ct-timeline)

Currently an empty template — its charts arrive in a follow-up change. Until then,
use the agent's Suzaku Timeline page, or SQL Lab against the
`Suzaku Timeline DuckDB` connection and the `suzaku_timeline` dataset, which is
already renamed to snake_case, with the `VARCHAR[]` tag columns joined into
readable strings.

## Notes on Suzaku's schema

Suzaku's DuckDB output is typed: real `TIMESTAMP`s, an ordered `suzaku_level`
ENUM for the severity, `NULL` for absent values, and `VARCHAR[]` for multi-value
fields. Senrigan reads it directly; the only adaptation left is the PascalCase →
snake_case rename in the Superset datasets. The schema is documented in
`doc/PLAN_SUZAKU_SCHEMA.md`.

Two things are worth knowing when you write your own SQL. `"Level"` is an ENUM, so
`ORDER BY "Level" DESC` is already severity order — but a threshold needs the
cast, `"Level" >= 'high'::suzaku_level`, because DuckDB compares an ENUM against a
bare string literal alphabetically. And every file carries a one-row `suzaku_meta`
table naming the command, ruleset and timezone that produced it.

One consequence is worth knowing while reading any Suzaku output: a timeline row is
one **rule match**, not one event. An event matching three rules produces three
rows, so detection counts are legitimately higher than event counts. Use
`COUNT(DISTINCT "EventID")` when you want events.
