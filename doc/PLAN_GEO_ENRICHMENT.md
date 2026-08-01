# PLAN: Automatic GeoIP Columns for IP Address Output

Implementation plan for the feature request: whenever query results (or exported data)
contain an IP address column, automatically include the geo-related columns
(country, city, ASN/ISP organization) so analysts never have to look up an IP manually.

**Status (2026-07-16): implemented.** Steps 1–5 below are done. Deviations from the
original plan discovered during implementation:

- Superset charts in this repo use no `all_columns` at all — "raw" tables are built as
  `groupby` (including `event_time`) + a `COUNT(*)` metric. Layer 3 therefore appends
  `geo_country_code` / `geo_city` to the **groupby** of every table chart that shows
  `source_ip_address` — both event-level listings (37 charts) and, revising the
  original "skip aggregates" plan, per-IP aggregation tables (7 more charts, e.g.
  `source_ip_requests.yaml`, which additionally gets `geo_org` for ISP context;
  geo columns are functionally dependent on the IP so grouping granularity is
  unchanged). Three pre-existing geo-aware charts that only showed a country column
  gained `geo_city`. An invariant test in `dashboard/tests/test_chart_yaml.py`
  enforces this for every current and future table chart (`geo_country_name` is
  accepted in place of `geo_country_code`, e.g. `fs_source_ip.yaml`).
- After editing chart YAML, both `cloudtrail_default.zip` and `cloudtrail_rare.zip`
  were rebuilt (`rebuild_zip.py` + `rebuild_rare_zip.py`). The derived Rare Events
  dashboard inherits the geo columns automatically because it is generated from the
  same `cloudtrail_default/` YAML. Running `docker compose run --rm superset-init`
  is still required on each deployment to import the new zips into Superset's
  metadata DB.

Affected modules: `agent` (primary), `dashboard` (secondary).
The `ingester` already populates `geo_country_code`, `geo_country_name`, `geo_city`,
`geo_latitude`, `geo_longitude`, `geo_asn`, and `geo_org` on `cloudtrail_events`
(see `ingester enrich` / `--geoip-*` flags), so no ingester changes are needed.

---

## Design Overview

Two complementary layers. Layer 1 is deterministic and covers every execution path
(AI-generated SQL, built-in hunts, edited/re-run SQL) without touching 120+ YAML
queries. Layer 2 nudges the LLM so that aggregated results — where a post-hoc join
is impossible — also carry geo context.

### Layer 1 — Post-execution DataFrame enrichment (agent, deterministic)

New module `agent/geo.py` with pure, independently testable functions:

```python
GEO_ENRICH_COLUMNS = ["geo_country_code", "geo_city", "geo_org"]  # display set
MAX_LOOKUP_IPS = 1000  # cap on distinct IPs per lookup query

def find_ip_columns(df: pd.DataFrame) -> list[str]:
    """Return result columns that look like IP addresses.

    Detection is name-based first (source_ip_address, *_ip, ip_address, ip),
    confirmed value-based (sample rows match an IPv4/IPv6 regex) so that
    LLM-aliased columns (e.g. "AS ip") are caught and false positives
    (e.g. "description") are not.
    """

def enrich_with_geo(conn, df: pd.DataFrame) -> pd.DataFrame:
    """Left-merge geo columns next to each detected IP column.

    - No-op when: df is empty, no IP column is found, or df already
      contains any geo_* column (the query author opted in manually).
    - Lookup: SELECT source_ip_address, MAX(geo_country_code), ...
      FROM cloudtrail_events WHERE source_ip_address IN (?, ...)
      GROUP BY source_ip_address  -- GROUP BY prevents row fan-out
      (parameterized; at most MAX_LOOKUP_IPS distinct IPs).
    - Geo columns are inserted immediately after the IP column.
      For a second/third IP column, prefix with the column name
      (e.g. "peer_ip_geo_country_code") to avoid collisions.
    - IPs absent from the DB (or private/unenriched) yield NULL geo values;
      row count and existing columns are never altered.
    """
```

Hook points (all three execution paths in `agent/handlers.py`):

- `_handle_direct_sql` (built-in hunts, no API key path)
- `_handle_edit_rerun_sql` (SQL editor re-run)
- `_handle_user_query` (AI-generated SQL via `execute_with_retry`)

Enrichment runs inside the existing `duckdb_connection` block right after query
execution, wrapped in `try/except` + `logger.warning` — a failed enrichment must
never fail the query itself.

UI: a sidebar toggle "🌍 Auto geo-enrich IP columns" (`st.session_state.geo_enrich`,
default **ON**). When the DB was ingested without GeoLite2 databases the merged
columns are all-NULL; in that case drop them again and show nothing (silent no-op),
so non-GeoIP users see no clutter.

Exports come for free: the Markdown/HTML report (`report.py`), session JSON export,
and any CSV download all serialize `entry.results`, which is already enriched.

### Layer 2 — LLM prompt guidance (agent)

Add to `agent/prompts/system_prompt.py`:

- A "GeoIP Columns" rule: *"When your SELECT outputs `source_ip_address` (or any
  IP-derived value), also select `geo_country_code`, `geo_city`, and `geo_org`.
  When you GROUP BY `source_ip_address`, include the geo columns in the GROUP BY
  (they are functionally dependent on the IP)."*
- One idiom example, e.g. logins per country:
  `SELECT geo_country_code, COUNT(*) FROM cloudtrail_events WHERE event_name = 'ConsoleLogin' GROUP BY 1`.

This covers aggregate shapes Layer 1 cannot fix (e.g. `COUNT(DISTINCT source_ip_address)`
rows contain no raw IP to join back on).

### Layer 3 — Dashboard (Superset) chart updates

~53 charts under `dashboard/assets/cloudtrail_default/charts/` reference
`source_ip_address`; 13 already use geo columns. For **table-type** charts that
list `source_ip_address` as a column, append `geo_country_code` and `geo_city`
to `params.all_columns` / `query_context`. Skip aggregation charts (they need a
per-chart redesign, out of scope).

Mandatory finishing steps (Superset never reads the YAML directly):

```bash
cd dashboard/assets && python3 rebuild_zip.py
cd ../../docker && docker compose run --rm superset-init
```

The dashboard asset-validation suite (`dashboard/tests/`) must stay green and the
test count must not decrease.

### Explicit non-goals

- No changes to `builtin_hunts.yaml` (Layer 1 enriches those results at runtime).
  Optionally, login-focused hunts may later add `geo_country_code` to their SQL for
  server-side ordering (e.g. "logins from unexpected countries"), as a follow-up.
- No ingester changes; no config_viz changes.
- No live GeoIP lookups — only the values already stored on `cloudtrail_events`.

---

## TDD Test List (write these first, one at a time)

`agent/tests/test_geo.py` (new; uses the `tmp_duckdb`-style temp-DB fixtures):

1. `find_ip_columns` detects `source_ip_address`.
2. `find_ip_columns` detects an aliased column (`ip`) whose values match the IP regex.
3. `find_ip_columns` ignores non-IP columns even with IP-ish names when values do not match.
4. `enrich_with_geo` appends geo columns directly after the IP column, values joined
   from `cloudtrail_events`.
5. `enrich_with_geo` is a no-op when the DataFrame already contains a `geo_*` column.
6. `enrich_with_geo` is a no-op on an empty DataFrame.
7. Unknown IPs produce NULL geo values; row count unchanged.
8. An IP occurring in many DB rows does not fan out result rows (GROUP BY dedup).
9. More than `MAX_LOOKUP_IPS` distinct IPs → only the first N are looked up, no error.
10. Two IP columns → second column's geo columns are name-prefixed.
11. All-NULL geo lookup (DB ingested without GeoIP) → enrichment columns are dropped.

`agent/tests/test_app.py` / handler tests:

12. `_handle_direct_sql` result in `query_history` contains geo columns when the
    toggle is ON (temp DB with geo data).
13. Toggle OFF → no geo columns added.
14. Enrichment raising an exception does not fail the handler (results still stored).

`agent/tests/test_prompts.py`:

15. `SYSTEM_PROMPT` mentions the geo-column rule (`geo_country_code` appears in the
    GeoIP guidance section).

`dashboard/tests/`:

16. Updated table charts include `geo_country_code`/`geo_city` in their column lists
    and the YAML→zip validation suite passes.

## Implementation Order

| Step | Deliverable | Est. size |
|------|-------------|-----------|
| 1 | `agent/geo.py` + tests 1–11 (pure functions, temp DuckDB) | ~150 LOC + tests |
| 2 | Handler integration + sidebar toggle + tests 12–14 | ~40 LOC |
| 3 | System prompt guidance + test 15 | ~15 LOC |
| 4 | Dashboard table-chart pass + rebuild zip + test 16 | YAML only |
| 5 | Docs: AGENTS.md (agent file map + test counts), CLAUDE.md pointer | — |

## Risks & Mitigations

- **Row fan-out on merge** — an IP with multiple geo rows (partial re-enrichment)
  duplicates result rows. Mitigated by `GROUP BY source_ip_address` in the lookup
  (test 8).
- **Lookup cost** — `WHERE source_ip_address IN (...)` is a full scan per query.
  Bounded by `MAX_LOOKUP_IPS` and executed once per user action; acceptable for a
  local analyst tool. If it becomes slow, cache lookups per session.
- **Column-name collisions** — a result already having a `geo_country_code` column
  is treated as "author opted in" and skipped entirely (test 5).
- **`_ct_filtered` date-filter CTE** — the enrichment lookup queries
  `cloudtrail_events` directly (not the filtered CTE) on purpose: geo attributes of
  an IP are date-independent.
