# PLAN: Multiple Suzaku databases in one directory

**Status:** Implemented (2026-07-30)
**Date:** 2026-07-29
**Goal:** When an analyst has more than one `*.duckdb` in the mounted database directory,
Senrigan must (a) pick the same file everywhere, (b) pick it for a stated reason, (c) say
which one it picked and which it ignored, and (d) refuse a file the dashboards cannot
actually query — instead of failing at chart render time.

Scope is discovery, selection, and reporting. It does **not** change the Suzaku schema
(see [PLAN_SUZAKU_SCHEMA.md](PLAN_SUZAKU_SCHEMA.md)) or any chart definition beyond
adding a provenance header.

---

## 1. Current state

Two independent implementations scan the same directory:

| | Superset | agent |
|---|---|---|
| Entry point | `dashboard/init/register_suzaku_dbs.py:192` `discover_databases()` | `agent/suzaku_db.py:263` `discover()` |
| Result | **one** file per command, chosen by mtime | **all** files, user picks in a selectbox (`agent/app.py:459`) |
| Payload tables verified | yes (`register_suzaku_dbs.py:131`) | no (`suzaku_db.py:219`) |
| Ignored candidates | dropped by `setdefault` (`:217`), never logged | listed with row counts and hints |
| Refresh | only when `superset-init` re-runs | 30 s cache (`app.py:432`) |

### 1.1 Findings

Reproduced on 2026-07-29 against the checked-in fixtures and a synthetic three-file
directory (Appendix A).

| # | Severity | Finding | Evidence |
|---|----------|---------|----------|
| F-1 | **High** | **A schema-incompatible file can win selection and break a whole dashboard.** The `suzaku_metrics` dataset is virtual SQL selecting `SrcASN`/`SrcCity`/`SrcCountry`, which Suzaku writes only for a `--geo-ip` run. Detection checks the command and the `metrics` table, never the columns, so a non-geo run registers cleanly and every chart then fails with a Binder Error. This is not hypothetical: `sample/suzaku/sample-metrics.duckdb` (a local full run, git-ignored) has **no geo columns**, while `docker/data/db/sample-metrics.duckdb` — another run of the same command — has them. Put both in one directory and the outcome depends on mtime. The *tracked* fixtures under `sample/suzaku/fixtures/` are all geo-enabled, so no fixture regeneration was needed. | `dashboard/assets/suzaku_metrics/datasets/suzaku_metrics.yaml:39-41`; `register_suzaku_dbs.py:101-133`; Appendix A.3 |
| F-2 | **High** | **Which *file* is on screen is unknowable from any dashboard.** The timeline bundle already charts the `suzaku_meta` row (`charts/run_info.yaml`, SZK-55) — command line, versions, scan counts — but not the file path, which is the one thing that distinguishes two runs of the same command. The summary and metrics bundles surface no provenance at all. | `dashboard/assets/suzaku_timeline/charts/run_info.yaml`; `suzaku_{summary,metrics}/datasets/`; Appendix A.4 |
| F-3 | **High** | **Selection is non-deterministic on tied mtimes.** `sorted(glob.glob(...), key=os.path.getmtime)` leaves ties in `os.scandir` order. Three files with identical mtimes selected `runA` on one filesystem ordering and would select another elsewhere. | `register_suzaku_dbs.py:209-213`; `suzaku_db.py:281-283`; Appendix A.1 |
| F-4 | **Medium** | **mtime is the wrong key even when it is unique.** It records when the file was *copied*, not when Suzaku *ran* — `cp` rewrites it, `rsync -a` / `docker cp` preserve it. `suzaku_meta.generated_at` (TIMESTAMPTZ) is the real answer and is already in every file. | `suzaku_meta` schema, Appendix A.4 |
| F-5 | **Medium** | **Ignored candidates are silently dropped.** `found.setdefault(command, ...)` discards every runner-up with no log line, no `--list` entry, and nothing in `make status`. An analyst who copies in a new run and sees stale numbers has no way to find out why. | `register_suzaku_dbs.py:217` |
| F-6 | **Medium** | **Detection genuinely diverges between the two implementations.** A file whose `suzaku_meta.command` says `aws-ct-timeline` but which has no `timeline` table is rejected by Superset and offered as a valid "0 rows" choice by the agent. `tests/test_suzaku_detection_parity.py` compares **constants only**, so it cannot catch a logic divergence. | Appendix A.1; `tests/test_suzaku_detection_parity.py:47-88` |
| F-7 | **Medium** | **No way to re-resolve Suzaku paths without a full bootstrap.** `make resync` runs `register_dataset.py`, which handles `cloudtrail_events` only. Adding, replacing, or deleting a Suzaku file has no documented refresh path. | `Makefile:185`; `docker-compose.yml` `superset-resync` mounts only `register_dataset.py` |
| F-8 | **Medium** | **A deleted file leaves a live, broken connection.** `register_suzaku_dbs.main()` only ever creates or repoints; it never notices that a registered database's path is gone. Every chart on it then raises IOError with no explanation. | `register_suzaku_dbs.py:292-327` |
| F-9 | **Low** | **Every file is opened three times at bootstrap.** `main()` → `--list` → `main()`, each doing a full `discover_databases()`. With several 200 MB timelines this is the dominant cost of `superset-init`. | `bootstrap.sh:30,53,78` |
| F-10 | **Low** | **`*.db`-named Suzaku output is invisible.** Only `*.duckdb` is globbed. A file named `run1.db` is never scanned and never reported, even though the `cloudtrail_events` guard already exists to keep Senrigan's own database out. | `register_suzaku_dbs.py:210`; `suzaku_db.py:282` |
| F-11 | **Low** | **Unreadable files are explained in one UI only.** The agent renders `_wal_hint`/`_error_hint` guidance; Superset prints `Skipping <path>: <exc>` into a bootstrap log nobody reads, and the dashboard simply does not exist. | `suzaku_db.py:126-156` vs `register_suzaku_dbs.py:153` |
| F-12 | **Low** | **Documentation understates the behaviour.** `dashboard/README.md:229` says only "the newest wins" — not that "newest" means mtime, not that runners-up are discarded silently, not that a running Superset ignores files added afterwards. | `dashboard/README.md:229-232` |

**Root cause:** discovery was designed for the one-file case and generalized to N files by
adding `setdefault`. Selection therefore has no stated policy, no fitness criterion, and no
output — and because the logic exists twice, the two UIs drifted apart.

---

## 2. Design decisions

**D-1 — One file per command stays the contract.**
Registering N connections would mean N UUIDs, and dataset/chart YAMLs reference database
UUIDs; making that variable is a redesign of every bundle. Multi-generation comparison is
deferred (§8) — the fix here is to make the single choice *correct, stated, and visible*.

**D-2 — One detection implementation, mounted into both images.**
`agent/suzaku_db.py` is already pure Python with no Streamlit import (its own docstring
says so), and the Superset image already ships `duckdb`. `docker-compose.yml` already
bind-mounts five individual files into `superset-init`; a sixth costs nothing.
`register_suzaku_dbs.py` becomes a thin Superset adapter, and the constants stop existing
twice. This retires the parity test in favour of "there is nothing to keep in parity".

**D-3 — Selection key: `(generated_at desc, mtime desc, path asc)`.**
`generated_at` is what the analyst means by "the newer run"; mtime is the fallback for a
file that somehow lacks it; the path makes ties deterministic. Never filesystem order.

**D-4 — Fitness, not just identity.**
A file is eligible only if it can serve its bundle: correct command, payload tables
present, **and every column the dataset SQL selects**. An unfit file is rejected with a
printed reason and the next candidate is considered — so a geo-less metrics run no longer
takes down the Metrics dashboard when a geo-enabled one is sitting next to it.

**D-5 — No new `make` verb.**
`tests/test_makefile_suzaku.py:49` encodes a deliberate principle: copying a file is the
whole workflow. Suzaku re-resolution therefore extends the existing `make resync`, which
is already documented as "fix the dashboard after the data changed".

---

## 3. Target behaviour

```
$ make status
  Database  docker/data/db/threat_hunting.db  (4.2G)
  GeoIP     enabled from docker/data/geoip/
  Suzaku    4 file(s) in docker/data/db/:
              aws-ct-timeline   sample-timeline.duckdb      generated 2026-07-28 07:32  1,206,049 rows
                                ↳ ignored: old-timeline.duckdb (generated 2026-07-20 11:03)
              aws-ct-summary    sample-summary.duckdb       generated 2026-07-28 07:33      8,214 rows
              aws-ct-metrics    — no usable file
                                ↳ rejected: nogeo-metrics.duckdb (missing columns SrcASN, SrcCity, SrcCountry — re-run Suzaku with --geo-ip)
```

Every Suzaku dashboard gains a provenance header row reading the file it is actually
connected to — `duckdb_databases()` exposes the real path, so the header cannot lie:

```sql
SELECT m.command, m.generated_at, m.suzaku_version, m.scanned_events, m.output_rows,
       d.path AS source_file
FROM suzaku_meta m
CROSS JOIN (SELECT path FROM duckdb_databases() WHERE database_name = current_database()) d
```

The agent's selectbox keeps letting an analyst inspect any file, but marks the one Superset
is serving, so the two UIs are never silently out of step.

---

## 4. Implementation phases

TDD throughout: every phase lists its tests first, each is written failing before the code.

### Phase 0 — One inventory, one scan (F-3, F-4, F-6, F-9, F-10)

Extend `agent/suzaku_db.py` into the single source of truth.

- `DbInfo` gains `generated_at: datetime | None`, `suzaku_version: str`,
  `output_rows: int | None`, `scanned_events: int | None`, `missing_columns: tuple[str, ...]`,
  `ignored_reason: str` (frozen dataclass, all defaulted — existing constructors keep working).
- `_read_meta()` selects the full provenance row, tolerating older files by column probe.
- `discover()` opens each candidate **once**, globs `*.duckdb` **and** `*.db` minus the
  resolved `DUCKDB_PATH`, and sorts by D-3.
- New `select(directory) -> dict[SuzakuKind, Selection]` returning the chosen `DbInfo` plus
  the rejected ones with reasons. This is what both consumers call.
- New `inventory_to_json()` / `inventory_from_json()` so a scan can cross a process boundary.

**Test list** (`agent/tests/test_suzaku_db.py`):
1. `generated_at` is read from `suzaku_meta` and exposed on `DbInfo`.
2. A file without `generated_at` (older layout) yields `None`, not an exception.
3. Two files of one kind: the later `generated_at` wins even when its mtime is older.
4. Equal `generated_at`: the later mtime wins.
5. Equal `generated_at` and mtime: the lexicographically first path wins — asserted over a
   shuffled directory listing, so filesystem order cannot satisfy it.
6. A `.db`-named Suzaku file is discovered.
7. A `.db` file containing `cloudtrail_events` is not, and is not opened twice.
8. `discover()` opens each file exactly once (counted through a `duckdb.connect` spy).
9. `select()` reports rejected candidates with a reason string.
10. JSON round-trip preserves kind, path, `generated_at`, and rejection reasons.

### Phase 1 — Fitness gate (F-1)

- `REQUIRED_COLUMNS: dict[SuzakuKind, dict[str, tuple[str, ...]]]` — per kind, per payload
  table, the columns the shipped dataset SQL selects.
- `inspect_db()` records `missing_columns`; `select()` skips a file with any, with the
  reason `missing columns X, Y — re-run Suzaku with --geo-ip` for the geo case.
- The agent selectbox shows unfit files greyed out with the same reason rather than
  offering them as valid choices.

**Test list:**
1. A metrics file without `SrcASN`/`SrcCity`/`SrcCountry` is rejected with the geo hint.
   Fixture: `sample/suzaku/sample-metrics.duckdb`, which really is such a file.
2. A geo-enabled metrics file is selected even when the geo-less one is newer.
3. A timeline file missing `RuleID` is rejected.
4. All bundles: the dataset YAML's `sql:` executes against a **reduced** fixture holding
   only the columns `REQUIRED_COLUMNS` promises (built with the fixture's own types, so
   `unnest` / `date_diff` / `FILTER (WHERE …)` still bind). A dataset that starts selecting
   an unlisted column fails to bind — this is what stops the contract from drifting from
   the assets, without parsing SQL. (Running the SQL against the *whole* fixture was
   already covered by `test_every_virtual_dataset_runs_against_the_fixture`.)
5. Every column named in a bundle's dataset SQL appears in `REQUIRED_COLUMNS` for that kind.
6. A rejected file leaves `select()` returning the next fit candidate, not `None`.

> **Resolved during implementation:** the tracked fixtures in `sample/suzaku/fixtures/`
> already come from `--geo-ip` runs, so no regeneration was needed. The geo-less
> `sample/suzaku/sample-metrics.duckdb` is a git-ignored local run, and it correctly
> becomes an *unfit* file — which is the behaviour this phase adds, verified against it
> directly (Appendix A.3).

### Phase 2 — Superset consumes the shared module (F-6, F-9)

- `docker-compose.yml`: mount `../agent/suzaku_db.py:/app/suzaku_db.py:ro` into
  `superset-init` (and `superset-resync`, see Phase 4).
- `register_suzaku_dbs.py` deletes `SENRIGAN_TABLE`, `META_TABLE`,
  `SUPPORTED_SCHEMA_VERSION`, `SUZAKU_TABLES`, `detect_command`, `detect_command_in`,
  `discover_databases` and imports from `suzaku_db`. It keeps only the Superset-specific
  parts: `DATABASE_NAMES`, `DATABASE_UUIDS`, `BUNDLE_COMMANDS`, `build_uri`, `build_extra`,
  `main`.
- New CLI: `--scan <file>` writes the inventory JSON; `--from <file>` makes `main()` and
  `--list` read it. `bootstrap.sh` scans once and passes the JSON to all three steps.
- `tests/test_suzaku_detection_parity.py` is replaced by
  `tests/test_suzaku_detection_shared.py`: the module is mounted by compose, and
  `register_suzaku_dbs` defines no detection constant of its own.

**Test list:**
1. `register_suzaku_dbs` re-exports nothing it used to duplicate (attribute absence).
2. `docker-compose.yml` mounts `suzaku_db.py` into `superset-init` read-only.
3. `--scan` writes JSON that `--from` reads back into the same selection.
4. `bootstrap.sh` calls `--scan` exactly once and never calls a bare `main()` (text assert).
5. `--list` with `--from` performs no `duckdb.connect` (spy).
6. `dashboard/tests/` can import `register_suzaku_dbs` with the agent dir on `sys.path`.

### Phase 3 — Say what was chosen (F-2 partly, F-5, F-11)

- `register_suzaku_dbs.py --report`: human-readable §3 block, one section per command,
  including rejected and unreadable files with their hints.
- `bootstrap.sh` prints the report after registration, so the reason a dashboard is missing
  is in the same log as the missing dashboard.
- `make status` prints the report when `senrigan-dashboard:latest` exists
  (`docker image inspect` guard), and falls back to today's filename list otherwise — cold
  `make status` must stay fast and image-free.
- `make up`'s "Suzaku output detected" line names the selected file per command.

**Test list** (`tests/test_makefile_suzaku.py`, `dashboard/tests/test_init_scripts.py`):
1. `--report` names the selected file, its `generated_at`, and its row count.
2. `--report` lists ignored candidates under the command they lost.
3. `--report` lists unreadable files with the shared `_wal_hint`/`_error_hint` text.
4. `--report` exits 0 with no Suzaku file present and says so.
5. `make status` still declares no target beginning with `suzaku` (D-5 guard kept).
6. `make status` degrades to the wildcard listing when the image is absent.

### Phase 4 — Lifecycle (F-7, F-8)

- `superset-resync` mounts `register_suzaku_dbs.py` + `suzaku_db.py` and runs a small
  `init/resync.sh` that calls `register_dataset.py` then `register_suzaku_dbs.py`.
  `make resync` therefore fixes both CloudTrail metadata and Suzaku paths. No new verb.
- `main()` gains stale-connection handling: a registered Suzaku database whose file no
  longer exists is reported and, when no replacement is found, has `expose_in_sqllab`
  cleared so it stops being offered — the row is kept, because the UUID must survive for a
  later re-import.
- `make reset` keeps its "never delete a `.duckdb`" guarantee unchanged.

**Test list:**
1. `resync.sh` runs both registration scripts in order.
2. `docker-compose.yml`'s `superset-resync` mounts both scripts.
3. `make resync` recipe references the resync entrypoint, not `register_dataset.py` alone.
4. A registered database whose path vanished is reported as stale.
5. A stale database that has a fit replacement is repointed rather than disabled.
6. `make reset` still deletes no `*.duckdb` (existing test, unchanged).

### Phase 5 — Provenance header in the dashboards (F-2)

- The timeline bundle already has a `suzaku_meta` dataset and a **Suzaku Run Info** chart:
  add `source_file` to both rather than duplicating them.
- Summary and metrics get the same pair, with new fixed UUIDs.
- Placement rule: **the last row of the last tab**, which is where the timeline card already
  sits — so all three dashboards agree and the timeline layout does not churn. The card is
  excluded from each dashboard's Date Range filter, because `generated_at` is when Suzaku
  ran, not when anything was detected.
- `dashboard.yaml` position JSON updated in summary and metrics, `FILE_MAP` updated in their
  rebuild scripts; rebuild all three ZIPs with `rebuild_suzaku_<name>_zip.py` and re-import
  (`docker compose run --rm superset-init`).

**Test list** (`dashboard/tests/`):
1. Each bundle has exactly one dataset whose SQL reads `suzaku_meta`.
2. The header SQL executes against each fixture and returns exactly one row.
3. The returned `source_file` equals the connected file's path (fixture-level assertion).
4. The provenance chart appears in each `dashboard.yaml` position tree.
5. New dataset/chart UUIDs are unique across all five bundles.
6. `test_rebuild_suzaku_zips.py` still passes — i.e. the ZIPs were rebuilt.

### Phase 6 — Agent/Superset agreement (F-6)

- The agent sidebar marks the file Superset serves — `select()` is now shared, so the agent
  computes it directly rather than guessing.
- Selecting a different file shows an inline caption: "the dashboard is showing X".

**Test list** (`agent/tests/test_app.py`, `test_suzaku_timeline_view.py`):
1. The selectbox default is the file `select()` chose, not merely the newest by mtime.
2. Choosing a non-selected file renders the divergence caption.
3. Unfit files are rendered disabled with their rejection reason.
4. A `SUZAKU_*_DB` override is reflected in the badge in both directions.

### Phase 7 — Documentation (F-12)

- `dashboard/README.md`: replace "the newest wins" with the D-3 rule, the fitness gate, the
  ignored-candidate report, and the fact that a running Superset only re-resolves on
  `make resync` / `make up`.
- `CLAUDE.md` + `AGENTS.md`: Suzaku paragraph and the test-count line.
- `doc/PLAN_SUZAKU_VIEWS.md` §5.1 cross-reference to this plan.
- `README.md` / `website/docs`: the copy-a-file workflow gains "put one run per command in
  the directory; `make status` shows which one is live".

**Test list** (`tests/test_docs.py`): the documented selection rule mentions `generated_at`;
the plan is linked from `CLAUDE.md`; the test-count line matches the suites.

---

## 5. File change map

| File | Phase | Change |
|---|---|---|
| `agent/suzaku_db.py` | 0,1 | `DbInfo` fields, single-open `discover()`, `select()`, `REQUIRED_COLUMNS`, JSON I/O |
| `agent/app.py` | 6 | selector marks the Superset choice, disables unfit files |
| `dashboard/init/register_suzaku_dbs.py` | 2,3,4 | drop duplicated detection, add `--scan`/`--from`/`--report`, stale handling |
| `dashboard/init/bootstrap.sh` | 2,3 | one scan, report printed |
| `dashboard/init/resync.sh` | 4 | new — dataset + Suzaku registration |
| `docker/docker-compose.yml` | 2,4 | mount `suzaku_db.py`; resync entrypoint and mounts |
| `Makefile` | 3 | `status` report with image guard, `up` names selected files |
| `dashboard/assets/suzaku_*/datasets/*_meta.yaml` | 5 | new provenance datasets |
| `dashboard/assets/suzaku_*/charts/provenance_header.yaml` | 5 | new charts |
| `dashboard/assets/suzaku_*/dashboard.yaml` | 5 | header row in position JSON |
| `dashboard/assets/*.zip` | 5 | rebuilt |
| `sample/generate_fixtures.py`, `sample/suzaku/sample-metrics.duckdb` | 1 | regenerate with `--geo-ip` |
| `tests/test_suzaku_detection_parity.py` → `test_suzaku_detection_shared.py` | 2 | replaced |

---

## 6. Test-count impact

| Suite | Before | After | Delta |
|---|---|---|---|
| agent (pytest) | 730 | **761** | +31 (Phases 0, 1, 6, and the `pytz` regression) |
| dashboard | 757 | **793** | +35 (Phases 1, 2, 3, 4, 5; net of the retired `test_suzaku_signatures.py`) |
| root `tests/` | 115 | **134** | +19 (Phases 2, 3, 4; net of the retired parity test) |
| ingester / config_viz | unchanged | unchanged | — |

`CLAUDE.md` and `AGENTS.md` carry these counts and must be updated in the same PR.

---

## 7. Sequencing and risk

Phases 0→1→2 are one dependency chain and should land as one PR per phase, in order.
3–7 are independent of each other once 2 is in.

| Risk | Mitigation |
|---|---|
| **Environment-dependent tests.** The Phase 3 Makefile tests read `SUZAKU_DBS`, a wildcard over the developer's own `docker/data/db`, so they passed on a machine holding Suzaku files and failed on a clean checkout. Likewise `select()` honours `SUZAKU_*_DB`, which a developer may have exported. | The Makefile tests now override `SUZAKU_DBS` on the make command line (which wins over `:=`) and pin **both** branches; autouse fixtures in `agent/tests/conftest.py` and `dashboard/tests/conftest.py` clear the `SUZAKU_*_DB` overrides. Both suites verified green with an empty database directory and with a hostile `SUZAKU_TIMELINE_DB` set |
| **Found in the running containers, not in CI:** reading `suzaku_meta.generated_at` (TIMESTAMPTZ) through the DuckDB Python client needs `pytz`, which the agent image does not ship. The whole meta projection raised, `except duckdb.Error` swallowed it, and all three healthy files reported "No suzaku_meta table". The host has `pytz`, so every test passed. | `_read_meta` now reads in two stages — `schema_version`/`command` alone decide usability, everything else is best-effort — and casts `generated_at` to VARCHAR in SQL so no timezone-aware value crosses into Python. Six regression tests drive both, using a fake connection that fails exactly the way the client did. The Superset image ships `pytz`, so the dashboards were never affected |
| Mounting `suzaku_db.py` into the Superset image couples two modules that ship separately | The module already declares no Streamlit dependency; Phase 2 test 6 keeps it importable standalone, and CI runs `dashboard/tests` without the agent installed |
| Phase 1 rejects a file that used to "work" | It only rejects files whose dataset SQL cannot execute — those never worked, they failed at render. The reason is printed, and Phase 3 surfaces it in `make status` |
| Phase 5 changes committed ZIPs | `test_rebuild_suzaku_zips.py` already fails on a stale ZIP; the rebuild+re-import steps are in `CLAUDE.md` |
| `duckdb_databases()` behaviour differs across DuckDB versions | Verified on 1.5.2 (Appendix A.4); Phase 5 test 3 pins it, and a NULL path degrades the header to blank rather than erroring |
| Regenerating the metrics fixture changes its size | Fixtures are trimmed by `generate_fixtures.py`; keep the same row cap |

---

## 8. Out of scope

**Viewing several runs of one command at once.** The path would be DuckDB `ATTACH` of every
fit file into one connection and a `UNION ALL BY NAME` virtual dataset carrying a
`source_file` column — one connection, one UUID, N files, and dashboard-level filtering by
run. It is the only approach that survives the fixed-UUID asset design, and it is a
separate plan: it changes every Suzaku dataset's SQL and adds a filter to every chart.
This plan deliberately makes the single-file choice trustworthy first.

---

## Appendix A: Reproduction

### A.1 — Tied mtimes and detection divergence

```python
# Three files, identical mtimes; "bad" declares aws-ct-timeline with no timeline table.
import register_suzaku_dbs as R, suzaku_db as A
R.discover_databases(d)   # {'aws-ct-timeline': '.../runA-timeline.duckdb'}  ← one, silent
[(i.path.name, i.kind) for i in A.discover(d)]
# runA → TIMELINE, runB → TIMELINE, bad → TIMELINE (rows={})   ← agent offers the broken one
```

### A.2 — The runner-up is invisible

`register_suzaku_dbs.discover_databases()` returns a `dict`; `--list` prints only its keys.
No code path ever names `runB-timeline.duckdb`.

### A.3 — The geo-less metrics file

```bash
python3 -c "import duckdb; print([r[0] for r in duckdb.connect(
  'sample/suzaku/sample-metrics.duckdb', read_only=True).execute(
  \"select column_name from information_schema.columns where table_name='metrics'\").fetchall()])"
# ['Field','TimelineColumn','Value','Count','FieldTotal','Percent','FirstSeen','LastSeen']
#   → no SrcASN/SrcCity/SrcCountry; the suzaku_metrics dataset SQL cannot bind against it,
#     yet detect_command() accepts it.
# docker/data/db/sample-metrics.duckdb, a different run of the same command, does have them.
```

### A.4 — What `suzaku_meta` already knows, and the path lookup

```bash
python3 -c "import duckdb; c=duckdb.connect('sample/suzaku/sample-timeline.duckdb', read_only=True); \
print(c.execute('select * from suzaku_meta').df().to_string()); \
print(c.execute(\"select path from duckdb_databases() where database_name=current_database()\").fetchall())"
# schema_version 1 | suzaku_version 2.0.0 | command aws-ct-timeline |
# generated_at 2026-07-28 07:32:13.922831+09:00 | scanned_files 3980 |
# scanned_events 1972588 | output_rows 1206049 | duplicate_rows_removed 719101
# [('/…/sample/suzaku/sample-timeline.duckdb',)]      ← the header chart can name its own file
```
