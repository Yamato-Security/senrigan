# PLAN: Documentation refresh — bring every doc back in step with the implementation

**Status:** Phases 1–4 and 6 implemented (2026-08-01). Phase 0 and Phase 5 outstanding.
**Date:** 2026-08-01
**Goal:** Every number, path, and structural claim in the documentation is either verified
against the implementation or enforced by a test, so the next reader — human or agent —
can trust what it says without re-deriving it.

---

## 1. Current state

The repository carries four layers of documentation, each with a different audience and a
different decay rate:

| Layer | Files | Audience | Decay observed |
|-------|-------|----------|----------------|
| Agent context | `AGENTS.md`, `CLAUDE.md`, `agent/AGENTS.md`, `ingester/AGENTS.md` | Coding agents | Structural (file tree, dead links) |
| Internal design | `doc/*.md` (ARCHITECTURE, DEVELOPMENT, TESTING, TDD_GUIDE, PRD*, PLAN*) | Contributors | Architectural (pre-Suzaku, pre-Makefile) |
| Module reference | `ingester/README.md`, `agent/README.md`, `dashboard/README.md`, `config_viz/README.md` | Contributors | Numeric (chart counts) |
| Public site | `website/docs/**` (15 locales), `README.md`, `OLD-README.md` | Users | Numeric + coverage gaps |

Test counts and CloudTrail hunt/chart counts were verified and are **accurate today**
(see §2.1). The drift is concentrated in the material added by the last ~15 commits:
Suzaku multi-DB support, the Suzaku Run Info provenance card, `agent/views/`, `sample/`,
and the Makefile UX rework.

### 1.1 Findings

| # | Severity | Finding | Evidence |
|---|----------|---------|----------|
| F-1 | **High** | **Seven `doc/PLAN_*.md` files are untracked.** `CLAUDE.md` and `AGENTS.md` are committed and link to all seven. A fresh clone therefore has seven broken links in its primary agent-context file, and no agent can read the Suzaku multi-DB / schema / views design it is told to follow. | `git status --short` lists `?? doc/PLAN_{GEO_ENRICHMENT,MAKEFILE_UX,SUZAKU_MULTI_DB,SUZAKU_SCHEMA,SUZAKU_TIMELINE_DASHBOARD,SUZAKU_VIEWS,THREAT_CATALOG}.md`; `git ls-files doc/` returns only 8 tracked docs |
| F-2 | **High** | **Suzaku chart counts are one short everywhere.** Commit `c2d0422` added a `Suzaku Run Info` provenance card to each Suzaku dashboard; no count was updated. Summary is 19 charts (documented 18), Metrics is 15 (documented 14). | `ls dashboard/assets/suzaku_summary/charts \| wc -l` → 19, `suzaku_metrics` → 15; `dashboard/README.md:340-341`; `website/docs/reference/suzaku.md:46-47` |
| F-3 | **High** | **Suzaku Timeline hunt count is wrong on the public site.** `suzaku_timeline_hunts.yaml` ships 16 hunts; the site says 15. | `agent/suzaku_timeline_hunts.yaml` → 16 entries; `website/docs/reference/suzaku.md:45` |
| F-4 | **High** | **`AGENTS.md` file structure omits most of what the last month added** and points at a file that does not exist. Missing: `agent/profiles.py`, `agent/suzaku_db.py`, `agent/geo.py`, `agent/views/`, `agent/suzaku_timeline_hunts.yaml`, `sample/`, `website/`, root `tests/`, `Makefile`, `doc/PLAN_SUZAKU_MULTI_DB.md`. Dead reference: `config_viz/PLAN.md`. | `AGENTS.md:366-442`; `ls agent/` and `ls config_viz/` |
| F-5 | **Medium** | **`doc/ARCHITECTURE.md` still describes a four-container, single-database system.** Reality is 5 compose services (+ `ingest` / `resync` profiles) and N read-only Suzaku `.duckdb` files alongside the main DB. The ASCII overview shows neither. | `doc/ARCHITECTURE.md:10` "four independent containers", diagram at `:13-35`; `docker/docker-compose.yml` defines `ingester`, `agent`, `config-viz`, `superset`, `superset-init`, `superset-resync` |
| F-6 | **Medium** | **`doc/DEVELOPMENT.md` predates both the Makefile UX rework and Suzaku.** It documents no `make` target, describes CI as "Expected" while `.github/workflows/ci.yml` exists, omits the `dashboard` and root `tests/` suites from its stage table, and its "Useful Commands" contradict the bind-mount architecture (`docker volume inspect threat-hunting-duckdb`) and use pre-move paths (`data/db/…` instead of `docker/data/db/…`). | `doc/DEVELOPMENT.md:318-358`; `grep -c suzaku doc/DEVELOPMENT.md` → 0; `Makefile` defines 33 targets |
| F-7 | **Medium** | **`website/docs/reference/suzaku.md` exists in English only.** The other 5 site pages ship all 15 locales; this one relies on i18n fallback, so 14 locales silently serve English for the newest feature. | `ls website/docs/reference/` → `index.<15 locales>.md` + a bare `suzaku.md`; `mkdocs.yml:184` puts it in the nav |
| F-8 | **Medium** | **The Getting Started page never mentions Suzaku.** A user has no path from the quick start to the three Suzaku dashboards or the agent's Suzaku Timeline page; the `--geo-ip` requirement for `aws-ct-metrics` is only stated in the reference. Affects all 15 locales. | `grep -ci suzaku website/docs/getting-started/index.md` → 0 |
| F-9 | **Low** | **`CLAUDE.md` says `make` prints "the five commands below" and then lists seven.** `make status` and `make resync` are real targets but do not appear in the default help, so the sentence is false in both directions. | `CLAUDE.md:167-177`; `make` prints ingest/up/down/logs/reset only |
| F-10 | **Low** | **`CLAUDE.md` repository map puts `generate_fixtures.py` at `sample/`.** The actual path is `sample/suzaku/generate_fixtures.py`. | `CLAUDE.md` repository map; `find sample` |
| F-11 | **Low** | **`agent/AGENTS.md` per-file test counts have drifted.** `test_llm.py` is listed as 49 tests; it collects 51. Other entries (`test_config.py` 10, `test_geo.py` 11) are correct. | `agent/AGENTS.md:114`; `pytest --collect-only -q` per file |
| F-12 | **Low** | **`AGENTS.md` labels `PRD_SUZAKU_SUMMARY.md` as "removed impl; redesign pending"** although the Suzaku Identity Summary dashboard now ships with 19 charts. | `AGENTS.md:430`; `dashboard/assets/suzaku_summary/` |
| F-13 | **Low** | **The ingester test count needs re-verification.** Docs claim ≈185; a static count of `#[test]`/`#[tokio::test]` attributes gives 187. `cargo test` was not run in this session (cold build). | `AGENTS.md:167`, `CLAUDE.md:180`; `grep -rc '#\[test\]' ingester/src ingester/tests` → 187 |
| F-14 | **Low** | **`OLD-README.md` is linked from `README.md` as a supported entry point but carries no staleness banner or date.** It predates Suzaku, the Makefile rework, and the docs site. | `README.md:60-64`; `head OLD-README.md` |
| F-15 | **Low** | **`config_viz/write_query.py` is a 0-byte file from the first commit**, undocumented, and its name contradicts the module's READ_ONLY contract. Either delete it or document why it exists. | `wc -c config_viz/write_query.py` → 0; `git log -1 -- config_viz/write_query.py` → `918a7d3 first commit` |

**Root cause:** counts and structure are asserted in prose in 4+ places per fact, and only
one class of fact (the localized Getting Started command list) has a test guarding it
(`tests/test_docs.py`). Everything else decays at the speed of the next feature commit.

---

## 2. Verified baseline

Everything in this section was measured in this session. Use it as the source of truth
when editing; do not re-derive.

### 2.1 Facts that are already correct in the docs

| Fact | Measured | Where documented |
|------|----------|------------------|
| agent tests | 761 | `AGENTS.md:167`, `CLAUDE.md:180` |
| config_viz backend tests | 67 | same |
| config_viz frontend tests | 114 | same, `doc/TESTING.md:461` |
| dashboard tests | 793 | same |
| root `tests/` | 134 | same |
| built-in CloudTrail hunts | 126 | `website/docs/reference/index*.md` (all 15 locales) |
| CloudTrail dashboard charts | 101 | same, `dashboard/tests/test_rare_zip.py:55` |
| Suzaku Timeline dashboard charts | 46 | `AGENTS.md:438`, `dashboard/README.md:339` |
| `cloudtrail_events` columns | 48 (17+7+24) | `CLAUDE.md:190`, `AGENTS.md:176`, `doc/ARCHITECTURE.md:183`, `ingester/README.md:308` |

### 2.2 Facts that must be corrected

| Fact | Documented | Actual |
|------|-----------|--------|
| Suzaku Summary charts | 18 | **19** |
| Suzaku Metrics charts | 14 | **15** |
| Suzaku Timeline hunts | 15 | **16** |
| `agent/tests/test_llm.py` | 49 | **51** |
| Compose containers | "four" | **5 services + 2 profile-only runners** |
| ingester tests | ≈185 | **verify — static count is 187** |

---

## 3. Plan

Six phases, ordered by reader impact. Each is independently shippable; **Phase 0 should
land on its own, immediately.**

### Phase 0 — Commit the untracked design docs *(fixes F-1)*

The only change that repairs a broken state rather than an inaccurate one.

1. Confirm each of the seven files is intended to be public (they are already linked from
   committed files, so the intent is on record).
2. `git add doc/PLAN_*.md` and commit as `docs: track the seven PLAN documents referenced
   from AGENTS.md`.
3. Add `doc/PLAN_SUZAKU_MULTI_DB.md` and this file to the `doc/` listing in `AGENTS.md`
   and to the `doc/` line of the repository map in `CLAUDE.md`.

**Done when:** `git ls-files doc/*.md` lists every file that `AGENTS.md` links to.

### Phase 1 — Guardrail tests first *(TDD; enables Phases 2–5)*

Per the project's non-negotiable TDD rule, the corrections in Phases 2–5 are driven by
tests written here. Extend the existing `tests/test_docs.py` pattern — it already proves
this approach works for the localized quick start.

Test list (each starts Red against today's docs):

1. `test_suzaku_chart_counts_match_the_assets` — parse the chart counts out of
   `dashboard/README.md` and `website/docs/reference/suzaku.md`, compare against
   `len(list(Path("dashboard/assets/<bundle>/charts").glob("*.yaml")))` for all three
   bundles. *(Red on F-2.)*
2. `test_suzaku_timeline_hunt_count_matches_the_yaml` — compare the site's number against
   `len(yaml.safe_load(open("agent/suzaku_timeline_hunts.yaml")))`. *(Red on F-3.)*
3. `test_builtin_hunt_count_matches_the_yaml` — same for `builtin_hunts.yaml` (126) across
   all 15 `reference/index*.md`. *(Green today — locks in §2.1.)*
4. `test_cloudtrail_chart_count_matches_the_assets` — same for 101. *(Green today.)*
5. `test_agents_file_tree_paths_exist` — every path-looking line in the `AGENTS.md`
   structure block resolves on disk. *(Red on F-4's `config_viz/PLAN.md`.)*
6. `test_documented_link_targets_exist` — every relative Markdown link in `CLAUDE.md`,
   `AGENTS.md`, and `doc/*.md` resolves. *(Guards F-1 from recurring.)*
7. `test_every_site_page_has_all_15_locales` — generalize the existing locale test from
   `getting-started/` to every directory under `website/docs/`. *(Red on F-7.)*
8. `test_core_command_list_length_matches_make` — the "five commands" claim in `CLAUDE.md`
   equals what `make` actually prints. *(Red on F-9.)*

These live in root `tests/` (Makefile / compose / docs consistency suite) and raise its
count from 134. Update the count line in `CLAUDE.md` and `AGENTS.md` in the same PR.

**Done when:** all eight tests exist, and 1/2/5/7/8 fail for the documented reasons.

### Phase 2 — Numeric corrections *(fixes F-2, F-3, F-11, F-13; turns Phase 1 green)*

1. `dashboard/README.md:340-341` → 19 / 15 charts.
2. `website/docs/reference/suzaku.md:45-47` → 16 hunts, 19 charts, 15 charts.
3. `agent/AGENTS.md:114` → 51 tests.
4. Run `cargo test` in `ingester/`, then set the real number in `CLAUDE.md:180` and
   `AGENTS.md:167`. If it is 187, correct both; if 185, note why the static count differs
   (e.g. `#[cfg]`-gated tests) so the next reader does not re-open this.
5. Re-check the Suzaku Run Info card is described — not just counted — in
   `dashboard/README.md` and `reference/suzaku.md`, since it is the user-visible answer to
   "which file is this dashboard reading?".

**Done when:** Phase 1 tests 1, 2 pass and `make test-repo` is green.

### Phase 3 — Structural corrections to agent context *(fixes F-4, F-9, F-10, F-12)*

1. Rebuild the `AGENTS.md` file-structure block from the actual tree. Add `agent/geo.py`,
   `agent/profiles.py`, `agent/suzaku_db.py`, `agent/views/suzaku_timeline.py`,
   `agent/suzaku_timeline_hunts.yaml`, `sample/suzaku/`, `website/`, root `tests/`,
   `Makefile`, `README.md` / `OLD-README.md`, and `doc/PLAN_SUZAKU_MULTI_DB.md`.
   Remove `config_viz/PLAN.md`.
2. Re-label `PRD_SUZAKU_SUMMARY.md` — the implementation shipped.
3. `CLAUDE.md`: fix the "five commands" sentence to name the five `make` actually prints,
   and present `status` / `resync` as the two recovery commands they are.
4. `CLAUDE.md`: correct the `sample/` line to `sample/suzaku/generate_fixtures.py`.

**Done when:** Phase 1 tests 5, 8 pass.

### Phase 4 — Architecture and development docs *(fixes F-5, F-6)*

The largest writing task; split from Phase 3 so the quick wins are not held hostage.

1. `doc/ARCHITECTURE.md`
   - "four independent containers" → the real service inventory, naming `superset-init`
     and `superset-resync` as one-shot profile runners rather than long-lived containers.
   - Redraw the overview so the storage layer shows the main DuckDB **plus** the read-only
     Suzaku files, which is the fact that explains the whole 1-writer/N-reader story now.
   - Add a short section on Suzaku file selection (`generated_at` → mtime → path,
     `REQUIRED_COLUMNS` eligibility), linking to `doc/PLAN_SUZAKU_MULTI_DB.md` rather than
     restating it — one owner per fact.
2. `doc/DEVELOPMENT.md`
   - Lead the workflow section with `make check` / `make test-*`; keep the raw per-module
     commands underneath for people editing one module.
   - Replace "CI Pipeline (Expected)" with what `.github/workflows/ci.yml` actually runs,
     and add the `dashboard` and root `tests/` suites to the stage table.
   - Fix "Useful Commands": bind mount, not `docker volume inspect`; `docker/data/db/…`
     paths.
   - Add a short Suzaku subsection: where `.duckdb` files go, and that `sample/suzaku/`
     fixtures exist for tests.

**Done when:** no section of either file describes a system that predates Suzaku or the
Makefile rework.

### Phase 5 — Public site *(fixes F-7, F-8, F-14)*

1. Translate `reference/suzaku.md` into the 14 remaining locales (Phase 1 test 7 enforces
   presence; the existing `reference/index*.md` set is the tone reference).
2. Add a Suzaku step to Getting Started in all 15 locales: where to put the `.duckdb`
   files, the `--geo-ip` requirement for `aws-ct-metrics`, and the three dashboards plus
   the agent page it unlocks. Keep the four-step structure that `tests/test_docs.py`
   already asserts — add it as a follow-on section, not a fifth step.
3. `overview/architecture.md` and `overview/modules.md` (all locales): match the corrected
   `doc/ARCHITECTURE.md`, and note that the agent is a two-page app.
4. Decide the headline numbers. `README.md` says "120+ hunts, 100+ charts"; the truth is
   126 hunts + 16 Suzaku hunts and 101 + 80 charts. Recommend "140+ hunts, 180+ charts"
   with the split explained on the reference page — but this is a marketing call, so
   confirm before editing the badge line.
5. Add a one-line dated banner to `OLD-README.md` stating it is a frozen snapshot and
   pointing at the docs site.

**Done when:** `mkdocs build --strict` passes and Phase 1 test 7 is green.

### Phase 6 — Housekeeping *(fixes F-15)*

1. Decide `config_viz/write_query.py`: delete it (recommended — 0 bytes, unreferenced,
   and its name contradicts the module's READ_ONLY contract) or document it.
2. Add a "Documentation" section to `CLAUDE.md` stating the ownership rule this plan
   assumes: **one owner per fact**. Counts live next to the assets that produce them and
   are asserted by `tests/test_docs.py`; every other mention links rather than restates.

---

## 4. Sequencing and effort

| Phase | Files touched | Effort | Blocks |
|-------|--------------|--------|--------|
| 0 | 9 | 10 min | — |
| 1 | 1 (+2 count lines) | half day | 2–5 |
| 2 | 4 | 1 hour | 1 |
| 3 | 2 | 1–2 hours | 1 |
| 4 | 2 | half day | — |
| 5 | ~45 (15 locales × 3 pages) | 1–2 days | 1 |
| 6 | 2 | 30 min | — |

Phases 0, 2, 3, 4, 6 are one PR each. Phase 5 is best split per page family
(`reference/suzaku`, `getting-started`, `overview`) to keep translation review reviewable.

## 5. Implementation log — Phases 1–4

### What landed

**Phase 1** — `tests/test_doc_counts.py` (new), `tests/test_doc_structure.py` (new),
`tests/test_docs.py` (extended) and shared helpers in `tests/conftest.py`. The root suite
grew from 134 to 249 tests. Ten of them were Red on the findings above before Phase 2.

The locale-coverage test carries one `xfail(strict=True)` for `reference/suzaku`, the page
Phase 5 will translate. `strict=True` means it turns into a failure the moment the
translations land, which is the reminder to delete the marker.

**Phase 2** — the counts in §2.2, plus the Suzaku Run Info card now named in prose rather
than only counted.

**Phase 3** — `AGENTS.md` file tree rebuilt from the working tree; `CLAUDE.md` repository
map extended with `tests/` and `website/`; the essential-commands block in both files split
so the first block is exactly what bare `make` prints.

**Phase 4** — `doc/ARCHITECTURE.md` service inventory, storage diagram (main DB *and* the
Suzaku files) and a new "Choosing between several files" subsection;
`doc/DEVELOPMENT.md` rewritten around `make`, with the real CI job list and a Suzaku
section.

**Phase 6** — `config_viz/write_query.py` deleted. It was 0 bytes, untouched since the first
commit, referenced by nothing, and not even copied into the image (`config_viz/Dockerfile`
takes `backend/` and `frontend/` only), so the only thing it carried was a name that
contradicts the module's READ_ONLY contract. `CLAUDE.md` gained a **Documentation**
section stating the one-owner-per-fact rule and the table of which artifact owns which
documented fact and which test asserts it; `AGENTS.md` points at it rather than restating
it, which is the rule applied to itself.

### Found while implementing, and fixed

| # | Finding | Where |
|---|---------|-------|
| F-16 | `.github/AGENTS.md` was titled **THuntCloud**, a former project name, and linked to the non-existent `config_viz/PLAN.md` | `.github/AGENTS.md` |
| F-17 | `doc/ARCHITECTURE.md` named `tests/test_suzaku_detection_parity.py`; the file is `tests/test_suzaku_detection_shared.py`, and the mechanism is a bind-mounted shared module, not duplicated constants | `doc/ARCHITECTURE.md` |
| F-18 | "Alternatives Considered" recorded **Named Volume** as *Adopted* while the bind mount is what ships — the opposite of the note four sections later | `doc/ARCHITECTURE.md` |
| F-19 | `AGENTS.md` quoted **605** dashboard tests against a suite of 793, and listed 8 commands under a sentence promising five | `AGENTS.md` |
| F-20 | `doc/DEVELOPMENT.md` step 2 said `cp .env.example .env`; no such file exists and Compose reads `docker/.env`. It also gave `gpt-5.4` as the default model, against `gpt-5.5` in compose | `doc/DEVELOPMENT.md` |
| F-21 | `dashboard/README.md` annotated `suzaku_summary/` with 3 virtual datasets; there are 4 | `dashboard/README.md` |
| F-22 | The Suzaku reference omitted the **🏴 Tactic Breakdown** hunt from its ATT&CK row | `website/docs/reference/suzaku.md` |

### Found while implementing, not fixed

- **CI does not run the config_viz backend suite.** `.github/workflows/ci.yml` has five jobs;
  none executes `config_viz/tests/` (~67 tests). `make check` does. `doc/DEVELOPMENT.md` now
  states this plainly, but closing the gap is a workflow change, not a documentation one.
- **`make check`'s own help text** reads "Run everything CI enforces", which is now an
  understatement for the same reason.
- The per-tab chart table on the reference page sums to 102 for 101 charts, because
  *CloudTrail Events Over Time* appears on two tabs. This is correct as written; the tests
  compare distinct names for exactly this reason.

## 6. Non-goals

- Rewriting `doc/PRD*.md` or the `doc/PLAN_*.md` files to match what shipped. They are
  point-in-time design records; their `Status:` line is the right place to note outcome.
- Restructuring the docs site navigation.
- Translating internal `doc/*.md` — English-only is the standing policy.
