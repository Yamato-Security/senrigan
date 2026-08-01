# PLAN: Makefile UX — a minimal, unambiguous command surface

**Status:** Proposed
**Date:** 2026-07-26
**Goal:** A first-time user should need to learn **five** commands, and `make` with no
arguments should tell them exactly which five. Everything else (advanced ingest modes,
per-service logs, the dev/test loop) stays available but moves out of the default view.

---

## 1. Current state

`Makefile` exposes **20 targets in one flat list**. `make help` prints all 20 with no
grouping, no ordering, and no distinction between "you need this on day one" and
"you need this only if you are editing Rust."

```
ensure-secret  up  down  clean  build  ps
ingest  ingest-full  ingest-geoip  enrich  config-import  resync
logs-agent  logs-config-viz  logs-superset
test  test-ingester  test-agent  test-config-viz  test-frontend
lint  fmt-check  build-ingester  help
```

### 1.1 Findings

| # | Severity | Finding | Evidence |
|---|----------|---------|----------|
| F-1 | **High** | Bare `make` runs `ensure-secret`, not `help`. There is no `.DEFAULT_GOAL`, so GNU Make picks the first target in the file. A new user typing `make` gets a silently-generated secret key and no guidance. | `Makefile:19` is the first rule; `make -pn \| grep DEFAULT_GOAL` → `.DEFAULT_GOAL := ensure-secret` |
| F-2 | **High** | **`make ingest-config` does not exist.** The documented target is named `config-import`. All 15 localized Getting Started pages tell users to run a command that fails. | `Makefile:74` defines `config-import`; `website/docs/getting-started/index.md:58` says `make ingest-config`; 15 files match `grep -rl ingest-config website/docs/` |
| F-3 | **High** | **`make enrich` is broken.** It passes `--geoip-country /data/geoip` — a *directory* — but the CLI takes a `PathBuf` to an `.mmdb` *file* and does no directory resolution. | `Makefile:70-72`; `ingester/src/main.rs:45-55` (`resolve_geoip_paths` only falls back to env vars, no dir walk) |
| F-4 | **Medium** | Docs point at the wrong host directory for AWS Config snapshots: `docker/logs/config/`. The actual bind mount is `${CONFIG_HOST_PATH:-./data/config-snapshots}`. 15 localized files affected. | `website/docs/getting-started/index.md:56`; `docker/docker-compose.yml:33` |
| F-5 | **Medium** | Four ways to ingest (`ingest`, `ingest-full`, `ingest-geoip`, `enrich`) with no stated default or decision rule. The user must understand `--strip-raw-event` / `--strip-fields` trade-offs before running anything. | `Makefile:57-72` |
| F-6 | **Medium** | `ensure-secret` is internal plumbing but carries a `##` comment, so it appears in `help` as if it were a user command. | `Makefile:19` |
| F-7 | **Medium** | No recovery path in `make`. `CLAUDE.md` documents re-ingest-from-scratch as a manual four-line `rm -f data/db/threat_hunting.db …` recipe. Users copy-paste `rm` against a path relative to `docker/`. | `CLAUDE.md` "Essential Commands" |
| F-8 | **Low** | Three near-identical log targets (`logs-agent`, `logs-config-viz`, `logs-superset`) that a single parameterized target covers. No target tails *all* services. | `Makefile:78-86` |
| F-9 | **Low** | Eight dev-loop targets (`test*`, `lint`, `fmt-check`, `build-ingester`) sit in the same list as `up`/`down`. They are ~40% of the visible surface and are irrelevant to the audience the README targets ("all on your laptop with a single `make up`"). | `Makefile:89-119` |
| F-10 | **Low** | `make up` before `make ingest` yields empty dashboards with no explanation; `resync` exists to fix stale metadata but is undiscoverable at the moment of failure. | `Makefile:31`, `Makefile:74-76` |

**Root cause:** the Makefile grew as a flat alias sheet for `docker compose` lines. There is
no notion of *tier* (user vs. advanced vs. contributor), so every new alias enlarges the
thing a new user has to read.

---

## 2. Target UX

### 2.1 The five commands

Bare `make` prints this and nothing else:

```
  Senrigan — offline AWS CloudTrail threat hunting

  1.  make ingest     Load CloudTrail logs from docker/logs/ into DuckDB
  2.  make up         Start the UI, dashboard, and resource graph
  3.  make down       Stop everything
      make logs       Tail service logs        (SERVICE=agent|superset|config-viz)
      make reset      Delete the database and start over

  More: make help-all   every target, grouped
```

Numbering the first three encodes the happy path, which the current flat list cannot.

There are **no flags and no variables** on the front page. Options are not something the
user selects at the command line — see §2.3.

### 2.2 Two-tier help

- `help` (the new `.DEFAULT_GOAL`) — hand-written block above. Deliberately **not**
  generated from `##` comments, so it stays curated as targets are added.
- `help-all` — generated, grouped by `##@ Section` headers, listing every public target.

Adopt the standard `##@` convention so grouping survives future edits:

```make
##@ Getting started
ingest: ## Load CloudTrail logs from docker/logs/ into DuckDB
##@ Advanced ingest
enrich: ## Back-fill GeoIP onto an existing database
##@ Development
test:   ## Run all tests (Rust + Python + TypeScript)
```

Internal targets simply drop their `##` comment and vanish from both views (fixes F-6).

### 2.3 Zero options: the filesystem is the configuration

The ingest family (F-5) is collapsed **without introducing flags or variables**. `make ingest`
inspects the bind-mount directories that Getting Started already tells the user to populate,
and enables the matching ingester options itself.

| Signal on disk | Effect on `make ingest` |
|----------------|-------------------------|
| `docker/data/geoip/GeoLite2-City.mmdb` present | add `--geoip-city <path>` |
| `docker/data/geoip/GeoLite2-ASN.mmdb` present | add `--geoip-asn <path>` |
| `docker/data/geoip/GeoLite2-Country.mmdb` present *and no City db* | add `--geoip-country <path>` |
| `docker/data/config-snapshots/` non-empty | run `config-import` after the CloudTrail pass |
| *(always)* | `--strip-raw-event --strip-fields` — today's `ingest` default |

Implemented with `$(wildcard …)`, so detection costs nothing and needs no shell probing:

```make
GEOIP_DIR   := docker/data/geoip
CITY_MMDB   := $(wildcard $(GEOIP_DIR)/GeoLite2-City.mmdb)
ASN_MMDB    := $(wildcard $(GEOIP_DIR)/GeoLite2-ASN.mmdb)
CONFIG_DIR  := docker/data/config-snapshots
CONFIG_SNAP := $(wildcard $(CONFIG_DIR)/*)
```

Paths must match `docker/docker-compose.yml:31-35`, whose defaults are
`${GEOIP_HOST_PATH:-./data/geoip}` and `${CONFIG_HOST_PATH:-./data/config-snapshots}`
relative to `docker/`. When those env vars are overridden the Makefile must honour them, so
the detection variables read the same env vars with the same defaults.

**Detection is always echoed before the run** — this is what keeps the implicitness honest:

```
$ make ingest
  ✓ GeoIP databases found (City, ASN)      → IP enrichment enabled
  ✓ AWS Config snapshots found (128 files) → will import after CloudTrail
    docker/logs/ … 1,204 files

  [ingest] …
  Next: make up
```

Rationale: a user choosing between four targets must understand all four before running any
of them. Here the only decision is *where to put files*, which Getting Started already
covers. The command count for the common path drops to one and stays at one.

Keeping the `raw_event` column has no filesystem signal and is a debugging concern, so it
stays where it already is — the existing `ingest-full` target — rather than becoming a flag.
No new target is needed for it.

### 2.3.1 Existing ingest targets: unchanged, just hidden

No existing target is renamed, re-pointed, or deleted. `ingest-full`, `ingest-geoip`, and
`enrich` keep their current recipes (modulo the F-3 fix) and move under `##@ Advanced ingest`
in `help-all`, out of the front page. They remain valid escape hatches for anyone who needs
to force a mode against what is on disk, and they stay correct in
`doc/PRD_DASHBOARD_REVIEW.md:98,116`.

The **one** name change is `config-import` → `ingest-config`, with `config-import` kept as an
alias. This makes 15 localized docs correct *without editing them* (F-2) — the cheapest fix
available.

Combined effect: the front page shrinks to five commands, and `help-all` remains a complete
inventory. The risk of the collapse is therefore near zero, because nothing is collapsed —
the default path simply stops requiring a choice.

### 2.4 New targets

| Target | Purpose | Replaces |
|--------|---------|----------|
| `logs` | `docker compose logs -f $(SERVICE)`; no `SERVICE` → all services | `logs-agent`, `logs-config-viz`, `logs-superset` (kept as aliases) |
| `reset` | `down` → delete `threat_hunting.db{,.wal}` → print the next step. **Prompts for confirmation** unless `FORCE=1`. | the manual `rm -f` recipe in `CLAUDE.md` (F-7) |
| `status` | `ps` plus: does the DB exist, how many rows, is GeoIP populated | `ps` (kept as alias) |
| ~~`doctor`~~ | Preflight checks — **dropped in Phase 3**; the §2.5 guardrails cover the same failures | — |
| `check` | `test` + `lint` + `fmt-check` — the one command a contributor runs before pushing | — |

### 2.5 Guardrails at the point of failure (F-10)

- `up` — if `docker/data/db/threat_hunting.db` is missing, print
  `⚠️  No database found. Run 'make ingest' first.` and continue (do not hard-fail; the
  services still start and the DB can be created afterwards by `make ingest`).
- `ingest` — if `docker/logs/` contains no `.json`/`.json.gz`, fail fast with the expected
  path and the `aws s3 cp` example, before spending a container start.
- `ingest` — on success, print `Next: make up`. On re-ingest into an existing DB, print
  `If dashboards look blank, run: make resync`.
- `ingest` — when no GeoIP database is detected, say so explicitly and name the directory:
  `· No GeoIP database in docker/data/geoip/ — IP enrichment skipped`. A silent skip is the
  main failure mode of auto-detection, and `PRD_DASHBOARD_REVIEW.md:98` (F-11) already
  records users hitting blank GeoIP charts with no explanation.

### 2.6 Resulting surface

`help`: **5 commands, zero flags, zero variables.** (was: 20 flat targets)

`help-all`: 25 targets in 5 groups — Getting started (5) / Advanced ingest (4) /
Operations (4) / Development (10) / Help (2).

---

## 3. Test plan (TDD)

`CLAUDE.md` exempts build boilerplate from strict TDD, but the *contract* here — which
targets exist, and whether the docs agree with them — is exactly the class of drift that
caused F-2 and F-4. Those are testable and would have been caught.

New home: `tests/` at repo root, with `tests/pytest.ini` mirroring `dashboard/pytest.ini`,
plus a `makefile` job in `.github/workflows/ci.yml` modeled on the existing
`dashboard-yaml` job (`.github/workflows/ci.yml:106`).

Test list, written before any Makefile edit:

1. `test_default_goal_is_help` — parse `make -pn` output, assert `.DEFAULT_GOAL := help`. **(F-1)**
2. `test_help_lists_exactly_the_core_commands` — `make help` output mentions `ingest`, `up`,
   `down`, `logs`, `reset` and does *not* mention `test`, `lint`, `clippy`, `ensure-secret`. **(F-6, F-9)**
3. `test_every_make_command_in_docs_exists` — regex `make ([a-z][a-z0-9-]*)` across
   `website/docs/**` and `doc/**`, assert each captured target is in `make help-all`. **(F-2)**
4. `test_every_public_target_is_phony` — every `##`-commented target appears in `.PHONY`.
5. `test_help_all_groups_are_nonempty` — each `##@` section has ≥1 target.
6. `test_geoip_paths_are_mmdb_files` — no `--geoip-*` flag in the Makefile points at a
   bare directory. **(F-3)**
7. `test_documented_host_paths_exist_in_compose` — host paths named in Getting Started
   (`docker/logs/`, config snapshot dir) appear as bind-mount sources in
   `docker/docker-compose.yml`. **(F-4)**
8. `test_reset_requires_confirmation` — the `reset` recipe contains a confirmation guard
   and does not `rm -rf`.
9. `test_help_mentions_no_flags` — `make help` output contains no `=` assignment and no
   `--` flag, i.e. the front page really is flag-free.
10. `test_legacy_targets_still_resolve` — `ingest-full`, `ingest-geoip`, `config-import`,
    `enrich`, `logs-agent`, `ps` all resolve via `make -n`.

Auto-detection (§2.3) is the part with real logic, so it gets its own tests. Each runs
`make -n ingest` with a fabricated tree via `tmp_path` and `GEOIP_HOST_PATH` /
`CONFIG_HOST_PATH` overrides, and asserts on the *expanded recipe*, never on a real run:

11. `test_geoip_detected_when_mmdb_present` — City + ASN files on disk → recipe contains
    `--geoip-city` and `--geoip-asn`.
12. `test_geoip_absent_adds_no_flags` — empty geoip dir → recipe contains no `--geoip-`,
    and the echoed output says enrichment was skipped (§2.5).
13. `test_country_only_fallback` — Country db but no City db → `--geoip-country`, and it
    points at the `.mmdb` file, not the directory. Directly pins F-3 shut.
14. `test_city_wins_over_country` — both present → `--geoip-city`, no `--geoip-country`.
15. `test_config_snapshots_trigger_import` — non-empty snapshot dir → recipe includes a
    `config-import` invocation; empty dir → it does not.
16. `test_detection_honours_host_path_env` — setting `GEOIP_HOST_PATH` moves where
    detection looks, matching `docker-compose.yml`'s bind mount.

Red-first against today's Makefile: 1, 2, 9, and 11–16 fail now.

---

## 4. Phases

Each phase is independently shippable and leaves the tree green.

**Phase 0 — Bug fixes only** *(no UX change)* — ✅ **done**
- `.DEFAULT_GOAL := help`, so bare `make` explains instead of acting (F-1).
- `ingest-config` is the real target; `config-import` kept as an alias (F-2).
- `enrich` passes `--geoip-city` / `--geoip-asn` as `.mmdb` file paths, matching
  `ingest-geoip`, instead of a directory (F-3).
- AWS Config host path corrected to `docker/data/config-snapshots/` across all 15 locales
  and `OLD-README.md` (F-4). The path was a pure string substitution, so no prose in any
  locale needed rewriting.
- Tests 1, 3, 6, 7 in a new root `tests/` suite (5 tests), wired into CI as the
  `repo-consistency` job and into `make test` via `make test-repo`.

Two decisions made during implementation:

- **Test scope excludes `PLAN_*` / `PRD*` documents.** They describe proposed state, so
  they legitimately name targets that do not exist yet — including the ones this plan
  introduces in Phases 2–3. Every other Markdown file in the repo is checked.
- **`make ingest-config` became correct without touching 15 files.** Only the host path
  needed a doc edit; the target name was fixed in the Makefile, as §2.3.1 predicted.

**Phase 1 — Two-tier help** — ✅ **done**
- Hand-written `help` as `.DEFAULT_GOAL`; generated grouped `help-all` via `##@`.
- Targets physically regrouped into five `##@` sections. Every operational recipe is
  byte-identical to Phase 0 — only `help`/`help-all` changed.
- `ensure-secret` lost its `##` comment and moved to an `Internal` block at the bottom, so
  it no longer appears in either help view (F-6).
- Tests 2, 4, 5, 9, plus three that emerged while writing the front page (below).

Adjustments made during implementation:

- **Test 9 moved from Phase 2 to Phase 1.** It asserts the front page advertises no flags
  or `VAR=value` switches, which is a property of the help text written here, not of the
  auto-detection written later.
- **Phase 1's front page lists three commands, not five.** `logs` and `reset` do not exist
  until Phases 2 and 3, and help must not advertise commands that fail. `CORE_COMMANDS` in
  `tests/test_makefile_help.py` is the single place to extend as they land.
- **Three tests added beyond the plan**, all catching classes of error the original list
  missed: `test_help_only_advertises_real_targets` (front page names a phantom target),
  `test_help_all_lists_every_documented_target` (a `##` target the generator drops), and
  `test_every_documented_target_is_grouped` (a target outside every `##@` section, which
  `help-all` would silently orphan).

**Phase 2 — Auto-detection** — ✅ **done**
- `ingest` detects GeoIP databases and Config snapshots from disk (§2.3) and echoes both
  what it found *and* what it skipped. Config snapshots are imported automatically as a
  second pass, resolving open question 4 in favour of automatic import.
- `logs` with `SERVICE=`; `logs-agent` / `logs-config-viz` / `logs-superset` reduced to
  target-specific variable assignments that defer to it — no recursive make.
- Existing ingest targets keep their recipes verbatim, with descriptions reworded to
  `Force: …` so `help-all` makes clear they override detection rather than duplicate it.
- Tests 10–16 plus three more (below), 18 in total for this phase.

Adjustments made during implementation:

- **`$(strip)` is load-bearing.** A line continuation inside `$(if …)` leaves a space
  behind, so the "no GeoIP found" case produced `GEOIP_FLAGS = " "` — non-empty, which made
  `ifneq` report enrichment as enabled while passing no flags. Caught by test 12, which is
  exactly the silent-skip failure the echo requirement in §2.5 exists to prevent.
- **`logs-*` are hidden from `help-all`, not listed as aliases.** This matches how
  `config-import` was treated in Phase 0: the superseded name keeps working and is pinned by
  test 10, but only the canonical target appears in the inventory. Listing both would grow
  `help-all` with rows that teach nothing.
- **Three tests added beyond the plan:** `test_no_config_snapshots_means_no_import` (the
  negative half of test 15), `test_logs_tails_all_services_by_default`, and
  `test_per_service_log_targets_delegate_to_logs` — target-specific variable propagation to
  a prerequisite is subtle enough to be worth pinning.

**Phase 3 — New affordances** — ✅ **done**
- `reset` (confirmation-guarded, `FORCE=1` for scripts), `status`, `check`.
- Guardrails: `up` warns when the database is missing; `ingest` fails fast on an empty
  `docker/logs/` and prints the `aws s3 cp` command that fixes it.
- `ps` reduced to a compatibility alias of `status`.
- Test 8 plus ten more, 11 in total for this phase.

Decisions made during implementation:

- **`doctor` dropped**, resolving open question 2 as its own proposal anticipated. With the
  §2.5 guardrails in place, the failures `doctor` would have caught are already handled:
  missing logs and missing database are covered explicitly, and a stopped Docker daemon
  produces a clear error from `docker compose` itself. A preflight target would have added
  surface without adding an answer — the opposite of this plan's goal.
- **`status` reports files, not row counts.** The plan asked for a row count and a "is
  GeoIP populated" check, both of which require querying DuckDB. There is no cheap path:
  the readers are containers, and the ingester has no stats subcommand, so `status` would
  have to start a container and could fail before the images exist. It instead reports
  container state, database presence and size, and what `ingest` would detect — answering
  the same questions without a container round-trip.
- **Aborting `reset` exits non-zero**, so make prints `make: *** [reset] Error 1` after a
  deliberate "n". This is intentional — a script must see that the reset did not happen —
  but it is cosmetically poor for an interactive abort. Removing it would mean running the
  confirmation and the deletion in one shell (`.ONESHELL` is global and would break every
  `cd docker && …` recipe), which is not worth it. The `Aborted — nothing was deleted.`
  line above it carries the actual meaning.

**Phase 4 — Docs** — ✅ **done**
- Getting Started rewritten around the five commands, in all 15 locales. Four numbered
  steps; the two former "Optional … then run `make ingest-geoip`" blocks replaced by a
  table of the two auto-detected directories, filled in *before* `make ingest`. A new
  "Everyday commands" table closes the page.
- `CLAUDE.md` and `AGENTS.md` Essential Commands now call `make` targets. The hand-copied
  `rm -f data/db/threat_hunting.db …` recipe is gone, replaced by `make reset` (F-7).
- `website/docs/reference/` (15 files): the KPI-88 note pointing at `make ingest-geoip`
  now names `docker/data/geoip/` instead, since filling the directory is the whole
  instruction.
- Five new parametrized doc tests (61 cases) pin cross-locale structure.

Notes on execution:

- **Existing translations were reused, not regenerated.** Step 1, the browser section and
  its URL bullets were extracted from each file and re-emitted, so only genuinely new
  strings were translated. The step-number prefix was derived per locale from its own
  step 1 (`**Step {n}.**`, `**{n}단계.**`, `**ขั้นตอนที่ {n}.**`, …) rather than hardcoded.
- **Code-block comments stay in English** in every locale, matching what the files already
  did.
- **Test 3 caught a regression during this phase.** A repo-map line added to `AGENTS.md`
  read `# make command surface: …` inside a code fence, which the extractor read as an
  invocation of a `command` target. Reworded to `# Makefile UX: …`.

---

## 5. Risks and non-goals

| Risk | Mitigation |
|------|------------|
| **Auto-detection is implicit — the user cannot see why a run behaved as it did** | Every run echoes what was detected *and* what was skipped, with the directory named (§2.5). The advanced targets remain as explicit overrides. |
| A stray `.mmdb` silently changes behaviour and slows ingest | The echoed detection block makes it visible on every run; `ingest-full` / plain `docker compose` remain available to bypass. |
| Detection paths drift from `docker-compose.yml` bind mounts | Tests 7 and 16 pin the Makefile's detection paths to the compose bind-mount sources and their `*_HOST_PATH` overrides. |
| Renaming breaks users' scripts and blog posts | Only `config-import` is renamed, and the old name survives as an alias. Nothing else is renamed or deleted. |
| 15-locale doc drift during the transition | Aliases keep old docs *correct*, not merely tolerated. Test 3 fails CI if a doc names a target that does not exist — in either direction. |
| Hand-written `help` goes stale | Tests 2 and 9 pin its contents; adding a core command means updating the test. |
| `reset` deletes user data | Confirmation prompt by default; `FORCE=1` for CI. Deletes only the two DuckDB files by explicit name, never a directory. |

**Non-goals:** replacing `make` with a task runner (`just`, `task`); adding a TUI/wizard or
interactive prompts (rejected: breaks CI and non-TTY use, and multiplies across 15 locales);
moving ingest options into `docker/.env` (rejected: adds a file-editing step and hides
behaviour from the command); changing anything about `docker-compose.yml` service topology.

---

## 6. Open questions

1. **`reset` semantics** — DB only, or also `docker compose down -v --rmi all` (today's
   `clean`)? Proposal: `reset` = data only, `clean` = images/volumes, kept distinct.
2. **`doctor` scope** — is a preflight worth the maintenance, or does the guardrail
   messaging in §2.5 cover the realistic failures? Proposal: defer `doctor` to Phase 3 and
   drop it if §2.5 lands well.
3. **Root `tests/` directory** — acceptable to add a fifth pytest root and CI job, or
   should these live in an existing suite? Proposal: root `tests/`, since the assertions
   are cross-cutting (Makefile × compose × website).
4. **Should Config snapshot import be part of `ingest` at all?** Auto-detection makes it a
   second pass inside one command, which lengthens a run the user may not expect. The
   alternative is to detect the snapshots and merely *suggest* `make ingest-config` at the
   end. Proposal: import automatically, since a populated `config-snapshots/` is an
   unambiguous statement of intent — but this is the weakest part of §2.3 and worth a
   second opinion.
5. **Does auto-detection extend to `up`?** e.g. skip the `config-viz` service entirely when
   no Config data was ever imported, rather than serving an empty graph. Out of scope here;
   noting it so it is not rediscovered later.
