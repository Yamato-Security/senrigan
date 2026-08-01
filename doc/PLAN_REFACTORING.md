# PLAN: Structural refactoring — `agent/app.py`, the explorer views, and the ingester core

> **Status: implemented (2026-08-01).** All six phases shipped. `agent/app.py` went from
> 1 417 to 1 049 lines, `test_app.py` from 2 239 to 1 808, and every suite held its
> baseline count (agent 825, dashboard 793, root 249+2, config_viz 67+114, ingester 187).
> Phases 1–5 edited no test file. Four deviations from the plan as written:
>
> - **§3 Phase 3** moved only `_discover_suzaku_dbs` and `_render_suzaku_db_selector`.
>   `_get_duckdb_path` stayed in `app.py` — moving it would have broken the invariant
>   `views/explorer.py:db_directory()` documents ("read through the ``app`` module … so a
>   test that patches the path for the database selector patches this too"), which six
>   `patch("app.get_duckdb_path_for_variant")` sites depend on. Keeping it avoided a
>   reach-back import that would have existed only to stay patchable. The phase found a
>   duplicated line instead: the selector's directory lookup was character-for-character
>   `db_directory()`, and now calls it.
> - **§3 Phase 4** produced five section renderers, not the four in the table below. The
>   table was written from a line-range skim and had the layout wrong: the row cap and geo
>   toggle are not adjacent to the date and severity filters, they sit *below* the report
>   and session sections. Merging them into one `_render_filter_section` would have moved
>   widgets, so date, severity and result-limit are separate.
> - **§3 Phase 5** went further than passing `&IngestOptions` into `ingest_core`: doing
>   only that would have moved the destructuring one level down and left `ingest()` a pure
>   pass-through — which is what the `#[allow(clippy::too_many_arguments)]` comment in the
>   source already argued against. `ingest_core` had exactly one caller (its doc claiming
>   it was "shared by all public entry points" was stale), so the two were merged: `ingest`
>   is now the single function, taking `IngestOptions` and destructuring it once. The
>   150-line pipeline body is untouched.
> - **§3 Phase 6** produced no `test_db_selector.py` — `test_app.py` contained no tests for
>   the selector; they already live in `test_suzaku_timeline_view.py` and
>   `test_suzaku_explorer_views.py`. The moved tests also kept their `from app import …`
>   bodies rather than switching to the new modules: the shim cannot be retired anyway,
>   because `views/*.py` (production code, not just tests) import `_init_session_state`,
>   `_get_duckdb_path`, `_render_suzaku_db_selector` and `render_chart` through `app`.
>   Rewriting the imports would have been churn that retires nothing while giving up the
>   guarantee that the move was purely a relocation.
>
> Nothing in this plan changes behaviour. Every phase is a pure structural move whose
> success criterion is *the same tests, still green, with no count change*. If a phase
> cannot be done without editing a test assertion, that phase is wrong and should be
> re-cut, not forced through.

This is a **behaviour-preserving** plan. It adds no feature, removes no feature, and changes
no output — so it deliberately does **not** follow the Red→Green→Refactor loop from
[TDD_GUIDE.md](TDD_GUIDE.md), which governs new behaviour. It runs the *Refactor* step of that
loop against the suite that already exists: the 1 935 Python tests and 186 Rust tests are the
harness, and a refactor that needs a new test is a refactor that changed something.

Baseline, measured on `chore/docker-base-images` at `047850e`:

| Suite | Command | Tests |
|-------|---------|-------|
| agent | `pytest agent` | 825 |
| dashboard | `make test-dashboard` | 793 |
| root | `make test-repo` | 250 collected (249 pass, 1 skip, 1 xfail) |
| config_viz backend | `pytest config_viz` | 67 |
| config_viz frontend | `npm test -- --run` | 114 |
| ingester | `cargo test` | ~186 |

Counts must be **identical** after every phase. A drop means something was dropped; a rise
means the phase stopped being a refactor.

---

## 1. What is actually wrong

The codebase is in good health overall. Rust modules look large by line count but are
mostly tests living beside their subjects, exactly as the conventions require —
`ingest.rs` is 1 468 lines of which 1 049 are `#[cfg(test)] mod tests`. The real
production files are 250–450 lines each and well factored.

Four things are genuinely load-bearing problems, in descending order of cost.

### R1 — `agent/app.py` is a 1 417-line module with nine responsibilities

It is the largest production file in the repository and, unlike the Rust files, that is all
production code. It currently owns:

| Lines | Responsibility |
|-------|----------------|
| 42–71 | constants and `SESSION_STATE_DEFAULTS` |
| 79–237 | Plotly chart rendering (`_render_bar_chart`, `_render_timeseries_chart`, `render_chart`) |
| 243–408 | session lifecycle (`_init_session_state`, `_clear_session`, `_export_session`) and hunt loading |
| 415–545 | DuckDB path resolution and the Suzaku file discovery/selector |
| 547–828 | `render_sidebar` — 283 lines, see R2 |
| 830–942 | three more sidebar sections (report, session, API) |
| 944–1162 | result-card rendering and the per-query filter widgets |
| 1164–1311 | `render_chat` |
| 1317–1417 | page wiring, `build_pages`, `main` |

The cost is not aesthetic. Any change to chart rendering, to Suzaku file selection, and to
the chat loop all touch the same file, and `test_app.py` has grown to 2 239 lines to match —
the largest test file in the project. Every session that opens this file pays to read past
eight things it does not care about.

**The precedent already exists.** `handlers.py` was extracted from `app.py` earlier and
`app.py` re-exports its four private functions (`_handle_direct_sql` and friends), which is
why `from app import _handle_direct_sql` still works in `test_app.py:368`. That re-export
shim is the migration mechanism this plan reuses.

### R2 — `render_sidebar` is 283 lines doing four unrelated jobs

`app.py:547`. In one function body: the Full/Lite database variant radio, preset-hunt
category and label selection, the bulk-run buttons, and the date/level/row-limit filters.
The three sibling sidebar sections (`render_report_section`, `render_session_section`,
`render_api_section`) show what the shape should be — this one function never got the same
treatment.

### R3 — the two explorer views carry byte-identical copies of the cache plumbing

`agent/views/suzaku_summary.py:55-82` and `agent/views/suzaku_metrics.py:58-85` contain
`_query` and `_run` character for character the same, docstrings included, differing only in
which `queries` module the caller bound. `views/explorer.py` already exists as the home for
exactly this kind of shared explorer machinery (`db_directory`, `render_empty_state`,
`render_run_info`, `render_panel`) — the cache pair simply was not put there. A third
explorer page would make it three copies.

### R4 — `ingest_core` takes nine positional parameters

`ingester/src/ingest.rs:251`. The public `ingest()` already accepts an `IngestOptions<'a>`
struct and then unpacks it into nine positional arguments for the private core, four of
which are bare `bool`/`&`-refs that a caller can silently transpose. `IngestOptions` is
right there; the core should take it.

Lower priority, not scheduled below: `main.rs:225` `run()` is a ~170-line subcommand match.
It is long but flat and readable, and splitting it buys less than the four items above.

---

## 2. Non-goals

- **No behaviour change, anywhere.** Not even a fixed typo in a user-facing string — that
  belongs in its own commit with its own test.
- **No `agent/` public API redesign.** Private names stay private and stay importable from
  `app` for the duration of this plan; the shim is not a deprecation.
- **No test rewrites.** `test_app.py` is oversized because `app.py` is oversized. Splitting
  the tests to follow the modules is worthwhile but is *separate* work, scheduled as an
  optional Phase 6 and explicitly not required for the others to land.
- **Nothing in `dashboard/assets/`.** `generate_dashboard_yaml.py` is 1 240 lines because it
  is a single `CONTENT` string literal holding generated YAML. That is what it is supposed to
  be, and `dashboard/tests/` guards it.
- **Nothing in `config_viz/backend/query.py`.** At 894 lines it is the second-largest Python
  file, but it is one coherent subject — graph construction — with 16 focused functions and
  772 lines of tests against it. Leave it.

---

## 3. Phases

Each phase is one commit, one PR-sized unit, and independently revertable. Run the full
matrix from §0 at the end of each. Do them in order: Phase 1 establishes the shim that
Phases 2–4 rely on.

### Phase 1 — extract chart rendering (`refactor: move chart rendering out of app.py`)

The safest first cut: three functions, no session-state access, no Streamlit layout
coupling beyond `st.plotly_chart`.

1. Create `agent/views/charts.py` with `_render_bar_chart`, `_find_time_column`,
   `_render_timeseries_chart`, `render_chart` moved verbatim (`app.py:79-237`).
2. In `app.py`, replace them with `from views.charts import render_chart` plus a
   `# re-exported for tests` comment, matching how `handlers` is imported at `app.py:22`.
3. `test_result_card_charts.py` imports `render_chart` from `app` — it must keep passing
   **unchanged**. That is the phase's acceptance test.

Removes ~160 lines from `app.py`.

### Phase 2 — extract session lifecycle (`refactor: move session state helpers out of app.py`)

1. Create `agent/session.py` with `SESSION_STATE_DEFAULTS`, `_init_session_state`,
   `_clear_session`, `_export_session`, `_load_builtin_prompts`, `_build_all_hunt_queries`,
   `_format_technique_caption` (`app.py:42-71` and `243-408`).
2. Re-export all seven from `app.py`. Note `MODEL_OPTIONS` stays in `app.py` — it is
   sidebar presentation, not session state.
3. Acceptance: the ~20 `from app import _init_session_state` / `_load_builtin_prompts` /
   `_export_session` / `_build_all_hunt_queries` sites across `test_app.py` and
   `test_builtin_hunts_techniques.py` pass untouched.

Removes ~200 lines.

### Phase 3 — extract the Suzaku database selector (`refactor: move the Suzaku db selector into views/`)

1. Move `_get_duckdb_path`, `_discover_suzaku_dbs`, `_render_suzaku_db_selector`
   (`app.py:415-545`) into `agent/views/db_selector.py`. This puts the UI that *chooses* a
   Suzaku file next to `views/explorer.py`, which is what *reads* one, and leaves
   `suzaku_db.py` — the shared detection logic that `dashboard/init/register_suzaku_dbs.py`
   also imports — untouched.
2. **Guard rail:** `tests/test_suzaku_detection_shared.py` (root suite) asserts the agent and
   Superset share one detection module. This phase must not import anything new into
   `suzaku_db.py` or that test is the first thing to fail. Run `make test-repo` here, not
   just `pytest agent`.
3. Re-export both private names; `test_suzaku_explorer_views.py` and
   `test_suzaku_timeline_view.py` import them from `app`.

Removes ~130 lines.

### Phase 4 — split `render_sidebar` (`refactor: split render_sidebar into its four sections`)

The only phase that restructures rather than relocates, so it goes last among the Python
work and stays inside `app.py` — no new module, no new import surface.

Cut `render_sidebar` (`app.py:547-828`) into four private renderers called in the current
order, preserving Streamlit widget order exactly (the sidebar reads top to bottom and
`st.session_state` keys are order-independent, but the rendered layout is not):

| New function | Covers | Current lines |
|--------------|--------|---------------|
| `_render_db_variant_section` | Full/Lite radio | 559–592 |
| `_render_preset_section` | category, preset label, technique captions | 594–~740 |
| `_render_bulk_run_buttons` | "Run All Hunts" / "Run All" | folded into the above, called before the selectbox |
| `_render_filter_section` | date range, levels, row limit, geo toggle | ~740–828 |

The bulk-run buttons are rendered *above* the category selectbox while depending on the
selectbox's current value read back out of session state (`app.py:611-616`). That inversion
is deliberate and load-bearing — preserve it verbatim and comment why, or the buttons will
render a run behind.

`render_sidebar` becomes a ~15-line orchestrator. No test imports it (it needs a live
Streamlit context), so the acceptance signal here is the unchanged agent suite plus a manual
`make up` pass over both chat pages and both explorer pages.

### Phase 5 — `ingest_core` takes `IngestOptions` (`refactor: pass IngestOptions into ingest_core`)

1. Change `ingest_core`'s signature to `(path: &Path, conn: &Connection, options: &IngestOptions<'_>)`
   and read the nine values off the struct at the top of the body.
2. `ingest()` (`ingest.rs:150`) then forwards `&options` instead of destructuring it.
3. `cargo clippy -- -D warnings` and `cargo fmt --check` must stay clean; the 186 Rust tests
   must not move. `parse_file_content` (`ingest.rs:174`) is a separate public entry point and
   is out of scope.

### Phase 6 — optional: split `test_app.py` to follow the modules

Only worth doing once Phases 1–4 land. `test_app.py` (2 239 lines) would split along the
same seams — `test_charts.py`, `test_session.py`, `test_db_selector.py` — and the
`from app import` sites would become direct imports from the new modules, retiring most of
the re-export shim. **This is the one phase that touches test files**, so it must be its own
PR, must move tests without editing their bodies, and must keep the agent total at 825.

Defer it if there is any concurrent feature work in `agent/` — it conflicts with everything.

---

## 4. Risks

**The re-export shim is the whole safety mechanism.** If a phase forgets one name, the
failure is an `ImportError` at collection time, which is loud and immediate — the good
failure mode. Do not "clean up" a re-export in the same PR that creates it.

**Streamlit widget keys are behaviour.** Every key in the sidebar is prefixed with the
profile key so the four pages do not share widget state (`app.py:552`). Phase 4 must not
change a single key string; a renamed key silently resets a user's filters and no test
covers it.

**`st.cache_data` boundaries are behaviour.** `_discover_suzaku_dbs` is cached for 30 s and
the explorer `_query` pair is cached for 300 s keyed on file mtime. Moving a cached function
between modules is safe; changing when it is *called* is not. Phases 1 and 3 move, they do
not re-order.

**Phase 3 crosses the agent/dashboard boundary.** `suzaku_db.py` is bind-mounted into
`superset-init` and `superset-resync` by `docker/docker-compose.yml`. It stays untouched, but
that is a constraint to verify rather than assume — hence the explicit `make test-repo` step.

---

## 5. What this leaves behind

`app.py` goes from 1 417 lines to roughly 500: constants, the four sidebar section renderers,
`render_report_section` / `render_session_section` / `render_api_section`, the result card,
`render_chat`, and the page wiring. That is still the biggest Python file in `agent/`, and it
should be — it is the entry point. The difference is that it will read as one subject.

No documentation count changes: this plan adds no chart, no hunt, and no test, so
`tests/test_doc_counts.py` has nothing to say about it. `CLAUDE.md` and [AGENTS.md](../AGENTS.md)
need their `agent/` file lists in the Repository Map updated in whichever PR first adds a
module — Phase 1.
