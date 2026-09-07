# CLAUDE.md

Senrigan — a locally-executed, AI-assisted threat hunting tool for AWS CloudTrail logs.

**This file is the working rules; it states no facts.** Architecture, the command surface, the
48-column schema, the ingester CLI, environment variables and the repository map all live in
[AGENTS.md](AGENTS.md) and are never restated here — `tests/test_doc_structure.py` fails if a
line from one turns up in the other. Module detail loads on demand through `.claude/rules/`
([ingester/AGENTS.md](ingester/AGENTS.md) · [agent/AGENTS.md](agent/AGENTS.md)). Background:
[doc/ARCHITECTURE.md](doc/ARCHITECTURE.md) · [doc/DEVELOPMENT.md](doc/DEVELOPMENT.md) ·
[doc/TESTING.md](doc/TESTING.md) · [doc/TDD_GUIDE.md](doc/TDD_GUIDE.md) · [doc/PRD.md](doc/PRD.md).

---

## Invariants

Break one of these and nothing fails loudly — that is why they are here rather than in a doc.

- **One writer, N readers.** Only `ingester` opens the DuckDB file READ_WRITE, and it must finish
  before a reader starts. Everything else passes `read_only=True`. Concurrent writers are
  unsupported, not merely discouraged.
- **Suzaku output is never imported and never opened writable** — that is what keeps the single
  writer single. Detection, fitness and file selection have exactly one implementation,
  `agent/suzaku_db.py`, bind-mounted into the Superset init and resync containers rather than
  copied into them (`tests/test_suzaku_detection_shared.py` guards it). Fix selection bugs there.
- **Exactly one file wins per Suzaku command,** so the chat page and the dashboard never disagree
  about which run they are describing. A candidate missing a required column is rejected with a
  reason instead of failing at render time — which is why the Metrics dashboard needs a Suzaku run
  made with `--geo-ip`. `make status` prints the winner and every loser.
- **The bind mount is deliberate.** Docker on Linux and WSL2 misresolves relative paths in
  named-volume `driver_opts`, so each service declares its own `volumes:` entry instead.
- **Two of the four agent pages never reach the LLM.** The explorer pages carry
  `chat_enabled=False` and run only the reviewed SQL in `agent/suzaku_{summary,metrics}_queries.py`;
  a profile that reaches the chat pipeline raises rather than prompting with an empty schema.
- **Dashboard YAML is compiled, not read.** Superset imports the ZIPs, so an edit under
  `dashboard/assets/` is inert until it is rebuilt *and* re-imported — the one change in this
  repository that fails by looking like it worked. `/rebuild-dashboard` has both steps and what
  derives from what.

## TDD (non-negotiable)

Red → Green → Refactor: write the test list, write ONE failing test, confirm it fails, write the
minimum code to pass, refactor green, repeat. **Never write production code without a failing test
first.** Exceptions: boilerplate (Dockerfile, compose, config), UI layout (test the logic behind
it), third-party wiring (mock + test the interface). Business logic and data transformations are
never exempt.

Tests live in `#[cfg(test)] mod tests` + `ingester/tests/` (Rust), `agent|config_viz|dashboard/tests/`
and root `tests/` (Python), `config_viz/frontend/src/__tests__/` (TypeScript).

## Verification

Report no work as done without the command and its output. Reach for the narrowest loop that can
still fail for the right reason:

```bash
pytest agent/tests/test_llm.py::test_name   # one test  — cargo test <name> / npm test -- --run <file>
pytest agent/tests                          # one suite — cargo test / npm test -- --run
make test-repo                              # the consistency suite: Makefile, compose, docs
make check                                  # everything CI enforces (tests + lint + format)
```

No document states a suite size. A count changes in every PR that adds a test, so a written one is
stale by the time it is read, and a stale one reads as a regression that never happened. To see a
count, `pytest --collect-only -q <path> | tail -1`.

## Conventions

- **English everywhere** — comments, docstrings, commits, PRs, `doc/`, `website/docs/`.
- **Commits:** Conventional Commits. **Branches:** `feature|fix/<module>-<short-desc>`.
- **Rust:** `cargo fmt`, `cargo clippy -- -D warnings` (zero warnings), `anyhow::Result` with
  `.with_context(...)`, DB writes **always** via `duckdb::Appender`, temp DBs in tests
  (keep the `NamedTempFile` handle alive).
- **Python:** `black` (88) + `ruff` (rule set pinned in root `ruff.toml` — a lint failure after a
  Ruff upgrade is fixed in the code or by a deliberate `select` change, never by suppression),
  type hints everywhere, Google docstrings. Patch OpenAI as
  `llm.OpenAI`, **not** `agent.llm.OpenAI` (`pytest.ini` sets `pythonpath = .`). Use the
  `tmp_duckdb` / `tmp_db_*` fixtures, never a shared file. **Real OpenAI calls in tests are
  forbidden.**

---

## Schema & SQL

JSON blobs are stored as `VARCHAR`, not the DuckDB JSON type, so every read of one goes through
`json_extract_string(col, '$.field')`. New columns are added with `ALTER TABLE ADD COLUMN IF NOT
EXISTS` so an existing database migrates itself on the next ingest. The LLM is shown a deliberate
subset of the table (`agent/schema.py`) — a column that is not there cannot appear in generated
SQL, however plainly the question asks for it. Hunt SQL may still use the rest.

**Adding or exposing a column touches four layers**, and stopping after the first two produces
a column the chat page can query and the dashboard cannot see. `/add-column` walks them.

Three guards run before any generated SQL executes, in `agent/query.py` and again in
`config_viz/backend/query.py`: a keyword blocklist, `EXPLAIN` validation on the read-only
connection, and a row-limit cap for queries that arrive without one. A failure buys exactly one
repair attempt (`execute_with_retry` → `fix_sql_with_llm`), never a second. Date filters wrap the
query in a `_ct_filtered` CTE; hunts in `agent/builtin_hunts.yaml` that carry an `sql` field run
with no API key at all; IP columns in a result set are geo-enriched best-effort (`agent/geo.py`).

## OpenAI models

The model lineup is spread across six files, and moving fewer than all six leaves the sidebar
offering a model the API rejects. `/update-model-lineup` lists them. Everything else about the API
surface is a code detail — read `agent/llm.py`.

---

## Documentation

**One owner per fact.** A number, path or command name lives in one place; every other mention
links to it. Repetition is how these docs decayed before. Where a fact must appear in prose
anyway, the root suite asserts it against the artifact that produces it — run `make test-repo`
after touching docs and it names the stale sentence.

| Fact | Owned by | Asserted by |
|------|----------|-------------|
| Hunt counts and names | `agent/*_hunts.yaml` | `tests/test_doc_counts.py` |
| Chart counts and names | `dashboard/assets/<bundle>/charts/` | `tests/test_doc_counts.py` |
| Suite sizes | the suites — never quoted in prose | `tests/test_doc_counts.py` |
| The five front-page commands | `Makefile` | `tests/test_doc_structure.py` |
| Repository layout | the working tree | `tests/test_doc_structure.py` |
| Locale coverage | `website/mkdocs.yml` | `tests/test_docs.py` |
| Everything else in `AGENTS.md` | `AGENTS.md` | `tests/test_doc_structure.py` |

`doc/` is internal, `website/docs/` is the product — a user-facing change needs the site page in
every locale, since a missing one silently serves English (`/add-locale-doc`). `PRD_*` are
point-in-time records: update their `Status:` line, never rewrite them. `OLD-README.md` is frozen.

## Security

Keys come from environment variables or a git-ignored `.env`, never from a file under version
control. SQL safety is the three guards above running on a read-only connection, not the guards
alone. The OpenAI request — prompt plus result rows — is the only traffic that leaves the machine;
everything else, DuckDB included, stays local, and every service binds locally by default.
