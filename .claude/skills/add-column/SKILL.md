---
name: add-column
description: Add a column to cloudtrail_events, or expose an existing one to the LLM. Use when a hunt needs a CloudTrail field the schema does not carry yet, or carries but does not show the model.
---

# Adding or exposing a column

A column is not one change in one place. Stopping early produces a database the chat page can
query and the dashboard cannot see, or a column present in DuckDB that the LLM will never write
SQL against because it was never shown the name.

Work in TDD order — the failing test first, at each layer that has one.

## 1. The Rust schema and its migration

`ingester/src/db.rs` is the authority for the table. Add the column to the `CREATE TABLE`
definition *and* to the `ALTER TABLE ADD COLUMN IF NOT EXISTS` migration, so an existing database
picks it up on the next ingest instead of needing `make reset`.

Then populate it: `ingester/src/parser.rs` maps the CloudTrail JSON to the row, and every write
goes through `duckdb::Appender`, so the column's position in the appender must match the schema.

Tests: `ingester/src/db.rs` and `parser.rs` both carry `#[cfg(test)] mod tests`; a new column
needs a parse test for the field and a schema test for the migration.

## 2. What the LLM sees

`agent/schema.py` is a deliberate subset, not the whole table — the prompt stays small on purpose.
Add the column only if it unlocks a hunt that cannot be written without it. If you do add it, give
`agent/prompts/system_prompt.py` the idiom for reading it, especially when the value is inside a
JSON blob and needs `json_extract_string(col, '$.field')`.

A column left out here is still available to the reviewed SQL in the hunt catalogues.

## 3. The reference table

Update the schema inventory in `AGENTS.md` (`## DuckDB Schema`), including the core/geo/extended
totals in its opening line. `AGENTS.md` owns this fact; nothing else restates it.

## 4. The dashboard

Add the column to the dataset YAML under `dashboard/assets/cloudtrail_default/datasets/`, then
follow `/rebuild-dashboard`. Finish with `make resync` so Superset re-reads the dataset's columns
for the database that is already running.

## Verify

```bash
cargo test                  # schema + parser
pytest agent/tests          # prompt and schema tests
make test-repo              # the docs you touched
make check                  # what CI enforces
```
