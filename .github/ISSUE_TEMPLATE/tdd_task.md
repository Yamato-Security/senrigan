---
name: TDD Task
about: Track a Red-Green-Refactor implementation task
title: "feat(<module>): <short description>"
labels: ["tdd", "task"]
assignees: []
---

## Goal

<!-- One sentence describing what this task implements. -->

## Module

- [ ] `ingester` (Rust)
- [ ] `agent` (Python / Streamlit)
- [ ] `config_viz` (FastAPI + React)
- [ ] `dashboard` (Apache Superset)

## Test List

> Write the full test list BEFORE writing any production code.

| # | Test description | Status |
|---|-----------------|--------|
| 1 | | 🔴 Red |
| 2 | | |
| 3 | | |

## Acceptance Criteria

- [ ] All tests in the test list above pass (Green).
- [ ] `cargo clippy -- -D warnings` / `ruff check .` reports no errors.
- [ ] `cargo fmt` / `black .` applied.
- [ ] No production code was written before a corresponding failing test.

## Related Issues / PRs

<!-- Link any related issues or PRs. -->

## Notes

<!-- Architecture decisions, edge cases, or anything else worth recording. -->

