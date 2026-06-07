# Copilot Custom Instructions

## Project: Senrigan

This is an AWS CloudTrail log threat hunting tool. It runs locally via Docker Compose with no SIEM dependency.

## Development Methodology

**This project uses strict TDD (Test-Driven Development).**

Every feature must be implemented using the Red-Green-Refactor cycle:
1. Write a test list before coding.
2. Write ONE failing test (Red).
3. Write the MINIMUM code to make it pass (Green).
4. Refactor while keeping tests green.
5. Repeat.

**Never write production code without a corresponding failing test first.**

## Key Rules

- **Language:** All code comments, documentation, docstrings, commit messages, and PR descriptions MUST be written in English.
- **Rust (ingester):** Use `cargo test`, `clippy`, `rustfmt`. Error handling with `anyhow`. Unit tests in `#[cfg(test)] mod tests`.
- **Python (agent):** Use `pytest`, `ruff`, `black`. Type hints required. Mock all OpenAI API calls in tests.
- **DuckDB:** ingester = `READ_WRITE`, agent/dashboard = `READ_ONLY`. Tests use temporary databases (`tempfile` / `tmp_path`).
- **Security:** Never hardcode API keys. Validate AI-generated SQL before execution. `READ_ONLY` + keyword filtering + `EXPLAIN`.
- **Commits:** Conventional Commits format (`feat:`, `fix:`, `test:`, `refactor:`, `docs:`).

## Reference Documentation

- [AGENTS.md](../AGENTS.md) — Full agent instructions (architecture, conventions, schema, CLI reference)
- [ingester/AGENTS.md](../ingester/AGENTS.md) — Rust ingester module TDD context
- [agent/AGENTS.md](../agent/AGENTS.md) — Python agent module TDD context
- [doc/PRD.md](../doc/PRD.md) — Product Requirements Document (source of truth for scope and priorities)
- [doc/TDD_GUIDE.md](../doc/TDD_GUIDE.md) — TDD methodology and examples
- [doc/TESTING.md](../doc/TESTING.md) — Testing strategy per module
- [doc/ARCHITECTURE.md](../doc/ARCHITECTURE.md) — System architecture
- [doc/DEVELOPMENT.md](../doc/DEVELOPMENT.md) — Development setup guide
