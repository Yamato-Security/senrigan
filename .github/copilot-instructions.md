# Copilot Custom Instructions

## Project: Senrigan

Senrigan is a locally-executed, AI-assisted threat hunting tool for AWS CloudTrail logs. It runs
on Docker Compose with no SIEM dependency.

## Where the instructions live

This file used to restate the working rules. It no longer does: it was a fourth copy of them, it
drifted (it described a two-module repository long after there were four), and the project's own
documentation rule is that a fact lives in exactly one place.

| What you need | Read |
|---------------|------|
| Working rules — TDD, conventions, invariants, verification | [`CLAUDE.md`](../CLAUDE.md) |
| Reference — architecture, commands, schema, CLI, env vars | [`AGENTS.md`](../AGENTS.md) |
| Rust ingester module | [`ingester/AGENTS.md`](../ingester/AGENTS.md) |
| Python agent module | [`agent/AGENTS.md`](../agent/AGENTS.md) |
| Scope and priorities | [`doc/PRD.md`](../doc/PRD.md) |

Read `CLAUDE.md` before writing code in this repository. It is short, and it is the file that
says what "done" means here — starting with the fact that no production code is written without
a failing test first.
