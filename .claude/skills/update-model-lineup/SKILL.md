---
name: update-model-lineup
description: Change which OpenAI models the agent offers or defaults to. Use when a model is added, retired, or renamed, because the lineup is spread across six files and a partial move leaves the UI offering a model the API rejects.
---

# Moving the OpenAI model lineup

Six places name the models. Move fewer than all six and the sidebar offers something the API
refuses, or a model that rejects an explicit temperature is sent one.

| # | Where | What it holds |
|---|-------|---------------|
| 1 | `agent/app.py` — `MODEL_OPTIONS` | The list the sidebar offers |
| 2 | `agent/session.py` | The default selected per session |
| 3 | `agent/llm.py` — `_NO_TEMPERATURE_MODELS` | Models that reject an explicit `temperature` |
| 4 | `docker/docker-compose.yml` | `OPENAI_MODEL` / `OPENAI_MODEL_LITE` defaults |
| 5 | `AGENTS.md` — `## Environment Variables` | The documented defaults and offered list |
| 6 | `agent/AGENTS.md` | The module's own environment table |

Item 3 is the one most often missed, and it fails at request time rather than at startup.

## Order

Write the failing test first: `agent/tests/test_app.py` covers the option list and
`agent/tests/test_llm.py` covers the temperature exclusion. Then move all six, then the docs.

## Verify

```bash
pytest agent/tests/test_app.py agent/tests/test_llm.py agent/tests/test_session.py
make test-repo
```

Real OpenAI calls in tests are forbidden — patch `llm.OpenAI`, not `agent.llm.OpenAI`.
