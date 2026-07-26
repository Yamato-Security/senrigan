"""Keeps the two Suzaku schema-signature tables identical.

Covers PLAN_SUZAKU_VIEWS.md §5.5 (test 18). Suzaku's DuckDB output carries no
metadata table, so the producing command has to be inferred from the schema — and
that inference is needed in two places that cannot share code:

* ``agent/suzaku_db.py`` — the Streamlit app rediscovers files on every rerun.
* ``dashboard/init/register_suzaku_dbs.py`` — Superset resolves a file path once,
  at bootstrap, and the Superset image cannot import the agent package.

Two copies drift silently: a column added to one table would make the agent
recognise a file the dashboard rejects. This test is the guard. The whole problem
disappears if Suzaku ships a metadata table (doc/PLAN_SUZAKU_SCHEMA.md P1).
"""

from __future__ import annotations

import importlib.util
import sys

from tests.conftest import REPO_ROOT

AGENT_MODULE = REPO_ROOT / "agent" / "suzaku_db.py"
DASHBOARD_MODULE = REPO_ROOT / "dashboard" / "init" / "register_suzaku_dbs.py"


def _load(path, name: str):
    """Import a module by file path, without adding its directory to sys.path."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _normalise(signatures: dict) -> dict[str, dict[str, list[str]]]:
    """Return ``{command: {table: sorted(columns)}}`` with lowercase keys.

    The agent keys its table by a ``SuzakuKind`` enum and the dashboard by the
    command string, so both are reduced to the command string here.
    """
    out: dict[str, dict[str, list[str]]] = {}
    for command, tables in signatures.items():
        key = getattr(command, "value", command)
        out[str(key)] = {
            table.lower(): sorted(column.lower() for column in columns)
            for table, columns in tables.items()
        }
    return out


agent_module = _load(AGENT_MODULE, "_parity_agent_suzaku_db")
dashboard_module = _load(DASHBOARD_MODULE, "_parity_register_suzaku_dbs")


def test_signature_tables_are_identical() -> None:
    """The agent and the dashboard must classify a file the same way."""
    assert _normalise(agent_module.SUZAKU_SIGNATURES) == _normalise(
        dashboard_module.SUZAKU_SIGNATURES
    )


def test_both_reject_the_senrigan_table() -> None:
    """Neither side may treat Senrigan's own database as Suzaku output."""
    assert (
        agent_module.SENRIGAN_TABLE
        == dashboard_module.SENRIGAN_TABLE
        == ("cloudtrail_events")
    )


def test_env_override_variables_match() -> None:
    """An operator pinning a file must have it honoured by both readers."""
    agent_overrides = {
        str(getattr(kind, "value", kind)): variable
        for kind, variable in agent_module.ENV_OVERRIDES.items()
    }
    assert agent_overrides == dashboard_module.ENV_OVERRIDES


def test_both_know_the_same_commands() -> None:
    """A command one side supports and the other ignores is a silent gap."""
    agent_commands = {
        str(getattr(kind, "value", kind)) for kind in agent_module.SUZAKU_SIGNATURES
    }
    assert agent_commands == set(dashboard_module.DATABASE_NAMES)
    assert agent_commands == {"aws-ct-timeline", "aws-ct-summary", "aws-ct-metrics"}
