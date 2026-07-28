"""Keeps the two Suzaku detection tables identical.

Covers PLAN_SUZAKU_VIEWS.md §5.5 (test 18). Suzaku names the producing command in
its ``suzaku_meta`` table, but reading it is needed in two places that cannot
share code:

* ``agent/suzaku_db.py`` — the Streamlit app rediscovers files on every rerun.
* ``dashboard/init/register_suzaku_dbs.py`` — Superset resolves a file path once,
  at bootstrap, and the Superset image cannot import the agent package.

Two copies drift silently: a supported schema version bumped on one side only
would make the agent read a file the dashboard refuses. This test is the guard.
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


def _by_command(mapping: dict) -> dict[str, list[str]]:
    """Return ``{command: sorted(tables)}`` with the enum keys reduced to strings."""
    return {
        str(getattr(key, "value", key)): sorted(tables)
        for key, tables in mapping.items()
    }


agent_module = _load(AGENT_MODULE, "_parity_agent_suzaku_db")
dashboard_module = _load(DASHBOARD_MODULE, "_parity_register_suzaku_dbs")


def test_payload_table_maps_are_identical() -> None:
    """The agent and the dashboard must expect the same tables per command."""
    assert _by_command(agent_module.SUZAKU_TABLES) == _by_command(
        dashboard_module.SUZAKU_TABLES
    )


def test_metadata_contract_is_identical() -> None:
    """Both sides must read the same table and accept the same layout version."""
    assert agent_module.META_TABLE == dashboard_module.META_TABLE == "suzaku_meta"
    assert (
        agent_module.SUPPORTED_SCHEMA_VERSION
        == dashboard_module.SUPPORTED_SCHEMA_VERSION
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
        str(getattr(kind, "value", kind)) for kind in agent_module.SUZAKU_TABLES
    }
    assert agent_commands == set(dashboard_module.DATABASE_NAMES)
    assert agent_commands == {"aws-ct-timeline", "aws-ct-summary", "aws-ct-metrics"}
