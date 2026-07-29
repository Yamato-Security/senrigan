"""Shared fixtures for the dashboard asset and init-script suite."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def clear_suzaku_env(monkeypatch):
    """Unset the ``SUZAKU_*_DB`` overrides for every test.

    ``register_suzaku_dbs`` selects through ``suzaku_db.select``, which honours
    them. Leaving a developer's pinned file in the environment would make these
    tests depend on the machine they run on rather than on the assets.
    """
    for variable in ("SUZAKU_TIMELINE_DB", "SUZAKU_SUMMARY_DB", "SUZAKU_METRICS_DB"):
        monkeypatch.delenv(variable, raising=False)
