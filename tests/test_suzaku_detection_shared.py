"""There is one Suzaku detection implementation, and both services use it.

Replaces the old parity test (PLAN_SUZAKU_VIEWS.md test 18), which compared two
copies of the detection constants and could only catch drift in the constants —
not in the logic, which had already diverged (PLAN_SUZAKU_MULTI_DB.md F-6).

``agent/suzaku_db.py`` is now the single implementation. The Superset image
still cannot install the agent package, so ``docker/docker-compose.yml``
bind-mounts the module next to the init scripts and
``dashboard/init/register_suzaku_dbs.py`` imports it. These tests assert that
arrangement holds: the mount exists, and the Superset side defines no detection
rule of its own.
"""

from __future__ import annotations

import importlib.util
import sys

import yaml

from tests.conftest import COMPOSE_FILE, REPO_ROOT

AGENT_MODULE = REPO_ROOT / "agent" / "suzaku_db.py"
DASHBOARD_MODULE = REPO_ROOT / "dashboard" / "init" / "register_suzaku_dbs.py"

# Rules that must exist in exactly one place. Any of these reappearing in the
# Superset script means the copy is back.
DETECTION_NAMES = (
    "SENRIGAN_TABLE",
    "META_TABLE",
    "SUPPORTED_SCHEMA_VERSION",
    "SUZAKU_TABLES",
    "REQUIRED_COLUMNS",
    "detect_command",
    "detect_command_in",
    "discover_databases",
)


def _load_dashboard_module():
    """Import the Superset registration script with the agent module reachable."""
    agent_dir = str(REPO_ROOT / "agent")
    if agent_dir not in sys.path:
        sys.path.insert(0, agent_dir)
    spec = importlib.util.spec_from_file_location(
        "_shared_register_suzaku_dbs", DASHBOARD_MODULE
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _compose() -> dict:
    """Parse docker/docker-compose.yml."""
    return yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))


def test_the_agent_module_is_the_only_implementation() -> None:
    """The detection rules live in agent/suzaku_db.py and nowhere else."""
    source = DASHBOARD_MODULE.read_text(encoding="utf-8")
    code = "\n".join(
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    )
    for name in DETECTION_NAMES:
        assert f"{name} =" not in code and f"def {name}" not in code, (
            f"register_suzaku_dbs.py redefines {name}; it must import from "
            "suzaku_db instead"
        )


def test_the_superset_script_imports_the_shared_module() -> None:
    """Importing it is what makes the two services agree."""
    assert "from suzaku_db import" in DASHBOARD_MODULE.read_text(encoding="utf-8")


def test_the_shared_module_needs_no_streamlit() -> None:
    """It is imported inside the Superset image, which has no Streamlit."""
    source = AGENT_MODULE.read_text(encoding="utf-8")
    assert "import streamlit" not in source


def test_compose_mounts_the_shared_module_into_superset_init() -> None:
    """Without the mount the Superset container cannot import it at all."""
    volumes = _compose()["services"]["superset-init"]["volumes"]
    mounts = [entry for entry in volumes if "suzaku_db.py" in entry]
    assert mounts, "superset-init must mount agent/suzaku_db.py"
    assert mounts[0].endswith(":ro"), "the shared module is read-only in the container"
    assert "/app/suzaku_db.py" in mounts[0], "it must land next to the init scripts"


def test_both_services_agree_on_every_kind() -> None:
    """The Superset script's fixed names and UUIDs cover the shared enum."""
    module = _load_dashboard_module()
    from suzaku_db import SuzakuKind  # noqa: PLC0415 — needs agent/ on sys.path

    commands = {kind.value for kind in SuzakuKind}
    assert set(module.DATABASE_NAMES) == commands
    assert set(module.DATABASE_UUIDS) == commands
    assert set(module.BUNDLE_COMMANDS.values()) == commands


# ---------------------------------------------------------------------------
# bootstrap.sh scans once (F-9)
# ---------------------------------------------------------------------------

BOOTSTRAP = REPO_ROOT / "dashboard" / "init" / "bootstrap.sh"


def _bootstrap_calls() -> list[str]:
    """Return every register_suzaku_dbs.py invocation in bootstrap.sh."""
    return [
        line.strip()
        for line in BOOTSTRAP.read_text(encoding="utf-8").splitlines()
        if "register_suzaku_dbs.py" in line and not line.lstrip().startswith("#")
    ]


def test_bootstrap_scans_the_directory_exactly_once() -> None:
    """Three full scans of a directory of 200 MB timelines is the old cost."""
    scans = [line for line in _bootstrap_calls() if "--scan" in line]
    assert len(scans) == 1, f"expected one --scan, got {scans}"


def test_every_other_bootstrap_call_reuses_the_scan() -> None:
    """A call without --from re-opens every file, defeating the single scan."""
    for line in _bootstrap_calls():
        if "--scan" in line:
            continue
        assert "--from" in line, f"{line} must select from the saved inventory"


def test_bootstrap_reports_the_selection() -> None:
    """The reason a dashboard is missing belongs in the log that made it so."""
    assert any("--report" in line for line in _bootstrap_calls())
