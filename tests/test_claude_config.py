"""Tests for the committed Claude Code configuration.

``.claude/settings.json`` is where rules that CLAUDE.md can only *state* become
rules the client *enforces*. That distinction is the whole point of the file,
and it fails quietly: a hook naming a script that was renamed, or a script that
stops exiting 2 on the path it guards, produces no error — the agent simply
never hears about it, and the dashboard ZIP goes un-rebuilt exactly the way it
did before the hook existed.

So these tests run the hooks the way Claude Code runs them: the event payload
on stdin, the exit code and stderr as the only outputs that matter.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

import pytest
import yaml

from tests.conftest import REPO_ROOT

CLAUDE_DIR = REPO_ROOT / ".claude"
SETTINGS = CLAUDE_DIR / "settings.json"
RULES_DIR = CLAUDE_DIR / "rules"
SKILLS_DIR = CLAUDE_DIR / "skills"


def settings() -> dict:
    """Return the parsed project settings file."""
    return json.loads(SETTINGS.read_text(encoding="utf-8"))


def hook_commands() -> list[str]:
    """Return the ``command`` of every hook the settings file declares."""
    commands = []
    for matchers in settings().get("hooks", {}).values():
        for matcher in matchers:
            commands += [hook["command"] for hook in matcher["hooks"]]
    return commands


def hook_script(name: str) -> Path:
    """Return the path of a hook script by file name."""
    return CLAUDE_DIR / "hooks" / name


def run_hook(name: str, file_path: str) -> subprocess.CompletedProcess[str]:
    """Invoke a hook the way Claude Code does: the event payload on stdin."""
    payload = {
        "hook_event_name": "PostToolUse",
        "tool_name": "Edit",
        "cwd": str(REPO_ROOT),
        "tool_input": {"file_path": file_path},
    }
    return subprocess.run(
        [str(hook_script(name))],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )


def test_settings_is_valid_json_with_the_expected_top_level_keys():
    """A malformed settings file is ignored, taking every rule down with it."""
    assert set(settings()) >= {"permissions", "hooks"}


@pytest.mark.parametrize("command", hook_commands(), ids=lambda c: Path(c).name)
def test_every_hook_command_points_at_an_executable_script(command: str):
    """A hook naming a missing script is a rule that silently does nothing."""
    script = Path(command.replace("${CLAUDE_PROJECT_DIR}", str(REPO_ROOT)))

    assert script.is_file(), f"{command} does not exist"
    assert script.stat().st_mode & 0o111, f"{command} is not executable"


def test_editing_a_dashboard_asset_tells_the_agent_to_rebuild():
    """Editing YAML under `dashboard/assets/` changes nothing on its own.

    Superset applies the compiled ZIPs, so the edit is inert until both the
    rebuild and the re-import run. Nothing fails; the dashboard just keeps
    serving the old chart. That is what this hook exists to interrupt.
    """
    result = run_hook(
        "dashboard_assets_reminder.py",
        str(REPO_ROOT / "dashboard/assets/cloudtrail_default/charts/foo.yaml"),
    )

    assert result.returncode == 2, "the reminder must reach the agent"
    assert "rebuild_zip.py" in result.stderr
    assert "superset-init" in result.stderr


def test_editing_anything_else_stays_silent():
    """A hook that speaks on every edit is a hook that gets tuned out."""
    result = run_hook("dashboard_assets_reminder.py", str(REPO_ROOT / "agent/app.py"))

    assert result.returncode == 0
    assert result.stderr == ""


def test_editing_a_guarded_document_names_the_target_that_checks_it():
    """The consistency suite only helps if the agent knows to run it."""
    result = run_hook("doc_consistency_reminder.py", str(REPO_ROOT / "AGENTS.md"))

    assert result.returncode == 2
    assert "make test-repo" in result.stderr


def test_editing_an_unguarded_document_stays_silent():
    """`doc/` prose is not asserted by the root suite, so it needs no nudge."""
    result = run_hook(
        "doc_consistency_reminder.py", str(REPO_ROOT / "doc/ARCHITECTURE.md")
    )

    assert result.returncode == 0


@contextmanager
def python_file_in_repo(source: str):
    """Yield a temporary ``.py`` file inside the repository, then remove it."""
    with tempfile.NamedTemporaryFile(
        dir=REPO_ROOT, suffix=".py", mode="w", encoding="utf-8"
    ) as handle:
        handle.write(source)
        handle.flush()
        yield Path(handle.name)


def test_python_edits_are_formatted_in_place():
    """`black --check .` is a CI gate; a hook keeps it from ever being hit."""
    with python_file_in_repo("x = {'a':1,  'b':2}\n") as sample:
        run_hook("format_edited_file.py", str(sample))

        assert sample.read_text(encoding="utf-8") == 'x = {"a": 1, "b": 2}\n'


def test_a_file_outside_the_repository_is_left_alone(tmp_path: Path):
    """This project's formatting rules stop at this project's boundary.

    An agent working with `--add-dir`, or editing a file in the user's own
    dotfiles, must not have those files silently rewritten to this
    repository's black and ruff configuration.
    """
    outside = tmp_path / "someone_elses.py"
    outside.write_text("x = {'a':1,  'b':2}\n", encoding="utf-8")

    run_hook("format_edited_file.py", str(outside))

    assert outside.read_text(encoding="utf-8") == "x = {'a':1,  'b':2}\n"


def test_formatting_a_file_black_cannot_parse_does_not_fail_the_turn():
    """A syntax error mid-edit is normal; the hook must not turn it into noise."""
    with python_file_in_repo("def f(\n") as broken:
        assert run_hook("format_edited_file.py", str(broken)).returncode == 0


def is_ignored(relative: str) -> bool:
    """Return whether git deliberately keeps a path out of the working tree.

    The trailing slash matters: `.gitignore` spells build output as a directory
    pattern, and `git check-ignore` only matches one against a directory path.
    """
    return (
        subprocess.run(
            ["git", "check-ignore", "-q", f"{relative}/"],
            cwd=REPO_ROOT,
            check=False,
        ).returncode
        == 0
    )


@pytest.mark.parametrize(
    "rule",
    [r for r in settings()["permissions"]["deny"] if "(/" in r],
    ids=lambda r: r,
)
def test_every_anchored_deny_rule_names_a_real_path(rule: str):
    """A deny rule for a renamed path protects nothing and reads as protection.

    Build output — the Vite bundle, the DuckDB file — is legitimately absent
    from a fresh checkout, so being git-ignored counts as existing on purpose.
    """
    pattern = rule.split("(", 1)[1].rstrip(")").lstrip("/")
    literal = "/".join(
        part for part in pattern.split("/") if "*" not in part and part != "**"
    )

    assert (REPO_ROOT / literal).exists() or is_ignored(
        literal
    ), f"{rule} points at {literal}, which neither exists nor is git-ignored"


def rule_files() -> list[Path]:
    """Return every path-scoped rule, following the symlinks into the modules."""
    return sorted(RULES_DIR.glob("*.md"))


def rule_paths(rule: Path) -> list[str]:
    """Return the glob patterns a rule scopes itself to."""
    _, _, body = rule.read_text(encoding="utf-8").partition("---\n")
    front, _, _ = body.partition("---\n")
    return yaml.safe_load(front)["paths"]


def test_both_module_guides_load_as_rules():
    """Claude Code reads CLAUDE.md, not AGENTS.md.

    Without these links `ingester/AGENTS.md` and `agent/AGENTS.md` are never
    loaded in a session — an agent reaches them only by choosing to follow a
    link from the root file, which is not something to rely on.
    """
    linked = {file.resolve() for file in rule_files()}

    assert (REPO_ROOT / "ingester" / "AGENTS.md").resolve() in linked
    assert (REPO_ROOT / "agent" / "AGENTS.md").resolve() in linked


@pytest.mark.parametrize("rule", rule_files(), ids=lambda p: p.name)
def test_every_rule_is_scoped_to_files_that_exist(rule: Path):
    """An unscoped rule loads every session; a mis-scoped one loads never.

    Both failures are silent, and a renamed directory produces the second one,
    so the patterns are checked against the working tree the same way the
    repository tree in AGENTS.md is.
    """
    patterns = rule_paths(rule)

    assert patterns, f"{rule.name} has no `paths`, so it loads unconditionally"
    for pattern in patterns:
        assert list(REPO_ROOT.glob(pattern)), f"{rule.name}: {pattern} matches nothing"


def skill_files() -> list[Path]:
    """Return every skill definition."""
    return sorted(SKILLS_DIR.glob("*/SKILL.md"))


def skill_frontmatter(skill: Path) -> dict:
    """Return the YAML header of a skill definition."""
    _, _, body = skill.read_text(encoding="utf-8").partition("---\n")
    front, _, _ = body.partition("---\n")
    return yaml.safe_load(front)


@pytest.mark.parametrize("skill", skill_files(), ids=lambda p: p.parent.name)
def test_every_skill_declares_a_name_matching_its_directory(skill: Path):
    """The directory name is what `/name` invokes; a mismatch is unreachable."""
    front = skill_frontmatter(skill)

    assert front["name"] == skill.parent.name
    assert front["description"].strip(), f"{skill.parent.name} has no description"


def test_every_skill_claude_md_points_at_exists():
    """A `/skill` in the always-loaded file is a promise about what is there."""
    referenced = set(
        re.findall(
            r"`/([a-z][a-z0-9-]*)`", (REPO_ROOT / "CLAUDE.md").read_text("utf-8")
        )
    )
    available = {skill.parent.name for skill in skill_files()}

    assert referenced, "CLAUDE.md points at no skill"
    assert (
        referenced <= available
    ), f"CLAUDE.md points at missing skills: {referenced - available}"
