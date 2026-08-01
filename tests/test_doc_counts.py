"""Tests pinning every documented count to the artifact that produces it.

Covers PLAN_DOCS_REFRESH.md Phase 1. A count written in prose is a copy of a
fact that lives somewhere else, and the copy goes stale the moment a chart or a
hunt is added — as happened when the Suzaku Run Info card landed and three
documents kept quoting the pre-provenance numbers. These tests make the asset
the owner and check the prose against it, so a count can only be wrong for as
long as CI takes to run.

Chart and hunt *names* stay in English in every locale, so the name-level tests
run against all 15 translations, not just the source page.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.conftest import (
    REPO_ROOT,
    WEBSITE_DOCS,
    chart_names,
    dataset_names,
    hunt_categories,
    hunt_labels,
    site_locales,
)

DASHBOARD_README = REPO_ROOT / "dashboard" / "README.md"
SUZAKU_REFERENCE = WEBSITE_DOCS / "reference" / "suzaku.md"
REFERENCE_PAGES = sorted((WEBSITE_DOCS / "reference").glob("index*.md"))

SUZAKU_BUNDLES = ["suzaku_timeline", "suzaku_summary", "suzaku_metrics"]

# `aws-ct-<command>` as the reference page names it → the bundle it feeds.
SUZAKU_COMMAND_BUNDLE = {
    "timeline": "suzaku_timeline",
    "summary": "suzaku_summary",
    "metrics": "suzaku_metrics",
}

# A row of a numbered reference table: `| 12 | 🔑 Some Chart | bar | ... |`.
_NUMBERED_ROW_RE = re.compile(r"^\|\s*\d+\s*\|([^|]+)\|", re.MULTILINE)


def numbered_row_names(text: str) -> list[str]:
    """Return the name column of every numbered table row in ``text``."""
    return [name.strip() for name in _NUMBERED_ROW_RE.findall(text)]


def full_list_sections(page: Path) -> tuple[str, str]:
    """Split a reference page into its hunts half and its charts half.

    Each half is a ``<details>`` block holding one exhaustive table, so the
    closing tags are the only boundary that survives translation.
    """
    blocks = page.read_text(encoding="utf-8").split("</details>")
    assert len(blocks) == 3, f"{page.name} has {len(blocks) - 1} <details> blocks"
    return blocks[0], blocks[1]


def heading_number(text: str, emoji: str) -> int:
    """Return the count stated in the ``## <emoji> …`` heading.

    Locales phrase the heading differently and some drop the spaces around the
    dash, but every one of them puts exactly one number in it.
    """
    heading = re.search(rf"^## {emoji}.*$", text, re.MULTILINE)
    assert heading, f"no `## {emoji}` heading found"
    numbers = re.findall(r"\d+", heading.group(0))
    assert len(numbers) == 1, f"expected one number in {heading.group(0)!r}"
    return int(numbers[0])


@pytest.mark.parametrize("bundle", SUZAKU_BUNDLES)
def test_dashboard_readme_states_the_real_suzaku_chart_count(bundle: str):
    """The module README's directory tree annotates each bundle with its size."""
    text = DASHBOARD_README.read_text(encoding="utf-8")
    match = re.search(rf"{bundle}\.zip.*?\((\d+) charts\)", text)

    assert match, f"{bundle}.zip carries no chart count in dashboard/README.md"
    assert int(match.group(1)) == len(chart_names(bundle))


@pytest.mark.parametrize("bundle", SUZAKU_BUNDLES)
def test_dashboard_readme_states_the_real_dataset_count(bundle: str):
    """Same tree annotates the asset directories with their dataset count."""
    text = DASHBOARD_README.read_text(encoding="utf-8")
    match = re.search(rf"{bundle}/\s+#.*?\((\d+) virtual datasets\)", text)

    if match is None:  # Not every bundle states one; when it does, it must be right.
        pytest.skip(f"{bundle}/ states no dataset count")
    assert int(match.group(1)) == len(dataset_names(bundle))


@pytest.mark.parametrize("command,bundle", sorted(SUZAKU_COMMAND_BUNDLE.items()))
def test_suzaku_reference_states_the_real_chart_count(command: str, bundle: str):
    """The site's Suzaku page maps each Suzaku command to a dashboard size."""
    text = SUZAKU_REFERENCE.read_text(encoding="utf-8")
    row = re.search(rf"^\|\s*`aws-ct-{command}`.*$", text, re.MULTILINE)
    assert row, f"aws-ct-{command} has no row in the visualization table"

    match = re.search(r"\((\d+) charts\)", row.group(0))
    if match is None:
        pytest.skip(f"aws-ct-{command} states no chart count")
    assert int(match.group(1)) == len(chart_names(bundle))


def test_suzaku_reference_states_the_real_timeline_hunt_count():
    """`aws-ct-timeline` is the one command with an agent page, so it has hunts."""
    text = SUZAKU_REFERENCE.read_text(encoding="utf-8")
    match = re.search(r"(\d+) built-in hunts", text)

    assert match, "the Suzaku Timeline page's hunt count is not stated"
    assert int(match.group(1)) == len(hunt_labels("suzaku_timeline_hunts.yaml"))


def test_suzaku_reference_names_every_timeline_hunt_category():
    """A new hunt in a new category must reach the prose, not just the count."""
    text = SUZAKU_REFERENCE.read_text(encoding="utf-8")

    missing = sorted(
        category
        for category in hunt_categories("suzaku_timeline_hunts.yaml")
        if category not in text
    )
    assert not missing, f"undocumented hunt categories: {missing}"


@pytest.mark.parametrize("page", REFERENCE_PAGES, ids=lambda p: p.name)
def test_reference_page_headings_state_the_real_counts(page: Path):
    """The two section headings are the numbers a reader sees first."""
    text = page.read_text(encoding="utf-8")

    assert heading_number(text, "🎯") == len(hunt_labels("builtin_hunts.yaml"))
    assert heading_number(text, "📊") == len(chart_names("cloudtrail_default"))


@pytest.mark.parametrize("page", REFERENCE_PAGES, ids=lambda p: p.name)
def test_reference_page_full_list_summaries_state_the_real_counts(page: Path):
    """The two `<summary>` lines repeat the counts; they must repeat them right."""
    summaries = re.findall(r"<summary>(.*?)</summary>", page.read_text("utf-8"))
    assert len(summaries) == 2, f"{page.name} has {len(summaries)} summary lines"

    stated = [int(re.search(r"\d+", summary).group(0)) for summary in summaries]
    assert stated == [
        len(hunt_labels("builtin_hunts.yaml")),
        len(chart_names("cloudtrail_default")),
    ]


@pytest.mark.parametrize("page", REFERENCE_PAGES, ids=lambda p: p.name)
def test_reference_page_lists_every_builtin_hunt(page: Path):
    """Names are not translated, so every locale lists the same 126 hunts."""
    hunts, _ = full_list_sections(page)
    documented = numbered_row_names(hunts)

    assert set(documented) == set(hunt_labels("builtin_hunts.yaml"))
    assert len(documented) == len(set(documented)), "a hunt is listed twice"


@pytest.mark.parametrize("page", REFERENCE_PAGES, ids=lambda p: p.name)
def test_reference_page_lists_every_dashboard_chart(page: Path):
    """Charts are listed per tab, so one chart shared by two tabs appears twice.

    That is why this compares sets and the heading test compares the distinct
    count — the per-tab table legitimately sums to more than the total.
    """
    _, charts = full_list_sections(page)

    assert set(numbered_row_names(charts)) == chart_names("cloudtrail_default")


def test_every_locale_ships_a_reference_page():
    """A missing locale silently falls back to English and looks up to date."""
    expected = {"index.md"} | {
        f"index.{locale}.md" for locale in site_locales()[1:]  # [0] is the default
    }

    assert {page.name for page in REFERENCE_PAGES} == expected


def test_test_count_lines_agree_across_the_agent_context_files():
    """`CLAUDE.md` and `AGENTS.md` state suite sizes; they must state the same.

    Both warn that a stale count causes false regression alarms, and both are
    edited by hand — this is the failure mode that warning describes.
    """
    pattern = re.compile(
        r"ingester ≈ (\d+).*?agent ≈ (\d+).*?config_viz ≈ (\d+) backend \+\s*"
        r"(\d+) frontend.*?dashboard ≈ (\d+).*?root `tests/` ≈ (\d+)",
        re.DOTALL,
    )
    counts = []
    for name in ("CLAUDE.md", "AGENTS.md"):
        match = pattern.search((REPO_ROOT / name).read_text(encoding="utf-8"))
        assert match, f"{name} has no parseable test-total line"
        counts.append(match.groups())

    assert counts[0] == counts[1], "CLAUDE.md and AGENTS.md disagree on suite sizes"


def test_inline_suite_sizes_agree_with_the_totals_line():
    """`AGENTS.md` also annotates its per-module commands with a suite size.

    Three copies of the same number in one file is how `dashboard` ended up
    quoting 605 tests long after the suite had grown to 793.
    """
    text = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
    inline = {
        label: int(count) for count, label in re.findall(r"\((\d+) (\w+) tests\)", text)
    }
    assert set(inline) >= {
        "backend",
        "frontend",
        "dashboard",
    }, f"AGENTS.md no longer labels its inline suite sizes: {sorted(inline)}"

    totals = dict(
        zip(
            ("ingester", "agent", "backend", "frontend", "dashboard", "root"),
            (
                int(n)
                for n in re.search(
                    r"ingester ≈ (\d+).*?agent ≈ (\d+).*?config_viz ≈ (\d+) backend \+\s*"
                    r"(\d+) frontend.*?dashboard ≈ (\d+).*?root `tests/` ≈ (\d+)",
                    text,
                    re.DOTALL,
                ).groups()
            ),
        )
    )

    mismatched = {
        label: (count, totals[label])
        for label, count in inline.items()
        if label in totals and count != totals[label]
    }
    assert not mismatched, f"inline count vs totals line: {mismatched}"
