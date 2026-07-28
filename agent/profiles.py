"""Dataset profiles — one description per queryable table.

The hunting pipeline (schema description, system prompt, filter injection,
session state) was written against ``cloudtrail_events``. A profile lifts those
assumptions into data so the same pipeline can serve Suzaku's ``timeline`` table
without a second copy of it.

Every parameterized function keeps :data:`CLOUDTRAIL_PROFILE` as its default, so
existing callers — and the existing tests — behave exactly as before.

See ``doc/PLAN_SUZAKU_VIEWS.md`` §4.1.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from prompts.suzaku_timeline_prompt import SUZAKU_TIMELINE_SYSTEM_PROMPT
from prompts.system_prompt import SYSTEM_PROMPT
from schema import (
    CLOUDTRAIL_COLUMNS,
    SUZAKU_TIMELINE_COLUMNS,
    get_schema_description,
)

_AGENT_DIR = Path(__file__).resolve().parent

# Session-state keys that stay global across pages. The API key, model choice and
# row cap are settings an analyst enters once; re-entering them per page would be
# a worse UI, not an isolation win.
SHARED_STATE_KEYS: frozenset[str] = frozenset(
    {
        "api_key",
        "model",
        "row_limit",
        "geo_enrich",
        "db_variant",
    }
)


@dataclass(frozen=True)
class DatasetProfile:
    """Everything the hunting pipeline needs to know about one table.

    Attributes:
        key:                 Stable identifier, also the :data:`PROFILES` key.
        label:               Human-readable name for navigation and headings.
        icon:                Emoji shown next to *label*.
        table:               Table name queried by hunts and generated SQL.
        time_column:         Column used by the date-range filter.
        columns:             Column metadata fed to the LLM (see ``schema.py``).
        hunts_filename:      Built-in hunts YAML, relative to the agent package.
        time_is_varchar:     When True the date filter CASTs *time_column*.
        quote_identifiers:   When True identifiers are double-quoted in SQL.
        level_column:        Severity column, or None when the table has none.
        level_order:         Severity values, most severe first.
        default_levels:      Severities selected by default in the UI.
        supports_geo_enrich: Whether ``geo.py`` can enrich results from *table*.
        state_prefix:        Prefix applied to per-page session-state keys.
        default_row_limit:   Initial per-query row cap.
        system_prompt:       Prompt template containing a ``{schema}`` slot.
    """

    key: str
    label: str
    icon: str
    table: str
    time_column: str
    columns: tuple[dict, ...] | list[dict]
    hunts_filename: str
    time_is_varchar: bool = False
    quote_identifiers: bool = False
    level_column: str | None = None
    level_order: tuple[str, ...] = ()
    default_levels: tuple[str, ...] = ()
    supports_geo_enrich: bool = True
    state_prefix: str | None = None
    default_row_limit: int = 200
    system_prompt: str = SYSTEM_PROMPT
    filter_alias: str = ""

    def __post_init__(self) -> None:
        """Derive the CTE alias and state prefix when the caller omitted them.

        A future dataset therefore needs no extra plumbing: both default to
        something unique per ``key``. ``CLOUDTRAIL_PROFILE`` passes an explicit
        empty prefix, which is what keeps its session-state keys unchanged.
        """
        if not self.filter_alias:
            object.__setattr__(self, "filter_alias", f"_{self.key}_filtered")
        if self.state_prefix is None:
            object.__setattr__(self, "state_prefix", f"{self.key}_")

    @property
    def hunts_path(self) -> Path:
        """Absolute path to this profile's built-in hunts YAML."""
        return _AGENT_DIR / self.hunts_filename

    def state_key(self, name: str) -> str:
        """Return the session-state key *name* scoped to this profile.

        Per-page state (chat history, results, filters, notes) is prefixed so two
        pages never overwrite each other; the keys in :data:`SHARED_STATE_KEYS`
        stay global.

        Args:
            name: Logical state name, e.g. ``"query_history"``.

        Returns:
            The key to use with ``st.session_state``.
        """
        if name in SHARED_STATE_KEYS:
            return name
        return f"{self.state_prefix}{name}"

    def quote(self, identifier: str) -> str:
        """Return *identifier* quoted when this profile's table requires it.

        Suzaku's columns are PascalCase, so every reference must be
        double-quoted; ``cloudtrail_events`` columns are snake_case and stay
        bare, keeping generated SQL readable.

        Args:
            identifier: A column name.

        Returns:
            The identifier, double-quoted where needed.
        """
        if not self.quote_identifiers:
            return identifier
        escaped = identifier.replace('"', '""')
        return f'"{escaped}"'

    def schema_description(self) -> str:
        """Return the Markdown schema description used in the system prompt."""
        return get_schema_description(self.table, self.columns)

    def build_system_prompt(self) -> str:
        """Return the system prompt for this profile with the schema injected."""
        return self.system_prompt.format(schema=self.schema_description())


CLOUDTRAIL_PROFILE = DatasetProfile(
    key="cloudtrail",
    label="Senrigan",
    icon="🔭",
    table="cloudtrail_events",
    time_column="event_time",
    columns=CLOUDTRAIL_COLUMNS,
    hunts_filename="builtin_hunts.yaml",
    # The alias is pinned rather than derived: it appears in generated SQL, in
    # reports, and in the existing tests.
    filter_alias="_ct_filtered",
    state_prefix="",
    default_row_limit=200,
    system_prompt=SYSTEM_PROMPT,
)

SUZAKU_TIMELINE_PROFILE = DatasetProfile(
    key="suzaku_timeline",
    label="Suzaku Timeline",
    icon="🕒",
    table="timeline",
    time_column="Timestamp",
    columns=SUZAKU_TIMELINE_COLUMNS,
    hunts_filename="suzaku_timeline_hunts.yaml",
    quote_identifiers=True,
    level_column="Level",
    level_order=("critical", "high", "medium", "low", "informational"),
    # low + informational are ~87% of the reference dataset; starting with them
    # off is what makes the page usable at all.
    default_levels=("critical", "high", "medium"),
    supports_geo_enrich=False,
    state_prefix="sz_",
    default_row_limit=200,
    system_prompt=SUZAKU_TIMELINE_SYSTEM_PROMPT,
    filter_alias="_sz_filtered",
)

PROFILES: dict[str, DatasetProfile] = {
    CLOUDTRAIL_PROFILE.key: CLOUDTRAIL_PROFILE,
    SUZAKU_TIMELINE_PROFILE.key: SUZAKU_TIMELINE_PROFILE,
}
