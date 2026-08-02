"""Dataset profiles — one description per queryable table.

The hunting pipeline (schema description, system prompt, filter injection,
session state) was written against ``cloudtrail_events``. A profile lifts those
assumptions into data so the same pipeline can serve Suzaku's ``timeline`` table
without a second copy of it.

Every parameterized function keeps :data:`CLOUDTRAIL_PROFILE` as its default, so
existing callers — and the existing tests — behave exactly as before.

Two of the four profiles describe **explorer** pages rather than chat pages:
Suzaku's ``aws-ct-summary`` and ``aws-ct-metrics`` output is already aggregated,
so those pages run reviewed, parameterized SQL and never generate any. They are
marked :attr:`DatasetProfile.chat_enabled` ``False``, and the chat-only members
raise for them rather than returning something empty.
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
from suzaku_db import SuzakuKind

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
        chat_enabled:        True for a page that generates SQL with an LLM;
                             False for an explorer page whose SQL is reviewed
                             and lives in the repository.
        suzaku_kind:         The Suzaku command whose output this profile reads,
                             or None for Senrigan's own database.
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
    chat_enabled: bool = True
    suzaku_kind: SuzakuKind | None = None

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

    def _require_chat(self, member: str) -> None:
        """Raise when a chat-pipeline member is used on an explorer profile.

        Args:
            member: The member being accessed, named in the message.

        Raises:
            ValueError: When this profile has ``chat_enabled=False``.
        """
        if not self.chat_enabled:
            raise ValueError(
                f"{self.key} is an explorer profile: {member} does not apply. "
                "Its page runs reviewed SQL and never generates any."
            )

    @property
    def hunts_path(self) -> Path:
        """Absolute path to this profile's built-in hunts YAML.

        Raises:
            ValueError: When this profile has no chat pipeline.
        """
        self._require_chat("hunts_path")
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
        """Return the system prompt for this profile with the schema injected.

        Raises:
            ValueError: When this profile has no chat pipeline.
        """
        self._require_chat("build_system_prompt()")
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
    suzaku_kind=SuzakuKind.TIMELINE,
)

# The two explorer profiles. `columns` is empty and `hunts_filename` blank
# because neither reaches the LLM: their pages run the reviewed SQL in
# `suzaku_summary_queries.py` / `suzaku_metrics_queries.py`. `table` and
# `time_column` still describe the file, since the report header and the
# database selector both read them.
SUZAKU_SUMMARY_PROFILE = DatasetProfile(
    key="suzaku_summary",
    label="Suzaku Summary",
    icon="👤",
    table="summary",
    time_column="FirstTimestamp",
    columns=(),
    hunts_filename="",
    quote_identifiers=True,
    supports_geo_enrich=False,
    state_prefix="szs_",
    chat_enabled=False,
    suzaku_kind=SuzakuKind.SUMMARY,
)

SUZAKU_METRICS_PROFILE = DatasetProfile(
    key="suzaku_metrics",
    label="Suzaku Metrics",
    icon="📊",
    table="metrics",
    time_column="FirstSeen",
    columns=(),
    hunts_filename="",
    quote_identifiers=True,
    supports_geo_enrich=False,
    state_prefix="szm_",
    chat_enabled=False,
    suzaku_kind=SuzakuKind.METRICS,
)

PROFILES: dict[str, DatasetProfile] = {
    CLOUDTRAIL_PROFILE.key: CLOUDTRAIL_PROFILE,
    SUZAKU_TIMELINE_PROFILE.key: SUZAKU_TIMELINE_PROFILE,
    SUZAKU_SUMMARY_PROFILE.key: SUZAKU_SUMMARY_PROFILE,
    SUZAKU_METRICS_PROFILE.key: SUZAKU_METRICS_PROFILE,
}
