"""The two built-in hunt catalogues, described once for the tests that span both.

``builtin_hunts.yaml`` and ``suzaku_timeline_hunts.yaml`` are the same kind of
artifact: a list of hunts, each carrying reviewed SQL that the page runs without
an API key. Their columns differ, but the rules that never mention a column do
not — a chart config has to name the columns its SQL returns, a query must not
filter on the machine's clock, and every hunt has to ship SQL.

Those rules were written for the CloudTrail catalogue and applied to it alone,
which is how the Suzaku catalogue shipped six bar charts with their axes
reversed: the test that would have caught it existed, and simply did not look at
that file. This module states what a catalogue *is* — where its hunts live and
what schema its SQL binds against — so a test can be written once and cover
every hunt Senrigan ships.

Nothing here is a test; it is imported by ``test_hunt_chart_configs.py`` and
``test_hunt_hygiene.py``.
"""

from __future__ import annotations

import pathlib
import re
from dataclasses import dataclass
from typing import Any

import duckdb
import yaml

AGENT_DIR = pathlib.Path(__file__).parent.parent
REPO_ROOT = AGENT_DIR.parent

TIMELINE_FIXTURE = (
    REPO_ROOT / "sample" / "suzaku" / "fixtures" / "suzaku-aws-ct-timeline.duckdb"
)

# The full cloudtrail_events schema (17 core + 7 GeoIP + 24 extended). Hunt SQL
# may use any of them, including the 18 columns withheld from the LLM.
CORE_COLUMNS = [
    "event_time TIMESTAMP",
    "event_name VARCHAR",
    "event_source VARCHAR",
    "aws_region VARCHAR",
    "source_ip_address VARCHAR",
    "user_agent VARCHAR",
    "user_identity_type VARCHAR",
    "user_identity_arn VARCHAR",
    "user_identity_account_id VARCHAR",
    "request_parameters VARCHAR",
    "response_elements VARCHAR",
    "error_code VARCHAR",
    "error_message VARCHAR",
    "read_only BOOLEAN",
    "event_type VARCHAR",
    "recipient_account_id VARCHAR",
    "raw_event VARCHAR",
]
GEO_COLUMNS = [
    "geo_country_code VARCHAR",
    "geo_country_name VARCHAR",
    "geo_city VARCHAR",
    "geo_latitude DOUBLE",
    "geo_longitude DOUBLE",
    "geo_asn VARCHAR",
    "geo_org VARCHAR",
]
EXTENDED_COLUMNS = [
    "user_identity_principal_id VARCHAR",
    "user_identity_access_key_id VARCHAR",
    "user_identity_user_name VARCHAR",
    "user_identity_invoked_by VARCHAR",
    "session_mfa_authenticated VARCHAR",
    "session_creation_date VARCHAR",
    "session_issuer_type VARCHAR",
    "session_issuer_arn VARCHAR",
    "session_issuer_account_id VARCHAR",
    "session_issuer_user_name VARCHAR",
    "session_issuer_principal_id VARCHAR",
    "event_id VARCHAR",
    "event_category VARCHAR",
    "shared_event_id VARCHAR",
    "vpc_endpoint_id VARCHAR",
    "resources VARCHAR",
    "additional_event_data VARCHAR",
    "service_event_details VARCHAR",
    "tls_version VARCHAR",
    "tls_cipher_suite VARCHAR",
    "tls_client_provided_host_header VARCHAR",
    "management_event VARCHAR",
    "session_credential_from_console VARCHAR",
    "api_version VARCHAR",
]


@dataclass(frozen=True)
class Catalogue:
    """One hunt YAML together with the schema its SQL binds against.

    Attributes:
        key:      Short identifier, used as the prefix of every test id.
        filename: The YAML, relative to the agent package.
        table:    The table the hunts query, named in failure messages.
    """

    key: str
    filename: str
    table: str

    @property
    def path(self) -> pathlib.Path:
        """Absolute path to the catalogue's YAML."""
        return AGENT_DIR / self.filename

    def hunts(self) -> list[dict[str, Any]]:
        """Every hunt in the catalogue, in file order."""
        return yaml.safe_load(self.path.read_text(encoding="utf-8"))

    def sql_hunts(self) -> list[dict[str, Any]]:
        """The hunts that ship pre-built SQL."""
        return [hunt for hunt in self.hunts() if hunt.get("sql")]

    def charted_hunts(self) -> list[dict[str, Any]]:
        """The hunts that carry both a chart config and pre-built SQL."""
        return [hunt for hunt in self.sql_hunts() if hunt.get("chart")]

    def connect(self) -> duckdb.DuckDBPyConnection:
        """Open a connection whose schema this catalogue's SQL binds against.

        CloudTrail gets an empty table built from the production column list —
        no rows are needed to read a result's column names and types. Suzaku's
        schema is not ours to declare, so its hunts bind against the committed
        fixture, which is real Suzaku output.
        """
        if self.key == "cloudtrail":
            conn = duckdb.connect(":memory:")
            columns = CORE_COLUMNS + GEO_COLUMNS + EXTENDED_COLUMNS
            conn.execute(f"CREATE TABLE {self.table} ({', '.join(columns)})")
            return conn
        return duckdb.connect(str(TIMELINE_FIXTURE), read_only=True)


CATALOGUES: tuple[Catalogue, ...] = (
    Catalogue(
        key="cloudtrail", filename="builtin_hunts.yaml", table="cloudtrail_events"
    ),
    Catalogue(
        key="suzaku_timeline",
        filename="suzaku_timeline_hunts.yaml",
        table="timeline",
    ),
)


def hunt_params(
    select: str = "sql",
) -> tuple[list[tuple[Catalogue, dict]], list[str]]:
    """Return ``(params, ids)`` for parametrizing over every catalogue's hunts.

    Args:
        select: Which hunts to include — ``"sql"``, ``"charted"``, ``"bar"`` or
                ``"timeseries"``.

    Returns:
        The ``(catalogue, hunt)`` pairs and their test ids, the id naming both
        the catalogue and the hunt so a failure says which file to open.
    """
    pairs: list[tuple[Catalogue, dict]] = []
    for catalogue in CATALOGUES:
        if select == "sql":
            hunts = catalogue.sql_hunts()
        elif select == "charted":
            hunts = catalogue.charted_hunts()
        else:
            hunts = [
                hunt
                for hunt in catalogue.charted_hunts()
                if hunt["chart"].get("type") == select
            ]
        pairs.extend((catalogue, hunt) for hunt in hunts)
    return pairs, [f"{cat.key}: {hunt['label']}" for cat, hunt in pairs]


# Functions that read the machine's clock. Cloud logs are historical by the time
# they are ingested, so any of these silently empties a hunt.
WALL_CLOCK_RE = re.compile(
    r"\b(now\(\)|current_timestamp|current_date|today\(\)|get_current_time)",
    re.IGNORECASE,
)

# A named zone hardcodes one team's working day into a tool shipped in 15
# locales. Hunts report in UTC and say so in the column name.
NAMED_TIMEZONE_RE = re.compile(
    r"AT TIME ZONE\s*'(?!UTC')[^']+'|'(?:Asia|Europe|America|Africa|Australia)/[^']+'",
    re.IGNORECASE,
)
