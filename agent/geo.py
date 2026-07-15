"""Automatic GeoIP enrichment of query result DataFrames.

Whenever a query result contains an IP address column, the functions here
join the GeoIP columns already stored on ``cloudtrail_events``
(``geo_country_code``, ``geo_city``, ``geo_org``) next to it, so analysts
see geographical context without a manual lookup.

Enrichment is purely local: only values previously written by
``ingester enrich`` are used — no live GeoIP lookups are performed.
"""

import logging
import re

import duckdb
import pandas as pd

logger = logging.getLogger(__name__)

# Geo columns joined next to each detected IP column, in display order.
GEO_ENRICH_COLUMNS: list[str] = ["geo_country_code", "geo_city", "geo_org"]

# Cap on distinct IPs sent to a single lookup query.
MAX_LOOKUP_IPS: int = 1000

# Number of non-null sample values inspected per column when confirming
# that a name-matched column actually holds IP addresses.
_VALUE_SAMPLE_SIZE: int = 20

# Column names that plausibly hold IP addresses (matched case-insensitively).
_IP_NAME_PATTERN = re.compile(r"(^ip$|_ip$|ip_address)", re.IGNORECASE)

# Loose IPv4 / IPv6 shapes — enough to separate IPs from service domains
# such as "cloudformation.amazonaws.com" or "AWS Internal".
_IPV4_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_IPV6_PATTERN = re.compile(r"^[0-9A-Fa-f:]*:[0-9A-Fa-f:]+$")


def _looks_like_ip(value: object) -> bool:
    """Return True when *value* is a string shaped like an IPv4/IPv6 address."""
    if not isinstance(value, str):
        return False
    return bool(_IPV4_PATTERN.match(value) or _IPV6_PATTERN.match(value))


def find_ip_columns(df: pd.DataFrame) -> list[str]:
    """Return the columns of *df* that hold IP addresses.

    A column qualifies when its name matches an IP-like pattern
    (``source_ip_address``, ``*_ip``, ``ip_address``, ``ip``) AND at least one
    sampled non-null value is shaped like an IPv4/IPv6 address. The value
    check avoids false positives on CloudTrail columns that hold service
    domains (e.g. "cloudformation.amazonaws.com") instead of addresses.

    Args:
        df: Query result DataFrame.

    Returns:
        Matching column names in *df* column order.
    """
    ip_columns: list[str] = []
    for column in df.columns:
        if not _IP_NAME_PATTERN.search(str(column)):
            continue
        sample = df[column].dropna().head(_VALUE_SAMPLE_SIZE)
        if any(_looks_like_ip(value) for value in sample):
            ip_columns.append(column)
    return ip_columns


def _lookup_geo(conn: duckdb.DuckDBPyConnection, ips: list[str]) -> pd.DataFrame:
    """Fetch geo attributes for *ips* from cloudtrail_events.

    ``GROUP BY`` guarantees one row per IP so the caller's merge can never
    fan out result rows, even when the DB holds many events per IP.
    """
    placeholders = ", ".join("?" for _ in ips)
    geo_selects = ", ".join(f"MAX({col}) AS {col}" for col in GEO_ENRICH_COLUMNS)
    return conn.execute(
        f"SELECT source_ip_address AS _geo_lookup_ip, {geo_selects} "
        f"FROM cloudtrail_events "
        f"WHERE source_ip_address IN ({placeholders}) "
        f"GROUP BY source_ip_address",
        ips,
    ).df()


def enrich_with_geo(
    conn: duckdb.DuckDBPyConnection,
    df: pd.DataFrame,
    max_ips: int = MAX_LOOKUP_IPS,
) -> pd.DataFrame:
    """Left-merge geo columns next to each IP column of *df*.

    No-op when *df* is empty, has no IP column, or already contains a
    ``geo_*`` column (the query author opted in manually). The first IP
    column receives the plain ``GEO_ENRICH_COLUMNS`` names; further IP
    columns get names prefixed with the IP column name to avoid collisions.
    IP columns whose lookup yields no geo data at all (e.g. the DB was
    ingested without GeoIP databases) are skipped so all-NULL columns never
    clutter the result.

    Args:
        conn:    An open READ_ONLY DuckDB connection.
        df:      Query result DataFrame to enrich.
        max_ips: Maximum number of distinct IPs per lookup query; IPs beyond
                 the cap keep NULL geo values.

    Returns:
        The enriched DataFrame, or *df* unchanged when there is nothing to do.
    """
    if df.empty:
        return df
    if any(str(col).startswith("geo_") for col in df.columns):
        return df
    ip_columns = find_ip_columns(df)
    if not ip_columns:
        return df

    enriched = df
    for position, ip_column in enumerate(ip_columns):
        ips = [
            value
            for value in pd.unique(enriched[ip_column].dropna())
            if _looks_like_ip(value)
        ][:max_ips]
        if not ips:
            continue
        lookup = _lookup_geo(conn, ips)
        if lookup.empty or lookup[GEO_ENRICH_COLUMNS].isna().all().all():
            continue

        prefix = "" if position == 0 else f"{ip_column}_"
        lookup = lookup.rename(
            columns={col: f"{prefix}{col}" for col in GEO_ENRICH_COLUMNS}
        )
        merged = enriched.merge(
            lookup, how="left", left_on=ip_column, right_on="_geo_lookup_ip"
        ).drop(columns=["_geo_lookup_ip"])

        # Move the new geo columns from the end to just after the IP column.
        geo_names = [f"{prefix}{col}" for col in GEO_ENRICH_COLUMNS]
        ordered = [col for col in merged.columns if col not in geo_names]
        insert_at = ordered.index(ip_column) + 1
        ordered[insert_at:insert_at] = geo_names
        enriched = merged[ordered]

    return enriched
