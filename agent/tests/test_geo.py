"""Tests for geo.py — automatic GeoIP enrichment of query result DataFrames."""

import duckdb
import pandas as pd
import pytest

from geo import enrich_with_geo, find_ip_columns

# ---------------------------------------------------------------------------
# find_ip_columns()
# ---------------------------------------------------------------------------


def test_find_ip_columns_detects_source_ip_address():
    """Test G-1: the canonical source_ip_address column is detected."""
    df = pd.DataFrame(
        {
            "event_name": ["ConsoleLogin"],
            "source_ip_address": ["203.0.113.10"],
        }
    )

    assert find_ip_columns(df) == ["source_ip_address"]


def test_find_ip_columns_detects_aliased_ip_column():
    """Test G-2: an LLM-aliased column (e.g. "AS ip") with IP values is detected."""
    df = pd.DataFrame(
        {
            "ip": ["198.51.100.7", "2001:db8::1"],
            "event_count": [12, 3],
        }
    )

    assert find_ip_columns(df) == ["ip"]


def test_find_ip_columns_ignores_ip_named_column_without_ip_values():
    """Test G-3: a name match alone is not enough — values must look like IPs.

    CloudTrail's source_ip_address often holds service domains
    (e.g. "cloudformation.amazonaws.com"); a column holding ONLY such values
    has nothing to geo-enrich.
    """
    df = pd.DataFrame(
        {
            "source_ip_address": ["cloudformation.amazonaws.com", "AWS Internal"],
            "principal_ip_address": [None, None],
            "description": ["203.0.113.10", "198.51.100.7"],
        }
    )

    assert find_ip_columns(df) == []


# ---------------------------------------------------------------------------
# enrich_with_geo()
# ---------------------------------------------------------------------------


_GEO_SCHEMA = """
    CREATE TABLE cloudtrail_events (
        event_name        VARCHAR,
        source_ip_address VARCHAR,
        geo_country_code  VARCHAR,
        geo_country_name  VARCHAR,
        geo_city          VARCHAR,
        geo_latitude      DOUBLE,
        geo_longitude     DOUBLE,
        geo_asn           VARCHAR,
        geo_org           VARCHAR
    )
"""


@pytest.fixture
def geo_conn():
    """In-memory DuckDB with geo-enriched cloudtrail_events rows."""
    conn = duckdb.connect(":memory:")
    conn.execute(_GEO_SCHEMA)
    conn.execute("""
        INSERT INTO cloudtrail_events
            (event_name, source_ip_address, geo_country_code, geo_city, geo_org)
        VALUES
            ('ConsoleLogin', '203.0.113.10', 'US', 'Ashburn', 'Amazon.com Inc.'),
            ('ConsoleLogin', '203.0.113.10', 'US', 'Ashburn', 'Amazon.com Inc.'),
            ('ConsoleLogin', '203.0.113.10', 'US', 'Ashburn', 'Amazon.com Inc.'),
            ('CreateUser',   '198.51.100.7', 'JP', 'Tokyo',   'Example ISP')
        """)
    yield conn
    conn.close()


@pytest.fixture
def no_geo_conn():
    """In-memory DuckDB whose rows were ingested without GeoIP databases."""
    conn = duckdb.connect(":memory:")
    conn.execute(_GEO_SCHEMA)
    conn.execute("""
        INSERT INTO cloudtrail_events (event_name, source_ip_address)
        VALUES ('ConsoleLogin', '203.0.113.10')
        """)
    yield conn
    conn.close()


def test_enrich_appends_geo_columns_after_ip_column(geo_conn):
    """Test G-4: geo columns are inserted directly after the IP column."""
    df = pd.DataFrame(
        {
            "event_name": ["ConsoleLogin", "CreateUser"],
            "source_ip_address": ["203.0.113.10", "198.51.100.7"],
            "event_count": [3, 1],
        }
    )

    enriched = enrich_with_geo(geo_conn, df)

    assert list(enriched.columns) == [
        "event_name",
        "source_ip_address",
        "geo_country_code",
        "geo_city",
        "geo_org",
        "event_count",
    ]
    assert enriched["geo_country_code"].tolist() == ["US", "JP"]
    assert enriched["geo_city"].tolist() == ["Ashburn", "Tokyo"]
    assert enriched["geo_org"].tolist() == ["Amazon.com Inc.", "Example ISP"]


def test_enrich_is_noop_when_geo_column_already_present(geo_conn):
    """Test G-5: a result that already selects any geo_* column is left alone."""
    df = pd.DataFrame(
        {
            "source_ip_address": ["203.0.113.10"],
            "geo_country_name": ["United States"],
        }
    )

    enriched = enrich_with_geo(geo_conn, df)

    pd.testing.assert_frame_equal(enriched, df)


def test_enrich_is_noop_on_empty_dataframe(geo_conn):
    """Test G-6: an empty result is returned unchanged."""
    df = pd.DataFrame({"source_ip_address": pd.Series(dtype="object")})

    enriched = enrich_with_geo(geo_conn, df)

    pd.testing.assert_frame_equal(enriched, df)


def test_enrich_unknown_ip_yields_null_geo_and_keeps_rows(geo_conn):
    """Test G-7: IPs absent from the DB get NULL geo values; no rows lost."""
    df = pd.DataFrame({"source_ip_address": ["203.0.113.10", "192.0.2.99"]})

    enriched = enrich_with_geo(geo_conn, df)

    assert len(enriched) == 2
    assert enriched["geo_country_code"].tolist()[0] == "US"
    assert pd.isna(enriched["geo_country_code"].tolist()[1])


def test_enrich_does_not_fan_out_rows(geo_conn):
    """Test G-8: an IP occurring in many DB rows must not duplicate result rows."""
    df = pd.DataFrame({"source_ip_address": ["203.0.113.10"]})

    enriched = enrich_with_geo(geo_conn, df)

    assert len(enriched) == 1


def test_enrich_caps_number_of_looked_up_ips(geo_conn):
    """Test G-9: beyond max_ips, extra IPs are skipped (NULL geo), no error."""
    df = pd.DataFrame(
        {
            "source_ip_address": [
                "203.0.113.10",
                "198.51.100.7",
                "192.0.2.99",
            ]
        }
    )

    enriched = enrich_with_geo(geo_conn, df, max_ips=1)

    assert len(enriched) == 3
    assert enriched["geo_country_code"].tolist()[0] == "US"
    assert pd.isna(enriched["geo_country_code"].tolist()[1])
    assert pd.isna(enriched["geo_country_code"].tolist()[2])


def test_enrich_prefixes_geo_columns_for_second_ip_column(geo_conn):
    """Test G-10: a second IP column gets name-prefixed geo columns."""
    df = pd.DataFrame(
        {
            "source_ip_address": ["203.0.113.10"],
            "peer_ip": ["198.51.100.7"],
        }
    )

    enriched = enrich_with_geo(geo_conn, df)

    assert list(enriched.columns) == [
        "source_ip_address",
        "geo_country_code",
        "geo_city",
        "geo_org",
        "peer_ip",
        "peer_ip_geo_country_code",
        "peer_ip_geo_city",
        "peer_ip_geo_org",
    ]
    assert enriched["geo_country_code"].tolist() == ["US"]
    assert enriched["peer_ip_geo_country_code"].tolist() == ["JP"]


def test_enrich_drops_columns_when_db_has_no_geo_data(no_geo_conn):
    """Test G-11: an un-geo-enriched DB must not add all-NULL clutter columns."""
    df = pd.DataFrame({"source_ip_address": ["203.0.113.10"]})

    enriched = enrich_with_geo(no_geo_conn, df)

    pd.testing.assert_frame_equal(enriched, df)
