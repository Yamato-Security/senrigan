"""Configuration management for the Senrigan agent.

Provides helpers for reading settings from environment variables.
"""

import os

# Default DuckDB path used when DUCKDB_PATH is not set.
DEFAULT_DUCKDB_PATH: str = "/data/db/threat_hunting.db"

# Labels used by the UI to identify the two database variants.
DB_VARIANT_FULL: str = "Full"
DB_VARIANT_LITE: str = "Lite"


def get_duckdb_path() -> str:
    """Return the DuckDB path from the DUCKDB_PATH environment variable.

    Safe to call without an OpenAI API key — suitable for use in the
    Streamlit agent where the API key is entered via the sidebar UI.

    Returns:
        The value of DUCKDB_PATH if set and non-empty, otherwise
        DEFAULT_DUCKDB_PATH.
    """
    return os.environ.get("DUCKDB_PATH") or DEFAULT_DUCKDB_PATH


def get_duckdb_path_lite() -> str | None:
    """Return the optional Lite DuckDB path from DUCKDB_PATH_LITE.

    A "Lite" database is one produced by `ingester ingest --strip-fields`,
    which removes low-signal CloudTrail keys (pagination, idempotency
    tokens, etc.) from `request_parameters` / `response_elements`. It is
    intended to coexist with the full database so an analyst can pick
    which copy to query at runtime.

    Returns:
        The value of DUCKDB_PATH_LITE if set and non-empty, otherwise
        None — meaning no Lite DB is configured and the UI should not
        offer a variant selector.
    """
    value = os.environ.get("DUCKDB_PATH_LITE")
    return value if value else None


def get_duckdb_path_for_variant(variant: str) -> str:
    """Resolve a DB path by variant label.

    Args:
        variant: ``DB_VARIANT_FULL`` or ``DB_VARIANT_LITE``.

    Returns:
        The path for the requested variant. Falls back to the Full path
        when the Lite variant is requested but ``DUCKDB_PATH_LITE`` is
        unset, so callers never need to handle the missing-config case.
    """
    if variant == DB_VARIANT_LITE:
        lite = get_duckdb_path_lite()
        if lite:
            return lite
    return get_duckdb_path()
