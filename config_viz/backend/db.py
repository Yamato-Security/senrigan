"""DuckDB connection management for the config_viz backend.

The connection is always opened in READ_ONLY mode.
The sole writer is the Rust ingester (``ingester config-import``).
DB path resolution: DUCKDB_PATH env var → default path.
"""

import os

import duckdb


def get_db_path() -> str:
    """Resolve the DuckDB database path from the environment.

    Returns:
        Path string from ``DUCKDB_PATH`` env var, or the default path when
        the variable is unset or empty.
    """
    return os.environ.get("DUCKDB_PATH") or "/data/db/threat_hunting.db"


# ``read_only`` alone does not sandbox the filesystem — COPY ... TO writes files
# and read_text/read_csv/glob read arbitrary files even on a read-only connection.
# Disabling external access (and locking the config so SQL cannot re-enable it)
# closes that hole for the reader service.
_READONLY_CONFIG = {
    "enable_external_access": "false",
    "lock_configuration": "true",
}


def get_conn():
    """FastAPI dependency that yields a READ_ONLY, filesystem-sandboxed connection.

    Opens a fresh connection for each request and closes it on teardown.
    Tests override this dependency via ``app.dependency_overrides``.

    Yields:
        An open, read-only DuckDB connection with external file access disabled.
    """
    conn = duckdb.connect(get_db_path(), read_only=True, config=_READONLY_CONFIG)
    try:
        yield conn
    finally:
        conn.close()
