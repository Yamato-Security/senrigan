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


def get_conn():
    """FastAPI dependency that yields a READ_ONLY DuckDB connection.

    Opens a fresh connection for each request and closes it on teardown.
    Tests override this dependency via ``app.dependency_overrides``.

    Yields:
        An open, read-only DuckDB connection.
    """
    conn = duckdb.connect(get_db_path(), read_only=True)
    try:
        yield conn
    finally:
        conn.close()
