"""Superset configuration overrides for THuntCloud.

This file is mounted into the Superset container at
/app/pythonpath/superset_config.py and is loaded automatically by Superset.
"""

import os

# DU-15: Explicitly register the DuckDB SQLAlchemy dialect under all lookup keys.
#
# SQLAlchemy 2.x normalizes the URI driver separator when resolving dialects:
#   URI "duckdb+duckdb_engine://"  →  registry lookup key "duckdb.duckdb_engine"
#   URI "duckdb://"                →  registry lookup key "duckdb"
#
# Without explicit registration both lookups fall through to importlib.metadata
# entry-point discovery, which can silently fail in Superset 6.x, producing:
#   Can't load plugin: sqlalchemy.dialects:duckdb.duckdb_engine
#
# We register both keys so either URI form works regardless of entry-point state.
from sqlalchemy.dialects import registry  # noqa: E402

registry.register("duckdb", "duckdb_engine", "Dialect")
registry.register("duckdb.duckdb_engine", "duckdb_engine", "Dialect")

# Secret key for session signing — MUST be overridden in production via env var.
SECRET_KEY = os.environ.get("SUPERSET_SECRET_KEY", "change-me-in-production")

# Superset home directory for metadata DB, uploads, etc.
DATA_DIR = "/app/superset_home"

# Superset internal metadata database (SQLite stored in the named volume).
SQLALCHEMY_DATABASE_URI = f"sqlite:///{DATA_DIR}/superset.db"

# Disable the default example dashboards to keep the UI clean.
SUPERSET_LOAD_EXAMPLES = False

# Prevent connections to unsafe internal/metadata databases.
PREVENT_UNSAFE_DB_CONNECTIONS = True

# CSRF — disable for local development convenience (re-enable for production).
WTF_CSRF_ENABLED = False

# Chart query results cache — FileSystemCache persists across container restarts via
# the superset_home named volume.  Data is static between ingester runs, so 8 h TTL
# covers a typical investigation session without serving stale results indefinitely.
DATA_CACHE_CONFIG = {
    "CACHE_TYPE": "FileSystemCache",
    "CACHE_DEFAULT_TIMEOUT": 28800,  # 8 hours
    "CACHE_DIR": f"{DATA_DIR}/data_cache",
}

CACHE_CONFIG = {
    "CACHE_TYPE": "FileSystemCache",
    "CACHE_DEFAULT_TIMEOUT": 28800,  # 8 hours
    "CACHE_DIR": f"{DATA_DIR}/cache",
}

# Feature flags
FEATURE_FLAGS = {
    # Disable Alerts & Reports to reduce complexity in v1.0.
    "ALERTS_ATTACH_REPORTS": False,
    # DU-03: DASHBOARD_NATIVE_FILTERS removed — enabled by default in Superset 6.x.
    # DU-04: ENABLE_EXPLORE_DRAG_AND_DROP removed — flag was removed in Superset 6.x.
}
