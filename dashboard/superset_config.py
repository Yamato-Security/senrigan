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

# Secret key for session signing. There is NO safe default: a known key lets
# anyone reachable on the port forge a valid signed admin session cookie without
# the password. Require it to be set to a non-default value and refuse to boot
# otherwise, so a missing/insecure key fails loudly instead of silently shipping
# a publicly-known one.
_INSECURE_DEFAULT_SECRET_KEY = "change-me-in-production"  # noqa: S105
SECRET_KEY = os.environ.get("SUPERSET_SECRET_KEY", "")
if not SECRET_KEY or SECRET_KEY == _INSECURE_DEFAULT_SECRET_KEY:
    raise SystemExit(
        "SUPERSET_SECRET_KEY is unset or still the insecure default. "
        "Generate a unique value and set it in docker/.env before starting "
        'Superset, e.g.:  echo "SUPERSET_SECRET_KEY=$(openssl rand -base64 42)" '
        ">> docker/.env"
    )

# Superset home directory for metadata DB, uploads, etc.
DATA_DIR = "/app/superset_home"

# Superset internal metadata database (SQLite stored in the named volume).
SQLALCHEMY_DATABASE_URI = f"sqlite:///{DATA_DIR}/superset.db"

# Disable the default example dashboards to keep the UI clean.
SUPERSET_LOAD_EXAMPLES = False

# Prevent connections to unsafe internal/metadata databases.
PREVENT_UNSAFE_DB_CONNECTIONS = True

# CSRF protection — enabled so a malicious web page the analyst visits cannot
# drive state-changing requests against Superset on localhost. The one-shot
# init/resync scripts use the in-process Python API (not HTTP forms), so this
# does not affect them.
WTF_CSRF_ENABLED = True

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
