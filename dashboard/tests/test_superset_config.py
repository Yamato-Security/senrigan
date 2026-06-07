"""Tests for superset_config.py — verify Superset 6.1 compatibility.

DU-03: DASHBOARD_NATIVE_FILTERS must NOT be in FEATURE_FLAGS (default ON in 6.x)
DU-04: ENABLE_EXPLORE_DRAG_AND_DROP must NOT be in FEATURE_FLAGS (removed in 6.x)
DU-05: ALERTS_ATTACH_REPORTS: False must still be present
DU-15: superset_config.py must explicitly register the duckdb+duckdb_engine dialect
       as a belt-and-suspenders guard against SA2 entry-point discovery failure.
"""

import ast
import os

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "superset_config.py")


def _extract_feature_flags() -> dict:
    """Parse superset_config.py and return the FEATURE_FLAGS dict."""
    with open(CONFIG_PATH, encoding="utf-8") as fh:
        source = fh.read()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "FEATURE_FLAGS":
                    # node.value should be a Dict
                    if isinstance(node.value, ast.Dict):
                        result = {}
                        for k, v in zip(node.value.keys, node.value.values):
                            if isinstance(k, ast.Constant):
                                if isinstance(v, ast.Constant):
                                    result[k.value] = v.value
                        return result
    return {}


def test_dashboard_native_filters_removed() -> None:
    """DU-03: DASHBOARD_NATIVE_FILTERS is enabled by default in Superset 6.x — must not appear in config."""
    flags = _extract_feature_flags()
    assert "DASHBOARD_NATIVE_FILTERS" not in flags, (
        "DASHBOARD_NATIVE_FILTERS is enabled by default in Superset 6.x and "
        "generates deprecation warnings when explicitly set.  Remove it from FEATURE_FLAGS."
    )


def test_explore_drag_and_drop_removed() -> None:
    """DU-04: ENABLE_EXPLORE_DRAG_AND_DROP was removed in Superset 6.x — must not appear in config."""
    flags = _extract_feature_flags()
    assert (
        "ENABLE_EXPLORE_DRAG_AND_DROP" not in flags
    ), "ENABLE_EXPLORE_DRAG_AND_DROP was removed in Superset 6.x.  Remove it from FEATURE_FLAGS."


def test_alerts_attach_reports_disabled() -> None:
    """DU-05: ALERTS_ATTACH_REPORTS: False must remain to suppress unwanted alert UI."""
    flags = _extract_feature_flags()
    assert (
        "ALERTS_ATTACH_REPORTS" in flags
    ), "ALERTS_ATTACH_REPORTS must remain in FEATURE_FLAGS (set to False)."
    assert (
        flags["ALERTS_ATTACH_REPORTS"] is False
    ), "ALERTS_ATTACH_REPORTS must be False to suppress alerts/reports UI."


def _extract_cache_config(var_name: str) -> dict:
    """Parse superset_config.py and return the named cache config dict."""
    with open(CONFIG_PATH, encoding="utf-8") as fh:
        source = fh.read()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == var_name:
                    if isinstance(node.value, ast.Dict):
                        result = {}
                        for k, v in zip(node.value.keys, node.value.values):
                            if isinstance(k, ast.Constant) and isinstance(
                                v, ast.Constant
                            ):
                                result[k.value] = v.value
                        return result
    return {}


def test_data_cache_config_present() -> None:
    """DATA_CACHE_CONFIG must be defined to enable chart query result caching."""
    config = _extract_cache_config("DATA_CACHE_CONFIG")
    assert config, "DATA_CACHE_CONFIG must be defined in superset_config.py"


def test_data_cache_type_filesystem() -> None:
    """DATA_CACHE_CONFIG must use FileSystemCache (no Redis dependency)."""
    config = _extract_cache_config("DATA_CACHE_CONFIG")
    assert (
        config.get("CACHE_TYPE") == "FileSystemCache"
    ), "DATA_CACHE_CONFIG CACHE_TYPE must be 'FileSystemCache'"


def test_data_cache_timeout_8h() -> None:
    """DATA_CACHE_CONFIG timeout must be 28800 seconds (8 hours)."""
    config = _extract_cache_config("DATA_CACHE_CONFIG")
    assert (
        config.get("CACHE_DEFAULT_TIMEOUT") == 28800
    ), "DATA_CACHE_CONFIG CACHE_DEFAULT_TIMEOUT must be 28800 (8 hours)"


def test_cache_config_present() -> None:
    """CACHE_CONFIG must be defined to enable UI/filter state caching."""
    config = _extract_cache_config("CACHE_CONFIG")
    assert config, "CACHE_CONFIG must be defined in superset_config.py"


def test_duckdb_dialect_explicitly_registered() -> None:
    """DU-15: superset_config.py must call registry.register() for the duckdb+duckdb_engine dialect.

    Superset 6.x (SQLAlchemy 2.x) can fail to auto-discover duckdb-engine via the
    importlib.metadata entry-point system, raising:
        Can't load plugin: sqlalchemy.dialects:duckdb

    Explicitly calling registry.register("duckdb", "duckdb_engine", "Dialect") inside
    superset_config.py ensures the dialect is always available regardless of entry-point
    cache state.
    """
    with open(CONFIG_PATH, encoding="utf-8") as fh:
        source = fh.read()

    assert (
        'registry.register("duckdb"' in source or "registry.register('duckdb'" in source
    ), (
        "superset_config.py must explicitly register the duckdb SQLAlchemy dialect:\n"
        '    registry.register("duckdb", "duckdb_engine", "Dialect")\n'
        "This prevents 'Can't load plugin: sqlalchemy.dialects:duckdb' errors in SA2."
    )
