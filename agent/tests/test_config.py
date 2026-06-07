"""Tests for config.py — get_duckdb_path and DEFAULT_DUCKDB_PATH."""

from config import (
    DB_VARIANT_FULL,
    DB_VARIANT_LITE,
    DEFAULT_DUCKDB_PATH,
    get_duckdb_path,
    get_duckdb_path_for_variant,
    get_duckdb_path_lite,
)

# ---------------------------------------------------------------------------
# Tests for get_duckdb_path()
# ---------------------------------------------------------------------------


def test_get_duckdb_path_returns_env_var(monkeypatch):
    """get_duckdb_path() returns the DUCKDB_PATH env var when set."""
    monkeypatch.setenv("DUCKDB_PATH", "/custom/path.db")
    assert get_duckdb_path() == "/custom/path.db"


def test_get_duckdb_path_returns_default_when_unset(monkeypatch):
    """get_duckdb_path() returns DEFAULT_DUCKDB_PATH when DUCKDB_PATH is not set."""
    monkeypatch.delenv("DUCKDB_PATH", raising=False)
    assert get_duckdb_path() == DEFAULT_DUCKDB_PATH


def test_get_duckdb_path_returns_default_when_empty(monkeypatch):
    """get_duckdb_path() falls back to DEFAULT_DUCKDB_PATH when DUCKDB_PATH is empty string."""
    monkeypatch.setenv("DUCKDB_PATH", "")
    assert get_duckdb_path() == DEFAULT_DUCKDB_PATH


def test_default_duckdb_path_constant():
    """DEFAULT_DUCKDB_PATH must point to the standard Docker container path."""
    assert DEFAULT_DUCKDB_PATH == "/data/db/threat_hunting.db"


# ---------------------------------------------------------------------------
# Tests for get_duckdb_path_lite() and get_duckdb_path_for_variant()
# ---------------------------------------------------------------------------


def test_get_duckdb_path_lite_returns_env_var(monkeypatch):
    """get_duckdb_path_lite() returns DUCKDB_PATH_LITE when set."""
    monkeypatch.setenv("DUCKDB_PATH_LITE", "/data/db/lite.db")
    assert get_duckdb_path_lite() == "/data/db/lite.db"


def test_get_duckdb_path_lite_returns_none_when_unset(monkeypatch):
    """get_duckdb_path_lite() returns None when DUCKDB_PATH_LITE is not set."""
    monkeypatch.delenv("DUCKDB_PATH_LITE", raising=False)
    assert get_duckdb_path_lite() is None


def test_get_duckdb_path_lite_returns_none_when_empty(monkeypatch):
    """Empty DUCKDB_PATH_LITE is treated as unset (matches DUCKDB_PATH semantics)."""
    monkeypatch.setenv("DUCKDB_PATH_LITE", "")
    assert get_duckdb_path_lite() is None


def test_get_duckdb_path_for_variant_full_returns_full_path(monkeypatch):
    monkeypatch.setenv("DUCKDB_PATH", "/data/db/full.db")
    monkeypatch.setenv("DUCKDB_PATH_LITE", "/data/db/lite.db")
    assert get_duckdb_path_for_variant(DB_VARIANT_FULL) == "/data/db/full.db"


def test_get_duckdb_path_for_variant_lite_returns_lite_path(monkeypatch):
    monkeypatch.setenv("DUCKDB_PATH", "/data/db/full.db")
    monkeypatch.setenv("DUCKDB_PATH_LITE", "/data/db/lite.db")
    assert get_duckdb_path_for_variant(DB_VARIANT_LITE) == "/data/db/lite.db"


def test_get_duckdb_path_for_variant_lite_falls_back_to_full(monkeypatch):
    """When Lite is requested but DUCKDB_PATH_LITE is unset, fall back to Full path
    so callers never need to handle a missing Lite variant explicitly."""
    monkeypatch.setenv("DUCKDB_PATH", "/data/db/full.db")
    monkeypatch.delenv("DUCKDB_PATH_LITE", raising=False)
    assert get_duckdb_path_for_variant(DB_VARIANT_LITE) == "/data/db/full.db"
