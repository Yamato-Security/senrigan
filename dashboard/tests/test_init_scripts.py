"""Tests for init scripts — verify Superset 6.1 compatibility.

DU-06: register_duckdb.py must NOT pass allow_run_async to Database() constructor.
DU-07: databases/CloudTrail_DuckDB.yaml must NOT have allow_run_async: true.
DU-13: SQLALCHEMY_URI must use duckdb+duckdb_engine:// (explicit driver) to avoid
       SA2 entry-point discovery failure ("Can't load plugin: sqlalchemy.dialects:duckdb").
DU-14: databases/CloudTrail_DuckDB.yaml sqlalchemy_uri must use duckdb+duckdb_engine://.
"""

import ast
import os
import re

import yaml

REGISTER_DUCKDB_PATH = os.path.join(
    os.path.dirname(__file__), "..", "init", "register_duckdb.py"
)
DATABASES_YAML_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "assets",
    "cloudtrail_default",
    "databases",
    "CloudTrail_DuckDB.yaml",
)


def test_register_duckdb_no_allow_run_async() -> None:
    """DU-06: allow_run_async must not be passed as a keyword argument to Database().

    The field is deprecated in Superset 6.x.  For the local Docker Compose deployment
    (no Celery) it is functionally a no-op and its removal prevents deprecation warnings.
    Comments mentioning the field for documentation purposes are permitted.
    """
    with open(REGISTER_DUCKDB_PATH, encoding="utf-8") as fh:
        source = fh.read()

    # Check that allow_run_async is not passed as keyword argument:
    # match "allow_run_async=..." (with optional whitespace) but not lines that are comments.
    non_comment_lines = [
        line for line in source.splitlines() if not line.lstrip().startswith("#")
    ]
    offending = [
        line for line in non_comment_lines if re.search(r"\ballow_run_async\s*=", line)
    ]
    assert not offending, (
        "register_duckdb.py must not pass allow_run_async= to Database(). "
        f"This field is deprecated in Superset 6.x.  Offending lines: {offending}"
    )


def test_databases_yaml_no_allow_run_async_true() -> None:
    """DU-07: databases/CloudTrail_DuckDB.yaml must not have allow_run_async: true."""
    with open(DATABASES_YAML_PATH, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    allow_run_async = data.get("allow_run_async")
    assert allow_run_async is not True, (
        "databases/CloudTrail_DuckDB.yaml has allow_run_async: true. "
        "This field is deprecated in Superset 6.x.  Set to false or remove."
    )


def test_register_duckdb_uri_uses_explicit_driver() -> None:
    """DU-13: SQLALCHEMY_URI must use duckdb+duckdb_engine:// scheme.

    Superset 6.x uses SQLAlchemy 2.x.  In SA2, entry-point auto-discovery for
    custom dialects can fail with:
        Can't load plugin: sqlalchemy.dialects:duckdb

    Using the explicit driver syntax `duckdb+duckdb_engine://` bypasses the
    entry-point system and directly imports duckdb_engine.Dialect, making the
    connection reliable regardless of the importlib.metadata cache state.
    """
    with open(REGISTER_DUCKDB_PATH, encoding="utf-8") as fh:
        source = fh.read()

    assert "duckdb+duckdb_engine" in source, (
        "register_duckdb.py SQLALCHEMY_URI must use 'duckdb+duckdb_engine://' "
        "instead of 'duckdb://' to avoid SA2 entry-point discovery failure.\n"
        'Change: SQLALCHEMY_URI = f"duckdb+duckdb_engine:///{DUCKDB_PATH}"'
    )


def test_databases_yaml_uri_uses_explicit_driver() -> None:
    """DU-14: databases/CloudTrail_DuckDB.yaml sqlalchemy_uri must use duckdb+duckdb_engine://.

    Same reason as DU-13 — avoids SA2 entry-point lookup failure.
    """
    with open(DATABASES_YAML_PATH, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    uri = data.get("sqlalchemy_uri", "")
    assert uri.startswith("duckdb+duckdb_engine://"), (
        f"databases/CloudTrail_DuckDB.yaml sqlalchemy_uri must start with "
        f"'duckdb+duckdb_engine://' to avoid SA2 entry-point failure.  "
        f"Current: '{uri}'"
    )
