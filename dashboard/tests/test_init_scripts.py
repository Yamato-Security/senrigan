"""Tests for init scripts — verify Superset 6.1 compatibility.

DU-06: register_duckdb.py must NOT pass allow_run_async to Database() constructor.
DU-07: databases/CloudTrail_DuckDB.yaml must NOT have allow_run_async: true.
DU-13: SQLALCHEMY_URI must use duckdb+duckdb_engine:// (explicit driver) to avoid
       SA2 entry-point discovery failure ("Can't load plugin: sqlalchemy.dialects:duckdb").
DU-14: databases/CloudTrail_DuckDB.yaml sqlalchemy_uri must use duckdb+duckdb_engine://.
"""

import os
import re

import yaml

REGISTER_DUCKDB_PATH = os.path.join(
    os.path.dirname(__file__), "..", "init", "register_duckdb.py"
)
BOOTSTRAP_SH_PATH = os.path.join(
    os.path.dirname(__file__), "..", "init", "bootstrap.sh"
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


def test_bootstrap_imports_rare_dashboard() -> None:
    """bootstrap.sh must import cloudtrail_rare.zip as a second dashboard.

    import_dashboard.py is parameterized by the DASHBOARD_ZIP env var, so
    the Rare Events dashboard is imported by invoking it a second time with
    DASHBOARD_ZIP pointing at the rare ZIP, guarded by a file-existence
    check (same pattern as the default dashboard import).
    """
    with open(BOOTSTRAP_SH_PATH, encoding="utf-8") as fh:
        source = fh.read()

    assert "/app/dashboards/cloudtrail_rare.zip" in source, (
        "bootstrap.sh must reference /app/dashboards/cloudtrail_rare.zip "
        "to import the Rare Events dashboard."
    )
    assert re.search(
        r"DASHBOARD_ZIP=/app/dashboards/cloudtrail_rare\.zip\s+"
        r"python3 /app/import_dashboard\.py",
        source,
    ), (
        "bootstrap.sh must invoke import_dashboard.py with "
        "DASHBOARD_ZIP=/app/dashboards/cloudtrail_rare.zip."
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


# ---------------------------------------------------------------------------
# Suzaku registration and dashboard import
# ---------------------------------------------------------------------------

REGISTER_SUZAKU_PATH = os.path.join(
    os.path.dirname(__file__), "..", "init", "register_suzaku_dbs.py"
)


def _bootstrap_text() -> str:
    """Return bootstrap.sh as text."""
    with open(BOOTSTRAP_SH_PATH, encoding="utf-8") as fh:
        return fh.read()


def test_bootstrap_registers_suzaku_databases_before_datasets() -> None:
    """Test 16: a dataset cannot be attached to a database that is not there yet."""
    text = _bootstrap_text()
    assert "register_suzaku_dbs.py" in text
    assert text.index("register_suzaku_dbs.py") < text.index("register_dataset.py")


def test_bootstrap_guards_every_suzaku_zip_import() -> None:
    """Test 17: importing a ZIP that does not exist aborts the bootstrap."""
    text = _bootstrap_text()
    for bundle in ("suzaku_timeline", "suzaku_summary", "suzaku_metrics"):
        assert bundle in text
    # The loop tests for the file before importing it.
    assert 'if [ -f "$zip_path" ]' in text


def test_bootstrap_stays_fail_fast() -> None:
    """`set -e` is what makes a failed migration stop the container."""
    assert "set -e" in _bootstrap_text()


def test_register_suzaku_script_exists() -> None:
    """bootstrap.sh calls it, and the compose file mounts it."""
    assert os.path.exists(REGISTER_SUZAKU_PATH)


def test_bootstrap_reasserts_suzaku_uris_after_importing_bundles() -> None:
    """Importing a bundle overwrites its database URI with the YAML placeholder.

    Superset's ImportAssetsCommand applies databases/*.yaml onto the existing
    object (matched by UUID), so the real path detected before the import is
    replaced by the placeholder shipped in the bundle. Registration therefore has
    to run again afterwards, or every Suzaku chart raises an IOError against a
    file name that only exists in the YAML.
    """
    text = _bootstrap_text()
    last_register = text.rindex("register_suzaku_dbs.py")
    last_suzaku_import = text.rindex("DASHBOARD_ZIP")
    assert (
        last_register > last_suzaku_import
    ), "register_suzaku_dbs.py must run again after the Suzaku ZIP imports"


def test_bootstrap_imports_a_suzaku_bundle_only_when_detected() -> None:
    """A bundle whose database is absent must not be imported at all.

    The ZIP is always present — it is committed — so testing for the file is not
    a guard. Importing it anyway registers a database pointing at a file that was
    never copied in, and every chart on that dashboard fails with an IOError.
    """
    text = _bootstrap_text()
    assert "--list" in text, "bootstrap must ask which commands were detected"
    assert "SUZAKU_DETECTED" in text
