"""vpc_flow_present.py — Exit 0 when the DuckDB file holds VPC Flow Logs records.

bootstrap.sh imports the VPC Flow Logs dashboard only when this succeeds. The
ZIP is always present (it is committed), so testing for the file is no guard:
on a CloudTrail-only install every chart on that dashboard would raise
"table vpc_flow_logs does not exist".

The database is opened read-only, like every reader in Senrigan.
"""

from __future__ import annotations

import os
import sys

DEFAULT_DB = "/data/db/threat_hunting.db"


def has_flow_logs(db_path: str) -> bool:
    """Return True when `db_path` exists and `vpc_flow_logs` has at least one row."""
    if not os.path.exists(db_path):
        return False
    import duckdb  # noqa: PLC0415 — only present inside the Superset image

    conn = duckdb.connect(db_path, read_only=True)
    try:
        (tables,) = conn.execute(
            "SELECT count(*) FROM information_schema.tables "
            "WHERE table_name = 'vpc_flow_logs'"
        ).fetchone()
        if not tables:
            return False
        return (
            conn.execute("SELECT 1 FROM vpc_flow_logs LIMIT 1").fetchone() is not None
        )
    finally:
        conn.close()


def main() -> None:
    """Exit 0 when flow logs are present, 1 otherwise."""
    db_path = os.environ.get("DUCKDB_PATH") or DEFAULT_DB
    sys.exit(0 if has_flow_logs(db_path) else 1)


if __name__ == "__main__":
    main()
