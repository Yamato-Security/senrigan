"""Streamlit page: hunt over VPC Flow Logs.

Like the Suzaku timeline page, this is a thin wrapper over the shared hunting
UI in ``app.py``, driven by :data:`~profiles.VPC_FLOW_PROFILE`. Unlike it, the
data lives in Senrigan's own ``threat_hunting.db`` — the ingester loads flow
logs from the same ``docker/logs/`` copy as CloudTrail — so there is no file
to pick, only the question of whether any flow logs were ingested.
"""

from __future__ import annotations

import os

import duckdb
import streamlit as st

from profiles import VPC_FLOW_PROFILE

PROFILE = VPC_FLOW_PROFILE

_EMPTY_STATE = """\
### 🌊 No VPC Flow Logs in this database

Copy the whole `AWSLogs/` prefix from S3 — CloudTrail and VPC Flow Logs are told apart per
file, and anything else is skipped — then ingest and restart:

```bash
aws s3 sync s3://<your-bucket>/AWSLogs/ docker/logs/AWSLogs/
make ingest
make up
```

Flow logs must be delivered to S3 in the plain-text format (`.log.gz`); Parquet is not
supported. Custom formats are fine — the more fields a subscription logs (`flow-direction`,
`pkt-srcaddr`, `pkt-dstaddr`, `tcp-flags`, `traffic-path`), the more the hunts can see.
"""


def has_flow_logs(db_path: str) -> bool:
    """Return True when *db_path* exists and ``vpc_flow_logs`` has at least one row.

    Args:
        db_path: Path to Senrigan's DuckDB file.

    Returns:
        Whether the page has anything to hunt over.
    """
    if not db_path or not os.path.exists(db_path):
        return False
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


def render() -> None:
    """Render the VPC Flow Logs hunting page."""
    # Imported here rather than at module scope: ``app`` imports this module's
    # package to build the navigation, so a module-level import would be circular.
    from app import _get_duckdb_path, _init_session_state, render_chat, render_sidebar

    _init_session_state(PROFILE)
    db_path = _get_duckdb_path(PROFILE)
    if not has_flow_logs(db_path):
        st.info(_EMPTY_STATE)
        return

    render_sidebar(PROFILE)
    render_chat(PROFILE)
