"""FastAPI application for the config_viz backend.

Endpoints:
  GET /api/snapshots                                — list all snapshots
  GET /api/snapshots/{id}/resource-types            — distinct resource types
  GET /api/snapshots/{id}/graph                     — React Flow nodes + edges
  GET /api/snapshots/{id}/resources/{rid}           — single resource detail
  GET /                                             — React frontend (static)
"""

from pathlib import Path
from typing import Any

import duckdb
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .db import get_conn
from .query import (
    get_graph,
    get_resource_detail,
    get_resource_types,
    list_snapshots,
    snapshot_exists,
)

app = FastAPI(title="config-viz API", version="1.0.0")

# ---------------------------------------------------------------------------
# Static frontend (served from ../static after Vite build)
# ---------------------------------------------------------------------------

_STATIC_DIR = Path(__file__).parent.parent / "static"

_ASSETS_DIR = _STATIC_DIR / "assets"
if _ASSETS_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=str(_ASSETS_DIR)), name="assets")

_ICONS_DIR = _STATIC_DIR / "icons"
if _ICONS_DIR.is_dir():
    app.mount("/icons", StaticFiles(directory=str(_ICONS_DIR)), name="icons")


@app.get("/", include_in_schema=False)
def serve_frontend() -> FileResponse:
    """Serve the React SPA entry point."""
    index = _STATIC_DIR / "index.html"
    if not index.is_file():
        raise HTTPException(status_code=404, detail="Frontend not built yet")
    return FileResponse(str(index))


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------


@app.get("/api/snapshots", response_model=list[dict[str, Any]])
def api_list_snapshots(
    conn: duckdb.DuckDBPyConnection = Depends(get_conn),
) -> list[dict[str, Any]]:
    """List all ingested Config snapshots.

    Returns:
        List of snapshot metadata dicts ordered by captured_at descending.
    """
    return list_snapshots(conn)


@app.get(
    "/api/snapshots/{snapshot_id}/resource-types",
    response_model=list[str],
)
def api_resource_types(
    snapshot_id: str,
    conn: duckdb.DuckDBPyConnection = Depends(get_conn),
) -> list[str]:
    """Return distinct resource types present in *snapshot_id*.

    Raises:
        HTTPException 404: When *snapshot_id* does not exist.
    """
    if not snapshot_exists(conn, snapshot_id):
        raise HTTPException(
            status_code=404, detail=f"Snapshot '{snapshot_id}' not found"
        )
    return get_resource_types(conn, snapshot_id)


@app.get(
    "/api/snapshots/{snapshot_id}/graph",
    response_model=dict[str, list],
)
def api_graph(
    snapshot_id: str,
    resource_type: str | None = None,
    limit: int = 5000,
    conn: duckdb.DuckDBPyConnection = Depends(get_conn),
) -> dict[str, list[dict[str, Any]]]:
    """Return a React Flow–compatible graph for *snapshot_id*.

    Query params:
        resource_type: Filter nodes to this AWS resource type.
        limit:         Maximum number of nodes to return (default 5 000).

    Raises:
        HTTPException 404: When *snapshot_id* does not exist.
    """
    if not snapshot_exists(conn, snapshot_id):
        raise HTTPException(
            status_code=404, detail=f"Snapshot '{snapshot_id}' not found"
        )
    return get_graph(conn, snapshot_id, resource_type=resource_type, limit=limit)


@app.get(
    "/api/snapshots/{snapshot_id}/resources/{resource_id}",
    response_model=dict[str, Any],
)
def api_resource_detail(
    snapshot_id: str,
    resource_id: str,
    resource_type: str | None = None,
    conn: duckdb.DuckDBPyConnection = Depends(get_conn),
) -> dict[str, Any]:
    """Return the full detail of a single resource.

    Query params:
        resource_type: When multiple resources share the same ``resource_id``
            (different ``resource_type``), supply this to select the exact one.

    Returns:
        Resource dict with ``configuration`` and ``tags`` as parsed dicts.

    Raises:
        HTTPException 404: When the snapshot or resource does not exist.
    """
    if not snapshot_exists(conn, snapshot_id):
        raise HTTPException(
            status_code=404, detail=f"Snapshot '{snapshot_id}' not found"
        )
    detail = get_resource_detail(
        conn, snapshot_id, resource_id, resource_type=resource_type
    )
    if detail is None:
        raise HTTPException(
            status_code=404,
            detail=f"Resource '{resource_id}' not found in snapshot '{snapshot_id}'",
        )
    return detail
