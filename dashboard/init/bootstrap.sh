#!/usr/bin/env bash
# bootstrap.sh — Idempotent Superset initialization for Senrigan.
# Runs inside the superset-init container on first startup.
# See doc/DASHBOARD_IMPLEMENTATION_PLAN.md Phase 1 for full details.
set -e

echo "==> Running Superset DB migrations..."
superset db upgrade

echo "==> Creating admin user (idempotent)..."
superset fab create-admin \
  --username  "${SUPERSET_ADMIN_USERNAME:-admin}" \
  --firstname "${SUPERSET_ADMIN_FIRSTNAME:-Admin}" \
  --lastname  "${SUPERSET_ADMIN_LASTNAME:-User}" \
  --email     "${SUPERSET_ADMIN_EMAIL:-admin@localhost}" \
  --password  "${SUPERSET_ADMIN_PASSWORD:-admin}" 2>/dev/null || true

echo "==> Initializing Superset roles and permissions..."
superset init

echo "==> Registering DuckDB database connection..."
# superset set_database_uri was removed in Superset 4.x.
# Use the Python API (DatabaseDAO) to register the DuckDB connection idempotently.
python3 /app/register_duckdb.py

echo "==> Registering datasets (cloudtrail_events + Suzaku detections)..."
python3 /app/register_dataset.py

echo "==> Importing pre-built dashboard (if available)..."
if [ -f /app/dashboards/cloudtrail_default.zip ]; then
  python3 /app/import_dashboard.py
else
  echo "    Dashboard ZIP not found — skipping import."
fi

echo "==> Importing Rare Events dashboard (if available)..."
if [ -f /app/dashboards/cloudtrail_rare.zip ]; then
  DASHBOARD_ZIP=/app/dashboards/cloudtrail_rare.zip python3 /app/import_dashboard.py
else
  echo "    Rare Events dashboard ZIP not found — skipping import."
fi

# The Suzaku dashboard reads suzaku_detections / suzaku_detection_tags, which
# are populated by `ingester suzaku-import`.  It is imported unconditionally:
# the ingester creates both tables (empty) on every run, so the charts render
# "No data" rather than an error until detections are actually imported.
echo "==> Importing Suzaku Detections dashboard (if available)..."
if [ -f /app/dashboards/suzaku_detections.zip ]; then
  DASHBOARD_ZIP=/app/dashboards/suzaku_detections.zip python3 /app/import_dashboard.py
else
  echo "    Suzaku Detections dashboard ZIP not found — skipping import."
fi

echo "==> Bootstrap complete."

