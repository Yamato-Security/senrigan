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

echo "==> Registering Suzaku DuckDB databases (if any were copied in)..."
# Suzaku output files are third-party artifacts an analyst copies into the
# mounted database directory. Their names are arbitrary, so the producing command
# is detected from the schema and each is registered under a fixed name + UUID.
python3 /app/register_suzaku_dbs.py

echo "==> Registering cloudtrail_events dataset..."
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

# Suzaku dashboards — the ZIPs are always present (they are committed), so the
# guard is which Suzaku databases were actually detected. Importing a bundle
# whose database was never copied in would register a connection pointing at a
# non-existent file, and every chart on that dashboard would raise an IOError.
SUZAKU_DETECTED="$(python3 /app/register_suzaku_dbs.py --list)"

for suzaku_bundle in suzaku_timeline suzaku_summary suzaku_metrics; do
  case "$suzaku_bundle" in
    suzaku_timeline) suzaku_command="aws-ct-timeline" ;;
    suzaku_summary)  suzaku_command="aws-ct-summary"  ;;
    suzaku_metrics)  suzaku_command="aws-ct-metrics"  ;;
  esac

  zip_path="/app/dashboards/${suzaku_bundle}.zip"
  if ! echo "$SUZAKU_DETECTED" | grep -qx "$suzaku_command"; then
    echo "    No ${suzaku_command} database — skipping ${suzaku_bundle} dashboard."
  elif [ -f "$zip_path" ]; then
    echo "==> Importing ${suzaku_bundle} dashboard..."
    DASHBOARD_ZIP="$zip_path" python3 /app/import_dashboard.py
  else
    echo "    ${suzaku_bundle}.zip not found — skipping."
  fi
done

# Importing a bundle applies its databases/*.yaml onto the existing connection
# (matched by UUID), overwriting the detected path with the placeholder shipped
# in the YAML. Re-run registration so the real, schema-detected file wins.
if [ -n "$SUZAKU_DETECTED" ]; then
  echo "==> Re-applying detected Suzaku database paths..."
  python3 /app/register_suzaku_dbs.py
fi

echo "==> Bootstrap complete."

