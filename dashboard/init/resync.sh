#!/usr/bin/env bash
# resync.sh — Re-sync Superset metadata after the data on disk changed.
#
# Runs inside the one-shot superset-resync container (`make resync`). Two things
# go stale independently:
#
#   1. cloudtrail_events column metadata, after the ingester rewrote the table —
#      the original reason this command exists.
#   2. The file each Suzaku database connection points at. Superset resolves
#      that path once, at bootstrap, so copying in a newer run, replacing one or
#      deleting one has no effect on a running dashboard until this runs.
#      See doc/PLAN_SUZAKU_MULTI_DB.md F-7.
#
# Idempotent: safe to run whenever a dashboard looks like it is showing the
# wrong data.
set -e

echo "==> Re-syncing cloudtrail_events dataset metadata..."
python3 /app/register_dataset.py

# One scan feeds both the re-registration and the report (F-9).
SUZAKU_INVENTORY=/tmp/suzaku_inventory.json
echo "==> Re-resolving Suzaku database paths..."
python3 /app/register_suzaku_dbs.py --scan "$SUZAKU_INVENTORY"
python3 /app/register_suzaku_dbs.py --from "$SUZAKU_INVENTORY"

echo "==> Suzaku selection:"
python3 /app/register_suzaku_dbs.py --report --from "$SUZAKU_INVENTORY"

echo "==> Resync complete."
