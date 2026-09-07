---
name: rebuild-dashboard
description: Rebuild and re-import Superset dashboard bundles after editing anything under dashboard/assets/. Use whenever a chart, dataset or dashboard YAML changes, because Superset never reads those files directly.
---

# Rebuilding a dashboard bundle

Superset imports ZIPs. It never reads `dashboard/assets/<bundle>/`. An edit that stops at the
YAML — or one that rebuilds the ZIP without re-importing it — leaves the running dashboard
serving the previous chart, and nothing anywhere reports an error. This is the repository's one
change that fails by looking like it worked.

## Both steps, every time

```bash
cd dashboard/assets
python3 rebuild_zip.py          # cloudtrail_default.zip
python3 rebuild_rare_zip.py     # cloudtrail_rare.zip, derived from cloudtrail_default/
# or, for a Suzaku bundle:
python3 rebuild_suzaku_timeline_zip.py    # _summary_ / _metrics_ likewise

cd ../../docker
docker compose run --rm superset-init     # re-import; idempotent
```

## What derives from what

`cloudtrail_rare.zip` is generated from `cloudtrail_default/`, never edited by hand: every chart
declaring `params.order_desc` is flipped to ascending (bottom-N). Charts with no ordering to
invert — KPI cards, time series, the world map, the heatmaps — have no rare counterpart and are
skipped, and a tab whose whole subtree was skipped is dropped rather than shipped empty. So the
rare bundle is a subset of the default one, not a mirror of it.

## Verify

```bash
pytest dashboard/tests    # fails on a stale committed ZIP
make test-repo            # chart counts quoted in the docs
make status               # which Suzaku file each dashboard resolved to
```

If the dashboard still looks stale after the re-import, the dataset column metadata is what is
behind, not the charts: run `make resync`.
