#!/usr/bin/env python3
"""Rebuild suzaku_metrics.zip — the Suzaku field metrics dashboard.

Superset never reads the bundle YAML directly; it only applies the compiled ZIP.
Run this after editing anything under ``suzaku_metrics/``, then re-import:

    python3 rebuild_suzaku_metrics_zip.py
    cd ../../docker && docker compose run --rm superset-init
"""

from __future__ import annotations

import os

from zip_builder import build_zip

BASE = os.path.dirname(os.path.abspath(__file__))
SOURCE_DIR = os.path.join(BASE, "suzaku_metrics")
OUTPUT_ZIP = os.path.join(BASE, "suzaku_metrics.zip")

# Map: source path (relative to SOURCE_DIR) -> arc path inside the ZIP.
FILE_MAP = {
    "metadata.yaml": "metadata.yaml",
    "dashboard.yaml": "dashboards/suzaku_field_metrics.yaml",
    "databases/Suzaku_Metrics_DuckDB.yaml": "databases/Suzaku_Metrics_DuckDB.yaml",
    "datasets/suzaku_metrics.yaml": (
        "datasets/Suzaku_Metrics_DuckDB/suzaku_metrics.yaml"
    ),
    # charts/
    "charts/geo_value_matrix.yaml": "charts/Value_by_Country_and_City.yaml",
    "charts/kpi_distinct_countries.yaml": "charts/Source_Countries.yaml",
    "charts/kpi_distinct_fields.yaml": "charts/Fields_Counted.yaml",
    "charts/kpi_distinct_values.yaml": "charts/Distinct_Values.yaml",
    "charts/kpi_singleton_values.yaml": "charts/Values_Seen_Once.yaml",
    "charts/kpi_top_share.yaml": "charts/Top_Value_Share.yaml",
    "charts/kpi_total_occurrences.yaml": "charts/Total_Occurrences.yaml",
    "charts/newest_values.yaml": "charts/Newest_Values_Latest_First_Seen.yaml",
    "charts/rare_values.yaml": "charts/Rare_Values_Bottom-N.yaml",
    "charts/top_asns.yaml": "charts/Top_Source_ASNs.yaml",
    "charts/top_countries.yaml": "charts/Top_Source_Countries.yaml",
    "charts/top_values.yaml": "charts/Top_Values_by_Occurrence.yaml",
    "charts/value_frequency_table.yaml": "charts/Value_Frequency_Table.yaml",
    "charts/value_share_composition.yaml": "charts/Value_Share_Composition.yaml",
}


def main() -> None:
    """Rebuild the ZIP from the FILE_MAP sources."""
    build_zip(SOURCE_DIR, OUTPUT_ZIP, FILE_MAP)


if __name__ == "__main__":
    main()
