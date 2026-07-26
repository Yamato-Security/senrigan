#!/usr/bin/env python3
"""Rebuild suzaku_summary.zip — the Suzaku identity summary dashboard.

Superset never reads the bundle YAML directly; it only applies the compiled ZIP.
Run this after editing anything under ``suzaku_summary/``, then re-import:

    python3 rebuild_suzaku_summary_zip.py
    cd ../../docker && docker compose run --rm superset-init
"""

from __future__ import annotations

import os

from zip_builder import build_zip

BASE = os.path.dirname(os.path.abspath(__file__))
SOURCE_DIR = os.path.join(BASE, "suzaku_summary")
OUTPUT_ZIP = os.path.join(BASE, "suzaku_summary.zip")

# Map: source path (relative to SOURCE_DIR) -> arc path inside the ZIP.
FILE_MAP = {
    "metadata.yaml": "metadata.yaml",
    "dashboard.yaml": "dashboards/suzaku_identity_summary.yaml",
    "databases/Suzaku_Summary_DuckDB.yaml": "databases/Suzaku_Summary_DuckDB.yaml",
    # datasets/
    "datasets/suzaku_summary_identities.yaml": (
        "datasets/Suzaku_Summary_DuckDB/suzaku_summary_identities.yaml"
    ),
    "datasets/suzaku_summary_api_calls.yaml": (
        "datasets/Suzaku_Summary_DuckDB/suzaku_summary_api_calls.yaml"
    ),
    "datasets/suzaku_summary_attributes.yaml": (
        "datasets/Suzaku_Summary_DuckDB/suzaku_summary_attributes.yaml"
    ),
    # charts/
    "charts/abused_api_catalogue.yaml": "charts/Abused_API_Catalogue.yaml",
    "charts/abused_apis_by_service.yaml": "charts/Abused_APIs_by_AWS_Service.yaml",
    "charts/abused_vs_other_per_identity.yaml": "charts/Abused_vs_Other_API_Calls_per_Identity.yaml",
    "charts/attribute_first_last_seen.yaml": "charts/Attribute_First_-_Last_Seen.yaml",
    "charts/identity_activity_span.yaml": "charts/Identity_Activity_Span.yaml",
    "charts/identity_triage.yaml": "charts/Identity_Triage_Table.yaml",
    "charts/identity_type_composition.yaml": "charts/Identity_Type_Composition.yaml",
    "charts/kpi_abused_apis.yaml": "charts/Distinct_Abused_APIs.yaml",
    "charts/kpi_access_keys.yaml": "charts/Distinct_Access_Keys.yaml",
    "charts/kpi_failed_abuse.yaml": "charts/Failed_Abuse_Attempts.yaml",
    "charts/kpi_identities.yaml": "charts/Profiled_Identities.yaml",
    "charts/kpi_source_ips.yaml": "charts/Distinct_Source_IPs.yaml",
    "charts/kpi_total_events.yaml": "charts/Total_Events.yaml",
    "charts/rare_attribute_values.yaml": "charts/Rare_Attribute_Values.yaml",
    "charts/top_abused_apis.yaml": "charts/Top_Abused_APIs.yaml",
    "charts/top_attribute_values.yaml": "charts/Top_Attribute_Values.yaml",
    "charts/top_failed_apis.yaml": "charts/Top_Failed_API_Calls.yaml",
    "charts/top_identities_by_events.yaml": "charts/Top_Identities_by_Event_Volume.yaml",
}


def main() -> None:
    """Rebuild the ZIP from the FILE_MAP sources."""
    build_zip(SOURCE_DIR, OUTPUT_ZIP, FILE_MAP)


if __name__ == "__main__":
    main()
