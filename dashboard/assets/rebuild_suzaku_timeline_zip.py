#!/usr/bin/env python3
"""Rebuild suzaku_timeline.zip — the Suzaku detection timeline dashboard.

Database, three virtual datasets (detections, unnested ATT&CK tags, the file's
own suzaku_meta provenance row) and 46 charts across six tabs.

Run after editing anything under ``suzaku_timeline/``, then re-import:

    python3 rebuild_suzaku_timeline_zip.py
    cd ../../docker && docker compose run --rm superset-init
"""

from __future__ import annotations

import os

from zip_builder import build_zip

BASE = os.path.dirname(os.path.abspath(__file__))
SOURCE_DIR = os.path.join(BASE, "suzaku_timeline")
OUTPUT_ZIP = os.path.join(BASE, "suzaku_timeline.zip")

# Map: source path (relative to SOURCE_DIR) -> arc path inside the ZIP.
FILE_MAP = {
    "metadata.yaml": "metadata.yaml",
    "dashboard.yaml": "dashboards/suzaku_detection_timeline.yaml",
    "databases/Suzaku_Timeline_DuckDB.yaml": ("databases/Suzaku_Timeline_DuckDB.yaml"),
    "datasets/suzaku_timeline.yaml": (
        "datasets/Suzaku_Timeline_DuckDB/suzaku_timeline.yaml"
    ),
    "datasets/suzaku_timeline_tags.yaml": (
        "datasets/Suzaku_Timeline_DuckDB/suzaku_timeline_tags.yaml"
    ),
    "datasets/suzaku_timeline_meta.yaml": (
        "datasets/Suzaku_Timeline_DuckDB/suzaku_timeline_meta.yaml"
    ),
    # charts/
    "charts/access_key_activity.yaml": "charts/Access_Keys_Involved_in_Detections.yaml",
    "charts/account_activity.yaml": "charts/Detections_by_Account.yaml",
    "charts/daily_severity_trend.yaml": "charts/Daily_Severity_Trend.yaml",
    "charts/detection_bursts.yaml": "charts/Detection_Bursts_5-minute_buckets.yaml",
    "charts/detection_detail.yaml": "charts/Detection_Detail_all_fields.yaml",
    "charts/detection_heatmap.yaml": "charts/Detection_Heatmap_Hour_x_Day.yaml",
    "charts/detection_timeline.yaml": "charts/Detection_Timeline.yaml",
    "charts/detections_over_time.yaml": "charts/Detections_Over_Time_by_Severity.yaml",
    "charts/error_code_breakdown.yaml": "charts/Error_Codes_on_Detections.yaml",
    "charts/event_rule_matrix.yaml": "charts/Action_x_Rule_Matrix.yaml",
    "charts/event_source_breakdown.yaml": (
        "charts/Detections_by_Service_-_Workload.yaml"
    ),
    "charts/identity_type_breakdown.yaml": "charts/Detections_by_Identity_Type.yaml",
    "charts/kpi_active_days.yaml": "charts/Days_With_Detections.yaml",
    "charts/kpi_critical_high.yaml": "charts/Critical_High_Detections.yaml",
    "charts/kpi_distinct_accounts.yaml": "charts/Accounts_-_Tenants.yaml",
    "charts/kpi_distinct_events.yaml": "charts/Distinct_Events.yaml",
    "charts/kpi_distinct_principals.yaml": "charts/Principals_Involved.yaml",
    "charts/kpi_distinct_rules.yaml": "charts/Distinct_Rules_Fired.yaml",
    "charts/kpi_distinct_source_ips.yaml": "charts/Source_IPs.yaml",
    "charts/kpi_distinct_tactics.yaml": "charts/ATTACK_Tactics_Covered.yaml",
    "charts/kpi_distinct_techniques.yaml": "charts/ATTACK_Techniques_Covered.yaml",
    "charts/kpi_total_detections.yaml": "charts/Total_Detections.yaml",
    "charts/mitre_tactic_by_principal.yaml": "charts/Tactic_x_Principal.yaml",
    "charts/mitre_tactic_distribution.yaml": "charts/ATTACK_Tactic_Distribution.yaml",
    "charts/mitre_tactic_over_time.yaml": "charts/ATTACK_Tactics_Over_Time.yaml",
    "charts/mitre_tactic_severity.yaml": "charts/Tactic_x_Severity_Matrix.yaml",
    "charts/mitre_technique_distribution.yaml": (
        "charts/ATTACK_Technique_Distribution.yaml"
    ),
    "charts/mitre_technique_rules.yaml": (
        "charts/Techniques_and_the_Rules_That_Found_Them.yaml"
    ),
    "charts/mitre_threat_groups.yaml": "charts/Attributed_Threat_Groups.yaml",
    "charts/newly_firing_rules.yaml": "charts/Newly_Firing_Rules.yaml",
    "charts/outcome_breakdown.yaml": "charts/Success_vs_Failure.yaml",
    "charts/principal_rule_matrix.yaml": "charts/Principal_x_Rule_Matrix.yaml",
    "charts/principal_summary.yaml": "charts/Principal_Summary.yaml",
    "charts/rare_rules.yaml": "charts/Rare_Rules_Least_Frequent.yaml",
    "charts/rare_user_agents.yaml": "charts/Rare_User_Agents.yaml",
    "charts/region_activity.yaml": "charts/Detections_by_AWS_Region.yaml",
    "charts/rule_catalog.yaml": "charts/Rule_Catalog_with_Rule_IDs.yaml",
    "charts/rule_summary.yaml": "charts/Rule_Summary.yaml",
    "charts/rules_over_time.yaml": "charts/Rule_Activity_Over_Time.yaml",
    "charts/run_info.yaml": "charts/Suzaku_Run_Info.yaml",
    "charts/severity_breakdown.yaml": "charts/Severity_Breakdown.yaml",
    "charts/top_event_names.yaml": "charts/Top_API_Actions_-_Operations.yaml",
    "charts/top_principals.yaml": "charts/Top_Principals_by_Detections.yaml",
    "charts/top_rules.yaml": "charts/Top_Rules_by_Detection_Count.yaml",
    "charts/top_source_ips.yaml": "charts/Top_Source_IPs.yaml",
    "charts/top_user_agents.yaml": "charts/Top_User_Agents.yaml",
}


def main() -> None:
    """Rebuild the ZIP from the FILE_MAP sources."""
    build_zip(SOURCE_DIR, OUTPUT_ZIP, FILE_MAP)


if __name__ == "__main__":
    main()
