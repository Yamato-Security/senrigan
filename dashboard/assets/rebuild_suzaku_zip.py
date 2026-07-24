#!/usr/bin/env python3
"""Rebuild suzaku_detections.zip in Superset v1 export format.

Superset v1 import requires the following ZIP structure (NO top-level subdir):
  metadata.yaml
  dashboards/<slug>.yaml
  charts/<slice_name>.yaml
  datasets/<db_name>/<table_name>.yaml
  databases/<db_name>.yaml

The Suzaku bundle reuses the same "CloudTrail DuckDB" connection as
cloudtrail_default.zip: both the CloudTrail events and the Suzaku detections
live in the same DuckDB file, written by the same ingester.

The output is byte-for-byte reproducible: entries are written with a fixed
timestamp rather than each source file's mtime, so re-running this script (as
the test suite does) leaves the committed ZIP unchanged instead of producing a
diff made entirely of file times.
"""

import os
import zipfile

# Fixed entry timestamp — see the reproducibility note above.
ZIP_TIMESTAMP = (2026, 7, 25, 0, 0, 0)

BASE = os.path.dirname(os.path.abspath(__file__))
SOURCE_DIR = os.path.join(BASE, "suzaku_detections")
OUTPUT_ZIP = os.path.join(BASE, "suzaku_detections.zip")

# Map: source path (relative to SOURCE_DIR) -> arc path inside ZIP
FILE_MAP = {
    "metadata.yaml": "metadata.yaml",
    "dashboard.yaml": "dashboards/suzaku_detections.yaml",
    "databases/CloudTrail_DuckDB.yaml": "databases/CloudTrail_DuckDB.yaml",
    "datasets/suzaku_detections.yaml": "datasets/CloudTrail_DuckDB/suzaku_detections.yaml",
    "datasets/suzaku_detection_tags.yaml": "datasets/CloudTrail_DuckDB/suzaku_detection_tags.yaml",
    # Tab 1 — Overview (SZK-01 to SZK-12)
    "charts/kpi_total_detections.yaml": "charts/SZK_KPI_Total_Detections.yaml",
    "charts/kpi_critical_high.yaml": "charts/SZK_KPI_Critical_High.yaml",
    "charts/kpi_distinct_rules.yaml": "charts/SZK_KPI_Distinct_Rules.yaml",
    "charts/kpi_distinct_principals.yaml": "charts/SZK_KPI_Distinct_Principals.yaml",
    "charts/kpi_distinct_source_ips.yaml": "charts/SZK_KPI_Distinct_Source_IPs.yaml",
    "charts/kpi_distinct_countries.yaml": "charts/SZK_KPI_Distinct_Countries.yaml",
    "charts/kpi_distinct_accounts.yaml": "charts/SZK_KPI_Distinct_Accounts.yaml",
    "charts/kpi_active_days.yaml": "charts/SZK_KPI_Active_Days.yaml",
    "charts/detections_over_time.yaml": "charts/SZK_Detections_Over_Time.yaml",
    "charts/severity_breakdown.yaml": "charts/SZK_Severity_Breakdown.yaml",
    "charts/top_rules.yaml": "charts/SZK_Top_Rules.yaml",
    "charts/detection_timeline.yaml": "charts/SZK_Detection_Timeline.yaml",
    # Tab 2 — Rules (SZK-13 to SZK-18)
    "charts/rule_summary.yaml": "charts/SZK_Rule_Summary.yaml",
    "charts/rules_over_time.yaml": "charts/SZK_Rules_Over_Time.yaml",
    "charts/rare_rules.yaml": "charts/SZK_Rare_Rules.yaml",
    "charts/rule_authors.yaml": "charts/SZK_Rule_Authors.yaml",
    "charts/rule_catalog.yaml": "charts/SZK_Rule_Catalog.yaml",
    "charts/newly_firing_rules.yaml": "charts/SZK_Newly_Firing_Rules.yaml",
    # Tab 3 — MITRE ATT&CK (SZK-19 to SZK-27, on suzaku_detection_tags)
    "charts/kpi_distinct_tactics.yaml": "charts/SZK_KPI_Distinct_Tactics.yaml",
    "charts/kpi_distinct_techniques.yaml": "charts/SZK_KPI_Distinct_Techniques.yaml",
    "charts/mitre_tactic_distribution.yaml": "charts/SZK_MITRE_Tactic_Distribution.yaml",
    "charts/mitre_technique_distribution.yaml": "charts/SZK_MITRE_Technique_Distribution.yaml",
    "charts/mitre_tactic_over_time.yaml": "charts/SZK_MITRE_Tactic_Over_Time.yaml",
    "charts/mitre_tactic_severity.yaml": "charts/SZK_MITRE_Tactic_Severity.yaml",
    "charts/mitre_technique_rules.yaml": "charts/SZK_MITRE_Technique_Rules.yaml",
    "charts/mitre_tactic_by_principal.yaml": "charts/SZK_MITRE_Tactic_By_Principal.yaml",
    "charts/mitre_threat_groups.yaml": "charts/SZK_MITRE_Threat_Groups.yaml",
    # Tab 4 — Identity (SZK-28 to SZK-35)
    "charts/top_principals.yaml": "charts/SZK_Top_Principals.yaml",
    "charts/identity_type_breakdown.yaml": "charts/SZK_Identity_Type_Breakdown.yaml",
    "charts/principal_summary.yaml": "charts/SZK_Principal_Summary.yaml",
    "charts/principal_rule_matrix.yaml": "charts/SZK_Principal_Rule_Matrix.yaml",
    "charts/access_key_activity.yaml": "charts/SZK_Access_Key_Activity.yaml",
    "charts/top_user_agents.yaml": "charts/SZK_Top_User_Agents.yaml",
    "charts/rare_user_agents.yaml": "charts/SZK_Rare_User_Agents.yaml",
    "charts/account_activity.yaml": "charts/SZK_Account_Activity.yaml",
    # Tab 5 — Origin (SZK-36 to SZK-42)
    "charts/geo_world_map.yaml": "charts/SZK_Geo_World_Map.yaml",
    "charts/top_countries.yaml": "charts/SZK_Top_Countries.yaml",
    "charts/top_asn.yaml": "charts/SZK_Top_ASN.yaml",
    "charts/top_source_ips.yaml": "charts/SZK_Top_Source_IPs.yaml",
    "charts/region_activity.yaml": "charts/SZK_Region_Activity.yaml",
    "charts/country_severity.yaml": "charts/SZK_Country_Severity.yaml",
    "charts/country_rule_matrix.yaml": "charts/SZK_Country_Rule_Matrix.yaml",
    # Tab 6 — Timeline (SZK-43 to SZK-48)
    "charts/detection_heatmap.yaml": "charts/SZK_Detection_Heatmap.yaml",
    "charts/detections_by_hour.yaml": "charts/SZK_Detections_By_Hour.yaml",
    "charts/detection_bursts.yaml": "charts/SZK_Detection_Bursts.yaml",
    "charts/daily_severity_trend.yaml": "charts/SZK_Daily_Severity_Trend.yaml",
    "charts/principal_first_last_seen.yaml": "charts/SZK_Principal_First_Last_Seen.yaml",
    "charts/source_ip_first_last_seen.yaml": "charts/SZK_Source_IP_First_Last_Seen.yaml",
    # Tab 7 — Events (SZK-49 to SZK-56)
    "charts/top_event_names.yaml": "charts/SZK_Top_Event_Names.yaml",
    "charts/event_source_breakdown.yaml": "charts/SZK_Event_Source_Breakdown.yaml",
    "charts/outcome_breakdown.yaml": "charts/SZK_Outcome_Breakdown.yaml",
    "charts/error_code_breakdown.yaml": "charts/SZK_Error_Code_Breakdown.yaml",
    "charts/event_rule_matrix.yaml": "charts/SZK_Event_Rule_Matrix.yaml",
    "charts/azure_workload_activity.yaml": "charts/SZK_Azure_Workload_Activity.yaml",
    "charts/import_provenance.yaml": "charts/SZK_Import_Provenance.yaml",
    "charts/detection_detail.yaml": "charts/SZK_Detection_Detail.yaml",
}


def main() -> None:
    """Rebuild suzaku_detections.zip from the FILE_MAP sources."""
    if os.path.exists(OUTPUT_ZIP):
        os.remove(OUTPUT_ZIP)
        print(f"Removed old: {OUTPUT_ZIP}")

    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
        for src_rel, arc_name in FILE_MAP.items():
            abs_path = os.path.join(SOURCE_DIR, src_rel)
            if not os.path.exists(abs_path):
                print(f"  MISSING: {abs_path}")
                continue
            with open(abs_path, "rb") as fh:
                info = zipfile.ZipInfo(arc_name, date_time=ZIP_TIMESTAMP)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                zf.writestr(info, fh.read())
            print(f"  Added: {arc_name}")

    print(f"\nCreated: {OUTPUT_ZIP}")

    # Warn about chart YAMLs on disk that FILE_MAP forgot — they would silently
    # never reach Superset.
    on_disk = {
        f"charts/{name}"
        for name in os.listdir(os.path.join(SOURCE_DIR, "charts"))
        if name.endswith(".yaml")
    }
    unmapped = sorted(on_disk - set(FILE_MAP))
    if unmapped:
        print(f"\nWARNING: chart YAMLs not listed in FILE_MAP: {unmapped}")

    with zipfile.ZipFile(OUTPUT_ZIP) as zf:
        names = zf.namelist()
        print(f"\nZIP contents ({len(names)} files):")
        for n in sorted(names):
            print(f"  {n}")


if __name__ == "__main__":
    main()
