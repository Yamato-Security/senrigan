#!/usr/bin/env python3
"""Rebuild cloudtrail_default.zip in Superset v1 export format.

Superset v1 import requires the following ZIP structure (NO top-level subdir):
  metadata.yaml
  dashboards/<slug>.yaml
  charts/<slice_name>.yaml
  datasets/<db_name>/<table_name>.yaml
  databases/<db_name>.yaml
"""

import zipfile
import os
import shutil

BASE = os.path.dirname(os.path.abspath(__file__))
SOURCE_DIR = os.path.join(BASE, "cloudtrail_default")
OUTPUT_ZIP = os.path.join(BASE, "cloudtrail_default.zip")

# Map: source path (relative to SOURCE_DIR) -> arc path inside ZIP
FILE_MAP = {
    "metadata.yaml": "metadata.yaml",
    "dashboard.yaml": "dashboards/cloudtrail_threat_hunting.yaml",
    "databases/CloudTrail_DuckDB.yaml": "databases/CloudTrail_DuckDB.yaml",
    "datasets/cloudtrail_events.yaml": "datasets/CloudTrail_DuckDB/cloudtrail_events.yaml",
    # Original charts (DSH-01 to DSH-05)
    "charts/event_timeseries.yaml": "charts/CloudTrail_Events_Over_Time.yaml",
    "charts/top_api_calls.yaml": "charts/Top_20_API_Calls.yaml",
    "charts/iam_entity_activity.yaml": "charts/IAM_Entity_Activity.yaml",
    "charts/error_trend.yaml": "charts/Error_Event_Trend.yaml",
    "charts/source_ip_requests.yaml": "charts/Top_Source_IP_Addresses.yaml",
    # Threat hunting charts (DSH-08 to DSH-14)
    "charts/console_login_activity.yaml": "charts/Console_Login_Activity.yaml",
    "charts/access_denied_top_actions.yaml": "charts/Top_Access_Denied_Actions.yaml",
    "charts/user_agent_analysis.yaml": "charts/User_Agent_Analysis.yaml",
    "charts/sensitive_api_calls.yaml": "charts/Sensitive_API_Calls.yaml",
    "charts/root_account_usage.yaml": "charts/Root_Account_Usage.yaml",
    "charts/region_activity.yaml": "charts/Region_Activity.yaml",
    # GeoIP charts (DSH-15 to DSH-18)
    "charts/geo_country_requests.yaml": "charts/Geo_Country_Requests.yaml",
    "charts/geo_world_map.yaml": "charts/Geo_World_Map.yaml",
    "charts/geo_city_requests.yaml": "charts/Geo_City_Requests.yaml",
    "charts/geo_asn_org_requests.yaml": "charts/Geo_ASN_Org_Requests.yaml",
    # New Sprint-1 charts (DSH-22, DSH-28)
    "charts/defense_evasion.yaml": "charts/Defense_Evasion.yaml",
    "charts/mfa_less_login_trend.yaml": "charts/MFA_Less_Login_Trend.yaml",
    # New Sprint-2 charts (DSH-19, DSH-20, DSH-21)
    "charts/login_heatmap.yaml": "charts/Login_Activity_Heatmap.yaml",
    "charts/write_read_ratio.yaml": "charts/Write_Read_Ratio_Trend.yaml",
    "charts/throttling_spikes.yaml": "charts/Throttling_Exception_Spikes.yaml",
    # New Sprint-3 charts (DSH-23, DSH-24, DSH-27, DSH-30)
    "charts/secrets_access_anomaly.yaml": "charts/Secrets_Access_Anomaly.yaml",
    "charts/org_scp_changes.yaml": "charts/Organizations_SCP_Changes.yaml",
    "charts/assumed_role_external_ip.yaml": "charts/AssumedRole_External_IP.yaml",
    "charts/priv_esc_timeline.yaml": "charts/Privilege_Escalation_Timeline.yaml",
    # New Sprint-4 charts (DSH-25, DSH-26, DSH-29)
    "charts/s3_protection_changes.yaml": "charts/S3_Protection_Config_Changes.yaml",
    "charts/first_time_services.yaml": "charts/First_Time_Service_Sources.yaml",
    "charts/route53_dns_changes.yaml": "charts/Route53_DNS_Changes.yaml",
    # Tab 5 — Temporal Analysis charts (DSH-31 to DSH-38)
    "charts/fs_identity.yaml": "charts/First_Last_Seen_IAM_Identity.yaml",
    "charts/fs_source_ip.yaml": "charts/First_Last_Seen_Source_IP.yaml",
    "charts/fs_event_name.yaml": "charts/First_Last_Seen_API_Call.yaml",
    "charts/fs_user_agent.yaml": "charts/First_Last_Seen_User_Agent.yaml",
    "charts/dormant_reactivated.yaml": "charts/Dormant_Accounts_Reactivated.yaml",
    "charts/velocity_spikes.yaml": "charts/Event_Velocity_Spikes.yaml",
    # Tab 6 — High-Risk API Monitor charts (HRM-39 to HRM-46)
    "charts/hrm_timeseries.yaml": "charts/HRM_High_Risk_API_Timeseries.yaml",
    "charts/hrm_top_calls.yaml": "charts/HRM_Top_High_Risk_API_Calls.yaml",
    "charts/hrm_top_actors.yaml": "charts/HRM_Top_Actors_High_Risk.yaml",
    "charts/hrm_top_source_ips.yaml": "charts/HRM_Top_Source_IPs_High_Risk.yaml",
    "charts/hrm_defense_evasion_table.yaml": "charts/HRM_Defense_Evasion_API_Events.yaml",
    "charts/hrm_credential_access_table.yaml": "charts/HRM_Credential_Access_API_Events.yaml",
    "charts/hrm_by_region.yaml": "charts/HRM_High_Risk_API_By_Region.yaml",
    # Phase-1 new charts (DSH-39 to DSH-43) — Critical DFIR gaps
    "charts/ssm_execution.yaml": "charts/SSM_Session_Run_Command_Execution.yaml",
    "charts/rds_snapshot_share.yaml": "charts/RDS_Snapshot_Cross_Account_Share.yaml",
    "charts/ec2_public_snapshot.yaml": "charts/EC2_Public_Snapshot_AMI_Sharing.yaml",
    "charts/vpc_flowlog_changes.yaml": "charts/VPC_Flow_Log_Changes.yaml",
    "charts/config_tampering.yaml": "charts/AWS_Config_Tampering.yaml",
    # Phase-2 new charts (DSH-44 to DSH-46) — High-priority DFIR gaps
    "charts/sso_events.yaml": "charts/IAM_Identity_Center_SSO_Events.yaml",
    "charts/s3_bucket_policy_changes.yaml": "charts/S3_Bucket_Policy_ACL_Changes.yaml",
    "charts/nacl_route_changes.yaml": "charts/Network_ACL_Route_Table_Changes.yaml",
    # Phase-3 new charts (DSH-47 to DSH-48) — Container and EventBridge coverage
    "charts/eventbridge_cw_tampering.yaml": "charts/EventBridge_CloudWatch_Rule_Tampering.yaml",
    "charts/container_platform_events.yaml": "charts/EKS_ECR_Container_Platform_Events.yaml",
    # Phase-4 new charts (DSH-49 to DSH-51) — ECS, Glue/SageMaker, EBS Direct API
    "charts/ecs_task_definition.yaml": "charts/ECS_Task_Definition_Backdoor.yaml",
    "charts/glue_sagemaker_privesc.yaml": "charts/Glue_SageMaker_Privilege_Escalation.yaml",
    "charts/ebs_direct_api.yaml": "charts/EBS_Direct_API_Snapshot_Exfiltration.yaml",
    # Phase-5 new charts (DSH-52 to DSH-57) — S3 & RDS DFIR
    "charts/s3_bulk_download.yaml": "charts/S3_Bulk_Download_Exfiltration.yaml",
    "charts/s3_bulk_deletion.yaml": "charts/S3_Bulk_Object_Deletion.yaml",
    "charts/s3_versioning_logging_disabled.yaml": "charts/S3_Versioning_Logging_Disabled.yaml",
    "charts/s3_cross_account_replication.yaml": "charts/S3_Cross_Account_Replication.yaml",
    "charts/rds_deleted_no_snapshot.yaml": "charts/RDS_Deleted_without_Final_Snapshot.yaml",
    "charts/backup_tampering.yaml": "charts/AWS_Backup_Tampering.yaml",
    # Phase-6 new charts (DSH-58 to DSH-63) — EC2 DFIR
    "charts/ec2_instance_launches.yaml": "charts/EC2_Instance_Launches.yaml",
    "charts/ec2_key_pair.yaml": "charts/EC2_Key_Pair_Creation.yaml",
    "charts/ec2_instance_profile.yaml": "charts/EC2_Instance_Profile_Changes.yaml",
    "charts/ec2_user_data.yaml": "charts/EC2_User_Data_Modification.yaml",
    "charts/ec2_mass_stop_terminate.yaml": "charts/EC2_Mass_Stop_Terminate.yaml",
    "charts/ec2_spot_fleet_abuse.yaml": "charts/EC2_Spot_Fleet_Reserved_Instance_Abuse.yaml",
}

if os.path.exists(OUTPUT_ZIP):
    os.remove(OUTPUT_ZIP)
    print(f"Removed old: {OUTPUT_ZIP}")

with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as zf:
    for src_rel, arc_name in FILE_MAP.items():
        abs_path = os.path.join(SOURCE_DIR, src_rel)
        if not os.path.exists(abs_path):
            print(f"  MISSING: {abs_path}")
            continue
        zf.write(abs_path, arc_name)
        print(f"  Added: {arc_name}")

print(f"\nCreated: {OUTPUT_ZIP}")

# Verify structure
with zipfile.ZipFile(OUTPUT_ZIP) as zf:
    names = zf.namelist()
    print("\nZIP contents:")
    for n in sorted(names):
        print(f"  {n}")

    # Check uuid in databases file
    db_yaml = zf.read("databases/CloudTrail_DuckDB.yaml").decode()
    if "uuid:" in db_yaml:
        print("\nOK: uuid found in databases/CloudTrail_DuckDB.yaml")
    else:
        print("\nERROR: uuid NOT found in databases/CloudTrail_DuckDB.yaml")

    # Check metadata
    meta = zf.read("metadata.yaml").decode()
    print(f"\nmetadata.yaml:\n{meta}")
