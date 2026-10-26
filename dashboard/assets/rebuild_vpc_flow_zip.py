#!/usr/bin/env python3
"""Rebuild vpc_flow_default.zip — the VPC Flow Logs threat hunting dashboard.

Superset never reads the bundle YAML directly; it only applies the compiled ZIP.
Run this after editing anything under ``vpc_flow_default/``, then re-import:

    python3 rebuild_vpc_flow_zip.py
    cd ../../docker && docker compose run --rm superset-init

The bundle shares the CloudTrail DuckDB connection: flow logs live in the same
threat_hunting.db, written by the same ingester.
"""

from __future__ import annotations

import os

from zip_builder import build_zip

BASE = os.path.dirname(os.path.abspath(__file__))
SOURCE_DIR = os.path.join(BASE, "vpc_flow_default")
OUTPUT_ZIP = os.path.join(BASE, "vpc_flow_default.zip")

# Map: source path (relative to SOURCE_DIR) -> arc path inside the ZIP.
FILE_MAP = {
    "metadata.yaml": "metadata.yaml",
    "dashboard.yaml": "dashboards/vpc_flow_logs_threat_hunting.yaml",
    "databases/CloudTrail_DuckDB.yaml": "databases/CloudTrail_DuckDB.yaml",
    # datasets/
    "datasets/vpc_flow_records.yaml": (
        "datasets/CloudTrail_DuckDB/vpc_flow_records.yaml"
    ),
    "datasets/vpc_flow_sources.yaml": (
        "datasets/CloudTrail_DuckDB/vpc_flow_sources.yaml"
    ),
    "datasets/vpc_flow_log_configs.yaml": (
        "datasets/CloudTrail_DuckDB/vpc_flow_log_configs.yaml"
    ),
    "datasets/vpc_flow_periodicity.yaml": (
        "datasets/CloudTrail_DuckDB/vpc_flow_periodicity.yaml"
    ),
    "datasets/vpc_flow_reject_accept.yaml": (
        "datasets/CloudTrail_DuckDB/vpc_flow_reject_accept.yaml"
    ),
    "datasets/vpc_flow_egress_daily.yaml": (
        "datasets/CloudTrail_DuckDB/vpc_flow_egress_daily.yaml"
    ),
    "datasets/vpc_flow_internal_pairs.yaml": (
        "datasets/CloudTrail_DuckDB/vpc_flow_internal_pairs.yaml"
    ),
    "datasets/vpc_flow_staging.yaml": (
        "datasets/CloudTrail_DuckDB/vpc_flow_staging.yaml"
    ),
    # charts/
    "charts/cov_sources.yaml": "charts/Flow_Log_Sources.yaml",
    "charts/cov_configs.yaml": "charts/Capture_Scope_from_CloudTrail.yaml",
    "charts/cov_status_ts.yaml": "charts/NODATA_SKIPDATA_Windows.yaml",
    "charts/cov_direction.yaml": "charts/Records_by_Direction_Source.yaml",
    "charts/cov_fields.yaml": "charts/Field_Availability_by_Source.yaml",
    "charts/kpi_records.yaml": "charts/Flow_Records.yaml",
    "charts/kpi_bytes.yaml": "charts/Bytes_Observed.yaml",
    "charts/kpi_reject_ratio.yaml": "charts/REJECT_Ratio.yaml",
    "charts/kpi_peers.yaml": "charts/Distinct_External_Peers.yaml",
    "charts/kpi_enis.yaml": "charts/Interfaces_Observed.yaml",
    "charts/kpi_skipdata.yaml": "charts/SKIPDATA_Windows.yaml",
    "charts/ov_records_ts.yaml": "charts/Flow_Records_by_Action.yaml",
    "charts/ov_bytes_ts.yaml": "charts/Bytes_by_Direction.yaml",
    "charts/rc_top_rejected.yaml": "charts/Top_Rejected_External_Sources.yaml",
    "charts/rc_vertical.yaml": "charts/Vertical_Scan_Candidates.yaml",
    "charts/rc_horizontal.yaml": "charts/Horizontal_Scan_Candidates.yaml",
    "charts/rc_admin.yaml": "charts/Internet_to_Admin_DB_Ports_Accepted.yaml",
    "charts/rc_syn_only.yaml": "charts/SYN_Only_Records_from_External_Sources.yaml",
    "charts/rc_reject_accept.yaml": "charts/REJECT_then_ACCEPT_Same_Peer_Target_and_Port.yaml",
    "charts/eg_top_dest.yaml": "charts/Top_External_Destinations_by_Bytes.yaml",
    "charts/eg_outliers.yaml": "charts/Egress_Volume_vs_Host_Baseline.yaml",
    "charts/eg_by_path.yaml": "charts/Egress_Bytes_by_Traffic_Path.yaml",
    "charts/eg_unusual_ports.yaml": "charts/Unusual_Destination_Ports.yaml",
    "charts/eg_dns.yaml": "charts/DNS_to_Non_Amazon_Resolvers.yaml",
    "charts/eg_smtp.yaml": "charts/Outbound_SMTP.yaml",
    "charts/eg_long_running.yaml": "charts/Long_Running_and_Low_and_Slow_Flows.yaml",
    "charts/pe_table.yaml": "charts/Periodic_Flow_Log_Observations.yaml",
    "charts/la_admin.yaml": "charts/Internal_Admin_Port_Traffic.yaml",
    "charts/la_new_pairs.yaml": "charts/First_Seen_Internal_Pairs.yaml",
    "charts/la_fanout.yaml": "charts/Internal_Fan_Out_by_Source.yaml",
    "charts/la_staging.yaml": "charts/Internal_Inbound_Followed_by_External_Egress.yaml",
    "charts/pr_icmp.yaml": "charts/ICMP_ICMPv6_Peers.yaml",
    "charts/pr_udp_fanout.yaml": "charts/UDP_Fan_Out_to_External_Hosts.yaml",
    "charts/pr_unusual.yaml": "charts/Unusual_IP_Protocols.yaml",
    "charts/pr_ipv6.yaml": "charts/IPv6_Flows.yaml",
    "charts/geo_kpi_in.yaml": "charts/Inbound_Countries.yaml",
    "charts/geo_kpi_out.yaml": "charts/Outbound_Countries.yaml",
    "charts/geo_kpi_asn.yaml": "charts/External_ASNs.yaml",
    "charts/geo_map_in_acc.yaml": "charts/Inbound_Accepted_Origin_Map.yaml",
    "charts/geo_map_in_rej.yaml": "charts/Inbound_Rejected_Origin_Map.yaml",
    "charts/geo_map_out.yaml": "charts/Outbound_Bytes_Destination_Map.yaml",
    "charts/geo_country_action.yaml": "charts/Inbound_Records_by_Country_and_Action.yaml",
    "charts/geo_country_port.yaml": "charts/Inbound_Accepted_Ports_by_Country.yaml",
    "charts/geo_asn_out.yaml": "charts/Top_Outbound_ASNs_by_Bytes.yaml",
    "charts/geo_rare_out.yaml": "charts/Rare_Outbound_Countries.yaml",
    "charts/po_reject_reason.yaml": "charts/REJECT_Reasons_BPA_Encryption_Controls.yaml",
    "charts/po_encryption.yaml": "charts/Encryption_Status.yaml",
    "charts/po_aws_service.yaml": "charts/Egress_to_AWS_Services_by_Path.yaml",
    "charts/po_middlebox.yaml": "charts/Middlebox_Interfaces.yaml",
    "charts/po_offhours.yaml": "charts/Egress_Heatmap_UTC_Hour_Weekday.yaml",
}


def main() -> None:
    """Rebuild the ZIP from the FILE_MAP sources."""
    build_zip(SOURCE_DIR, OUTPUT_ZIP, FILE_MAP)


if __name__ == "__main__":
    main()
