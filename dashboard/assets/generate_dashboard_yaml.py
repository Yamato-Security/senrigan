#!/usr/bin/env python3
"""Regenerate dashboard.yaml — 5-tab layout with 37 charts and 14 native filters.

Run from the project root:
    python3 dashboard/assets/generate_dashboard_yaml.py
"""

import os

DEST = os.path.join(
    os.path.dirname(__file__),
    "cloudtrail_default",
    "dashboard.yaml",
)

CONTENT = """\
# CloudTrail Threat Hunting — Dashboard Definition (v2)
# 5-tab layout: Identity & Access | Threat Detection |
# Data & Infrastructure | GeoIP Intelligence | Temporal Analysis.
# 37 charts total (30 original + 7 new DSH-31 to DSH-38, excluding DSH-36).
# Import via: superset import-dashboards -p cloudtrail_default.zip -u admin
uuid: c3d4e5f6-a7b8-9012-cdef-123456789012
version: 1.0.0
dashboard_title: CloudTrail Threat Hunting
description: >
  Pre-built threat hunting dashboard for AWS CloudTrail logs stored in DuckDB.
  5-tab layout: Identity & Access | Threat Detection | Data & Infrastructure |
  GeoIP Intelligence | Temporal Analysis.  Covers event volume trends, Read/Write
  ratio, top API calls, IAM entity activity, error patterns, defense evasion,
  privilege escalation timelines, secrets access anomalies, SSRF/IMDS detection,
  DNS exfiltration, geographic source analysis, and first/last seen temporal
  hunting for DFIR.
published: true
css: ""
slug: cloudtrail-threat-hunting

position:
  DASHBOARD_VERSION_KEY: "v2"
  ROOT_ID:
    type: ROOT
    id: ROOT_ID
    children:
      - GRID_ID
  GRID_ID:
    type: GRID
    id: GRID_ID
    children:
      - TABS_ID
  TABS_ID:
    type: TABS
    id: TABS_ID
    children:
      - TAB-identity
      - TAB-threat
      - TAB-data
      - TAB-geoip
      - TAB-temporal

  # Tab 1 — Identity & Access
  TAB-identity:
    type: TAB
    id: TAB-identity
    children:
      - ROW-ia-1
      - ROW-ia-2
      - ROW-ia-3
      - ROW-ia-4
      - ROW-ia-5
    meta:
      text: "\\U0001f511 Identity & Access"
      defaultText: "Tab 1"
      tooltip: "Login monitoring, privilege escalation, and sensitive API tracking"
  ROW-ia-1:
    type: ROW
    id: ROW-ia-1
    children:
      - CHART-console-login
      - CHART-mfa-login-trend
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-ia-2:
    type: ROW
    id: ROW-ia-2
    children:
      - CHART-login-heatmap
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-ia-3:
    type: ROW
    id: ROW-ia-3
    children:
      - CHART-sensitive-api
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-ia-4:
    type: ROW
    id: ROW-ia-4
    children:
      - CHART-root-usage
      - CHART-iam-entity
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-ia-5:
    type: ROW
    id: ROW-ia-5
    children:
      - CHART-priv-esc-timeline
    meta:
      background: BACKGROUND_TRANSPARENT

  # Tab 2 — Threat Detection
  TAB-threat:
    type: TAB
    id: TAB-threat
    children:
      - ROW-td-1
      - ROW-td-2
      - ROW-td-3
      - ROW-td-4
      - ROW-td-5
      - ROW-td-6
    meta:
      text: "\\U0001f3af Threat Detection"
      defaultText: "Tab 2"
      tooltip: "Defense evasion, anomalous patterns, and baseline deviations"
  ROW-td-1:
    type: ROW
    id: ROW-td-1
    children:
      - CHART-timeseries
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-td-2:
    type: ROW
    id: ROW-td-2
    children:
      - CHART-write-read-ratio
      - CHART-throttling-spikes
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-td-3:
    type: ROW
    id: ROW-td-3
    children:
      - CHART-defense-evasion
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-td-4:
    type: ROW
    id: ROW-td-4
    children:
      - CHART-access-denied
      - CHART-error-trend
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-td-5:
    type: ROW
    id: ROW-td-5
    children:
      - CHART-org-scp
      - CHART-s3-protection
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-td-6:
    type: ROW
    id: ROW-td-6
    children:
      - CHART-first-time-svc
    meta:
      background: BACKGROUND_TRANSPARENT

  # Tab 3 — Data & Infrastructure
  TAB-data:
    type: TAB
    id: TAB-data
    children:
      - ROW-di-1
      - ROW-di-2
      - ROW-di-3
      - ROW-di-4
      - ROW-di-5
    meta:
      text: "\\U0001f5c4 Data & Infrastructure"
      defaultText: "Tab 3"
      tooltip: "Data access anomalies and infrastructure change tracking"
  ROW-di-1:
    type: ROW
    id: ROW-di-1
    children:
      - CHART-top-api
      - CHART-region-activity
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-di-2:
    type: ROW
    id: ROW-di-2
    children:
      - CHART-source-ip
      - CHART-user-agent
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-di-3:
    type: ROW
    id: ROW-di-3
    children:
      - CHART-secrets-anomaly
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-di-4:
    type: ROW
    id: ROW-di-4
    children:
      - CHART-assumed-role-ext
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-di-5:
    type: ROW
    id: ROW-di-5
    children:
      - CHART-route53
    meta:
      background: BACKGROUND_TRANSPARENT

  # Tab 4 — GeoIP Intelligence
  TAB-geoip:
    type: TAB
    id: TAB-geoip
    children:
      - ROW-geo-1
      - ROW-geo-2
    meta:
      text: "\\U0001f30d GeoIP Intelligence"
      defaultText: "Tab 4"
      tooltip: "Geographic origin of API calls (requires GeoIP enrichment)"
  ROW-geo-1:
    type: ROW
    id: ROW-geo-1
    children:
      - CHART-geo-country
      - CHART-geo-world-map
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-geo-2:
    type: ROW
    id: ROW-geo-2
    children:
      - CHART-geo-city
      - CHART-geo-asn
    meta:
      background: BACKGROUND_TRANSPARENT

  # Tab 5 — Temporal Analysis (DFIR)
  TAB-temporal:
    type: TAB
    id: TAB-temporal
    children:
      - ROW-ta-1
      - ROW-ta-2
      - ROW-ta-3
      - ROW-ta-4
      - ROW-ta-6
      - ROW-ta-7
    meta:
      text: "\\U0001f552 Temporal Analysis"
      defaultText: "Tab 5"
      tooltip: "First/Last seen tracking, temporal anomalies, and activity velocity for DFIR"
  ROW-ta-1:
    type: ROW
    id: ROW-ta-1
    children:
      - CHART-fs-identity
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-ta-2:
    type: ROW
    id: ROW-ta-2
    children:
      - CHART-fs-source-ip
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-ta-3:
    type: ROW
    id: ROW-ta-3
    children:
      - CHART-fs-event-name
      - CHART-fs-user-agent
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-ta-4:
    type: ROW
    id: ROW-ta-4
    children:
      - CHART-activity-heatmap
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-ta-6:
    type: ROW
    id: ROW-ta-6
    children:
      - CHART-dormant-reactivated
    meta:
      background: BACKGROUND_TRANSPARENT
  ROW-ta-7:
    type: ROW
    id: ROW-ta-7
    children:
      - CHART-velocity-spikes
    meta:
      background: BACKGROUND_TRANSPARENT

  # Chart entries — Tab 1: Identity & Access
  CHART-console-login:
    type: CHART
    id: CHART-console-login
    children: []
    meta:
      chartId: 8
      uuid: c1d2e3f4-a5b6-7890-abcd-ef0123456789
      width: 6
      height: 50
      sliceName: Console Login Activity
  CHART-mfa-login-trend:
    type: CHART
    id: CHART-mfa-login-trend
    children: []
    meta:
      chartId: 28
      uuid: 28d0e1f2-a3b4-5678-3456-789012345678
      width: 6
      height: 50
      sliceName: MFA-less Login Trend
  CHART-login-heatmap:
    type: CHART
    id: CHART-login-heatmap
    children: []
    meta:
      chartId: 19
      uuid: 19a1b2c3-d4e5-6789-abcd-ef0123456789
      width: 12
      height: 50
      sliceName: Login Activity Heatmap
  CHART-sensitive-api:
    type: CHART
    id: CHART-sensitive-api
    children: []
    meta:
      chartId: 12
      uuid: a5b6c7d8-e9f0-1234-ef01-234567890123
      width: 12
      height: 50
      sliceName: Sensitive API Calls
  CHART-root-usage:
    type: CHART
    id: CHART-root-usage
    children: []
    meta:
      chartId: 13
      uuid: b6c7d8e9-f0a1-2345-f012-345678901234
      width: 6
      height: 50
      sliceName: Root Account Usage
  CHART-iam-entity:
    type: CHART
    id: CHART-iam-entity
    children: []
    meta:
      chartId: 3
      uuid: f6a7b8c9-d0e1-2345-f012-456789012345
      width: 6
      height: 50
      sliceName: IAM Entity Activity
  CHART-priv-esc-timeline:
    type: CHART
    id: CHART-priv-esc-timeline
    children: []
    meta:
      chartId: 30
      uuid: 30f2a3b4-c5d6-7890-5678-901234567890
      width: 12
      height: 50
      sliceName: Privilege Escalation Timeline

  # Chart entries — Tab 2: Threat Detection
  CHART-timeseries:
    type: CHART
    id: CHART-timeseries
    children: []
    meta:
      chartId: 1
      uuid: d4e5f6a7-b8c9-0123-def0-234567890123
      width: 12
      height: 50
      sliceName: CloudTrail Events Over Time
  CHART-write-read-ratio:
    type: CHART
    id: CHART-write-read-ratio
    children: []
    meta:
      chartId: 20
      uuid: 20b2c3d4-e5f6-7890-bcde-f01234567890
      width: 6
      height: 50
      sliceName: Write/Read Ratio Trend
  CHART-throttling-spikes:
    type: CHART
    id: CHART-throttling-spikes
    children: []
    meta:
      chartId: 21
      uuid: 21c3d4e5-f6a7-8901-cdef-012345678901
      width: 6
      height: 50
      sliceName: Throttling Exception Spikes
  CHART-defense-evasion:
    type: CHART
    id: CHART-defense-evasion
    children: []
    meta:
      chartId: 22
      uuid: 22d4e5f6-a7b8-9012-def0-123456789012
      width: 12
      height: 50
      sliceName: Defense Evasion Events
  CHART-access-denied:
    type: CHART
    id: CHART-access-denied
    children: []
    meta:
      chartId: 9
      uuid: d2e3f4a5-b6c7-8901-bcde-f01234567890
      width: 6
      height: 50
      sliceName: Top Access Denied Actions
  CHART-error-trend:
    type: CHART
    id: CHART-error-trend
    children: []
    meta:
      chartId: 4
      uuid: a7b8c9d0-e1f2-3456-0123-567890123456
      width: 6
      height: 50
      sliceName: Error Event Trend
  CHART-org-scp:
    type: CHART
    id: CHART-org-scp
    children: []
    meta:
      chartId: 24
      uuid: 24f6a7b8-c9d0-1234-f012-345678901234
      width: 6
      height: 50
      sliceName: Organizations / SCP Changes
  CHART-s3-protection:
    type: CHART
    id: CHART-s3-protection
    children: []
    meta:
      chartId: 25
      uuid: 25a7b8c9-d0e1-2345-0123-456789012345
      width: 6
      height: 50
      sliceName: S3 Protection Config Changes
  CHART-first-time-svc:
    type: CHART
    id: CHART-first-time-svc
    children: []
    meta:
      chartId: 26
      uuid: 26b8c9d0-e1f2-3456-1234-567890123456
      width: 12
      height: 50
      sliceName: First-Time Service Sources

  # Chart entries — Tab 3: Data & Infrastructure
  CHART-top-api:
    type: CHART
    id: CHART-top-api
    children: []
    meta:
      chartId: 2
      uuid: e5f6a7b8-c9d0-1234-ef01-345678901234
      width: 6
      height: 50
      sliceName: Top 20 API Calls
  CHART-region-activity:
    type: CHART
    id: CHART-region-activity
    children: []
    meta:
      chartId: 14
      uuid: c7d8e9f0-a1b2-3456-0123-456789012345
      width: 6
      height: 50
      sliceName: Region Activity
  CHART-source-ip:
    type: CHART
    id: CHART-source-ip
    children: []
    meta:
      chartId: 5
      uuid: b8c9d0e1-f2a3-4567-1234-678901234567
      width: 6
      height: 50
      sliceName: Top Source IP Addresses
  CHART-user-agent:
    type: CHART
    id: CHART-user-agent
    children: []
    meta:
      chartId: 11
      uuid: f4a5b6c7-d8e9-0123-def0-123456789012
      width: 6
      height: 50
      sliceName: User Agent Analysis
  CHART-secrets-anomaly:
    type: CHART
    id: CHART-secrets-anomaly
    children: []
    meta:
      chartId: 23
      uuid: 23e5f6a7-b8c9-0123-ef01-234567890123
      width: 12
      height: 50
      sliceName: Secrets Access Anomaly
  CHART-assumed-role-ext:
    type: CHART
    id: CHART-assumed-role-ext
    children: []
    meta:
      chartId: 27
      uuid: 27c9d0e1-f2a3-4567-2345-678901234567
      width: 12
      height: 50
      sliceName: AssumedRole from External IP
  CHART-route53:
    type: CHART
    id: CHART-route53
    children: []
    meta:
      chartId: 29
      uuid: 29e1f2a3-b4c5-6789-4567-890123456789
      width: 12
      height: 50
      sliceName: Route53 DNS Changes

  # Chart entries — Tab 4: GeoIP Intelligence
  CHART-geo-country:
    type: CHART
    id: CHART-geo-country
    children: []
    meta:
      chartId: 15
      uuid: 15a6c7d8-e9f0-1234-5678-901234567890
      width: 6
      height: 50
      sliceName: Top Countries by Request Volume
  CHART-geo-world-map:
    type: CHART
    id: CHART-geo-world-map
    children: []
    meta:
      chartId: 16
      uuid: 16b7c8d9-e0f1-2345-6789-012345678901
      width: 6
      height: 50
      sliceName: Global Request Origin Map
  CHART-geo-city:
    type: CHART
    id: CHART-geo-city
    children: []
    meta:
      chartId: 17
      uuid: 17c8d9e0-f1a2-3456-7890-123456789012
      width: 6
      height: 50
      sliceName: Top Cities by Request Volume
  CHART-geo-asn:
    type: CHART
    id: CHART-geo-asn
    children: []
    meta:
      chartId: 18
      uuid: 18d9e0f1-a2b3-4567-8901-234567890123
      width: 6
      height: 50
      sliceName: Top ASN Organizations by Request Volume

  # Chart entries — Tab 5: Temporal Analysis
  CHART-fs-identity:
    type: CHART
    id: CHART-fs-identity
    children: []
    meta:
      chartId: 31
      uuid: 31a2b3c4-d5e6-7890-abcd-ef0123456701
      width: 12
      height: 50
      sliceName: First / Last Seen per IAM Identity
  CHART-fs-source-ip:
    type: CHART
    id: CHART-fs-source-ip
    children: []
    meta:
      chartId: 32
      uuid: 32b3c4d5-e6f7-8901-bcde-f01234567802
      width: 12
      height: 50
      sliceName: First / Last Seen per Source IP
  CHART-fs-event-name:
    type: CHART
    id: CHART-fs-event-name
    children: []
    meta:
      chartId: 33
      uuid: 33c4d5e6-f7a8-9012-cdef-012345678903
      width: 6
      height: 50
      sliceName: First / Last Seen per API Call
  CHART-fs-user-agent:
    type: CHART
    id: CHART-fs-user-agent
    children: []
    meta:
      chartId: 34
      uuid: 34d5e6f7-a8b9-0123-def0-123456789004
      width: 6
      height: 50
      sliceName: First / Last Seen per User Agent
  CHART-activity-heatmap:
    type: CHART
    id: CHART-activity-heatmap
    children: []
    meta:
      chartId: 35
      uuid: 35e6f7a8-b9c0-1234-ef01-234567890105
      width: 12
      height: 50
      sliceName: Activity Heatmap (Hour vs Day-of-Week)
  CHART-dormant-reactivated:
    type: CHART
    id: CHART-dormant-reactivated
    children: []
    meta:
      chartId: 37
      uuid: 37a8b9c0-d1e2-3456-0123-456789012307
      width: 12
      height: 50
      sliceName: Dormant Accounts Reactivated
  CHART-velocity-spikes:
    type: CHART
    id: CHART-velocity-spikes
    children: []
    meta:
      chartId: 38
      uuid: 38b9c0d1-e2f3-4567-1234-567890123408
      width: 12
      height: 50
      sliceName: Event Velocity Spikes per Identity

metadata:
  native_filter_configuration:
    - id: NATIVE_FILTER-timerange
      name: Date Range
      filterType: filter_time
      targets:
        - {}
      defaultDataMask:
        filterState:
          value: "No filter"
      controlValues:
        enableEmptyFilter: false
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Filter all charts by event_time date range"
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-identity-type
      name: "Identity Type"
      filterType: filter_select
      targets:
        - column:
            name: user_identity_type
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: true
        searchAllOptions: false
        inverseSelection: false
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Filter by identity type: Root, IAMUser, AssumedRole, etc."
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-identity-type-not
      name: "Identity Type  NOT"
      filterType: filter_select
      targets:
        - column:
            name: user_identity_type
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: true
        searchAllOptions: false
        inverseSelection: true
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Exclude the selected identity types (NOT filter)."
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-arn
      name: "Principal ARN  + Include"
      filterType: filter_select
      targets:
        - column:
            name: user_identity_arn
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: true
        searchAllOptions: true
        inverseSelection: false
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Include only the selected IAM principal ARNs."
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-arn-not
      name: "Principal ARN  NOT"
      filterType: filter_select
      targets:
        - column:
            name: user_identity_arn
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: true
        searchAllOptions: true
        inverseSelection: true
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Exclude the selected IAM principal ARNs (NOT filter)."
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-source-ip
      name: "Source IP  + Include"
      filterType: filter_select
      targets:
        - column:
            name: source_ip_address
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: true
        searchAllOptions: true
        inverseSelection: false
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Include only the selected source IP addresses."
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-source-ip-not
      name: "Source IP  NOT"
      filterType: filter_select
      targets:
        - column:
            name: source_ip_address
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: true
        searchAllOptions: true
        inverseSelection: true
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Exclude the selected source IP addresses (NOT filter)."
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-event-name
      name: "Event Name  + Include"
      filterType: filter_select
      targets:
        - column:
            name: event_name
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: true
        searchAllOptions: true
        inverseSelection: false
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Include only the selected API action names."
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-event-name-not
      name: "Event Name  NOT"
      filterType: filter_select
      targets:
        - column:
            name: event_name
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: true
        searchAllOptions: true
        inverseSelection: true
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Exclude the selected API action names (NOT filter)."
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-event-source
      name: "Event Source  + Include"
      filterType: filter_select
      targets:
        - column:
            name: event_source
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: true
        searchAllOptions: true
        inverseSelection: false
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Include only the selected AWS service sources."
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-event-source-not
      name: "Event Source  NOT"
      filterType: filter_select
      targets:
        - column:
            name: event_source
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: true
        searchAllOptions: true
        inverseSelection: true
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Exclude the selected AWS service sources (NOT filter)."
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-region
      name: "AWS Region  + Include"
      filterType: filter_select
      targets:
        - column:
            name: aws_region
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: true
        searchAllOptions: true
        inverseSelection: false
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Filter all charts to the selected AWS regions."
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-region-not
      name: "AWS Region  NOT"
      filterType: filter_select
      targets:
        - column:
            name: aws_region
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: true
        searchAllOptions: true
        inverseSelection: true
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Exclude the selected AWS regions (NOT filter)."
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-user-agent
      name: "User Agent  + Include"
      filterType: filter_select
      targets:
        - column:
            name: user_agent
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: true
        searchAllOptions: true
        inverseSelection: false
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Include only the selected user agents."
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-user-agent-not
      name: "User Agent  NOT"
      filterType: filter_select
      targets:
        - column:
            name: user_agent
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: true
        searchAllOptions: true
        inverseSelection: true
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Exclude the selected user agents (NOT filter)."
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-error-code
      name: "Error Code"
      filterType: filter_select
      targets:
        - column:
            name: error_code
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: true
        searchAllOptions: true
        inverseSelection: false
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Focus on a specific error code (AccessDenied, Throttling, etc.)."
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-error-code-not
      name: "Error Code  NOT"
      filterType: filter_select
      targets:
        - column:
            name: error_code
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: true
        searchAllOptions: true
        inverseSelection: true
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Exclude the selected error codes (NOT filter)."
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-read-only
      name: "Write / Read"
      filterType: filter_select
      targets:
        - column:
            name: read_only
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: false
        searchAllOptions: false
        inverseSelection: false
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Filter to write-only (false) or read-only (true) operations."
      chartsInScope: []
      tabsInScope: []
    - id: NATIVE_FILTER-read-only-not
      name: "Write / Read  NOT"
      filterType: filter_select
      targets:
        - column:
            name: read_only
          datasetUuid: d8444b4a-ac55-4710-a777-a5b940bebabe
      defaultDataMask:
        filterState:
          value: null
      controlValues:
        enableEmptyFilter: false
        defaultToFirstItem: false
        multiSelect: false
        searchAllOptions: false
        inverseSelection: true
      cascadeParentIds: []
      scope:
        rootPath:
          - ROOT_ID
        excluded: []
      type: NATIVE_FILTER
      description: "Exclude the selected read_only value (NOT filter)."
      chartsInScope: []
      tabsInScope: []
  charts:
    - slice_name: CloudTrail Events Over Time
      viz_type: echarts_timeseries_bar
      description: DSH-01 - Hourly Read/Write event volume (stacked bar).
    - slice_name: Top 20 API Calls
      viz_type: bar
      description: DSH-02 - Most frequently called AWS API actions.
    - slice_name: IAM Entity Activity
      viz_type: table
      description: DSH-03 - IAM entities ranked by API call volume with write ratio.
    - slice_name: Error Event Trend
      viz_type: echarts_timeseries_bar
      description: DSH-04 - Hourly error counts broken down by error code.
    - slice_name: Top Source IP Addresses
      viz_type: table
      description: DSH-05 - External source IPs ranked by request count.
    - slice_name: Console Login Activity
      viz_type: table
      description: DSH-08 - Console sign-in attempts with MFA-less count.
    - slice_name: Top Access Denied Actions
      viz_type: bar
      description: DSH-09 - API actions most frequently denied access.
    - slice_name: User Agent Analysis
      viz_type: table
      description: DSH-11 - Top user agents by request count.
    - slice_name: Sensitive API Calls
      viz_type: table
      description: DSH-12 - Expanded list of high-risk API invocations.
    - slice_name: Root Account Usage
      viz_type: table
      description: DSH-13 - All API calls made by the Root account.
    - slice_name: Region Activity
      viz_type: bar
      description: DSH-14 - Event distribution across AWS regions with write ratio.
    - slice_name: Top Countries by Request Volume
      viz_type: dist_bar
      description: DSH-15 - Top 20 source countries (GeoIP enrichment required).
    - slice_name: Global Request Origin Map
      viz_type: world_map
      description: DSH-16 - World map of API call origins (GeoIP enrichment required).
    - slice_name: Top Cities by Request Volume
      viz_type: table
      description: DSH-17 - Top 25 source cities (GeoIP enrichment required).
    - slice_name: Top ASN Organizations by Request Volume
      viz_type: table
      description: DSH-18 - Top 25 ASN organizations (GeoIP enrichment required).
    - slice_name: Login Activity Heatmap
      viz_type: table
      description: DSH-19 - Console login counts by hour-of-day and day-of-week.
    - slice_name: Write/Read Ratio Trend
      viz_type: echarts_timeseries_bar
      description: DSH-20 - Hourly Read vs Write stacked bar.
    - slice_name: Throttling Exception Spikes
      viz_type: echarts_timeseries_bar
      description: DSH-21 - Throttling errors per service per hour.
    - slice_name: Defense Evasion Events
      viz_type: table
      description: DSH-22 - CloudTrail/GuardDuty/Config/VPC tampering events.
    - slice_name: Secrets Access Anomaly
      viz_type: table
      description: DSH-23 - Bulk Secrets Manager / SSM Parameter Store reads.
    - slice_name: Organizations / SCP Changes
      viz_type: table
      description: DSH-24 - AWS Organizations management events.
    - slice_name: S3 Protection Config Changes
      viz_type: table
      description: DSH-25 - S3 logging / encryption / public-access changes.
    - slice_name: First-Time Service Sources
      viz_type: table
      description: DSH-26 - AWS service sources ordered by first appearance.
    - slice_name: AssumedRole from External IP
      viz_type: table
      description: DSH-27 - AssumedRole calls from public (non-RFC1918) IPs.
    - slice_name: MFA-less Login Trend
      viz_type: echarts_timeseries_bar
      description: DSH-28 - Daily console logins split by MFA usage.
    - slice_name: Route53 DNS Changes
      viz_type: table
      description: DSH-29 - Route 53 hosted-zone and resolver changes.
    - slice_name: Privilege Escalation Timeline
      viz_type: echarts_timeseries_bar
      description: DSH-30 - Daily privilege-escalation API calls by event name.
    - slice_name: First / Last Seen per IAM Identity
      viz_type: table
      description: DSH-31 - IAM identities with first/last seen timestamps, event counts, and active span.
    - slice_name: First / Last Seen per Source IP
      viz_type: table
      description: DSH-32 - Source IPs with first/last seen, identity count, and GeoIP context.
    - slice_name: First / Last Seen per API Call
      viz_type: table
      description: DSH-33 - API actions ordered by first appearance for recon detection.
    - slice_name: First / Last Seen per User Agent
      viz_type: table
      description: DSH-34 - User agents ordered by first appearance for tool introduction detection.
    - slice_name: Activity Heatmap (Hour vs Day-of-Week)
      viz_type: table
      description: DSH-35 - Event counts by hour-of-day and day-of-week for off-hours detection.
    - slice_name: Dormant Accounts Reactivated
      viz_type: table
      description: DSH-37 - Identities with long inactivity gaps that resumed activity.
    - slice_name: Event Velocity Spikes per Identity
      viz_type: table
      description: DSH-38 - Identities with 50+ events/hour burst activity periods.
"""

with open(DEST, "w", encoding="utf-8") as fh:
    fh.write(CONTENT)

print(f"Written {DEST} ({CONTENT.count(chr(10))} lines)")
