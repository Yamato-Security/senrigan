# PLAN: Threat Technique Catalog for AWS — Coverage & Annotation

Implementation plan for aligning Senrigan's built-in hunts and dashboard charts with the
[Threat Technique Catalog for AWS](https://aws-samples.github.io/threat-technique-catalog-for-aws/)
(aws-samples). The catalog maps ~60 leaf techniques across 11 MITRE ATT&CK-aligned tactics,
each with AWS-specific TIDs (e.g. `T1486.A001`, `AT1669`) and per-technique pages at
`https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/<TID>.html`.

## Goals

1. **agent** — add built-in hunts for catalog techniques that currently have no query.
2. **agent** — annotate every built-in hunt with the catalog technique(s) it detects
   (TID + name + one-line summary + link) and surface that in query output and reports.
3. **dashboard** — add charts for catalog techniques that currently have no chart.

Out of scope: data-event-only techniques that never appear in management-event CloudTrail
(e.g. `T1552.001` Credentials In Files, IMDS *use* itself), and network-only techniques
(`T1190.A016` EC2 hosted app compromise). These are documented as "not observable" below
rather than getting noise-only queries.

---

## 1. Coverage Analysis

Senrigan currently ships **111 built-in hunts** (`agent/builtin_hunts.yaml`) and
**92 dashboard charts** (`dashboard/assets/cloudtrail_default/charts/`, 11-tab layout in
`dashboard.yaml`). Most catalog techniques are already covered (CloudTrail/GuardDuty/Config
tampering, IAM privilege escalation, PassRole abuse, S3 exfiltration, Bedrock LLMjacking,
snapshot sharing, EKS/ECS, Organizations account creation, …).

### Gaps — catalog techniques with NO existing hunt

| # | TID | Technique | Key CloudTrail events | Hunt exists? | Chart exists? |
|---|-----|-----------|----------------------|:---:|:---:|
| G1 | T1070.A001 | Indicator Removal: Delete IAM Entities | `DeleteUser`, `DeleteRole`, `DeleteAccessKey`, `DeleteLoginProfile`, `DeletePolicy`, `DeleteVirtualMFADevice`, `DeleteGroup` | ✗ | ✗ |
| G2 | AT1669 | Assume Root into Organization Member Account | `AssumeRoot` (sts), paired with `DeactivateMFADevice`, `DeleteLoginProfile` | ✗ | ✗ |
| G3 | T1486.A001 | S3 SSE-C Ransomware Encryption | `CopyObject`/`PutObject` with `SSEApplied=SSE_C` / `x-amz-server-side-encryption-customer-algorithm`, `PutBucketEncryption` | ✗ | ✗ |
| G4 | T1485.001 | Lifecycle-Triggered Deletion | `PutBucketLifecycle(Configuration)` with short expiration, `DeleteBucketLifecycle` | ✗ | ✗ |
| G5 | AT1023.001 / T1213.A013 | Query RDS / RDS Instance Manipulation | `ExecuteStatement` (rds-data), `ModifyDBInstance` (masterUserPassword), `RestoreDBInstanceFromDBSnapshot`, `RestoreDBClusterFromSnapshot`, `DownloadDBLogFilePortion` | ✗ | ✗ |
| G6 | T1552.005 | Cloud Instance Metadata API (weakening) | `ModifyInstanceMetadataOptions` (HttpTokens → `optional`) | ✗ | ✗ |
| G7 | T1583.001 / T1491.A001 | Acquire Domains / Subdomain Takeover | `RegisterDomain`, `TransferDomain`, `ChangeResourceRecordSets`, `CreateHostedZone`, `DeleteHostedZone`, `DisableDomainTransferLock` | ✗ | ✓ (`route53_dns_changes`) |
| G8 | T1619.A001 | S3 Object and Bucket Enumeration | `ListBuckets` + `GetBucketAcl` / `GetBucketPolicy` / `GetBucketVersioning` sweeps (threshold ≥10/h per caller) | ✗ | ✓ (`s3_list_activity`) |
| G9 | T1485.A002 | AMI Image Deletion | `DeregisterImage`, bulk `DeleteSnapshot` (≥5/h) | ✗ | ✗ |
| G10 | T1486.A002 / T1486.A003 | EC2/EBS & RDS Data Encryption for Impact | `CopySnapshot`/`CopyDBSnapshot` with foreign `kmsKeyId`, `CreateVolume` re-encryption, `DisableEbsEncryptionByDefault` | ✗ | ✗ |
| G11 | T1496.A009 | Compute Hijacking — WorkSpaces | `CreateWorkspaces`, `CreateWorkspacesPool`, `DescribeWorkspaces` recon | ✗ | ✗ |
| G12 | T1098.A001 | AWS Support Case Closure | `ResolveCase`, `AddCommunicationToCase`, `DescribeCases` (attacker monitoring abuse reports) | ✗ | ✗ |
| G13 | T1098.A006 | Cognito Refresh Token Abuse / user pool manipulation | `UpdateUserPoolClient` (token validity extension), `AdminCreateUser`, `AdminSetUserPassword`, `CreateUserPoolClient` | partial¹ | ✗ |
| G14 | T1666.A002 / T1666.A003 | Leave Organization / Invite to Unknown Org | `LeaveOrganization`, `RemoveAccountFromOrganization`, `InviteAccountToOrganization`, `AcceptHandshake` | partial² | ✗ |
| G15 | T1648.A001 | Serverless Execution: Invoking Lambda | `CreateFunctionUrlConfig`, `UpdateFunctionUrlConfig`, `AddPermission` with `FunctionUrlAuthType=NONE`; `Invoke` when data events are ingested | partial³ | ✓ (`lambda_config_changes`) |
| G16 | T1535 | Unused/Unsupported Cloud Regions | first write activity in a region with no prior history | partial⁴ | ✓ (`region_activity`) |

¹ existing Cognito hunt covers identity-pool unauthenticated access only.
² existing Organizations hunt covers `CreateAccount` + delegated admin only — extend it.
³ existing Lambda hunts cover Create/Update/AddPermission but not Function URLs.
⁴ "Multi-Region Activity" detects 3+ regions/day but not *never-before-seen* regions.

Everything else in the catalog maps to at least one existing hunt; the mapping is recorded
per-hunt in Phase 1 metadata (below), which doubles as the authoritative coverage matrix.

---

## 2. Phase 1 — agent: technique metadata on all hunts

### 2.1 YAML schema extension (`agent/builtin_hunts.yaml`)

Add an optional `techniques` list to every entry:

```yaml
- category: "🛡 Detection & Response"
  label: "🛑 CloudTrail Tampering"
  description: "Detects any attempt to stop or modify CloudTrail. …"
  techniques:
    - tid: "T1562.008"
      name: "Impair Defenses: Disable Cloud Logs"
      summary: "Adversaries disable CloudTrail logging to avoid leaving an audit trail."
      url: "https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1562.008.html"
  chart: …
  prompt: …
  sql: …
```

Conventions:
- `tid` must match `^A?T\d{4}(\.(00\d|A\d{3}))?$` (covers `T1078`, `T1562.008`,
  `T1486.A001`, `AT1669`, `AT1023.001`).
- Multiple techniques per hunt are allowed (e.g. PassRole hunt → `T1098.003` + `T1078.A001`).
- Hunts with no catalog counterpart (e.g. baseline/activity queries) may omit `techniques`;
  the schema test only requires it for the threat-detection categories
  (Detection & Response, Identity & Access, Data & Storage, Compute & Serverless,
  AI & LLM Abuse, Network & Infrastructure, Threat Patterns).

### 2.2 Rendering in query output (`agent/app.py`)

- `_load_builtin_prompts()` / `_build_all_hunt_queries()`: pass `techniques` through
  (same pattern as `description` today, `app.py:218`).
- Preset run path (`app.py:432-446`): after the existing `st.caption(f"ℹ️ {desc}")`,
  render one caption line per technique:
  `🎯 T1562.008 — Impair Defenses: Disable Cloud Logs` (linked to `url`) followed by the
  one-line `summary`.
- Result rendering path (`app.py:750-754`, `ReportEntry` display): same caption block.

### 2.3 Reports (`agent/report.py`)

- `ReportEntry`: add `techniques: list[dict] = field(default_factory=list)`.
- `_render_entry()` (Markdown) and `_render_entry_html()` (HTML): emit a
  "**Techniques:** [T1562.008 — …](url) — summary" block under the description.
- All call sites that construct `ReportEntry` (`app.py` preset + Run All Hunts paths)
  populate the new field.

### 2.4 TDD test list (Phase 1)

New file `agent/tests/test_builtin_hunts_techniques.py`:
1. every threat-category entry has a non-empty `techniques` list;
2. every `tid` matches the TID regex; `name`/`summary` are non-empty strings;
3. every `url` starts with the catalog base URL and ends with `<tid>.html`;
4. no entry has duplicate TIDs.

Extend existing suites:
5. `test_app.py`: preset run renders a `🎯` technique caption (AppTest);
6. `test_report.py`: Markdown report contains TID + link; HTML report contains an
   anchor to the catalog URL; entries without techniques render unchanged.

Then annotate all 111 existing hunts (bulk YAML edit, driven by the tests above).
Suggested mapping anchors: tampering hunts → `T1562.*`; IAM/PassRole/privesc → `T1098.*`,
`T1078.*`; console login → `T1078.A001`/`T1538`; enumeration → `T1087.004`/`T1580`-style
discovery TIDs present in the catalog; S3 exfil → `T1530.A001`; ransomware/destruction →
`T1485.*`/`T1486.*`; cryptomining/Bedrock → `T1496.*`; Organizations → `T1666.*`/`T1136.003`;
region spread → `T1535`; recon patterns → `T1059.009`.

---

## 3. Phase 2 — agent: new built-in hunts

Each hunt follows the existing entry shape (category, label, description, `techniques`,
`chart`, `prompt`, and an API-key-free `sql`). SQL conventions: `cloudtrail_events` table,
`json_extract_string()`, `LIMIT 100`, threshold CTEs matching existing style.

### Priority 1 (clear catalog gap, high signal)

| Hunt (proposed label) | Category | TIDs | Detection sketch |
|---|---|---|---|
| 🪓 IAM Entity Deletion | 🔑 Identity & Access | T1070.A001 | `event_name IN ('DeleteUser','DeleteRole','DeleteAccessKey','DeleteLoginProfile','DeletePolicy','DeleteRolePolicy','DeleteUserPolicy','DeleteVirtualMFADevice','DeleteGroup')`; flag bursts ≥5/h per caller |
| 👑 AssumeRoot Usage | 🔑 Identity & Access | AT1669 | `event_name = 'AssumeRoot'`; join ±1h window with `DeactivateMFADevice`/`DeleteLoginProfile` by same caller |
| 🔐 S3 SSE-C Encryption (Ransomware) | 🪣 Data & Storage | T1486.A001 | `CopyObject`/`PutObject` where `additional_event_data` or `request_parameters` shows `SSEApplied='SSE_C'` / customer-algorithm header; plus `PutBucketEncryption` changes |
| ⏳ S3 Lifecycle-Triggered Deletion | 🪣 Data & Storage | T1485.001 | `PutBucketLifecycle`/`PutBucketLifecycleConfiguration` (extract expiration days), `DeleteBucketLifecycle` |
| 🗃 RDS Query & Instance Manipulation | 🪣 Data & Storage | AT1023.001, T1213.A013 | `ExecuteStatement`/`BatchExecuteStatement` (event_source `rds-data`), `ModifyDBInstance` with `masterUserPassword`, `RestoreDBInstanceFromDBSnapshot`, `RestoreDBClusterFromSnapshot`, `DownloadDBLogFilePortion` |
| 🛰 IMDS Options Weakening | ⚡ Compute & Serverless | T1552.005 | `ModifyInstanceMetadataOptions` where `httpTokens='optional'` or `httpEndpoint` toggled |
| 🌐 Route 53 & Domain Changes | 🌐 Network & Infrastructure | T1583.001, T1491.A001 | `RegisterDomain`, `TransferDomain`, `ChangeResourceRecordSets`, `CreateHostedZone`, `DeleteHostedZone`, `DisableDomainTransferLock` |
| 🔎 S3 Bucket Enumeration | 🪣 Data & Storage | T1619.A001 | callers with ≥10 `ListBuckets`/`GetBucket*` read calls in 1h (CTE + HAVING, same pattern as Reconnaissance hunt) |
| 💥 AMI & Snapshot Deletion | ⚡ Compute & Serverless | T1485.A002 | `DeregisterImage`, bulk `DeleteSnapshot` ≥5/h per caller |
| 🔑 Storage Re-Encryption for Impact | 🪣 Data & Storage | T1486.A002, T1486.A003 | `CopySnapshot`/`CopyDBSnapshot`/`CreateVolume` with explicit `kmsKeyId`, `DisableEbsEncryptionByDefault` |

### Priority 2 (extend existing hunts or lower frequency)

| Hunt | Action | TIDs |
|---|---|---|
| 🖥 WorkSpaces Hijacking | new hunt: `CreateWorkspaces`, `CreateWorkspacesPool`, recon `DescribeWorkspaces` bursts | T1496.A009 |
| 🎫 Support Case Manipulation | new hunt: `ResolveCase`, `AddCommunicationToCase`, `DescribeCases` bursts | T1098.A001 |
| 🪪 Cognito User Pool Manipulation | new hunt (complements existing identity-pool hunt): `UpdateUserPoolClient`, `CreateUserPoolClient`, `AdminCreateUser`, `AdminSetUserPassword` | T1098.A006 |
| 🏢 Organization Membership Changes | extend "AWS Organizations Account Creation" SQL with `LeaveOrganization`, `RemoveAccountFromOrganization`, `InviteAccountToOrganization`, `AcceptHandshake`; add TIDs | T1666.A001–A003 |
| ⚡ Lambda Function URL Exposure | extend "Lambda Function Tampering" with `CreateFunctionUrlConfig`/`UpdateFunctionUrlConfig` and `FunctionUrlAuthType=NONE`; include `Invoke` when present | T1648.A001 |
| 🗺 First-Seen Region Activity | new hunt: writes in a region with zero events before the last 24h (pattern of "First-Time API Calls") | T1535 |

### TDD test list (Phase 2)

Continue the `test_builtin_hunts_phase*.py` convention → `test_builtin_hunts_phase5.py`:
1. each new hunt exists with expected label/category and passes the schema test;
2. each new `sql` executes on a temp DuckDB (`tmp_duckdb` fixture) seeded with a matching
   synthetic event and returns it;
3. each `sql` returns nothing on non-matching seed data (negative case);
4. threshold hunts (enumeration, snapshot deletion) honor their HAVING cutoffs;
5. keyword-blocklist guard still passes for all new SQL (SELECT-only).

Update the test-count lines in `CLAUDE.md` and `AGENTS.md` (agent ≈ 440 → new total).

---

## 4. Phase 3 — dashboard: new charts

New chart YAMLs in `dashboard/assets/cloudtrail_default/charts/` (dataset:
`cloudtrail_events`, same `dataset_uuid` as existing charts). Chart `description` fields
include the TID(s) so the Superset UI shows catalog alignment.

| Chart file | Type | Tab (dashboard.yaml) | Mirrors hunt |
|---|---|---|---|
| `iam_entity_deletion.yaml` | table (event/caller/time) | TAB-identity | IAM Entity Deletion (T1070.A001) |
| `assume_root_events.yaml` | table | TAB-identity | AssumeRoot Usage (AT1669) |
| `s3_ssec_encryption.yaml` | timeseries + table | TAB-s3-rds | SSE-C Ransomware (T1486.A001) |
| `s3_lifecycle_deletion.yaml` | table | TAB-s3-rds | Lifecycle Deletion (T1485.001) |
| `rds_manipulation.yaml` | table | TAB-s3-rds | RDS Query & Manipulation (AT1023.001/T1213.A013) |
| `imds_options_changes.yaml` | table | TAB-computing | IMDS Weakening (T1552.005) |
| `ami_snapshot_deletion.yaml` | bar (per caller/day) | TAB-computing | AMI/Snapshot Deletion (T1485.A002) |
| `storage_reencryption.yaml` | table | TAB-s3-rds | Re-Encryption for Impact (T1486.A002/A003) |
| `workspaces_activity.yaml` | table | TAB-computing | WorkSpaces Hijacking (T1496.A009) |
| `org_membership_changes.yaml` | table | TAB-threat | Organization Membership (T1666.*) |

Not added (already covered): Route 53 (`route53_dns_changes.yaml`), S3 enumeration
(`s3_list_activity.yaml`), regions (`region_activity.yaml`), Lambda
(`lambda_config_changes.yaml`).

Steps per the CLAUDE.md dashboard-assets rule:
1. add chart YAML(s);
2. add `CHART-*` nodes + rows to `dashboard.yaml` under the tabs above
   (keep `generate_dashboard_yaml.py` in sync if it is regenerated);
3. `cd dashboard/assets && python3 rebuild_zip.py && python3 rebuild_rare_zip.py`;
4. `cd ../../docker && docker compose run --rm superset-init`;
5. `docker compose --profile resync run --rm superset-resync` if columns look stale.

### TDD test list (Phase 3)

1. `dashboard/tests/test_chart_yaml.py`: new charts validate (uuid unique, dataset_uuid
   correct, SQL is SELECT-only, TID present in description) — extend expected chart count;
2. `test_dashboard_yaml.py`: every new `CHART-*` node references an existing chart file and
   sits under a valid TAB/ROW; chart count assertions updated;
3. `test_rebuild_zip.py` / `test_rare_zip.py`: zips contain the new chart files.

Update dashboard test-count line (≈ 605 → new total) in `CLAUDE.md` / `AGENTS.md`.

---

## 5. Rollout order & PR slicing

| PR | Content | Risk |
|---|---|---|
| 1 | Phase 1 schema + rendering + report + annotate all existing hunts | low (additive metadata) |
| 2 | Phase 2 Priority-1 hunts (10 hunts) | low (new YAML entries + tests) |
| 3 | Phase 2 Priority-2 hunts + extensions | low |
| 4 | Phase 3 dashboard charts + layout + zip rebuild | medium (Superset import) |

Each PR: tests green (`pytest`, dashboard suite), `ruff` / `black --check` clean, no
test-count regression, update `CLAUDE.md`/`AGENTS.md` counts and doc index (add this file).

## 6. Verification

- `pytest agent/tests` and `pytest dashboard/tests` — all green.
- Manual: run "Run All Hunts" in the Streamlit UI against a seeded DB; confirm 🎯 technique
  captions and report output (Markdown + HTML) contain catalog links.
- Manual: import rebuilt zips into a fresh Superset and confirm the new charts render on
  their tabs for both the default and Rare Events dashboards.
