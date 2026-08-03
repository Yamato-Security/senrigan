# Changes

## 1.0.0 [2026/07/31] - Black Hat Arsenal USA 2026 Release

**New Features:**

- Added a multilingual documentation site built with Material for MkDocs and published to GitHub Pages, and replaced the README with a landing page pointing at it. (#38 #39) (@YamatoSecurity)
- Added Suzaku integration: `aws-ct-summary` and timeline DuckDB views, a Suzaku detections dashboard, and agent explorer pages for the summary and metrics outputs, so Suzaku's Sigma detections can be pivoted alongside the raw CloudTrail events in the same database. (#32 #70 #71 #72 #73 #75) (@fukusuket)
- Added a Rare Events dashboard that surfaces the API calls, principals, and source IPs seen least often in the ingested window — the inverse of the volume-ranked charts, where a single anomalous call is otherwise buried. (#42) (@fukusuket)
- Added Threat Technique Catalog mappings so hunts and dashboard charts carry their MITRE ATT&CK technique context. (#45) (@fukusuket)
- Added automatic GeoIP enrichment for IP columns in query results, so any hunt or ad-hoc query returning a source IP gets ASN, city, and country without the analyst joining anything by hand. (#43) (@fukusuket)
- Added JSON Lines support to the summary parser and uploader, alongside the existing formats. (#35) (@fukusuket)
- Added repository-level consistency tests covering the AWS Config snapshot paths, so a moved or renamed asset fails CI rather than silently breaking a dashboard at runtime. (#68) (@fukusuket)
- Added a `clean` command to the Makefile for Docker cleanup. (#30) (@fukusuket)

**Enhancements:**

- `SUPERSET_SECRET_KEY` is now auto-generated rather than shipped with a default value, so a fresh deployment is not signed with a key that is public in the repository. (#63) (@fukusuket)
- Enhanced console login event tracking, and fixed the SQL expressions behind the console login and MFA trend charts. (#23 #40) (@fukusuket)
- Added performance logging for the ingestion phases and GeoIP lookups, so a slow ingest can be attributed to a phase instead of guessed at. (#24) (@fukusuket)
- Restructured the agent module by extracting session state and chart rendering into their own modules. (#78 #79) (@fukusuket)
- Added further dashboard charts covering additional CloudTrail activity. (#34) (@fukusuket)
- Added a project logo and a DEF CON 2026 badge to the README and documentation landing pages. (#28 #64) (@fukusuket) (@YamatoSecurity)

**Bug Fixes:**

- The AI agent executed analyst-supplied SQL against a read-write DuckDB connection with guards that could be bypassed, so a crafted prompt could reach statements that modified or read outside the intended scope. Reader connections are now sandboxed and the SQL guards hardened. (#46 #52) (@YamatoSecurity)
- The agent disabled TLS certificate verification when talking to the configured LLM endpoint, so the connection could be intercepted. It now trusts the configured CA bundle instead. (#47 #53) (@YamatoSecurity)
- AI analysis output and analyst notes were interpolated into HTML reports unescaped, so log-derived content could inject markup into a report opened in a browser. Both are now escaped, and the analysis prompt is hardened. (#48 #54) (@YamatoSecurity)
- Superset shipped with insecure defaults — a published secret key, CSRF disabled, and a read-write mount. All three are removed. (#51 #56) (@YamatoSecurity)
- `ingester` aborted the whole run when a previously ingested file had changed, because the `ingested_files` bookkeeping insert collided instead of updating. It now upserts, so a re-ingest of modified logs proceeds. (#49 #57) (@YamatoSecurity)

**Other:**

- Pinned every GitHub Action to a commit SHA and added Dependabot, so a compromised or retagged action cannot silently enter the build. (#50 #55) (@YamatoSecurity)
- Updated the Docker base images, moved CI and the release workflow to Node.js 24, and refreshed `actions/checkout` and `actions/upload-artifact`. (#26 #36 #37 #76) (@fukusuket)
- Updated the npm and pip registry URLs, and pinned pip installs with `--uploaded-prior-to P30D` so a package published in the last 30 days cannot enter an image build. (#25 #27) (@fukusuket)
- Updated the `make` commands. (#69) (@fukusuket)

## 0.1.0 [2026/06/12]

- Initial public release: the CloudTrail ingester, the Superset dashboard, the AI hunting agent, and the AWS Config resource graph.
