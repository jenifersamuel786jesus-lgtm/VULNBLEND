# VulnBlend implementation todo

## 1. Deliver the Streamlit research dashboard shell and dedicated modules
- Run `streamlit run app.py --server.address 0.0.0.0 --server.port 3000` for Preview compatibility.
- Provide dedicated screens for Overview, New Scan, Target Applications, Static Analysis, Dynamic Analysis, Hybrid Correlation, Vulnerability Explorer, Risk Prioritization, Scan History, Experiment Lab, Reports, and Settings.
- Include a collapsible dark cybersecurity navigation shell, contextual breadcrumbs, search/filter controls, global notifications, tooltips, responsive layouts, and loading, empty, error, partial, and completed states.
- Use the cyber-noir mission-control visual system in the approved plan: dark navy surfaces, blue analysis accents, violet correlation accents, reserved severity colors, Inter plus IBM Plex Mono, visible system state, and reduced-motion-friendly transitions.

## 2. Deliver SQLite persistence, migrations, repositories, and audit trail
- Create migrations for applications, source registrations, scan configurations, scan executions, execution events, crawled endpoints, static findings, dynamic findings, correlated vulnerabilities, evidence artifacts, risk scores, test cases, ground-truth labels, experiment runs/results, remediation/status history, reports, users/roles, and audit events.
- Use UUID-like IDs, timestamps, foreign keys, indexes for target/severity/status/risk queries, and immutable historical scan records.
- Store only minimized, redacted evidence; never persist secrets, credentials, cookies, authorization headers, session tokens, or sensitive request values raw.
- Recalculate dashboard aggregates from SQLite records rather than hard-coded summary numbers.

## 3. Deliver authorized target management and backend safety enforcement
- Support registering a local or explicitly authorized laboratory target with application name, description, environment, technology stack, source directory, scope boundaries, crawler depth, request limits, timeout, included/excluded routes, selected vulnerability classes, and authorization confirmation.
- Enforce target allowlisting and authorization in the backend before any file scan or request.
- Block public production URLs by default, cloud metadata endpoints, unauthorized internal-network access, unsupported schemes, out-of-scope redirects, arbitrary file paths, and SSRF pivots.
- Enforce request limits, timeouts, crawl depth, route exclusions, safe file handling, secret redaction, and controlled scan termination.
- Provide local single-user defaults plus role records for administrator, researcher, and viewer; keep multi-user authentication configurable.

## 4. Deliver reproducible scan configuration and staged execution
- Provide a guided wizard for Static Analysis, Dynamic Analysis, Hybrid Analysis, and Hybrid Analysis with Risk Prioritization.
- Persist reproducible scan configurations and `queued` execution records before work begins.
- Run and log stages in order: scope validation, source discovery/static analysis, crawl/endpoint inventory, dynamic tests, correlation, risk scoring, and finalization.
- Persist stage events, progress, counters, errors, limitations, and reproducibility metadata.
- Offer safe pause/resume/cancel transitions and never claim success when a stage is blocked or only simulated.

## 5. Deliver the real modular Python static analyzer
- Use Python AST and extensible rule interfaces for unsafe SQL construction, request-derived input reaching database/template sinks, suspicious input handling, and unsafe HTML response/template rendering.
- Emit rule ID, language/framework, source/sink hints, location and line number, redacted evidence, severity, confidence, remediation, and references.
- Keep pattern matches labelled potential or unverified until corroborating evidence exists.
- Add unit and scanner tests for deterministic findings and redaction.

## 6. Deliver controlled crawling and dynamic SQLi/XSS analysis
- Maintain an in-scope URL set, depth and request budget, duplicate detection, route/parameter/form inventory, HTTP method, content type, request/response summaries, and error events.
- Use Requests and optional Playwright with a capability check; if Playwright or the target is unavailable, show a blocked/partial state and limitation rather than inventing results.
- Record a baseline before safe SQLi/XSS marker tests against allowlisted laboratory endpoints.
- Compare status, response signatures, reflected markers, known SQL error patterns, and rendering contexts; distinguish reflected/stored/DOM-based findings only when actually observed.
- Do not implement destructive testing, persistence, data extraction, denial of service, or third-party scanning.

## 7. Deliver hybrid correlation and evidence-preserving deduplication
- Correlate static and dynamic results across vulnerability type, endpoint/route, HTTP method, parameter, source location, source-to-sink trace, and supporting evidence.
- Classify static-only potential, dynamic-only, correlated, dynamically verified, unverified, and duplicate/related findings.
- Never confirm a vulnerability from a similar name alone.
- Preserve links to original source snippets, HTTP request/response summaries, test cases, and execution logs when merging related findings.

## 8. Deliver explainable risk scoring and prioritization
- Implement the approved configurable score: `risk = 100 × clamp(0.22×severity + 0.20×verification + 0.15×static_confidence + 0.12×exploitability_evidence + 0.12×input_reachability + 0.10×endpoint_exposure + 0.06×potential_impact + 0.03×analysis_confidence, 0, 1)`.
- Normalize components to 0–1, expose the breakdown and evidence, and allow weight editing through Settings.
- Use research thresholds Critical 90–100, High 70–89, Medium 40–69, Low 0–39; label them as VulnBlend choices, not an established standard.
- Provide risk category, rank, prioritization reason, remediation order, interactive sorting/filtering/search, and comparison with severity-only ordering.
- Do not treat missing dynamic verification as proof of safety.

## 9. Deliver vulnerability exploration, workflow, and scan history
- Show vulnerability ID, type, target, endpoint, source location, static/dynamic status, severity, confidence, risk, priority, first detected timestamp, and remediation status.
- Provide detail views with methodology, static evidence, dynamic evidence, correlation, risk breakdown, safe isolated-testbed reproduction, code-level remediation, and security references.
- Allow reviewed, false positive, accepted risk, fixed, and awaiting retest states with an audit trail.
- Provide immutable searchable scan history, execution timelines, configurations, experimental run IDs, review/export/compare actions, and retest records.

## 10. Deliver the Experiment Lab and valid evaluation metrics
- Store fixed configurations, testbed version, payload dictionary identifier, crawler settings, repeated-run IDs, ground-truth cases, method labels, and results.
- Compare Static Analysis, Dynamic Analysis, Hybrid Analysis, and Hybrid Analysis with Risk Prioritization.
- Calculate TP, FP, TN, FN, precision, recall, F1-score, false-positive rate, verification rate, execution time, and crawl coverage using the standard formulas.
- Handle zero denominators safely and label metrics unavailable when ground truth is insufficient.
- Compare severity ordering with risk ordering without claiming accuracy or remediation improvements unsupported by stored runs.

## 11. Deliver reports, exports, and the isolated Docker testbed
- Generate downloadable executive, technical, and research reports in PDF, CSV, and JSON with application details, scope/methodology, configuration, summary, severity/risk, findings, evidence, correlation, remediation, experiment metrics, limitations, environment, and timestamps.
- Record generated reports in SQLite and ensure report content is redacted.
- Provide Docker Compose with VulnBlend, SQLite persistence, an isolated deliberately vulnerable test application, controlled networking, environment variables, and reproducible SQLi/XSS ground truth.
- Include pinned `requirements.txt`, Dockerfile, `.env.example`, README setup/configuration/usage/test/known-limitations documentation, and `public/manus-routes.json` synchronized to the page set.

## 12. Validate the full application and deliver a working Preview
- Run Python syntax/import checks and unit, database, integration, scanner, reporting, and end-to-end tests.
- Prove unauthorized public/internal targets are rejected and prohibited destructive behaviors are absent.
- Verify the app listens on port 3000, the route manifest returns HTTP 200 JSON, the Preview is not a placeholder, and all displayed demo data is explicitly labelled.
- Commit the completed implementation to the initialized Webdev project and deliver the working Preview URL with the README and source available in the project.
