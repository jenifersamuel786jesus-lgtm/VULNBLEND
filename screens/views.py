from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from vulblend.config import DEFAULT_TARGET_URL, RISK_WEIGHTS, ROOT, SEVERITY_VALUES
from vulblend.db import audit, execute, insert, json_load, new_id, now_iso, one, query
from vulblend.services.experiment_engine import metric_label
from vulblend.services.reporting import generate_csv, generate_json, generate_pdf, report_payload
from vulblend.services.risk_engine import calculate_score, latest_scores
from vulblend.services.background_scans import start_scan
from vulblend.services.scan_runner import create_scan
from vulblend.services.static_analyzer import analyze_source
from vulblend.services.target_guard import ScopeError, validate_target, validate_source_path
from vulblend.ui.charts import method_comparison, polish, risk_histogram, severity_chart
from vulblend.ui.theme import card_metric, page_header, severity_chip


def records(rows) -> list[dict]:
    return [dict(row) for row in rows]


def apps():
    return query("SELECT * FROM applications WHERE archived=0 ORDER BY name")


def current_app(app_id: str | None = None):
    rows = apps()
    if not rows:
        return None
    return next((row for row in rows if row["id"] == app_id), rows[0])


def scans():
    return query("""SELECT s.*, a.name AS application_name, c.mode FROM scan_executions s JOIN applications a ON a.id=s.application_id JOIN scan_configs c ON c.id=s.config_id ORDER BY s.created_at DESC""")


def risk_rows():
    return query("""SELECT f.*, a.name AS application_name, r.score, r.category, r.priority_rank, r.components, r.rationale
        FROM findings f JOIN applications a ON a.id=f.application_id
        LEFT JOIN risk_scores r ON r.finding_id=f.id AND r.created_at=(SELECT MAX(r2.created_at) FROM risk_scores r2 WHERE r2.finding_id=f.id)
        ORDER BY COALESCE(r.score,0) DESC, f.created_at DESC""")


def demo_notice():
    st.markdown('<div class="vb-demo"><strong>LAB DATA NOTICE</strong> · Seeded rows are an explicitly labelled demonstration dataset. They are not a claim about a production system.</div>', unsafe_allow_html=True)


def live_scan_monitor(scan_id: str):
    """Render a polling monitor backed by persisted SQLite state."""
    scan = one("SELECT s.*, a.name AS application_name, c.mode FROM scan_executions s JOIN applications a ON a.id=s.application_id JOIN scan_configs c ON c.id=s.config_id WHERE s.id=?", [scan_id])
    if not scan:
        return
    row = dict(scan)
    progress = float(row.get("progress") or 0)
    status = row.get("status", "queued")
    stage = (row.get("current_stage") or "queued").upper()
    tone = {"completed": "success", "partial": "warning", "failed": "error", "blocked": "error"}.get(status, "info")
    st.markdown(f"<div class='vb-eyebrow'>LIVE EXECUTION · {row['id']}</div>", unsafe_allow_html=True)
    st.progress(progress, text=f"{status.upper()} · {stage} · {round(progress * 100)}%")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Requests", row.get("requests_processed") or 0)
    m2.metric("Routes", row.get("routes_discovered") or 0)
    m3.metric("Findings", row.get("findings_count") or 0)
    m4.metric("Errors", row.get("errors_count") or 0)
    events = records(query("SELECT stage, level, message, created_at FROM execution_events WHERE scan_id=? ORDER BY created_at DESC LIMIT 12", [scan_id]))
    if events:
        st.dataframe(pd.DataFrame(events), use_container_width=True, hide_index=True)
    if row.get("limitation"):
        st.warning(row["limitation"])
    if status == "completed":
        st.success("Scan completed. Findings, evidence, risk scores, and audit events are available in the other modules.")
    elif status == "partial":
        st.warning("Scan completed partially. Review the recorded limitation before interpreting the result.")
    elif status in {"failed", "blocked"}:
        st.error(row.get("limitation") or "Scan did not complete.")
    else:
        st.info("This panel refreshes automatically while the background worker is running.")


def render_overview():
    page_header("01 / command center", "Overview", "Evidence-led visibility across static analysis, dynamic verification, and remediation priority.")
    demo_notice()
    all_scans = records(scans()); all_findings = records(risk_rows()); all_apps = records(apps())
    c1, c2, c3, c4 = st.columns(4)
    with c1: card_metric("Total scans", str(len(all_scans)), "SQLite-backed executions")
    with c2: card_metric("Vulnerabilities", str(len(all_findings)), f"{sum(1 for r in all_findings if r.get('verification_status') == 'verified')} verified")
    with c3: card_metric("Critical / High", f"{sum(1 for r in all_findings if r.get('severity') in ('Critical','High'))}", "Remediate first")
    with c4: card_metric("Targets", str(len(all_apps)), "Allowlisted applications")
    st.markdown("<div class='vb-rule'></div>", unsafe_allow_html=True)
    f1, f2, f3 = st.columns(3)
    with f1:
        target_filter = st.selectbox("Target", ["All targets"] + [a["name"] for a in all_apps], key="overview_target")
    with f2:
        severity_filter = st.selectbox("Severity", ["All severities", "Critical", "High", "Medium", "Low"], key="overview_severity")
    with f3:
        verification_filter = st.selectbox("Verification", ["All statuses", "verified", "unverified", "partially verified"], key="overview_verification")
    filtered = [row for row in all_findings if (target_filter == "All targets" or row["application_name"] == target_filter) and (severity_filter == "All severities" or row["severity"] == severity_filter) and (verification_filter == "All statuses" or row["verification_status"] == verification_filter)]
    left, right = st.columns([1.1, 1])
    with left:
        st.markdown("<div class='vb-chart-title'>Findings by severity</div>", unsafe_allow_html=True)
        st.plotly_chart(severity_chart(filtered), use_container_width=True, config={"displayModeBar": False})
    with right:
        st.markdown("<div class='vb-chart-title'>Risk score distribution</div>", unsafe_allow_html=True)
        st.plotly_chart(risk_histogram(filtered), use_container_width=True, config={"displayModeBar": False})
    st.subheader("Top vulnerabilities requiring attention")
    if filtered:
        table = pd.DataFrame([{**row, "risk": row.get("score") or 0, "priority": row.get("priority_rank") or "—"} for row in filtered])
        st.dataframe(table[["priority", "title", "finding_type", "severity", "verification_status", "risk", "application_name"]].head(8), use_container_width=True, hide_index=True)
    else:
        st.info("No findings match the current filters.")
    st.subheader("Recent scans")
    st.dataframe(pd.DataFrame(all_scans)[["id", "application_name", "mode", "status", "progress", "findings_count", "created_at"]].head(6) if all_scans else pd.DataFrame(), use_container_width=True, hide_index=True)


def render_new_scan():
    page_header("02 / execution", "New Scan", "Configure a reproducible laboratory run. Backend scope checks execute before any source or network access.")
    demo_notice()
    applications = apps()
    if not applications:
        st.warning("Register an authorized target before creating a scan.")
        return
    selected_name = st.selectbox("Registered target", [a["name"] for a in applications])
    app = next(a for a in applications if a["name"] == selected_name)
    mode = st.radio("Analysis mode", ["Static Analysis", "Dynamic Analysis", "Hybrid Analysis", "Hybrid + Risk Prioritization"], horizontal=True)
    col1, col2, col3 = st.columns(3)
    with col1: depth = st.number_input("Crawler depth", min_value=0, max_value=5, value=int(app["crawler_depth"]))
    with col2: max_requests = st.number_input("Max requests", min_value=1, max_value=500, value=int(app["max_requests"]))
    with col3: timeout = st.number_input("Timeout (seconds)", min_value=1, max_value=60, value=int(app["timeout_seconds"]))
    selected_classes = st.multiselect("Vulnerability classes", ["SQLi", "XSS", "Input handling", "Security headers"], default=["SQLi", "XSS"])
    with st.expander("Review authorized testing scope", expanded=True):
        st.write({"target": app["target_url"], "environment": app["environment"], "allowed_paths": json_load(app["allowed_paths"], []), "excluded_paths": json_load(app["excluded_paths"], []), "source": app["source_path"], "authorization_confirmed": bool(app["authorization_confirmed"])})
    if not app["authorization_confirmed"]:
        st.error("This target is not authorization-confirmed. Scans are blocked at the backend.")
    if st.button("Start controlled scan", type="primary", disabled=not bool(app["authorization_confirmed"])):
        config_id = insert("scan_configs", {"id": new_id("cfg_"), "application_id": app["id"], "mode": mode, "selected_classes": selected_classes, "crawler_depth": depth, "max_requests": max_requests, "timeout_seconds": timeout, "included_routes": json_load(app["allowed_paths"], []), "excluded_routes": json_load(app["excluded_paths"], []), "payload_dictionary": "safe-lab-v1", "created_at": now_iso()})
        config = one("SELECT * FROM scan_configs WHERE id=?", [config_id]); scan_id = create_scan(dict(config), dict(app))
        st.session_state["last_scan_id"] = scan_id
        start_scan(scan_id, dict(config), dict(app))
        st.success("Scan queued in the background. Live progress will update automatically.")
    if st.session_state.get("last_scan_id"):
        st.caption(f"Latest execution: {st.session_state['last_scan_id']}")
        live_scan_monitor(st.session_state["last_scan_id"])


def render_targets():
    page_header("03 / scope registry", "Target Applications", "Only explicitly authorized local or isolated laboratory applications may become active scan targets.")
    with st.expander("Register an authorized laboratory target", expanded=False):
        with st.form("target_form"):
            name = st.text_input("Application name")
            url = st.text_input("Target URL", value=DEFAULT_TARGET_URL)
            source = st.text_input("Source directory", value=str(ROOT / "testbed" / "app"))
            description = st.text_area("Description", value="Authorized isolated laboratory target")
            environment = st.selectbox("Environment", ["isolated-lab", "local-dev", "staging-lab"])
            technology = st.text_input("Technology stack", value="Python web application")
            allowed = st.text_input("Allowed paths", value="/,/search,/profile")
            excluded = st.text_input("Excluded paths", value="/admin,/health")
            authorized = st.checkbox("I confirm this target is authorized for controlled security testing.")
            submitted = st.form_submit_button("Register target")
        if submitted:
            try:
                validate_target(url, authorized)
                path = validate_source_path(source)
                now = now_iso(); app_id = insert("applications", {"id": new_id("app_"), "name": name, "description": description, "target_url": url, "source_path": str(path), "environment": environment, "technology": technology, "category": "User registered", "authorization_confirmed": int(authorized), "allowed_paths": [item.strip() for item in allowed.split(",") if item.strip()], "excluded_paths": [item.strip() for item in excluded.split(",") if item.strip()], "crawler_depth": 2, "max_requests": 40, "timeout_seconds": 15, "vulnerability_classes": ["SQLi", "XSS"], "created_at": now, "updated_at": now})
                audit("target_registered", "application", app_id, {"authorization_confirmed": authorized})
                st.success("Authorized target registered."); st.rerun()
            except (ScopeError, ValueError) as exc:
                st.error(str(exc))
    rows = records(apps())
    st.subheader(f"Registered applications · {len(rows)}")
    if rows:
        for row in rows:
            with st.container(border=True):
                a, b, c = st.columns([2, 2, 1])
                with a: st.markdown(f"**{row['name']}**  ·  {row['environment']}\n\n`{row['target_url']}`")
                with b: st.caption(row["description"]); st.caption(f"Source: {row['source_path']}")
                with c: st.success("AUTHORIZED" if row["authorization_confirmed"] else "PENDING")
    else: st.info("No active targets yet.")


def render_static_analysis():
    page_header("04 / source signals", "Static Analysis", "Deterministic Python AST rules surface potential source-to-sink paths without executing application code.")
    demo_notice()
    app = current_app(st.selectbox("Target", [a["id"] for a in apps()], format_func=lambda x: next(a["name"] for a in apps() if a["id"] == x)) if apps() else None)
    if not app: st.info("Register a target to inspect source."); return
    if st.button("Run standalone static inspection", type="primary"):
        try:
            result = analyze_source(app["source_path"]); st.session_state["static_result"] = result
        except Exception as exc: st.error(str(exc))
    result = st.session_state.get("static_result")
    if result:
        m1, m2, m3 = st.columns(3); m1.metric("Files inspected", result["files_scanned"]); m2.metric("Potential findings", len(result["findings"])); m3.metric("Parser errors", len(result["errors"]))
        if result["findings"]: st.dataframe(pd.DataFrame(result["findings"])[["rule_id", "finding_type", "title", "file_path", "line_number", "severity", "confidence"]], use_container_width=True, hide_index=True)
        else: st.success("No matching rules in the selected source.")
    st.markdown("<div class='vb-card'><strong>Rule posture</strong><br><span style='color:#91a4bb'>Pattern matches are potential until dynamic evidence or analyst review corroborates them. Evidence snippets are truncated and redacted before persistence.</span></div>", unsafe_allow_html=True)


def render_dynamic_analysis():
    page_header("05 / runtime signals", "Dynamic Analysis", "Safe-marker probes compare baselines and responses only inside the authorized laboratory boundary.")
    demo_notice()
    rows = records(query("""SELECT f.*, a.name AS application_name, s.id AS scan_id FROM findings f JOIN applications a ON a.id=f.application_id JOIN scan_executions s ON s.id=f.scan_id WHERE f.detection_method LIKE '%Dynamic%' ORDER BY f.created_at DESC"""))
    scans_rows = records(scans())
    col1, col2, col3 = st.columns(3)
    col1.metric("Dynamic findings", len(rows)); col2.metric("Verified", sum(1 for r in rows if r["verification_status"] == "verified")); col3.metric("Coverage note", "Safe markers only")
    if rows: st.dataframe(pd.DataFrame(rows)[["title", "finding_type", "endpoint", "parameter", "verification_status", "confidence", "data_origin"]], use_container_width=True, hide_index=True)
    else: st.info("No dynamic findings stored yet. Start a controlled dynamic or hybrid scan from New Scan.")
    if scans_rows:
        st.caption("Dynamic limitations are persisted per scan. Missing target reachability is reported as partial, never as a fabricated pass.")
        st.dataframe(pd.DataFrame(scans_rows)[["id", "application_name", "status", "requests_processed", "routes_discovered", "limitation"]].head(8), use_container_width=True, hide_index=True)


def render_correlation():
    page_header("06 / evidence braid", "Hybrid Correlation", "Trace a user input from endpoint discovery to source location and dynamic verification.")
    demo_notice()
    rows = records(query("""SELECT f.*, a.name AS application_name, r.score, r.category FROM findings f JOIN applications a ON a.id=f.application_id LEFT JOIN risk_scores r ON r.finding_id=f.id AND r.created_at=(SELECT MAX(r2.created_at) FROM risk_scores r2 WHERE r2.finding_id=f.id) ORDER BY COALESCE(r.score,0) DESC"""))
    pairs = [r for r in rows if r.get("correlation_status") == "dynamically verified"]
    c1, c2, c3 = st.columns(3); c1.metric("Correlated", len(pairs)); c2.metric("Static-only", sum(1 for r in rows if r.get("correlation_status") == "static-only potential")); c3.metric("Dynamic-only", sum(1 for r in rows if r.get("correlation_status") == "dynamic-only"))
    if pairs:
        for row in pairs:
            st.markdown(f"<div class='vb-card'><div class='vb-eyebrow'>CORRELATED EVIDENCE · {row['id']}</div><h3>{row['title']}</h3><div class='vb-mono'>{row.get('endpoint') or '—'} · {row.get('method') or '—'} · {row.get('parameter') or '—'}</div><div style='display:flex;gap:8px;margin-top:10px'>{severity_chip(row['severity'])}<span class='vb-chip' style='color:#c4b5fd;background:rgba(139,92,246,.17)'>STATIC + DYNAMIC</span><span class='vb-chip' style='color:#a7f3d0;background:rgba(16,185,129,.14)'>VERIFIED</span></div><p style='color:#b8c7d9'>{row['description']}</p><div class='vb-rule'></div><div><strong>Static:</strong> {row.get('file_path') or 'source not mapped'}:{row.get('line_number') or '—'} → {row.get('sink') or 'sink evidence'}<br><strong>Stored evidence:</strong> {row.get('evidence') or '—'}</div></div>", unsafe_allow_html=True)
    else: st.info("No correlated evidence yet. Hybrid runs preserve the original static and dynamic records even when they remain unverified.")


def render_vulnerabilities():
    page_header("07 / issue registry", "Vulnerability Explorer", "Search, review, retest, and document the lifecycle of every stored finding.")
    rows = records(risk_rows())
    q = st.text_input("Search findings", placeholder="SQLi, route, file, ID...")
    severity = st.multiselect("Severity filter", ["Critical", "High", "Medium", "Low"], default=[])
    filtered = [r for r in rows if (not q or q.lower() in json.dumps(r, default=str).lower()) and (not severity or r["severity"] in severity)]
    st.dataframe(pd.DataFrame([{**r, "risk_score": r.get("score") or "—"} for r in filtered])[["id", "title", "finding_type", "application_name", "endpoint", "severity", "verification_status", "risk_score", "status"]] if filtered else pd.DataFrame(), use_container_width=True, hide_index=True)
    if filtered:
        chosen = st.selectbox("Open finding", [r["id"] for r in filtered], format_func=lambda x: next(r["title"] for r in filtered if r["id"] == x))
        row = next(r for r in filtered if r["id"] == chosen)
        with st.expander("Finding detail", expanded=True):
            st.markdown(f"### {row['title']}  {severity_chip(row['severity'])}", unsafe_allow_html=True)
            st.write(row["description"])
            a, b = st.columns(2)
            with a: st.markdown(f"**Detection**\n\n{row['detection_method']} · {row['verification_status']}\n\n**Location**\n\n`{row.get('file_path') or '—'}:{row.get('line_number') or '—'}`")
            with b: st.markdown(f"**Endpoint**\n\n`{row.get('method') or '—'} {row.get('endpoint') or '—'}` · `{row.get('parameter') or '—'}`\n\n**Correlation**\n\n{row.get('correlation_status')}")
            st.code(row.get("evidence") or "No evidence stored.", language="text")
            st.markdown(f"**Remediation:** {row.get('remediation')}")
            st.markdown(f"**Risk rationale:** {row.get('rationale') or 'No score persisted.'}")
            new_status = st.selectbox("Remediation status", ["open", "reviewed", "false positive", "accepted risk", "fixed", "awaiting retest"], index=["open", "reviewed", "false positive", "accepted risk", "fixed", "awaiting retest"].index(row["status"]))
            if st.button("Save status", key=f"status_{row['id']}"):
                execute("UPDATE findings SET status=?, updated_at=? WHERE id=?", [new_status, now_iso(), row["id"]]); insert("remediation_history", {"id": new_id("rem_"), "finding_id": row["id"], "old_status": row["status"], "new_status": new_status, "note": "Updated from Vulnerability Explorer", "actor": "local-user", "created_at": now_iso()}); audit("finding_status_updated", "finding", row["id"], {"status": new_status}); st.success("Status and audit trail saved."); st.rerun()


def render_prioritization():
    page_header("08 / remediation order", "Risk Prioritization", "VulnBlend ranks evidence-backed urgency without pretending its research formula is a universal standard.")
    demo_notice(); rows = records(risk_rows())
    ranked = sorted(rows, key=lambda r: float(r.get("score") or 0), reverse=True)
    st.markdown("<div class='vb-demo'><strong>FORMULA v1-RESEARCH</strong> · Severity, verification, confidence, reachability, exposure, impact, and analysis confidence are normalized to a 0–1 weighted score.</div>", unsafe_allow_html=True)
    if ranked:
        df = pd.DataFrame([{**r, "risk_score": r.get("score") or 0, "severity_rank": list(sorted(SEVERITY_VALUES, key=SEVERITY_VALUES.get, reverse=True)).index(r["severity"]) + 1} for r in ranked])
        st.markdown("<div class='vb-chart-title'>Risk score distribution</div>", unsafe_allow_html=True)
        st.plotly_chart(risk_histogram([{**r, "score": r.get("score") or 0, "category": r.get("category") or "Unscored"} for r in ranked]), use_container_width=True, config={"displayModeBar": False})
        st.dataframe(df[["priority_rank", "title", "severity", "verification_status", "risk_score", "category", "rationale"]], use_container_width=True, hide_index=True)
        st.subheader("Explain a score")
        chosen = st.selectbox("Finding", [r["id"] for r in ranked], format_func=lambda x: next(r["title"] for r in ranked if r["id"] == x))
        row = next(r for r in ranked if r["id"] == chosen); components = json_load(row.get("components"), {})
        st.bar_chart(pd.DataFrame({"component": list(components.keys()), "normalized value": list(components.values())}).set_index("component"))
        st.caption("Compare severity-only ordering by sorting the table on severity. Risk prioritization adds verification and evidence context; it does not change detection accuracy.")
    else: st.info("No scores are available yet.")


def render_history():
    page_header("09 / reproducibility", "Scan History", "Immutable execution records, stage timelines, configurations, and limitations.")
    rows = records(scans())
    if not rows: st.info("No scans have been executed yet."); return
    st.dataframe(pd.DataFrame(rows)[["id", "application_name", "mode", "status", "current_stage", "duration_seconds", "findings_count", "data_origin", "created_at"]], use_container_width=True, hide_index=True)
    chosen = st.selectbox("Open execution", [r["id"] for r in rows])
    scan = next(r for r in rows if r["id"] == chosen)
    st.markdown(f"<div class='vb-card'><strong>{scan['id']}</strong> · {scan['status']} · {scan['mode']}<br><span class='vb-mono'>{scan.get('limitation') or 'No limitations recorded.'}</span></div>", unsafe_allow_html=True)
    events = records(query("SELECT stage, level, message, created_at FROM execution_events WHERE scan_id=? ORDER BY created_at", [chosen]))
    st.subheader("Execution timeline"); st.dataframe(pd.DataFrame(events) if events else pd.DataFrame(), use_container_width=True, hide_index=True)


def render_experiments():
    page_header("10 / evaluation", "Experiment Lab", "Compare methods against stored ground truth without overstating accuracy or remediation gains.")
    demo_notice(); rows = records(query("SELECT e.method, e.name, e.data_origin, r.* FROM experiment_runs e JOIN experiment_results r ON r.experiment_id=e.id ORDER BY e.method"))
    if not rows: st.info("No experiment results available."); return
    df = pd.DataFrame(rows); st.markdown("<div class='vb-chart-title'>Controlled method comparison</div>", unsafe_allow_html=True); st.plotly_chart(method_comparison(df.to_dict("records")), use_container_width=True, config={"displayModeBar": False})
    display = df.copy();
    for col in ["precision", "recall", "f1", "false_positive_rate", "verification_rate", "crawl_coverage"]: display[col] = display[col].apply(lambda value: metric_label(value))
    st.dataframe(display[["method", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "false_positive_rate", "verification_rate", "execution_time", "crawl_coverage", "data_origin"]], use_container_width=True, hide_index=True)
    st.caption("Unavailable metrics indicate insufficient denominator or ground truth. Seeded demo rows are not external evaluation results.")


def render_reports():
    page_header("11 / evidence export", "Reports", "Generate redacted executive, technical, and research artifacts from stored records.")
    applications = apps(); scan_rows = scans()
    if not applications or not scan_rows: st.info("Run or seed a scan before generating reports."); return
    app = current_app(st.selectbox("Application", [a["id"] for a in applications], format_func=lambda x: next(a["name"] for a in applications if a["id"] == x)))
    selected_scans = [s for s in scan_rows if s["application_id"] == app["id"]]; scan = selected_scans[0] if selected_scans else scan_rows[0]
    st.caption(f"Using scan {scan['id']} · {scan['status']} · origin {scan['data_origin']}")
    findings = records(query("SELECT f.*, r.score, r.category FROM findings f LEFT JOIN risk_scores r ON r.finding_id=f.id AND r.created_at=(SELECT MAX(r2.created_at) FROM risk_scores r2 WHERE r2.finding_id=f.id) WHERE f.scan_id=?", [scan["id"]]))
    experiments = records(query("SELECT e.method, r.* FROM experiment_runs e JOIN experiment_results r ON r.experiment_id=e.id"))
    payload = report_payload(dict(app), dict(scan), findings, experiments)
    p1, p2, p3 = st.columns(3)
    with p1:
        if st.button("Generate PDF", type="primary"):
            name, content = generate_pdf(payload, app["id"], scan["id"]); st.session_state["pdf_report"] = (name, content)
        if st.session_state.get("pdf_report"): st.download_button("Download PDF", st.session_state["pdf_report"][1], file_name=st.session_state["pdf_report"][0], mime="application/pdf")
    with p2:
        if st.button("Generate CSV"):
            name, content = generate_csv(findings, app["id"], scan["id"]); st.session_state["csv_report"] = (name, content)
        if st.session_state.get("csv_report"): st.download_button("Download CSV", st.session_state["csv_report"][1], file_name=st.session_state["csv_report"][0], mime="text/csv")
    with p3:
        if st.button("Generate JSON"):
            name, content = generate_json(payload, app["id"], scan["id"]); st.session_state["json_report"] = (name, content)
        if st.session_state.get("json_report"): st.download_button("Download JSON", st.session_state["json_report"][1], file_name=st.session_state["json_report"][0], mime="application/json")
    reports = records(query("SELECT report_type, file_name, created_at FROM reports ORDER BY created_at DESC")); st.subheader("Generated report record"); st.dataframe(pd.DataFrame(reports) if reports else pd.DataFrame(), use_container_width=True, hide_index=True)


def render_settings():
    page_header("12 / control plane", "Settings", "Tune research parameters, review safety defaults, and understand what VulnBlend does not claim.")
    st.subheader("Risk formula weights")
    st.caption("These weights are configurable research parameters, not an established industry standard. Changes are persisted for reproducibility metadata.")
    cols = st.columns(4); values = {}
    for index, (key, value) in enumerate(RISK_WEIGHTS.items()):
        with cols[index % 4]: values[key] = st.number_input(key.replace("_", " ").title(), min_value=0.0, max_value=1.0, value=float(value), step=.01, format="%.2f")
    if st.button("Save risk configuration"):
        insert("settings", {"key": "risk_weights", "value": json.dumps(values), "updated_at": now_iso()}) if not one("SELECT key FROM settings WHERE key='risk_weights'") else execute("UPDATE settings SET value=?, updated_at=? WHERE key='risk_weights'", [json.dumps(values), now_iso()])
        audit("risk_weights_updated", "settings", "risk_weights", values); st.success("Weights saved for future reproducible runs.")
    st.subheader("Safety posture")
    st.dataframe(pd.DataFrame([{ "control": "Target allowlist", "status": "Enforced", "detail": "Local/isolated hosts only by default" }, {"control": "Authorization gate", "status": "Enforced", "detail": "Required before network or source scan"}, {"control": "Request limits", "status": "Enforced", "detail": "Depth, timeout, and max requests persisted per scan"}, {"control": "Evidence redaction", "status": "Enforced", "detail": "Secrets and session data are not stored raw"}, {"control": "ML risk prediction", "status": "Future extension", "detail": "Initial score is transparent and model-free"}]), use_container_width=True, hide_index=True)
