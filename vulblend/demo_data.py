"""Safe, clearly labelled demo seed data for the isolated laboratory."""
from __future__ import annotations

import json
from datetime import timedelta

from .config import DEMO_MODE, DEFAULT_TARGET_URL, ROOT
from .db import audit, execute, insert, new_id, now_iso, one, query


def seed_demo_data() -> None:
    if not DEMO_MODE or one("SELECT id FROM applications LIMIT 1"):
        return
    now = now_iso()
    source_path = str(ROOT / "testbed" / "app")
    target_id = insert("applications", {
        "id": "app_lab_demo", "name": "VulnShop Lab", "description": "Deliberately vulnerable isolated testbed for reproducible SQLi and XSS research.",
        "target_url": DEFAULT_TARGET_URL, "source_path": source_path, "environment": "isolated-lab", "technology": "Python / Flask / SQLite",
        "category": "Research testbed", "authorization_confirmed": 1, "allowed_paths": ["/", "/search", "/profile"],
        "excluded_paths": ["/admin", "/health"], "crawler_depth": 2, "max_requests": 40, "timeout_seconds": 10,
        "vulnerability_classes": ["SQLi", "XSS"], "created_at": now, "updated_at": now,
    })
    cfg_id = insert("scan_configs", {
        "id": "cfg_demo_hybrid", "application_id": target_id, "mode": "Hybrid + Risk Prioritization",
        "selected_classes": ["SQLi", "XSS"], "crawler_depth": 2, "max_requests": 40, "timeout_seconds": 10,
        "included_routes": ["/search", "/profile"], "excluded_routes": ["/admin"], "payload_dictionary": "safe-lab-v1", "created_at": now,
    })
    scan_id = insert("scan_executions", {
        "id": "scan_demo_001", "config_id": cfg_id, "application_id": target_id, "status": "completed", "current_stage": "finalized",
        "progress": 1, "started_at": "2026-10-03T08:12:00+00:00", "ended_at": "2026-10-03T08:13:38+00:00", "duration_seconds": 98,
        "requests_processed": 18, "routes_discovered": 6, "findings_count": 4, "errors_count": 0, "data_origin": "demo",
        "limitation": "Seeded demo dataset; not an observed production assessment.", "created_at": "2026-10-03T08:12:00+00:00",
    })
    events = [
        ("scope", "Scope validated: isolated lab target and authorization confirmed."),
        ("static", "Python AST rules inspected 8 source files."),
        ("crawl", "Discovered 6 in-scope endpoints with 18 requests."),
        ("dynamic", "Safe SQLi/XSS marker comparisons completed."),
        ("correlation", "Linked 2 static and dynamic evidence pairs."),
        ("risk", "Calculated explainable research scores for 4 findings."),
    ]
    for stage, message in events:
        insert("execution_events", {"id": new_id("evt_"), "scan_id": scan_id, "stage": stage, "level": "info", "message": message, "metadata": {"data_origin": "demo"}, "created_at": now})
    for route, method, params, status in [
        ("/", "GET", [], 200), ("/search", "GET", ["q"], 200), ("/profile", "GET", ["name"], 200),
        ("/static/app.js", "GET", [], 200), ("/health", "GET", [], 200), ("/favicon.ico", "GET", [], 404),
    ]:
        insert("endpoints", {"id": new_id("end_"), "scan_id": scan_id, "application_id": target_id, "url": f"{DEFAULT_TARGET_URL}{route}", "route": route, "method": method, "parameters": params, "form_fields": [], "status_code": status, "content_type": "text/html", "depth": 0, "in_scope": 1, "discovered_at": now})
    findings = [
        {"id": "vuln_demo_sqli", "finding_type": "SQLi", "title": "User input reaches SQL query construction", "endpoint": "/search", "method": "GET", "parameter": "q", "file_path": "testbed/app/vulnerable_app.py", "line_number": 28, "source": "request.args['q']", "sink": "db.execute(query)", "description": "A request parameter is concatenated into a SQL query. Static evidence is corroborated by a safe lab response difference.", "evidence": "query = \"SELECT * FROM products WHERE name LIKE '%\" + q + \"%'\"", "remediation": "Use parameterized queries and validate the search input.", "severity": "Critical", "confidence": 0.96, "verification_status": "verified", "detection_method": "Static + Dynamic", "correlation_status": "dynamically verified"},
        {"id": "vuln_demo_xss", "finding_type": "XSS", "title": "Reflected search input in HTML response", "endpoint": "/search", "method": "GET", "parameter": "q", "file_path": "testbed/app/vulnerable_app.py", "line_number": 34, "source": "request.args['q']", "sink": "render_template_string(html)", "description": "A controlled marker is reflected in an HTML context without output encoding.", "evidence": "<h2>Results for: {{ q }}</h2>", "remediation": "Use context-aware output encoding and avoid rendering untrusted template strings.", "severity": "High", "confidence": 0.91, "verification_status": "verified", "detection_method": "Static + Dynamic", "correlation_status": "dynamically verified"},
        {"id": "vuln_demo_input", "finding_type": "Input handling", "title": "Request value is used without validation", "endpoint": "/profile", "method": "GET", "parameter": "name", "file_path": "testbed/app/vulnerable_app.py", "line_number": 42, "source": "request.args.get('name')", "sink": "response body", "description": "A request-derived value flows directly into a response path; this is a potential finding pending context review.", "evidence": "name = request.args.get('name', 'guest')", "remediation": "Validate length, character set, and expected format before use.", "severity": "Medium", "confidence": 0.68, "verification_status": "unverified", "detection_method": "Static", "correlation_status": "static-only potential"},
        {"id": "vuln_demo_headers", "finding_type": "Configuration", "title": "Security headers not observed in lab baseline", "endpoint": "/", "method": "GET", "parameter": None, "file_path": None, "line_number": None, "source": None, "sink": None, "description": "The demo baseline did not include a Content-Security-Policy header.", "evidence": "baseline headers summary: CSP absent", "remediation": "Define a restrictive Content-Security-Policy appropriate for the application.", "severity": "Low", "confidence": 0.74, "verification_status": "verified", "detection_method": "Dynamic", "correlation_status": "dynamic-only"},
    ]
    for finding in findings:
        finding.update({"scan_id": scan_id, "application_id": target_id, "status": "open", "data_origin": "demo", "created_at": now, "updated_at": now})
        insert("findings", finding)
        insert("evidence", {"id": new_id("ev_"), "finding_id": finding["id"], "evidence_type": "analysis", "content": finding["evidence"], "redacted": 1, "created_at": now})
    for code, name, typ, endpoint, parameter, truth in [
        ("TC-SQLI-001", "Search query injection", "SQLi", "/search", "q", 1),
        ("TC-XSS-001", "Search reflection", "XSS", "/search", "q", 1),
        ("TC-XSS-002", "Profile output encoding", "XSS", "/profile", "name", 0),
        ("TC-SEC-001", "Security header baseline", "Configuration", "/", None, 0),
    ]:
        insert("test_cases", {"id": new_id("tc_"), "code": code, "name": name, "finding_type": typ, "endpoint": endpoint, "parameter": parameter, "expected_behavior": "Safe lab ground truth case", "ground_truth": truth, "created_at": now})
    for finding_id, score, category, components, rationale in [
        ("vuln_demo_sqli", 94, "Critical", {"severity": 1, "verification": 1, "static_confidence": .96, "exploitability_evidence": .95, "input_reachability": 1, "endpoint_exposure": .7, "potential_impact": 1, "analysis_confidence": .95}, "Verified query construction issue with reachable input and high impact."),
        ("vuln_demo_xss", 82, "High", {"severity": .8, "verification": 1, "static_confidence": .91, "exploitability_evidence": .86, "input_reachability": 1, "endpoint_exposure": .7, "potential_impact": .7, "analysis_confidence": .9}, "Verified reflected HTML context with a reachable parameter."),
        ("vuln_demo_input", 48, "Medium", {"severity": .55, "verification": .2, "static_confidence": .68, "exploitability_evidence": .25, "input_reachability": .8, "endpoint_exposure": .5, "potential_impact": .4, "analysis_confidence": .65}, "Potential flow requires context review; dynamic verification is absent."),
        ("vuln_demo_headers", 24, "Low", {"severity": .25, "verification": 1, "static_confidence": .1, "exploitability_evidence": .2, "input_reachability": .1, "endpoint_exposure": .5, "potential_impact": .25, "analysis_confidence": .75}, "Baseline configuration gap is lower priority than verified injection findings."),
    ]:
        insert("risk_scores", {"id": new_id("risk_"), "finding_id": finding_id, "score": score, "category": category, "priority_rank": len(query("SELECT id FROM risk_scores")) + 1, "components": components, "rationale": rationale, "weights_version": "v1-research", "created_at": now})
    for method in ["Static Analysis", "Dynamic Analysis", "Hybrid Analysis", "Hybrid + Risk Prioritization"]:
        run_id = insert("experiment_runs", {"id": new_id("exp_"), "name": "Seeded lab comparison", "method": method, "configuration": {"depth": 2, "requests": 40, "classes": ["SQLi", "XSS"]}, "testbed_version": "lab-v1", "payload_dictionary": "safe-lab-v1", "started_at": now, "ended_at": now, "data_origin": "demo"})
        vals = {"Static Analysis": (2, 1, 1, 1), "Dynamic Analysis": (2, 0, 2, 1), "Hybrid Analysis": (2, 0, 2, 0), "Hybrid + Risk Prioritization": (2, 0, 2, 0)}[method]
        tp, fp, tn, fn = vals
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
        fpr = fp / (fp + tn) if fp + tn else None
        insert("experiment_results", {"id": new_id("res_"), "experiment_id": run_id, "tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision, "recall": recall, "f1": f1, "false_positive_rate": fpr, "verification_rate": .5 if method == "Static Analysis" else .85, "execution_time": {"Static Analysis": 12, "Dynamic Analysis": 36, "Hybrid Analysis": 48, "Hybrid + Risk Prioritization": 51}[method], "crawl_coverage": .2 if method == "Static Analysis" else .86, "notes": "Seeded demo result; not an external evaluation.", "created_at": now})
    audit("seed_demo_dataset", "application", target_id, {"data_origin": "demo", "records": "lab target, scan, findings, experiments"})
