"""Reproducible staged scan execution with SQLite progress records."""
from __future__ import annotations

import json
import time
from typing import Callable

from ..db import audit, execute, insert, new_id, now_iso, one, query
from .correlation import correlate
from .crawler import crawl
from .dynamic_scanner import dynamic_scan
from .risk_engine import persist_score
from .static_analyzer import analyze_source
from .target_guard import ScopeError, validate_target, validate_source_path


def _event(scan_id: str, stage: str, message: str, level: str = "info", metadata: dict | None = None) -> None:
    insert("execution_events", {"id": new_id("evt_"), "scan_id": scan_id, "stage": stage, "level": level, "message": message, "metadata": metadata or {}, "created_at": now_iso()})


def _update(scan_id: str, **fields) -> None:
    assignments = ", ".join(f"{key}=?" for key in fields)
    execute(f"UPDATE scan_executions SET {assignments} WHERE id=?", [*fields.values(), scan_id])


def _persist_finding(finding: dict, scan_id: str, app_id: str) -> dict:
    row = {
        "id": finding.get("id", new_id("vuln_")), "scan_id": scan_id, "application_id": app_id,
        "finding_type": finding.get("finding_type", "Unknown"), "title": finding.get("title", "Potential security finding"),
        "endpoint": finding.get("endpoint"), "method": finding.get("method"), "parameter": finding.get("parameter"),
        "file_path": finding.get("file_path"), "line_number": finding.get("line_number"), "source": finding.get("source"), "sink": finding.get("sink"),
        "description": finding.get("description", "No description available."), "evidence": finding.get("evidence", "Evidence not available."),
        "remediation": finding.get("remediation", "Review the affected code path."), "severity": finding.get("severity", "Medium"),
        "confidence": finding.get("confidence", .5), "verification_status": finding.get("verification_status", "unverified"),
        "detection_method": finding.get("detection_method", "Static"), "correlation_status": finding.get("correlation_status", "unverified"),
        "status": "open", "data_origin": "real", "created_at": now_iso(), "updated_at": now_iso(),
    }
    insert("findings", row)
    insert("evidence", {"id": new_id("ev_"), "finding_id": row["id"], "evidence_type": "analysis", "content": row["evidence"], "redacted": 1, "created_at": now_iso()})
    return row


def run_scan(scan_id: str, config: dict, app: dict, progress: Callable[[float, str], None] | None = None) -> dict:
    """Run stages synchronously; UI can show progress and persisted state."""
    started = time.time()
    config_id = config["id"]
    mode = config["mode"]
    try:
        validate_target(app["target_url"], bool(app["authorization_confirmed"]))
        source = validate_source_path(app["source_path"]) if app.get("source_path") else None
    except ScopeError as exc:
        _update(scan_id, status="blocked", current_stage="scope", progress=0, ended_at=now_iso(), duration_seconds=0, limitation=str(exc))
        _event(scan_id, "scope", str(exc), "error")
        return {"status": "blocked", "error": str(exc)}
    _update(scan_id, status="running", started_at=now_iso(), current_stage="scope", progress=.05)
    _event(scan_id, "scope", "Scope validated: authorization and allowlist checks passed.")
    if progress: progress(.05, "Scope validated")

    static_findings: list[dict] = []
    dynamic_findings: list[dict] = []
    endpoint_rows: list[dict] = []
    requests_processed = 0
    routes_discovered = 0
    errors = 0
    limitation = None
    if mode in {"Static Analysis", "Hybrid Analysis", "Hybrid + Risk Prioritization"} and source:
        _update(scan_id, current_stage="static", progress=.18)
        _event(scan_id, "static", f"Inspecting Python source under {source}.")
        static_result = analyze_source(str(source)); static_findings = static_result["findings"]; errors += len(static_result["errors"])
        _event(scan_id, "static", f"Inspected {static_result['files_scanned']} files and found {len(static_findings)} potential findings.", metadata={"files_scanned": static_result["files_scanned"]})
    if progress: progress(.35, "Static analysis complete")

    if mode in {"Dynamic Analysis", "Hybrid Analysis", "Hybrid + Risk Prioritization"}:
        _update(scan_id, current_stage="crawl", progress=.42)
        _event(scan_id, "crawl", "Discovering in-scope routes with request limits enforced.")
        crawl_result = crawl(app["target_url"], bool(app["authorization_confirmed"]), json.loads(app.get("allowed_paths") or "[]"), json.loads(app.get("excluded_paths") or "[]"), int(config["crawler_depth"]), int(config["max_requests"]), int(config["timeout_seconds"]))
        endpoint_rows = crawl_result["endpoints"]; requests_processed += crawl_result["requests_processed"]; routes_discovered = len(endpoint_rows); errors += len(crawl_result["errors"])
        for endpoint in endpoint_rows:
            insert("endpoints", {"id": new_id("end_"), "scan_id": scan_id, "application_id": app["id"], **endpoint, "parameters": endpoint.get("parameters", []), "form_fields": endpoint.get("form_fields", []), "discovered_at": now_iso()})
        if crawl_result["errors"]:
            limitation = "Target was reachable only partially; crawl errors are recorded." if endpoint_rows else "Dynamic target was unavailable; no dynamic findings were fabricated."
        _event(scan_id, "crawl", f"Discovered {routes_discovered} routes with {requests_processed} requests.", "warning" if crawl_result["errors"] else "info")
        if progress: progress(.58, "Endpoint inventory complete")
        _update(scan_id, current_stage="dynamic", progress=.68, requests_processed=requests_processed, routes_discovered=routes_discovered)
        dynamic_result = dynamic_scan(app["target_url"], bool(app["authorization_confirmed"]), endpoint_rows, int(config["timeout_seconds"]), int(config["max_requests"]))
        dynamic_findings = dynamic_result["findings"]; requests_processed += dynamic_result["requests_processed"]; errors += len(dynamic_result["errors"])
        _event(scan_id, "dynamic", f"Completed safe-marker comparison with {len(dynamic_findings)} dynamic findings.", "warning" if dynamic_result["errors"] else "info")
    if progress: progress(.75, "Dynamic analysis complete")

    if mode in {"Hybrid Analysis", "Hybrid + Risk Prioritization"}:
        _update(scan_id, current_stage="correlation", progress=.8)
        merged = correlate(static_findings, dynamic_findings)["findings"]
    else:
        merged = static_findings or dynamic_findings
    persisted = [_persist_finding(finding, scan_id, app["id"]) for finding in merged]
    _event(scan_id, "correlation", f"Persisted {len(persisted)} findings with evidence links.")
    if mode == "Hybrid + Risk Prioritization" or mode in {"Hybrid Analysis", "Static Analysis", "Dynamic Analysis"}:
        _update(scan_id, current_stage="risk", progress=.9)
        ranked = []
        for finding in persisted:
            ranked.append(persist_score(finding))
        if ranked:
            ordered = sorted(ranked, key=lambda item: item["score"], reverse=True)
            for rank, item in enumerate(ordered, 1):
                execute("UPDATE risk_scores SET priority_rank=? WHERE id=?", [rank, item["id"]])
        _event(scan_id, "risk", f"Calculated {len(ranked)} explainable risk scores.")
    duration = round(time.time() - started, 2)
    status = "completed" if not (limitation and not persisted) else "partial"
    _update(scan_id, status=status, current_stage="finalized", progress=1, ended_at=now_iso(), duration_seconds=duration, requests_processed=requests_processed, routes_discovered=routes_discovered, findings_count=len(persisted), errors_count=errors, limitation=limitation)
    audit("scan_completed", "scan", scan_id, {"status": status, "findings": len(persisted), "data_origin": "real"})
    if progress: progress(1.0, "Scan finalized")
    return {"status": status, "findings": persisted, "requests_processed": requests_processed, "routes_discovered": routes_discovered, "errors": errors, "limitation": limitation}


def create_scan(config: dict, app: dict) -> str:
    scan_id = new_id("scan_")
    insert("scan_executions", {"id": scan_id, "config_id": config["id"], "application_id": app["id"], "status": "queued", "current_stage": "queued", "progress": 0, "created_at": now_iso(), "data_origin": "real"})
    audit("scan_queued", "scan", scan_id, {"mode": config["mode"], "application_id": app["id"]})
    return scan_id
