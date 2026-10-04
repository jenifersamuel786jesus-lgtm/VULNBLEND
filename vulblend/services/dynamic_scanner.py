"""Non-destructive dynamic probes for authorized lab applications."""
from __future__ import annotations

import hashlib
from urllib.parse import urlencode, urljoin

import requests

from .target_guard import validate_target

SQL_MARKER = "vb_safe_sql_marker"
XSS_MARKER = "vb_safe_xss_marker"
SQL_ERROR_PATTERNS = ("sql syntax", "sqlite error", "database error", "near ")


def _signature(response: requests.Response) -> str:
    return hashlib.sha256(response.text[:100_000].encode("utf-8", "replace")).hexdigest()[:16]


def dynamic_scan(target_url: str, authorized: bool, endpoints: list[dict], timeout: int = 10, max_requests: int = 40) -> dict:
    target = validate_target(target_url, authorized)
    findings = []
    evidence = []
    requests_processed = 0
    errors = []
    for endpoint in endpoints[:max_requests]:
        route = endpoint.get("route", "/")
        params = endpoint.get("parameters") or endpoint.get("form_fields") or []
        if not params or endpoint.get("method") != "GET":
            continue
        parameter = params[0]
        url = urljoin(target["base"], route)
        try:
            baseline = requests.get(url, params={parameter: "baseline"}, timeout=timeout, allow_redirects=False, headers={"User-Agent": "VulnBlend-Lab/0.1"})
            requests_processed += 1
            for kind, marker in (("SQLi", SQL_MARKER), ("XSS", XSS_MARKER)):
                probe = requests.get(url, params={parameter: marker}, timeout=timeout, allow_redirects=False, headers={"User-Agent": "VulnBlend-Lab/0.1"})
                requests_processed += 1
                reflected = marker in probe.text
                sql_error = any(pattern in probe.text.lower() for pattern in SQL_ERROR_PATTERNS)
                changed = _signature(baseline) != _signature(probe) or baseline.status_code != probe.status_code
                if (kind == "XSS" and reflected) or (kind == "SQLi" and sql_error) or (kind == "SQLi" and changed and probe.status_code >= 500):
                    verification = "verified"
                    title = "Controlled reflected marker observed" if kind == "XSS" else "Suspicious SQL response difference observed"
                    findings.append({"finding_type": kind, "title": title, "endpoint": route, "method": "GET", "parameter": parameter, "description": "Safe laboratory marker produced an observable response signal.", "evidence": f"baseline={baseline.status_code}/{_signature(baseline)} probe={probe.status_code}/{_signature(probe)} reflected={reflected} sql_error={sql_error}", "severity": "High" if kind == "XSS" else "Critical", "confidence": .88, "verification_status": verification, "detection_method": "Dynamic", "correlation_status": "dynamic-only"})
                    evidence.append({"kind": kind, "route": route, "parameter": parameter, "baseline_status": baseline.status_code, "probe_status": probe.status_code, "marker_reflected": reflected, "sql_error": sql_error})
        except requests.RequestException as exc:
            errors.append({"url": url, "error": str(exc)[:200]})
    return {"findings": findings, "evidence": evidence, "requests_processed": requests_processed, "errors": errors, "limitations": ["Only safe markers were used.", "Dynamic verification requires an available reachable lab target."], "data_origin": "real"}
