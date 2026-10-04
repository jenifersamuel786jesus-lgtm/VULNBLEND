"""Hybrid evidence correlation; names alone never confirm findings."""
from __future__ import annotations

from collections import defaultdict


def _match(static: dict, dynamic: dict) -> float:
    score = 0.0
    if static.get("finding_type") == dynamic.get("finding_type"): score += .35
    if static.get("endpoint") and static.get("endpoint") == dynamic.get("endpoint"): score += .25
    if static.get("parameter") and static.get("parameter") == dynamic.get("parameter"): score += .2
    if static.get("method") and static.get("method") == dynamic.get("method"): score += .1
    if static.get("file_path") and dynamic.get("file_path"): score += .1
    return score


def correlate(static_findings: list[dict], dynamic_findings: list[dict]) -> dict:
    pairs = []
    used_dynamic = set()
    merged = []
    for static in static_findings:
        best = None
        best_score = 0.0
        for index, dynamic in enumerate(dynamic_findings):
            if index in used_dynamic:
                continue
            score = _match(static, dynamic)
            if score > best_score:
                best_score, best = score, (index, dynamic)
        combined = dict(static)
        if best and best_score >= .55:
            index, dynamic = best
            used_dynamic.add(index)
            combined.update({"endpoint": dynamic.get("endpoint") or static.get("endpoint"), "method": dynamic.get("method") or static.get("method"), "parameter": dynamic.get("parameter") or static.get("parameter"), "verification_status": "verified" if dynamic.get("verification_status") == "verified" else "partially verified", "detection_method": "Static + Dynamic", "correlation_status": "dynamically verified", "dynamic_evidence": dynamic.get("evidence"), "correlation_score": round(best_score, 2)})
            pairs.append({"static_title": static.get("title"), "dynamic_title": dynamic.get("title"), "route": combined.get("endpoint"), "parameter": combined.get("parameter"), "match_score": round(best_score, 2), "status": "correlated"})
        else:
            combined["correlation_status"] = "static-only potential"
        merged.append(combined)
    for index, dynamic in enumerate(dynamic_findings):
        if index not in used_dynamic:
            dynamic = dict(dynamic)
            dynamic["correlation_status"] = "dynamic-only"
            merged.append(dynamic)
    return {"findings": merged, "pairs": pairs, "counts": {"static_only": sum(1 for item in merged if item.get("correlation_status") == "static-only potential"), "dynamic_only": sum(1 for item in merged if item.get("correlation_status") == "dynamic-only"), "correlated": len(pairs)}}
