"""Explainable risk scoring; thresholds and weights are research choices."""
from __future__ import annotations

from ..config import RISK_THRESHOLDS, RISK_WEIGHTS, SEVERITY_VALUES
from ..db import insert, new_id, now_iso, query


def category_for(score: float) -> str:
    if score >= RISK_THRESHOLDS["Critical"]:
        return "Critical"
    if score >= RISK_THRESHOLDS["High"]:
        return "High"
    if score >= RISK_THRESHOLDS["Medium"]:
        return "Medium"
    return "Low"


def calculate_score(finding: dict, overrides: dict[str, float] | None = None) -> dict:
    weights = dict(RISK_WEIGHTS)
    if overrides:
        weights.update(overrides)
    components = {
        "severity": SEVERITY_VALUES.get(finding.get("severity", "Low"), .25),
        "verification": {"verified": 1.0, "partially verified": .65, "unverified": .2}.get(str(finding.get("verification_status", "unverified")).lower(), .2),
        "static_confidence": float(finding.get("confidence", .4)),
        "exploitability_evidence": float(finding.get("exploitability_evidence", .25 if finding.get("verification_status") == "unverified" else .8)),
        "input_reachability": float(finding.get("input_reachability", .8 if finding.get("parameter") else .3)),
        "endpoint_exposure": float(finding.get("endpoint_exposure", .7 if finding.get("endpoint") in ("/search", "/login", "/api") else .45)),
        "potential_impact": float(finding.get("potential_impact", SEVERITY_VALUES.get(finding.get("severity", "Low"), .25))),
        "analysis_confidence": float(finding.get("analysis_confidence", finding.get("confidence", .5))),
    }
    raw = sum(components[key] * weights[key] for key in weights)
    score = round(max(0.0, min(100.0, raw * 100)), 1)
    category = category_for(score)
    verification = str(finding.get("verification_status", "unverified"))
    rationale = f"{category} priority because severity is {finding.get('severity', 'Low')}, verification is {verification}, and the weighted evidence score is {score}/100."
    return {"score": score, "category": category, "components": components, "weights": weights, "rationale": rationale}


def persist_score(finding: dict, rank: int | None = None, overrides: dict[str, float] | None = None) -> dict:
    result = calculate_score(finding, overrides)
    score_id = insert("risk_scores", {"id": new_id("risk_"), "finding_id": finding["id"], "score": result["score"], "category": result["category"], "priority_rank": rank, "components": result["components"], "rationale": result["rationale"], "weights_version": "v1-research", "created_at": now_iso()})
    result["id"] = score_id
    return result


def rank_findings(rows: list[dict]) -> list[dict]:
    scored = []
    for row in rows:
        result = calculate_score(row)
        scored.append({**row, **result})
    scored.sort(key=lambda item: item["score"], reverse=True)
    for rank, item in enumerate(scored, 1):
        item["priority_rank"] = rank
    return scored


def latest_scores() -> list:
    return query("""SELECT f.*, r.score, r.category, r.priority_rank, r.components, r.rationale
        FROM findings f LEFT JOIN risk_scores r ON r.finding_id=f.id
        WHERE r.id IS NULL OR r.created_at=(SELECT MAX(r2.created_at) FROM risk_scores r2 WHERE r2.finding_id=f.id)
        ORDER BY COALESCE(r.score, 0) DESC""")
