from vulblend.services.risk_engine import calculate_score, category_for

def test_verified_critical_scores_high():
    result = calculate_score({"severity": "Critical", "verification_status": "verified", "confidence": .95, "endpoint": "/search", "parameter": "q"})
    assert result["score"] > 70
    assert result["category"] in {"High", "Critical"}
    assert set(result["components"]) == {"severity", "verification", "static_confidence", "exploitability_evidence", "input_reachability", "endpoint_exposure", "potential_impact", "analysis_confidence"}

def test_category_boundaries():
    assert category_for(95) == "Critical"
    assert category_for(75) == "High"
    assert category_for(50) == "Medium"
    assert category_for(10) == "Low"
