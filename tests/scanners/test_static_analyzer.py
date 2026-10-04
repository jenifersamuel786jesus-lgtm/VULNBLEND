from vulblend.config import ROOT
from vulblend.services.static_analyzer import analyze_source

def test_fixture_has_expected_static_signals():
    result = analyze_source(str(ROOT / "testbed" / "app"))
    types = {finding["finding_type"] for finding in result["findings"]}
    assert "SQLi" in types
    assert "XSS" in types
    assert result["files_scanned"] >= 1
