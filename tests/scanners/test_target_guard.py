import pytest
from vulblend.services.target_guard import ScopeError, validate_target, validate_source_path
from vulblend.config import ROOT

def test_unauthorized_target_is_blocked():
    with pytest.raises(ScopeError):
        validate_target("http://localhost:8080", False)

def test_public_target_is_blocked():
    with pytest.raises(ScopeError):
        validate_target("https://example.com", True)

def test_testbed_target_is_allowed():
    result = validate_target("http://testbed:8080", True)
    assert result["host"] == "testbed"

def test_workspace_source_allowed():
    assert validate_source_path(str(ROOT / "testbed" / "app")).exists()
