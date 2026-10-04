"""Configuration and safety defaults for VulnBlend."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
REPORT_DIR = ROOT / "reports"
DB_PATH = Path(os.getenv("VULNBLEND_DB_PATH", str(DATA_DIR / "vulnblend.db")))
DEFAULT_TARGET_URL = os.getenv("VULNBLEND_DEFAULT_TARGET_URL", "http://testbed:8080")
DEMO_MODE = os.getenv("VULNBLEND_DEMO_MODE", "true").lower() == "true"
MAX_UPLOAD_MB = int(os.getenv("VULNBLEND_MAX_UPLOAD_MB", "10"))
SCAN_TIMEOUT = int(os.getenv("VULNBLEND_SCAN_TIMEOUT", "15"))
ALLOWED_HOSTS = {h.strip().lower() for h in os.getenv("VULNBLEND_ALLOWED_HOSTS", "127.0.0.1,localhost,testbed,web").split(",") if h.strip()}

RISK_WEIGHTS = {
    "severity": 0.22,
    "verification": 0.20,
    "static_confidence": 0.15,
    "exploitability_evidence": 0.12,
    "input_reachability": 0.12,
    "endpoint_exposure": 0.10,
    "potential_impact": 0.06,
    "analysis_confidence": 0.03,
}
RISK_THRESHOLDS = {"Critical": 90, "High": 70, "Medium": 40, "Low": 0}
SEVERITY_VALUES = {"Critical": 1.0, "High": 0.8, "Medium": 0.55, "Low": 0.25, "Info": 0.05}

for directory in (DATA_DIR, REPORT_DIR):
    directory.mkdir(parents=True, exist_ok=True)
