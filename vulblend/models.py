from __future__ import annotations

from dataclasses import dataclass
from typing import Any

@dataclass(frozen=True)
class FindingRecord:
    id: str
    finding_type: str
    title: str
    severity: str
    confidence: float
    verification_status: str
    risk_score: float | None = None
    risk_category: str | None = None
    data_origin: str = "real"

@dataclass(frozen=True)
class ScoreBreakdown:
    score: float
    category: str
    components: dict[str, float]
    rationale: str
    weights: dict[str, float]
