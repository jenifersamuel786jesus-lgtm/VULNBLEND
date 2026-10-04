from __future__ import annotations

from dataclasses import dataclass
from typing import Any

@dataclass
class RuleFinding:
    rule_id: str
    finding_type: str
    title: str
    file_path: str
    line_number: int
    source: str
    sink: str
    description: str
    evidence: str
    severity: str
    confidence: float
    remediation: str

class SecurityRule:
    rule_id = "VB-GENERIC"
    name = "Generic security rule"

    def inspect(self, tree: Any, source: str, file_path: str) -> list[RuleFinding]:
        raise NotImplementedError
