"""Deterministic Python AST analyzer used by VulnBlend."""
from __future__ import annotations

import ast
from pathlib import Path

from ..rules.python_input import RequestInputRule
from ..rules.python_output import UnsafeOutputRule
from ..rules.python_sql import UnsafeSQLRule
from ..services.target_guard import validate_source_path

RULES = [UnsafeSQLRule(), RequestInputRule(), UnsafeOutputRule()]


def analyze_source(source_path: str) -> dict:
    root = validate_source_path(source_path)
    findings = []
    files_scanned = 0
    errors = []
    for path in sorted(root.rglob("*.py")):
        if any(part.startswith(".") or part == "__pycache__" for part in path.parts):
            continue
        files_scanned += 1
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(path))
            for rule in RULES:
                for finding in rule.inspect(tree, source, str(path.relative_to(root.parent))):
                    findings.append({
                        "rule_id": finding.rule_id, "finding_type": finding.finding_type, "title": finding.title,
                        "file_path": finding.file_path, "line_number": finding.line_number, "source": finding.source,
                        "sink": finding.sink, "description": finding.description, "evidence": finding.evidence,
                        "severity": finding.severity, "confidence": finding.confidence, "remediation": finding.remediation,
                        "detection_method": "Static", "verification_status": "unverified", "correlation_status": "static-only potential",
                    })
        except (OSError, SyntaxError) as exc:
            errors.append({"file": str(path), "error": str(exc)[:200]})
    return {"files_scanned": files_scanned, "findings": findings, "errors": errors, "data_origin": "real"}
