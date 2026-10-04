from __future__ import annotations

import ast
from .base import RuleFinding, SecurityRule

class UnsafeOutputRule(SecurityRule):
    rule_id = "VB-PY-OUTPUT-001"
    name = "Unsafe output rendering"

    def inspect(self, tree: ast.AST, source: str, file_path: str) -> list[RuleFinding]:
        findings = []
        lines = source.splitlines()
        for node in ast.walk(tree):
            if isinstance(node, ast.Return) and isinstance(node.value, ast.JoinedStr):
                line = getattr(node, "lineno", 1)
                findings.append(RuleFinding(self.rule_id, "XSS", "Interpolated value returned as HTML", file_path, line, "f-string or formatted response", "HTTP response body", "An interpolated value is returned directly and may be interpreted as HTML.", lines[line - 1].strip()[:240] if lines else "", "High", .72, "Encode output for its context and set an appropriate content type."))
        return findings
