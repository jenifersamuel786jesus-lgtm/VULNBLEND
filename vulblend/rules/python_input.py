from __future__ import annotations

import ast
from .base import RuleFinding, SecurityRule

class RequestInputRule(SecurityRule):
    rule_id = "VB-PY-INPUT-001"
    name = "Request-derived input flow"

    def inspect(self, tree: ast.AST, source: str, file_path: str) -> list[RuleFinding]:
        findings = []
        lines = source.splitlines()
        request_names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and isinstance(node.value.func.value, ast.Name) and node.value.func.value.id == "request":
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        request_names.add(target.id)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {"render_template_string", "Response"}:
                text = ast.unparse(node)
                if any(name in text for name in request_names):
                    line = getattr(node, "lineno", 1)
                    findings.append(RuleFinding(self.rule_id, "XSS", "Request value reaches output rendering", file_path, line, "request.args/request.form", node.func.id, "A request-derived value reaches an output sink; rendering context must be verified.", lines[line - 1].strip()[:240] if lines else "", "High", .76, "Apply context-aware output encoding and avoid dynamic template strings."))
        return findings
