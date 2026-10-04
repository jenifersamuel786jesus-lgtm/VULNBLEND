from __future__ import annotations

import ast
from .base import RuleFinding, SecurityRule

class UnsafeSQLRule(SecurityRule):
    rule_id = "VB-PY-SQL-001"
    name = "Unsafe SQL string construction"

    def inspect(self, tree: ast.AST, source: str, file_path: str) -> list[RuleFinding]:
        findings = []
        lines = source.splitlines()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany", "executescript"} and node.args:
                query_node = node.args[0]
                risky = isinstance(query_node, (ast.BinOp, ast.JoinedStr, ast.Call))
                if not risky and isinstance(query_node, ast.Name):
                    risky = query_node.id.lower() in {"query", "sql", "statement"}
                if risky:
                    line = getattr(node, "lineno", 1)
                    findings.append(RuleFinding(self.rule_id, "SQLi", "User-controlled or dynamic SQL construction", file_path, line, "request-derived value or dynamic string", f"{ast.unparse(node.func)}(...)"[:120], "Dynamic SQL reaches a database execution sink. This is a potential finding until corroborated.", lines[line - 1].strip()[:240] if lines else "", "Critical", .82, "Use parameterized queries; never concatenate request values into SQL."))
        return findings
