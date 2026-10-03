"""Lexical binding helpers. A local binding shadows builtins for its whole scope."""

from __future__ import annotations

import ast


def assigned_names(node: ast.AST) -> set[str]:
    return {
        n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
    }


def scope_bindings(statements: list[ast.stmt]) -> set[str]:
    names: set[str] = set()

    class Visitor(ast.NodeVisitor):
        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                names.add(node.id)

        def visit_Import(self, node: ast.Import) -> None:
            names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            names.update(alias.asname or alias.name for alias in node.names)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            names.add(node.name)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            names.add(node.name)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            names.add(node.name)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            pass

        def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
            if node.name:
                names.add(node.name)
            self.generic_visit(node)

    visitor = Visitor()
    for statement in statements:
        visitor.visit(statement)
    return names


def imports(node: ast.Import | ast.ImportFrom) -> dict[str, str]:
    if isinstance(node, ast.Import):
        return {
            a.asname or a.name.split(".")[0]: a.name if a.asname else a.name.split(".")[0]
            for a in node.names
        }
    if node.level or not node.module:
        return {}
    return {a.asname or a.name: f"{node.module}.{a.name}" for a in node.names if a.name != "*"}
