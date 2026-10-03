"""Structured per-scope control-flow graphs; no target code is evaluated."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass
class Edge:
    target: int
    condition: ast.expr | None = None
    truth: bool = True


@dataclass
class Block:
    id: int
    statement: ast.AST | None
    edges: list[Edge] = field(default_factory=list)


@dataclass
class Graph:
    blocks: dict[int, Block]
    entry: int


class Builder:
    def __init__(self) -> None:
        self.blocks: dict[int, Block] = {}

    def node(self, stmt: ast.AST | None) -> int:
        index = len(self.blocks)
        self.blocks[index] = Block(index, stmt)
        return index

    def sequence(
        self, statements: list[ast.stmt], after: int, loop: tuple[int, int] | None = None
    ) -> int:
        current = after
        for stmt in reversed(statements):
            index = self.node(stmt)
            if isinstance(stmt, ast.If):
                yes = self.sequence(stmt.body, current, loop)
                no = self.sequence(stmt.orelse, current, loop)
                self.blocks[index].edges = [Edge(yes, stmt.test), Edge(no, stmt.test, False)]
            elif isinstance(stmt, (ast.While, ast.For, ast.AsyncFor)):
                otherwise = self.sequence(stmt.orelse, current, loop)
                body = self.sequence(stmt.body, index, (current, index))
                test = stmt.test if isinstance(stmt, ast.While) else None
                self.blocks[index].edges = [Edge(body, test), Edge(otherwise, test, False)]
            elif isinstance(stmt, ast.Break):
                self.blocks[index].edges = [Edge(loop[0])] if loop else []
            elif isinstance(stmt, ast.Continue):
                self.blocks[index].edges = [Edge(loop[1])] if loop else []
            elif isinstance(stmt, (ast.Return, ast.Raise)):
                self.blocks[index].edges = []
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                self.blocks[index].edges = [Edge(self.sequence(stmt.body, current, loop))]
            elif isinstance(stmt, (ast.Try, ast.TryStar)):
                # Exception edges conservatively join; completion diagnostics disclose this model.
                final = self.sequence(stmt.finalbody, current, loop)
                normal = self.sequence(stmt.orelse, final, loop)
                entries = [self.sequence(stmt.body, normal, loop)]
                entries.extend(self.sequence(h.body, final, loop) for h in stmt.handlers)
                self.blocks[index].edges = [Edge(item) for item in entries]
            else:
                self.blocks[index].edges = [Edge(current)]
            current = index
        return current

    def build(self, statements: list[ast.stmt]) -> Graph:
        exit_node = self.node(None)
        entry = self.sequence(statements, exit_node)
        return Graph(self.blocks, entry)
