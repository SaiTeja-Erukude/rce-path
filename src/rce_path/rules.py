"""Data-only sink rules, separated from symbol and flow analysis for later rule packs."""

from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class SinkRule:
    id: str
    names: tuple[str, ...]
    argument_position: int
    argument_names: tuple[str, ...]
    impact: str
    requires_shell: bool = False


SINK_RULES = (
    SinkRule("python.eval", ("builtins.eval",), 0, ("source",), "Potential code execution"),
    SinkRule(
        "python.exec", ("builtins.exec",), 0, ("source", "object"), "Potential code execution"
    ),
    SinkRule("os.system", ("os.system",), 0, ("command",), "Potential command injection"),
    SinkRule("os.popen", ("os.popen",), 0, ("cmd",), "Potential command injection"),
    SinkRule(
        "subprocess.shell",
        tuple(
            f"subprocess.{name}"
            for name in (
                "run",
                "call",
                "check_call",
                "check_output",
                "Popen",
                "getoutput",
                "getstatusoutput",
            )
        ),
        0,
        ("args", "cmd"),
        "Potential command injection",
        True,
    ),
)


def argument(call: ast.Call, rule: SinkRule) -> ast.expr | None:
    if len(call.args) > rule.argument_position:
        node = call.args[rule.argument_position]
        return None if isinstance(node, ast.Starred) else node
    return next((kw.value for kw in call.keywords if kw.arg in rule.argument_names), None)


def shell_argument(call: ast.Call, symbol: str) -> ast.expr | None:
    keyword = next((kw.value for kw in call.keywords if kw.arg == "shell"), None)
    # Popen permits positional shell in position 8; wrappers accept shell only via kwargs.
    if keyword is None and symbol == "subprocess.Popen" and len(call.args) > 8:
        return call.args[8]
    return keyword
