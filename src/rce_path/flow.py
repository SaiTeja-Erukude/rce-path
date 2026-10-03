"""Bounded intraprocedural abstract interpretation over explicit CFGs."""

from __future__ import annotations

import ast
import hashlib
from collections import deque
from dataclasses import dataclass, replace
from typing import Any, Literal

from .cfg import Builder
from .config import ScanConfig
from .findings import Diagnostic, EvidenceStep, Finding, Location, SourceCategory, fingerprint
from .rules import SINK_RULES, argument, shell_argument
from .symbols import assigned_names, imports, scope_bindings


@dataclass(frozen=True)
class Trace:
    category: SourceCategory
    source: Location
    steps: tuple[EvidenceStep, ...]
    conditions: tuple[str, ...] = ()


@dataclass(frozen=True)
class Value:
    traces: tuple[Trace, ...] = ()
    symbol: str | None = None
    known: bool = False
    constant: Any = None
    unresolved: tuple[EvidenceStep, ...] = ()
    literal_only: bool = False
    alternatives: tuple[str, ...] = ()


EMPTY = Value()
Environment = dict[str, Value]


def unique(items: tuple) -> tuple:
    result: list = []
    for item in items:
        if item not in result:
            result.append(item)
    return tuple(result)


class Analyzer:
    def __init__(self, source: str, file: str, config: ScanConfig) -> None:
        self.source = source
        self.file = file
        self.config = config
        self.findings: dict[str, Finding] = {}
        self.diagnostics: list[Diagnostic] = []
        self.steps_taken = 0
        self.scope = "<module>"

    def diagnostic(
        self, code: str, message: str, node: ast.AST | None = None, incomplete: bool = False
    ) -> None:
        diagnostic = Diagnostic(
            code=code,
            message=message,
            file=self.file,
            line=getattr(node, "lineno", None),
            affects_completion=incomplete,
        )
        if diagnostic not in self.diagnostics:
            self.diagnostics.append(diagnostic)

    def location(self, node: ast.AST) -> Location:
        return Location(
            file=self.file,
            line=getattr(node, "lineno", 1),
            column=getattr(node, "col_offset", 0),
            end_line=int(getattr(node, "end_lineno", None) or getattr(node, "lineno", 1) or 1),
            end_column=int(
                getattr(node, "end_col_offset", None) or getattr(node, "col_offset", 0) or 0
            ),
        )

    def step(self, node: ast.AST, kind: str, description: str) -> EvidenceStep:
        location = self.location(node)
        identity = f"{location.model_dump_json()}:{kind}:{description}"
        snippet = ast.get_source_segment(self.source, node) or ""
        return EvidenceStep(
            id=hashlib.sha256(identity.encode()).hexdigest()[:16],
            kind=kind,
            location=location,
            description=description,
            snippet=snippet[:512],
        )

    def merge(self, left: Value, right: Value) -> Value:
        # Origins are merged without fabricating cross-call propagation. Branch paths are
        # explicit overapproximations; steps preserve first traversal order per origin.
        traces: dict[str, Trace] = {}
        for trace in left.traces + right.traces:
            key = trace.steps[0].id
            old = traces.get(key)
            if old:
                trace = replace(
                    trace,
                    steps=unique(old.steps + trace.steps),
                    conditions=unique(old.conditions + trace.conditions),
                )
            if len(trace.steps) > self.config.max_evidence_steps:
                self.diagnostic(
                    "evidence_limit", "Evidence path exceeded its step budget.", incomplete=True
                )
                trace = replace(trace, steps=trace.steps[: self.config.max_evidence_steps])
            traces[key] = trace
        if len(traces) > 64:
            self.diagnostic(
                "origin_limit", "More than 64 origins at one program point.", incomplete=True
            )
        same = left.known and right.known and left.constant == right.constant
        return Value(
            traces=tuple(list(traces.values())[:64]),
            symbol=left.symbol if left.symbol == right.symbol else None,
            known=same,
            constant=left.constant if same else None,
            unresolved=unique(left.unresolved + right.unresolved)[:64],
            literal_only=left.literal_only and right.literal_only,
            alternatives=unique(
                left.alternatives
                + right.alternatives
                + ((left.symbol,) if left.symbol else ())
                + ((right.symbol,) if right.symbol else ())
            )[:64],
        )

    def join(self, left: Environment, right: Environment) -> Environment:
        return {
            key: self.merge(left.get(key, EMPTY), right.get(key, EMPTY))
            for key in left.keys() | right.keys()
        }

    def advance(self, value: Value, node: ast.AST, kind: str, description: str) -> Value:
        step = self.step(node, kind, description)
        updated = []
        for trace in value.traces:
            steps = unique(trace.steps + (step,))
            if len(steps) >= self.config.max_evidence_steps:
                self.diagnostic(
                    "evidence_limit", "Evidence path exceeded its step budget.", node, True
                )
                steps = steps[: self.config.max_evidence_steps - 1]
            updated.append(replace(trace, steps=steps))
        unresolved = unique(value.unresolved + ((step,) if value.unresolved else ()))
        if len(unresolved) >= self.config.max_evidence_steps:
            self.diagnostic(
                "evidence_limit", "Unresolved evidence exceeded its step budget.", node, True
            )
            unresolved = unresolved[: self.config.max_evidence_steps - 1]
        return replace(value, traces=tuple(updated), unresolved=unresolved)

    def source_value(self, node: ast.AST, category: SourceCategory, label: str) -> Value:
        step = self.step(node, "source", label)
        return Value(traces=(Trace(category, step.location, (step,)),))

    def candidates(self, node: ast.expr, env: Environment) -> tuple[str, ...]:
        if isinstance(node, ast.Name) and node.id in env:
            value = env[node.id]
            return unique(((value.symbol,) if value.symbol else ()) + value.alternatives)
        if isinstance(node, ast.Attribute):
            return tuple(f"{symbol}.{node.attr}" for symbol in self.candidates(node.value, env))
        symbol = self.resolve(node, env)
        return (symbol,) if symbol else ()

    def resolve(self, node: ast.expr, env: Environment) -> str | None:
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id].symbol
            return f"builtins.{node.id}" if node.id in {"eval", "exec", "input", "open"} else None
        if isinstance(node, ast.Attribute):
            parent = self.resolve(node.value, env)
            return f"{parent}.{node.attr}" if parent else None
        return None

    def external_source(self, node: ast.expr, env: Environment) -> Value | None:
        symbol = self.resolve(node, env)
        if symbol in {"flask.request.args", "flask.request.form", "flask.request.data"}:
            if isinstance(node, ast.Name) and env[node.id].traces:
                return env[node.id]
            return replace(
                self.source_value(node, "network_request", f"Modeled {symbol}"), symbol=symbol
            )
        if symbol in {"os.environ", "sys.argv"}:
            if isinstance(node, ast.Name) and env[node.id].traces:
                return env[node.id]
            return replace(
                self.source_value(node, "local_input", f"Local process input: {symbol}"),
                symbol=symbol,
            )
        if isinstance(node, ast.Call):
            callee = self.resolve(node.func, env)
            if callee in {
                "flask.request.get_data",
                "flask.request.args.get",
                "flask.request.form.get",
                "flask.request.args.getlist",
                "flask.request.form.getlist",
            }:
                return self.source_value(node, "network_request", f"Modeled {callee}")
            if callee in {"builtins.input", "os.getenv", "os.environ.get"}:
                return self.source_value(node, "local_input", f"Local process input: {callee}")
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "read",
                "readline",
                "readlines",
            }:
                if self.resolve(node.func.value, env) == "local.file":
                    return self.source_value(node, "local_input", "Local file content")
        return None

    def expression(self, node: ast.expr | None, env: Environment) -> Value:
        if node is None:
            return EMPTY
        external = self.external_source(node, env)
        if external:
            return external
        if isinstance(node, ast.Name):
            return env.get(node.id, Value(symbol=self.resolve(node, env)))
        if isinstance(node, ast.Constant):
            return Value(known=True, constant=node.value, literal_only=True)
        if isinstance(node, ast.Attribute):
            base = self.expression(node.value, env)
            return replace(
                base,
                symbol=self.resolve(node, env),
                known=False,
                constant=None,
                literal_only=False,
                alternatives=self.candidates(node, env),
            )
        if isinstance(node, ast.Subscript):
            base = self.expression(node.value, env)
            self.expression(node.slice, env)
            return self.advance(
                replace(base, symbol=None, known=False, alternatives=()),
                node,
                "index",
                "Indexed value",
            )
        if isinstance(node, ast.NamedExpr):
            value = self.expression(node.value, env)
            self.assign(node.target, value, env, node)
            return value
        if isinstance(node, ast.IfExp):
            self.expression(node.test, env)
            return self.merge(self.expression(node.body, env), self.expression(node.orelse, env))
        if isinstance(node, ast.Call):
            symbol = self.resolve(node.func, env)
            args = [self.expression(item, env) for item in node.args]
            args.extend(self.expression(kw.value, env) for kw in node.keywords)
            detected = False
            for candidate in self.candidates(node.func, env):
                detected |= self.detect_sink(node, candidate, env)
            if detected:
                return EMPTY
            if symbol == "builtins.open":
                return Value(symbol="local.file")
            # Conversions/escaping and all other unknown calls stop the path. They are
            # never declared sanitizers. Keep the unresolved edge and disclose coverage.
            step = self.step(
                node, "unresolved_call", f"Unknown return flow: {symbol or ast.unparse(node.func)}"
            )
            self.diagnostic("unresolved_call", step.description, node)
            unresolved: tuple[EvidenceStep, ...] = ()
            for value in args:
                unresolved = unique(unresolved + value.unresolved)
                for trace in value.traces:
                    unresolved = unique(unresolved + trace.steps)
            unresolved = unique(unresolved + (step,))
            if len(unresolved) > self.config.max_evidence_steps - 1:
                self.diagnostic(
                    "evidence_limit", "Unknown call evidence exceeded its step budget.", node, True
                )
                unresolved = unresolved[: self.config.max_evidence_steps - 2] + (step,)
            return Value(unresolved=unresolved)
        if isinstance(
            node, (ast.Lambda, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            self.diagnostic(
                "unsupported_expression", "Lambda/comprehension flow is unsupported.", node
            )
            # Nested calls are inventoried separately so sinks are not silently lost.
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    nested = dict(env)
                    for name in assigned_names(node):
                        nested[name] = EMPTY
                    if isinstance(node, ast.Lambda):
                        for param in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
                            nested[param.arg] = EMPTY
                    self.detect_sink(child, self.resolve(child.func, nested), nested)
            return EMPTY
        merged: Value | None = None
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                value = self.expression(child, env)
                merged = value if merged is None else self.merge(merged, value)
        merged = merged or EMPTY
        if isinstance(
            node,
            (
                ast.BinOp,
                ast.JoinedStr,
                ast.FormattedValue,
                ast.List,
                ast.Tuple,
                ast.Set,
                ast.Dict,
                ast.BoolOp,
                ast.UnaryOp,
            ),
        ):
            return self.advance(
                replace(merged, symbol=None, known=False, constant=None, alternatives=()),
                node,
                "expression",
                f"{type(node).__name__} combines values",
            )
        return replace(
            merged, symbol=None, known=False, constant=None, alternatives=(), literal_only=False
        )

    def detect_sink(self, call: ast.Call, symbol: str | None, env: Environment) -> bool:
        rule = next(
            (r for r in SINK_RULES if symbol in r.names and r.id in self.config.rules), None
        )
        if rule is None:
            return False
        assumptions = ["Static overapproximation; feasibility requires human review."]
        if self.resolve(call.func, env) != symbol:
            assumptions.append("Sink identity depends on a conditional alias binding.")
        if rule.requires_shell and symbol not in {
            "subprocess.getoutput",
            "subprocess.getstatusoutput",
        }:
            shell_node = shell_argument(call, symbol or "")
            shell = (
                self.expression(shell_node, env)
                if shell_node
                else Value(known=True, constant=False)
            )
            if shell.known and not bool(shell.constant):
                if any(kw.arg is None for kw in call.keywords):
                    assumptions.append("Expanded keyword arguments may enable shell execution.")
                else:
                    self.diagnostic(
                        "unsupported_process_execution",
                        "shell=False/default does not establish safety; executable and explicit interpreter flows are Phase 2.",
                        call,
                    )
                    return True
            elif not shell.known:
                assumptions.append("Shell execution depends on an unresolved shell argument.")
        arg = argument(call, rule)
        if arg is None:
            self.diagnostic(
                "unresolved_sink_argument", "Sink argument is missing or expanded.", call
            )
        value = self.expression(arg, env)
        sink_step = self.step(
            call, "sink", f"{symbol}: argument {ast.unparse(arg) if arg else '<unresolved>'}"
        )
        if (value.known or value.literal_only) and not value.unresolved and not value.traces:
            return True  # literal-only negative control, still covered by the sink model
        paths: tuple[Trace | None, ...] = value.traces or (None,)
        for trace in paths:
            source = trace.source if trace else None
            category: SourceCategory = trace.category if trace else "unknown"
            reachability: Literal["network_source_modeled", "caller_controlled_only", "unknown"] = (
                "network_source_modeled"
                if category == "network_request"
                else "caller_controlled_only"
                if category == "caller_parameter"
                else "unknown"
            )
            if category == "network_request":
                assumptions.extend(["Authentication and deployment exposure are unknown."])
            steps = unique((trace.steps if trace else ()) + (sink_step,))
            identity = fingerprint(rule.id, sink_step.location, source)
            finding = Finding(
                fingerprint=identity,
                rule_id=rule.id,
                sink=symbol or rule.id,
                argument=ast.unparse(arg) if arg else "<unresolved>",
                location=sink_step.location,
                source_category=category,
                source=source,
                evidence_tier="static_path" if trace else "sink_only",
                remote_reachability=reachability,
                impact=rule.impact,
                steps=steps,
                conditions=trace.conditions if trace else (),
                assumptions=unique(tuple(assumptions)),
                unresolved_edges=value.unresolved,
            )
            old = self.findings.get(identity)
            if old:
                finding = finding.model_copy(
                    update={
                        "steps": unique(old.steps[:-1] + steps),
                        "conditions": unique(old.conditions + finding.conditions),
                        "unresolved_edges": unique(old.unresolved_edges + finding.unresolved_edges),
                    }
                )
            if len(finding.steps) > self.config.max_evidence_steps:
                self.diagnostic(
                    "evidence_limit", "Joined evidence exceeded its step budget.", call, True
                )
                finding = finding.model_copy(
                    update={
                        "steps": finding.steps[: self.config.max_evidence_steps - 1] + (sink_step,)
                    }
                )
            self.findings[identity] = finding
        return True

    def assign(self, target: ast.expr, value: Value, env: Environment, node: ast.AST) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = self.advance(value, node, "assignment", f"Assigned to {target.id}")
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.assign(element, value, env, node)
        else:
            self.diagnostic(
                "unsupported_mutation", "Attribute/container mutation is not modeled.", node
            )
            for name in assigned_names(target):
                env[name] = EMPTY

    def transfer(self, stmt: ast.AST | None, env: Environment) -> Environment:
        env = dict(env)
        if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            if isinstance(stmt, ast.AnnAssign) and stmt.value is None:
                return env
            value = self.expression(stmt.value, env)
            if isinstance(stmt, ast.AugAssign):
                value = self.merge(self.expression(stmt.target, env), value)
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            if (
                isinstance(stmt, ast.Assign)
                and len(targets) == 1
                and isinstance(targets[0], (ast.Tuple, ast.List))
                and isinstance(stmt.value, (ast.Tuple, ast.List))
                and len(targets[0].elts) == len(stmt.value.elts)
            ):
                for target, item in zip(targets[0].elts, stmt.value.elts, strict=True):
                    self.assign(target, self.expression(item, env), env, stmt)
            else:
                for target in targets:
                    self.assign(target, value, env, stmt)
        elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
            env.update({name: Value(symbol=symbol) for name, symbol in imports(stmt).items()})
            if isinstance(stmt, ast.ImportFrom) and any(a.name == "*" for a in stmt.names):
                self.diagnostic(
                    "star_import", "Wildcard imports make symbol resolution incomplete.", stmt, True
                )
                env.update({"eval": EMPTY, "exec": EMPTY})
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            env[stmt.name] = EMPTY
            for decorator in stmt.decorator_list:
                self.expression(decorator, env)
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in stmt.args.defaults + [d for d in stmt.args.kw_defaults if d]:
                    self.expression(default, env)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            self.assign(stmt.target, self.expression(stmt.iter, env), env, stmt)
        elif isinstance(stmt, (ast.If, ast.While)):
            self.expression(stmt.test, env)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for with_item in stmt.items:
                value = self.expression(with_item.context_expr, env)
                if with_item.optional_vars:
                    self.assign(with_item.optional_vars, value, env, stmt)
        elif isinstance(stmt, (ast.Try, ast.TryStar)):
            self.diagnostic(
                "exception_overapproximation",
                "Exception timing and finally on abrupt exits are unsupported.",
                stmt,
            )
        elif isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    env[target.id] = EMPTY
        elif isinstance(stmt, (ast.Global, ast.Nonlocal)):
            self.diagnostic(
                "nonlocal_state", "Global/nonlocal writes are not traced across scopes.", stmt
            )
        elif isinstance(stmt, ast.Match):
            self.diagnostic(
                "unsupported_statement", "Match control flow is unsupported.", stmt, True
            )
            for child in ast.walk(stmt):
                if isinstance(child, ast.Call):
                    self.detect_sink(child, self.resolve(child.func, env), env)
            for name in assigned_names(stmt):
                env[name] = EMPTY
        elif stmt is not None:
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    self.expression(child, env)
        return env

    def condition_env(
        self, env: Environment, condition: ast.expr | None, truth: bool
    ) -> Environment:
        if condition is None:
            return env
        label = f"{'if' if truth else 'unless'} {ast.unparse(condition)} (line {condition.lineno})"
        step = self.step(condition, "condition", label)
        return {
            key: replace(
                value,
                traces=tuple(
                    replace(
                        trace,
                        steps=unique(trace.steps + (step,)),
                        conditions=unique(trace.conditions + (label,)),
                    )
                    for trace in value.traces
                ),
            )
            for key, value in env.items()
        }

    def run_scope(self, statements: list[ast.stmt], initial: Environment) -> Environment:
        graph = Builder().build(statements)
        inputs = {graph.entry: initial}
        queue = deque([graph.entry])
        visits: dict[int, int] = {}
        while queue:
            index = queue.popleft()
            self.steps_taken += 1
            if self.steps_taken > self.config.max_flow_steps:
                self.diagnostic("flow_limit", "Flow node budget exhausted.", incomplete=True)
                break
            visits[index] = visits.get(index, 0) + 1
            if visits[index] > self.config.loop_iterations:
                self.diagnostic(
                    "loop_truncated",
                    "Bounded fixed point did not converge.",
                    graph.blocks[index].statement,
                    True,
                )
                continue
            block = graph.blocks[index]
            output = self.transfer(block.statement, inputs[index])
            for edge in block.edges:
                if edge.condition:
                    test_value = self.expression(edge.condition, output)
                    if test_value.known and bool(test_value.constant) != edge.truth:
                        continue
                candidate = self.condition_env(output, edge.condition, edge.truth)
                previous = inputs.get(edge.target)
                joined = candidate if previous is None else self.join(previous, candidate)
                if previous != joined:
                    inputs[edge.target] = joined
                    if edge.target not in queue:
                        queue.append(edge.target)
        return inputs.get(0, initial)

    def analyze(self, tree: ast.Module) -> tuple[list[Finding], list[Diagnostic]]:
        module_env = self.run_scope(tree.body, {})
        # Global names are available only as resolved symbols/constants. Cross-scope
        # provenance is Phase 2; do not attribute a global path to a function caller.
        global_env = {name: replace(value, traces=()) for name, value in module_env.items()}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.scope = node.name
                env = dict(global_env)
                env.update({name: EMPTY for name in scope_bindings(node.body)})
                parameters = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                parameters += [a for a in (node.args.vararg, node.args.kwarg) if a]
                for param in parameters:
                    env[param.arg] = self.source_value(
                        param, "caller_parameter", f"Caller parameter {param.arg}"
                    )
                self.run_scope(node.body, env)
            elif isinstance(node, ast.ClassDef):
                self.diagnostic(
                    "class_scope", "Class body and descriptor resolution are limited.", node
                )
                self.run_scope(node.body, global_env)
        return list(self.findings.values()), self.diagnostics
