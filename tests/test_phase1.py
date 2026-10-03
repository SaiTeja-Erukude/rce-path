from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from rce_path import ScanConfig, scan
from rce_path.flow import Analyzer

CASES = json.loads((Path(__file__).parent / "fixtures" / "phase1.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=[c["id"] for c in CASES])
def test_labeled_classification(case):
    tree = ast.parse(case["code"])
    findings, diagnostics = Analyzer(case["code"], f"{case['id']}.py", ScanConfig()).analyze(tree)
    if case["label"] == "none":
        assert findings == []
    else:
        assert {f.source_category for f in findings} == {case["label"]}
        assert all(
            f.evidence_tier == ("sink_only" if case["label"] == "unknown" else "static_path")
            for f in findings
        )
    if "diagnostic" in case:
        assert case["diagnostic"] in {d.code for d in diagnostics}
    for finding in findings:
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        assert any(
            node.lineno == finding.location.line and node.col_offset == finding.location.column
            for node in calls
        )
        assert finding.steps[-1].kind == "sink"
        if finding.source:
            assert finding.steps[0].location == finding.source
        if case["label"] == "network_request":
            assert finding.remote_reachability == "network_source_modeled"
        elif case["label"] == "caller_parameter":
            assert finding.remote_reachability == "caller_controlled_only"
        else:
            assert finding.remote_reachability == "unknown"


def test_release_gate_through_isolated_workers(tmp_path):
    assert len(CASES) >= 40
    for case in CASES:
        (tmp_path / f"{case['id']}.py").write_text(case["code"])
    report = scan(tmp_path)
    assert report.status == "completed", report.diagnostics
    assert report.analyzed_files == len(CASES)
    actual = {Path(f.location.file).stem: f.source_category for f in report.findings}
    expected = {c["id"]: c["label"] for c in CASES if c["label"] != "none"}
    assert actual == expected


def test_assignment_and_branch_provenance():
    code = "def f(x, flag):\n    y = x\n    if flag:\n        z = f'{y}'\n        eval(z)\n"
    findings, _ = Analyzer(code, "flow.py", ScanConfig()).analyze(ast.parse(code))
    steps = findings[0].steps
    assert [s.kind for s in steps] == [
        "source",
        "assignment",
        "condition",
        "expression",
        "expression",
        "assignment",
        "sink",
    ]
    assert findings[0].conditions


def test_no_invented_cross_function_flow():
    code = "def identity(x):\n    return x\ndef f(x):\n    eval(identity(x))\n"
    findings, _ = Analyzer(code, "f.py", ScanConfig()).analyze(ast.parse(code))
    assert len(findings) == 1
    assert findings[0].evidence_tier == "sink_only"
    assert findings[0].unresolved_edges
    kinds = [step.kind for step in findings[0].unresolved_edges]
    assert kinds == ["source", "unresolved_call"]
