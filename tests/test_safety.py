from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from rce_path import ScanConfig, ScanReport, scan
from rce_path.cli import main


def test_top_level_side_effects_never_execute(tmp_path):
    marker = tmp_path / "executed"
    (tmp_path / "target.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\nraise RuntimeError('should never execute')\ndef f(x):\n    eval(x)\n"
    )
    report = scan(tmp_path)
    assert not marker.exists()
    assert len(report.findings) == 1


def test_parse_failure_overrides_findings_policy(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:")
    (tmp_path / "good.py").write_text("def f(x):\n    eval(x)\n")
    report = scan(tmp_path)
    assert report.status == "incomplete"
    assert len(report.findings) == 1
    assert any(d.code == "parse_error" for d in report.diagnostics)
    assert "Incomplete" in report.summary
    assert (
        main(["scan", str(tmp_path), "--fail-on", "any", "--output", str(tmp_path / "report.json")])
        == 2
    )


def test_file_size_and_exclusions(tmp_path):
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "ignored.py").write_text("exec(input())")
    (tmp_path / "large.py").write_text("#" * 201)
    report = scan(tmp_path, ScanConfig(max_file_bytes=200))
    assert report.findings == ()
    assert report.status == "incomplete"
    assert report.skipped_files == 2


def test_arbitrarily_named_virtual_environment_is_excluded(tmp_path):
    environment = tmp_path / "custom-environment"
    environment.mkdir()
    (environment / "pyvenv.cfg").write_text("home = python")
    (environment / "target.py").write_text("exec(input())")
    (tmp_path / "safe.py").write_text("pass")
    report = scan(tmp_path)
    assert report.status == "completed"
    assert not report.findings
    assert report.analyzed_files == 1
    assert any("pyvenv.cfg" in d.message for d in report.diagnostics)


def test_symlink_cannot_escape(tmp_path):
    outside = tmp_path.parent / "outside-rce-test.py"
    outside.write_text("exec(input())")
    try:
        (tmp_path / "escape.py").symlink_to(outside)
    except OSError:
        pytest.skip("OS does not grant symlink creation")
    report = scan(tmp_path)
    assert not report.findings
    assert report.status == "incomplete"
    assert any(d.code == "symlink_skipped" for d in report.diagnostics)


def test_symlink_directory_is_not_followed(tmp_path):
    directory = tmp_path.parent / "outside-rce-dir"
    directory.mkdir(exist_ok=True)
    (directory / "target.py").write_text("exec(input())")
    try:
        (tmp_path / "escape").symlink_to(directory, target_is_directory=True)
    except OSError:
        pytest.skip("OS does not grant symlink creation")
    report = scan(tmp_path)
    assert not report.findings
    assert report.status == "incomplete"


@pytest.mark.skipif(os.name == "nt", reason="POSIX FIFO source safety")
def test_fifo_python_filename_never_blocks(tmp_path):
    os.mkfifo(tmp_path / "pipe.py")
    report = scan(tmp_path)
    assert report.status == "incomplete"
    assert any(d.code == "source_skipped" for d in report.diagnostics)


def test_config_sections_must_be_tables(tmp_path):
    (tmp_path / "rce-path.toml").write_text("scan = 'invalid table'")
    assert scan(tmp_path).status == "error"


@pytest.mark.parametrize(
    "text",
    [
        "[scan]\nmax_file_bytes = -1",
        "[scan]\nunknown = 2",
        "[scan]\nrules = ['typo']",
        "[ai]\nallow_remote_code = true",
        "[scan]\nai_enabled = true",
        "bad [",
    ],
)
def test_invalid_config_returns_error(tmp_path, text):
    (tmp_path / "rce-path.toml").write_text(text)
    report = scan(tmp_path)
    assert report.status == "error"
    assert "No modeled findings" not in report.summary


def test_repository_cannot_enable_ai_or_endpoint(tmp_path):
    from rce_path.config import load_config

    path = tmp_path / "rce-path.toml"
    path.write_text(
        "[ai]\nprovider = 'ollama'\nmodel = 'operator-selects'\nendpoint = 'https://example.invalid'\n"
    )
    config = load_config(path)
    assert config.ai_enabled is False
    assert config.ai_endpoint is None
    assert load_config(path, accept_ai_endpoint=True).ai_endpoint == "https://example.invalid"


@pytest.mark.parametrize(
    "settings,code,diagnostic",
    [
        ({"max_ast_nodes": 1}, "x = 1", "parse_error"),
        ({"max_flow_steps": 1}, "x = 1\ny = 2", "flow_limit"),
        (
            {"loop_iterations": 1},
            "def f(x, flag):\n    while flag:\n        x = f'{x}'\n    eval(x)",
            "loop_truncated",
        ),
        ({"parser_timeout_seconds": 0.001}, "x = 1", "parser_timeout"),
        ({"scan_timeout_seconds": 0.001}, "x = 1", None),
    ],
)
def test_resource_limits_fail_visibly(tmp_path, settings, code, diagnostic):
    (tmp_path / "f.py").write_text(code)
    report = scan(tmp_path, ScanConfig(**settings))
    assert report.status == "incomplete"
    if diagnostic:
        assert diagnostic in {d.code for d in report.diagnostics}


def test_file_count_limit(tmp_path):
    (tmp_path / "a.py").write_text("pass")
    (tmp_path / "b.py").write_text("pass")
    report = scan(tmp_path, ScanConfig(max_files=1))
    assert report.status == "incomplete"
    assert report.analyzed_files == 1


def test_inventory_and_straight_line_evidence_budgets(tmp_path):
    for name in ("a.txt", "b.txt", "c.txt"):
        (tmp_path / name).write_text("data")
    report = scan(tmp_path, ScanConfig(max_inventory_entries=1))
    assert report.status == "incomplete"
    assert any(d.code == "inventory_limit" for d in report.diagnostics)
    (tmp_path / "flow.py").write_text("def f(x):\n    y = x\n    z = y\n    eval(z)\n")
    report = scan(tmp_path, ScanConfig(max_evidence_steps=2))
    assert report.status == "incomplete"
    assert report.findings[0].steps[-1].kind == "sink"
    assert len(report.findings[0].steps) == 2


def test_encoding_cookie(tmp_path):
    (tmp_path / "encoded.py").write_bytes(b"# coding: latin-1\n# caf\xe9\ndef f(x):\n    eval(x)\n")
    assert scan(tmp_path).status == "completed"


def test_clean_wording_and_json_round_trip(tmp_path):
    (tmp_path / "safe.py").write_text("eval('1+1')")
    report = scan(tmp_path)
    assert report.summary == "No modeled findings."
    assert "Coverage diagnostics" in report.to_markdown()
    assert ScanReport.model_validate_json(report.to_json()) == report


def test_fingerprints_independent_of_root(tmp_path):
    reports = []
    for name in ("one", "two"):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "f.py").write_text("def f(x):\n    eval(x)\n")
        reports.append(scan(directory))
    assert reports[0].findings[0].fingerprint == reports[1].findings[0].fingerprint
    assert reports[0].content_hashes == reports[1].content_hashes


def test_cli_policies_and_output(tmp_path):
    (tmp_path / "f.py").write_text("def f(x):\n    eval(x)\n")
    output = tmp_path / "out.json"
    assert main(["scan", str(tmp_path), "--output", str(output)]) == 0
    assert main(["scan", str(tmp_path), "--output", str(output), "--fail-on", "static-path"]) == 1
    assert json.loads(output.read_text())["findings"]
    assert main(["scan", str(tmp_path), "--ai", "openai", "--model", "test"]) == 2


def test_nonexistent_and_empty_target(tmp_path):
    assert scan(tmp_path / "missing").status == "error"
    assert scan(tmp_path).status == "incomplete"


def test_worker_memory_limit_is_enforced(tmp_path):
    import subprocess
    import sys

    # Run trusted allocation code in a disposable child, never in the test runner.
    script = tmp_path / "memory_probe.py"
    script.write_text(
        f"import sys\nsys.path.insert(0, {str(Path(__file__).resolve().parents[1] / 'src')!r})\nfrom rce_path._worker import memory_limit\nmemory_limit(128)\ntry:\n    value = bytearray(256 * 1024 * 1024)\nexcept MemoryError:\n    raise SystemExit(0)\nraise SystemExit(1)\n"
    )
    result = subprocess.run([sys.executable, str(script)], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr.decode()


def test_markdown_renders_repository_text_as_inert(tmp_path):
    (tmp_path / "f.py").write_text("def f(x):\n    eval(x + '<script>alert(1)</script>')\n")
    text = scan(tmp_path).to_markdown()
    assert "<script>" not in text
