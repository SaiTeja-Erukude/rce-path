from __future__ import annotations

import tomllib
from pathlib import Path

from rce_path import __version__
from rce_path.cli import main
from rce_path.findings import ScanReport


def test_release_versions_agree(capsys):
    import pytest

    project = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())
    report = ScanReport(root=".", status="completed", target_syntax="Python 3.11")
    assert project["project"]["version"] == __version__ == report.tool_version
    with pytest.raises(SystemExit) as result:
        main(["--version"])
    assert result.value.code == 0
    assert capsys.readouterr().out.strip() == f"rce-path {__version__}"


def test_static_api_does_not_import_ai_sdks():
    import subprocess
    import sys

    source = Path(__file__).resolve().parents[1] / "src"
    script = f"import sys; sys.path.insert(0, {str(source)!r}); import rce_path; assert 'openai' not in sys.modules; assert 'ollama' not in sys.modules"
    result = subprocess.run([sys.executable, "-I", "-c", script], capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr.decode()
