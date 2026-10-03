"""Offline smoke test; run with a Python interpreter that installed the built wheel."""

from __future__ import annotations

import importlib.metadata
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import rce_path


def main() -> None:
    package = Path(rce_path.__file__).resolve().parent
    assert "site-packages" in package.parts, f"Expected an installed wheel, got {package}"
    assert (package / "py.typed").exists()
    assert importlib.metadata.version("rce-path") == rce_path.__version__
    assert "openai" not in sys.modules and "ollama" not in sys.modules
    with tempfile.TemporaryDirectory(prefix="rce-path-install-") as temporary:
        directory = Path(temporary)
        target = directory / "view.py"
        marker = directory / "executed"
        target.write_text(
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('never execute')\n"
            "from flask import request\nimport os\n"
            "def view():\n    command = request.args['command']\n    os.system(command)\n"
        )
        output = directory / "report.json"
        result = subprocess.run(
            [sys.executable, "-m", "rce_path", "scan", str(target), "--output", str(output)],
            capture_output=True,
            timeout=20,
        )
        assert result.returncode == 0, result.stderr.decode()
        report = json.loads(output.read_text())
        assert report["status"] == "completed"
        assert len(report["findings"]) == 1
        finding = report["findings"][0]
        assert finding["source_category"] == "network_request"
        assert finding["evidence_tier"] == "static_path"
        assert finding["steps"][-1]["kind"] == "sink"
        assert not marker.exists()
        print(
            f"Installed rce-path {rce_path.__version__}: CLI, static path, typed marker, and non-execution verified."
        )


if __name__ == "__main__":
    main()
