# rce-path

Trace potentially untrusted Python inputs to execution sinks, with source
locations and static flow evidence. Scans local code without executing it.

## Install

```bash
python -m pip install .
# Optional AI backends: ".[openai]" or ".[ollama]"
```

After publishing: `pip install rce-path`.

## Quick start

```bash
rce-path scan ./checkout --format json --output findings.json
rce-path scan ./checkout --format markdown --output report.md
```

```python
from rce_path import scan

report = scan("./checkout")
print(report.summary)
```

## Features

- Detects `eval`, `exec`, OS shell calls, and subprocess shell execution.
- Tracks parameters, Flask request data, and local inputs through assignments,
  branches, and bounded loops.
- Exports evidence, assumptions, coverage diagnostics, and stable fingerprints.
- Supports optional OpenAI and Ollama reviews.

Static findings require human review. Remote AI code transmission requires
`--allow-remote-code`. Exit codes: **0** completed, **1** findings policy failed,
**2** incomplete scan or operational error.

[Usage & limitations](docs/usage.md) · [Configuration](examples/rce-path.toml) ·
[AI providers](docs/providers.md) · [Contributing](CONTRIBUTING.md) ·
[Publishing](docs/releasing.md)

Author: Sai Teja Erukude.
