# Usage and limitations

Investigate potentially untrusted Python inputs reaching execution sinks, with
reproducible source locations and ordered static evidence. Built for researchers
reviewing local checkouts. **Phase 1, version 0.1.0; Python 3.11+.**

Author: Sai Teja Erukude. License: MIT. Uses the src layout, Hatch builds, typed API,
pytest, and trusted publishing conventions of `rai-audit`.

An execution sink is not automatically a vulnerability. Static flow does not prove
exploitability, deployment exposure, or remote code execution. Reports assign no
automatic severity, CVSS, or exploitability probability.

## Installation

From this checkout:

```bash
python -m pip install .
python -m pip install ".[openai]"  # optional official OpenAI SDK
python -m pip install ".[ollama]"  # optional official Ollama client
```

After publishing, the equivalent PyPI installation is `pip install rce-path`.
The static scanner needs only Pydantic; it does not load either AI SDK.

## Quick start

```bash
rce-path scan ./checkout --format json --output findings.json
rce-path scan ./checkout --format markdown --output report.md
rce-path scan ./checkout --fail-on static-path
```

```python
from rce_path import ScanConfig, scan

report = scan("./checkout", config=ScanConfig(ai_enabled=False))
print(report.summary)
for finding in report.findings:
    print(finding.rule_id, finding.location.file, finding.location.line)
    for step in finding.steps:
        print(step.kind, step.location.line, step.description)
```

`rce-path` is the distribution/command name; `rce_path` is the Python import name.
Scan a directory or an individual `.py` file. Report methods include `to_json()`
and `to_markdown()`; public records are validated, typed Pydantic models.

## Phase 1 models

- `eval`/`exec`, including builtin imports and common aliases.
- `os.system`/`os.popen`, including module/from imports and assignment aliases.
- `subprocess.run`, `call`, `check_call`, `check_output`, `Popen` with shell execution;
  `getoutput` and `getstatusoutput` always imply shell execution. Unknown shell
  values carry an explicit condition. `shell=False` scenarios produce limitations.
- Function parameters, Flask `request.args`, `request.form`, `request.data`, and
  `request.get_data()`. Environment, CLI, stdin, and file reads are local input.
- Assignments, reassignment, concatenation, f-strings, branches, early returns,
  and bounded loop fixed points over per-scope control-flow graphs.

Literal-only sinks are negative controls. Unknown return values produce
`sink_only` findings and unresolved evidence; unknown calls never propagate an
invented path and are never automatically treated as sanitizers. A guard or
escaping function does not prove the argument safe. Branch joins are conservative
overapproximations and can retain mutually exclusive conditions.

Every finding includes a stable fingerprint, rule/schema versions, exact relative
file spans (columns are AST UTF-8 byte offsets, zero based), source category,
evidence tier, ordered evidence, assumptions, unresolved calls, and review state.
`network_source_modeled` means a modeled network input, with authentication and
deployment still unknown. Fingerprints exclude AI annotations and absolute roots.
Content hashes cover read source files; revision is unknown unless supplied by a
future trusted provenance integration. Dependency-version provenance is empty in
Phase 1 because its rules are not dependency-version-sensitive.

## Safety, completion, and coverage

Targets are read as data: no imports, package installation, target build hooks,
deserialization, or checkpoint loading. Excluded environments/build trees and
skipped files appear in diagnostics. Symlinks/reparse points are not followed.
Isolated parser/analysis workers enforce wall time, memory, AST, flow, and evidence
budgets. Windows uses Job Objects; POSIX uses `RLIMIT_AS`. If enforcement fails,
the worker fails and the report is incomplete. Source inventory and the static
scan also have overall time/file/inventory limits. The total scan deadline includes
requested AI reviews; each review also has its own timeout and token budget.

Exit codes: **0** completed and selected policy passed; **1** findings policy
failed; **2** operational/configuration error, incomplete static scan, or requested
AI review failed. `--fail-on none` is the default. Incomplete status wins over a
findings policy. A complete empty report says only **“No modeled findings.”**
Read coverage diagnostics even when the status is completed.

Supported target syntax follows the running Python interpreter (recorded in each
report). A Python 3.11 runtime cannot parse newer syntax. Cross-file/function flow,
closures, dynamic dispatch, complex heap mutation, comprehensions, and precise
exception/finally flow are outside Phase 1 coverage. Known unsupported constructs
produce diagnostics. Parsing is isolated and bounded, but this scanner is not a
general-purpose sandbox for running hostile code. Avoid concurrently modifying
the checkout during a scan.

## Configuration

Use [`examples/rce-path.toml`](../examples/rce-path.toml) as a starter. `scan(path)`
and the CLI discover `rce-path.toml` at the scan root. Passing `ScanConfig` directly
uses exactly that configuration; the CLI also accepts `--config PATH`.
Unknown keys and invalid budgets fail explicitly. Exclusion patterns use forward
slashes. Repository configuration cannot enable AI, supply credentials, or grant
remote transmission permission. AI model/provider settings take effect only after
runtime opt-in. Repository AI endpoints are ignored unless the operator supplies
`--accept-config-ai-endpoint`; an explicit `--endpoint` takes precedence.

## Optional AI annotations

```bash
rce-path scan ./checkout --ai ollama --model YOUR_MODEL --format markdown
rce-path scan ./checkout --ai openai --model YOUR_MODEL --allow-remote-code
```

Set `OPENAI_API_KEY` in the operator environment for OpenAI. Model names are always
operator-selected. OpenAI uses the official Responses API with strict structured
output and `store=False`; this is not a zero-retention promise. Ollama uses native
`/api/chat` with a JSON schema; the default is `http://127.0.0.1:11434`.

OpenAI and non-loopback Ollama endpoints require `--allow-remote-code`. Numeric
loopback addresses are recognized; hostnames, including `localhost`, conservatively
require consent to avoid DNS trust assumptions. No automatic cloud fallback.
Only bounded evidence slices are sent, with best-effort known-secret redaction.
Redaction can miss secrets; review your inputs before allowing transmission.
The scanner does not log raw prompts/source or provider exception bodies.

Both providers share `review(EvidenceBundle, ReviewConfig) -> ReviewResult`, validate
cited evidence IDs, and annotate without altering findings. Malformed output gets
at most one repair. Refusals/authentication failures do not trigger repairs.
Only transient failures retry with backoff and jitter. Requests are serial per
provider, with timeout, input/output size, context, review-count, and total token
budgets. Byte-based input token reservations are deliberately conservative;
actual tokenizer/context accounting varies by model. Temperature is omitted
unless explicitly declared supported through `ReviewConfig`.

`ai_status` distinguishes completed, refused, invalid_output, unsupported,
unavailable, and budget_exceeded. Failed reviews never appear successful.
Cancellation is available through `Cancellation` when constructing a provider;
in-flight transport completes or times out before cancellation takes effect.
No application cache is enabled or persisted; a versioned `cache_key()` helper is
provided for a future operator-controlled cache. Unknown model revisions remain
explicit. See [provider testing](providers.md) for optional live smoke tests.

## Development and publishing

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check src tests
python -m mypy
python -m build
python -m twine check dist/*
```

See [CONTRIBUTING.md](../CONTRIBUTING.md) and [release instructions](releasing.md)
for TestPyPI, PyPI trusted publishing, and the version/tag checks. Nothing in a
normal scan uploads code. No publishing occurs when running the tests/build.

The full [specification](../rce-path_spec.md) guides module boundaries. Phase 2 will
add bounded local call summaries, deserialization/version-aware rules, framework
and process models, independent AI review, evaluation, and SARIF. Phase 3 will add
separate human-approved validation and evidence bundles. Those phases are not
implemented in this release. Phase 1's P1 external rule-file enhancement is deferred.

