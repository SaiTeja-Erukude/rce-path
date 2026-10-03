# Contributing

Install `python -m pip install -e ".[dev]"`. Keep the static scanner independent
of optional AI SDKs. Run pytest, Ruff, mypy, build, and Twine before release.

`src/rce_path` follows the spec's pipeline: ingestion, symbols, CFG, flow, rules,
findings, optional `llm/providers`, reports, and CLI. Models are versioned at the
evidence boundary. Add future cross-function summaries at the flow boundary,
provider roles at the review contract, and SARIF at the report boundary. Validation
must be a separate Phase 3 component; do not execute targets to improve static
coverage. No repository-provided executable plugins are accepted.

Labeled synthetic fixtures live in `tests/fixtures/phase1.json`. Each records a
unique ID, source, expected category/negative control, and relevant diagnostics.
They are development/release fixtures, not independent holdout benchmarks. Keep
future project datasets split by project and record provenance, revisions, and
vulnerable/patched labels before tuning. No detection superiority claim follows
from this fixture suite.

Provider tests use identical scenarios for both adapters, fake transports, no
credentials, no model downloads, and no network. Optional live tests are manual
and use the operator's selected model. Never store keys or raw SDK exceptions in
reports or fixtures. See `docs/providers.md` and `docs/releasing.md`.
