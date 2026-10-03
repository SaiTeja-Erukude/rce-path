# rce-path — Build Specification

## 1. Product and scope

A local-first Python library and CLI that traces potentially untrusted input to code-execution sinks, records code-location evidence, and optionally uses an LLM to explain and prioritize findings.

Primary initial user: an open-source vulnerability researcher reviewing a local checkout. Secondary user: a maintainer investigating a report. Default: static analysis, no target execution, no remote services.

Audience decision: researcher-first. Optimize for investigating unfamiliar packages, inspecting incomplete paths, and collecting reproducible evidence. Maintainer reports are a secondary workflow; organization-wide blocking CI is a later adoption target. Delivery is milestone-driven, with flexible timing and research depth prioritized.

Value proposition: evidence-backed RCE-path investigation, not another list of dangerous function calls. An execution sink is not automatically a vulnerability; a dataflow is not automatically a feasible exploit; code execution is not automatically remote code execution.

Non-goals: universal Python analysis, automatic CVE/CVSS assignment, autonomous exploitation, a web dashboard, or replacing existing SAST products. PyPI name availability remains unchecked.

## 2. Priority definitions

- **P0:** phase release blocker.
- **P1:** next enhancement; not a blocker.
- **P2:** defer until user demand and evaluation justify it.

## 3. Phase 1 — Useful static MVP (v0.1)

| Priority | Feature | Implementation / acceptance condition |
|---|---|---|
| P0 | Local source ingestion | Scan `.py` files using `ast`; exclude virtual environments/build outputs; never import the target, install it, run its build hooks, or load checkpoints. Return parse errors and skipped files. |
| P0 | Sink resolution | Resolve imports, `from` imports, common aliases, and builtin shadowing. Detect `eval`/`exec`, `os.system`/`os.popen`, and `subprocess` calls with shell execution. Each rule identifies the relevant argument and conditions. |
| P0 | Intraprocedural flow | Build a per-function control-flow graph; track assignments, reassignment, concatenation, f-strings, and basic branch joins. Preserve provenance for every edge. Stop at unknown callees rather than inventing flow. Loops use a bounded fixed point and report truncation. |
| P0 | Source distinctions | Separate caller-controlled function parameters from modeled external sources. Initially support Flask request arguments, form fields, and raw body access. CLI/file/environment input has a separate trust category, not a remote-source label. |
| P0 | Findings and export | JSON and Markdown reports with exact source/sink locations, ordered flow steps, assumptions, unresolved calls, and evidence tier. Stable finding fingerprint excludes volatile AI text. |
| P0 | Safety and limits | No target execution; no symlink escape outside scan root; bounded file size, parser-worker time/memory, and total scan time. Invalid config and partial scans must not produce a clean bill of health. |
| P0 | Tests and packaging | `pyproject.toml`, typed public API, pytest fixtures, license, README, and CI. Static scanning has no model dependency. |
| P0 | Interchangeable AI backends | Provide OpenAI and Ollama adapters behind one provider contract; both are optional installation extras and opt-in at runtime. Feed bounded evidence slices, validate a shared response schema and cited locations, and preserve static results on AI failure. |
| P1 | Small external rule file | Data-only source/sink definitions; validate schema. No arbitrary repository-provided Python plugins. |

Important rule semantics: `shell=False` is not blanket safety when an attacker controls the executable or invokes a shell/interpreter explicitly. Phase 1 must report unsupported process-execution scenarios as limitations; expand those cases in phase 2. A conversion/escaping call is not automatically a sanitizer. A modeled allowlist must constrain the actual argument reaching the sink.

**Release gate:** at least 40 labeled synthetic fixtures covering positive paths, negative controls, aliases, reassignment, shadowing, branches, and unknown calls. Every supported-pattern fixture must match its expected classification. All findings require resolvable sink locations. Test that scanning a file with top-level side effects never executes it. A clean report states only “no modeled findings,” and includes coverage diagnostics.

Provider release gate: identical contract fixtures for both adapters covering valid output, malformed output, refusal, truncation, unavailable model, timeout, rate limit, invalid credentials, and unsupported schema/options. Stubbed tests run without keys or downloads; document optional live smoke tests separately. A failed AI review reports `ai_status` and never appears as a successful review.

## 4. Phase 2 — Research-grade tracing and AI triage (v0.2)

| Priority | Feature | Implementation / acceptance condition |
|---|---|---|
| P0 | Bounded cross-function tracing | Follow statically resolved local functions and imports using argument/return summaries; configurable depth and node budget. Unknown dynamic dispatch stays unresolved. |
| P0 | Deserialization rules | Add `pickle.load(s)` and unsafe YAML loader variants. Inspect loader arguments and dependency-version evidence, not just the function name. |
| P0 | AI/ML loading rules | Inspect `torch.load` configuration, including `weights_only`, custom pickle handling, and declared versions. Unknown version/default becomes an uncertainty, not an assumed unsafe default. Analyze source; never deserialize the artifact. |
| P0 | Entry-point and process models | Add FastAPI request parameters/body, selected Django request APIs, and attacker-controlled executable/interpreter arguments. Separate network-origin evidence from authentication/deployment assumptions. |
| P0 | Holdout evaluation | Evaluate labeled vulnerable/patched pairs and safe controls against Bandit and static-only rce-path. Measure precision, recall within declared scope, false positives, path correctness, latency, and reviewer time. |
| P0 | Two-model review | Configurable researcher and reviewer roles; each can use OpenAI or Ollama, including your local models. Reviewer evaluates the original code evidence before seeing the first verdict; preserve disagreements. Agreement is not independent proof or a calibrated probability. |
| P1 | SARIF and CI | SARIF 2.1.0 export with code-flow evidence; differential scan and explicit user-selected CI failure policy. Preserve incomplete-scan status. |
| P2 | Scanner import | Enrich Bandit/Semgrep findings with native paths; retain original tool provenance. |

Use your four disclosed CVEs as case-study seeds where root causes fall within modeled scope. Do not assume all four are detectable, and do not count tuning cases as independent holdout successes. Split by project and deduplicate similar cases. Record model training/cutoff uncertainty to avoid claiming uncontaminated evaluation.

Research gate: freeze the dataset/splits, prompt version, rule version, and primary metrics before comparing static-only, one-model, and two-model configurations. Include OpenAI-only, Ollama-only, and mixed-provider runs when practical. Report per-sink results, abstentions, incomplete paths, repeated-run variability, cost/usage, and false-positive examples. Preserve a separate discovery log for genuinely new findings; do not claim superiority from the four case studies alone.

## 5. Phase 3 — Validation and maintainer workflows (v1.0 candidate)

| Priority | Feature | Implementation / acceptance condition |
|---|---|---|
| P0 | Opt-in validation runner | Human-approved benign canary tests in disposable hardened containers/VMs. No live targets, credentials, outbound network, privileged mode, host socket, or writable host mounts. Enforce resource limits. Containers are not a complete security boundary. |
| P0 | Vulnerable/patched comparison | Run the same approved test against pinned revisions; record exact test, hashes, environment, and result. A blocked test does not prove the entire patch is secure. |
| P0 | Evidence bundle | Export code traces, validation logs, environment metadata, assumptions, and a redacted maintainer report. No automatic external submissions. |
| P1 | Regression-test export | Generate reviewable pytest tests using harmless markers. Never execute model-generated code automatically. |
| P1 | Additional execution chains | Model config-to-import, custom callback registration, and extraction-to-import chains only when prerequisite dataflow models exist. Dynamic imports/templates are not universally execution vulnerabilities. |
| P2 | Extensibility | Versioned rule API and framework-specific rule packs, with explicit opt-in for any executable plugins. |

## 6. Architecture and interfaces

Processing: source inventory → AST/symbol resolution → source/sink matching → bounded dataflow → evidence records → optional AI annotations → export.

Recommended modules: `ingest`, `symbols`, `cfg`, `flow`, `rules`, `findings`, `llm/providers`, `reports`, `cli`. Keep `validation` separate until phase 3. Suggested stack: Python 3.11+, standard-library `ast`/`tomllib`, Pydantic schemas, argparse or Typer, pytest; optional official OpenAI and Ollama clients. Record supported target syntax separately from runtime versions.

Proposed commands and API (not available yet):

```bash
rce-path scan ./checkout --format json --output findings.json
rce-path scan ./checkout --ai ollama --model MODEL --format markdown --output report.md
rce-path scan ./checkout --ai openai --model MODEL --allow-remote-code --format markdown --output report.md
# Phase 2
rce-path scan ./checkout --format sarif --output findings.sarif
```

```python
from rce-path import ScanConfig, scan
report = scan("./checkout", config=ScanConfig(ai_enabled=False))
```

Use `rce-path.toml` for rule selection, exclusions, flow budgets, and optional model settings. Ignore repository-provided AI endpoints unless explicitly accepted by the operator. Proposed exit codes: 0 = completed / selected policy passed; 1 = selected findings policy failed; 2 = incomplete scan or operational error. Partial status takes precedence.

### Provider contract (proposed)

One interface: `review(EvidenceBundle, ReviewConfig) -> ReviewResult`. Core flow analysis has no provider-specific branches. The result includes verdict, rationale, cited evidence IDs, missing context, provider/model identity, usage when available, latency, and `ai_status` (`completed`, `refused`, `invalid_output`, `unsupported`, `unavailable`, or `budget_exceeded`).

| Adapter | Transport and behavior |
|---|---|
| `OpenAIProvider` | Official SDK / Responses API with a configured model supporting structured output. Use a supported strict JSON schema; explicitly handle refusals and incomplete responses. Credentials come from operator environment variables, not project files. Disable application response storage where supported; make no zero-retention promise. |
| `OllamaProvider` | Native `/api/chat` with JSON schema in `format`; operator-selected model and endpoint, loopback by default. Validate returned JSON locally. Do not assume every model has equal schema-following or review quality. |
| Additional compatible endpoints | P2 extension. Compatibility must be tested; a shared URL/SDK format does not guarantee schema, token, or error semantics. |

Shared requirements: bounded concurrency, request timeouts, retry with backoff/jitter for transient failures only, cancellation, context budgets, and response-size limits. Unsupported model parameters fail clearly rather than being silently dropped. Schema-invalid output gets at most one repair attempt; refusals and authentication failures are not repair loops.

Model names are configurable; do not hardcode a universal best model. Capability checks and adapter tests cover structured output, context limits, and supported generation controls. Low temperature is requested only when supported and does not promise determinism. Cache keys include code/evidence hashes, prompt/schema/rule version, model identity and settings, and provider endpoint. Local caches are opt-in and do not store keys. Record unknown model revisions explicitly.

No automatic local-to-cloud fallback. External endpoints, including non-loopback Ollama endpoints, require explicit operator permission to transmit code. Send only the relevant snippets, redact known secrets, and keep raw source/prompts out of logs by default. Usage/token caps are P0; configurable price tables and estimated currency budgets are P1 because prices and local token accounting vary. Source transmission/redaction limitations must be visible.

## 7. Finding contract

Each finding contains: schema/rule version, fingerprint, relative file and line spans, sink/argument, source category, ordered evidence steps, control-flow conditions, unresolved edges, dependencies/version provenance, and review notes. Report metadata contains revision/content hashes, analyzed/skipped counts, tool version, limits, and scan completion status.

Keep these fields separate:

| Field | Allowed meaning |
|---|---|
| Evidence | `sink_only`, `static_path`, or `canary_validated` |
| Remote reachability | `network_source_modeled`, `caller_controlled_only`, or `unknown` |
| Feasibility | Known preconditions plus unresolved conditions; static overapproximations are explicit |
| Impact | Potential code execution / command injection, separately from exploit prerequisites |
| AI verdict | `plausible`, `needs_context`, or `unlikely`; explanation with evidence references |
| Human review | `unreviewed`, `confirmed`, `dismissed`, or `needs_information`, with rationale |

Never output an LLM confidence percentage as an exploitability probability. No automatic critical/high severity or CVSS assignment.

## 8. AI and scanner security

Treat repository comments, strings, README content, and external scanner output as untrusted data, including prompt injection. AI receives no tools, secrets, or shell access; it cannot modify the verified graph, suppress findings, or trigger execution. Reject invented locations; render output as inert text. Make source transmission opt-in, keep endpoints local by default, and use bounded schema-validated responses, timeouts, retries, and content/version keyed caches. JSON-schema compliance ensures structure, not truth. Keep credentials out of reports, cache files, and exceptions.

## 9. Build order and decisions

Start with findings schema and fixtures → sink resolver → CFG/dataflow → reports/CLI → scan safety → provider contract and both AI adapters. Complete phase 1 before cross-file analysis. Validate phase 2 with holdouts before investing in phase 3 isolation infrastructure. Design benchmark labels and data provenance from the start, even before the full evaluation runner exists.

Resolved decisions: researcher-first; interchangeable OpenAI and Ollama backends; static-only use always supported; flexible schedule with research depth prioritized. Release when evidence, coverage, and provider-contract gates pass, rather than on a fixed calendar date.

## Official implementation references

- [Python AST](https://docs.python.org/3/library/ast.html): parsing and syntax structures; hostile/complex inputs still need resource limits.
- [Python subprocess](https://docs.python.org/3/library/subprocess.html#security-considerations): shell and argument handling semantics.
- [PyYAML](https://pyyaml.org/wiki/PyYAMLDocumentation): loader behavior and safe loading.
- [PyTorch serialization](https://docs.pytorch.org/docs/stable/notes/serialization): version-dependent `weights_only` defaults and limitations.
- [Ollama structured outputs](https://docs.ollama.com/capabilities/structured-outputs): JSON-schema responses and validation.
- [OpenAI structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs): supported JSON schemas, SDK parsing, refusals, and incomplete responses.
- [Bandit](https://bandit.readthedocs.io/en/latest/): Python static-analysis baseline.
- [SARIF standard](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=sarif): interoperable static-analysis reports.
