# Provider validation

`tests/test_providers.py` applies the same contract fixtures to OpenAI and Ollama:
valid JSON, malformed JSON, refusal, truncation, unavailable model, timeout, rate
limit, invalid credentials, unsupported schema/options, and invented citations.
Tests also cover repair/retry bounds, byte/token budgets, cancellation, consent,
redaction, cache-key invalidation, and preservation of the static evidence.
Tests use stubs and require no keys or downloads.

For an optional live smoke test, create a temporary file containing:

```python
def investigate(code):
    eval(code)
```

Install the appropriate extra. Start your existing Ollama server and choose a
model you have already installed; no automatic pulls occur. Then:

```bash
rce-path scan smoke.py --ai ollama --model YOUR_MODEL --output ollama-review.json
rce-path scan smoke.py --ai openai --model YOUR_MODEL --allow-remote-code --output openai-review.json
```

For OpenAI, supply `OPENAI_API_KEY` through the environment. Verify `ai_status`,
cited evidence IDs, usage, static fingerprint, and provider/model identity. An
unsupported schema/model is a failed review, not a reason to silently drop options.
Do not run live tests in standard CI. Local model refusals can appear as
schema-invalid output if the model does not emit a structured refusal marker;
either result is explicitly unsuccessful.

Implementation references: [OpenAI structured output](https://developers.openai.com/api/docs/guides/structured-outputs),
[Ollama structured output](https://docs.ollama.com/capabilities/structured-outputs),
and [Ollama chat API](https://docs.ollama.com/api/chat).
