"""Native Ollama /api/chat adapter via the optional official client."""

from __future__ import annotations

import json
import time

from ..contract import (
    SYSTEM_PROMPT,
    ProviderFailure,
    RawResponse,
    ReviewConfig,
    is_loopback,
    response_schema,
)
from .base import BaseProvider


def field(item, name, default=None):
    return item.get(name, default) if isinstance(item, dict) else getattr(item, name, default)


class OllamaProvider(BaseProvider):
    name = "ollama"

    def authorize(self, config: ReviewConfig) -> None:
        endpoint = config.endpoint or "http://127.0.0.1:11434"
        if not is_loopback(endpoint) and not config.allow_remote_code:
            raise ProviderFailure("unsupported")

    def request(self, prompt: str, config: ReviewConfig, timeout: float) -> RawResponse:
        client = self.client
        deadline = time.monotonic() + timeout
        if client is None:
            from ollama import Client  # type: ignore[import-not-found]

            client = Client(
                host=config.endpoint or "http://127.0.0.1:11434",
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            )
        options: dict[str, int | float] = {
            "num_predict": config.max_output_tokens,
            "num_ctx": config.context_tokens,
        }
        if config.temperature is not None:
            options["temperature"] = config.temperature
        stream = client.chat(
            model=config.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": prompt + "\nResponse schema: " + json.dumps(response_schema()),
                },
            ],
            format=response_schema(),
            options=options,
            stream=True,
        )
        chunks: list[str] = []
        size = 0
        last = None
        try:
            for part in stream:
                if time.monotonic() >= deadline or self.cancellation.event.is_set():
                    raise ProviderFailure("budget_exceeded")
                last = part
                message = field(part, "message", {})
                if field(message, "refusal"):
                    return RawResponse(status="refused")
                text = field(message, "content", "")
                size += len(text.encode()) + len((field(message, "thinking", "") or "").encode())
                if size > config.max_response_bytes:
                    raise ProviderFailure("budget_exceeded")
                chunks.append(text)
        finally:
            if hasattr(stream, "close"):
                stream.close()
        if last is None or not field(last, "done", False):
            return RawResponse(status="budget_exceeded")
        if field(last, "done_reason") == "length":
            return RawResponse(status="budget_exceeded")
        usage = {
            key: field(last, name)
            for key, name in (
                ("input_tokens", "prompt_eval_count"),
                ("output_tokens", "eval_count"),
            )
            if isinstance(field(last, name), int)
        }
        return RawResponse(text="".join(chunks), usage=usage)
