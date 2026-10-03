"""Official OpenAI SDK / Responses API adapter, imported only when selected."""

from __future__ import annotations

import json
import os
import time

from ..contract import SYSTEM_PROMPT, ProviderFailure, RawResponse, ReviewConfig, response_schema
from .base import BaseProvider


class OpenAIProvider(BaseProvider):
    name = "openai"

    def authorize(self, config: ReviewConfig) -> None:
        if not config.allow_remote_code:
            raise ProviderFailure("unsupported")
        if config.endpoint is not None:
            # Other compatible endpoints are a Phase 2+ capability, not silently interchangeable.
            raise ProviderFailure("unsupported")

    def request(self, prompt: str, config: ReviewConfig, timeout: float) -> RawResponse:
        deadline = time.monotonic() + timeout
        if self.client is None:
            from openai import OpenAI

            key = os.environ.get("OPENAI_API_KEY")
            if not key:
                raise ProviderFailure("unavailable")
            self.client = OpenAI(api_key=key, base_url="https://api.openai.com/v1", max_retries=0)
        options = {
            "model": config.model,
            "input": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "rce_path_review",
                    "strict": True,
                    "schema": response_schema(),
                }
            },
            "store": False,
            "max_output_tokens": config.max_output_tokens,
            "timeout": timeout,
        }
        if config.temperature is not None:
            options["temperature"] = config.temperature
        # Bound the HTTP body before decoding/parsing. No tools are supplied.
        with self.client.responses.with_streaming_response.create(**options) as response:
            chunks = bytearray()
            for chunk in response.iter_bytes():
                if time.monotonic() >= deadline or self.cancellation.event.is_set():
                    raise ProviderFailure("budget_exceeded")
                chunks.extend(chunk)
                if len(chunks) > config.max_response_bytes:
                    raise ProviderFailure("budget_exceeded")
        data = json.loads(chunks)
        if data.get("status") == "incomplete":
            return RawResponse(status="budget_exceeded")
        if data.get("status") != "completed":
            return RawResponse(status="unavailable")
        texts = []
        for item in data.get("output", []):
            for content in item.get("content", []):
                if content.get("type") == "refusal":
                    return RawResponse(status="refused")
                if content.get("type") == "output_text":
                    texts.append(content.get("text", ""))
        usage = data.get("usage") or {}
        return RawResponse(
            text="".join(texts),
            usage={
                k: usage[k]
                for k in ("input_tokens", "output_tokens")
                if isinstance(usage.get(k), int)
            },
            model_revision=data.get("model") or "unknown",
        )
