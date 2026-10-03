"""Serial provider orchestration: bounded requests, transient retries, one schema repair."""

from __future__ import annotations

import random
import threading
import time

from pydantic import ValidationError

from ..contract import (
    SYSTEM_PROMPT,
    Annotation,
    Cancellation,
    EvidenceBundle,
    ProviderFailure,
    RawResponse,
    ReviewConfig,
    ReviewResult,
    evidence_prompt,
)


class BaseProvider:
    name = "base"

    def __init__(self, client=None, cancellation: Cancellation | None = None) -> None:
        self.client = client
        self.cancellation = cancellation or Cancellation()
        self._lock = threading.Lock()
        self._charged_tokens = 0

    def request(self, prompt: str, config: ReviewConfig, timeout: float) -> RawResponse:
        raise NotImplementedError

    def authorize(self, config: ReviewConfig) -> None:
        raise NotImplementedError

    def review(self, evidence: EvidenceBundle, config: ReviewConfig) -> ReviewResult:
        started = time.monotonic()
        deadline = started + config.timeout_seconds
        usage: dict[str, int] = {}

        def result(status, **kwargs) -> ReviewResult:
            return ReviewResult(
                ai_status=status,
                provider=self.name,
                model=config.model,
                usage=usage,
                latency_seconds=time.monotonic() - started,
                **kwargs,
            )

        # One in-flight request per provider. Cancellation is checked between attempts;
        # an active SDK request is bounded by the remaining review timeout.
        if not self._lock.acquire(timeout=config.timeout_seconds):
            return result("budget_exceeded", error="Provider concurrency wait exhausted timeout.")
        try:
            self.authorize(config)
            prompt = evidence_prompt(evidence, config)
            for repair in range(2):
                repair_note = (
                    "\nPrevious output was invalid. Follow the schema and cite supplied IDs."
                    if repair
                    else ""
                )
                request_prompt = prompt + repair_note
                reserve = (
                    len((request_prompt + SYSTEM_PROMPT).encode()) + config.max_output_tokens + 512
                )
                if reserve > config.context_tokens:
                    return result(
                        "budget_exceeded", error="Evidence exceeds configured model context budget."
                    )
                raw = None
                for attempt in range(config.max_retries + 1):
                    if self.cancellation.event.is_set() or time.monotonic() >= deadline:
                        return result(
                            "budget_exceeded", error="Review cancelled or deadline exhausted."
                        )
                    if self._charged_tokens + reserve > config.total_token_budget:
                        return result("budget_exceeded", error="Total token budget exhausted.")
                    # Conservative byte-based token reservation, including failed attempts.
                    self._charged_tokens += reserve
                    try:
                        raw = self.request(request_prompt, config, deadline - time.monotonic())
                        break
                    except Exception as error:
                        failure = normalize_error(error)
                        if not failure.transient or attempt >= config.max_retries:
                            return result(
                                failure.status,
                                error="Provider request failed; static evidence preserved.",
                            )
                        delay = min(
                            0.25 * (2**attempt) + random.uniform(0, 0.1),
                            max(0, deadline - time.monotonic()),
                        )
                        self.cancellation.event.wait(delay)
                assert raw is not None
                if time.monotonic() >= deadline or self.cancellation.event.is_set():
                    return result(
                        "budget_exceeded", error="Review cancelled or deadline exhausted."
                    )
                for key, value in raw.usage.items():
                    usage[key] = usage.get(key, 0) + value
                actual_tokens = sum(
                    raw.usage.get(key, 0) for key in ("input_tokens", "output_tokens")
                )
                if actual_tokens > reserve:
                    self._charged_tokens += actual_tokens - reserve
                if self._charged_tokens > config.total_token_budget:
                    return result(
                        "budget_exceeded", error="Reported provider usage exceeded reserved budget."
                    )
                if raw.status != "completed":
                    return result(raw.status, error="Provider did not complete a review.")
                if len(raw.text.encode()) > config.max_response_bytes:
                    return result("budget_exceeded", error="Provider response size limit exceeded.")
                try:
                    annotation = Annotation.model_validate_json(raw.text, strict=True)
                    known_ids = {step.id for step in evidence.evidence}
                    if (
                        not annotation.cited_evidence_ids
                        or set(annotation.cited_evidence_ids) - known_ids
                    ):
                        raise ValueError("Missing or invented evidence citation")
                    if not annotation.rationale.strip():
                        raise ValueError("Empty rationale")
                    return result(
                        "completed", **annotation.model_dump(), model_revision=raw.model_revision
                    )
                except (ValidationError, ValueError):
                    if repair:
                        return result(
                            "invalid_output",
                            error="Response schema or evidence citations are invalid.",
                        )
            return result("invalid_output")
        except (ProviderFailure, ValueError) as error:
            return result(
                error.status if isinstance(error, ProviderFailure) else "unsupported",
                error="Provider configuration/permission or evidence budget rejected the request.",
            )
        finally:
            self._lock.release()


def normalize_error(error: Exception) -> ProviderFailure:
    if isinstance(error, ProviderFailure):
        return error
    status = getattr(error, "status_code", None)
    if status in {400, 405, 415, 422}:
        return ProviderFailure("unsupported")
    if status == 429 or status in {500, 502, 503, 504}:
        return ProviderFailure("unavailable", transient=True)
    if (
        isinstance(error, (TimeoutError, ConnectionError))
        or "Timeout" in type(error).__name__
        or "Connection" in type(error).__name__
    ):
        return ProviderFailure("unavailable", transient=True)
    return ProviderFailure("unavailable")
