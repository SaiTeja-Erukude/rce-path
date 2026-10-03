"""Opt-in evidence review; static results survive every provider failure."""

from __future__ import annotations

import time

from ..config import ScanConfig
from ..findings import Diagnostic, ScanReport
from .contract import EvidenceBundle, Provider, ReviewConfig, ReviewResult


def annotate(
    report: ScanReport,
    config: ScanConfig,
    provider: Provider | None = None,
    *,
    deadline: float | None = None,
) -> ScanReport:
    if provider is None:
        from .providers import OllamaProvider, OpenAIProvider

        provider = OpenAIProvider() if config.ai_provider == "openai" else OllamaProvider()
    try:
        settings = ReviewConfig(
            model=config.ai_model or "",
            endpoint=config.ai_endpoint,
            allow_remote_code=config.allow_remote_code,
            timeout_seconds=config.ai_timeout_seconds,
            max_input_bytes=config.ai_max_input_bytes,
            max_output_tokens=config.ai_max_output_tokens,
            total_token_budget=config.ai_total_token_budget,
        )
    except ValueError:
        failure = ReviewResult(
            ai_status="unsupported",
            provider=config.ai_provider,
            model=config.ai_model or "unknown",
            error="Invalid provider settings; static evidence preserved.",
        )
        return report.model_copy(
            update={
                "ai_status": "unsupported",
                "ai_reviews": {f.fingerprint: failure.model_dump() for f in report.findings},
            }
        )
    reviews: dict[str, dict] = {}
    for index, finding in enumerate(report.findings):
        remaining = (
            deadline - time.monotonic() if deadline is not None else settings.timeout_seconds
        )
        if index >= config.ai_max_reviews or remaining <= 0:
            result = ReviewResult(
                ai_status="budget_exceeded",
                provider=config.ai_provider,
                model=settings.model,
                error="Review count budget exhausted.",
            )
        else:
            evidence = EvidenceBundle.from_finding(
                finding, report.content_hashes.get(finding.location.file, "unknown")
            )
            try:
                result = provider.review(
                    evidence,
                    settings.model_copy(
                        update={"timeout_seconds": min(settings.timeout_seconds, remaining)}
                    ),
                )
            except Exception:
                result = ReviewResult(
                    ai_status="unavailable",
                    provider=config.ai_provider,
                    model=settings.model,
                    error="Provider failed; static evidence preserved.",
                )
        reviews[finding.fingerprint] = result.model_dump()
    statuses = {r["ai_status"] for r in reviews.values()}
    status = (
        "no_findings"
        if not reviews
        else "completed"
        if statuses == {"completed"}
        else next(iter(statuses))
        if len(statuses) == 1
        else "partial_failure"
    )
    updates: dict = {"ai_status": status, "ai_reviews": reviews}
    if deadline is not None and time.monotonic() >= deadline:
        updates.update(
            status="incomplete",
            diagnostics=report.diagnostics
            + (
                Diagnostic(
                    code="scan_timeout",
                    message="Total scan deadline exhausted during AI review.",
                    affects_completion=True,
                ),
            ),
        )
    return report.model_copy(update=updates)


__all__ = ["EvidenceBundle", "Provider", "ReviewConfig", "ReviewResult", "annotate"]
