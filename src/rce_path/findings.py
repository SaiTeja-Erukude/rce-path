"""Versioned evidence contracts, independent of analysis and provider implementations."""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0"
RULE_VERSION = "0.1.0"
SourceCategory = Literal["caller_parameter", "network_request", "local_input", "unknown"]


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Location(Record):
    file: str
    line: int = Field(ge=1)
    column: int = Field(ge=0)
    end_line: int = Field(ge=1)
    end_column: int = Field(ge=0)


class EvidenceStep(Record):
    id: str
    kind: str
    location: Location
    description: str
    snippet: str = ""


class Diagnostic(Record):
    code: str
    message: str
    file: str | None = None
    line: int | None = None
    affects_completion: bool = False


class Finding(Record):
    schema_version: str = SCHEMA_VERSION
    rule_version: str = RULE_VERSION
    fingerprint: str
    rule_id: str
    sink: str
    argument: str
    location: Location
    source_category: SourceCategory
    source: Location | None = None
    evidence_tier: Literal["sink_only", "static_path", "canary_validated"]
    remote_reachability: Literal["network_source_modeled", "caller_controlled_only", "unknown"]
    impact: str
    steps: tuple[EvidenceStep, ...]
    conditions: tuple[str, ...] = ()
    assumptions: tuple[str, ...] = ()
    unresolved_edges: tuple[EvidenceStep, ...] = ()
    dependencies: dict[str, str] = Field(default_factory=dict)
    human_review: Literal["unreviewed", "confirmed", "dismissed", "needs_information"] = (
        "unreviewed"
    )
    human_rationale: str | None = None
    review_notes: tuple[str, ...] = ()


class ScanReport(Record):
    schema_version: str = SCHEMA_VERSION
    tool_version: str = "0.1.0"
    rule_version: str = RULE_VERSION
    root: str
    status: Literal["completed", "incomplete", "error"]
    findings: tuple[Finding, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    analyzed_files: int = 0
    skipped_files: int = 0
    content_hashes: dict[str, str] = Field(default_factory=dict)
    revision: str | None = None
    limits: dict[str, int | float] = Field(default_factory=dict)
    enabled_rules: tuple[str, ...] = ()
    exclusions: tuple[str, ...] = ()
    target_syntax: str
    ai_status: str = "disabled"
    ai_reviews: dict[str, dict] = Field(default_factory=dict)

    @property
    def summary(self) -> str:
        if self.status != "completed":
            return "Incomplete scan; coverage diagnostics require review."
        return (
            f"{len(self.findings)} modeled findings." if self.findings else "No modeled findings."
        )

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)

    def to_markdown(self) -> str:
        from .reports import markdown

        return markdown(self)


def fingerprint(rule: str, location: Location, source: Location | None) -> str:
    """Stable across roots, timestamps, rendering, and AI annotations."""
    payload = [RULE_VERSION, rule, location.model_dump(), source.model_dump() if source else None]
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
