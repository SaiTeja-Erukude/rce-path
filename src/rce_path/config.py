"""Strict operator configuration. Repository settings cannot enable AI or grant consent."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

DEFAULT_EXCLUDES = (
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    ".tox",
    ".nox",
    "site-packages",
    ".eggs",
)
RULE_IDS = ("python.eval", "python.exec", "os.system", "os.popen", "subprocess.shell")


class ScanConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    excludes: tuple[str, ...] = DEFAULT_EXCLUDES
    rules: tuple[str, ...] = RULE_IDS
    max_file_bytes: int = Field(default=1_000_000, ge=1, le=20_000_000)
    max_files: int = Field(default=10_000, ge=1, le=1_000_000)
    max_inventory_entries: int = Field(default=100_000, ge=1, le=1_000_000)
    parser_timeout_seconds: float = Field(default=10.0, gt=0, le=300)
    parser_memory_mb: int = Field(default=256, ge=64, le=4096)
    scan_timeout_seconds: float = Field(default=120.0, gt=0, le=86400)
    max_ast_nodes: int = Field(default=30_000, ge=1, le=1_000_000)
    max_flow_steps: int = Field(default=20_000, ge=1, le=1_000_000)
    loop_iterations: int = Field(default=8, ge=1, le=100)
    max_evidence_steps: int = Field(default=64, ge=2, le=512)
    ai_enabled: bool = False
    ai_provider: Literal["openai", "ollama"] = "ollama"
    ai_model: str | None = None
    allow_remote_code: bool = False
    ai_endpoint: str | None = None
    ai_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    ai_max_reviews: int = Field(default=20, ge=1, le=1000)
    ai_max_input_bytes: int = Field(default=16_000, ge=512, le=200_000)
    ai_max_output_tokens: int = Field(default=1024, ge=64, le=8192)
    ai_total_token_budget: int = Field(default=50_000, ge=64, le=10_000_000)

    @model_validator(mode="after")
    def valid_selection(self) -> ScanConfig:
        if not self.rules or set(self.rules) - set(RULE_IDS):
            raise ValueError("rules must be a nonempty selection of built-in Phase 1 rules")
        if self.ai_enabled and not self.ai_model:
            raise ValueError("an explicit ai_model is required when AI is enabled")
        if any(not item or "\\" in item for item in self.excludes):
            raise ValueError("excludes must be nonempty names or forward-slash glob patterns")
        return self


def load_config(path: Path, *, accept_ai_endpoint: bool = False) -> ScanConfig:
    from .ingest import _read

    path = path.absolute()
    raw = tomllib.loads(_read(path, path.parent.resolve(), 64_000).decode("utf-8"))
    if any(not isinstance(raw.get(section, {}), dict) for section in ("scan", "ai")):
        raise ValueError("scan and ai must be TOML tables")
    if set(raw) - {"scan", "ai"}:
        raise ValueError("unknown configuration section")
    settings = dict(raw.get("scan", {}))
    for key in ("excludes", "rules"):
        if key in settings and isinstance(settings[key], list):
            settings[key] = tuple(settings[key])
    ai = dict(raw.get("ai", {}))
    allowed_ai = {
        "provider",
        "model",
        "endpoint",
        "timeout_seconds",
        "max_reviews",
        "max_input_bytes",
        "max_output_tokens",
        "total_token_budget",
    }
    if set(ai) - allowed_ai:
        raise ValueError("unknown AI setting; runtime opt-in/consent belongs on the command line")
    if set(settings) - (
        set(ScanConfig.model_fields) - {"ai_enabled", "allow_remote_code", "ai_endpoint"}
    ):
        raise ValueError("unknown or privileged scan setting")
    for key, value in ai.items():
        if key == "endpoint" and not accept_ai_endpoint:
            continue
        settings[f"ai_{key}"] = value
    return ScanConfig(**settings)
