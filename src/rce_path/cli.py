"""CLI policies are explicit; incomplete scans always take precedence."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import ScanConfig, load_config
from .ingest import scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rce-path",
        description="Investigate modeled Python execution paths without executing the target.",
    )
    parser.add_argument("--version", action="version", version="rce-path 0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("scan")
    command.add_argument("path")
    command.add_argument("--format", choices=["json", "markdown"], default="json")
    command.add_argument("--output", type=Path)
    command.add_argument("--config", type=Path)
    command.add_argument("--fail-on", choices=["none", "static-path", "any"], default="none")
    command.add_argument("--ai", choices=["openai", "ollama"])
    command.add_argument("--model")
    command.add_argument("--endpoint")
    command.add_argument("--allow-remote-code", action="store_true")
    command.add_argument("--accept-config-ai-endpoint", action="store_true")
    args = parser.parse_args(argv)
    try:
        target = Path(args.path)
        root = target if target.is_dir() else target.parent
        config_path = args.config or root / "rce-path.toml"
        if args.config or config_path.exists():
            if config_path.is_symlink() or (
                getattr(config_path.lstat(), "st_file_attributes", 0) & 0x400
            ):
                raise ValueError("configuration symlinks/reparse points are not accepted")
            config = load_config(config_path, accept_ai_endpoint=args.accept_config_ai_endpoint)
        else:
            config = ScanConfig()
        updates = {"ai_enabled": bool(args.ai), "allow_remote_code": args.allow_remote_code}
        for name, value in (
            ("ai_provider", args.ai),
            ("ai_model", args.model),
            ("ai_endpoint", args.endpoint),
        ):
            if value is not None:
                updates[name] = value
        config = ScanConfig(**(config.model_dump() | updates))
        if config.ai_enabled and config.ai_provider == "openai" and not config.allow_remote_code:
            raise ValueError("OpenAI code transmission requires --allow-remote-code")
        report = scan(args.path, config)
        output = report.to_json() if args.format == "json" else report.to_markdown()
        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
        if report.status != "completed" or report.ai_status not in {
            "disabled",
            "completed",
            "no_findings",
        }:
            return 2
        failed = args.fail_on == "any" and bool(report.findings)
        failed |= args.fail_on == "static-path" and any(
            f.evidence_tier == "static_path" for f in report.findings
        )
        return 1 if failed else 0
    except (OSError, ValueError) as error:
        print(f"rce-path: {str(error)[:500]}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
