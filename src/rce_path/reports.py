"""Inert JSON/Markdown exports, with coverage and review status always visible."""

from __future__ import annotations

import html

from .findings import ScanReport


def inert(text: str) -> str:
    text = html.escape(text).replace("`", "&#96;").replace("\n", " ").replace("|", "&#124;")
    for character in "\\[]()*_~#":
        text = text.replace(character, f"&#{ord(character)};")
    return text


def markdown(report: ScanReport) -> str:
    lines = [
        "# rce-path report",
        "",
        report.summary,
        "",
        f"Status: **{report.status}**. Analyzed: {report.analyzed_files}; skipped: {report.skipped_files}.",
        f"AI status: **{inert(report.ai_status)}**. Target syntax: {report.target_syntax}.",
        "",
        "Static evidence does not establish exploitability or remote reachability.",
        "",
    ]
    for finding in report.findings:
        location = finding.location
        lines.extend(
            [
                f"## {inert(finding.rule_id)} at {inert(location.file)}:{location.line}",
                "",
                f"Fingerprint: {finding.fingerprint}",
                "",
                f"Evidence: {finding.evidence_tier}; source: {finding.source_category}; reachability: {finding.remote_reachability}.",
                f"Impact: {finding.impact}.",
                "",
                "| Step | Location | Evidence |",
                "|---|---|---|",
            ]
        )
        for step in finding.steps:
            lines.append(
                f"| {step.kind} ({step.id}) | {inert(step.location.file)}:{step.location.line}:{step.location.column} | {inert(step.description)} |"
            )
        for label, items in (
            ("Conditions", finding.conditions),
            ("Assumptions", finding.assumptions),
        ):
            if items:
                lines.extend(["", f"{label}:", ""] + [f"- {inert(item)}" for item in items])
        if finding.unresolved_edges:
            lines.extend(
                ["", "Unresolved calls:", ""]
                + [
                    f"- {inert(step.description)} at line {step.location.line}"
                    for step in finding.unresolved_edges
                ]
            )
        review = report.ai_reviews.get(finding.fingerprint)
        if review:
            lines.extend(
                [
                    "",
                    f"AI review: {inert(str(review.get('ai_status')))}.",
                    inert(str(review.get("rationale") or review.get("error") or "")),
                ]
            )
        lines.append("")
    lines.extend(["## Coverage diagnostics", ""])
    if report.diagnostics:
        lines.extend(
            f"- {inert(d.code)}: {inert(d.file or '')} {inert(d.message)}"
            for d in report.diagnostics
        )
    else:
        lines.append("No ingestion or analysis diagnostics within the configured models.")
    lines.extend(
        [
            "",
            "Unsupported scope: cross-function/cross-file flow, dynamic dispatch, deserialization, framework models beyond Flask, and executable/interpreter selection with shell=False.",
            "",
        ]
    )
    return "\n".join(lines)
