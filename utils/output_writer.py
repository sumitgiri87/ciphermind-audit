"""
Output writer for audit reports.

Writes:
  audits/<project-name>/reports/final_report.json
  audits/<project-name>/reports/summary.md

Design: all functions return the path written, so the CLI can echo it.
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from recommender.rule_engine import RuleFinding
from recommender.ai_recommender import AIRecommendation

logger = logging.getLogger(__name__)

AUDITS_DIR = Path("audits")


def get_report_dir(project_name: str) -> Path:
    """Return the reports directory path for a project (does not create it)."""
    return AUDITS_DIR / project_name / "reports"


def write_reports(
    project_name: str,
    findings: list[RuleFinding],
    recommendations: list[AIRecommendation],
    cbom_path: str = "",
) -> tuple[Path, Path]:
    """
    Write final_report.json and summary.md for a completed audit.

    Returns:
        (json_path, md_path) — paths of the written files.
    """
    report_dir = get_report_dir(project_name)
    report_dir.mkdir(parents=True, exist_ok=True)

    json_path = _write_json(report_dir, project_name, findings, recommendations, cbom_path)
    md_path = _write_markdown(report_dir, project_name, findings, recommendations)

    return json_path, md_path


def _write_json(
    report_dir: Path,
    project_name: str,
    findings: list[RuleFinding],
    recommendations: list[AIRecommendation],
    cbom_path: str,
) -> Path:
    """Write final_report.json and return its path."""
    # Map rule_id → recommendation for easy lookup in report
    rec_map = {r.rule_id: r.as_dict() for r in recommendations}

    report = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": project_name,
        "cbom_source": cbom_path,
        "summary": _build_summary_counts(findings),
        "findings": [f.as_dict() for f in findings],
        "ai_recommendations": [r.as_dict() for r in recommendations],
    }

    path = report_dir / "final_report.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    logger.info("Wrote %s", path)
    return path


def _write_markdown(
    report_dir: Path,
    project_name: str,
    findings: list[RuleFinding],
    recommendations: list[AIRecommendation],
) -> Path:
    """Write summary.md and return its path."""
    counts = _build_summary_counts(findings)
    rec_map = {r.rule_id: r for r in recommendations}

    lines: list[str] = [
        f"# CipherMind PQC Audit Report: `{project_name}`",
        "",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Summary",
        "",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 Critical | {counts['critical']} |",
        f"| 🟠 High     | {counts['high']} |",
        f"| 🟡 Medium   | {counts['medium']} |",
        f"| 🟢 Low      | {counts['low']} |",
        f"| **Total**   | **{counts['total']}** |",
        "",
        "---",
        "",
        "## Findings",
        "",
    ]

    if not findings:
        lines.append("✅ No issues found. All cryptographic assets appear PQC-compliant.")
    else:
        for finding in findings:
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(
                finding.severity, "⚪"
            )
            lines += [
                f"### {severity_icon} [{finding.severity.upper()}] {finding.rule_id}: {finding.rule_name}",
                "",
                f"**Algorithm:** `{finding.asset.variant}`"
                + (f" / key_size={finding.asset.key_size}" if finding.asset.key_size else "")
                + (f" / mode={finding.asset.mode}" if finding.asset.mode else ""),
                "",
                f"**Description:** {finding.description}",
                "",
                "**Detected at:**",
            ]
            for loc in finding.asset.locations:
                ctx = f" — `{loc.additional_context}`" if loc.additional_context else ""
                lines.append(f"- `{loc.file_path}` (lines {loc.line_numbers}){ctx}")

            lines += [
                "",
                f"**Suggested migration:** {', '.join(finding.migration)}",
                "",
            ]

            rec = rec_map.get(finding.rule_id)
            if rec:
                lines += [
                    "**AI Guidance:**",
                    "",
                    f"> {rec.summary}",
                    "",
                    f"*Effort: {rec.effort_estimate}*",
                    "",
                    "Steps:",
                ]
                for i, step in enumerate(rec.migration_steps, 1):
                    lines.append(f"{i}. {step}")
                if rec.caveats:
                    lines += ["", "⚠️ Caveats:"]
                    for caveat in rec.caveats:
                        lines.append(f"- {caveat}")

            lines.append("")
            lines.append("---")
            lines.append("")

    path = report_dir / "summary.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Wrote %s", path)
    return path


def _build_summary_counts(findings: list[RuleFinding]) -> dict:
    """Count findings by severity."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": len(findings)}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts
