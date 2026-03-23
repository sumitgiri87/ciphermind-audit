"""
CipherMind Audit Tool — CLI entry point.

Commands:
  audit scan <repo-path-or-url>         CodeQL → SARIF → CBOM
  audit analyze <cbom.json> [--no-ai]  rule engine + AI → report
  audit report <project-name>           replay/print existing report

Exit codes:
  0 = clean (no findings)
  1 = high findings detected
  2 = critical findings detected
"""

import json
import sys
from pathlib import Path
from typing import Optional

import typer

from cbom.parser import parse_cbom, CBOMParseError
from cbom.normalizer import normalize_assets
from recommender.rule_engine import load_rules, evaluate_rules, RuleEngineError
from recommender.ai_recommender import get_recommendations, AIRecommenderError
from utils.output_writer import write_reports, get_report_dir, AUDITS_DIR
from utils.logging_config import configure_logging

app = typer.Typer(
    name="audit",
    help="CipherMind PQC Audit Tool — detect and migrate weak cryptography.",
    add_completion=False,
)

# Default rules path (resolved relative to this file's package root)
DEFAULT_RULES = Path(__file__).parent.parent / "configs" / "pqc_rules.yml"


@app.command("scan")
def scan(
    repo: str = typer.Argument(..., help="Local path or GitHub URL to scan"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
) -> None:
    """
    Run CodeQL on a repo, produce SARIF, and generate a CBOM.

    Output: audits/<project-name>/cbom/cbom.json
    """
    configure_logging(verbose)

    from scanner.codeql_runner import run_scan, ScannerError

    try:
        cbom_path = run_scan(repo_path=repo, project_name=Path(repo).name)
        typer.echo(f"✅ CBOM generated: {cbom_path}")
        typer.echo(f"Run: audit analyze {cbom_path}")
    except ScannerError as exc:
        typer.echo(f"❌ Scan failed: {exc}", err=True)
        raise typer.Exit(code=2)


@app.command("analyze")
def analyze(
    cbom_file: str = typer.Argument(..., help="Path to cbom.json from cryptobom-forge"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip the AI recommendation layer"),
    rules: str = typer.Option(str(DEFAULT_RULES), "--rules", help="Path to pqc_rules.yml"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
    ollama_url: str = typer.Option(
        "http://localhost:11434/api/chat", "--ollama-url", help="Ollama API endpoint"
    ),
    ollama_model: str = typer.Option("llama3", "--model", help="Ollama model name"),
) -> None:
    """
    Parse a CBOM, run PQC rules, optionally get AI recommendations, write report.

    Exit code: 0=clean, 1=high findings, 2=critical findings.
    """
    configure_logging(verbose)

    # 1. Parse + normalize CBOM
    try:
        project_name, raw_assets = parse_cbom(cbom_file)
    except (CBOMParseError, FileNotFoundError) as exc:
        typer.echo(f"❌ CBOM parse error: {exc}", err=True)
        raise typer.Exit(code=2)

    assets = normalize_assets(raw_assets)
    typer.echo(f"📦 Project: {project_name} — {len(assets)} crypto asset(s) found")

    # 2. Run rule engine
    try:
        rule_list = load_rules(rules)
    except RuleEngineError as exc:
        typer.echo(f"❌ Rule load error: {exc}", err=True)
        raise typer.Exit(code=2)

    findings = evaluate_rules(assets, rule_list)
    _print_findings_summary(findings)

    # 3. Optional AI layer
    recommendations = []
    if not no_ai and findings:
        typer.echo("🤖 Requesting AI recommendations (Ollama) ...")
        try:
            recommendations = get_recommendations(
                findings, model=ollama_model, base_url=ollama_url
            )
            typer.echo(f"   {len(recommendations)} recommendation(s) received")
        except AIRecommenderError as exc:
            typer.echo(f"❌ AI error: {exc}", err=True)
            raise typer.Exit(code=2)

    # 4. Write reports
    json_path, md_path = write_reports(
        project_name=project_name,
        findings=findings,
        recommendations=recommendations,
        cbom_path=cbom_file,
    )
    typer.echo(f"\n📄 Report:   {json_path}")
    typer.echo(f"📝 Summary:  {md_path}")

    # 5. Exit code
    severities = {f.severity for f in findings}
    if "critical" in severities:
        raise typer.Exit(code=2)
    if "high" in severities:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


@app.command("report")
def report(
    project_name: str = typer.Argument(..., help="Project name from a prior audit"),
) -> None:
    """
    Print a summary of a previously completed audit.

    Reads from: audits/<project-name>/reports/summary.md
    """
    md_path = get_report_dir(project_name) / "summary.md"
    json_path = get_report_dir(project_name) / "final_report.json"

    if not md_path.exists():
        typer.echo(
            f"❌ No audit found for '{project_name}'. "
            f"Expected: {md_path}",
            err=True,
        )
        raise typer.Exit(code=2)

    # Print the markdown summary
    typer.echo(md_path.read_text(encoding="utf-8"))

    # Print counts from JSON if available
    if json_path.exists():
        data = json.loads(json_path.read_text(encoding="utf-8"))
        summary = data.get("summary", {})
        typer.echo(
            f"\nTotal findings: {summary.get('total', '?')} "
            f"(critical={summary.get('critical', 0)}, "
            f"high={summary.get('high', 0)}, "
            f"medium={summary.get('medium', 0)}, "
            f"low={summary.get('low', 0)})"
        )


def _print_findings_summary(findings: list) -> None:
    """Print a concise findings table to stdout."""
    if not findings:
        typer.echo("✅ No PQC issues found.")
        return

    typer.echo(f"\n🔍 {len(findings)} finding(s):\n")
    for f in findings:
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(f.severity, "⚪")
        typer.echo(f"  {icon} [{f.severity.upper():8}] {f.rule_id}: {f.rule_name} ({f.asset.variant})")
    typer.echo("")


def main() -> None:
    """Entry point for the 'audit' CLI command."""
    app()


if __name__ == "__main__":
    main()
