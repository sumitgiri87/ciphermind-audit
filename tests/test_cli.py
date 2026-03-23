"""
Tests for cli/main.py

Uses Typer's CliRunner to invoke commands in-process without spawning
a subprocess. The AI layer and output writer are mocked where needed.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from cli.main import app

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_CBOM = str(FIXTURES_DIR / "sample_cbom.json")

runner = CliRunner()


# ---------------------------------------------------------------------------
# audit analyze — happy path (--no-ai)
# ---------------------------------------------------------------------------

def test_analyze_no_ai_exits_nonzero_for_sample_cbom():
    """
    The sample CBOM has critical/high findings — exit code must be 1 or 2,
    not 0 (0 means clean).
    """
    result = runner.invoke(app, ["analyze", SAMPLE_CBOM, "--no-ai"])
    assert result.exit_code in (1, 2), (
        f"Expected non-zero exit for sample CBOM, got {result.exit_code}\n{result.output}"
    )


def test_analyze_no_ai_outputs_findings(tmp_path, monkeypatch):
    """audit analyze --no-ai must print findings to stdout."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["analyze", SAMPLE_CBOM, "--no-ai"])
    assert "finding" in result.output.lower() or "RULE-" in result.output


def test_analyze_no_ai_creates_report_files(tmp_path, monkeypatch):
    """audit analyze --no-ai must write final_report.json and summary.md."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["analyze", SAMPLE_CBOM, "--no-ai"])

    # The output should mention the report path
    assert "final_report.json" in result.output or "summary.md" in result.output

    # Files must exist on disk
    report_files = list(tmp_path.rglob("final_report.json"))
    assert len(report_files) >= 1, "final_report.json was not created"

    md_files = list(tmp_path.rglob("summary.md"))
    assert len(md_files) >= 1, "summary.md was not created"


def test_analyze_exit_code_2_for_critical(tmp_path, monkeypatch):
    """
    The sample CBOM contains MD5, RC4, AES-ECB, RSA-1024 — all critical.
    Exit code must be 2.
    """
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["analyze", SAMPLE_CBOM, "--no-ai"])
    assert result.exit_code == 2


# ---------------------------------------------------------------------------
# audit analyze — error cases
# ---------------------------------------------------------------------------

def test_analyze_missing_cbom_file_exits_2():
    """Nonexistent CBOM path must exit with code 2."""
    result = runner.invoke(app, ["analyze", "/tmp/no_such_cbom.json", "--no-ai"])
    assert result.exit_code == 2
    assert "error" in result.output.lower() or "not found" in result.output.lower()


def test_analyze_missing_rules_file_exits_2(tmp_path, monkeypatch):
    """Nonexistent rules file must exit with code 2."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, [
        "analyze", SAMPLE_CBOM, "--no-ai",
        "--rules", "/tmp/no_such_rules.yml",
    ])
    assert result.exit_code == 2


def test_analyze_with_ai_fails_when_ollama_down(tmp_path, monkeypatch):
    """
    Without --no-ai and with Ollama unreachable, the command must fail
    with exit code 2 and print an actionable error message.
    """
    import httpx
    monkeypatch.chdir(tmp_path)

    with patch("recommender.ai_recommender.httpx.post") as mock_post:
        mock_post.side_effect = httpx.ConnectError("Connection refused")
        result = runner.invoke(app, ["analyze", SAMPLE_CBOM])

    assert result.exit_code == 2
    assert "Ollama" in result.output or "ollama" in result.output.lower()


# ---------------------------------------------------------------------------
# audit report
# ---------------------------------------------------------------------------

def test_report_nonexistent_project_exits_2():
    """Requesting a report for a project that has no prior audit must exit 2."""
    result = runner.invoke(app, ["report", "no-such-project-xyz"])
    assert result.exit_code == 2


def test_report_prints_summary_for_existing_audit(tmp_path, monkeypatch):
    """
    After running analyze, audit report <name> should print the markdown summary.
    """
    monkeypatch.chdir(tmp_path)

    # First run analyze to produce the reports
    runner.invoke(app, ["analyze", SAMPLE_CBOM, "--no-ai"])

    # Now run report
    result = runner.invoke(app, ["report", "my-python-app"])
    assert result.exit_code == 0
    # The markdown heading should appear
    assert "my-python-app" in result.output
    assert "CipherMind" in result.output


# ---------------------------------------------------------------------------
# audit scan — stub
# ---------------------------------------------------------------------------

def test_scan_fails_when_codeql_not_installed():
    """
    If CodeQL is not installed, audit scan must exit non-zero with
    a helpful error message.
    """
    result = runner.invoke(app, ["scan", "/some/repo"])
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# CLI help
# ---------------------------------------------------------------------------

def test_help_exits_0():
    """--help must always exit 0."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0


def test_analyze_help_mentions_no_ai():
    """audit analyze --help must document the --no-ai flag."""
    result = runner.invoke(app, ["analyze", "--help"])
    assert "--no-ai" in result.output
