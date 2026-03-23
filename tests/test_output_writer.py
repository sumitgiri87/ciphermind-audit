"""
Tests for utils/output_writer.py

Verifies that final_report.json and summary.md are written correctly
and contain expected content.
"""

import json
import tempfile
from pathlib import Path

import pytest

from cbom.models import CryptoAsset, DetectionLocation
from recommender.rule_engine import RuleFinding
from recommender.ai_recommender import AIRecommendation
from utils.output_writer import write_reports, get_report_dir, _build_summary_counts


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(
    rule_id: str = "RULE-001",
    severity: str = "critical",
    variant: str = "MD5",
) -> RuleFinding:
    """Minimal RuleFinding for output tests."""
    asset = CryptoAsset(
        bom_ref=f"test:{variant.lower()}",
        name=variant,
        primitive="hash",
        variant=variant,
        locations=[
            DetectionLocation(
                file_path="app/utils/hash.py",
                line_numbers=[10, 11],
                additional_context="hashlib.md5(...)",
            )
        ],
    )
    return RuleFinding(
        rule_id=rule_id,
        rule_name=f"Test rule {rule_id}",
        severity=severity,
        description="Test description",
        migration=["SHA-3-256"],
        asset=asset,
    )


def make_recommendation(rule_id: str = "RULE-001") -> AIRecommendation:
    """Minimal AIRecommendation for output tests."""
    return AIRecommendation(
        rule_id=rule_id,
        asset_variant="MD5",
        summary="MD5 is broken and must be replaced.",
        migration_steps=["Step 1: replace MD5", "Step 2: update stored hashes"],
        effort_estimate="Medium",
        caveats=["Cache keys using MD5 are not security-sensitive"],
    )


# ---------------------------------------------------------------------------
# write_reports — JSON output
# ---------------------------------------------------------------------------

def test_write_reports_creates_json_file(tmp_path, monkeypatch):
    """write_reports must create final_report.json in the expected directory."""
    monkeypatch.chdir(tmp_path)  # ensure AUDITS_DIR resolves under tmp_path

    findings = [make_finding()]
    recs = [make_recommendation()]
    json_path, md_path = write_reports("my-project", findings, recs)

    assert json_path.exists()
    assert json_path.name == "final_report.json"


def test_write_reports_json_structure(tmp_path, monkeypatch):
    """final_report.json must contain all required top-level keys."""
    monkeypatch.chdir(tmp_path)

    findings = [make_finding()]
    recs = [make_recommendation()]
    json_path, _ = write_reports("my-project", findings, recs)

    data = json.loads(json_path.read_text())
    assert "schema_version" in data
    assert "generated_at" in data
    assert "project" in data
    assert "summary" in data
    assert "findings" in data
    assert "ai_recommendations" in data


def test_write_reports_json_project_name(tmp_path, monkeypatch):
    """project field in report must match the provided project name."""
    monkeypatch.chdir(tmp_path)

    json_path, _ = write_reports("my-python-app", [], [])
    data = json.loads(json_path.read_text())
    assert data["project"] == "my-python-app"


def test_write_reports_json_findings_count(tmp_path, monkeypatch):
    """findings array length must match the number of findings passed in."""
    monkeypatch.chdir(tmp_path)

    findings = [make_finding("RULE-001"), make_finding("RULE-002", severity="high", variant="SHA1")]
    json_path, _ = write_reports("proj", findings, [])
    data = json.loads(json_path.read_text())
    assert len(data["findings"]) == 2


def test_write_reports_json_summary_counts(tmp_path, monkeypatch):
    """summary counts in JSON must reflect actual finding severities."""
    monkeypatch.chdir(tmp_path)

    findings = [
        make_finding("RULE-001", severity="critical"),
        make_finding("RULE-002", severity="high"),
        make_finding("RULE-003", severity="medium"),
    ]
    json_path, _ = write_reports("proj", findings, [])
    data = json.loads(json_path.read_text())
    s = data["summary"]
    assert s["critical"] == 1
    assert s["high"] == 1
    assert s["medium"] == 1
    assert s["total"] == 3


# ---------------------------------------------------------------------------
# write_reports — Markdown output
# ---------------------------------------------------------------------------

def test_write_reports_creates_markdown_file(tmp_path, monkeypatch):
    """write_reports must create summary.md."""
    monkeypatch.chdir(tmp_path)

    _, md_path = write_reports("proj", [], [])
    assert md_path.exists()
    assert md_path.name == "summary.md"


def test_markdown_contains_project_name(tmp_path, monkeypatch):
    """summary.md must reference the project name in the heading."""
    monkeypatch.chdir(tmp_path)

    _, md_path = write_reports("my-python-app", [], [])
    content = md_path.read_text()
    assert "my-python-app" in content


def test_markdown_clean_audit_message(tmp_path, monkeypatch):
    """summary.md for zero findings must say no issues found."""
    monkeypatch.chdir(tmp_path)

    _, md_path = write_reports("clean-proj", [], [])
    content = md_path.read_text()
    assert "No issues found" in content or "PQC-compliant" in content


def test_markdown_contains_rule_id(tmp_path, monkeypatch):
    """summary.md must include finding rule IDs."""
    monkeypatch.chdir(tmp_path)

    findings = [make_finding("RULE-001")]
    _, md_path = write_reports("proj", findings, [])
    content = md_path.read_text()
    assert "RULE-001" in content


def test_markdown_contains_ai_summary(tmp_path, monkeypatch):
    """summary.md must include AI recommendation summary when provided."""
    monkeypatch.chdir(tmp_path)

    findings = [make_finding("RULE-001")]
    recs = [make_recommendation("RULE-001")]
    _, md_path = write_reports("proj", findings, recs)
    content = md_path.read_text()
    assert "MD5 is broken" in content


def test_markdown_severity_icons_present(tmp_path, monkeypatch):
    """summary.md must use emoji severity icons for critical and high findings."""
    monkeypatch.chdir(tmp_path)

    findings = [
        make_finding("RULE-001", severity="critical"),
        make_finding("RULE-002", severity="high", variant="SHA1"),
    ]
    _, md_path = write_reports("proj", findings, [])
    content = md_path.read_text()
    assert "🔴" in content
    assert "🟠" in content


# ---------------------------------------------------------------------------
# _build_summary_counts
# ---------------------------------------------------------------------------

def test_build_summary_counts_empty():
    """Empty findings list must return all-zero counts."""
    counts = _build_summary_counts([])
    assert counts == {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}


def test_build_summary_counts_mixed():
    """Mixed severities must be tallied correctly."""
    findings = [
        make_finding(severity="critical"),
        make_finding(severity="critical"),
        make_finding(severity="high"),
        make_finding(severity="low"),
    ]
    counts = _build_summary_counts(findings)
    assert counts["critical"] == 2
    assert counts["high"] == 1
    assert counts["medium"] == 0
    assert counts["low"] == 1
    assert counts["total"] == 4
