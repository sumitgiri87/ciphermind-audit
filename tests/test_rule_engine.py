"""
Tests for recommender/rule_engine.py

Verifies that rules load correctly and evaluate accurately against
CryptoAssets parsed from the sample CBOM.
"""

import tempfile
from pathlib import Path

import pytest
import yaml

from cbom.models import CryptoAsset, DetectionLocation
from cbom.parser import parse_cbom
from cbom.normalizer import normalize_assets
from recommender.rule_engine import (
    load_rules,
    evaluate_rules,
    RuleEngineError,
    RuleFinding,
    SEVERITY_ORDER,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_CBOM = FIXTURES_DIR / "sample_cbom.json"
DEFAULT_RULES = Path(__file__).parent.parent / "configs" / "pqc_rules.yml"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_asset(
    variant: str,
    primitive: str = "hash",
    key_size: int | None = None,
    mode: str | None = None,
    padding: str | None = None,
    curve: str | None = None,
) -> CryptoAsset:
    """Minimal CryptoAsset factory for unit tests."""
    return CryptoAsset(
        bom_ref=f"test:{variant.lower()}",
        name=variant,
        primitive=primitive,
        variant=variant,
        key_size=key_size,
        mode=mode,
        padding=padding,
        curve=curve,
        locations=[DetectionLocation(file_path="test/file.py", line_numbers=[1])],
    )


# ---------------------------------------------------------------------------
# load_rules
# ---------------------------------------------------------------------------

def test_load_rules_returns_nonempty_list():
    """Default rules file must contain at least 8 rules."""
    rules = load_rules(DEFAULT_RULES)
    assert isinstance(rules, list)
    assert len(rules) >= 8


def test_load_rules_each_rule_has_required_keys():
    """Every rule must have id, name, severity, conditions, migration."""
    rules = load_rules(DEFAULT_RULES)
    required = {"id", "name", "severity", "conditions", "migration"}
    for rule in rules:
        missing = required - rule.keys()
        assert not missing, f"Rule {rule.get('id', '?')} missing keys: {missing}"


def test_load_rules_severity_values_valid():
    """All severity values must be within the known set."""
    rules = load_rules(DEFAULT_RULES)
    valid = {"critical", "high", "medium", "low"}
    for rule in rules:
        assert rule["severity"] in valid, f"Rule {rule['id']} has invalid severity: {rule['severity']}"


def test_load_rules_missing_file_raises():
    """RuleEngineError raised when file does not exist."""
    with pytest.raises(RuleEngineError, match="not found"):
        load_rules("/tmp/no_such_rules.yml")


def test_load_rules_invalid_yaml_raises():
    """RuleEngineError raised on malformed YAML."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write("rules: [: bad yaml {{{{")
        bad_path = f.name
    with pytest.raises(RuleEngineError, match="Invalid YAML"):
        load_rules(bad_path)


def test_load_rules_empty_rules_key_raises():
    """RuleEngineError raised when rules list is empty."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        yaml.dump({"rules": []}, f)
        path = f.name
    with pytest.raises(RuleEngineError):
        load_rules(path)


# ---------------------------------------------------------------------------
# evaluate_rules — individual algorithm flags
# ---------------------------------------------------------------------------

def test_md5_triggers_rule_001():
    """MD5 asset must trigger RULE-001."""
    rules = load_rules(DEFAULT_RULES)
    findings = evaluate_rules([make_asset("MD5", "hash")], rules)
    rule_ids = {f.rule_id for f in findings}
    assert "RULE-001" in rule_ids


def test_sha1_triggers_rule_002():
    """SHA1 asset must trigger RULE-002."""
    rules = load_rules(DEFAULT_RULES)
    findings = evaluate_rules([make_asset("SHA1", "hash")], rules)
    rule_ids = {f.rule_id for f in findings}
    assert "RULE-002" in rule_ids


def test_rsa_1024_triggers_rule_003_and_004():
    """RSA-1024 must trigger both RULE-003 (key size) and RULE-004 (not PQC)."""
    rules = load_rules(DEFAULT_RULES)
    findings = evaluate_rules(
        [make_asset("RSA", "asymmetric-encryption", key_size=1024, padding="PKCS1V15")],
        rules,
    )
    rule_ids = {f.rule_id for f in findings}
    assert "RULE-003" in rule_ids
    assert "RULE-004" in rule_ids


def test_rsa_2048_does_not_trigger_rule_003():
    """RSA-2048 is NOT below the 2048-bit threshold — RULE-003 must not fire."""
    rules = load_rules(DEFAULT_RULES)
    findings = evaluate_rules(
        [make_asset("RSA", "asymmetric-encryption", key_size=2048)],
        rules,
    )
    rule_ids = {f.rule_id for f in findings}
    assert "RULE-003" not in rule_ids


def test_ecdsa_triggers_rule_005():
    """ECDSA must trigger RULE-005."""
    rules = load_rules(DEFAULT_RULES)
    findings = evaluate_rules(
        [make_asset("ECDSA", "signature", curve="P-256")],
        rules,
    )
    rule_ids = {f.rule_id for f in findings}
    assert "RULE-005" in rule_ids


def test_aes_ecb_triggers_rule_006():
    """AES in ECB mode must trigger RULE-006."""
    rules = load_rules(DEFAULT_RULES)
    findings = evaluate_rules(
        [make_asset("AES", "block-cipher", key_size=128, mode="ECB")],
        rules,
    )
    rule_ids = {f.rule_id for f in findings}
    assert "RULE-006" in rule_ids


def test_aes_gcm_does_not_trigger_rule_006():
    """AES-GCM must NOT trigger RULE-006 (ECB-only rule)."""
    rules = load_rules(DEFAULT_RULES)
    findings = evaluate_rules(
        [make_asset("AES", "block-cipher", key_size=256, mode="GCM")],
        rules,
    )
    rule_ids = {f.rule_id for f in findings}
    assert "RULE-006" not in rule_ids


def test_3des_triggers_rule_007():
    """3DES must trigger RULE-007."""
    rules = load_rules(DEFAULT_RULES)
    findings = evaluate_rules(
        [make_asset("3DES", "block-cipher", key_size=112, mode="CBC")],
        rules,
    )
    rule_ids = {f.rule_id for f in findings}
    assert "RULE-007" in rule_ids


def test_rc4_triggers_rule_008():
    """RC4 must trigger RULE-008."""
    rules = load_rules(DEFAULT_RULES)
    findings = evaluate_rules(
        [make_asset("RC4", "stream-cipher")],
        rules,
    )
    rule_ids = {f.rule_id for f in findings}
    assert "RULE-008" in rule_ids


def test_sha256_triggers_no_rules():
    """SHA-256 is safe — no rules should fire."""
    rules = load_rules(DEFAULT_RULES)
    findings = evaluate_rules([make_asset("SHA256", "hash")], rules)
    assert findings == []


# ---------------------------------------------------------------------------
# evaluate_rules — full sample CBOM integration
# ---------------------------------------------------------------------------

def test_sample_cbom_produces_findings():
    """Running the full sample CBOM through the rule engine must produce findings."""
    _, raw = parse_cbom(SAMPLE_CBOM)
    assets = normalize_assets(raw)
    rules = load_rules(DEFAULT_RULES)
    findings = evaluate_rules(assets, rules)
    assert len(findings) >= 5, f"Expected ≥5 findings, got {len(findings)}"


def test_sample_cbom_critical_findings_present():
    """Sample CBOM contains MD5, RC4, AES-ECB, RSA-1024 — at least one critical finding expected."""
    _, raw = parse_cbom(SAMPLE_CBOM)
    assets = normalize_assets(raw)
    rules = load_rules(DEFAULT_RULES)
    findings = evaluate_rules(assets, rules)
    critical = [f for f in findings if f.severity == "critical"]
    assert len(critical) >= 1


def test_findings_sorted_by_severity_descending():
    """Findings must be returned sorted: critical first, low last."""
    rules = load_rules(DEFAULT_RULES)
    assets = [
        make_asset("SHA256", "hash"),         # no finding
        make_asset("SHA1", "hash"),            # high
        make_asset("MD5", "hash"),             # critical
        make_asset("RC4", "stream-cipher"),    # critical
    ]
    findings = evaluate_rules(assets, rules)
    severities = [SEVERITY_ORDER[f.severity] for f in findings]
    assert severities == sorted(severities, reverse=True)


# ---------------------------------------------------------------------------
# RuleFinding serialization
# ---------------------------------------------------------------------------

def test_rule_finding_as_dict():
    """RuleFinding.as_dict() must include all expected keys."""
    rules = load_rules(DEFAULT_RULES)
    findings = evaluate_rules([make_asset("MD5", "hash")], rules)
    assert findings, "Expected at least one finding for MD5"
    d = findings[0].as_dict()
    assert "rule_id" in d
    assert "severity" in d
    assert "migration" in d
    assert "asset" in d
    assert "locations" in d["asset"]
