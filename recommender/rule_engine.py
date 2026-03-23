"""
Rule-based PQC classifier.

Loads rules from pqc_rules.yml and evaluates them against a list of
CryptoAssets, producing a list of RuleFindings.

Design: purely functional evaluation — no state, easy to test in isolation.
"""

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from cbom.models import CryptoAsset

# Default path to rules file relative to project root
DEFAULT_RULES_PATH = Path(__file__).parent.parent / "configs" / "pqc_rules.yml"

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class RuleFinding:
    """A single rule match against a CryptoAsset."""

    rule_id: str
    rule_name: str
    severity: str            # critical | high | medium | low
    description: str
    migration: list[str]
    asset: CryptoAsset

    def as_dict(self) -> dict:
        """Return a plain dict for JSON serialization."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "description": self.description,
            "migration": self.migration,
            "asset": self.asset.as_dict(),
        }


class RuleEngineError(Exception):
    """Raised when rules cannot be loaded or parsed."""


def load_rules(path: str | Path = DEFAULT_RULES_PATH) -> list[dict]:
    """
    Load and validate PQC rules from a YAML file.

    Raises:
        RuleEngineError: if the file is missing or malformed.
    """
    path = Path(path)
    if not path.exists():
        raise RuleEngineError(f"Rules file not found: {path}")

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleEngineError(f"Invalid YAML in {path}: {exc}") from exc

    rules = data.get("rules", [])
    if not isinstance(rules, list) or not rules:
        raise RuleEngineError("'rules' key must be a non-empty list")

    return rules


def evaluate_rules(
    assets: list[CryptoAsset],
    rules: list[dict],
) -> list[RuleFinding]:
    """
    Evaluate all rules against all assets.

    Returns a flat list of RuleFindings sorted by severity descending.
    One asset can match multiple rules (e.g. RSA matches both RULE-003 and RULE-004).
    """
    findings: list[RuleFinding] = []

    for rule in rules:
        for asset in assets:
            if _rule_matches(rule, asset):
                findings.append(
                    RuleFinding(
                        rule_id=rule["id"],
                        rule_name=rule["name"],
                        severity=rule["severity"],
                        description=rule.get("description", "").strip(),
                        migration=rule.get("migration", []),
                        asset=asset,
                    )
                )

    # Sort: critical → high → medium → low
    findings.sort(
        key=lambda f: SEVERITY_ORDER.get(f.severity, 0),
        reverse=True,
    )
    return findings


def _rule_matches(rule: dict, asset: CryptoAsset) -> bool:
    """
    Return True if ALL conditions in a rule match the given asset.

    Condition format: [field, operator, value]
    Supported fields: variant, primitive, key_size, mode, padding, curve
    Supported ops: eq, neq, lt, lte, gt, gte, in, not_in
    """
    conditions = rule.get("conditions", [])
    return all(_condition_matches(cond, asset) for cond in conditions)


def _condition_matches(condition: list, asset: CryptoAsset) -> bool:
    """Evaluate a single condition tuple against an asset."""
    if len(condition) != 3:
        return False

    field, op, expected = condition

    actual = _get_field(asset, field)
    if actual is None:
        # A missing field never satisfies eq/lt/gt/in — only neq/not_in
        return op in ("neq", "not_in")

    # Normalize strings to uppercase for comparison
    if isinstance(actual, str):
        actual = actual.upper()
    if isinstance(expected, str):
        expected = expected.upper()

    match op:
        case "eq":
            return actual == expected
        case "neq":
            return actual != expected
        case "lt":
            return isinstance(actual, (int, float)) and actual < expected
        case "lte":
            return isinstance(actual, (int, float)) and actual <= expected
        case "gt":
            return isinstance(actual, (int, float)) and actual > expected
        case "gte":
            return isinstance(actual, (int, float)) and actual >= expected
        case "in":
            expected_list = [v.upper() if isinstance(v, str) else v for v in expected]
            return actual in expected_list
        case "not_in":
            expected_list = [v.upper() if isinstance(v, str) else v for v in expected]
            return actual not in expected_list
        case _:
            return False


def _get_field(asset: CryptoAsset, field: str) -> str | int | None:
    """Extract a field value from a CryptoAsset by name."""
    return {
        "variant": asset.variant,
        "primitive": asset.primitive,
        "key_size": asset.key_size,
        "mode": asset.mode,
        "padding": asset.padding,
        "curve": asset.curve,
        "name": asset.name,
    }.get(field)
