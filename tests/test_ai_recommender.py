"""
Tests for recommender/ai_recommender.py

The AI layer calls Ollama over HTTP. All tests mock at the httpx.post level
so no Ollama instance is required. The mock is injected via unittest.mock.patch.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cbom.models import CryptoAsset, DetectionLocation
from recommender.ai_recommender import (
    AIRecommendation,
    AIRecommenderError,
    get_recommendations,
    _build_prompt,
    OLLAMA_DEFAULT_URL,
    OLLAMA_DEFAULT_MODEL,
)
from recommender.rule_engine import RuleFinding

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(
    rule_id: str = "RULE-001",
    rule_name: str = "MD5 Usage Detected",
    severity: str = "critical",
    variant: str = "MD5",
    primitive: str = "hash",
    key_size: int | None = None,
    mode: str | None = None,
    migration: list[str] | None = None,
) -> RuleFinding:
    """Minimal RuleFinding factory for tests."""
    asset = CryptoAsset(
        bom_ref=f"test:{variant.lower()}",
        name=variant,
        primitive=primitive,
        variant=variant,
        key_size=key_size,
        mode=mode,
        locations=[
            DetectionLocation(
                file_path="app/utils/hash.py",
                line_numbers=[12, 13],
                additional_context="hashlib.md5(data).hexdigest()",
            )
        ],
    )
    return RuleFinding(
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        description="Test description",
        migration=migration or ["SHA-3-256"],
        asset=asset,
    )


def make_ollama_response(payload: dict) -> MagicMock:
    """
    Build a mock httpx.Response that returns the given payload as JSON.

    The Ollama chat API wraps the model's text in:
      { "message": { "content": "<json string>" } }
    """
    inner_json = json.dumps(payload)
    response_body = {"message": {"content": inner_json}}

    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = response_body
    return mock_resp


VALID_AI_PAYLOAD = {
    "summary": "MD5 is cryptographically broken and must be replaced.",
    "migration_steps": [
        "Identify all MD5 usages with grep or SAST tooling.",
        "Replace hashlib.md5 with hashlib.sha3_256 or hashlib.shake_256.",
        "Update any stored hashes and re-hash existing data.",
    ],
    "effort_estimate": "Medium",
    "caveats": [
        "If MD5 is used for non-security checksums (e.g. cache keys), SHA-256 is sufficient.",
        "Stored hash values in databases will need migration.",
    ],
}


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------

@patch("recommender.ai_recommender.httpx.post")
def test_get_recommendations_returns_list(mock_post):
    """get_recommendations returns a list of AIRecommendation objects."""
    mock_post.return_value = make_ollama_response(VALID_AI_PAYLOAD)

    findings = [make_finding()]
    recs = get_recommendations(findings)

    assert isinstance(recs, list)
    assert len(recs) == 1
    assert isinstance(recs[0], AIRecommendation)


@patch("recommender.ai_recommender.httpx.post")
def test_recommendation_fields_populated(mock_post):
    """Returned AIRecommendation must have all expected fields populated."""
    mock_post.return_value = make_ollama_response(VALID_AI_PAYLOAD)

    findings = [make_finding()]
    rec = get_recommendations(findings)[0]

    assert rec.rule_id == "RULE-001"
    assert rec.asset_variant == "MD5"
    assert "MD5" in rec.summary
    assert len(rec.migration_steps) == 3
    assert rec.effort_estimate == "Medium"
    assert len(rec.caveats) == 2


@patch("recommender.ai_recommender.httpx.post")
def test_deduplication_same_rule_and_variant(mock_post):
    """
    Two findings with the same (rule_id, variant) should produce only one
    Ollama call — we deduplicate to avoid redundant LLM requests.
    """
    mock_post.return_value = make_ollama_response(VALID_AI_PAYLOAD)

    findings = [make_finding(), make_finding()]  # identical pair
    recs = get_recommendations(findings)

    assert mock_post.call_count == 1
    assert len(recs) == 1


@patch("recommender.ai_recommender.httpx.post")
def test_different_rules_make_separate_calls(mock_post):
    """Different (rule_id, variant) pairs each get their own Ollama call."""
    mock_post.return_value = make_ollama_response(VALID_AI_PAYLOAD)

    findings = [
        make_finding(rule_id="RULE-001", variant="MD5"),
        make_finding(rule_id="RULE-002", variant="SHA1"),
    ]
    recs = get_recommendations(findings)

    assert mock_post.call_count == 2
    assert len(recs) == 2


@patch("recommender.ai_recommender.httpx.post")
def test_empty_findings_returns_empty_list(mock_post):
    """No findings → no Ollama calls, empty recommendation list."""
    recs = get_recommendations([])

    mock_post.assert_not_called()
    assert recs == []


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------

@patch("recommender.ai_recommender.httpx.post")
def test_connect_error_raises_recommender_error(mock_post):
    """ConnectError (Ollama down) must raise AIRecommenderError with helpful message."""
    import httpx
    mock_post.side_effect = httpx.ConnectError("Connection refused")

    findings = [make_finding()]
    with pytest.raises(AIRecommenderError, match="Ollama"):
        get_recommendations(findings)


@patch("recommender.ai_recommender.httpx.post")
def test_http_status_error_raises_recommender_error(mock_post):
    """HTTP 500 from Ollama must raise AIRecommenderError."""
    import httpx
    mock_resp = MagicMock()
    mock_resp.raise_for_status.side_effect = httpx.HTTPStatusError(
        "Server error",
        request=MagicMock(),
        response=MagicMock(status_code=500, text="Internal Server Error"),
    )
    mock_post.return_value = mock_resp

    findings = [make_finding()]
    with pytest.raises(AIRecommenderError, match="500"):
        get_recommendations(findings)


@patch("recommender.ai_recommender.httpx.post")
def test_invalid_json_in_response_raises(mock_post):
    """If the model returns non-JSON content, AIRecommenderError must be raised."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"message": {"content": "Sorry, I cannot help with that."}}
    mock_post.return_value = mock_resp

    findings = [make_finding()]
    with pytest.raises(AIRecommenderError, match="parse"):
        get_recommendations(findings)


# ---------------------------------------------------------------------------
# AIRecommendation serialization
# ---------------------------------------------------------------------------

@patch("recommender.ai_recommender.httpx.post")
def test_recommendation_as_dict(mock_post):
    """AIRecommendation.as_dict() must return all expected keys."""
    mock_post.return_value = make_ollama_response(VALID_AI_PAYLOAD)

    findings = [make_finding()]
    rec = get_recommendations(findings)[0]
    d = rec.as_dict()

    assert set(d.keys()) == {
        "rule_id", "asset_variant", "summary",
        "migration_steps", "effort_estimate", "caveats"
    }


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

def test_build_prompt_includes_rule_id():
    """The prompt sent to the LLM must contain the rule ID."""
    finding = make_finding(rule_id="RULE-008", variant="RC4")
    prompt = _build_prompt(finding)
    assert "RULE-008" in prompt


def test_build_prompt_includes_variant():
    """The prompt must mention the algorithm variant."""
    finding = make_finding(variant="RC4")
    prompt = _build_prompt(finding)
    assert "RC4" in prompt


def test_build_prompt_requests_json_output():
    """The prompt must instruct the model to respond with JSON only."""
    finding = make_finding()
    prompt = _build_prompt(finding)
    assert "JSON" in prompt
