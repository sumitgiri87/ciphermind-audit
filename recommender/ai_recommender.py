"""
AI recommendation layer.

Sends rule findings to a local Ollama instance (or any OpenAI-compatible
endpoint) and returns structured migration guidance per finding.

Design decisions:
- Uses httpx (sync) for simplicity — no async needed at CLI level.
- Prompts are structured to elicit JSON output — no parsing of free text.
- If Ollama is unreachable and --no-ai is not set, we fail loudly.
- The AI never performs crypto operations — recommendations only.
"""

import json
import logging
from dataclasses import dataclass

import httpx

from recommender.rule_engine import RuleFinding

logger = logging.getLogger(__name__)

OLLAMA_DEFAULT_URL = "http://localhost:11434/api/chat"
OLLAMA_DEFAULT_MODEL = "llama3"
REQUEST_TIMEOUT = 60  # seconds


@dataclass
class AIRecommendation:
    """AI-generated migration guidance for a single RuleFinding."""

    rule_id: str
    asset_variant: str
    summary: str                  # 1-2 sentence plain-language summary
    migration_steps: list[str]    # ordered list of concrete actions
    effort_estimate: str          # e.g. "Low", "Medium", "High"
    caveats: list[str]            # edge cases or gotchas to be aware of

    def as_dict(self) -> dict:
        """Return a plain dict for JSON serialization."""
        return {
            "rule_id": self.rule_id,
            "asset_variant": self.asset_variant,
            "summary": self.summary,
            "migration_steps": self.migration_steps,
            "effort_estimate": self.effort_estimate,
            "caveats": self.caveats,
        }


class AIRecommenderError(Exception):
    """Raised when the AI endpoint is unreachable or returns an invalid response."""


def get_recommendations(
    findings: list[RuleFinding],
    model: str = OLLAMA_DEFAULT_MODEL,
    base_url: str = OLLAMA_DEFAULT_URL,
) -> list[AIRecommendation]:
    """
    Generate AI migration recommendations for each finding.

    Sends one request to Ollama per unique (rule_id, variant) pair to
    avoid redundant LLM calls for the same algorithm.

    Raises:
        AIRecommenderError: if Ollama is unreachable.
    """
    seen: set[tuple[str, str]] = set()
    recommendations: list[AIRecommendation] = []

    for finding in findings:
        key = (finding.rule_id, finding.asset.variant)
        if key in seen:
            continue
        seen.add(key)

        logger.debug("Requesting AI recommendation for %s / %s", finding.rule_id, finding.asset.variant)
        rec = _query_ollama(finding, model=model, base_url=base_url)
        recommendations.append(rec)

    return recommendations


def _query_ollama(
    finding: RuleFinding,
    model: str,
    base_url: str,
) -> AIRecommendation:
    """
    Send a single finding to Ollama and parse the structured JSON response.

    Raises:
        AIRecommenderError: on network error or invalid JSON response.
    """
    prompt = _build_prompt(finding)
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "format": "json",
    }

    try:
        response = httpx.post(base_url, json=payload, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except httpx.ConnectError as exc:
        raise AIRecommenderError(
            f"Cannot reach Ollama at {base_url}. "
            "Is Ollama running? Try: ollama serve\n"
            "Or skip AI with: audit analyze <cbom.json> --no-ai"
        ) from exc
    except httpx.HTTPStatusError as exc:
        raise AIRecommenderError(
            f"Ollama returned HTTP {exc.response.status_code}: {exc.response.text}"
        ) from exc

    return _parse_response(response.json(), finding)


def _parse_response(data: dict, finding: RuleFinding) -> AIRecommendation:
    """
    Extract structured fields from Ollama's JSON response.

    Falls back gracefully if the LLM output is missing expected keys.
    """
    try:
        content = data["message"]["content"]
        parsed = json.loads(content)
    except (KeyError, json.JSONDecodeError) as exc:
        raise AIRecommenderError(f"Failed to parse Ollama response: {exc}") from exc

    return AIRecommendation(
        rule_id=finding.rule_id,
        asset_variant=finding.asset.variant,
        summary=parsed.get("summary", "No summary provided."),
        migration_steps=parsed.get("migration_steps", []),
        effort_estimate=parsed.get("effort_estimate", "Unknown"),
        caveats=parsed.get("caveats", []),
    )


def _build_prompt(finding: RuleFinding) -> str:
    """
    Build the structured prompt sent to the LLM.

    Instructs the model to return strict JSON with no markdown wrapping.
    """
    locations_text = "; ".join(
        str(loc) for loc in finding.asset.locations[:3]
    ) or "unknown location"

    return f"""You are a post-quantum cryptography migration expert.

A security audit found the following issue:

Rule: {finding.rule_id} — {finding.rule_name}
Severity: {finding.severity}
Algorithm: {finding.asset.variant} (primitive: {finding.asset.primitive})
Key size: {finding.asset.key_size or 'N/A'}
Mode: {finding.asset.mode or 'N/A'}
Detected at: {locations_text}
Suggested replacements: {', '.join(finding.migration)}

Respond ONLY with a valid JSON object (no markdown, no explanation outside JSON):
{{
  "summary": "<1-2 sentence plain-language summary of why this is a problem>",
  "migration_steps": [
    "<step 1>",
    "<step 2>",
    ...
  ],
  "effort_estimate": "<Low | Medium | High>",
  "caveats": [
    "<any edge case or gotcha to be aware of>"
  ]
}}"""
