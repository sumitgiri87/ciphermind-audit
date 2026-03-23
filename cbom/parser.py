"""
Parser for CBOM JSON produced by cryptobom-forge.

Responsibility: load raw JSON → list[CryptoAsset].
Does NOT normalize values (that's normalizer.py).
"""

import json
from pathlib import Path

from cbom.models import CryptoAsset, DetectionLocation


class CBOMParseError(Exception):
    """Raised when the CBOM JSON is missing required structure."""


def parse_cbom(path: str | Path) -> tuple[str, list[CryptoAsset]]:
    """
    Parse a CBOM JSON file produced by cryptobom-forge.

    Returns:
        (project_name, assets) — project name from metadata, list of raw CryptoAssets.

    Raises:
        CBOMParseError: if the file is invalid or missing required fields.
        FileNotFoundError: if the path does not exist.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"CBOM file not found: {path}")

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CBOMParseError(f"Invalid JSON in {path}: {exc}") from exc

    project_name = _extract_project_name(data)
    assets = _extract_assets(data)
    return project_name, assets


def _extract_project_name(data: dict) -> str:
    """Pull project name from metadata.component.name, fallback to 'unknown'."""
    try:
        return data["metadata"]["component"]["name"]
    except (KeyError, TypeError):
        return "unknown"


def _extract_assets(data: dict) -> list[CryptoAsset]:
    """Extract all crypto-asset components from CBOM components array."""
    components = data.get("components", [])
    if not isinstance(components, list):
        raise CBOMParseError("'components' must be an array")

    assets = []
    for component in components:
        # Only process crypto-asset type entries
        if component.get("type") != "crypto-asset":
            continue

        crypto_props = component.get("cryptoProperties", {})
        if crypto_props.get("assetType") != "algorithm":
            continue

        asset = _parse_component(component, crypto_props)
        if asset:
            assets.append(asset)

    return assets


def _parse_component(component: dict, crypto_props: dict) -> CryptoAsset | None:
    """
    Parse a single CBOM component dict into a CryptoAsset.

    Returns None if essential fields (variant, primitive) are missing.
    """
    algo_props = crypto_props.get("algorithmProperties", {})

    variant = algo_props.get("variant", "")
    primitive = algo_props.get("primitive", "")

    if not variant or not primitive:
        return None

    locations = _parse_locations(crypto_props.get("detectionContext", []))

    return CryptoAsset(
        bom_ref=component.get("bom-ref", ""),
        name=component.get("name", variant),
        primitive=primitive,
        variant=variant,
        key_size=algo_props.get("keySize"),
        mode=algo_props.get("mode"),
        padding=algo_props.get("padding"),
        curve=algo_props.get("curve"),
        locations=locations,
    )


def _parse_locations(detection_context: list) -> list[DetectionLocation]:
    """Parse detectionContext array into DetectionLocation objects."""
    locations = []
    for ctx in detection_context:
        if not isinstance(ctx, dict):
            continue
        locations.append(
            DetectionLocation(
                file_path=ctx.get("filePath", ""),
                line_numbers=ctx.get("lineNumbers", []),
                additional_context=ctx.get("additionalContext", ""),
            )
        )
    return locations
