"""
Tests for cbom/parser.py

Verifies that parse_cbom correctly extracts CryptoAssets from the sample
CBOM JSON produced by cryptobom-forge.
"""

import json
import tempfile
from pathlib import Path

import pytest

from cbom.parser import parse_cbom, CBOMParseError
from cbom.models import CryptoAsset

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SAMPLE_CBOM = FIXTURES_DIR / "sample_cbom.json"


def test_parse_sample_cbom_returns_correct_count():
    """sample_cbom.json has 10 crypto-asset components — all should be parsed."""
    project_name, assets = parse_cbom(SAMPLE_CBOM)
    assert len(assets) == 10


def test_parse_sample_cbom_project_name():
    """Project name should be extracted from metadata.component.name."""
    project_name, _ = parse_cbom(SAMPLE_CBOM)
    assert project_name == "my-python-app"


def test_parse_sample_cbom_md5_asset():
    """MD5 asset should have correct primitive, variant, and locations."""
    _, assets = parse_cbom(SAMPLE_CBOM)
    md5 = next((a for a in assets if a.variant == "MD5"), None)
    assert md5 is not None
    assert md5.primitive == "hash"
    assert len(md5.locations) == 2
    assert md5.locations[0].file_path == "app/utils/avatar.py"
    assert 12 in md5.locations[0].line_numbers


def test_parse_sample_cbom_rsa_key_size():
    """RSA assets should carry key_size values."""
    _, assets = parse_cbom(SAMPLE_CBOM)
    rsa_assets = [a for a in assets if a.variant == "RSA"]
    key_sizes = {a.key_size for a in rsa_assets}
    assert 2048 in key_sizes
    assert 1024 in key_sizes


def test_parse_sample_cbom_aes_mode():
    """AES assets should carry mode values (ECB and GCM)."""
    _, assets = parse_cbom(SAMPLE_CBOM)
    aes_assets = [a for a in assets if a.name == "AES"]
    modes = {a.mode for a in aes_assets}
    assert "ECB" in modes
    assert "GCM" in modes


def test_parse_cbom_missing_file_raises():
    """FileNotFoundError should be raised for a nonexistent path."""
    with pytest.raises(FileNotFoundError):
        parse_cbom("/tmp/this_does_not_exist.json")


def test_parse_cbom_invalid_json_raises():
    """CBOMParseError should be raised for malformed JSON."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("this is not json {{{")
        bad_path = f.name

    with pytest.raises(CBOMParseError, match="Invalid JSON"):
        parse_cbom(bad_path)


def test_parse_cbom_empty_components():
    """A CBOM with no components should return empty list, not raise."""
    data = {
        "bomFormat": "CBOM",
        "components": [],
        "metadata": {"component": {"name": "empty-project"}},
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = f.name

    project_name, assets = parse_cbom(path)
    assert project_name == "empty-project"
    assert assets == []


def test_parse_cbom_missing_metadata_uses_unknown():
    """When metadata is absent, project name should fall back to 'unknown'."""
    data = {"components": []}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = f.name

    project_name, _ = parse_cbom(path)
    assert project_name == "unknown"


def test_parse_cbom_non_crypto_asset_skipped():
    """Components with type != 'crypto-asset' should be ignored."""
    data = {
        "components": [
            {
                "bom-ref": "lib:requests",
                "type": "library",
                "name": "requests",
            }
        ],
        "metadata": {"component": {"name": "test"}},
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        path = f.name

    _, assets = parse_cbom(path)
    assert assets == []


def test_parse_cbom_detection_context_additional_context():
    """additionalContext field should be preserved in DetectionLocation."""
    _, assets = parse_cbom(SAMPLE_CBOM)
    sha1 = next((a for a in assets if a.variant == "SHA1"), None)
    assert sha1 is not None
    assert sha1.locations[0].additional_context != ""
