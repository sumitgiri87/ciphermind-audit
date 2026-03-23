"""
Data models for cryptographic assets parsed from CBOM JSON.

These are plain dataclasses — no external dependencies, easy to serialize.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DetectionLocation:
    """A single place in source code where a crypto asset was detected."""

    file_path: str
    line_numbers: list[int] = field(default_factory=list)
    additional_context: str = ""

    def __str__(self) -> str:
        """Return a human-readable location string."""
        lines = ", ".join(str(n) for n in self.line_numbers)
        return f"{self.file_path}:{lines}"


@dataclass
class CryptoAsset:
    """
    Normalized representation of a single cryptographic algorithm usage.

    Extracted from a CBOM component with type 'crypto-asset'.
    All fields use lowercase strings for consistent comparison in the rule engine.
    """

    bom_ref: str
    name: str                          # e.g. "MD5", "RSA", "AES"
    primitive: str                     # e.g. "hash", "asymmetric-encryption"
    variant: str                       # e.g. "MD5", "RSA", "AES"
    key_size: Optional[int] = None     # bits, if applicable
    mode: Optional[str] = None         # e.g. "ECB", "GCM", "CBC"
    padding: Optional[str] = None      # e.g. "PKCS1v15", "OAEP"
    curve: Optional[str] = None        # e.g. "P-256", "P-384"
    locations: list[DetectionLocation] = field(default_factory=list)

    def as_dict(self) -> dict:
        """Return a plain dict for JSON serialization."""
        return {
            "bom_ref": self.bom_ref,
            "name": self.name,
            "primitive": self.primitive,
            "variant": self.variant,
            "key_size": self.key_size,
            "mode": self.mode,
            "padding": self.padding,
            "curve": self.curve,
            "locations": [
                {
                    "file_path": loc.file_path,
                    "line_numbers": loc.line_numbers,
                    "additional_context": loc.additional_context,
                }
                for loc in self.locations
            ],
        }
