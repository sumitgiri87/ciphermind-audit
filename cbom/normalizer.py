"""
Normalizer for CryptoAsset fields.

cryptobom-forge can produce variant strings in different casings or aliases
(e.g. "Sha256", "sha-256", "SHA256"). This module canonicalizes them so the
rule engine can compare against a single known form.

Design: pure functions operating on CryptoAsset — no mutation of originals.
"""

from cbom.models import CryptoAsset

# Maps raw variant strings (uppercase) → canonical form used in rules
VARIANT_ALIASES: dict[str, str] = {
    # Hashes
    "MD5": "MD5",
    "MD-5": "MD5",
    "SHA1": "SHA1",
    "SHA-1": "SHA1",
    "SHA256": "SHA256",
    "SHA-256": "SHA256",
    "SHA2-256": "SHA256",
    "SHA384": "SHA384",
    "SHA-384": "SHA384",
    "SHA512": "SHA512",
    "SHA-512": "SHA512",
    "SHA3-256": "SHA3-256",
    "SHA3-512": "SHA3-512",
    # Symmetric
    "AES": "AES",
    "3DES": "3DES",
    "TRIPLE-DES": "3DES",
    "TRIPLEDES": "3DES",
    "DES3": "3DES",
    "RC4": "RC4",
    "ARC4": "RC4",
    "ARCFOUR": "RC4",
    # Asymmetric
    "RSA": "RSA",
    "ECDSA": "ECDSA",
    "ECDH": "ECDH",
    "DSA": "DSA",
    "DH": "DH",
    "DIFFIEHELLMAN": "DH",
    # PQC
    "KYBER": "ML-KEM",
    "ML-KEM": "ML-KEM",
    "MLKEM": "ML-KEM",
    "DILITHIUM": "ML-DSA",
    "ML-DSA": "ML-DSA",
    "MLDSA": "ML-DSA",
    "SPHINCS+": "SLH-DSA",
    "SLH-DSA": "SLH-DSA",
    "SLHDSA": "SLH-DSA",
    "FALCON": "FN-DSA",
    "FN-DSA": "FN-DSA",
    "FNDSA": "FN-DSA",
}

# Maps raw primitive strings → canonical form
PRIMITIVE_ALIASES: dict[str, str] = {
    "hash": "hash",
    "digest": "hash",
    "block-cipher": "block-cipher",
    "blockcipher": "block-cipher",
    "stream-cipher": "stream-cipher",
    "streamcipher": "stream-cipher",
    "asymmetric-encryption": "asymmetric-encryption",
    "signature": "signature",
    "key-agreement": "key-agreement",
    "keyagreement": "key-agreement",
    "mac": "mac",
    "kdf": "kdf",
    "xof": "xof",
}


def normalize_asset(asset: CryptoAsset) -> CryptoAsset:
    """
    Return a new CryptoAsset with variant and primitive canonicalized.

    Does not mutate the input. All string fields are lowered for canonical
    comparison except variant/name which keep their uppercase canonical form.
    """
    canonical_variant = _normalize_variant(asset.variant)
    canonical_primitive = _normalize_primitive(asset.primitive)
    canonical_mode = asset.mode.upper() if asset.mode else None
    canonical_padding = asset.padding.upper() if asset.padding else None

    return CryptoAsset(
        bom_ref=asset.bom_ref,
        name=asset.name,
        primitive=canonical_primitive,
        variant=canonical_variant,
        key_size=asset.key_size,
        mode=canonical_mode,
        padding=canonical_padding,
        curve=asset.curve,
        locations=asset.locations,
    )


def normalize_assets(assets: list[CryptoAsset]) -> list[CryptoAsset]:
    """Normalize a list of CryptoAssets. Convenience wrapper."""
    return [normalize_asset(a) for a in assets]


def _normalize_variant(raw: str) -> str:
    """Map raw variant string to canonical form. Fallback: uppercase of raw."""
    key = raw.upper().replace(" ", "").replace("_", "-")
    return VARIANT_ALIASES.get(key, raw.upper())


def _normalize_primitive(raw: str) -> str:
    """Map raw primitive string to canonical form. Fallback: lowercase of raw."""
    key = raw.lower().replace(" ", "").replace("_", "-")
    return PRIMITIVE_ALIASES.get(key, raw.lower())
