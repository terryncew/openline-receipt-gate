"""Deterministic TEST-ONLY Ed25519 identities for HOME-GUARD-001.

Keys are derived from fixed 32-byte seeds so every run is byte-reproducible.
These keys are fixtures, not credentials. They must never be used to protect
anything real.
"""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import public_key_hex

# Fixed seeds (hex). Labeled TEST ONLY.
_SEEDS = {
    "owner": "a1" * 32,
    "receiver": "b2" * 32,
    "assistant": "c3" * 32,
    "attacker": "d4" * 32,
}


def private_key(name: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(_SEEDS[name]))


def public_key_hex_of(name: str) -> str:
    return public_key_hex(private_key(name).public_key())


def known_identities() -> dict[str, str]:
    """name -> Ed25519 public key hex."""
    return {name: public_key_hex_of(name) for name in _SEEDS}
