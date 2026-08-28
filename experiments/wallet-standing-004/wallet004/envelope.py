"""Tamper-evident measurement envelope around an unchanged wallet003 artifact.

The envelope has authority ``NONE``. Its timestamp is measurement evidence only;
the inner wallet003 object remains the sole input to the frozen admission logic.
"""
from __future__ import annotations

from typing import Any, Mapping

_MAX_SIGNED_64 = (1 << 63) - 1

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import olp_canonical_json, sha256_hex, sign_olp_body, verify_olp_signature

SCHEMA = "openline.wallet_transport_measurement_envelope.v1"


def _encode_emitted_ns(value: int) -> str:
    """Encode epoch nanoseconds without violating OLP's 2^53-1 integer ceiling."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError("emitted_ns_must_be_int")
    if value < 0 or value > _MAX_SIGNED_64:
        raise ValueError("emitted_ns_out_of_range")
    return str(value)


def _decode_emitted_ns(value: Any) -> int | None:
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdigit():
        return None
    if len(value) > 1 and value.startswith("0"):
        return None
    parsed = int(value)
    if parsed > _MAX_SIGNED_64:
        return None
    return parsed


def create_envelope(
    payload: Mapping[str, Any],
    *,
    kind: str,
    emitted_ns: int,
    measurement_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    inner = dict(payload)
    inner_hash = sha256_hex(olp_canonical_json(inner))
    body = {
        "schema": SCHEMA,
        "kind": str(kind),
        "inner_hash": inner_hash,
        # Unix epoch nanoseconds are ~1e18, above OLP's interoperable integer
        # ceiling. Keep the exact value as canonical decimal text. This field is
        # measurement-only and is parsed back only after envelope verification.
        "emitted_ns": _encode_emitted_ns(emitted_ns),
        "measurement_authority": "NONE",
        "inner": inner,
    }
    return sign_olp_body(body, measurement_key)


def verify_envelope(envelope: Mapping[str, Any], *, measurement_public_key: str) -> tuple[bool, str | None]:
    if not isinstance(envelope, Mapping) or envelope.get("schema") != SCHEMA:
        return False, "envelope_schema_invalid"
    if envelope.get("measurement_authority") != "NONE":
        return False, "envelope_authority_invalid"
    valid, reason = verify_olp_signature(envelope)
    if valid is not True:
        return False, reason or "envelope_signature_invalid"
    sig = envelope.get("signature")
    if not isinstance(sig, Mapping) or str(sig.get("public_key", "")).lower() != measurement_public_key.lower():
        return False, "measurement_signer_mismatch"
    inner = envelope.get("inner")
    if not isinstance(inner, Mapping):
        return False, "inner_invalid"
    if envelope.get("inner_hash") != sha256_hex(olp_canonical_json(inner)):
        return False, "inner_hash_mismatch"
    if _decode_emitted_ns(envelope.get("emitted_ns")) is None:
        return False, "emitted_ns_invalid"
    return True, None
