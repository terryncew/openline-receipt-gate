"""Tamper-evident measurement envelope around an unchanged wallet003 artifact.

The envelope has authority ``NONE``. Its timestamp is measurement evidence only;
the inner wallet003 object remains the sole input to the frozen admission logic.
"""
from __future__ import annotations

from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import olp_canonical_json, sha256_hex, sign_olp_body, verify_olp_signature

SCHEMA = "openline.wallet_transport_measurement_envelope.v1"


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
        "emitted_ns": int(emitted_ns),
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
    if not isinstance(envelope.get("emitted_ns"), int):
        return False, "emitted_ns_invalid"
    return True, None
