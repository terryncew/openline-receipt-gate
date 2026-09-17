"""Issuance authorization for bounded capabilities (draft §5).

The issuance authorization is an independently verified artifact for the
exact act of creating a capability: exact-act, digest-bound, one-time
consumed. It is verified against the same receiver-pinned issuer key as
the receipt, and its digest must match the ``issuance_auth_digest`` bound
into the receipt. Creating budget and spending budget are different
authentications; this artifact can never authorize consumption.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .crypto import olp_canonical_json, sha256_hex, sign_olp_body, verify_olp_signature

ISSUANCE_SCHEMA = "openline.capability_issuance_authorization.v1"
_AUTH_KEYS = frozenset({
    "schema", "capability_id", "receipt_digest", "issuer_owner_id", "issued_at",
})


class IssuanceError(ValueError):
    """Raised when an issuance authorization fails verification."""


def make_issuance_auth(
    capability_id: str,
    receipt_digest: str,
    issuer_owner_id: str,
    issuer_key: Ed25519PrivateKey,
    issued_at: datetime,
) -> dict[str, Any]:
    """Create (owner-side helper) the signed issuance authorization."""
    if issued_at.tzinfo is None:
        raise IssuanceError("issuance_timestamp_timezone_required")
    body = {
        "schema": ISSUANCE_SCHEMA,
        "capability_id": capability_id,
        "receipt_digest": receipt_digest,
        "issuer_owner_id": issuer_owner_id,
        "issued_at": issued_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    return sign_olp_body(body, issuer_key)


def issuance_auth_digest(auth: Mapping[str, Any]) -> str:
    return sha256_hex(olp_canonical_json(dict(auth)))


def verify_issuance_auth(
    auth: Mapping[str, Any],
    *,
    capability_id: str,
    receipt_digest: str,
    pinned_owner_id: str,
    pinned_pubkey_hex: str,
) -> str:
    """Verify the issuance authorization; returns its digest.

    Raises :class:`IssuanceError` on any failure (fail-closed).
    """
    if not isinstance(auth, Mapping):
        raise IssuanceError("issuance_not_a_mapping")
    body = dict(auth)
    if set(body) - {"signature", "payload_hash"} != _AUTH_KEYS:
        raise IssuanceError("issuance_shape_invalid")
    if body.get("schema") != ISSUANCE_SCHEMA:
        raise IssuanceError("issuance_schema_invalid")
    if body.get("capability_id") != capability_id:
        raise IssuanceError("issuance_capability_mismatch")
    if body.get("receipt_digest") != receipt_digest:
        raise IssuanceError("issuance_receipt_binding_mismatch")
    if body.get("issuer_owner_id") != pinned_owner_id:
        raise IssuanceError("issuance_issuer_not_pinned")
    ok, reason = verify_olp_signature(auth)
    if not ok:
        raise IssuanceError(f"issuance_signature_invalid:{reason}")
    if str(auth["signature"]["public_key"]).lower() != pinned_pubkey_hex.lower():
        raise IssuanceError("issuance_key_not_pinned")
    return issuance_auth_digest(auth)
