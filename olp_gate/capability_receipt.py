"""Pinned draft-06 root capability receipt profile.

Implements the narrow profile frozen in BOUND-AUTHORITY-ADOPT-001 against
``draft-schrock-ep-bounded-capability-receipts-06``: root semantics only.
``parent`` is always null, ``revocation_mode`` is fixed ``direct``,
threshold is fixed m=1/n=1, no epochs, no delegation, no conformance claim.

Cryptographic primitives are reused from :mod:`olp_gate.crypto`
(``olp_canonical_json`` is the integer-canonical JSON profile: the receipt
has no float fields, so full RFC 8785 is not required; a future float
field would need a full JCS backend).

Trust rule (§3 of the draft, ``mandate_owner.py:15``): a key embedded in
the receipt MUST NOT become a trust anchor by itself. Verification
additionally requires the embedded key to equal the receiver-pinned key.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from .crypto import olp_canonical_json, sha256_hex, verify_olp_signature

RECEIPT_VERSION = "EP-BOUNDED-CAPABILITY-v1"
SCOPE_PROFILE = "principal-mandates-v1"
HOLDER_METHOD = "receiver-held-v1"

_BODY_KEYS = frozenset({
    "@version", "capability_id", "issuer_owner_id", "issuer_public_key",
    "subject", "budget", "scope", "holder", "expires_at", "parent",
    "revocation_mode", "threshold",
})
_HEX = frozenset("0123456789abcdef")


class CapabilityReceiptError(ValueError):
    """Raised when a capability receipt fails profile verification."""


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise CapabilityReceiptError("receipt_expires_at_invalid")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise CapabilityReceiptError("receipt_expires_at_invalid") from exc
    if parsed.tzinfo is None:
        raise CapabilityReceiptError("receipt_expires_at_timezone_required")
    return parsed.astimezone(timezone.utc)


def receipt_digest(receipt: Mapping[str, Any]) -> str:
    """SHA-256 over the JCS-serialized full receipt, signature included."""
    return sha256_hex(olp_canonical_json(dict(receipt)))


def verify_capability_receipt(
    receipt: Mapping[str, Any],
    pinned_owner_id: str,
    pinned_pubkey_hex: str,
) -> dict[str, Any]:
    """Verify a receipt against the pinned -06 narrow profile.

    Returns the parsed capability fields plus ``receipt_digest``.
    Raises :class:`CapabilityReceiptError` on any failure (fail-closed).
    """
    if not isinstance(receipt, Mapping):
        raise CapabilityReceiptError("receipt_not_a_mapping")
    body = dict(receipt)
    if set(body) - {"signature", "payload_hash"} != _BODY_KEYS:
        raise CapabilityReceiptError("receipt_shape_invalid")
    if body.get("@version") != RECEIPT_VERSION:
        raise CapabilityReceiptError("receipt_version_unsupported")
    if body.get("parent") is not None:
        raise CapabilityReceiptError("receipt_delegation_not_supported")
    if body.get("revocation_mode") != "direct":
        raise CapabilityReceiptError("receipt_revocation_mode_unsupported")
    if body.get("threshold") != {"m": 1, "n": 1}:
        raise CapabilityReceiptError("receipt_threshold_unsupported")
    if body.get("scope") != {"profile": SCOPE_PROFILE}:
        raise CapabilityReceiptError("receipt_scope_profile_unsupported")
    if body.get("holder") != {"method": HOLDER_METHOD}:
        raise CapabilityReceiptError("receipt_holder_method_unsupported")
    budget = body.get("budget")
    if not isinstance(budget, Mapping) or set(budget) != {"amount", "unit", "scale"}:
        raise CapabilityReceiptError("receipt_budget_invalid")
    amount, unit, scale = budget["amount"], budget["unit"], budget["scale"]
    if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
        raise CapabilityReceiptError("receipt_budget_amount_invalid")
    if not isinstance(unit, str) or not unit:
        raise CapabilityReceiptError("receipt_budget_unit_invalid")
    if not isinstance(scale, int) or isinstance(scale, bool) or scale < 0:
        raise CapabilityReceiptError("receipt_budget_scale_invalid")
    for name in ("capability_id", "issuer_owner_id", "issuer_public_key", "subject"):
        if not isinstance(body.get(name), str) or not body[name]:
            raise CapabilityReceiptError(f"receipt_{name}_invalid")
    if body["issuer_owner_id"] != pinned_owner_id:
        raise CapabilityReceiptError("receipt_issuer_not_pinned")
    key = str(body["issuer_public_key"]).lower()
    if len(key) != 64 or any(c not in _HEX for c in key):
        raise CapabilityReceiptError("receipt_issuer_key_invalid")
    _parse_time(body["expires_at"])
    ok, reason = verify_olp_signature(receipt)
    if not ok:
        raise CapabilityReceiptError(f"receipt_signature_invalid:{reason}")
    embedded = str(receipt["signature"]["public_key"]).lower()
    if embedded != pinned_pubkey_hex.lower():
        # §3: an embedded key is not a trust anchor by itself.
        raise CapabilityReceiptError("receipt_key_not_pinned")
    return {
        "capability_id": body["capability_id"],
        "issuer_owner_id": body["issuer_owner_id"],
        "issuer_public_key": key,
        "subject": body["subject"],
        "amount": amount,
        "unit": unit,
        "scale": scale,
        "scope_profile": SCOPE_PROFILE,
        "holder_method": HOLDER_METHOD,
        "expires_at": body["expires_at"],
        "receipt_digest": receipt_digest(receipt),
        "receipt_json": olp_canonical_json(dict(receipt)).decode("utf-8"),
    }
