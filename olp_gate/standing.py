"""Receiver-owned seam from external standing projections to policy evidence.

The external system reports standing. It does not mutate tool authority.

A receiver explicitly admits a signed projection as the current head for one
support artifact + one exact protected action. At authorization time the gate
checks the externally supplied projection again against that receiver-owned
head. Only then is the projection converted into ordinary permission evidence.

This module deliberately knows nothing about Claim Graph internals.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any, Callable, Mapping

from .authority_link import canonical_hash
from .crypto import verify_olp_signature
from .tool_adapter import EvidenceAssertion, ToolCallContext


STANDING_PROJECTION_SCHEMA = "openline.standing_projection.v1"
_ALLOWED_STANDING = {"ACTIVE", "INACTIVE"}
_ALLOWED_EVENTS = {"ADMIT", "REVOKE", "EXPIRE", "SUPERSEDE", "CORRECT"}
_HEX = frozenset("0123456789abcdef")


class StandingProjectionError(ValueError):
    """Raised when a standing projection cannot be receiver-admitted."""


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise StandingProjectionError("standing_timestamp_invalid")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise StandingProjectionError("standing_timestamp_invalid") from exc
    if parsed.tzinfo is None:
        raise StandingProjectionError("standing_timestamp_timezone_required")
    return parsed.astimezone(timezone.utc)


def _is_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in _HEX for char in value)
    )


def _copy_json(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return json.loads(
            json.dumps(
                dict(value),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        )
    except (TypeError, ValueError) as exc:
        raise StandingProjectionError("standing_projection_json_invalid") from exc


def support_receipt_hash(receipt: Mapping[str, Any]) -> str:
    """Hash the complete support artifact, including its existing signature."""
    if not isinstance(receipt, Mapping):
        raise StandingProjectionError("support_receipt_invalid")
    return canonical_hash(_copy_json(receipt))


def standing_action_hash(
    *,
    tool: str,
    target: str,
    arguments: Mapping[str, Any],
) -> str:
    """Bind standing to one exact protected call, independent of proposal ID."""
    if not isinstance(tool, str) or not tool:
        raise StandingProjectionError("standing_tool_invalid")
    if not isinstance(target, str) or not target:
        raise StandingProjectionError("standing_target_invalid")
    if not isinstance(arguments, Mapping):
        raise StandingProjectionError("standing_arguments_invalid")
    return canonical_hash(
        {
            "tool": tool,
            "target": target,
            "arguments": _copy_json(arguments),
        }
    )


def standing_action_hash_from_call(call: ToolCallContext) -> str:
    return standing_action_hash(
        tool=call.tool,
        target=call.target,
        arguments=call.arguments,
    )


def validate_standing_projection(
    projection: Mapping[str, Any],
    *,
    trusted_issuers: Mapping[str, str],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify shape, signature, pinned issuer, hashes, and projection freshness.

    `verify_olp_signature` proves cryptographic validity. The explicit key pin
    below is what prevents a self-signed agent assertion from becoming standing.
    """
    if not isinstance(projection, Mapping):
        raise StandingProjectionError("standing_projection_invalid")
    item = _copy_json(projection)
    required = {
        "schema",
        "projection_id",
        "issuer_id",
        "support_hash",
        "action_hash",
        "standing",
        "event_type",
        "sequence",
        "predecessor_hash",
        "issued_at",
        "expires_at",
        "payload_hash",
        "signature",
    }
    if set(item) != required:
        raise StandingProjectionError("standing_projection_shape_invalid")
    if item["schema"] != STANDING_PROJECTION_SCHEMA:
        raise StandingProjectionError("standing_projection_schema_invalid")
    for name in ("projection_id", "issuer_id"):
        if not isinstance(item.get(name), str) or not item[name]:
            raise StandingProjectionError(f"standing_{name}_invalid")
    for name in ("support_hash", "action_hash", "payload_hash"):
        if not _is_hash(item.get(name)):
            raise StandingProjectionError(f"standing_{name}_invalid")
    predecessor = item.get("predecessor_hash")
    if predecessor is not None and not _is_hash(predecessor):
        raise StandingProjectionError("standing_predecessor_hash_invalid")
    if item.get("standing") not in _ALLOWED_STANDING:
        raise StandingProjectionError("standing_value_invalid")
    if item.get("event_type") not in _ALLOWED_EVENTS:
        raise StandingProjectionError("standing_event_type_invalid")
    sequence = item.get("sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence <= 0:
        raise StandingProjectionError("standing_sequence_invalid")

    issued_at = _parse_time(item["issued_at"])
    expires_at = _parse_time(item["expires_at"])
    current = now or _utc_now()
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)
    if issued_at > current:
        raise StandingProjectionError("standing_projection_from_future")
    if expires_at <= issued_at:
        raise StandingProjectionError("standing_projection_lifetime_invalid")
    if expires_at <= current:
        raise StandingProjectionError("standing_projection_expired")

    valid, reason = verify_olp_signature(item)
    if valid is not True:
        raise StandingProjectionError(f"standing_signature_invalid:{reason or 'unknown'}")

    issuer_id = item["issuer_id"]
    trusted_key = trusted_issuers.get(issuer_id)
    if trusted_key is None:
        raise StandingProjectionError("standing_issuer_untrusted")
    signature = item.get("signature")
    if not isinstance(signature, Mapping):
        raise StandingProjectionError("standing_signature_shape_invalid")
    observed_key = str(signature.get("public_key", "")).lower()
    if observed_key != str(trusted_key).lower():
        raise StandingProjectionError("standing_issuer_key_mismatch")

    return item


class ReceiverStandingView:
    """Receiver-owned admission state for external standing projections.

    Calling `admit()` is the receiver's policy act. A Claim Graph, database, or
    other upstream system may supply the signed projection, but it cannot move
    this head merely by emitting an event.
    """

    def __init__(self, trusted_issuers: Mapping[str, str]) -> None:
        if not isinstance(trusted_issuers, Mapping) or not trusted_issuers:
            raise StandingProjectionError("standing_trust_store_required")
        normalized: dict[str, str] = {}
        for issuer_id, public_key in trusted_issuers.items():
            if not isinstance(issuer_id, str) or not issuer_id:
                raise StandingProjectionError("standing_trusted_issuer_invalid")
            key = str(public_key).lower()
            if len(key) != 64 or any(char not in _HEX for char in key):
                raise StandingProjectionError("standing_trusted_key_invalid")
            normalized[issuer_id] = key
        self._trusted_issuers = normalized
        self._heads: dict[tuple[str, str], dict[str, Any]] = {}

    def admit(
        self,
        projection: Mapping[str, Any],
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Admit one verified successor as current receiver-recognized standing."""
        checked = validate_standing_projection(
            projection,
            trusted_issuers=self._trusted_issuers,
            now=now,
        )
        key = (checked["support_hash"], checked["action_hash"])
        current = self._heads.get(key)
        if current is None:
            if checked["sequence"] != 1:
                raise StandingProjectionError("standing_initial_sequence_invalid")
            if checked["predecessor_hash"] is not None:
                raise StandingProjectionError("standing_initial_predecessor_forbidden")
        else:
            if checked["sequence"] != current["sequence"] + 1:
                raise StandingProjectionError("standing_successor_sequence_invalid")
            if checked["predecessor_hash"] != current["payload_hash"]:
                raise StandingProjectionError("standing_successor_predecessor_mismatch")
        self._heads[key] = checked
        return {
            "admitted": True,
            "support_hash": checked["support_hash"],
            "action_hash": checked["action_hash"],
            "head_hash": checked["payload_hash"],
            "standing": checked["standing"],
            "event_type": checked["event_type"],
            "sequence": checked["sequence"],
        }

    def head_hash(self, support_hash: str, action_hash: str) -> str | None:
        current = self._heads.get((support_hash, action_hash))
        return None if current is None else str(current["payload_hash"])

    def assess(
        self,
        projection: Mapping[str, Any],
        *,
        support_hash: str,
        action_hash: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Independently assess a supplied projection against the admitted head."""
        reasons: list[str] = []
        try:
            checked = validate_standing_projection(
                projection,
                trusted_issuers=self._trusted_issuers,
                now=now,
            )
        except StandingProjectionError as exc:
            return {
                "verified": False,
                "standing": "UNKNOWN",
                "current": False,
                "reason_codes": [str(exc)],
                "projection_hash": (
                    str(projection.get("payload_hash"))
                    if isinstance(projection, Mapping)
                    else None
                ),
                "support_hash": support_hash,
                "action_hash": action_hash,
            }

        if checked["support_hash"] != support_hash:
            reasons.append("standing_support_mismatch")
        if checked["action_hash"] != action_hash:
            reasons.append("standing_action_mismatch")
        current_head = self.head_hash(support_hash, action_hash)
        if current_head is None:
            reasons.append("standing_head_missing")
        elif checked["payload_hash"] != current_head:
            reasons.append("standing_head_mismatch")

        verified = not reasons
        return {
            "verified": verified,
            "standing": checked["standing"] if verified else "UNKNOWN",
            "current": verified,
            "reason_codes": sorted(set(reasons)),
            "projection_hash": checked["payload_hash"],
            "support_hash": support_hash,
            "action_hash": action_hash,
            "event_type": checked["event_type"],
            "sequence": checked["sequence"],
            "expires_at": checked["expires_at"],
        }


def standing_requirement_source(
    view: ReceiverStandingView,
    *,
    support_source: Callable[[ToolCallContext], Mapping[str, Any] | None],
    projection_source: Callable[[ToolCallContext], Mapping[str, Any] | None],
    action_hash_source: Callable[[ToolCallContext], str] = standing_action_hash_from_call,
    evidence_issuer_id: str = "receiver_standing",
    max_assertion_ttl_seconds: int = 60,
    now_source: Callable[[], datetime] = _utc_now,
) -> Callable[[ToolCallContext], EvidenceAssertion | None]:
    """Adapt current external standing into ordinary policy evidence.

    The returned callback is intended to be placed in the existing
    `evidence_sources` mapping for a normal policy requirement. The permission
    engine remains unchanged.
    """
    if not isinstance(view, ReceiverStandingView):
        raise StandingProjectionError("standing_view_invalid")
    if not callable(support_source) or not callable(projection_source):
        raise StandingProjectionError("standing_source_not_callable")
    if not callable(action_hash_source) or not callable(now_source):
        raise StandingProjectionError("standing_resolver_not_callable")
    if not isinstance(evidence_issuer_id, str) or not evidence_issuer_id:
        raise StandingProjectionError("standing_evidence_issuer_invalid")
    if (
        not isinstance(max_assertion_ttl_seconds, int)
        or isinstance(max_assertion_ttl_seconds, bool)
        or max_assertion_ttl_seconds <= 0
    ):
        raise StandingProjectionError("standing_assertion_ttl_invalid")

    def provide(call: ToolCallContext) -> EvidenceAssertion | None:
        support = support_source(call)
        projection = projection_source(call)
        if support is None or projection is None:
            return None

        support_hash = support_receipt_hash(support)
        action_hash = action_hash_source(call)
        now = now_source()
        if now.tzinfo is None:
            raise StandingProjectionError("standing_now_timezone_required")
        now = now.astimezone(timezone.utc)

        assessment = view.assess(
            projection,
            support_hash=support_hash,
            action_hash=action_hash,
            now=now,
        )
        payload = {
            "standing_projection_hash": assessment.get("projection_hash"),
            "support_hash": support_hash,
            "action_hash": action_hash,
            "standing": assessment.get("standing"),
            "reason_codes": assessment.get("reason_codes", []),
        }

        if not assessment["verified"]:
            return EvidenceAssertion(
                payload=payload,
                issuer_id=evidence_issuer_id,
                expires_in_seconds=1,
                verified=False,
            )

        expires_at = _parse_time(str(assessment["expires_at"]))
        remaining = max(1, int((expires_at - now).total_seconds()))
        ttl = min(max_assertion_ttl_seconds, remaining)
        return EvidenceAssertion(
            payload=payload,
            issuer_id=evidence_issuer_id,
            expires_in_seconds=ttl,
            revoked=assessment["standing"] != "ACTIVE",
            verified=True,
        )

    return provide
