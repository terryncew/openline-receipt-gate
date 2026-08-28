"""Receiver-pinned quorum recovery used by WALLET-STANDING-002.

The initial wallet root cannot authorize its own replacement after compromise.
Instead, a recovery policy is pinned before the emergency. A threshold of
independent guardian keys may sign one exact succession event. The receiver
verifies that event, advances its local root generation, and rejects every
future action rooted in the superseded key.

This kernel is deliberately single-receiver and single-policy. Distribution,
fork convergence, policy rotation, and threshold-guardian compromise remain
outside the claim.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
import re
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import (
    olp_canonical_json,
    public_key_hex,
    sha256_hex,
    sign_olp_body,
    verify_olp_signature,
)
from wallet001 import AdmissionPolicy, evaluate_bundle


RECOVERY_POLICY_BODY_SCHEMA = "openline.wallet_recovery_policy_body.v1"
RECOVERY_POLICY_SCHEMA = "openline.wallet_recovery_policy.v1"
ROOT_ENDORSEMENT_SCHEMA = "openline.wallet_recovery_root_endorsement.v1"
GUARDIAN_ACCEPTANCE_SCHEMA = "openline.wallet_recovery_guardian_acceptance.v1"
ROOT_SUCCESSION_BODY_SCHEMA = "openline.wallet_root_succession_body.v1"
ROOT_SUCCESSION_APPROVAL_SCHEMA = "openline.wallet_root_succession_approval.v1"
ROOT_SUCCESSION_EVENT_SCHEMA = "openline.wallet_root_succession_event.v1"

_HEX = frozenset("0123456789abcdef")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_REASONS = frozenset({"LOST", "COMPROMISED"})
_EPOCH_CERTIFICATE_SCHEMA = "openline.wallet_epoch_certificate.v1"


class RootRecoveryError(ValueError):
    """Fail-closed recovery error with a stable machine code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class RootHistoryEntry:
    generation: int
    root_public_key: str
    standing: str
    succession_event_hash: str | None = None


@dataclass(frozen=True)
class ReceiverRootView:
    principal_id: str
    recovery_policy_hash: str
    current_root_public_key: str
    current_generation: int
    root_history: tuple[RootHistoryEntry, ...]
    accepted_event_hashes: tuple[str, ...] = ()


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise RootRecoveryError(f"{label}_invalid")
    return value


def _is_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _json_copy(value: Any) -> Any:
    try:
        return json.loads(olp_canonical_json(value).decode("ascii"))
    except (TypeError, ValueError) as exc:
        raise RootRecoveryError("canonical_json_invalid") from exc


def _iso(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise RootRecoveryError("timestamp_timezone_required")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise RootRecoveryError(f"{label}_invalid")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise RootRecoveryError(f"{label}_invalid") from exc
    if parsed.tzinfo is None:
        raise RootRecoveryError(f"{label}_timezone_required")
    return parsed.astimezone(timezone.utc)


def _verify_signature(
    receipt: Mapping[str, Any],
    *,
    expected_schema: str,
    expected_public_key: str,
    label: str,
) -> None:
    if not isinstance(receipt, Mapping) or receipt.get("schema") != expected_schema:
        raise RootRecoveryError(f"{label}_schema_invalid")
    valid, _reason = verify_olp_signature(receipt)
    if valid is not True:
        raise RootRecoveryError(f"{label}_signature_invalid")
    signature = receipt.get("signature")
    if (
        not isinstance(signature, Mapping)
        or str(signature.get("public_key", "")).lower()
        != expected_public_key.lower()
    ):
        raise RootRecoveryError(f"{label}_signer_mismatch")


def create_recovery_policy(
    initial_root_key: Ed25519PrivateKey,
    guardian_keys: Mapping[str, Ed25519PrivateKey],
    *,
    policy_id: str,
    principal_id: str,
    threshold: int,
    issued_at: datetime,
) -> dict[str, Any]:
    """Create the policy that a receiver must pin before root compromise."""
    policy_name = _identifier(policy_id, "policy_id")
    principal = _identifier(principal_id, "principal_id")
    if not isinstance(guardian_keys, Mapping) or not guardian_keys:
        raise RootRecoveryError("guardian_set_invalid")
    if isinstance(threshold, bool) or not isinstance(threshold, int):
        raise RootRecoveryError("recovery_threshold_invalid")

    guardians: list[dict[str, str]] = []
    seen_keys: set[str] = set()
    for raw_guardian_id, guardian_key in sorted(guardian_keys.items()):
        guardian_id = _identifier(raw_guardian_id, "guardian_id")
        guardian_public_key = public_key_hex(guardian_key)
        if guardian_public_key in seen_keys:
            raise RootRecoveryError("guardian_key_duplicate")
        seen_keys.add(guardian_public_key)
        guardians.append(
            {
                "guardian_id": guardian_id,
                "public_key": guardian_public_key,
            }
        )
    if threshold <= 0 or threshold > len(guardians):
        raise RootRecoveryError("recovery_threshold_invalid")

    body = {
        "schema": RECOVERY_POLICY_BODY_SCHEMA,
        "policy_id": policy_name,
        "principal_id": principal,
        "initial_root_public_key": public_key_hex(initial_root_key),
        "threshold": threshold,
        "guardians": guardians,
        "issued_at": _iso(issued_at),
        "rotation": "FROZEN",
    }
    policy_hash = sha256_hex(olp_canonical_json(body))
    root_endorsement = sign_olp_body(
        {
            "schema": ROOT_ENDORSEMENT_SCHEMA,
            "policy_hash": policy_hash,
            "policy_id": policy_name,
            "principal_id": principal,
            "initial_root_public_key": public_key_hex(initial_root_key),
        },
        initial_root_key,
    )
    guardian_acceptances = [
        sign_olp_body(
            {
                "schema": GUARDIAN_ACCEPTANCE_SCHEMA,
                "policy_hash": policy_hash,
                "policy_id": policy_name,
                "principal_id": principal,
                "guardian_id": guardian_id,
            },
            guardian_keys[guardian_id],
        )
        for guardian_id in sorted(guardian_keys)
    ]
    return {
        "schema": RECOVERY_POLICY_SCHEMA,
        "body": _json_copy(body),
        "policy_hash": policy_hash,
        "initial_root_endorsement": _json_copy(root_endorsement),
        "guardian_acceptances": _json_copy(guardian_acceptances),
    }


def verify_recovery_policy(
    policy: Mapping[str, Any],
    *,
    expected_policy_hash: str,
) -> dict[str, Any]:
    """Verify a portable policy only against the receiver's pinned hash."""
    if not _is_hash(expected_policy_hash):
        raise RootRecoveryError("trusted_policy_hash_invalid")
    if not isinstance(policy, Mapping) or set(policy) != {
        "schema",
        "body",
        "policy_hash",
        "initial_root_endorsement",
        "guardian_acceptances",
    }:
        raise RootRecoveryError("recovery_policy_shape_invalid")
    if policy.get("schema") != RECOVERY_POLICY_SCHEMA:
        raise RootRecoveryError("recovery_policy_schema_invalid")
    body = policy.get("body")
    if not isinstance(body, Mapping) or set(body) != {
        "schema",
        "policy_id",
        "principal_id",
        "initial_root_public_key",
        "threshold",
        "guardians",
        "issued_at",
        "rotation",
    }:
        raise RootRecoveryError("recovery_policy_body_shape_invalid")
    if body.get("schema") != RECOVERY_POLICY_BODY_SCHEMA:
        raise RootRecoveryError("recovery_policy_body_schema_invalid")
    if body.get("rotation") != "FROZEN":
        raise RootRecoveryError("recovery_policy_rotation_invalid")
    _identifier(body.get("policy_id"), "policy_id")
    _identifier(body.get("principal_id"), "principal_id")
    if not _is_hash(body.get("initial_root_public_key")):
        raise RootRecoveryError("initial_root_key_invalid")
    _parse_time(body.get("issued_at"), "policy_issued_at")
    computed_hash = sha256_hex(olp_canonical_json(body))
    if policy.get("policy_hash") != computed_hash:
        raise RootRecoveryError("recovery_policy_hash_invalid")
    if computed_hash != expected_policy_hash:
        raise RootRecoveryError("recovery_policy_pin_mismatch")

    guardians = body.get("guardians")
    if not isinstance(guardians, list) or not guardians:
        raise RootRecoveryError("guardian_set_invalid")
    guardian_map: dict[str, str] = {}
    public_keys: set[str] = set()
    for guardian in guardians:
        if not isinstance(guardian, Mapping) or set(guardian) != {
            "guardian_id",
            "public_key",
        }:
            raise RootRecoveryError("guardian_record_invalid")
        guardian_id = _identifier(guardian.get("guardian_id"), "guardian_id")
        public_key = guardian.get("public_key")
        if not _is_hash(public_key):
            raise RootRecoveryError("guardian_public_key_invalid")
        if guardian_id in guardian_map or public_key in public_keys:
            raise RootRecoveryError("guardian_duplicate")
        guardian_map[guardian_id] = str(public_key)
        public_keys.add(str(public_key))
    if list(guardian_map) != sorted(guardian_map):
        raise RootRecoveryError("guardian_order_invalid")
    threshold = body.get("threshold")
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, int)
        or threshold <= 0
        or threshold > len(guardian_map)
    ):
        raise RootRecoveryError("recovery_threshold_invalid")

    root_endorsement = policy.get("initial_root_endorsement")
    if not isinstance(root_endorsement, Mapping) or set(root_endorsement) != {
        "schema",
        "policy_hash",
        "policy_id",
        "principal_id",
        "initial_root_public_key",
        "payload_hash",
        "signature",
    }:
        raise RootRecoveryError("root_endorsement_shape_invalid")
    _verify_signature(
        root_endorsement,
        expected_schema=ROOT_ENDORSEMENT_SCHEMA,
        expected_public_key=str(body["initial_root_public_key"]),
        label="root_endorsement",
    )
    expected_root_body = {
        "schema": ROOT_ENDORSEMENT_SCHEMA,
        "policy_hash": computed_hash,
        "policy_id": body["policy_id"],
        "principal_id": body["principal_id"],
        "initial_root_public_key": body["initial_root_public_key"],
    }
    for key, value in expected_root_body.items():
        if root_endorsement.get(key) != value:
            raise RootRecoveryError("root_endorsement_binding_invalid")

    acceptances = policy.get("guardian_acceptances")
    if not isinstance(acceptances, list):
        raise RootRecoveryError("guardian_acceptances_invalid")
    accepted_ids: set[str] = set()
    for acceptance in acceptances:
        if not isinstance(acceptance, Mapping) or set(acceptance) != {
            "schema",
            "policy_hash",
            "policy_id",
            "principal_id",
            "guardian_id",
            "payload_hash",
            "signature",
        }:
            raise RootRecoveryError("guardian_acceptance_invalid")
        guardian_id = _identifier(acceptance.get("guardian_id"), "guardian_id")
        if guardian_id in accepted_ids:
            raise RootRecoveryError("guardian_acceptance_duplicate")
        if guardian_id not in guardian_map:
            raise RootRecoveryError("guardian_acceptance_unknown")
        _verify_signature(
            acceptance,
            expected_schema=GUARDIAN_ACCEPTANCE_SCHEMA,
            expected_public_key=guardian_map[guardian_id],
            label="guardian_acceptance",
        )
        expected_acceptance = {
            "schema": GUARDIAN_ACCEPTANCE_SCHEMA,
            "policy_hash": computed_hash,
            "policy_id": body["policy_id"],
            "principal_id": body["principal_id"],
            "guardian_id": guardian_id,
        }
        for key, value in expected_acceptance.items():
            if acceptance.get(key) != value:
                raise RootRecoveryError("guardian_acceptance_binding_invalid")
        accepted_ids.add(guardian_id)
    if len(accepted_ids) < threshold:
        raise RootRecoveryError("guardian_acceptance_threshold_not_met")

    return {
        "body": _json_copy(body),
        "policy_hash": computed_hash,
        "guardian_map": guardian_map,
        "threshold": threshold,
    }


def initialize_root_view(
    policy: Mapping[str, Any],
    *,
    trusted_policy_hash: str,
) -> ReceiverRootView:
    """Initialize receiver state from an already pinned recovery policy."""
    verified = verify_recovery_policy(
        policy,
        expected_policy_hash=trusted_policy_hash,
    )
    body = verified["body"]
    root_public_key = str(body["initial_root_public_key"])
    return ReceiverRootView(
        principal_id=str(body["principal_id"]),
        recovery_policy_hash=verified["policy_hash"],
        current_root_public_key=root_public_key,
        current_generation=1,
        root_history=(
            RootHistoryEntry(
                generation=1,
                root_public_key=root_public_key,
                standing="CURRENT",
            ),
        ),
    )


def create_root_succession_event(
    policy: Mapping[str, Any],
    approval_keys: Mapping[str, Ed25519PrivateKey],
    *,
    event_id: str,
    prior_root_public_key: str,
    prior_generation: int,
    successor_root_public_key: str,
    successor_generation: int,
    reason: str,
    effective_at: datetime,
) -> dict[str, Any]:
    """Create an event; acceptance still depends on receiver verification."""
    if not isinstance(policy, Mapping) or not _is_hash(policy.get("policy_hash")):
        raise RootRecoveryError("recovery_policy_invalid")
    body_policy = policy.get("body")
    if not isinstance(body_policy, Mapping):
        raise RootRecoveryError("recovery_policy_invalid")
    event_name = _identifier(event_id, "event_id")
    if not _is_hash(prior_root_public_key) or not _is_hash(successor_root_public_key):
        raise RootRecoveryError("succession_root_key_invalid")
    if prior_root_public_key == successor_root_public_key:
        raise RootRecoveryError("succession_root_unchanged")
    for generation, label in (
        (prior_generation, "prior_generation"),
        (successor_generation, "successor_generation"),
    ):
        if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
            raise RootRecoveryError(f"{label}_invalid")
    if reason not in _REASONS:
        raise RootRecoveryError("succession_reason_invalid")
    body = {
        "schema": ROOT_SUCCESSION_BODY_SCHEMA,
        "event_id": event_name,
        "policy_hash": policy["policy_hash"],
        "principal_id": body_policy["principal_id"],
        "prior_root_public_key": prior_root_public_key,
        "prior_generation": prior_generation,
        "successor_root_public_key": successor_root_public_key,
        "successor_generation": successor_generation,
        "reason": reason,
        "effective_at": _iso(effective_at),
    }
    event_hash = sha256_hex(olp_canonical_json(body))
    approvals = [
        sign_olp_body(
            {
                "schema": ROOT_SUCCESSION_APPROVAL_SCHEMA,
                "policy_hash": policy["policy_hash"],
                "principal_id": body_policy["principal_id"],
                "event_hash": event_hash,
                "guardian_id": guardian_id,
            },
            approval_keys[guardian_id],
        )
        for guardian_id in sorted(approval_keys)
    ]
    return {
        "schema": ROOT_SUCCESSION_EVENT_SCHEMA,
        "body": _json_copy(body),
        "event_hash": event_hash,
        "approvals": _json_copy(approvals),
    }


def _verify_succession_event(
    policy: Mapping[str, Any],
    event: Mapping[str, Any],
    *,
    expected_policy_hash: str,
    now: datetime,
) -> dict[str, Any]:
    verified_policy = verify_recovery_policy(
        policy,
        expected_policy_hash=expected_policy_hash,
    )
    if not isinstance(event, Mapping) or set(event) != {
        "schema",
        "body",
        "event_hash",
        "approvals",
    }:
        raise RootRecoveryError("succession_event_shape_invalid")
    if event.get("schema") != ROOT_SUCCESSION_EVENT_SCHEMA:
        raise RootRecoveryError("succession_event_schema_invalid")
    body = event.get("body")
    if not isinstance(body, Mapping) or set(body) != {
        "schema",
        "event_id",
        "policy_hash",
        "principal_id",
        "prior_root_public_key",
        "prior_generation",
        "successor_root_public_key",
        "successor_generation",
        "reason",
        "effective_at",
    }:
        raise RootRecoveryError("succession_body_shape_invalid")
    if body.get("schema") != ROOT_SUCCESSION_BODY_SCHEMA:
        raise RootRecoveryError("succession_body_schema_invalid")
    _identifier(body.get("event_id"), "event_id")
    if body.get("policy_hash") != expected_policy_hash:
        raise RootRecoveryError("succession_policy_mismatch")
    if body.get("principal_id") != verified_policy["body"]["principal_id"]:
        raise RootRecoveryError("succession_principal_mismatch")
    if not _is_hash(body.get("prior_root_public_key")) or not _is_hash(
        body.get("successor_root_public_key")
    ):
        raise RootRecoveryError("succession_root_key_invalid")
    if body.get("prior_root_public_key") == body.get("successor_root_public_key"):
        raise RootRecoveryError("succession_root_unchanged")
    for field in ("prior_generation", "successor_generation"):
        value = body.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise RootRecoveryError(f"{field}_invalid")
    if body.get("reason") not in _REASONS:
        raise RootRecoveryError("succession_reason_invalid")
    if now.tzinfo is None:
        raise RootRecoveryError("gate_time_timezone_required")
    effective = _parse_time(body.get("effective_at"), "succession_effective_at")
    if effective > now.astimezone(timezone.utc):
        raise RootRecoveryError("succession_not_effective")
    computed_hash = sha256_hex(olp_canonical_json(body))
    if event.get("event_hash") != computed_hash:
        raise RootRecoveryError("succession_event_hash_invalid")

    approvals = event.get("approvals")
    if not isinstance(approvals, list):
        raise RootRecoveryError("succession_approvals_invalid")
    approved_ids: set[str] = set()
    for approval in approvals:
        if not isinstance(approval, Mapping) or set(approval) != {
            "schema",
            "policy_hash",
            "principal_id",
            "event_hash",
            "guardian_id",
            "payload_hash",
            "signature",
        }:
            raise RootRecoveryError("succession_approval_invalid")
        guardian_id = _identifier(approval.get("guardian_id"), "guardian_id")
        if guardian_id in approved_ids:
            raise RootRecoveryError("duplicate_guardian_approval")
        expected_guardian_key = verified_policy["guardian_map"].get(guardian_id)
        if expected_guardian_key is None:
            raise RootRecoveryError("unknown_guardian_approval")
        _verify_signature(
            approval,
            expected_schema=ROOT_SUCCESSION_APPROVAL_SCHEMA,
            expected_public_key=expected_guardian_key,
            label="guardian_approval",
        )
        expected_approval = {
            "schema": ROOT_SUCCESSION_APPROVAL_SCHEMA,
            "policy_hash": expected_policy_hash,
            "principal_id": body["principal_id"],
            "event_hash": computed_hash,
            "guardian_id": guardian_id,
        }
        for key, value in expected_approval.items():
            if approval.get(key) != value:
                raise RootRecoveryError("guardian_approval_binding_invalid")
        approved_ids.add(guardian_id)
    if len(approved_ids) < verified_policy["threshold"]:
        raise RootRecoveryError("recovery_threshold_not_met")
    return {
        "body": _json_copy(body),
        "event_hash": computed_hash,
        "approved_guardian_ids": sorted(approved_ids),
        "threshold": verified_policy["threshold"],
    }


def _accept_root_succession(
    view: ReceiverRootView,
    policy: Mapping[str, Any],
    event: Mapping[str, Any],
    *,
    now: datetime,
) -> tuple[ReceiverRootView, dict[str, Any]]:
    if not isinstance(view, ReceiverRootView):
        raise RootRecoveryError("receiver_root_view_required")
    verified = _verify_succession_event(
        policy,
        event,
        expected_policy_hash=view.recovery_policy_hash,
        now=now,
    )
    body = verified["body"]
    event_hash = verified["event_hash"]
    if event_hash in view.accepted_event_hashes:
        raise RootRecoveryError("succession_replayed")
    if body["principal_id"] != view.principal_id:
        raise RootRecoveryError("root_view_principal_mismatch")
    if body["prior_generation"] != view.current_generation:
        raise RootRecoveryError("prior_generation_mismatch")
    if body["prior_root_public_key"] != view.current_root_public_key:
        raise RootRecoveryError("prior_root_mismatch")
    if body["successor_generation"] != view.current_generation + 1:
        raise RootRecoveryError("successor_generation_invalid")
    prior_roots = {entry.root_public_key for entry in view.root_history}
    if body["successor_root_public_key"] in prior_roots:
        raise RootRecoveryError("root_rollback_forbidden")

    updated_history = tuple(
        replace(
            entry,
            standing="SUPERSEDED",
            succession_event_hash=event_hash,
        )
        if entry.generation == view.current_generation
        else entry
        for entry in view.root_history
    ) + (
        RootHistoryEntry(
            generation=body["successor_generation"],
            root_public_key=body["successor_root_public_key"],
            standing="CURRENT",
        ),
    )
    next_view = ReceiverRootView(
        principal_id=view.principal_id,
        recovery_policy_hash=view.recovery_policy_hash,
        current_root_public_key=body["successor_root_public_key"],
        current_generation=body["successor_generation"],
        root_history=updated_history,
        accepted_event_hashes=view.accepted_event_hashes + (event_hash,),
    )
    receipt = {
        "decision": "ACCEPT_SUCCESSION",
        "accepted": True,
        "reason_codes": [],
        "state_delta": 1,
        "event_hash": event_hash,
        "prior_generation": view.current_generation,
        "successor_generation": next_view.current_generation,
        "approved_guardian_ids": verified["approved_guardian_ids"],
        "threshold": verified["threshold"],
        "wallet_policy_authority": "NONE",
        "succession_authority": "PRECOMMITTED_GUARDIAN_QUORUM",
        "decision_authority": "RECEIVER_GATE",
    }
    return next_view, receipt


def accept_root_succession(
    view: ReceiverRootView,
    policy: Mapping[str, Any],
    event: Mapping[str, Any],
    *,
    now: datetime,
) -> tuple[ReceiverRootView, dict[str, Any]]:
    """Fail closed while keeping the receiver's root view unchanged on error."""
    try:
        return _accept_root_succession(view, policy, event, now=now)
    except RootRecoveryError as exc:
        return view, {
            "decision": "REJECT_SUCCESSION",
            "accepted": False,
            "reason_codes": [exc.code.upper()],
            "state_delta": 0,
            "wallet_policy_authority": "NONE",
            "succession_authority": "PRECOMMITTED_GUARDIAN_QUORUM",
            "decision_authority": "RECEIVER_GATE",
        }
    except Exception:
        return view, {
            "decision": "REJECT_SUCCESSION",
            "accepted": False,
            "reason_codes": ["ROOT_RECOVERY_VERIFICATION_ERROR"],
            "state_delta": 0,
            "wallet_policy_authority": "NONE",
            "succession_authority": "PRECOMMITTED_GUARDIAN_QUORUM",
            "decision_authority": "RECEIVER_GATE",
        }


def evaluate_current_root_bundle(
    view: ReceiverRootView,
    bundle: Mapping[str, Any],
    *,
    expected_action: Mapping[str, Any],
    receiver_challenge: str,
    now: datetime,
    policy: AdmissionPolicy,
) -> dict[str, Any]:
    """Evaluate a WALLET-001 bundle against the receiver's current root only."""
    certificate = bundle.get("epoch_certificate") if isinstance(bundle, Mapping) else None
    if not isinstance(certificate, Mapping) or certificate.get("principal_id") != view.principal_id:
        return {
            "decision": "BLOCK",
            "reason_codes": ["ROOT_VIEW_PRINCIPAL_MISMATCH"],
            "executed": False,
            "effect_delta": 0,
            "wallet_policy_authority": "NONE",
            "decision_authority": "RECEIVER_GATE",
            "root_generation": view.current_generation,
            "recovery_policy_hash": view.recovery_policy_hash,
        }
    result = evaluate_bundle(
        bundle,
        trusted_root_public_key=view.current_root_public_key,
        expected_action=expected_action,
        receiver_challenge=receiver_challenge,
        now=now,
        policy=policy,
    )
    return {
        **result,
        "root_generation": view.current_generation,
        "recovery_policy_hash": view.recovery_policy_hash,
    }


def verify_historical_epoch_certificate(
    view: ReceiverRootView,
    certificate: Mapping[str, Any],
) -> dict[str, Any]:
    """Preserve authenticity without restoring current execution standing."""
    try:
        if not isinstance(certificate, Mapping):
            raise RootRecoveryError("historical_certificate_invalid")
        if certificate.get("schema") != _EPOCH_CERTIFICATE_SCHEMA:
            raise RootRecoveryError("historical_certificate_schema_invalid")
        if set(certificate) != {
            "schema",
            "principal_id",
            "epoch_id",
            "sequence",
            "branch",
            "epoch_public_key",
            "predecessor_epoch_id",
            "issued_at",
            "expires_at",
            "payload_hash",
            "signature",
        }:
            raise RootRecoveryError("historical_certificate_shape_invalid")
        _identifier(certificate.get("epoch_id"), "historical_epoch_id")
        _identifier(certificate.get("branch"), "historical_epoch_branch")
        sequence = certificate.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
            raise RootRecoveryError("historical_epoch_sequence_invalid")
        if not _is_hash(certificate.get("epoch_public_key")):
            raise RootRecoveryError("historical_epoch_key_invalid")
        _parse_time(certificate.get("issued_at"), "historical_issued_at")
        _parse_time(certificate.get("expires_at"), "historical_expires_at")
        if certificate.get("principal_id") != view.principal_id:
            raise RootRecoveryError("historical_principal_mismatch")
        valid, _reason = verify_olp_signature(certificate)
        if valid is not True:
            raise RootRecoveryError("historical_signature_invalid")
        signature = certificate.get("signature")
        if not isinstance(signature, Mapping):
            raise RootRecoveryError("historical_signature_invalid")
        signer = str(signature.get("public_key", "")).lower()
        entry = next(
            (
                candidate
                for candidate in view.root_history
                if candidate.root_public_key.lower() == signer
            ),
            None,
        )
        if entry is None:
            raise RootRecoveryError("historical_root_unrecognized")
        status = (
            "CURRENT"
            if entry.standing == "CURRENT"
            else "HISTORICALLY_AUTHENTIC_NONCURRENT"
        )
        return {
            "verification": "PASS",
            "status": status,
            "root_generation": entry.generation,
            "execution_authority": "NONE" if status != "CURRENT" else "UNASSESSED",
            "cryptographically_authentic": True,
        }
    except RootRecoveryError as exc:
        return {
            "verification": "FAIL",
            "status": "UNVERIFIED",
            "reason_codes": [exc.code.upper()],
            "execution_authority": "NONE",
            "cryptographically_authentic": False,
        }
    except Exception:
        return {
            "verification": "FAIL",
            "status": "UNVERIFIED",
            "reason_codes": ["HISTORICAL_VERIFICATION_ERROR"],
            "execution_authority": "NONE",
            "cryptographically_authentic": False,
        }
