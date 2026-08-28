"""Controlled event-distribution kernel for WALLET-STANDING-003.

One precommitted guardian may temporarily reduce authority at a receiver. That
freeze is nonrenewable for the current root generation and expires after the
receiver's fixed ceiling. A guardian quorum is still required to install a new
root. Virgin receivers require a fresh quorum checkpoint before high-risk use.

The kernel deliberately does not invent global ordering. If two valid quorum
successions from the same prior generation are observed, the receiver records
the fork and quarantines execution. Before cross-delivery, partitioned receivers
can temporarily follow different valid branches.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
import re
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import (
    olp_canonical_json,
    sha256_hex,
    sign_olp_body,
    verify_olp_signature,
)
from wallet001 import AdmissionPolicy
from wallet002 import (
    ReceiverRootView,
    RootHistoryEntry,
    accept_root_succession,
    evaluate_current_root_bundle,
    initialize_root_view,
    verify_recovery_policy,
)


GUARDIAN_FREEZE_SCHEMA = "openline.wallet_guardian_freeze.v1"
ROOT_CHECKPOINT_BODY_SCHEMA = "openline.wallet_root_checkpoint_body.v1"
ROOT_CHECKPOINT_APPROVAL_SCHEMA = "openline.wallet_root_checkpoint_approval.v1"
ROOT_CHECKPOINT_SCHEMA = "openline.wallet_root_checkpoint.v1"

_HEX = frozenset("0123456789abcdef")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_FREEZE_REASONS = frozenset(
    {"SUSPECTED_COMPROMISE", "DEVICE_LOSS", "MANUAL_EMERGENCY"}
)


class DistributionProtocolError(ValueError):
    """Fail-closed distribution error with a stable reason code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ActiveFreeze:
    event_hash: str
    guardian_id: str
    root_generation: int
    issued_at: str
    expires_at: str


@dataclass(frozen=True)
class SuccessionRecord:
    event_hash: str
    prior_generation: int
    successor_generation: int
    successor_root_public_key: str


@dataclass(frozen=True)
class RootCheckpoint:
    checkpoint_hash: str
    root_generation: int
    root_public_key: str
    issued_at: str
    expires_at: str


@dataclass(frozen=True)
class DistributedGateState:
    gate_id: str
    root_view: ReceiverRootView
    requires_checkpoint: bool
    active_freeze: ActiveFreeze | None = None
    used_freeze_generations: tuple[int, ...] = ()
    seen_freeze_hashes: tuple[str, ...] = ()
    succession_records: tuple[SuccessionRecord, ...] = ()
    checkpoint: RootCheckpoint | None = None
    fork_event_hashes: tuple[str, ...] = ()

    @property
    def fork_quarantined(self) -> bool:
        return bool(self.fork_event_hashes)


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise DistributionProtocolError(f"{label}_invalid")
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
        raise DistributionProtocolError("canonical_json_invalid") from exc


def _iso(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise DistributionProtocolError("timestamp_timezone_required")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise DistributionProtocolError(f"{label}_invalid")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise DistributionProtocolError(f"{label}_invalid") from exc
    if parsed.tzinfo is None:
        raise DistributionProtocolError(f"{label}_timezone_required")
    return parsed.astimezone(timezone.utc)


def _seconds(delta) -> int:
    return int(delta.total_seconds())


def _authority_receipt(**values: Any) -> dict[str, Any]:
    return {
        **values,
        "wallet_policy_authority": "NONE",
        "freeze_authority": "ONE_PRECOMMITTED_GUARDIAN_REDUCE_ONLY",
        "succession_authority": "PRECOMMITTED_GUARDIAN_QUORUM",
        "decision_authority": "RECEIVER_GATE",
    }


def _reject(
    state: DistributedGateState,
    decision: str,
    reason: str,
) -> tuple[DistributedGateState, dict[str, Any]]:
    return state, _authority_receipt(
        decision=decision,
        accepted=False,
        reason_codes=[reason.upper()],
        state_delta=0,
    )


def initialize_distributed_gate(
    recovery_policy: Mapping[str, Any],
    *,
    trusted_policy_hash: str,
    gate_id: str,
    requires_checkpoint: bool = False,
) -> DistributedGateState:
    """Initialize independent receiver state from the same pinned policy."""
    return DistributedGateState(
        gate_id=_identifier(gate_id, "gate_id"),
        root_view=initialize_root_view(
            recovery_policy,
            trusted_policy_hash=trusted_policy_hash,
        ),
        requires_checkpoint=bool(requires_checkpoint),
    )


def create_guardian_freeze(
    recovery_policy: Mapping[str, Any],
    guardian_key: Ed25519PrivateKey,
    root_view: ReceiverRootView,
    *,
    event_id: str,
    guardian_id: str,
    reason: str,
    issued_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Create a reduce-only alert; the receiver owns its acceptance limits."""
    if not isinstance(recovery_policy, Mapping) or not _is_hash(
        recovery_policy.get("policy_hash")
    ):
        raise DistributionProtocolError("recovery_policy_invalid")
    if reason not in _FREEZE_REASONS:
        raise DistributionProtocolError("freeze_reason_invalid")
    issued = _parse_time(_iso(issued_at), "freeze_issued_at")
    expires = _parse_time(_iso(expires_at), "freeze_expires_at")
    if expires <= issued:
        raise DistributionProtocolError("freeze_lifetime_invalid")
    return sign_olp_body(
        {
            "schema": GUARDIAN_FREEZE_SCHEMA,
            "event_id": _identifier(event_id, "event_id"),
            "policy_hash": recovery_policy["policy_hash"],
            "principal_id": root_view.principal_id,
            "root_public_key": root_view.current_root_public_key,
            "root_generation": root_view.current_generation,
            "guardian_id": _identifier(guardian_id, "guardian_id"),
            "reason": reason,
            "issued_at": _iso(issued),
            "expires_at": _iso(expires),
            "effect": "TEMPORARY_HIGH_RISK_FREEZE",
        },
        guardian_key,
    )


def _verify_guardian_freeze(
    state: DistributedGateState,
    recovery_policy: Mapping[str, Any],
    event: Mapping[str, Any],
    *,
    now: datetime,
    max_duration_seconds: int,
    max_event_age_seconds: int,
) -> dict[str, Any]:
    verified_policy = verify_recovery_policy(
        recovery_policy,
        expected_policy_hash=state.root_view.recovery_policy_hash,
    )
    if not isinstance(event, Mapping) or set(event) != {
        "schema",
        "event_id",
        "policy_hash",
        "principal_id",
        "root_public_key",
        "root_generation",
        "guardian_id",
        "reason",
        "issued_at",
        "expires_at",
        "effect",
        "payload_hash",
        "signature",
    }:
        raise DistributionProtocolError("freeze_event_shape_invalid")
    if event.get("schema") != GUARDIAN_FREEZE_SCHEMA:
        raise DistributionProtocolError("freeze_event_schema_invalid")
    _identifier(event.get("event_id"), "event_id")
    guardian_id = _identifier(event.get("guardian_id"), "guardian_id")
    if event.get("policy_hash") != state.root_view.recovery_policy_hash:
        raise DistributionProtocolError("freeze_policy_mismatch")
    if event.get("principal_id") != state.root_view.principal_id:
        raise DistributionProtocolError("freeze_principal_mismatch")
    if event.get("root_public_key") != state.root_view.current_root_public_key:
        raise DistributionProtocolError("freeze_root_mismatch")
    if event.get("root_generation") != state.root_view.current_generation:
        raise DistributionProtocolError("freeze_generation_mismatch")
    if event.get("reason") not in _FREEZE_REASONS:
        raise DistributionProtocolError("freeze_reason_invalid")
    if event.get("effect") != "TEMPORARY_HIGH_RISK_FREEZE":
        raise DistributionProtocolError("freeze_effect_invalid")
    guardian_key = verified_policy["guardian_map"].get(guardian_id)
    if guardian_key is None:
        raise DistributionProtocolError("freeze_guardian_unknown")
    valid, _reason = verify_olp_signature(event)
    if valid is not True:
        raise DistributionProtocolError("freeze_signature_invalid")
    signature = event.get("signature")
    if (
        not isinstance(signature, Mapping)
        or str(signature.get("public_key", "")).lower() != guardian_key.lower()
    ):
        raise DistributionProtocolError("freeze_guardian_signer_mismatch")
    if now.tzinfo is None:
        raise DistributionProtocolError("gate_time_timezone_required")
    current = now.astimezone(timezone.utc)
    issued = _parse_time(event.get("issued_at"), "freeze_issued_at")
    expires = _parse_time(event.get("expires_at"), "freeze_expires_at")
    if issued > current:
        raise DistributionProtocolError("freeze_from_future")
    if expires <= current:
        raise DistributionProtocolError("freeze_expired")
    if _seconds(expires - issued) > max_duration_seconds:
        raise DistributionProtocolError("freeze_duration_exceeds_policy")
    if _seconds(current - issued) > max_event_age_seconds:
        raise DistributionProtocolError("freeze_stale")
    return {
        "event_hash": str(event["payload_hash"]),
        "guardian_id": guardian_id,
        "issued_at": _iso(issued),
        "expires_at": _iso(expires),
        "root_generation": int(event["root_generation"]),
    }


def ingest_guardian_freeze(
    state: DistributedGateState,
    recovery_policy: Mapping[str, Any],
    event: Mapping[str, Any],
    *,
    now: datetime,
    max_duration_seconds: int = 600,
    max_event_age_seconds: int = 60,
) -> tuple[DistributedGateState, dict[str, Any]]:
    """Accept one nonrenewable freeze for the current root generation."""
    try:
        if state.fork_quarantined:
            raise DistributionProtocolError("root_fork_quarantined")
        verified = _verify_guardian_freeze(
            state,
            recovery_policy,
            event,
            now=now,
            max_duration_seconds=max_duration_seconds,
            max_event_age_seconds=max_event_age_seconds,
        )
        event_hash = verified["event_hash"]
        generation = verified["root_generation"]
        if event_hash in state.seen_freeze_hashes:
            raise DistributionProtocolError("freeze_replayed")
        if generation in state.used_freeze_generations:
            raise DistributionProtocolError("freeze_generation_already_used")
        active = ActiveFreeze(**verified)
        next_state = replace(
            state,
            active_freeze=active,
            used_freeze_generations=state.used_freeze_generations + (generation,),
            seen_freeze_hashes=state.seen_freeze_hashes + (event_hash,),
        )
        return next_state, _authority_receipt(
            decision="ACCEPT_FREEZE",
            accepted=True,
            reason_codes=[],
            state_delta=1,
            event_hash=event_hash,
            guardian_id=verified["guardian_id"],
            root_generation=generation,
            expires_at=verified["expires_at"],
        )
    except DistributionProtocolError as exc:
        return _reject(state, "REJECT_FREEZE", exc.code)
    except Exception:
        return _reject(state, "REJECT_FREEZE", "freeze_verification_error")


def _view_at_generation(
    state: DistributedGateState,
    generation: int,
) -> ReceiverRootView:
    matching = next(
        (
            entry
            for entry in state.root_view.root_history
            if entry.generation == generation
        ),
        None,
    )
    if matching is None:
        raise DistributionProtocolError("succession_prior_generation_unknown")
    history = tuple(
        RootHistoryEntry(
            generation=entry.generation,
            root_public_key=entry.root_public_key,
            standing="CURRENT" if entry.generation == generation else "SUPERSEDED",
            succession_event_hash=entry.succession_event_hash,
        )
        for entry in state.root_view.root_history
        if entry.generation <= generation
    )
    accepted = tuple(
        record.event_hash
        for record in state.succession_records
        if record.successor_generation <= generation
    )
    return ReceiverRootView(
        principal_id=state.root_view.principal_id,
        recovery_policy_hash=state.root_view.recovery_policy_hash,
        current_root_public_key=matching.root_public_key,
        current_generation=generation,
        root_history=history,
        accepted_event_hashes=accepted,
    )


def _record_from_event(event: Mapping[str, Any]) -> SuccessionRecord:
    body = event.get("body")
    if not isinstance(body, Mapping) or not _is_hash(event.get("event_hash")):
        raise DistributionProtocolError("succession_event_shape_invalid")
    return SuccessionRecord(
        event_hash=str(event["event_hash"]),
        prior_generation=int(body["prior_generation"]),
        successor_generation=int(body["successor_generation"]),
        successor_root_public_key=str(body["successor_root_public_key"]),
    )


def ingest_root_succession(
    state: DistributedGateState,
    recovery_policy: Mapping[str, Any],
    event: Mapping[str, Any],
    *,
    now: datetime,
) -> tuple[DistributedGateState, dict[str, Any]]:
    """Advance one branch or quarantine two valid branches when co-observed."""
    if state.fork_quarantined:
        return _reject(state, "REJECT_SUCCESSION", "root_fork_quarantined")
    next_view, receipt = accept_root_succession(
        state.root_view,
        recovery_policy,
        event,
        now=now,
    )
    if receipt.get("accepted") is True:
        try:
            record = _record_from_event(event)
        except Exception:
            return _reject(state, "REJECT_SUCCESSION", "succession_record_invalid")
        next_state = replace(
            state,
            root_view=next_view,
            active_freeze=None,
            checkpoint=None,
            succession_records=state.succession_records + (record,),
        )
        return next_state, _authority_receipt(
            **{
                **receipt,
                "freeze_cleared": state.active_freeze is not None,
            }
        )

    try:
        candidate = _record_from_event(event)
        existing = next(
            (
                record
                for record in state.succession_records
                if record.prior_generation == candidate.prior_generation
            ),
            None,
        )
        if existing is None:
            return state, _authority_receipt(**receipt)
        if existing.event_hash == candidate.event_hash:
            return _reject(state, "REJECT_SUCCESSION", "succession_replayed")
        if existing.successor_root_public_key == candidate.successor_root_public_key:
            return _reject(
                state,
                "REJECT_SUCCESSION",
                "succession_branch_already_accepted",
            )
        prior_view = _view_at_generation(state, candidate.prior_generation)
        _candidate_view, candidate_receipt = accept_root_succession(
            prior_view,
            recovery_policy,
            event,
            now=now,
        )
        if candidate_receipt.get("accepted") is not True:
            return state, _authority_receipt(**receipt)
        fork_hashes = tuple(sorted({existing.event_hash, candidate.event_hash}))
        forked = replace(
            state,
            active_freeze=None,
            checkpoint=None,
            fork_event_hashes=fork_hashes,
        )
        return forked, _authority_receipt(
            decision="FORK_DETECTED",
            accepted=False,
            reason_codes=["CONFLICTING_VALID_SUCCESSIONS"],
            state_delta=1,
            fork_event_hashes=list(fork_hashes),
            resolution="EXTERNAL_RESOLUTION_REQUIRED",
        )
    except Exception:
        return state, _authority_receipt(**receipt)


def create_root_checkpoint(
    recovery_policy: Mapping[str, Any],
    approval_keys: Mapping[str, Ed25519PrivateKey],
    root_view: ReceiverRootView,
    *,
    checkpoint_id: str,
    issued_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    """Create a quorum checkpoint; it confirms a view but cannot install it."""
    if not isinstance(recovery_policy, Mapping) or not _is_hash(
        recovery_policy.get("policy_hash")
    ):
        raise DistributionProtocolError("recovery_policy_invalid")
    issued = _parse_time(_iso(issued_at), "checkpoint_issued_at")
    expires = _parse_time(_iso(expires_at), "checkpoint_expires_at")
    if expires <= issued:
        raise DistributionProtocolError("checkpoint_lifetime_invalid")
    latest_event_hash = (
        root_view.accepted_event_hashes[-1]
        if root_view.accepted_event_hashes
        else None
    )
    body = {
        "schema": ROOT_CHECKPOINT_BODY_SCHEMA,
        "checkpoint_id": _identifier(checkpoint_id, "checkpoint_id"),
        "policy_hash": recovery_policy["policy_hash"],
        "principal_id": root_view.principal_id,
        "root_public_key": root_view.current_root_public_key,
        "root_generation": root_view.current_generation,
        "latest_succession_event_hash": latest_event_hash,
        "issued_at": _iso(issued),
        "expires_at": _iso(expires),
    }
    checkpoint_hash = sha256_hex(olp_canonical_json(body))
    approvals = [
        sign_olp_body(
            {
                "schema": ROOT_CHECKPOINT_APPROVAL_SCHEMA,
                "policy_hash": recovery_policy["policy_hash"],
                "principal_id": root_view.principal_id,
                "checkpoint_hash": checkpoint_hash,
                "guardian_id": guardian_id,
            },
            approval_keys[guardian_id],
        )
        for guardian_id in sorted(approval_keys)
    ]
    return {
        "schema": ROOT_CHECKPOINT_SCHEMA,
        "body": _json_copy(body),
        "checkpoint_hash": checkpoint_hash,
        "approvals": _json_copy(approvals),
    }


def _verify_root_checkpoint(
    state: DistributedGateState,
    recovery_policy: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    *,
    now: datetime,
    max_lifetime_seconds: int,
    max_age_seconds: int,
) -> RootCheckpoint:
    verified_policy = verify_recovery_policy(
        recovery_policy,
        expected_policy_hash=state.root_view.recovery_policy_hash,
    )
    if not isinstance(checkpoint, Mapping) or set(checkpoint) != {
        "schema",
        "body",
        "checkpoint_hash",
        "approvals",
    }:
        raise DistributionProtocolError("checkpoint_shape_invalid")
    if checkpoint.get("schema") != ROOT_CHECKPOINT_SCHEMA:
        raise DistributionProtocolError("checkpoint_schema_invalid")
    body = checkpoint.get("body")
    if not isinstance(body, Mapping) or set(body) != {
        "schema",
        "checkpoint_id",
        "policy_hash",
        "principal_id",
        "root_public_key",
        "root_generation",
        "latest_succession_event_hash",
        "issued_at",
        "expires_at",
    }:
        raise DistributionProtocolError("checkpoint_body_shape_invalid")
    if body.get("schema") != ROOT_CHECKPOINT_BODY_SCHEMA:
        raise DistributionProtocolError("checkpoint_body_schema_invalid")
    _identifier(body.get("checkpoint_id"), "checkpoint_id")
    if body.get("policy_hash") != state.root_view.recovery_policy_hash:
        raise DistributionProtocolError("checkpoint_policy_mismatch")
    if body.get("principal_id") != state.root_view.principal_id:
        raise DistributionProtocolError("checkpoint_principal_mismatch")
    if body.get("root_public_key") != state.root_view.current_root_public_key:
        raise DistributionProtocolError("checkpoint_root_mismatch")
    if body.get("root_generation") != state.root_view.current_generation:
        raise DistributionProtocolError("checkpoint_generation_mismatch")
    expected_latest = (
        state.root_view.accepted_event_hashes[-1]
        if state.root_view.accepted_event_hashes
        else None
    )
    if body.get("latest_succession_event_hash") != expected_latest:
        raise DistributionProtocolError("checkpoint_lineage_mismatch")
    computed_hash = sha256_hex(olp_canonical_json(body))
    if checkpoint.get("checkpoint_hash") != computed_hash:
        raise DistributionProtocolError("checkpoint_hash_invalid")
    if now.tzinfo is None:
        raise DistributionProtocolError("gate_time_timezone_required")
    current = now.astimezone(timezone.utc)
    issued = _parse_time(body.get("issued_at"), "checkpoint_issued_at")
    expires = _parse_time(body.get("expires_at"), "checkpoint_expires_at")
    if issued > current:
        raise DistributionProtocolError("checkpoint_from_future")
    if expires <= current:
        raise DistributionProtocolError("checkpoint_expired")
    if _seconds(expires - issued) > max_lifetime_seconds:
        raise DistributionProtocolError("checkpoint_lifetime_exceeds_policy")
    if _seconds(current - issued) > max_age_seconds:
        raise DistributionProtocolError("checkpoint_stale")

    approvals = checkpoint.get("approvals")
    if not isinstance(approvals, list):
        raise DistributionProtocolError("checkpoint_approvals_invalid")
    approved_ids: set[str] = set()
    for approval in approvals:
        if not isinstance(approval, Mapping) or set(approval) != {
            "schema",
            "policy_hash",
            "principal_id",
            "checkpoint_hash",
            "guardian_id",
            "payload_hash",
            "signature",
        }:
            raise DistributionProtocolError("checkpoint_approval_invalid")
        guardian_id = _identifier(approval.get("guardian_id"), "guardian_id")
        if guardian_id in approved_ids:
            raise DistributionProtocolError("checkpoint_guardian_duplicate")
        guardian_key = verified_policy["guardian_map"].get(guardian_id)
        if guardian_key is None:
            raise DistributionProtocolError("checkpoint_guardian_unknown")
        valid, _reason = verify_olp_signature(approval)
        if valid is not True:
            raise DistributionProtocolError("checkpoint_signature_invalid")
        signature = approval.get("signature")
        if (
            not isinstance(signature, Mapping)
            or str(signature.get("public_key", "")).lower()
            != guardian_key.lower()
        ):
            raise DistributionProtocolError("checkpoint_guardian_signer_mismatch")
        expected = {
            "schema": ROOT_CHECKPOINT_APPROVAL_SCHEMA,
            "policy_hash": state.root_view.recovery_policy_hash,
            "principal_id": state.root_view.principal_id,
            "checkpoint_hash": computed_hash,
            "guardian_id": guardian_id,
        }
        for key, value in expected.items():
            if approval.get(key) != value:
                raise DistributionProtocolError("checkpoint_approval_binding_invalid")
        approved_ids.add(guardian_id)
    if len(approved_ids) < verified_policy["threshold"]:
        raise DistributionProtocolError("checkpoint_threshold_not_met")
    return RootCheckpoint(
        checkpoint_hash=computed_hash,
        root_generation=int(body["root_generation"]),
        root_public_key=str(body["root_public_key"]),
        issued_at=_iso(issued),
        expires_at=_iso(expires),
    )


def ingest_root_checkpoint(
    state: DistributedGateState,
    recovery_policy: Mapping[str, Any],
    checkpoint: Mapping[str, Any],
    *,
    now: datetime,
    max_lifetime_seconds: int = 120,
    max_age_seconds: int = 60,
) -> tuple[DistributedGateState, dict[str, Any]]:
    """Admit a fresh quorum checkpoint for the already-known root view."""
    try:
        if state.fork_quarantined:
            raise DistributionProtocolError("root_fork_quarantined")
        accepted = _verify_root_checkpoint(
            state,
            recovery_policy,
            checkpoint,
            now=now,
            max_lifetime_seconds=max_lifetime_seconds,
            max_age_seconds=max_age_seconds,
        )
        next_state = replace(state, checkpoint=accepted)
        return next_state, _authority_receipt(
            decision="ACCEPT_CHECKPOINT",
            accepted=True,
            reason_codes=[],
            state_delta=1,
            checkpoint_hash=accepted.checkpoint_hash,
            root_generation=accepted.root_generation,
            expires_at=accepted.expires_at,
        )
    except DistributionProtocolError as exc:
        return _reject(state, "REJECT_CHECKPOINT", exc.code)
    except Exception:
        return _reject(state, "REJECT_CHECKPOINT", "checkpoint_verification_error")


def evaluate_distributed_bundle(
    state: DistributedGateState,
    bundle: Mapping[str, Any],
    *,
    expected_action: Mapping[str, Any],
    receiver_challenge: str,
    now: datetime,
    policy: AdmissionPolicy,
) -> dict[str, Any]:
    """Apply fork, checkpoint, and freeze state before current-root admission."""
    if now.tzinfo is None:
        return _authority_receipt(
            decision="BLOCK",
            reason_codes=["GATE_TIME_TIMEZONE_REQUIRED"],
            executed=False,
            effect_delta=0,
            gate_id=state.gate_id,
        )
    current = now.astimezone(timezone.utc)
    if state.fork_quarantined:
        return _authority_receipt(
            decision="BLOCK",
            reason_codes=["ROOT_FORK_QUARANTINED"],
            executed=False,
            effect_delta=0,
            gate_id=state.gate_id,
            fork_event_hashes=list(state.fork_event_hashes),
            resolution="EXTERNAL_RESOLUTION_REQUIRED",
        )
    if state.requires_checkpoint:
        checkpoint = state.checkpoint
        if (
            checkpoint is None
            or checkpoint.root_generation != state.root_view.current_generation
            or checkpoint.root_public_key != state.root_view.current_root_public_key
            or _parse_time(checkpoint.expires_at, "checkpoint_expires_at") <= current
        ):
            return _authority_receipt(
                decision="BLOCK",
                reason_codes=["CURRENT_ROOT_CHECKPOINT_REQUIRED"],
                executed=False,
                effect_delta=0,
                gate_id=state.gate_id,
            )
    active = state.active_freeze
    if active is not None and _parse_time(active.expires_at, "freeze_expires_at") > current:
        return _authority_receipt(
            decision="BLOCK",
            reason_codes=["GUARDIAN_FREEZE_ACTIVE"],
            executed=False,
            effect_delta=0,
            gate_id=state.gate_id,
            freeze_event_hash=active.event_hash,
            freeze_expires_at=active.expires_at,
        )
    result = evaluate_current_root_bundle(
        state.root_view,
        bundle,
        expected_action=expected_action,
        receiver_challenge=receiver_challenge,
        now=current,
        policy=policy,
    )
    return _authority_receipt(**{**result, "gate_id": state.gate_id})
