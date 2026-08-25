"""STANDING-SEAM-001.

A valid approval remains cryptographically intact while receiver-recognized
standing changes what an unchanged protected action may do next.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import (
    olp_canonical_json,
    public_key_hex,
    sign_olp_body,
    verify_olp_signature,
)
from olp_gate.standing import (
    ReceiverStandingView,
    STANDING_PROJECTION_SCHEMA,
    StandingProjectionError,
    standing_action_hash,
    standing_action_hash_from_call,
    standing_requirement_source,
    support_receipt_hash,
)
from olp_gate.tool_adapter import (
    AuthorizationBlocked,
    AuthorizedValue,
    EvidenceAssertion,
    authorize,
)


CLAIM = (
    "An action previously authorized by a valid receipt can be selectively "
    "blocked after its supporting evidence loses receiver-recognized standing, "
    "without revoking unrelated actions or invalidating the original receipt "
    "cryptographically."
)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class FakeRuntime:
    """Exercise the real guarded-tool compiler while keeping the effect harmless."""

    def __init__(self) -> None:
        self.executions: list[tuple[Mapping[str, Any], Any]] = []
        self.compilations: list[Mapping[str, Any]] = []

    def record_compilation(self, value: Mapping[str, Any]) -> None:
        self.compilations.append(dict(value))

    def execute(self, *, compiler, proposal, compilation, executor, now):
        preflight = compiler.preflight(compilation, proposal, now=now)
        if not preflight["allowed"]:
            raise AuthorizationBlocked(
                "DENY",
                preflight["reason_codes"],
                compilation=compilation,
            )
        value = executor()
        self.executions.append((dict(proposal), value))
        return AuthorizedValue(
            value=value,
            decision_receipt={"decision": "COMMIT", "verdict": "VERIFIED"},
            compilation=compilation,
            execution={"authorized": True, "execution_status": "completed"},
        )


class SeamHarness:
    def __init__(self) -> None:
        self.now = datetime.now(timezone.utc)
        self.alice_key = Ed25519PrivateKey.generate()
        self.standing_key = Ed25519PrivateKey.generate()
        self.agent_key = Ed25519PrivateKey.generate()
        self.standing_issuer = "claim-graph-projector"
        self.view = ReceiverStandingView(
            {self.standing_issuer: public_key_hex(self.standing_key)}
        )
        self.runtime = FakeRuntime()
        self.effects: list[tuple[str, str]] = []
        self.approvals: dict[tuple[str, str], dict[str, Any]] = {}
        self.presented: dict[tuple[str, str], dict[str, Any]] = {}
        self.projections: dict[tuple[str, str], dict[str, Any]] = {}

        self.bundle = {
            "schema": "openline.authorized_tool_policy.v1",
            "mandate": {
                "profile": "principal_mandate/v1",
                "mandate_id": "message-standing-seam-mandate",
                "principal_id": "alice",
                "agent_id": "message-agent",
                "purpose": "send messages approved by Alice",
                "allowed_action_types": ["send"],
                "allowed_targets": ["message://send"],
                "allowed_disclosure_classes": ["message_content"],
                "forbidden_disclosure_classes": [],
                "max_settlement_cents": 0,
                "max_payment_cents": 0,
                "delegation_allowed": False,
                "expires_at": _iso(self.now + timedelta(days=1)),
                "version": "1",
            },
            "permission_policy": {
                "profile": "decision_permission_policy/v1",
                "policy_id": "message-standing-seam-permission",
                "version": "1",
                "routes": [
                    {
                        "route_id": "send-message",
                        "tool": "send_message",
                        "target": "message://send",
                        "requirements": [
                            {
                                "requirement_id": "message_authority",
                                "kind": "authority",
                                "accepted_issuers": ["message_authority"],
                                "max_age_seconds": 300,
                                "independent_from_producer": True,
                            },
                            {
                                "requirement_id": "message_standing",
                                "kind": "evidence",
                                "accepted_issuers": ["receiver_standing"],
                                "max_age_seconds": 300,
                                "independent_from_producer": True,
                            },
                        ],
                        "unknown_behavior": "QUARANTINE",
                        "max_authorization_ttl_seconds": 120,
                    }
                ],
            },
        }

        self._standing_provider = standing_requirement_source(
            self.view,
            support_source=self._support_for_call,
            projection_source=self._projection_for_call,
            action_hash_source=standing_action_hash_from_call,
            evidence_issuer_id="receiver_standing",
            max_assertion_ttl_seconds=60,
            now_source=lambda: datetime.now(timezone.utc),
        )

        @authorize(
            policy=self.bundle,
            tool="send_message",
            target="message://send",
            semantics=self._semantics,
            state_source=self._state,
            evidence_sources={
                "message_authority": self._authority_for_call,
                "message_standing": self._standing_provider,
            },
            producer_model="standing-seam-agent",
            runtime=self.runtime,
        )
        def send_message(recipient: str, message: str):
            self.effects.append((recipient, message))
            return {"sent": True, "recipient": recipient, "message": message}

        self.send_message = send_message

    @staticmethod
    def _semantics(call):
        return {
            "action_type": "send",
            "disclosures": ["message_content"],
            "value_cents": 0,
            "delegatee": None,
        }

    @staticmethod
    def _state(call):
        # Standing is deliberately absent. Upstream events do not mutate the
        # protected function's state or proposal; they change only evidence.
        return {
            "recipient": call.arguments["recipient"],
            "message": call.arguments["message"],
        }

    @staticmethod
    def action_hash(recipient: str, message: str) -> str:
        return standing_action_hash(
            tool="send_message",
            target="message://send",
            arguments={"recipient": recipient, "message": message},
        )

    def approve(self, recipient: str, message: str) -> dict[str, Any]:
        receipt = sign_olp_body(
            {
                "schema": "openline.message_approval.v1",
                "approval_id": f"alice:{len(self.approvals) + 1}",
                "issuer_id": "alice",
                "recipient": recipient,
                "message": message,
                "issued_at": _iso(self.now),
                "expires_at": _iso(self.now + timedelta(hours=1)),
            },
            self.alice_key,
        )
        self.approvals[(recipient, message)] = receipt
        return receipt

    def _support_for_call(self, call):
        return self.approvals.get(
            (call.arguments.get("recipient"), call.arguments.get("message"))
        )

    def _approval_is_valid(self, receipt: Mapping[str, Any]) -> bool:
        valid, _ = verify_olp_signature(receipt)
        if valid is not True:
            return False
        signature = receipt.get("signature")
        if not isinstance(signature, Mapping):
            return False
        if signature.get("public_key") != public_key_hex(self.alice_key):
            return False
        return True

    def _authority_for_call(self, call):
        receipt = self._support_for_call(call)
        if receipt is None or not self._approval_is_valid(receipt):
            return None
        if receipt.get("recipient") != call.arguments.get("recipient"):
            return None
        if receipt.get("message") != call.arguments.get("message"):
            return None
        return EvidenceAssertion(
            payload={"approval_receipt_hash": support_receipt_hash(receipt)},
            issuer_id="message_authority",
            expires_in_seconds=60,
        )

    def _projection_for_call(self, call):
        receipt = self._support_for_call(call)
        if receipt is None:
            return None
        key = (
            support_receipt_hash(receipt),
            standing_action_hash_from_call(call),
        )
        return self.presented.get(key)

    def _projection(
        self,
        recipient: str,
        message: str,
        *,
        standing: str,
        event_type: str,
        signer: Ed25519PrivateKey | None = None,
        issuer_id: str | None = None,
    ) -> dict[str, Any]:
        receipt = self.approvals[(recipient, message)]
        support_hash = support_receipt_hash(receipt)
        action_hash = self.action_hash(recipient, message)
        current_hash = self.view.head_hash(support_hash, action_hash)
        current = self.projections.get((support_hash, action_hash))
        sequence = 1 if current is None else int(current["sequence"]) + 1
        key = signer or self.standing_key
        return sign_olp_body(
            {
                "schema": STANDING_PROJECTION_SCHEMA,
                "projection_id": f"{event_type.lower()}:{recipient}:{sequence}",
                "issuer_id": issuer_id or self.standing_issuer,
                "support_hash": support_hash,
                "action_hash": action_hash,
                "standing": standing,
                "event_type": event_type,
                "sequence": sequence,
                "predecessor_hash": current_hash,
                "issued_at": _iso(datetime.now(timezone.utc)),
                "expires_at": _iso(datetime.now(timezone.utc) + timedelta(hours=1)),
            },
            key,
        )

    def admit(
        self,
        recipient: str,
        message: str,
        *,
        standing: str,
        event_type: str,
    ) -> dict[str, Any]:
        projection = self._projection(
            recipient,
            message,
            standing=standing,
            event_type=event_type,
        )
        self.view.admit(projection, now=datetime.now(timezone.utc))
        receipt = self.approvals[(recipient, message)]
        key = (support_receipt_hash(receipt), self.action_hash(recipient, message))
        self.projections[key] = projection
        self.presented[key] = projection
        return projection

    def present(self, recipient: str, message: str, projection: Mapping[str, Any]) -> None:
        receipt = self.approvals[(recipient, message)]
        key = (support_receipt_hash(receipt), self.action_hash(recipient, message))
        self.presented[key] = dict(projection)

    def activate(self, recipient: str, message: str) -> dict[str, Any]:
        if (recipient, message) not in self.approvals:
            self.approve(recipient, message)
        return self.admit(
            recipient,
            message,
            standing="ACTIVE",
            event_type="ADMIT",
        )

    def block_event(self, recipient: str, message: str, event_type: str) -> dict[str, Any]:
        return self.admit(
            recipient,
            message,
            standing="INACTIVE",
            event_type=event_type,
        )

    def restore(self, recipient: str, message: str) -> dict[str, Any]:
        return self.admit(
            recipient,
            message,
            standing="ACTIVE",
            event_type="ADMIT",
        )

    def forged_restore(self, recipient: str, message: str) -> dict[str, Any]:
        return self._projection(
            recipient,
            message,
            standing="ACTIVE",
            event_type="ADMIT",
            signer=self.agent_key,
            issuer_id=self.standing_issuer,
        )


def _try_send(harness: SeamHarness, recipient: str, message: str) -> dict[str, Any]:
    before = len(harness.effects)
    try:
        value = harness.send_message(recipient, message)
        return {
            "executed": True,
            "blocked": False,
            "decision": "COMMIT",
            "reasons": [],
            "effect_delta": len(harness.effects) - before,
            "value": value,
        }
    except AuthorizationBlocked as exc:
        return {
            "executed": False,
            "blocked": True,
            "decision": exc.decision,
            "reasons": list(exc.reason_codes),
            "effect_delta": len(harness.effects) - before,
        }


def run_case_matrix() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []

    # Main story: valid exact approval -> execute -> revoke standing -> same call
    # blocked, while the original approval remains intact and an unrelated
    # approved message continues to execute.
    h = SeamHarness()
    a = ("alice@example.com", "Meet at 3.")
    b = ("bob@example.com", "Ship the report.")
    h.activate(*a)
    h.activate(*b)
    approval_before = olp_canonical_json(h.approvals[a])
    initial = _try_send(h, *a)
    h.block_event(*a, event_type="REVOKE")
    after_revoke = _try_send(h, *a)
    unrelated_after_revoke = _try_send(h, *b)
    approval_after = olp_canonical_json(h.approvals[a])
    approval_signature_valid, _ = verify_olp_signature(h.approvals[a])
    rows.append(
        {
            "case": "relevant_revocation_selective_block",
            "passed": (
                initial["executed"]
                and after_revoke["blocked"]
                and after_revoke["effect_delta"] == 0
                and unrelated_after_revoke["executed"]
                and approval_before == approval_after
                and approval_signature_valid is True
            ),
            "initial": initial,
            "after_event": after_revoke,
            "unrelated": unrelated_after_revoke,
            "approval_bytes_unchanged": approval_before == approval_after,
            "approval_signature_still_valid": approval_signature_valid is True,
        }
    )

    for event_type in ("EXPIRE", "SUPERSEDE", "CORRECT"):
        h = SeamHarness()
        h.activate(*a)
        h.block_event(*a, event_type=event_type)
        observed = _try_send(h, *a)
        rows.append(
            {
                "case": f"relevant_{event_type.lower()}_blocks",
                "passed": observed["blocked"] and observed["effect_delta"] == 0,
                "observed": observed,
            }
        )

    h = SeamHarness()
    h.activate(*a)
    h.activate(*b)
    h.block_event(*b, event_type="REVOKE")
    observed = _try_send(h, *a)
    rows.append(
        {
            "case": "unrelated_revocation_preserves_action",
            "passed": observed["executed"] and observed["effect_delta"] == 1,
            "observed": observed,
        }
    )

    h = SeamHarness()
    old_active = h.activate(*a)
    h.block_event(*a, event_type="REVOKE")
    h.present(*a, old_active)
    observed = _try_send(h, *a)
    rows.append(
        {
            "case": "old_pre_revocation_projection_replay_blocked",
            "passed": observed["blocked"] and observed["effect_delta"] == 0,
            "observed": observed,
        }
    )

    h = SeamHarness()
    h.activate(*a)
    h.block_event(*a, event_type="REVOKE")
    forged = h.forged_restore(*a)
    h.present(*a, forged)
    observed = _try_send(h, *a)
    try:
        h.view.admit(forged, now=datetime.now(timezone.utc))
        receiver_rejected = False
    except StandingProjectionError:
        receiver_rejected = True
    rows.append(
        {
            "case": "agent_fabricated_standing_restore_blocked",
            "passed": (
                observed["blocked"]
                and observed["effect_delta"] == 0
                and receiver_rejected
            ),
            "observed": observed,
            "receiver_rejected_forged_successor": receiver_rejected,
        }
    )

    h = SeamHarness()
    h.activate(*a)
    h.block_event(*a, event_type="REVOKE")
    h.restore(*a)
    observed = _try_send(h, *a)
    rows.append(
        {
            "case": "receiver_admitted_successor_restores_action",
            "passed": observed["executed"] and observed["effect_delta"] == 1,
            "observed": observed,
        }
    )

    return {
        "schema": "openline.standing_seam_001.report.v1",
        "claim": CLAIM,
        "passed": all(row["passed"] for row in rows),
        "case_count": len(rows),
        "rows": rows,
    }


def main() -> int:
    report = run_case_matrix()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
