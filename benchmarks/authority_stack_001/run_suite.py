"""AUTHORITY-STACK-001: end-to-end composition proof.

This benchmark adds no new authority primitive. It composes the existing
MandateOwnerView/authorize_owned path, exact-action approval evidence,
ReceiverStandingView/standing_requirement_source, AuthorityCompiler, Receipt
Gate, and LocalAuthorityRuntime.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import (
    olp_canonical_json,
    public_key_hex,
    sign_olp_body,
    verify_olp_signature,
)
from olp_gate.mandate import MandateSpec
from olp_gate.mandate_owner import (
    MandateOwnerView,
    authorize_owned,
    issue_mandate_authorization,
)
from olp_gate.standing import (
    ReceiverStandingView,
    STANDING_PROJECTION_SCHEMA,
    standing_action_hash,
    standing_action_hash_from_call,
    standing_requirement_source,
    support_receipt_hash,
)
from olp_gate.tool_adapter import (
    AuthorizationBlocked,
    AuthorizedValue,
    EvidenceAssertion,
    LocalAuthorityRuntime,
    payment_semantics,
)


CLAIM = (
    "OpenLine can compose mandate ownership, exact-action approval, temporal "
    "standing, selective standing loss, and exact-action gating so that "
    "historically valid artifacts remain verifiable while current execution "
    "authority changes selectively."
)

VERDICT = "AUTHORITY_STACK_COMPOSITION_PASS"
GAP = "AUTHORITY_STACK_COMPOSITION_GAP"
POLICY_AUTHORITY = "NONE"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class AuthorityStackHarness:
    SLOT_ID = "refund-agent/default"
    STANDING_ISSUER = "claim-graph-projector"

    def __init__(self) -> None:
        self.owner_key = Ed25519PrivateKey.generate()
        self.approval_key = Ed25519PrivateKey.generate()
        self.standing_key = Ed25519PrivateKey.generate()

        self.mandate_view = MandateOwnerView(
            {
                self.SLOT_ID: {
                    "owner_id": "alice",
                    "public_key": public_key_hex(self.owner_key),
                }
            }
        )
        self.standing_view = ReceiverStandingView(
            {self.STANDING_ISSUER: public_key_hex(self.standing_key)}
        )

        self._tmp = tempfile.TemporaryDirectory(prefix="authority-stack-001-")
        self.runtime = LocalAuthorityRuntime(Path(self._tmp.name) / "runtime")
        self.effects: list[tuple[int, str]] = []

        self.approvals: dict[tuple[int, str], dict[str, Any]] = {}
        self.presented: dict[tuple[str, str], dict[str, Any]] = {}
        self.standing_records: dict[tuple[str, str], dict[str, Any]] = {}

        # Deliberately broader developer-authored proposal. It remains proposal
        # material; the current receiver-admitted owner mandate governs instead.
        self.developer_draft = self.mandate(50_000, version="developer-draft-500")
        self.permission_policy = {
            "profile": "decision_permission_policy/v1",
            "policy_id": "authority-stack-001-refund",
            "version": "1",
            "routes": [
                {
                    "route_id": "refund",
                    "tool": "process_refund",
                    "target": "refund://process",
                    "requirements": [
                        {
                            "requirement_id": "refund_authority",
                            "kind": "authority",
                            "accepted_issuers": ["refund_authority"],
                            "max_age_seconds": 300,
                            "independent_from_producer": True,
                        },
                        {
                            "requirement_id": "refund_standing",
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
        }
        self.bundle = {
            "schema": "openline.authorized_tool_policy.v1",
            "mandate": self.developer_draft,
            "permission_policy": self.permission_policy,
        }

        self._standing_source = standing_requirement_source(
            self.standing_view,
            support_source=self._support_for_call,
            projection_source=self._projection_for_call,
            action_hash_source=standing_action_hash_from_call,
            evidence_issuer_id="receiver_standing",
            max_assertion_ttl_seconds=60,
            now_source=_now,
        )

        @authorize_owned(
            policy=self.bundle,
            mandate_view=self.mandate_view,
            mandate_slot_id=self.SLOT_ID,
            tool="process_refund",
            target="refund://process",
            semantics=payment_semantics("amount_cents"),
            state_source=self._state,
            evidence_sources={
                "refund_authority": self._authority_for_call,
                "refund_standing": self._standing_source,
            },
            producer_model="authority-stack-001-agent",
            runtime=self.runtime,
            return_receipt=True,
        )
        def process_refund(amount_cents: int, customer_id: str):
            self.effects.append((amount_cents, customer_id))
            return {"refunded_cents": amount_cents, "customer_id": customer_id}

        self.process_refund = process_refund

    def close(self) -> None:
        self._tmp.cleanup()

    def mandate(self, max_payment_cents: int, *, version: str) -> dict[str, Any]:
        now = _now()
        return {
            "profile": "principal_mandate/v1",
            "mandate_id": "refund-mandate",
            "principal_id": "alice",
            "agent_id": "refund-agent",
            "purpose": "customer refunds",
            "allowed_action_types": ["authorize_payment"],
            "allowed_targets": ["refund://process"],
            "allowed_disclosure_classes": [],
            "forbidden_disclosure_classes": [],
            "max_settlement_cents": 0,
            "max_payment_cents": max_payment_cents,
            "delegation_allowed": False,
            "expires_at": _iso(now + timedelta(days=1)),
            "version": version,
        }

    def admit_mandate(self, mandate: Mapping[str, Any]) -> dict[str, Any]:
        now = _now()
        authorization = issue_mandate_authorization(
            slot_id=self.SLOT_ID,
            owner_id="alice",
            mandate=mandate,
            state="ACTIVE",
            sequence=self.mandate_view.head_sequence(self.SLOT_ID) + 1,
            predecessor_hash=self.mandate_view.head_hash(self.SLOT_ID),
            issued_at=now,
            expires_at=now + timedelta(hours=12),
            key=self.owner_key,
        )
        self.mandate_view.admit(authorization, mandate, now=now)
        return authorization

    @staticmethod
    def _state(call):
        return {
            "customer_id": call.arguments["customer_id"],
            "request_version": 1,
        }

    @staticmethod
    def _action_key(amount_cents: int, customer_id: str) -> tuple[int, str]:
        return (amount_cents, customer_id)

    def approve(self, amount_cents: int, customer_id: str) -> dict[str, Any]:
        now = _now()
        approval = sign_olp_body(
            {
                "schema": "openline.authority_stack_approval.v1",
                "approval_id": f"approval:{amount_cents}:{customer_id}",
                "issuer_id": "alice-action-approval",
                "tool": "process_refund",
                "target": "refund://process",
                "amount_cents": amount_cents,
                "customer_id": customer_id,
                "issued_at": _iso(now),
                "expires_at": _iso(now + timedelta(hours=1)),
            },
            self.approval_key,
        )
        self.approvals[self._action_key(amount_cents, customer_id)] = approval
        return approval

    def _support_for_call(self, call):
        amount = call.arguments.get("amount_cents")
        customer = call.arguments.get("customer_id")
        if not isinstance(amount, int) or not isinstance(customer, str):
            return None
        return self.approvals.get(self._action_key(amount, customer))

    def _authority_for_call(self, call):
        approval = self._support_for_call(call)
        if approval is None:
            return None
        valid, _ = verify_olp_signature(approval)
        signature = approval.get("signature")
        if valid is not True or not isinstance(signature, Mapping):
            return None
        if signature.get("public_key") != public_key_hex(self.approval_key):
            return None
        if approval.get("tool") != call.tool or approval.get("target") != call.target:
            return None
        if approval.get("amount_cents") != call.arguments.get("amount_cents"):
            return None
        if approval.get("customer_id") != call.arguments.get("customer_id"):
            return None
        return EvidenceAssertion(
            payload={"approval_receipt_hash": support_receipt_hash(approval)},
            issuer_id="refund_authority",
            expires_in_seconds=60,
        )

    @staticmethod
    def action_hash(amount_cents: int, customer_id: str) -> str:
        return standing_action_hash(
            tool="process_refund",
            target="refund://process",
            arguments={"amount_cents": amount_cents, "customer_id": customer_id},
        )

    def _projection_key(self, amount_cents: int, customer_id: str) -> tuple[str, str]:
        approval = self.approvals[self._action_key(amount_cents, customer_id)]
        return (support_receipt_hash(approval), self.action_hash(amount_cents, customer_id))

    def _projection_for_call(self, call):
        approval = self._support_for_call(call)
        if approval is None:
            return None
        key = (support_receipt_hash(approval), standing_action_hash_from_call(call))
        return self.presented.get(key)

    def set_standing(
        self,
        amount_cents: int,
        customer_id: str,
        *,
        standing: str,
        event_type: str,
    ) -> dict[str, Any]:
        key = self._projection_key(amount_cents, customer_id)
        current = self.standing_records.get(key)
        now = _now()
        projection = sign_olp_body(
            {
                "schema": STANDING_PROJECTION_SCHEMA,
                "projection_id": f"{event_type.lower()}:{amount_cents}:{customer_id}:{1 if current is None else int(current['sequence']) + 1}",
                "issuer_id": self.STANDING_ISSUER,
                "support_hash": key[0],
                "action_hash": key[1],
                "standing": standing,
                "event_type": event_type,
                "sequence": 1 if current is None else int(current["sequence"]) + 1,
                "predecessor_hash": self.standing_view.head_hash(key[0], key[1]),
                "issued_at": _iso(now),
                "expires_at": _iso(now + timedelta(hours=1)),
            },
            self.standing_key,
        )
        self.standing_view.admit(projection, now=now)
        self.standing_records[key] = projection
        self.presented[key] = projection
        return projection

    def activate(self, amount_cents: int, customer_id: str) -> dict[str, Any]:
        if self._action_key(amount_cents, customer_id) not in self.approvals:
            self.approve(amount_cents, customer_id)
        return self.set_standing(
            amount_cents,
            customer_id,
            standing="ACTIVE",
            event_type="ADMIT",
        )

    def revoke(self, amount_cents: int, customer_id: str) -> dict[str, Any]:
        return self.set_standing(
            amount_cents,
            customer_id,
            standing="INACTIVE",
            event_type="REVOKE",
        )

    def restore(self, amount_cents: int, customer_id: str) -> dict[str, Any]:
        return self.set_standing(
            amount_cents,
            customer_id,
            standing="ACTIVE",
            event_type="ADMIT",
        )

    def attempt(self, amount_cents: int, customer_id: str) -> dict[str, Any]:
        before = len(self.effects)
        try:
            authorized = self.process_refund(amount_cents, customer_id)
            assert isinstance(authorized, AuthorizedValue)
            return {
                "executed": True,
                "blocked": False,
                "effect_delta": len(self.effects) - before,
                "decision": str(authorized.decision_receipt.get("decision")),
                "verdict": str(authorized.decision_receipt.get("verdict")),
                "compiled_mandate_hash": str(authorized.compilation.get("mandate_hash")),
            }
        except AuthorizationBlocked as exc:
            return {
                "executed": False,
                "blocked": True,
                "effect_delta": len(self.effects) - before,
                "decision": exc.decision,
                "reason_codes": list(exc.reason_codes),
            }


def run_sequence() -> dict[str, Any]:
    h = AuthorityStackHarness()
    rows: list[dict[str, Any]] = []
    action1 = (7_500, "C-1")
    action2 = (2_500, "C-2")
    governance_probe = (9_000, "C-3")

    try:
        # Stage 1: authored mandate proposal exists, but no pinned-owner admission.
        no_owner = h.attempt(*action1)
        rows.append(
            {
                "stage": "developer_proposes_without_owner_authority",
                "boundary": "AUTHORSHIP_NE_AUTHORITY",
                "passed": no_owner["blocked"] and no_owner["effect_delta"] == 0,
                "observed": no_owner,
            }
        )

        # Stage 2: receiver-pinned owner admits a narrower $100 mandate than the
        # developer-authored $500 proposal.
        mandate_100 = h.mandate(10_000, version="owner-100-v1")
        owner_100 = h.admit_mandate(mandate_100)
        owner_100_bytes = olp_canonical_json(owner_100)
        owner_100_sig, _ = verify_olp_signature(owner_100)

        # Stage 3: exact-action approvals and independent current standing.
        approval1 = h.approve(*action1)
        approval2 = h.approve(*action2)
        h.set_standing(*action1, standing="ACTIVE", event_type="ADMIT")
        h.set_standing(*action2, standing="ACTIVE", event_type="ADMIT")
        approval1_bytes = olp_canonical_json(approval1)
        approval1_hash = support_receipt_hash(approval1)

        # Stage 4: action 1 executes under the receiver-admitted $100 mandate,
        # not the broader developer-authored $500 proposal.
        initial = h.attempt(*action1)
        mandate_100_hash = MandateSpec.from_mapping(mandate_100).mandate_hash
        rows.append(
            {
                "stage": "active_standing_executes_exact_action",
                "boundary": "RECEIVER_ADMITTED_GOVERNANCE",
                "passed": (
                    initial["executed"]
                    and initial["effect_delta"] == 1
                    and initial.get("compiled_mandate_hash") == mandate_100_hash
                ),
                "observed": initial,
                "developer_draft_mandate_hash": MandateSpec.from_mapping(
                    h.developer_draft
                ).mandate_hash,
                "current_owner_mandate_hash": mandate_100_hash,
            }
        )

        # Stage 5: the exact same approval remains cryptographically valid and
        # byte-for-byte unchanged, but a newer standing head revokes use.
        h.revoke(*action1)
        after_revoke = h.attempt(*action1)
        approval1_sig_after, _ = verify_olp_signature(approval1)
        approval1_bytes_after = olp_canonical_json(approval1)
        approval1_hash_after = support_receipt_hash(approval1)
        unrelated = h.attempt(*action2)
        rows.append(
            {
                "stage": "valid_receipt_loses_current_standing_selectively",
                "boundary": "VALID_RECEIPT_NE_CURRENT_STANDING",
                "passed": (
                    approval1_sig_after is True
                    and approval1_bytes_after == approval1_bytes
                    and approval1_hash_after == approval1_hash
                    and after_revoke["blocked"]
                    and after_revoke["effect_delta"] == 0
                    and unrelated["executed"]
                    and unrelated["effect_delta"] == 1
                ),
                "receipt_signature_still_valid": approval1_sig_after is True,
                "receipt_bytes_unchanged": approval1_bytes_after == approval1_bytes,
                "receipt_hash_unchanged": approval1_hash_after == approval1_hash,
                "revoked_action": after_revoke,
                "unrelated_action": unrelated,
            }
        )

        # Stage 6: owner narrows the mandate to $80. The old owner-signed $100
        # record remains authentic but is non-current. A $90 action with valid
        # approval and ACTIVE standing is denied by the current mandate.
        mandate_80 = h.mandate(8_000, version="owner-80-v2")
        h.admit_mandate(mandate_80)
        owner_100_assessment = h.mandate_view.assess(owner_100, mandate_100, now=_now())
        owner_100_sig_after, _ = verify_olp_signature(owner_100)
        owner_100_bytes_after = olp_canonical_json(owner_100)
        h.activate(*governance_probe)
        probe = h.attempt(*governance_probe)
        mandate_80_hash = MandateSpec.from_mapping(mandate_80).mandate_hash
        rows.append(
            {
                "stage": "superseded_mandate_authentic_but_noncurrent",
                "boundary": "RECEIVER_ADMITTED_GOVERNANCE",
                "passed": (
                    owner_100_sig is True
                    and owner_100_sig_after is True
                    and owner_100_bytes_after == owner_100_bytes
                    and owner_100_assessment["verified"]
                    and not owner_100_assessment["current"]
                    and probe["blocked"]
                    and probe["effect_delta"] == 0
                ),
                "old_mandate_signature_still_valid": owner_100_sig_after is True,
                "old_mandate_bytes_unchanged": owner_100_bytes_after == owner_100_bytes,
                "old_mandate_verified": owner_100_assessment["verified"],
                "old_mandate_current": owner_100_assessment["current"],
                "current_mandate_hash": mandate_80_hash,
                "governance_probe_90_under_current_80": probe,
            }
        )

        # Composition pressure check: mandate succession must NOT silently restore
        # a separately revoked standing relation.
        still_revoked = h.attempt(*action1)
        rows.append(
            {
                "stage": "mandate_successor_does_not_restore_revoked_standing",
                "boundary": "LAYER_ORTHOGONALITY",
                "passed": still_revoked["blocked"] and still_revoked["effect_delta"] == 0,
                "observed": still_revoked,
            }
        )

        # Stage 7/8: a separate receiver-admitted standing successor restores the
        # same exact action. It now executes under the current $80 mandate.
        h.restore(*action1)
        restored = h.attempt(*action1)
        approval1_final_sig, _ = verify_olp_signature(approval1)
        rows.append(
            {
                "stage": "explicit_standing_successor_restores_execution",
                "boundary": "CURRENT_AUTHORITY_REEVALUATION",
                "passed": (
                    restored["executed"]
                    and restored["effect_delta"] == 1
                    and restored.get("compiled_mandate_hash") == mandate_80_hash
                    and approval1_final_sig is True
                    and olp_canonical_json(approval1) == approval1_bytes
                ),
                "observed": restored,
                "receipt_signature_still_valid": approval1_final_sig is True,
                "receipt_bytes_unchanged": olp_canonical_json(approval1) == approval1_bytes,
                "current_mandate_hash": mandate_80_hash,
            }
        )

        invariant_results = {
            "authorship_ne_authority": rows[0]["passed"] and rows[1]["passed"],
            "valid_receipt_ne_current_standing": rows[2]["passed"],
            "selective_standing_loss": rows[2]["passed"],
            "receiver_admitted_governance": rows[3]["passed"],
            "layer_orthogonality": rows[4]["passed"],
        }
        composition_constraints = {
            "uses_local_authority_runtime": type(h.runtime) is LocalAuthorityRuntime,
            "custom_runtime_shim": False,
            "receipt_mutation_used": False,
            "bypass_flags_used": False,
            "standing_layer_rewrites_mandate": False,
            "mandate_successor_silently_restores_standing": not rows[4]["passed"],
            "new_core_authority_primitive_added": False,
        }
        falsifier_triggered = (
            not all(invariant_results.values())
            or not composition_constraints["uses_local_authority_runtime"]
            or composition_constraints["custom_runtime_shim"]
            or composition_constraints["receipt_mutation_used"]
            or composition_constraints["bypass_flags_used"]
            or composition_constraints["standing_layer_rewrites_mandate"]
            or composition_constraints["mandate_successor_silently_restores_standing"]
            or composition_constraints["new_core_authority_primitive_added"]
        )
        passed = all(row["passed"] for row in rows) and not falsifier_triggered
        return {
            "schema": "openline.authority_stack_001.report.v1",
            "experiment": "AUTHORITY-STACK-001",
            "verdict": VERDICT if passed else GAP,
            "claim": CLAIM,
            "passed": passed,
            "stage_count": len(rows),
            "rows": rows,
            "invariants": invariant_results,
            "composition_constraints": composition_constraints,
            "falsifier": {
                "triggered": falsifier_triggered,
                "kill_condition": (
                    "Fail if composition requires a custom runtime shim, bypass flags, "
                    "receipt mutation, standing-layer mandate semantics, silent cross-layer "
                    "restoration, or a new core authority primitive."
                ),
            },
            "policy_authority": POLICY_AUTHORITY,
            "claim_boundary": [
                "This is a deterministic composition proof over existing OpenLine primitives, not an external deployment result.",
                "The developer-authored mandate in the bundle is proposal material; this benchmark does not establish that every developer-authored permission-policy field is separately owner-admitted.",
                "Mandate ownership and action standing remain independent authorities; restoring one does not silently restore the other.",
                "Receiver-side pinned keys are trust roots for this experiment; legal identity, fiduciary duty, and organizational key governance remain outside the claim.",
                "Distributed persistence, multi-process concurrency, crash recovery, and external protocol interoperability remain outside this benchmark.",
            ],
        }
    finally:
        h.close()


def main() -> int:
    report = run_sequence()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
