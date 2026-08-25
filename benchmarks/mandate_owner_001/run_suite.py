"""MANDATE-OWNER-001: authorship is not governing authority.

The experiment separates the new invariant from reused #32-style lifecycle
semantics. Developer/model-authored mandate proposals remain non-authoritative
until a receiver-pinned owner signs and the receiver admits them.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import olp_canonical_json, public_key_hex, verify_olp_signature
from olp_gate.mandate_owner import (
    MANDATE_AUTHORIZATION_SCHEMA,
    MandateAuthorityError,
    MandateOwnerView,
    authorize_owned,
    issue_mandate_authorization,
)
from olp_gate.standing import ReceiverStandingView
from olp_gate.tool_adapter import (
    AuthorizationBlocked,
    AuthorizedValue,
    payment_semantics,
)


CLAIM = (
    "A mandate may be syntactically valid and correctly compiled without having "
    "authority to govern. Executable mandate authority exists only after admission "
    "by the receiver-pinned mandate owner, and only the current admitted mandate "
    "may govern new actions."
)

VERDICT = "MANDATE_AUTHORSHIP_AUTHORITY_SEPARATION"
EXTENSION_ONLY = "STANDING_SEAM_EXTENSION_ONLY"
NOT_ESTABLISHED = "MANDATE_AUTHORSHIP_AUTHORITY_SEPARATION_NOT_ESTABLISHED"


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class FakeRuntime:
    """Exercise the real AuthorityCompiler path without an external side effect."""

    def __init__(self) -> None:
        self.compilations: list[Mapping[str, Any]] = []
        self.executions: list[tuple[Mapping[str, Any], Any]] = []
        self.before_preflight = None

    def record_compilation(self, value: Mapping[str, Any]) -> None:
        self.compilations.append(dict(value))

    def execute(self, *, compiler, proposal, compilation, executor, now):
        if self.before_preflight is not None:
            callback = self.before_preflight
            self.before_preflight = None
            callback()
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


class Harness:
    SLOT_ID = "refund-agent/default"

    def __init__(self) -> None:
        self.now = datetime.now(timezone.utc)
        self.owner_key = Ed25519PrivateKey.generate()
        self.developer_key = Ed25519PrivateKey.generate()
        self.agent_key = Ed25519PrivateKey.generate()
        self.view = MandateOwnerView(
            {
                self.SLOT_ID: {
                    "owner_id": "alice",
                    "public_key": public_key_hex(self.owner_key),
                }
            }
        )
        self.runtime = FakeRuntime()
        self.effects: list[tuple[int, str]] = []
        self.permission_policy = {
            "profile": "decision_permission_policy/v1",
            "policy_id": "refund-owner-001-permission",
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
                            "max_age_seconds": 60,
                            "independent_from_producer": True,
                        }
                    ],
                    "unknown_behavior": "QUARANTINE",
                    "max_authorization_ttl_seconds": 60,
                }
            ],
        }

    def mandate(self, max_payment_cents: int, *, version: str) -> dict[str, Any]:
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
            "expires_at": _iso(self.now + timedelta(days=1)),
            "version": version,
        }

    def bundle(self, draft_mandate: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "schema": "openline.authorized_tool_policy.v1",
            "mandate": dict(draft_mandate),
            "permission_policy": self.permission_policy,
        }

    def authorization(
        self,
        mandate: Mapping[str, Any],
        *,
        key: Ed25519PrivateKey,
        owner_id: str = "alice",
        state: str = "ACTIVE",
        sequence: int | None = None,
        predecessor_hash: str | None = None,
    ) -> dict[str, Any]:
        seq = sequence if sequence is not None else self.view.head_sequence(self.SLOT_ID) + 1
        pred = predecessor_hash
        if sequence is None:
            pred = self.view.head_hash(self.SLOT_ID)
        return issue_mandate_authorization(
            slot_id=self.SLOT_ID,
            owner_id=owner_id,
            mandate=mandate,
            state=state,
            sequence=seq,
            predecessor_hash=pred,
            issued_at=self.now,
            expires_at=self.now + timedelta(hours=12),
            key=key,
        )

    def admit_owner(self, mandate: Mapping[str, Any], *, state: str = "ACTIVE") -> dict[str, Any]:
        record = self.authorization(mandate, key=self.owner_key, state=state)
        self.view.admit(record, mandate, now=self.now)
        return record

    @staticmethod
    def _state(call):
        return {
            "customer_id": call.arguments["customer_id"],
            "request_version": 1,
        }

    @staticmethod
    def _authority(call):
        return {
            "basis": "merchant_refund_workflow",
            "customer_id": call.arguments["customer_id"],
        }

    def guarded(self, draft_mandate: Mapping[str, Any]):
        @authorize_owned(
            policy=self.bundle(draft_mandate),
            mandate_view=self.view,
            mandate_slot_id=self.SLOT_ID,
            tool="process_refund",
            target="refund://process",
            semantics=payment_semantics("amount_cents"),
            state_source=self._state,
            evidence_sources={"refund_authority": self._authority},
            producer_model="mandate-owner-001-agent",
            runtime=self.runtime,
        )
        def process_refund(amount_cents: int, customer_id: str):
            self.effects.append((amount_cents, customer_id))
            return {"refunded_cents": amount_cents, "customer_id": customer_id}

        return process_refund


def _try_refund(harness: Harness, guarded, amount_cents: int = 7_500) -> dict[str, Any]:
    before = len(harness.effects)
    try:
        value = guarded(amount_cents, "C-1")
        return {
            "executed": True,
            "blocked": False,
            "effect_delta": len(harness.effects) - before,
            "value": value,
            "decision": "COMMIT",
            "reason_codes": [],
        }
    except AuthorizationBlocked as exc:
        return {
            "executed": False,
            "blocked": True,
            "effect_delta": len(harness.effects) - before,
            "decision": exc.decision,
            "reason_codes": list(exc.reason_codes),
        }


def _rejected_admission(
    view: MandateOwnerView,
    authorization: Mapping[str, Any],
    mandate: Mapping[str, Any],
    *,
    now: datetime,
) -> tuple[bool, str | None]:
    try:
        view.admit(authorization, mandate, now=now)
    except MandateAuthorityError as exc:
        return True, str(exc)
    return False, None


def run_case_matrix() -> dict[str, Any]:
    h = Harness()
    draft_500 = h.mandate(50_000, version="draft-500")
    draft_100 = h.mandate(10_000, version="owner-100-v1")
    draft_50 = h.mandate(5_000, version="owner-50-v2")
    restore_100 = h.mandate(10_000, version="owner-100-v3")

    rows: list[dict[str, Any]] = []

    # NEW INVARIANT 1: a valid developer-authored mandate proposal has no
    # executable authority merely because it parses and compiles cleanly.
    guarded_500 = h.guarded(draft_500)
    unsigned = _try_refund(h, guarded_500)
    rows.append(
        {
            "case": "developer_authored_valid_mandate_without_owner_admission",
            "claim_class": "NEW_AUTHORSHIP_AUTHORITY_INVARIANT",
            "passed": unsigned["blocked"] and unsigned["effect_delta"] == 0,
            "observed": unsigned,
        }
    )

    # NEW INVARIANT 2: signing with the developer's own key does not promote the
    # draft because the receiver pins Alice's owner key out of band.
    developer_record = h.authorization(
        draft_500,
        key=h.developer_key,
        sequence=1,
        predecessor_hash=None,
    )
    developer_rejected, developer_reason = _rejected_admission(
        h.view, developer_record, draft_500, now=h.now
    )
    after_developer = _try_refund(h, guarded_500)
    rows.append(
        {
            "case": "developer_signed_mandate_wrong_key",
            "claim_class": "NEW_AUTHORSHIP_AUTHORITY_INVARIANT",
            "passed": (
                developer_rejected
                and after_developer["blocked"]
                and after_developer["effect_delta"] == 0
            ),
            "receiver_rejected": developer_rejected,
            "rejection_reason": developer_reason,
            "observed": after_developer,
        }
    )

    # NEW INVARIANT 3: the producing agent cannot sign its own governing mandate.
    agent_record = h.authorization(
        draft_500,
        key=h.agent_key,
        sequence=1,
        predecessor_hash=None,
    )
    agent_rejected, agent_reason = _rejected_admission(
        h.view, agent_record, draft_500, now=h.now
    )
    after_agent = _try_refund(h, guarded_500)
    rows.append(
        {
            "case": "agent_signed_mandate_wrong_key",
            "claim_class": "NEW_AUTHORSHIP_AUTHORITY_INVARIANT",
            "passed": (
                agent_rejected
                and after_agent["blocked"]
                and after_agent["effect_delta"] == 0
            ),
            "receiver_rejected": agent_rejected,
            "rejection_reason": agent_reason,
            "observed": after_agent,
        }
    )

    # NEW INVARIANT 4: the receiver-pinned owner can confer current mandate authority.
    owner_100_record = h.admit_owner(draft_100)
    guarded_old_100 = h.guarded(draft_100)
    owner_100_result = _try_refund(h, guarded_old_100)
    rows.append(
        {
            "case": "pinned_owner_admits_100_dollar_mandate",
            "claim_class": "NEW_AUTHORSHIP_AUTHORITY_INVARIANT",
            "passed": owner_100_result["executed"] and owner_100_result["effect_delta"] == 1,
            "observed": owner_100_result,
        }
    )

    # COMPOSITION WITH #32-STYLE CURRENT-HEAD SEMANTICS: the old owner-signed
    # record remains authentic, but a narrower admitted successor becomes current.
    owner_100_bytes_before = olp_canonical_json(owner_100_record)
    narrow_50_record = h.admit_owner(draft_50)
    del narrow_50_record
    stale_assessment = h.view.assess(owner_100_record, draft_100, now=h.now)
    old_signature_valid, _ = verify_olp_signature(owner_100_record)
    owner_100_bytes_after = olp_canonical_json(owner_100_record)
    stale_old_draft_result = _try_refund(h, guarded_old_100)
    rows.append(
        {
            "case": "old_owner_signed_100_mandate_after_narrowing_to_50",
            "claim_class": "COMPOSITION_WITH_CURRENT_HEAD_SEMANTICS",
            "passed": (
                stale_assessment["verified"]
                and not stale_assessment["current"]
                and old_signature_valid is True
                and owner_100_bytes_before == owner_100_bytes_after
                and stale_old_draft_result["blocked"]
                and stale_old_draft_result["effect_delta"] == 0
            ),
            "historical_authorization_verified": stale_assessment["verified"],
            "historical_authorization_current": stale_assessment["current"],
            "historical_signature_still_valid": old_signature_valid is True,
            "historical_bytes_unchanged": owner_100_bytes_before == owner_100_bytes_after,
            "observed": stale_old_draft_result,
        }
    )

    # COMPOSITION: a later explicit owner act can restore a broader current mandate.
    h.admit_owner(restore_100)
    restored = _try_refund(h, guarded_old_100)
    rows.append(
        {
            "case": "owner_admitted_100_successor_restores_75_action",
            "claim_class": "COMPOSITION_WITH_CURRENT_HEAD_SEMANTICS",
            "passed": restored["executed"] and restored["effect_delta"] == 1,
            "observed": restored,
        }
    )

    standing_admit_reused_unmodified = MandateOwnerView.admit is ReceiverStandingView.admit
    new_owner_validation_path_present = (
        developer_rejected
        and agent_rejected
        and owner_100_result["executed"]
        and MANDATE_AUTHORIZATION_SCHEMA != "openline.standing_projection.v1"
    )
    falsifier_triggered = standing_admit_reused_unmodified or not new_owner_validation_path_present
    passed = all(row["passed"] for row in rows)
    if passed and not falsifier_triggered:
        verdict = VERDICT
    elif passed:
        verdict = EXTENSION_ONLY
    else:
        verdict = NOT_ESTABLISHED

    return {
        "schema": "openline.mandate_owner_001.report.v1",
        "experiment": "MANDATE-OWNER-001",
        "verdict": verdict,
        "claim": CLAIM,
        "passed": passed,
        "case_count": len(rows),
        "rows": rows,
        "falsifier": {
            "kill_condition": (
                "If mandate activation reduces to ReceiverStandingView.admit() "
                "unmodified with no owner-validation path between policy authorship "
                "and AuthorityCompiler, classify this as a #32 extension only."
            ),
            "receiver_standing_admit_reused_unmodified": standing_admit_reused_unmodified,
            "new_owner_validation_path_present": new_owner_validation_path_present,
            "triggered": falsifier_triggered,
        },
        "policy_authority": "NONE",
        "claim_boundary": [
            "The receiver-pinned slot configuration is the trust root for this experiment; the mandate does not authenticate its own owner.",
            "This demonstrates software authority separation, not legal identity, legal authority, fiduciary duty, or a solution to trust-root regress in general.",
            "The first four arms test the new authorship-versus-authority invariant. The final two reuse current-head lifecycle semantics already established by STANDING-SEAM-001.",
            "The benchmark is local and deterministic; distributed persistence, concurrency, crash recovery, and organizational key management remain outside the earned claim.",
        ],
    }


def run_preflight_head_change_case() -> dict[str, Any]:
    """Hostile check: a head change after compile but before effect must block."""
    h = Harness()
    mandate_100 = h.mandate(10_000, version="race-100-v1")
    mandate_50 = h.mandate(5_000, version="race-50-v2")
    h.admit_owner(mandate_100)
    guarded = h.guarded(mandate_100)

    def narrow_between_compile_and_preflight() -> None:
        h.admit_owner(mandate_50)

    h.runtime.before_preflight = narrow_between_compile_and_preflight
    observed = _try_refund(h, guarded)
    return {
        "case": "mandate_head_changes_between_compile_and_preflight",
        "passed": observed["blocked"] and observed["effect_delta"] == 0,
        "observed": observed,
    }


def main() -> int:
    report = run_case_matrix()
    report["hostile_preflight"] = run_preflight_head_change_case()
    report["passed"] = report["passed"] and report["hostile_preflight"]["passed"]
    if not report["passed"] and report["verdict"] == VERDICT:
        report["verdict"] = NOT_ESTABLISHED
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
