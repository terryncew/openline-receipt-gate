#!/usr/bin/env python3
"""Run and write the frozen WALLET-STANDING-002 root succession receipt."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


EXPERIMENT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = EXPERIMENT_ROOT.parents[1]
WALLET001_ROOT = REPO_ROOT / "experiments" / "wallet-standing-001"
for path in (REPO_ROOT, WALLET001_ROOT, EXPERIMENT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from olp_gate.crypto import public_key_hex  # noqa: E402
from wallet001 import (  # noqa: E402
    AdmissionPolicy,
    build_presentation_bundle,
    issue_epoch_certificate,
    issue_mandate,
    issue_standing_witness,
)
from wallet002 import (  # noqa: E402
    accept_root_succession,
    create_recovery_policy,
    create_root_succession_event,
    evaluate_current_root_bundle,
    initialize_root_view,
    verify_historical_epoch_certificate,
)


VERDICT = "QUORUM_ROOT_SUCCESSION_ENFORCED_WITH_DECLARED_RECOVERY_LAG"
FAIL = "ROOT_SUCCESSION_BOUNDARY_NOT_ESTABLISHED"
RESULT_PATH = EXPERIMENT_ROOT / "frozen_result.json"
T0 = datetime(2026, 8, 28, 13, 0, 0, tzinfo=timezone.utc)
T_COMPROMISE = T0 + timedelta(minutes=1)
T_RECOVERY = T0 + timedelta(minutes=6)
RECOVERY_LAG_SECONDS = 300
CHALLENGE = "wallet-standing-002-gate"
REQUIRED_FIELDS = ("action", "amount_cents", "recipient")


def _key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"wallet-standing-002:{label}".encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


class FrozenSaltSource:
    """Deterministic fixture entropy; production issuance remains random."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.index = 0

    def __call__(self, size: int) -> bytes:
        if size != 32:
            raise ValueError("frozen salt source supports only 32-byte salts")
        value = hashlib.sha256(
            f"wallet-standing-002:salt:{self.label}:{self.index}".encode("utf-8")
        ).digest()
        self.index += 1
        return value


def _admission_policy() -> AdmissionPolicy:
    return AdmissionPolicy(
        high_risk_max_witness_age_seconds=60,
        low_risk_max_offline_ttl_seconds=600,
        required_fields=REQUIRED_FIELDS,
        forbid_extra_disclosures=True,
    )


def _action(recipient: str, amount_cents: int) -> dict[str, Any]:
    return {
        "action": "transfer",
        "amount_cents": amount_cents,
        "recipient": recipient,
    }


def _issue_bundle(
    root_key: Ed25519PrivateKey,
    subject_key: Ed25519PrivateKey,
    *,
    principal_id: str,
    epoch_id: str,
    mandate_id: str,
    action: Mapping[str, Any],
    issued_at: datetime,
) -> dict[str, Any]:
    epoch_key = _key(f"epoch:{epoch_id}")
    epoch_certificate = issue_epoch_certificate(
        root_key,
        epoch_key,
        principal_id=principal_id,
        epoch_id=epoch_id,
        sequence=1,
        issued_at=issued_at,
        expires_at=T0 + timedelta(days=1),
    )
    fields = {
        **dict(action),
        "private_purpose": f"private:{mandate_id}",
    }
    issued_mandate = issue_mandate(
        epoch_key,
        epoch_certificate,
        mandate_id=mandate_id,
        subject_key=subject_key,
        risk_tier="HIGH",
        fields=fields,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=30),
        epoch_salt_registry=set(),
        salt_source=FrozenSaltSource(mandate_id),
    )
    witness = issue_standing_witness(
        root_key,
        epoch_certificate,
        standing="ACTIVE",
        sequence=1,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(hours=1),
    )
    bundle = build_presentation_bundle(
        issued_mandate,
        disclose_fields=REQUIRED_FIELDS,
        subject_key=subject_key,
        receiver_challenge=CHALLENGE,
        standing_witness=witness,
    )
    return {
        "epoch_certificate": epoch_certificate,
        "issued_mandate": issued_mandate,
        "bundle": bundle,
        "action": dict(action),
    }


def _gate(view, bundle_fixture: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
    return evaluate_current_root_bundle(
        view,
        bundle_fixture["bundle"],
        expected_action=bundle_fixture["action"],
        receiver_challenge=CHALLENGE,
        now=now,
        policy=_admission_policy(),
    )


def _row(
    arm_id: str,
    condition: str,
    expected: str,
    observed: Mapping[str, Any],
    passed: bool,
    *,
    declared_exposure: bool = False,
) -> dict[str, Any]:
    return {
        "arm_id": arm_id,
        "condition": condition,
        "expected": expected,
        "declared_exposure": declared_exposure,
        "observed": dict(observed),
        "passed": bool(passed),
    }


def _rejected(receipt: Mapping[str, Any], reason: str) -> bool:
    return (
        receipt.get("decision") == "REJECT_SUCCESSION"
        and receipt.get("accepted") is False
        and reason in receipt.get("reason_codes", [])
        and receipt.get("state_delta") == 0
    )


def run_frozen() -> dict[str, Any]:
    old_root = _key("principal-root-old")
    successor_root = _key("principal-root-successor")
    attacker_root = _key("principal-root-attacker")
    subject = _key("principal-subject")
    guardians = {
        "guardian-1": _key("guardian-1"),
        "guardian-2": _key("guardian-2"),
        "guardian-3": _key("guardian-3"),
    }
    policy = create_recovery_policy(
        old_root,
        guardians,
        policy_id="wallet-recovery-policy-1",
        principal_id="principal-terrynce",
        threshold=2,
        issued_at=T0,
    )
    pinned_policy_hash = policy["policy_hash"]
    genesis_view = initialize_root_view(
        policy,
        trusted_policy_hash=pinned_policy_hash,
    )

    legitimate_action = _action("merchant.example", 7500)
    compromised_action = _action("attacker.example", 9000)
    successor_action = _action("utility.example", 1200)
    unrelated_action = _action("supplier.example", 500)

    legitimate_old = _issue_bundle(
        old_root,
        subject,
        principal_id="principal-terrynce",
        epoch_id="epoch-old-legitimate",
        mandate_id="mandate-old-legitimate",
        action=legitimate_action,
        issued_at=T0,
    )
    compromised_old = _issue_bundle(
        old_root,
        subject,
        principal_id="principal-terrynce",
        epoch_id="epoch-old-compromised",
        mandate_id="mandate-old-compromised",
        action=compromised_action,
        issued_at=T_COMPROMISE,
    )

    root_self_event = create_root_succession_event(
        policy,
        {"guardian-1": old_root},
        event_id="succession-root-self-claim",
        prior_root_public_key=public_key_hex(old_root),
        prior_generation=1,
        successor_root_public_key=public_key_hex(successor_root),
        successor_generation=2,
        reason="COMPROMISED",
        effective_at=T_RECOVERY,
    )
    one_guardian_event = create_root_succession_event(
        policy,
        {"guardian-1": guardians["guardian-1"]},
        event_id="succession-one-guardian",
        prior_root_public_key=public_key_hex(old_root),
        prior_generation=1,
        successor_root_public_key=public_key_hex(successor_root),
        successor_generation=2,
        reason="LOST",
        effective_at=T_RECOVERY,
    )
    duplicate_guardian_event = copy.deepcopy(one_guardian_event)
    duplicate_guardian_event["approvals"].append(
        copy.deepcopy(duplicate_guardian_event["approvals"][0])
    )
    valid_event = create_root_succession_event(
        policy,
        {
            "guardian-1": guardians["guardian-1"],
            "guardian-2": guardians["guardian-2"],
        },
        event_id="succession-valid-quorum",
        prior_root_public_key=public_key_hex(old_root),
        prior_generation=1,
        successor_root_public_key=public_key_hex(successor_root),
        successor_generation=2,
        reason="COMPROMISED",
        effective_at=T_RECOVERY,
    )

    _same_view, root_self_receipt = accept_root_succession(
        genesis_view, policy, root_self_event, now=T_RECOVERY
    )
    _same_view, one_guardian_receipt = accept_root_succession(
        genesis_view, policy, one_guardian_event, now=T_RECOVERY
    )
    _same_view, duplicate_guardian_receipt = accept_root_succession(
        genesis_view, policy, duplicate_guardian_event, now=T_RECOVERY
    )
    successor_view, valid_receipt = accept_root_succession(
        genesis_view, policy, valid_event, now=T_RECOVERY
    )

    successor_bundle = _issue_bundle(
        successor_root,
        subject,
        principal_id="principal-terrynce",
        epoch_id="epoch-successor",
        mandate_id="mandate-successor",
        action=successor_action,
        issued_at=T_RECOVERY,
    )

    unrelated_root = _key("unrelated-root")
    unrelated_subject = _key("unrelated-subject")
    unrelated_guardians = {
        "other-guardian-1": _key("other-guardian-1"),
        "other-guardian-2": _key("other-guardian-2"),
        "other-guardian-3": _key("other-guardian-3"),
    }
    unrelated_policy = create_recovery_policy(
        unrelated_root,
        unrelated_guardians,
        policy_id="wallet-recovery-policy-unrelated",
        principal_id="principal-unrelated",
        threshold=2,
        issued_at=T0,
    )
    unrelated_view = initialize_root_view(
        unrelated_policy,
        trusted_policy_hash=unrelated_policy["policy_hash"],
    )
    unrelated_bundle = _issue_bundle(
        unrelated_root,
        unrelated_subject,
        principal_id="principal-unrelated",
        epoch_id="epoch-unrelated",
        mandate_id="mandate-unrelated",
        action=unrelated_action,
        issued_at=T_RECOVERY,
    )

    before_legitimate = _gate(
        genesis_view,
        legitimate_old,
        now=T0 + timedelta(seconds=30),
    )
    before_compromised = _gate(
        genesis_view,
        compromised_old,
        now=T_COMPROMISE + timedelta(seconds=30),
    )
    after_compromised = _gate(
        successor_view,
        compromised_old,
        now=T_RECOVERY + timedelta(seconds=10),
    )
    after_legitimate = _gate(
        successor_view,
        legitimate_old,
        now=T_RECOVERY + timedelta(seconds=10),
    )
    historical = verify_historical_epoch_certificate(
        successor_view,
        legitimate_old["epoch_certificate"],
    )
    successor_execution = _gate(
        successor_view,
        successor_bundle,
        now=T_RECOVERY + timedelta(seconds=10),
    )
    unrelated_execution = _gate(
        unrelated_view,
        unrelated_bundle,
        now=T_RECOVERY + timedelta(seconds=10),
    )

    altered_event = copy.deepcopy(valid_event)
    altered_event["body"]["successor_root_public_key"] = public_key_hex(attacker_root)
    _same_view, altered_receipt = accept_root_succession(
        genesis_view,
        policy,
        altered_event,
        now=T_RECOVERY,
    )
    _same_view, replay_receipt = accept_root_succession(
        successor_view,
        policy,
        valid_event,
        now=T_RECOVERY + timedelta(seconds=1),
    )
    rollback_event = create_root_succession_event(
        policy,
        {
            "guardian-1": guardians["guardian-1"],
            "guardian-2": guardians["guardian-2"],
        },
        event_id="succession-rollback-old-root",
        prior_root_public_key=public_key_hex(successor_root),
        prior_generation=2,
        successor_root_public_key=public_key_hex(old_root),
        successor_generation=3,
        reason="LOST",
        effective_at=T_RECOVERY + timedelta(seconds=1),
    )
    _same_view, rollback_receipt = accept_root_succession(
        successor_view,
        policy,
        rollback_event,
        now=T_RECOVERY + timedelta(seconds=1),
    )
    tamper_variants = {
        "altered_successor_after_signature": altered_receipt,
        "exact_event_replay": replay_receipt,
        "rollback_to_superseded_root": rollback_receipt,
    }
    tamper_expected = {
        "altered_successor_after_signature": "SUCCESSION_EVENT_HASH_INVALID",
        "exact_event_replay": "SUCCESSION_REPLAYED",
        "rollback_to_superseded_root": "ROOT_ROLLBACK_FORBIDDEN",
    }
    tamper_passed = all(
        _rejected(tamper_variants[name], reason)
        for name, reason in tamper_expected.items()
    )

    threshold_compromise_event = create_root_succession_event(
        policy,
        {
            "guardian-1": guardians["guardian-1"],
            "guardian-2": guardians["guardian-2"],
        },
        event_id="succession-threshold-compromise",
        prior_root_public_key=public_key_hex(old_root),
        prior_generation=1,
        successor_root_public_key=public_key_hex(attacker_root),
        successor_generation=2,
        reason="COMPROMISED",
        effective_at=T_RECOVERY,
    )
    _attacker_view, threshold_compromise_receipt = accept_root_succession(
        genesis_view,
        policy,
        threshold_compromise_event,
        now=T_RECOVERY,
    )

    rows = [
        _row(
            "01_genesis_root_legitimate_action",
            "A legitimate high-risk action under the pinned generation-1 root",
            "PASS",
            before_legitimate,
            before_legitimate.get("decision") == "PASS",
        ),
        _row(
            "02_compromised_root_before_recovery_acceptance",
            "The compromised root creates a new epoch, mandate, and ACTIVE witness before the Gate learns a succession",
            "PASS:DECLARED_PRE_ACCEPTANCE_EXPOSURE",
            before_compromised,
            before_compromised.get("decision") == "PASS",
            declared_exposure=True,
        ),
        _row(
            "03_old_root_self_declares_successor",
            "The compromised old root signs while posing as one configured guardian",
            "REJECT:GUARDIAN_APPROVAL_SIGNER_MISMATCH",
            root_self_receipt,
            _rejected(root_self_receipt, "GUARDIAN_APPROVAL_SIGNER_MISMATCH"),
        ),
        _row(
            "04_one_of_three_guardians",
            "One genuine guardian attempts recovery under a two-of-three policy",
            "REJECT:RECOVERY_THRESHOLD_NOT_MET",
            one_guardian_receipt,
            _rejected(one_guardian_receipt, "RECOVERY_THRESHOLD_NOT_MET"),
        ),
        _row(
            "05_duplicate_guardian_approval",
            "One genuine approval is copied to appear twice",
            "REJECT:DUPLICATE_GUARDIAN_APPROVAL",
            duplicate_guardian_receipt,
            _rejected(duplicate_guardian_receipt, "DUPLICATE_GUARDIAN_APPROVAL"),
        ),
        _row(
            "06_valid_two_of_three_root_succession",
            "Two precommitted guardians install generation 2 without an old-root signature",
            "ACCEPT_SUCCESSION",
            valid_receipt,
            valid_receipt.get("decision") == "ACCEPT_SUCCESSION"
            and successor_view.current_generation == 2,
        ),
        _row(
            "07_compromised_descendant_after_acceptance",
            "The exact compromised-root bundle is replayed after generation 2 is accepted",
            "BLOCK:EPOCH_CERTIFICATE_SIGNER_MISMATCH",
            after_compromised,
            after_compromised.get("decision") == "BLOCK"
            and "EPOCH_CERTIFICATE_SIGNER_MISMATCH"
            in after_compromised.get("reason_codes", []),
        ),
        _row(
            "08_legitimate_old_descendant_after_acceptance",
            "A pre-compromise legitimate bundle under the old root is also noncurrent",
            "BLOCK:EPOCH_CERTIFICATE_SIGNER_MISMATCH",
            after_legitimate,
            after_legitimate.get("decision") == "BLOCK"
            and "EPOCH_CERTIFICATE_SIGNER_MISMATCH"
            in after_legitimate.get("reason_codes", []),
        ),
        _row(
            "09_old_history_remains_authentic_noncurrent",
            "The old epoch certificate remains cryptographically authentic for history only",
            "HISTORICALLY_AUTHENTIC_NONCURRENT",
            historical,
            historical.get("status") == "HISTORICALLY_AUTHENTIC_NONCURRENT"
            and historical.get("execution_authority") == "NONE",
        ),
        _row(
            "10_successor_root_action",
            "Generation 2 issues a fresh epoch, mandate, and standing witness",
            "PASS",
            successor_execution,
            successor_execution.get("decision") == "PASS",
        ),
        _row(
            "11_unrelated_principal_control",
            "An independent principal remains current and executable",
            "PASS",
            unrelated_execution,
            unrelated_execution.get("decision") == "PASS",
        ),
        _row(
            "12_tamper_replay_and_rollback",
            "Altered successor, exact replay, and rollback to a superseded root",
            "REJECT_ALL",
            {
                "decision": "REJECT_ALL" if tamper_passed else "VARIANT_FAILURE",
                "accepted": any(
                    receipt.get("accepted") is True
                    for receipt in tamper_variants.values()
                ),
                "state_delta": sum(
                    int(receipt.get("state_delta", 0))
                    for receipt in tamper_variants.values()
                ),
                "variants": tamper_variants,
            },
            tamper_passed,
        ),
        _row(
            "13_recovery_threshold_compromise",
            "Two compromised guardian keys sign an attacker root; the valid quorum is indistinguishable from legitimate recovery",
            "ACCEPT_SUCCESSION:DECLARED_TRUST_FLOOR",
            threshold_compromise_receipt,
            threshold_compromise_receipt.get("decision") == "ACCEPT_SUCCESSION",
            declared_exposure=True,
        ),
    ]

    pre_accept_effects = int(before_compromised.get("effect_delta", 0))
    post_accept_effects = int(after_compromised.get("effect_delta", 0)) + int(
        after_legitimate.get("effect_delta", 0)
    )
    below_threshold_acceptances = sum(
        int(receipt.get("accepted") is True)
        for receipt in (
            root_self_receipt,
            one_guardian_receipt,
            duplicate_guardian_receipt,
        )
    )
    passed = all(row["passed"] for row in rows)
    return {
        "schema": "openline.wallet_standing_002.result.v1",
        "experiment_id": "WALLET-STANDING-002",
        "verdict": VERDICT if passed else FAIL,
        "passed": passed,
        "wallet_policy_authority": "NONE",
        "succession_authority": "PRECOMMITTED_GUARDIAN_QUORUM",
        "decision_authority": "RECEIVER_GATE",
        "frozen_times": {
            "t0_policy_pinned": T0.isoformat().replace("+00:00", "Z"),
            "t1_root_compromise": T_COMPROMISE.isoformat().replace("+00:00", "Z"),
            "t2_succession_accepted": T_RECOVERY.isoformat().replace("+00:00", "Z"),
        },
        "recovery_policy": {
            "policy_hash": pinned_policy_hash,
            "guardian_count": 3,
            "threshold": 2,
            "rotation": "FROZEN",
        },
        "rows": rows,
        "metrics": {
            "arm_count": len(rows),
            "passed_arm_count": sum(int(row["passed"]) for row in rows),
            "recovery_lag_seconds": RECOVERY_LAG_SECONDS,
            "pre_acceptance_compromised_root_execution_count": pre_accept_effects,
            "post_acceptance_old_root_execution_count": post_accept_effects,
            "below_threshold_acceptance_count": below_threshold_acceptances,
            "successor_execution_count": int(
                successor_execution.get("effect_delta", 0)
            ),
            "unrelated_principal_collateral_loss_count": int(
                unrelated_execution.get("decision") != "PASS"
            ),
            "historically_authentic_noncurrent_count": int(
                historical.get("status")
                == "HISTORICALLY_AUTHENTIC_NONCURRENT"
            ),
            "declared_threshold_compromise_acceptance_count": int(
                threshold_compromise_receipt.get("accepted") is True
            ),
        },
        "earned_claim": (
            "Given a recovery policy pinned before compromise and a receiver that has accepted a valid two-of-three guardian event, "
            "the receiver supersedes the old root, blocks all of its descendants from new execution, admits a fresh successor, "
            "preserves old signatures as historical evidence, and leaves an unrelated principal untouched."
        ),
        "explicit_boundaries": [
            "The compromised root retains full practical authority until the receiver accepts a succession event; actions already executed during that lag are not undone.",
            "The recovery quorum is the higher trust anchor. A threshold compromise produces a cryptographically valid attacker succession and is accepted in the declared boundary arm.",
            "Guardian keys, policy creation, and succession delivery are controlled fixtures. Real custody, identity proofing, coercion, death, and availability are untested.",
            "This is one receiver with one linear root view. Distribution to a virgin Gate, cross-device freshness, competing valid successions, and convergence are deferred to WALLET-STANDING-003.",
            "Recovery-policy rotation and guardian replacement are frozen and untested.",
            "Root succession invalidates every descendant of the superseded root, including legitimate old mandates. Selectivity exists across principals, not within the compromised root's descendants.",
            "Historical authenticity does not restore execution standing. Old records remain evidence-only.",
            "The wallet carries continuity evidence but has policy authority NONE; the receiver Gate owns the consequence decision."
        ],
        "next_falsifier": {
            "experiment_id": "WALLET-STANDING-003",
            "question": "Can two devices and a virgin Gate converge on one current root under delayed, missing, replayed, and conflicting succession delivery without silently accepting a stale fork?"
        },
    }


def main() -> int:
    result = run_frozen()
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    RESULT_PATH.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
