#!/usr/bin/env python3
"""Run and write the frozen WALLET-STANDING-003 distribution receipt."""

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
WALLET002_ROOT = REPO_ROOT / "experiments" / "wallet-standing-002"
for path in (REPO_ROOT, WALLET001_ROOT, WALLET002_ROOT, EXPERIMENT_ROOT):
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
    create_recovery_policy,
    create_root_succession_event,
)
from wallet003 import (  # noqa: E402
    create_guardian_freeze,
    create_root_checkpoint,
    evaluate_distributed_bundle,
    ingest_guardian_freeze,
    ingest_root_checkpoint,
    ingest_root_succession,
    initialize_distributed_gate,
)


VERDICT = (
    "RECEIVED_FREEZE_AND_FORK_QUARANTINE_ENFORCED_"
    "WITH_DECLARED_INFORMATION_LAG"
)
FAIL = "DISTRIBUTED_WALLET_STANDING_BOUNDARY_NOT_ESTABLISHED"
RESULT_PATH = EXPERIMENT_ROOT / "frozen_result.json"
T0 = datetime(2026, 8, 28, 15, 0, 0, tzinfo=timezone.utc)
T_FREEZE = T0 + timedelta(seconds=60)
T_FREEZE_EXPIRES = T_FREEZE + timedelta(seconds=600)
T_SUCCESSION = T0 + timedelta(seconds=150)
T_FORK = T0 + timedelta(seconds=200)
CHALLENGE = "wallet-standing-003-gate"
REQUIRED_FIELDS = ("action", "amount_cents", "recipient")


def _key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"wallet-standing-003:{label}".encode("utf-8")).digest()
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
            f"wallet-standing-003:salt:{self.label}:{self.index}".encode("utf-8")
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
    issued_mandate = issue_mandate(
        epoch_key,
        epoch_certificate,
        mandate_id=mandate_id,
        subject_key=subject_key,
        risk_tier="HIGH",
        fields={**dict(action), "private_purpose": f"private:{mandate_id}"},
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
    return {"bundle": bundle, "action": dict(action)}


def _gate(state, fixture: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
    return evaluate_distributed_bundle(
        state,
        fixture["bundle"],
        expected_action=fixture["action"],
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


def _decision(receipt: Mapping[str, Any], decision: str, reason: str) -> bool:
    return (
        receipt.get("decision") == decision
        and reason in receipt.get("reason_codes", [])
        and int(receipt.get("state_delta", 0)) == 0
    )


def run_frozen() -> dict[str, Any]:
    old_root = _key("principal-root-old")
    successor_root = _key("principal-root-successor")
    fork_root_x = _key("principal-root-fork-x")
    fork_root_y = _key("principal-root-fork-y")
    subject = _key("principal-subject")
    guardians = {
        "guardian-1": _key("guardian-1"),
        "guardian-2": _key("guardian-2"),
        "guardian-3": _key("guardian-3"),
    }
    policy = create_recovery_policy(
        old_root,
        guardians,
        policy_id="wallet-recovery-policy-distributed",
        principal_id="principal-terrynce",
        threshold=2,
        issued_at=T0,
    )
    policy_hash = policy["policy_hash"]

    def gate(name: str, *, virgin: bool = False):
        return initialize_distributed_gate(
            policy,
            trusted_policy_hash=policy_hash,
            gate_id=name,
            requires_checkpoint=virgin,
        )

    compromised = _issue_bundle(
        old_root,
        subject,
        principal_id="principal-terrynce",
        epoch_id="epoch-compromised",
        mandate_id="mandate-compromised",
        action=_action("attacker.example", 9900),
        issued_at=T_FREEZE + timedelta(seconds=5),
    )
    freeze = create_guardian_freeze(
        policy,
        guardians["guardian-1"],
        gate("freeze-template").root_view,
        event_id="guardian-freeze-generation-1",
        guardian_id="guardian-1",
        reason="SUSPECTED_COMPROMISE",
        issued_at=T_FREEZE,
        expires_at=T_FREEZE_EXPIRES,
    )

    gate_a = gate("gate-a")
    gate_a, freeze_a_receipt = ingest_guardian_freeze(
        gate_a, policy, freeze, now=T_FREEZE + timedelta(seconds=5)
    )
    blocked_a = _gate(gate_a, compromised, now=T_FREEZE + timedelta(seconds=10))

    gate_b = gate("gate-b")
    unreceived_b = _gate(
        gate_b, compromised, now=T_FREEZE + timedelta(seconds=10)
    )
    gate_b, freeze_b_receipt = ingest_guardian_freeze(
        gate_b, policy, freeze, now=T_FREEZE + timedelta(seconds=30)
    )
    blocked_b = _gate(gate_b, compromised, now=T_FREEZE + timedelta(seconds=35))

    gate_c = gate("gate-c")
    stale_fixture = _issue_bundle(
        old_root,
        subject,
        principal_id="principal-terrynce",
        epoch_id="epoch-stale-delivery",
        mandate_id="mandate-stale-delivery",
        action=_action("attacker-stale.example", 9800),
        issued_at=T_FREEZE + timedelta(seconds=60),
    )
    gate_c, stale_receipt = ingest_guardian_freeze(
        gate_c, policy, freeze, now=T_FREEZE + timedelta(seconds=61)
    )
    stale_execution = _gate(
        gate_c, stale_fixture, now=T_FREEZE + timedelta(seconds=61)
    )

    original_expiry = gate_a.active_freeze.expires_at if gate_a.active_freeze else None
    replay_state, replay_receipt = ingest_guardian_freeze(
        gate_a, policy, freeze, now=T_FREEZE + timedelta(seconds=6)
    )
    second_freeze = create_guardian_freeze(
        policy,
        guardians["guardian-2"],
        gate("second-freeze-template").root_view,
        event_id="guardian-freeze-second-attempt",
        guardian_id="guardian-2",
        reason="MANUAL_EMERGENCY",
        issued_at=T_FREEZE + timedelta(seconds=1),
        expires_at=T_FREEZE_EXPIRES + timedelta(seconds=1),
    )
    second_state, second_receipt = ingest_guardian_freeze(
        gate_a, policy, second_freeze, now=T_FREEZE + timedelta(seconds=7)
    )
    replay_expiries = {
        original_expiry,
        replay_state.active_freeze.expires_at if replay_state.active_freeze else None,
        second_state.active_freeze.expires_at if second_state.active_freeze else None,
    }

    malicious_gate = gate("gate-malicious-freeze")
    malicious_gate, malicious_receipt = ingest_guardian_freeze(
        malicious_gate, policy, freeze, now=T_FREEZE
    )
    legitimate_at_expiry = _issue_bundle(
        old_root,
        subject,
        principal_id="principal-terrynce",
        epoch_id="epoch-legitimate-expiry",
        mandate_id="mandate-legitimate-expiry",
        action=_action("utility.example", 1400),
        issued_at=T_FREEZE_EXPIRES - timedelta(seconds=30),
    )
    before_expiry = _gate(
        malicious_gate,
        legitimate_at_expiry,
        now=T_FREEZE_EXPIRES - timedelta(seconds=1),
    )
    at_expiry = _gate(
        malicious_gate, legitimate_at_expiry, now=T_FREEZE_EXPIRES
    )

    fake_freeze = create_guardian_freeze(
        policy,
        old_root,
        gate("fake-freeze-template").root_view,
        event_id="old-root-fake-guardian-freeze",
        guardian_id="guardian-1",
        reason="SUSPECTED_COMPROMISE",
        issued_at=T_FREEZE,
        expires_at=T_FREEZE_EXPIRES,
    )
    _unchanged_fake, fake_receipt = ingest_guardian_freeze(
        gate("gate-fake-freeze"),
        policy,
        fake_freeze,
        now=T_FREEZE + timedelta(seconds=5),
    )

    succession = create_root_succession_event(
        policy,
        {
            "guardian-1": guardians["guardian-1"],
            "guardian-2": guardians["guardian-2"],
        },
        event_id="succession-normal",
        prior_root_public_key=public_key_hex(old_root),
        prior_generation=1,
        successor_root_public_key=public_key_hex(successor_root),
        successor_generation=2,
        reason="COMPROMISED",
        effective_at=T_SUCCESSION,
    )
    gate_a, succession_a = ingest_root_succession(
        gate_a, policy, succession, now=T_SUCCESSION
    )
    gate_b, succession_b = ingest_root_succession(
        gate_b, policy, succession, now=T_SUCCESSION
    )
    successor_fixture = _issue_bundle(
        successor_root,
        subject,
        principal_id="principal-terrynce",
        epoch_id="epoch-successor",
        mandate_id="mandate-successor",
        action=_action("merchant.example", 2500),
        issued_at=T_SUCCESSION + timedelta(seconds=1),
    )
    successor_a = _gate(
        gate_a, successor_fixture, now=T_SUCCESSION + timedelta(seconds=2)
    )
    successor_b = _gate(
        gate_b, successor_fixture, now=T_SUCCESSION + timedelta(seconds=2)
    )

    virgin = gate("gate-virgin", virgin=True)
    virgin_old_block = _gate(
        virgin, compromised, now=T_FREEZE + timedelta(seconds=10)
    )
    virgin, virgin_succession = ingest_root_succession(
        virgin, policy, succession, now=T_SUCCESSION
    )
    virgin_successor_block = _gate(
        virgin, successor_fixture, now=T_SUCCESSION + timedelta(seconds=2)
    )
    checkpoint = create_root_checkpoint(
        policy,
        {
            "guardian-1": guardians["guardian-1"],
            "guardian-2": guardians["guardian-2"],
        },
        virgin.root_view,
        checkpoint_id="checkpoint-successor",
        issued_at=T_SUCCESSION + timedelta(seconds=2),
        expires_at=T_SUCCESSION + timedelta(seconds=122),
    )
    virgin, checkpoint_receipt = ingest_root_checkpoint(
        virgin,
        policy,
        checkpoint,
        now=T_SUCCESSION + timedelta(seconds=3),
    )
    virgin_successor_pass = _gate(
        virgin, successor_fixture, now=T_SUCCESSION + timedelta(seconds=4)
    )

    checkpoint_base = gate("gate-checkpoint-variants", virgin=True)
    checkpoint_base, _ = ingest_root_succession(
        checkpoint_base, policy, succession, now=T_SUCCESSION
    )
    tampered_checkpoint = copy.deepcopy(checkpoint)
    tampered_checkpoint["body"]["root_public_key"] = public_key_hex(old_root)
    _, checkpoint_tampered = ingest_root_checkpoint(
        checkpoint_base,
        policy,
        tampered_checkpoint,
        now=T_SUCCESSION + timedelta(seconds=3),
    )
    _, checkpoint_stale = ingest_root_checkpoint(
        checkpoint_base,
        policy,
        checkpoint,
        now=T_SUCCESSION + timedelta(seconds=63),
    )
    one_guardian_checkpoint = create_root_checkpoint(
        policy,
        {"guardian-1": guardians["guardian-1"]},
        checkpoint_base.root_view,
        checkpoint_id="checkpoint-one-guardian",
        issued_at=T_SUCCESSION + timedelta(seconds=2),
        expires_at=T_SUCCESSION + timedelta(seconds=122),
    )
    _, checkpoint_threshold = ingest_root_checkpoint(
        checkpoint_base,
        policy,
        one_guardian_checkpoint,
        now=T_SUCCESSION + timedelta(seconds=3),
    )

    fork_event_x = create_root_succession_event(
        policy,
        {
            "guardian-1": guardians["guardian-1"],
            "guardian-2": guardians["guardian-2"],
        },
        event_id="succession-fork-x",
        prior_root_public_key=public_key_hex(old_root),
        prior_generation=1,
        successor_root_public_key=public_key_hex(fork_root_x),
        successor_generation=2,
        reason="COMPROMISED",
        effective_at=T_FORK,
    )
    fork_event_y = create_root_succession_event(
        policy,
        {
            "guardian-2": guardians["guardian-2"],
            "guardian-3": guardians["guardian-3"],
        },
        event_id="succession-fork-y",
        prior_root_public_key=public_key_hex(old_root),
        prior_generation=1,
        successor_root_public_key=public_key_hex(fork_root_y),
        successor_generation=2,
        reason="COMPROMISED",
        effective_at=T_FORK,
    )
    fork_gate_x = gate("gate-fork-x")
    fork_gate_y = gate("gate-fork-y")
    fork_gate_x, fork_x_accept = ingest_root_succession(
        fork_gate_x, policy, fork_event_x, now=T_FORK
    )
    fork_gate_y, fork_y_accept = ingest_root_succession(
        fork_gate_y, policy, fork_event_y, now=T_FORK
    )
    fork_fixture_x = _issue_bundle(
        fork_root_x,
        subject,
        principal_id="principal-terrynce",
        epoch_id="epoch-fork-x",
        mandate_id="mandate-fork-x",
        action=_action("fork-x.example", 3100),
        issued_at=T_FORK + timedelta(seconds=1),
    )
    fork_fixture_y = _issue_bundle(
        fork_root_y,
        subject,
        principal_id="principal-terrynce",
        epoch_id="epoch-fork-y",
        mandate_id="mandate-fork-y",
        action=_action("fork-y.example", 3200),
        issued_at=T_FORK + timedelta(seconds=1),
    )
    partition_x = _gate(
        fork_gate_x, fork_fixture_x, now=T_FORK + timedelta(seconds=2)
    )
    partition_y = _gate(
        fork_gate_y, fork_fixture_y, now=T_FORK + timedelta(seconds=2)
    )
    fork_gate_x, fork_x_detect = ingest_root_succession(
        fork_gate_x, policy, fork_event_y, now=T_FORK + timedelta(seconds=3)
    )
    fork_gate_y, fork_y_detect = ingest_root_succession(
        fork_gate_y, policy, fork_event_x, now=T_FORK + timedelta(seconds=3)
    )
    post_fork_x = _gate(
        fork_gate_x, fork_fixture_x, now=T_FORK + timedelta(seconds=4)
    )
    post_fork_y = _gate(
        fork_gate_y, fork_fixture_y, now=T_FORK + timedelta(seconds=4)
    )

    checkpoint_variants_pass = (
        _decision(checkpoint_tampered, "REJECT_CHECKPOINT", "CHECKPOINT_ROOT_MISMATCH")
        and _decision(checkpoint_stale, "REJECT_CHECKPOINT", "CHECKPOINT_STALE")
        and _decision(
            checkpoint_threshold,
            "REJECT_CHECKPOINT",
            "CHECKPOINT_THRESHOLD_NOT_MET",
        )
    )
    fork_pass = (
        fork_x_accept.get("decision") == "ACCEPT_SUCCESSION"
        and fork_y_accept.get("decision") == "ACCEPT_SUCCESSION"
        and partition_x.get("decision") == "PASS"
        and partition_y.get("decision") == "PASS"
        and fork_x_detect.get("decision") == "FORK_DETECTED"
        and fork_y_detect.get("decision") == "FORK_DETECTED"
        and post_fork_x.get("decision") == "BLOCK"
        and post_fork_y.get("decision") == "BLOCK"
        and fork_gate_x.root_view.current_root_public_key != fork_gate_y.root_view.current_root_public_key
    )

    rows = [
        _row(
            "01_fresh_single_guardian_freeze",
            "One precommitted guardian sends a fresh reduce-only freeze to Gate A",
            "ACCEPT_FREEZE",
            freeze_a_receipt,
            freeze_a_receipt.get("decision") == "ACCEPT_FREEZE",
        ),
        _row(
            "02_received_freeze_blocks_old_root",
            "The compromised old root acts after Gate A receives the freeze",
            "BLOCK:GUARDIAN_FREEZE_ACTIVE",
            blocked_a,
            blocked_a.get("decision") == "BLOCK"
            and "GUARDIAN_FREEZE_ACTIVE" in blocked_a.get("reason_codes", []),
        ),
        _row(
            "03_unreceived_freeze_information_lag",
            "Gate B evaluates the same old-root action before the freeze arrives",
            "PASS:DECLARED_INFORMATION_LAG",
            unreceived_b,
            unreceived_b.get("decision") == "PASS",
            declared_exposure=True,
        ),
        _row(
            "04_fresh_cross_delivery_blocks",
            "Gate B receives the still-fresh freeze and evaluates again",
            "ACCEPT_FREEZE_THEN_BLOCK",
            {"ingest": freeze_b_receipt, "execution": blocked_b},
            freeze_b_receipt.get("decision") == "ACCEPT_FREEZE"
            and blocked_b.get("decision") == "BLOCK",
        ),
        _row(
            "05_stale_freeze_is_not_backdated",
            "Gate C first sees the freeze after its maximum delivery age",
            "REJECT_FREEZE_THEN_PASS:DECLARED_INFORMATION_LAG",
            {"ingest": stale_receipt, "execution": stale_execution},
            _decision(stale_receipt, "REJECT_FREEZE", "FREEZE_STALE")
            and stale_execution.get("decision") == "PASS",
            declared_exposure=True,
        ),
        _row(
            "06_freeze_replay_cannot_extend",
            "Exact replay and a second guardian freeze target the used generation",
            "REJECT_BOTH:NO_EXPIRY_EXTENSION",
            {
                "exact_replay": replay_receipt,
                "second_event": second_receipt,
                "observed_expiries": sorted(value for value in replay_expiries if value),
            },
            _decision(replay_receipt, "REJECT_FREEZE", "FREEZE_REPLAYED")
            and _decision(
                second_receipt,
                "REJECT_FREEZE",
                "FREEZE_GENERATION_ALREADY_USED",
            )
            and len(replay_expiries) == 1,
        ),
        _row(
            "07_malicious_guardian_bounded_dos",
            "One guardian freezes a legitimate action until the receiver ceiling",
            "BLOCK:DECLARED_BOUNDED_DOS",
            {"ingest": malicious_receipt, "execution": before_expiry},
            malicious_receipt.get("decision") == "ACCEPT_FREEZE"
            and before_expiry.get("decision") == "BLOCK",
            declared_exposure=True,
        ),
        _row(
            "08_exact_expiry_restores_current_root",
            "No quorum recovers the root, so the one-shot freeze expires exactly on schedule",
            "PASS:DECLARED_RISK_RESUMPTION",
            at_expiry,
            at_expiry.get("decision") == "PASS",
            declared_exposure=True,
        ),
        _row(
            "09_old_root_cannot_fake_guardian",
            "The compromised root signs a freeze while claiming a configured guardian id",
            "REJECT_FREEZE:GUARDIAN_SIGNER_MISMATCH",
            fake_receipt,
            _decision(
                fake_receipt,
                "REJECT_FREEZE",
                "FREEZE_GUARDIAN_SIGNER_MISMATCH",
            ),
        ),
        _row(
            "10_quorum_succession_clears_freeze",
            "A two-of-three succession arrives while Gates A and B are frozen",
            "ACCEPT_SUCCESSION:CLEAR_FREEZE",
            {"gate_a": succession_a, "gate_b": succession_b},
            succession_a.get("decision") == "ACCEPT_SUCCESSION"
            and succession_b.get("decision") == "ACCEPT_SUCCESSION"
            and succession_a.get("freeze_cleared") is True
            and succession_b.get("freeze_cleared") is True
            and gate_a.active_freeze is None
            and gate_b.active_freeze is None,
        ),
        _row(
            "11_successor_executes_after_quorum",
            "Both receivers admit a fresh bundle rooted in generation 2",
            "PASS_BOTH",
            {"gate_a": successor_a, "gate_b": successor_b},
            successor_a.get("decision") == "PASS"
            and successor_b.get("decision") == "PASS",
        ),
        _row(
            "12_virgin_gate_requires_checkpoint",
            "A virgin Gate blocks both genesis and successor bundles until a fresh quorum checkpoint",
            "BLOCK_BOTH:CURRENT_ROOT_CHECKPOINT_REQUIRED",
            {
                "before_lineage": virgin_old_block,
                "succession": virgin_succession,
                "after_lineage": virgin_successor_block,
            },
            virgin_old_block.get("decision") == "BLOCK"
            and virgin_succession.get("decision") == "ACCEPT_SUCCESSION"
            and virgin_successor_block.get("decision") == "BLOCK"
            and "CURRENT_ROOT_CHECKPOINT_REQUIRED"
            in virgin_successor_block.get("reason_codes", []),
        ),
        _row(
            "13_fresh_quorum_checkpoint_admits_known_root",
            "The virgin Gate already knows the lineage, then receives a matching fresh two-of-three checkpoint",
            "ACCEPT_CHECKPOINT_THEN_PASS",
            {"checkpoint": checkpoint_receipt, "execution": virgin_successor_pass},
            checkpoint_receipt.get("decision") == "ACCEPT_CHECKPOINT"
            and virgin_successor_pass.get("decision") == "PASS",
        ),
        _row(
            "14_checkpoint_tamper_stale_and_threshold",
            "Altered-root, stale, and one-guardian checkpoints are presented",
            "REJECT_ALL",
            {
                "tampered": checkpoint_tampered,
                "stale": checkpoint_stale,
                "below_threshold": checkpoint_threshold,
            },
            checkpoint_variants_pass,
        ),
        _row(
            "15_partitioned_quorum_fork_quarantine",
            "Two Gates execute different valid branches during a partition, then cross-deliver and quarantine",
            "PASS_DURING_PARTITION_THEN_BLOCK_BOTH",
            {
                "branch_x_accept": fork_x_accept,
                "branch_y_accept": fork_y_accept,
                "partition_x": partition_x,
                "partition_y": partition_y,
                "cross_delivery_x": fork_x_detect,
                "cross_delivery_y": fork_y_detect,
                "post_detection_x": post_fork_x,
                "post_detection_y": post_fork_y,
                "automatic_resolution": "NONE",
            },
            fork_pass,
            declared_exposure=True,
        ),
    ]

    passed = all(row["passed"] for row in rows)
    metrics = {
        "arm_count": len(rows),
        "passed_arm_count": sum(int(row["passed"]) for row in rows),
        "freeze_received_old_root_execution_count": sum(
            receipt.get("decision") == "PASS" for receipt in (blocked_a, blocked_b)
        ),
        "freeze_unreceived_old_root_execution_count": int(
            unreceived_b.get("decision") == "PASS"
        ),
        "stale_freeze_old_root_execution_count": int(
            stale_execution.get("decision") == "PASS"
        ),
        "freeze_replay_extension_seconds": 0 if len(replay_expiries) == 1 else 1,
        "malicious_guardian_dos_seconds": 600,
        "post_expiry_legitimate_execution_count": int(
            at_expiry.get("decision") == "PASS"
        ),
        "post_quorum_successor_execution_count": sum(
            receipt.get("decision") == "PASS" for receipt in (successor_a, successor_b)
        ),
        "virgin_without_checkpoint_execution_count": sum(
            receipt.get("decision") == "PASS"
            for receipt in (virgin_old_block, virgin_successor_block)
        ),
        "virgin_with_checkpoint_execution_count": int(
            virgin_successor_pass.get("decision") == "PASS"
        ),
        "partitioned_conflicting_branch_execution_count": sum(
            receipt.get("decision") == "PASS" for receipt in (partition_x, partition_y)
        ),
        "post_fork_detection_execution_count": sum(
            receipt.get("decision") == "PASS" for receipt in (post_fork_x, post_fork_y)
        ),
        "automatic_convergence_count": 0,
        "fork_quarantine_count": sum(
            state.fork_quarantined for state in (fork_gate_x, fork_gate_y)
        ),
    }
    return {
        "schema": "openline.wallet_standing_003.result.v1",
        "experiment_id": "WALLET-STANDING-003",
        "generated_at": "2026-08-28T15:20:00Z",
        "verdict": VERDICT if passed else FAIL,
        "passed": passed,
        "wallet_policy_authority": "NONE",
        "freeze_authority": "ONE_PRECOMMITTED_GUARDIAN_REDUCE_ONLY",
        "succession_authority": "PRECOMMITTED_GUARDIAN_QUORUM",
        "decision_authority": "RECEIVER_GATE",
        "metrics": metrics,
        "rows": rows,
        "explicit_boundaries": [
            "This is a deterministic event-delivery schedule, not a real network, device, guardian-custody, or witness-distribution test.",
            "A receiver cannot enforce a freeze it has not received; fresh and stale delivery exposures are recorded rather than rewritten as prevention.",
            "One malicious guardian can deny high-risk execution for 600 seconds, and current-root risk resumes at exact expiry when quorum recovery does not arrive.",
            "The freeze is nonrenewable within one root generation; a valid quorum succession installs a successor and clears the prior freeze.",
            "A virgin Gate needs the succession lineage plus a fresh quorum checkpoint; the checkpoint confirms an already-known view and cannot install a root.",
            "Two valid same-generation quorum branches may each execute during a partition; cross-observation quarantines both and requires external resolution.",
            "A compromised guardian threshold remains the trust floor established in WALLET-STANDING-002 and is not retested or solved here.",
            "The wallet has policy authority NONE; guardians may reduce or redirect only within the precommitted recovery policy, and the receiver Gate owns consequences.",
        ],
        "conclusion": (
            "Received emergency freezes stop old-root effects without granting a single "
            "guardian succession power. Distribution delay remains execution exposure, "
            "and conflicting valid recoveries quarantine instead of claiming automatic "
            "consensus."
        ),
    }


def main() -> int:
    result = run_frozen()
    RESULT_PATH.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(result["verdict"])
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
