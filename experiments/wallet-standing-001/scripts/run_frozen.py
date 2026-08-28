#!/usr/bin/env python3
"""Run and write the frozen WALLET-STANDING-001 ten-arm receipt."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import copy
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


EXPERIMENT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = EXPERIMENT_ROOT.parents[1]
for path in (REPO_ROOT, EXPERIMENT_ROOT):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from olp_gate.crypto import public_key_hex, sign_olp_body  # noqa: E402
from wallet001 import (  # noqa: E402
    AdmissionPolicy,
    build_presentation_bundle,
    evaluate_bundle,
    issue_epoch_certificate,
    issue_mandate,
    issue_standing_witness,
)


VERDICT = "EPOCH_REVOCATION_ENFORCED_WITH_BOUNDED_OFFLINE_LAG"
FAIL = "WALLET_STANDING_BOUNDARY_NOT_ESTABLISHED"
RESULT_PATH = EXPERIMENT_ROOT / "frozen_result.json"
T0 = datetime(2026, 8, 28, 12, 0, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(minutes=5)
HIGH_CHALLENGE = "wallet-standing-001-high"
LOW_CHALLENGE = "wallet-standing-001-low"


def _key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"wallet-standing-001:{label}".encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


class FrozenSaltSource:
    """Deterministic fixture entropy; production defaults to secrets.token_bytes."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.index = 0

    def __call__(self, size: int) -> bytes:
        if size != 32:
            raise ValueError("frozen salt source supports only 32-byte salts")
        value = hashlib.sha256(
            f"wallet-standing-001:salt:{self.label}:{self.index}".encode("utf-8")
        ).digest()
        self.index += 1
        return value


def _issue_fixture() -> dict[str, Any]:
    root = _key("principal-root")
    epoch1 = _key("epoch-1")
    epoch2 = _key("epoch-2")
    sibling_epoch = _key("epoch-sibling")
    subject = _key("subject")
    salt_registries = {
        "epoch-1": set(),
        "epoch-2": set(),
        "epoch-sibling": set(),
    }

    epoch1_certificate = issue_epoch_certificate(
        root,
        epoch1,
        principal_id="principal-terrynce",
        epoch_id="epoch-1",
        sequence=1,
        branch="operational",
        issued_at=T0,
        expires_at=T0 + timedelta(days=1),
    )
    epoch2_certificate = issue_epoch_certificate(
        root,
        epoch2,
        principal_id="principal-terrynce",
        epoch_id="epoch-2",
        sequence=2,
        branch="operational",
        predecessor_epoch_id="epoch-1",
        issued_at=T1,
        expires_at=T0 + timedelta(days=1),
    )
    sibling_certificate = issue_epoch_certificate(
        root,
        sibling_epoch,
        principal_id="principal-terrynce",
        epoch_id="epoch-sibling",
        sequence=1,
        branch="independent",
        issued_at=T0,
        expires_at=T0 + timedelta(days=1),
    )

    high_fields = {
        "action": "transfer",
        "amount_cents": 7500,
        "recipient": "merchant.example",
        "private_purpose": "invoice-77",
    }
    sibling_fields = {
        "action": "transfer",
        "amount_cents": 250,
        "recipient": "utility.example",
        "private_purpose": "account-44",
    }
    low_fields = {
        "action": "archive",
        "record_id": "record-R1",
        "retention_days": 30,
        "private_note": "synthetic-private-value",
    }
    high1 = issue_mandate(
        epoch1,
        epoch1_certificate,
        mandate_id="mandate-high-epoch-1",
        subject_key=subject,
        risk_tier="HIGH",
        fields=high_fields,
        issued_at=T0,
        expires_at=T0 + timedelta(minutes=30),
        epoch_salt_registry=salt_registries["epoch-1"],
        salt_source=FrozenSaltSource("mandate-high-epoch-1"),
    )
    high2 = issue_mandate(
        epoch2,
        epoch2_certificate,
        mandate_id="mandate-high-epoch-2",
        subject_key=subject,
        risk_tier="HIGH",
        fields=high_fields,
        issued_at=T1,
        expires_at=T0 + timedelta(minutes=30),
        epoch_salt_registry=salt_registries["epoch-2"],
        salt_source=FrozenSaltSource("mandate-high-epoch-2"),
    )
    sibling = issue_mandate(
        sibling_epoch,
        sibling_certificate,
        mandate_id="mandate-high-sibling",
        subject_key=subject,
        risk_tier="HIGH",
        fields=sibling_fields,
        issued_at=T0,
        expires_at=T0 + timedelta(minutes=30),
        epoch_salt_registry=salt_registries["epoch-sibling"],
        salt_source=FrozenSaltSource("mandate-high-sibling"),
    )
    low1 = issue_mandate(
        epoch1,
        epoch1_certificate,
        mandate_id="mandate-low-epoch-1",
        subject_key=subject,
        risk_tier="LOW",
        fields=low_fields,
        issued_at=T0,
        expires_at=T0 + timedelta(minutes=10),
        epoch_salt_registry=salt_registries["epoch-1"],
        salt_source=FrozenSaltSource("mandate-low-epoch-1"),
    )

    active_epoch1 = issue_standing_witness(
        root,
        epoch1_certificate,
        standing="ACTIVE",
        sequence=1,
        issued_at=T0,
        expires_at=T0 + timedelta(hours=1),
    )
    revoked_epoch1 = issue_standing_witness(
        root,
        epoch1_certificate,
        standing="REVOKED",
        sequence=2,
        issued_at=T1,
        expires_at=T1 + timedelta(hours=1),
    )
    active_epoch2 = issue_standing_witness(
        root,
        epoch2_certificate,
        standing="ACTIVE",
        sequence=1,
        issued_at=T1,
        expires_at=T1 + timedelta(hours=1),
    )
    active_sibling = issue_standing_witness(
        root,
        sibling_certificate,
        standing="ACTIVE",
        sequence=1,
        issued_at=T1,
        expires_at=T1 + timedelta(hours=1),
    )
    return {
        "root": root,
        "subject": subject,
        "high1": high1,
        "high2": high2,
        "sibling": sibling,
        "low1": low1,
        "active_epoch1": active_epoch1,
        "revoked_epoch1": revoked_epoch1,
        "active_epoch2": active_epoch2,
        "active_sibling": active_sibling,
        "high_action": {
            "action": "transfer",
            "amount_cents": 7500,
            "recipient": "merchant.example",
        },
        "sibling_action": {
            "action": "transfer",
            "amount_cents": 250,
            "recipient": "utility.example",
        },
        "low_action": {
            "action": "archive",
            "record_id": "record-R1",
            "retention_days": 30,
        },
    }


def _policy(fields: tuple[str, ...]) -> AdmissionPolicy:
    return AdmissionPolicy(
        high_risk_max_witness_age_seconds=60,
        low_risk_max_offline_ttl_seconds=600,
        required_fields=fields,
        forbid_extra_disclosures=True,
    )


def _bundle(
    issued,
    *,
    fields: tuple[str, ...],
    subject: Ed25519PrivateKey,
    challenge: str,
    witness,
) -> dict[str, Any]:
    return build_presentation_bundle(
        issued,
        disclose_fields=fields,
        subject_key=subject,
        receiver_challenge=challenge,
        standing_witness=witness,
    )


def _evaluate(
    bundle: dict[str, Any],
    *,
    root_key: Ed25519PrivateKey,
    action: MappingLike,
    challenge: str,
    now: datetime,
    policy: AdmissionPolicy,
) -> dict[str, Any]:
    return evaluate_bundle(
        bundle,
        trusted_root_public_key=public_key_hex(root_key),
        expected_action=action,
        receiver_challenge=challenge,
        now=now,
        policy=policy,
    )


MappingLike = dict[str, Any]


def _row(
    arm_id: str,
    condition: str,
    expected_decision: str,
    observed: dict[str, Any],
    *,
    expected_reason: str | None = None,
    declared_exposure: bool = False,
) -> dict[str, Any]:
    passed = observed.get("decision") == expected_decision
    if expected_reason is not None:
        passed = passed and expected_reason in observed.get("reason_codes", [])
    return {
        "arm_id": arm_id,
        "condition": condition,
        "expected_decision": expected_decision,
        "expected_reason": expected_reason,
        "declared_exposure": declared_exposure,
        "observed": observed,
        "passed": passed,
    }


def _tamper_arm(
    fixture: dict[str, Any],
    base_bundle: dict[str, Any],
    high_policy: AdmissionPolicy,
) -> dict[str, Any]:
    variants: dict[str, dict[str, Any]] = {}

    altered = copy.deepcopy(base_bundle)
    amount_entry = next(
        item
        for item in altered["projection"]["disclosures"]
        if item["field_path"] == "amount_cents"
    )
    amount_entry["value"] = 7600
    variants["altered_disclosed_value"] = _evaluate(
        altered,
        root_key=fixture["root"],
        action={**fixture["high_action"], "amount_cents": 7600},
        challenge=HIGH_CHALLENGE,
        now=T0 + timedelta(seconds=30),
        policy=high_policy,
    )

    proof_tamper = copy.deepcopy(base_bundle)
    proof_entry = proof_tamper["projection"]["disclosures"][0]
    proof_entry["proof"][0]["hash"] = "00" * 32
    variants["altered_merkle_sibling"] = _evaluate(
        proof_tamper,
        root_key=fixture["root"],
        action=fixture["high_action"],
        challenge=HIGH_CHALLENGE,
        now=T0 + timedelta(seconds=30),
        policy=high_policy,
    )

    bearer = copy.deepcopy(base_bundle)
    holder_body = dict(bearer["holder_proof"])
    holder_body.pop("signature")
    holder_body.pop("payload_hash")
    bearer["holder_proof"] = sign_olp_body(holder_body, _key("intruder"))
    variants["copied_bearer_bundle"] = _evaluate(
        bearer,
        root_key=fixture["root"],
        action=fixture["high_action"],
        challenge=HIGH_CHALLENGE,
        now=T0 + timedelta(seconds=30),
        policy=high_policy,
    )

    variants["replayed_holder_challenge"] = _evaluate(
        base_bundle,
        root_key=fixture["root"],
        action=fixture["high_action"],
        challenge="wallet-standing-001-other-gate",
        now=T0 + timedelta(seconds=30),
        policy=high_policy,
    )
    required_reasons = {
        "altered_disclosed_value": "MERKLE_PROOF_INVALID",
        "altered_merkle_sibling": "MERKLE_PROOF_INVALID",
        "copied_bearer_bundle": "HOLDER_PROOF_SIGNER_MISMATCH",
        "replayed_holder_challenge": "HOLDER_CHALLENGE_MISMATCH",
    }
    passed = all(
        value.get("decision") == "BLOCK"
        and required_reasons[name] in value.get("reason_codes", [])
        for name, value in variants.items()
    )
    return {
        "arm_id": "10_projection_and_holder_tampering",
        "condition": "Altered field, altered proof, copied bearer bundle, and replayed challenge",
        "expected_decision": "BLOCK_ALL",
        "expected_reason": "VARIANT_SPECIFIC",
        "declared_exposure": False,
        "observed": {
            "decision": "BLOCK_ALL" if passed else "VARIANT_FAILURE",
            "executed": any(value.get("executed") for value in variants.values()),
            "effect_delta": sum(int(value.get("effect_delta", 0)) for value in variants.values()),
            "variants": variants,
        },
        "passed": passed,
    }


def run_frozen() -> dict[str, Any]:
    fixture = _issue_fixture()
    high_fields = ("action", "amount_cents", "recipient")
    low_fields = ("action", "record_id", "retention_days")
    high_policy = _policy(high_fields)
    low_policy = _policy(low_fields)

    high_active = _bundle(
        fixture["high1"],
        fields=high_fields,
        subject=fixture["subject"],
        challenge=HIGH_CHALLENGE,
        witness=fixture["active_epoch1"],
    )
    high_revoked = _bundle(
        fixture["high1"],
        fields=high_fields,
        subject=fixture["subject"],
        challenge=HIGH_CHALLENGE,
        witness=fixture["revoked_epoch1"],
    )
    high_no_witness = _bundle(
        fixture["high1"],
        fields=high_fields,
        subject=fixture["subject"],
        challenge=HIGH_CHALLENGE,
        witness=None,
    )
    successor = _bundle(
        fixture["high2"],
        fields=high_fields,
        subject=fixture["subject"],
        challenge=HIGH_CHALLENGE,
        witness=fixture["active_epoch2"],
    )
    sibling = _bundle(
        fixture["sibling"],
        fields=high_fields,
        subject=fixture["subject"],
        challenge=HIGH_CHALLENGE,
        witness=fixture["active_sibling"],
    )
    low_no_witness = _bundle(
        fixture["low1"],
        fields=low_fields,
        subject=fixture["subject"],
        challenge=LOW_CHALLENGE,
        witness=None,
    )

    rows = [
        _row(
            "01_high_fresh_active",
            "Epoch 1 with a fresh ACTIVE witness",
            "PASS",
            _evaluate(
                high_active,
                root_key=fixture["root"],
                action=fixture["high_action"],
                challenge=HIGH_CHALLENGE,
                now=T0 + timedelta(seconds=30),
                policy=high_policy,
            ),
        ),
        _row(
            "02_high_fresh_revoked",
            "Epoch 1 after revocation with a fresh REVOKED witness",
            "BLOCK",
            _evaluate(
                high_revoked,
                root_key=fixture["root"],
                action=fixture["high_action"],
                challenge=HIGH_CHALLENGE,
                now=T1 + timedelta(seconds=10),
                policy=high_policy,
            ),
            expected_reason="EPOCH_REVOKED",
        ),
        _row(
            "03_high_stale_active_witness",
            "Old ACTIVE witness beyond the receiver freshness budget",
            "BLOCK",
            _evaluate(
                high_active,
                root_key=fixture["root"],
                action=fixture["high_action"],
                challenge=HIGH_CHALLENGE,
                now=T1 + timedelta(seconds=10),
                policy=high_policy,
            ),
            expected_reason="FRESHNESS_REQUIRED",
        ),
        _row(
            "04_high_missing_witness",
            "High-risk presentation carries no standing witness",
            "BLOCK",
            _evaluate(
                high_no_witness,
                root_key=fixture["root"],
                action=fixture["high_action"],
                challenge=HIGH_CHALLENGE,
                now=T1 + timedelta(seconds=10),
                policy=high_policy,
            ),
            expected_reason="FRESHNESS_REQUIRED",
        ),
        _row(
            "05_high_successor_epoch",
            "Fresh epoch-2 successor with a fresh ACTIVE witness",
            "PASS",
            _evaluate(
                successor,
                root_key=fixture["root"],
                action=fixture["high_action"],
                challenge=HIGH_CHALLENGE,
                now=T1 + timedelta(seconds=10),
                policy=high_policy,
            ),
        ),
        _row(
            "06_high_independent_root_sibling",
            "Independent root-certified sibling remains active",
            "PASS",
            _evaluate(
                sibling,
                root_key=fixture["root"],
                action=fixture["sibling_action"],
                challenge=HIGH_CHALLENGE,
                now=T1 + timedelta(seconds=10),
                policy=high_policy,
            ),
        ),
        _row(
            "07_low_within_ttl_no_witness",
            "Low-risk mandate within its 600-second TTL and no witness",
            "PASS",
            _evaluate(
                low_no_witness,
                root_key=fixture["root"],
                action=fixture["low_action"],
                challenge=LOW_CHALLENGE,
                now=T0 + timedelta(seconds=60),
                policy=low_policy,
            ),
        ),
        _row(
            "08_low_revoked_but_unexpired_offline",
            "Epoch 1 is revoked externally, but the offline low-risk bundle carries no post-export witness and remains unexpired",
            "PASS",
            _evaluate(
                low_no_witness,
                root_key=fixture["root"],
                action=fixture["low_action"],
                challenge=LOW_CHALLENGE,
                now=T1 + timedelta(seconds=30),
                policy=low_policy,
            ),
            declared_exposure=True,
        ),
        _row(
            "09_low_at_expiry_no_witness",
            "The same low-risk mandate reaches its exact expiry",
            "BLOCK",
            _evaluate(
                low_no_witness,
                root_key=fixture["root"],
                action=fixture["low_action"],
                challenge=LOW_CHALLENGE,
                now=T0 + timedelta(seconds=600),
                policy=low_policy,
            ),
            expected_reason="MANDATE_EXPIRED",
        ),
        _tamper_arm(fixture, high_active, high_policy),
    ]

    issued_mandates = [
        fixture["high1"],
        fixture["high2"],
        fixture["sibling"],
        fixture["low1"],
    ]
    salts = [salt for issued in issued_mandates for salt in issued.salts.values()]
    salt_invariants = {
        "salt_count": len(salts),
        "unique_salt_count": len(set(salts)),
        "duplicate_salt_count": len(salts) - len(set(salts)),
        "salt_bytes": 32,
        "production_default": "secrets.token_bytes",
        "frozen_fixture_entropy": "deterministic-unique-test-fixture",
        "passed": len(salts) == len(set(salts))
        and all(len(bytes.fromhex(salt)) == 32 for salt in salts),
    }
    high_hostile = rows[1:4]
    high_risk_stale_executions = sum(
        int(row["observed"].get("effect_delta", 0)) for row in high_hostile
    )
    collateral_loss = int(rows[5]["observed"].get("decision") != "PASS")
    passed = all(row["passed"] for row in rows) and salt_invariants["passed"]

    return {
        "schema": "openline.wallet_standing_001.result.v1",
        "experiment_id": "WALLET-STANDING-001",
        "verdict": VERDICT if passed else FAIL,
        "passed": passed,
        "policy_authority": "NONE",
        "decision_authority": "RECEIVER_GATE",
        "root_public_key": public_key_hex(fixture["root"]),
        "frozen_times": {
            "t0_export": T0.isoformat().replace("+00:00", "Z"),
            "t1_epoch_revocation": T1.isoformat().replace("+00:00", "Z"),
        },
        "receiver_policy": {
            "high_risk_max_witness_age_seconds": 60,
            "low_risk_max_offline_ttl_seconds": 600,
            "unexpected_disclosures": "BLOCK",
        },
        "rows": rows,
        "metrics": {
            "arm_count": len(rows),
            "passed_arm_count": sum(int(row["passed"]) for row in rows),
            "high_risk_stale_execution_count": high_risk_stale_executions,
            "collateral_loss_count": collateral_loss,
            "declared_low_risk_stale_pass_count": int(
                rows[7]["observed"].get("decision") == "PASS"
            ),
            "offline_exposure_ceiling_seconds": 600,
        },
        "salt_invariants": salt_invariants,
        "earned_claim": (
            "Given a controlled signed standing witness, a receiver-owned Gate enforces epoch revocation within its declared freshness budget. "
            "Offline low-risk authority remains usable only for its frozen signed lifetime, and revoking one epoch leaves an independent root-certified sibling intact."
        ),
        "explicit_boundaries": [
            "Witness creation is controlled and local. Distribution, replication, cross-device delivery, and availability are untested.",
            "The principal root remains intact. Root loss, compromise, recovery quorum, and root succession are untested.",
            "The low-risk expiry-only arm intentionally accepts an unexpired stale bundle after an unseen revocation; the maximum admitted lag is the receiver's 600-second TTL ceiling.",
            "The Merkle surface covers top-level integer-profile JSON fields. It provides selective disclosure and integrity, not unlinkability or hidden predicates.",
            "Frozen deterministic salts exist only for reproducibility. The protocol default uses independent secrets.token_bytes(32) values and requires an epoch-scoped registry that rejects reuse across mandates.",
            "The wallet bundle carries evidence of a signed mandate and holder possession. It never grants itself policy authority; the receiver Gate owns the consequence decision."
        ],
        "next_falsifiers": {
            "WALLET-STANDING-002": "Root loss and compromise, threshold recovery, root succession, and history preservation.",
            "WALLET-STANDING-003": "Real witness propagation across devices and a virgin Gate under delay, partition, replay, and equivocation."
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
