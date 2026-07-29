"""Deterministic synthetic x402 transaction fixture.

This helper builds ordinary Receipt Gate requests whose existing COMMIT
authorization carries x402 settlement settings.  It is benchmark scaffolding,
not a network client, facilitator, wallet, or chain simulator.
"""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from olp_gate.adapters import TrustStore
from olp_gate.crypto import public_key_hex, sha256_hex
from olp_gate.demo import _agent_receipt, _source_hash
from olp_gate.evidence import issue_outcome_receipt
from olp_gate.gateway import evaluate_request
from olp_gate.policy import PolicySpec
from olp_gate.session import SessionLedger
from olp_gate.verified_commit import settings_hash
from olp_gate.x402_airlock import (
    X402_AIRLOCK_PROFILE,
    X402_CONFIRMATION_PROFILE,
    X402_POLICY_PROFILE,
    X402_SNAPSHOT_PROFILE,
    payment_hash,
    requirements_hash,
    verification_context_hash,
)


FIXED_NOW = datetime(2026, 7, 28, 8, 0, 0, tzinfo=timezone.utc)
PAYER = "0x1111111111111111111111111111111111111111"
RECIPIENT = "0x2222222222222222222222222222222222222222"
ASSET = (
    "eip155:8453/erc20:"
    "0x3333333333333333333333333333333333333333"
)
PROGRAM = "0x3333333333333333333333333333333333333333"


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def set_path(value: dict[str, Any], path: str, replacement: Any) -> None:
    parts = path.split(".")
    current: dict[str, Any] = value
    for part in parts[:-1]:
        child = current.get(part)
        if not isinstance(child, dict):
            child = {}
            current[part] = child
        current = child
    current[parts[-1]] = replacement


def clean_settings(
    now: datetime = FIXED_NOW,
) -> dict[str, Any]:
    verified_at = iso(now)
    value: dict[str, Any] = {
        "profile": X402_AIRLOCK_PROFILE,
        "requirements": {
            "scheme": "exact",
            "network": "eip155:8453",
            "asset": ASSET,
            "amount_atomic": 100_000,
            "pay_to": RECIPIENT,
            "resource": "resource://weather-report/42",
        },
        "payment": {
            "scheme": "exact",
            "network": "eip155:8453",
            "asset": ASSET,
            "amount_atomic": 100_000,
            "recipient": RECIPIENT,
            "payer": PAYER,
            "signature_model": "eip712",
            "authorization_hash": sha256_hex(
                b"x402-fixture-authorization"
            ),
            "valid_after": iso(now - timedelta(seconds=30)),
            "valid_before": iso(now + timedelta(seconds=120)),
            "nonce": "0x" + "44" * 32,
        },
        "execution": {
            "template_id": "erc3009-transfer-v1",
            "program": PROGRAM,
            "instructions": ["transferWithAuthorization"],
            "accounts": [PAYER, RECIPIENT],
            "signers": [PAYER],
            "fee_atomic": 5_000,
            "gas": 150_000,
            "compute_units": 0,
        },
        "verification": {
            "context_hash": "0" * 64,
            "verified_at": verified_at,
        },
    }
    refresh_verification_context(value)
    return value


def refresh_verification_context(settings: dict[str, Any]) -> None:
    verification = settings.setdefault("verification", {})
    verified_at = str(verification.get("verified_at", ""))
    verification["context_hash"] = verification_context_hash(
        settings,
        verified_at=verified_at,
    )


def clean_x402_policy() -> dict[str, Any]:
    return {
        "profile": X402_POLICY_PROFILE,
        "allowed_schemes": ["exact"],
        "allowed_networks": ["eip155:8453"],
        "allowed_assets": [ASSET],
        "allowed_recipients": [RECIPIENT],
        "allowed_signature_models": ["eip712"],
        "allowed_templates": [
            {
                "template_id": "erc3009-transfer-v1",
                "program": PROGRAM,
                "instructions": ["transferWithAuthorization"],
                "accounts": [PAYER, RECIPIENT],
                "signers": [PAYER],
            }
        ],
        "min_amount_atomic": 1,
        "max_amount_atomic": 1_000_000,
        "max_fee_atomic": 10_000,
        "max_gas": 200_000,
        "max_compute_units": 200_000,
        "min_remaining_validity_seconds": 30,
        "max_snapshot_age_seconds": 5,
    }


def clean_snapshot(
    settings: dict[str, Any],
    *,
    now: datetime = FIXED_NOW,
) -> dict[str, Any]:
    payment = settings["payment"]
    return {
        "profile": X402_SNAPSHOT_PROFILE,
        "checked_at": iso(now),
        "verification_context_hash": settings["verification"][
            "context_hash"
        ],
        "requirements_hash": requirements_hash(settings),
        "payment_hash": payment_hash(settings),
        "authorization_hash": payment["authorization_hash"],
        "authorization_authentic": True,
        "nonce_unused": True,
        "payer_balance_atomic": 500_000,
        "settleable": True,
    }


def clean_confirmation(
    settings: dict[str, Any],
    *,
    confirmed: bool = True,
) -> dict[str, Any]:
    payment = settings["payment"]
    return {
        "profile": X402_CONFIRMATION_PROFILE,
        "confirmed": confirmed,
        "transaction_hash": sha256_hex(b"x402-fixture-transaction"),
        "network": payment["network"],
        "asset": payment["asset"],
        "amount_atomic": payment["amount_atomic"],
        "recipient": payment["recipient"],
        "nonce": payment["nonce"],
    }


class SyntheticX402Fixture:
    """Issue deterministic signed decisions for hostile-case execution."""

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.source_key = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex("71" * 32)
        )
        self.witness_key = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex("72" * 32)
        )
        self.gate_key = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex("73" * 32)
        )
        self.source_method = "did:example:x402-source#key-1"
        self.trust_store = TrustStore.from_mapping(
            {
                "keys": {
                    self.source_method: {
                        "public_key": public_key_hex(self.source_key),
                        "roles": ["source"],
                        "independence": "operator",
                        "controller": "x402-fixture-source",
                    },
                    public_key_hex(self.witness_key): {
                        "public_key": public_key_hex(self.witness_key),
                        "roles": ["outcome"],
                        "independence": "receiver",
                        "controller": "x402-fixture-receiver",
                    },
                }
            }
        )

    @property
    def gate_public_key(self) -> str:
        return public_key_hex(self.gate_key)

    def issue(
        self,
        case_id: str,
        *,
        settings_mutation: tuple[str, Any] | None = None,
        settings_mutations: Sequence[tuple[str, Any]] = (),
        policy_mutation: tuple[str, Any] | None = None,
        policy_mutations: Sequence[tuple[str, Any]] = (),
        permission_seconds: int = 60,
        now: datetime = FIXED_NOW,
    ) -> dict[str, Any]:
        settings = clean_settings(now)
        effective_settings_mutations = list(settings_mutations)
        if settings_mutation is not None:
            effective_settings_mutations.append(settings_mutation)
        for mutation in effective_settings_mutations:
            set_path(settings, *mutation)
        if effective_settings_mutations:
            refresh_verification_context(settings)
        x402_policy = clean_x402_policy()
        effective_policy_mutations = list(policy_mutations)
        if policy_mutation is not None:
            effective_policy_mutations.append(policy_mutation)
        for mutation in effective_policy_mutations:
            set_path(x402_policy, *mutation)

        artifact = self.root / f"{case_id}.json"
        artifact.write_text(
            '{"approved":true,"status":"complete"}\n',
            encoding="utf-8",
        )
        artifact_hash = sha256_hex(artifact.read_bytes())
        run_id = f"run-x402-{case_id}"
        source = _agent_receipt(
            key=self.source_key,
            method=self.source_method,
            chain_id=run_id,
            session_id=f"session-x402-{case_id}",
            action_id=f"action-x402-{case_id}",
            action_type="tool_call",
            response_hash=artifact_hash,
            timestamp=iso(now),
        )
        source_hash = _source_hash(source)
        session = SessionLedger(
            self.root / f"{case_id}-session-ledger.json"
        )
        binding = session.issue_challenge(
            run_id=run_id,
            session_id=f"session-x402-{case_id}",
            expected_source_hash=source_hash,
        )
        outcome = issue_outcome_receipt(
            source_receipt_hash=source_hash,
            outcome_status="pass",
            harmful=False,
            evidence_hash=artifact_hash,
            witness_id="x402-fixture-receiver",
            rollback_supported=True,
            key=self.witness_key,
            observed_at=iso(now),
        )
        action: dict[str, Any] = {
            "tool": "x402.settle",
            "target": "resource://weather-report/42",
            "settings": settings,
            "run_id": run_id,
            "capsule_hash": sha256_hex(
                f"capsule:{case_id}".encode("utf-8")
            ),
            "evidence_hashes": [artifact_hash],
        }
        verified_commit_policy = {
            "required": True,
            "tool": action["tool"],
            "target": action["target"],
            "settings_hash": settings_hash(settings),
            "run_id": run_id,
            "capsule_hash": action["capsule_hash"],
            "evidence_hashes": action["evidence_hashes"],
            "max_ttl_seconds": 120,
        }
        policy = PolicySpec.from_mapping(
            {
                "policy_id": "x402-airlock.receiver-policy",
                "version": "1",
                "require_declared_coverage": True,
                "require_outcome_witness": True,
                "required_evidence_ids": ["result"],
                "evidence_assertions": [
                    {
                        "evidence_id": "result",
                        "path": "approved",
                        "op": "equals",
                        "value": True,
                    }
                ],
                "metadata": {
                    "verified_commit": verified_commit_policy,
                    "x402_airlock": x402_policy,
                },
            }
        )
        code = sha256_hex(f"one-use:{case_id}".encode("utf-8"))
        expiry = now + timedelta(seconds=permission_seconds)
        request = {
            "schema": "openline.proof_to_policy.request.v0.2",
            "request_id": f"request-x402-{case_id}",
            "action_type": "tool_call",
            "claim": (
                "The exact receiver-approved x402 settlement may execute "
                "once after fresh appraisal."
            ),
            "source_receipts": [source],
            "binding": binding,
            "evidence": [
                {
                    "id": "result",
                    "artifact_path": artifact.name,
                    "content_hash": artifact_hash,
                    "source_commitment_path": (
                        "credentialSubject.outcome.response_hash"
                    ),
                }
            ],
            "outcome_receipt": outcome,
            "commit_request": {
                **action,
                "policy_hash": policy.policy_hash,
                "expires_at": iso(expiry),
                "one_use_code": code,
            },
        }
        receipt = evaluate_request(
            request,
            policy=policy,
            trust_store=self.trust_store,
            signing_key=self.gate_key,
            issuer_id="x402-fixture-gate",
            decision_path=self.root / f"{case_id}-decisions.jsonl",
            session_ledger=session,
            base_dir=self.root,
            now=now,
        )
        action["policy_hash"] = policy.policy_hash
        return {
            "receipt": receipt,
            "action": action,
            "code": code,
            "expiry": expiry,
            "settings": settings,
            "x402_policy": x402_policy,
            "snapshot": clean_snapshot(settings, now=now),
            "confirmation": clean_confirmation(settings),
            "gate_public_key": self.gate_public_key,
        }


def clone(value: Any) -> Any:
    return copy.deepcopy(value)


__all__ = [
    "FIXED_NOW",
    "SyntheticX402Fixture",
    "clean_confirmation",
    "clean_settings",
    "clean_snapshot",
    "clean_x402_policy",
    "clone",
    "iso",
    "refresh_verification_context",
    "set_path",
]
