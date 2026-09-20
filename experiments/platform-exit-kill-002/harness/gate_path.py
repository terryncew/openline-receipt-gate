"""Shared gate-path helpers for PLATFORM-EXIT-KILL-002.

Ports the proven proof-to-policy -> VerifiedCommitLedger path from
tests/test_stop_standing_integration.py (the frozen A/B/C/D shape), plus
mandate/effect builders and the independently observable effect executor.
Harness only; zero product-code changes.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from olp_gate.adapters import TrustStore
from olp_gate.crypto import (
    public_key_hex,
    sha256_hex,
    sign_olp_body,
    verify_olp_signature,
)
from olp_gate._durable_heads import DurableHeadStore
from olp_gate.demo import _agent_receipt, _source_hash
from olp_gate.evidence import issue_outcome_receipt
from olp_gate.gateway import evaluate_request
from olp_gate.mandate import (
    MandateSpec,
    compile_verified_commit_settings,
    validate_effect,
)
from olp_gate.mandate_gate import mandate_preflight
from olp_gate.mandate_gate import execute_mandated_once
from olp_gate.mandate_owner import MandateOwnerView
from olp_gate.policy import PolicySpec
from olp_gate.session import SessionLedger
from olp_gate.stop_standing import owner_mandate_stop_check
from olp_gate.verified_commit import VerifiedCommitLedger, settings_hash


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(Path(path).read_text(encoding="utf-8").strip())
    )


def write_private_key(path: str | Path, key: Ed25519PrivateKey) -> None:
    raw = key.private_bytes_raw().hex() if hasattr(key, "private_bytes_raw") else None
    if raw is None:  # pragma: no cover - defensive
        from cryptography.hazmat.primitives import serialization

        raw = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ).hex()
    Path(path).write_text(raw + "\n", encoding="utf-8")


def build_mandate(agent_id: str, mandate_id: str = "platform-exit-job") -> dict:
    return {
        "profile": "principal_mandate/v1",
        "mandate_id": mandate_id,
        "principal_id": "owner",
        "agent_id": agent_id,
        "purpose": "platform exit study job",
        "allowed_action_types": ["authorize_payment"],
        "allowed_targets": ["payments://ledger"],
        "allowed_disclosure_classes": [],
        "forbidden_disclosure_classes": [],
        "max_settlement_cents": 0,
        "max_payment_cents": 10_000,
        "delegation_allowed": False,
        "expires_at": "2030-01-01T00:00:00Z",
        "version": "v1",
    }


def build_effect(
    mandate: Mapping[str, Any], effect_id: str, value_cents: int = 60
) -> dict:
    return validate_effect(
        {
            "profile": "principal_effect/v1",
            "effect_id": effect_id,
            "mandate_id": mandate["mandate_id"],
            "principal_id": mandate["principal_id"],
            "agent_id": mandate["agent_id"],
            "purpose": mandate["purpose"],
            "action_type": "authorize_payment",
            "target": "payments://ledger",
            "disclosures": [],
            "value_cents": value_cents,
            "delegatee": None,
            "producer_model": f"platform-exit-worker/{mandate['agent_id']}",
        }
    )


class GatePath:
    """The receiver's existing authorization path, driven by a worker process.

    Holds the receiver-side gate key, the outcome witness key, and the
    agent's source key. Issues one signed proof-to-policy decision receipt
    per attempt and executes the mandated consequence through
    execute_mandated_once.
    """

    def __init__(
        self,
        *,
        root: Path,
        run_now: datetime,
        gate_key: Ed25519PrivateKey,
        witness_key: Ed25519PrivateKey,
        source_key: Ed25519PrivateKey,
        source_method: str,
        witness_id: str = "platform-exit-receiver",
    ) -> None:
        self.root = root
        self.run_now = run_now
        self.gate_key = gate_key
        self.witness_key = witness_key
        self.source_key = source_key
        self.source_method = source_method
        self.witness_id = witness_id
        self.store = TrustStore.from_mapping(
            {
                "keys": {
                    source_method: {
                        "public_key": public_key_hex(source_key),
                        "roles": ["source"],
                        "independence": "operator",
                        "controller": f"platform-exit-{source_method}",
                    },
                    public_key_hex(witness_key): {
                        "public_key": public_key_hex(witness_key),
                        "roles": ["outcome"],
                        "independence": "receiver",
                        "controller": "platform-exit-receiver",
                    },
                }
            }
        )

    def issue_decision_receipt(
        self,
        attempt_id: str,
        settings: Mapping[str, Any],
        tool: str = "authorize_payment",
        target: str = "payments://ledger",
    ) -> tuple[dict, dict, str]:
        """Port of the frozen _issue() shape from test_stop_standing_integration."""
        now = self.run_now
        artifacts = self.root / "artifacts"
        artifacts.mkdir(parents=True, exist_ok=True)
        artifact = artifacts / f"{attempt_id}.json"
        artifact.write_text(
            json.dumps(
                {"approved": True, "attempt": attempt_id, "status": "complete"},
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        artifact_hash = sha256_hex(artifact.read_bytes())
        run_id = f"run-{attempt_id}"
        source = _agent_receipt(
            key=self.source_key,
            method=self.source_method,
            chain_id=run_id,
            session_id=f"session-{attempt_id}",
            action_id=f"action-{attempt_id}",
            action_type="tool_call",
            response_hash=artifact_hash,
            timestamp=iso(now),
        )
        source_hash = _source_hash(source)
        session = SessionLedger(self.root / "sessions" / f"{attempt_id}.json")
        binding = session.issue_challenge(
            run_id=run_id,
            session_id=f"session-{attempt_id}",
            expected_source_hash=source_hash,
        )
        outcome = issue_outcome_receipt(
            source_receipt_hash=source_hash,
            outcome_status="pass",
            harmful=False,
            evidence_hash=artifact_hash,
            witness_id=self.witness_id,
            rollback_supported=True,
            key=self.witness_key,
        )
        action = {
            "tool": tool,
            "target": target,
            "settings": dict(settings),
            "run_id": run_id,
            "capsule_hash": sha256_hex(f"capsule:{attempt_id}".encode("utf-8")),
            "evidence_hashes": [artifact_hash],
        }
        policy = PolicySpec.from_mapping(
            {
                "policy_id": "platform-exit.receiver-policy",
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
                    "verified_commit": {
                        "required": True,
                        "tool": action["tool"],
                        "target": action["target"],
                        "settings_hash": settings_hash(settings),
                        "run_id": run_id,
                        "capsule_hash": action["capsule_hash"],
                        "evidence_hashes": action["evidence_hashes"],
                        "max_ttl_seconds": 120,
                    }
                },
            }
        )
        code = sha256_hex(f"one-use:{attempt_id}".encode("utf-8"))[:64]
        request = {
            "schema": "openline.proof_to_policy.request.v0.2",
            "request_id": f"request-{attempt_id}",
            "action_type": "tool_call",
            "claim": "The exact receiver-approved action may execute once.",
            "source_receipts": [source],
            "binding": binding,
            "evidence": [
                {
                    "id": "result",
                    "artifact_path": f"artifacts/{attempt_id}.json",
                    "content_hash": artifact_hash,
                    "source_commitment_path": "credentialSubject.outcome.response_hash",
                }
            ],
            "outcome_receipt": outcome,
            "commit_request": {
                **action,
                "policy_hash": policy.policy_hash,
                "expires_at": iso(now + timedelta(seconds=60)),
                "one_use_code": code,
            },
        }
        receipt = evaluate_request(
            request,
            policy=policy,
            trust_store=self.store,
            signing_key=self.gate_key,
            issuer_id="platform-exit-test-gate",
            decision_path=self.root / "decisions" / f"{attempt_id}.jsonl",
            session_ledger=session,
            base_dir=self.root,
            now=now,
        )
        action["policy_hash"] = policy.policy_hash
        return receipt, action, code


def make_executor(
    effects_dir: Path, agent_id: str, case: str, attempt_id: str, effect_id: str
):
    """The protected consequence: an independently observable effect marker."""
    effects_dir.mkdir(parents=True, exist_ok=True)
    marker = effects_dir / f"{attempt_id}.json"

    def executor():
        marker.write_text(
            json.dumps(
                {
                    "agent_id": agent_id,
                    "case": case,
                    "attempt_id": attempt_id,
                    "effect_id": effect_id,
                    "committed": True,
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        return {"effect": attempt_id, "agent_id": agent_id}

    return marker, executor


def attest_attempt(
    worker_key: Ed25519PrivateKey, agent_id: str, attempt_id: str, effect_hash: str
) -> dict:
    """Harness-level worker attestation: the agent signs its own attempt.

    This is NOT product authority (the receiver never gates on it); it is
    receipt-level attribution evidence so the appraiser can check A-era vs
    B-era attempts against the agents' distinct public keys.
    """
    body = {
        "schema": "openline.platform-exit.worker_attestation.v1",
        "agent_id": agent_id,
        "attempt_id": attempt_id,
        "effect_hash": effect_hash,
    }
    return sign_olp_body(body, worker_key)


def check_attestation(
    attestation: Mapping[str, Any],
    expected_agent_id: str,
    expected_pubkey: str,
    expected_effect_hash: str,
) -> tuple[bool, str | None]:
    valid, reason = verify_olp_signature(attestation)
    if valid is not True:
        return False, f"attestation_signature_invalid:{reason}"
    sig = attestation.get("signature") or {}
    if str(sig.get("public_key", "")).lower() != expected_pubkey.lower():
        return False, "attestation_key_mismatch"
    if attestation.get("agent_id") != expected_agent_id:
        return False, "attestation_agent_mismatch"
    if attestation.get("effect_hash") != expected_effect_hash:
        return False, "attestation_effect_hash_mismatch"
    return True, None
