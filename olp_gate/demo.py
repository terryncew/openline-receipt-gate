"""Five discriminating proof-to-policy demonstrations."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .adapters import TrustStore
from .crypto import jcs_integer_canonical_json, public_key_hex, sha256_hex
from .evidence import issue_outcome_receipt
from .gateway import evaluate_request, verify_decision_log
from .policy import PolicySpec
from .session import SessionLedger


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _u64(value: bytes) -> str:
    return "u" + base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _agent_receipt(
    *,
    key: Ed25519PrivateKey,
    method: str,
    chain_id: str,
    session_id: str,
    action_id: str,
    action_type: str,
    response_hash: str,
    timestamp: str | None = None,
    risk_level: str = "medium",
) -> dict[str, Any]:
    observed_at = timestamp or _iso_now()
    body: dict[str, Any] = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://agentreceipts.ai/context/v2",
        ],
        "id": f"urn:receipt:{action_id}",
        "type": ["VerifiableCredential", "AgentReceipt"],
        "version": "0.5.0",
        "issuer": {
            "id": "did:example:demo-agent",
            "type": "AIAgent",
            "session_id": session_id,
        },
        "issuanceDate": observed_at,
        "credentialSubject": {
            "principal": {"id": "did:example:demo-user", "type": "HumanPrincipal"},
            "action": {
                "id": action_id,
                "type": action_type,
                "risk_level": risk_level,
                "timestamp": observed_at,
            },
            "outcome": {
                "status": "success",
                "reversible": action_type == "memory_write",
                "response_hash": "sha256:" + response_hash,
            },
            "chain": {
                "sequence": 1,
                "previous_receipt_hash": None,
                "chain_id": chain_id,
                "terminal": True,
                "status": "complete",
            },
        },
    }
    signature = key.sign(jcs_integer_canonical_json(body))
    return {
        **body,
        "proof": {
            "type": "Ed25519Signature2020",
            "created": observed_at,
            "verificationMethod": method,
            "proofPurpose": "assertionMethod",
            "proofValue": _u64(signature),
        },
    }


def _source_hash(receipt: dict[str, Any]) -> str:
    body = dict(receipt)
    body.pop("proof", None)
    return sha256_hex(jcs_integer_canonical_json(body))


def _request(
    *,
    request_id: str,
    receipt: dict[str, Any],
    binding: dict[str, Any],
    action_type: str,
    claim: str,
    evidence: list[dict[str, Any]] | None = None,
    outcome: dict[str, Any] | None = None,
) -> dict[str, Any]:
    value = {
        "schema": "openline.proof_to_policy.request.v0.2",
        "request_id": request_id,
        "action_type": action_type,
        "claim": claim,
        "source_receipts": [receipt],
        "binding": binding,
        "evidence": evidence or [],
    }
    if outcome is not None:
        value["outcome_receipt"] = outcome
    return value


def run_demo(output_dir: str | Path) -> dict[str, Any]:
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    evidence_dir = root / "evidence"
    evidence_dir.mkdir(exist_ok=True)
    decisions = root / "decision_receipts.jsonl"
    decisions.unlink(missing_ok=True)
    ledger_path = root / "session_ledger.json"
    ledger_path.unlink(missing_ok=True)
    ledger_path.with_suffix(".json.lock").unlink(missing_ok=True)

    source_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("11" * 32))
    witness_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("22" * 32))
    gate_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("33" * 32))
    source_method = "did:example:demo-agent#key-1"
    store = TrustStore.from_mapping({
        "keys": {
            source_method: {
                "public_key": public_key_hex(source_key),
                "roles": ["source"],
                "independence": "operator",
                "controller": "demo-agent-operator",
            },
            public_key_hex(witness_key): {
                "public_key": public_key_hex(witness_key),
                "roles": ["outcome"],
                "independence": "orthogonal",
                "controller": "demo-ci-witness",
            },
        }
    })
    ledger = SessionLedger(ledger_path)

    safe_artifact = evidence_dir / "tool_result.json"
    safe_artifact.write_text('{"approved":true,"status":"completed"}\n', encoding="utf-8")
    safe_hash = sha256_hex(safe_artifact.read_bytes())
    harmful_artifact = evidence_dir / "mutation_result.json"
    harmful_artifact.write_text('{"damage":true,"mutation":"applied"}\n', encoding="utf-8")
    harmful_hash = sha256_hex(harmful_artifact.read_bytes())

    def receipt_for(case: str, action_type: str, artifact_hash: str, risk: str = "medium") -> dict[str, Any]:
        return _agent_receipt(
            key=source_key,
            method=source_method,
            chain_id=f"run-{case}",
            session_id=f"session-{case}",
            action_id=f"act-{case}",
            action_type=action_type,
            response_hash=artifact_hash,
            risk_level=risk,
        )

    results: dict[str, Any] = {}

    # 1. A valid signature cannot replace missing evidence.
    source_1 = receipt_for("insufficient", "tool_call", safe_hash)
    binding_1 = ledger.issue_challenge(
        run_id="run-insufficient",
        session_id="session-insufficient",
        expected_source_hash=_source_hash(source_1),
    )
    policy_1 = PolicySpec.from_mapping({
        "policy_id": "demo.require-evidence",
        "version": "1",
        "require_declared_coverage": True,
        "required_evidence_ids": ["tool_result"],
    })
    decision_1 = evaluate_request(
        _request(
            request_id="case-1",
            receipt=source_1,
            binding=binding_1,
            action_type="tool_call",
            claim="The tool completed the approved action.",
        ),
        policy=policy_1,
        trust_store=store,
        signing_key=gate_key,
        issuer_id="openline-demo-gate",
        decision_path=decisions,
        session_ledger=ledger,
        base_dir=root,
    )
    results["valid_signature_insufficient_evidence"] = decision_1

    # 2. Bound evidence plus an orthogonal outcome earns COMMIT.
    source_2 = receipt_for("complete", "tool_call", safe_hash)
    source_2_hash = _source_hash(source_2)
    binding_2 = ledger.issue_challenge(
        run_id="run-complete",
        session_id="session-complete",
        expected_source_hash=source_2_hash,
    )
    outcome_2 = issue_outcome_receipt(
        source_receipt_hash=source_2_hash,
        outcome_status="pass",
        harmful=False,
        evidence_hash=safe_hash,
        witness_id="demo-ci-witness",
        rollback_supported=False,
        key=witness_key,
    )
    policy_2 = PolicySpec.from_mapping({
        "policy_id": "demo.complete-tool-action",
        "version": "1",
        "require_declared_coverage": True,
        "require_outcome_witness": True,
        "required_evidence_ids": ["tool_result"],
        "evidence_assertions": [
            {"evidence_id": "tool_result", "path": "approved", "op": "equals", "value": True},
            {"evidence_id": "tool_result", "path": "status", "op": "equals", "value": "completed"},
        ],
    })
    evidence_2 = [{
        "id": "tool_result",
        "artifact_path": str(safe_artifact.relative_to(root)),
        "content_hash": safe_hash,
        "source_commitment_path": "credentialSubject.outcome.response_hash",
        "supports": ["act-complete"],
    }]
    request_2 = _request(
        request_id="case-2",
        receipt=source_2,
        binding=binding_2,
        action_type="tool_call",
        claim="The tool completed the approved action.",
        evidence=evidence_2,
        outcome=outcome_2,
    )
    decision_2 = evaluate_request(
        request_2,
        policy=policy_2,
        trust_store=store,
        signing_key=gate_key,
        issuer_id="openline-demo-gate",
        decision_path=decisions,
        session_ledger=ledger,
        base_dir=root,
    )
    results["complete_evidence_trusted_outcome"] = decision_2

    # 3. Exact replay is rejected even though every source signature remains valid.
    replay_2 = evaluate_request(
        {**request_2, "request_id": "case-3-replay"},
        policy=policy_2,
        trust_store=store,
        signing_key=gate_key,
        issuer_id="openline-demo-gate",
        decision_path=decisions,
        session_ledger=ledger,
        base_dir=root,
    )
    results["exact_replay"] = replay_2

    # 4. An unsupported score receives no badge.
    source_4 = receipt_for("score", "eval_score_claim", safe_hash)
    binding_4 = ledger.issue_challenge(
        run_id="run-score",
        session_id="session-score",
        expected_source_hash=_source_hash(source_4),
    )
    policy_4 = PolicySpec.from_mapping({
        "policy_id": "demo.score-badge",
        "version": "1",
        "require_declared_coverage": True,
        "required_evidence_ids": ["grader_receipt"],
        "no_badge_action_types": ["eval_score_claim"],
    })
    decision_4 = evaluate_request(
        _request(
            request_id="case-4",
            receipt=source_4,
            binding=binding_4,
            action_type="eval_score_claim",
            claim="Publish benchmark score 0.91.",
        ),
        policy=policy_4,
        trust_store=store,
        signing_key=gate_key,
        issuer_id="openline-demo-gate",
        decision_path=decisions,
        session_ledger=ledger,
        base_dir=root,
    )
    results["unsupported_score"] = decision_4

    # 5. A trusted harmful outcome requests rollback only when the actuator says it can.
    source_5 = receipt_for("mutation", "memory_write", harmful_hash, "high")
    source_5_hash = _source_hash(source_5)
    binding_5 = ledger.issue_challenge(
        run_id="run-mutation",
        session_id="session-mutation",
        expected_source_hash=source_5_hash,
    )
    outcome_5 = issue_outcome_receipt(
        source_receipt_hash=source_5_hash,
        outcome_status="harmful_mutation",
        harmful=True,
        evidence_hash=harmful_hash,
        witness_id="demo-ci-witness",
        rollback_supported=True,
        key=witness_key,
    )
    policy_5 = PolicySpec.from_mapping({
        "policy_id": "demo.rollback-harmful-mutation",
        "version": "1",
        "require_declared_coverage": True,
        "require_outcome_witness": True,
        "required_evidence_ids": ["mutation_result"],
        "rollback_on_harm": True,
        "evidence_assertions": [
            {"evidence_id": "mutation_result", "path": "damage", "op": "equals", "value": True}
        ],
    })
    decision_5 = evaluate_request(
        _request(
            request_id="case-5",
            receipt=source_5,
            binding=binding_5,
            action_type="memory_write",
            claim="The mutation was safe to retain.",
            evidence=[{
                "id": "mutation_result",
                "artifact_path": str(harmful_artifact.relative_to(root)),
                "content_hash": harmful_hash,
                "source_commitment_path": "credentialSubject.outcome.response_hash",
                "supports": ["act-mutation"],
            }],
            outcome=outcome_5,
        ),
        policy=policy_5,
        trust_store=store,
        signing_key=gate_key,
        issuer_id="openline-demo-gate",
        decision_path=decisions,
        session_ledger=ledger,
        base_dir=root,
    )
    results["harmful_mutation"] = decision_5

    expected = {
        "valid_signature_insufficient_evidence": ["UNDECIDABLE", "QUARANTINE"],
        "complete_evidence_trusted_outcome": ["VERIFIED", "COMMIT"],
        "exact_replay": ["REJECTED", "DENY"],
        "unsupported_score": ["UNDECIDABLE", "NO_BADGE"],
        "harmful_mutation": ["REJECTED", "ROLLBACK_REQUEST"],
    }
    observed = {name: [receipt["verdict"], receipt["decision"]] for name, receipt in results.items()}
    summary = {
        "schema": "openline.proof_to_policy.demo.v0.2",
        "passed": observed == expected,
        "expected": expected,
        "observed": observed,
        "decision_log": verify_decision_log(decisions, [public_key_hex(gate_key)]),
        "decision_receipt_count": len(results),
        "gate_public_key": public_key_hex(gate_key),
        "claim_boundary": "The demo proves deterministic policy behavior inside declared fixtures, not production safety.",
    }
    (root / "demo_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # The release artifact keeps the portable receipts and evidence, not live
    # replay-guard state. A deployment must custody its own ledger separately.
    ledger_path.unlink(missing_ok=True)
    ledger.lock_path.unlink(missing_ok=True)
    decisions.with_suffix(decisions.suffix + ".lock").unlink(missing_ok=True)
    return summary
