"""Offline signed fixtures issued through the ordinary Verified Commit gate.

Every private key in this module is a public test fixture.  The fixed clock is
experiment apparatus, not a caller-controlled clock on the protected adapter.
No model, paid API, device, or network operation is involved.
"""

from __future__ import annotations

import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.adapters import TrustStore
from olp_gate.crypto import olp_canonical_json, public_key_hex, sha256_hex
from olp_gate.demo import _agent_receipt, _source_hash
from olp_gate.evidence import issue_outcome_receipt
from olp_gate.gateway import evaluate_request, verify_decision_receipt
from olp_gate.mandate import MandateSpec
from olp_gate.mandate_owner import issue_mandate_authorization
from olp_gate.policy import PolicySpec
from olp_gate.session import SessionLedger
from olp_gate.verified_commit import settings_hash


NOW = datetime(2026, 10, 17, 18, 0, tzinfo=timezone.utc)
TARGET = "sqlite://commissioning/site-1"
SUBJECT = "operator:alice"
OWNER_ID = "owner:local"
SLOT_ID = "commissioning/site-1"


def key(seed: str) -> Ed25519PrivateKey:
    """Return an explicitly public, deterministic test signing key."""

    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed * 32))


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def fixture(
    root: str | Path,
    *,
    case: str = "default",
    code: str | None = None,
) -> dict[str, Any]:
    """Issue a genuine signed commissioning authorization and owner head.

    Issuance logs and challenge state are retained below ``root/issuance``.
    Each invocation gets an independent challenge ledger, including repeated
    invocations for the same named case.  Consumers must use their own protected
    receiver clock and authentication source rather than trust fixture fields.
    """

    if not re.fullmatch(r"[A-Za-z0-9_.-]+", case):
        raise ValueError("fixture_case_invalid")
    destination = Path(root) / "issuance"
    destination.mkdir(parents=True, exist_ok=True)
    issuance = Path(tempfile.mkdtemp(prefix=case + "-", dir=destination))
    expiry = NOW + timedelta(minutes=5)
    source_key, witness_key, gate_key = key("61"), key("62"), key("63")
    owner_key, outcome_key = key("71"), key("74")
    source_method = "did:example:consequence-002-source#key-1"
    trust_store = TrustStore.from_mapping(
        {
            "keys": {
                source_method: {
                    "public_key": public_key_hex(source_key),
                    "roles": ["source"],
                    "independence": "operator",
                    "controller": "consequence-002-source",
                },
                public_key_hex(witness_key): {
                    "public_key": public_key_hex(witness_key),
                    "roles": ["outcome"],
                    "independence": "receiver",
                    "controller": "consequence-002-receiver",
                },
            }
        }
    )
    simulation = olp_canonical_json(
        {
            "approved": True,
            "simulation": {
                "fixture_only": True,
                "site_id": "site-1",
                "result": "commissioning prerequisites satisfied",
            },
        }
    )
    robot_config = olp_canonical_json(
        {"fixture_only": True, "robot_id": "simulated-robot-1", "mode": "local"}
    )
    simulation_digest = sha256_hex(simulation)
    robot_config_digest = sha256_hex(robot_config)
    artifacts = {
        simulation_digest: simulation.decode("utf-8"),
        robot_config_digest: robot_config.decode("utf-8"),
    }
    mandate_spec = MandateSpec.from_mapping(
        {
            "profile": "principal_mandate/v1",
            "mandate_id": "commission-site-1",
            "principal_id": OWNER_ID,
            "agent_id": SUBJECT,
            "purpose": "commission site",
            "allowed_action_types": ["send"],
            "allowed_targets": [TARGET],
            "allowed_disclosure_classes": [],
            "forbidden_disclosure_classes": [],
            "max_settlement_cents": 0,
            "max_payment_cents": 0,
            "delegation_allowed": False,
            "expires_at": iso(expiry),
            "version": "1",
        }
    )
    mandate = mandate_spec.as_dict()
    owner_authorization = issue_mandate_authorization(
        slot_id=SLOT_ID,
        owner_id=OWNER_ID,
        mandate=mandate,
        state="ACTIVE",
        sequence=1,
        predecessor_hash=None,
        issued_at=NOW,
        expires_at=expiry,
        key=owner_key,
    )
    settings = {
        "profile": "sqlite_commissioning/v1",
        "mandate_hash": mandate_spec.mandate_hash,
        "simulation_digest": simulation_digest,
        "robot_config_digest": robot_config_digest,
        "site_version": 1,
        "site_id": "site-1",
        "idempotency_key": "commission-site-1-v1",
    }
    run_id = "consequence-002-" + case
    action = {
        "tool": "sqlite.commission",
        "target": TARGET,
        "settings": settings,
        "run_id": run_id,
        "capsule_hash": sha256_hex(b"openline-consequence-002-public-capsule"),
        "evidence_hashes": [simulation_digest],
    }
    policy = PolicySpec.from_mapping(
        {
            "policy_id": "consequence-002.receiver-policy",
            "version": "1",
            "require_declared_coverage": True,
            "require_outcome_witness": True,
            "required_evidence_ids": ["simulation"],
            "evidence_assertions": [
                {
                    "evidence_id": "simulation",
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
                    "max_ttl_seconds": 600,
                }
            },
        }
    )
    action["policy_hash"] = policy.policy_hash
    one_use_code = code if code is not None else sha256_hex(
        ("openline-consequence-002:one-use:" + case).encode("ascii")
    )
    source = _agent_receipt(
        key=source_key,
        method=source_method,
        chain_id=run_id,
        session_id="session-" + case,
        action_id="commission-" + case,
        action_type="tool_call",
        response_hash=simulation_digest,
        timestamp=iso(NOW),
    )
    source_hash = _source_hash(source)
    session = SessionLedger(issuance / "session.json")
    # SessionLedger has no clock injection API.  Freeze only its fixture clock;
    # the protected consequence adapter never receives this patch.
    with patch("olp_gate.session._utc_now", return_value=NOW):
        binding = session.issue_challenge(
            run_id=run_id,
            session_id="session-" + case,
            expected_source_hash=source_hash,
        )
        outcome = issue_outcome_receipt(
            source_receipt_hash=source_hash,
            outcome_status="pass",
            harmful=False,
            evidence_hash=simulation_digest,
            witness_id="consequence-002-simulation-witness",
            rollback_supported=True,
            key=witness_key,
            observed_at=iso(NOW),
        )
        request = {
            "schema": "openline.proof_to_policy.request.v0.2",
            "request_id": "request-" + case,
            "action_type": "tool_call",
            "claim": "Commission this simulated site through the exact local SQLite action.",
            "source_receipts": [source],
            "binding": binding,
            "evidence": [
                {
                    "id": "simulation",
                    "content": simulation.decode("utf-8"),
                    "content_hash": simulation_digest,
                    "source_commitment_path": "credentialSubject.outcome.response_hash",
                }
            ],
            "outcome_receipt": outcome,
            "commit_request": {
                **action,
                "expires_at": iso(expiry),
                "one_use_code": one_use_code,
            },
        }
        receipt = evaluate_request(
            request,
            policy=policy,
            trust_store=trust_store,
            signing_key=gate_key,
            issuer_id="consequence-002-fixture-gate",
            decision_path=issuance / "decision.jsonl",
            session_ledger=session,
            base_dir=issuance,
            now=NOW,
        )
    verification = verify_decision_receipt(receipt, [public_key_hex(gate_key)])
    if (
        receipt.get("decision") != "COMMIT"
        or receipt.get("verdict") != "VERIFIED"
        or not verification["valid"]
    ):
        raise RuntimeError(
            "fixture_issuance_failed: "
            + repr({"reasons": receipt.get("reason_codes"), "verification": verification})
        )
    return {
        "receipt": receipt,
        "action": action,
        "code": one_use_code,
        "now": iso(NOW),
        "mandate": mandate,
        "owner_authorization": owner_authorization,
        "artifacts": artifacts,
        "roots": {
            "owner_id": OWNER_ID,
            "owner_key": public_key_hex(owner_key),
            "gate_keys": [public_key_hex(gate_key)],
            "outcome_key": public_key_hex(outcome_key),
            "slot_id": SLOT_ID,
        },
        "site": {
            "site_id": "site-1",
            "version": 1,
            "simulation_digest": simulation_digest,
            "robot_config_digest": robot_config_digest,
        },
        "policy_hash": policy.policy_hash,
    }
