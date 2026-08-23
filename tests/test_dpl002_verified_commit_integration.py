"""Actual DPL -> Proof-to-Policy Gate -> Verified Commit integration.

This test intentionally uses the repository's existing signed decision receipt
and VerifiedCommitLedger.  It is the execution-half of the DPL-002 falsifier;
the caveated capability control independently exercises the same exact-action
and replay attacks in the comparison suite.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from benchmarks.decision_permission_link_002.scenario import NOW, POLICY, evidence_for, proposal
from olp_gate.adapters import TrustStore
from olp_gate.authority_link import compile_link, canonical_hash
from olp_gate.crypto import public_key_hex, sha256_hex
from olp_gate.demo import _agent_receipt, _source_hash
from olp_gate.evidence import issue_outcome_receipt
from olp_gate.gateway import evaluate_request
from olp_gate.policy import PolicySpec
from olp_gate.session import SessionLedger
from olp_gate.verified_commit import VerifiedCommitLedger, settings_hash


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class DPL002VerifiedCommitIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="dpl002-vc-")
        self.root = Path(self.temp.name)
        self.source_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("81" * 32))
        self.witness_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("82" * 32))
        self.gate_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("83" * 32))
        self.source_method = "did:example:dpl002-source#key-1"
        self.store = TrustStore.from_mapping({"keys": {
            self.source_method: {"public_key": public_key_hex(self.source_key), "roles": ["source"], "independence": "operator", "controller": "dpl002-source"},
            public_key_hex(self.witness_key): {"public_key": public_key_hex(self.witness_key), "roles": ["outcome"], "independence": "receiver", "controller": "dpl002-receiver"},
        }})

    def tearDown(self):
        self.temp.cleanup()

    def issue(self):
        p = proposal()
        link = compile_link(POLICY, p, evidence_for(p), now=NOW, current_state_hash=p["state_hash"])
        self.assertEqual(link["assessment"]["decision"], "COMMIT_ELIGIBLE")
        settings = link["verified_commit_settings"]
        permission_artifact = self.root / "permission.json"
        permission_artifact.write_text(json.dumps({
            "decision": "COMMIT_ELIGIBLE",
            "assessment_hash": link["assessment"]["assessment_hash"],
            "obligation_hash": link["obligation"]["obligation_hash"],
            "effect_hash": link["assessment"]["effect_hash"],
        }, sort_keys=True) + "\n", encoding="utf-8")
        artifact_hash = sha256_hex(permission_artifact.read_bytes())
        now = NOW
        run_id = "dpl002-run"
        source = _agent_receipt(key=self.source_key, method=self.source_method, chain_id=run_id, session_id="dpl002-session", action_id="dpl002-action", action_type="tool_call", response_hash=artifact_hash, timestamp=iso(now))
        source_hash = _source_hash(source)
        session = SessionLedger(self.root / "sessions.json")
        binding = session.issue_challenge(run_id=run_id, session_id="dpl002-session", expected_source_hash=source_hash)
        outcome = issue_outcome_receipt(source_receipt_hash=source_hash, outcome_status="pass", harmful=False, evidence_hash=artifact_hash, witness_id="dpl002-receiver", rollback_supported=True, key=self.witness_key)
        action = {
            "tool": p["tool"],
            "target": p["target"],
            "settings": settings,
            "run_id": run_id,
            "capsule_hash": canonical_hash({"dpl002": "settlement"}),
            "evidence_hashes": [artifact_hash],
        }
        policy = PolicySpec.from_mapping({
            "policy_id": "dpl002.receiver.execution",
            "version": "1",
            "require_declared_coverage": True,
            "require_outcome_witness": True,
            "required_evidence_ids": ["permission"],
            "evidence_assertions": [{"evidence_id": "permission", "path": "decision", "op": "equals", "value": "COMMIT_ELIGIBLE"}],
            "metadata": {"verified_commit": {
                "required": True,
                "tool": action["tool"], "target": action["target"], "settings_hash": settings_hash(settings),
                "run_id": run_id, "capsule_hash": action["capsule_hash"], "evidence_hashes": action["evidence_hashes"], "max_ttl_seconds": 30,
            }},
        })
        code = "ef" * 32
        request = {
            "schema": "openline.proof_to_policy.request.v0.2",
            "request_id": "dpl002-request",
            "action_type": "tool_call",
            "claim": "The DPL-qualified exact settlement action may execute once.",
            "source_receipts": [source],
            "binding": binding,
            "evidence": [{"id": "permission", "artifact_path": permission_artifact.name, "content_hash": artifact_hash, "source_commitment_path": "credentialSubject.outcome.response_hash"}],
            "outcome_receipt": outcome,
            "commit_request": {**action, "policy_hash": policy.policy_hash, "expires_at": iso(now + timedelta(seconds=20)), "one_use_code": code},
        }
        receipt = evaluate_request(request, policy=policy, trust_store=self.store, signing_key=self.gate_key, issuer_id="dpl002-gate", decision_path=self.root / "decisions.jsonl", session_ledger=session, base_dir=self.root, now=now)
        action["policy_hash"] = policy.policy_hash
        return p, receipt, action, code

    def test_dpl_qualified_action_executes_once_and_replay_fails(self):
        _p, receipt, action, code = self.issue()
        ledger = VerifiedCommitLedger(self.root / "ledger.json")
        calls = []
        first = ledger.execute_once(receipt, action, one_use_code=code, trusted_gate_keys=[public_key_hex(self.gate_key)], executor=lambda: calls.append("paid") or {"settled": True}, now=NOW)
        replay = ledger.execute_once(receipt, action, one_use_code=code, trusted_gate_keys=[public_key_hex(self.gate_key)], executor=lambda: calls.append("replay"), now=NOW)
        self.assertTrue(first["authorized"])
        self.assertFalse(replay["authorized"])
        self.assertIn("authorization_replay", replay["reason_codes"])
        self.assertEqual(calls, ["paid"])

    def test_post_authorization_payload_mutation_fails_before_execution(self):
        _p, receipt, action, code = self.issue()
        mutated = json.loads(json.dumps(action))
        mutated["settings"]["effect_settings"]["vendor_id"] = "VENDOR-EVIL"
        calls = []
        result = VerifiedCommitLedger(self.root / "mutation-ledger.json").execute_once(receipt, mutated, one_use_code=code, trusted_gate_keys=[public_key_hex(self.gate_key)], executor=lambda: calls.append("bad"), now=NOW)
        self.assertFalse(result["authorized"])
        self.assertIn("settings_mismatch", result["reason_codes"])
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
