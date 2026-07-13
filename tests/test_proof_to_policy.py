from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.adapters import FAIL, PARTIAL, PASS, UNAVAILABLE, TrustStore, assess_source_bundle
from olp_gate.crypto import (
    DuplicateKeyError,
    generate_private_key_file,
    jcs_integer_canonical_json,
    public_key_hex,
    sha256_hex,
    strict_json_loads,
    sign_olp_body,
)
from olp_gate.demo import _agent_receipt, _source_hash, run_demo
from olp_gate.evidence import issue_outcome_receipt
from olp_gate.gateway import evaluate_request, verify_decision_log, verify_decision_receipt
from olp_gate.policy import PolicySpec
from olp_gate.session import SessionLedger


class ProofToPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("41" * 32))
        self.witness_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("42" * 32))
        self.gate_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("43" * 32))
        self.method = "did:example:test-agent#key-1"
        self.store = TrustStore.from_mapping({"keys": {
            self.method: {
                "public_key": public_key_hex(self.source_key),
                "roles": ["source"],
                "independence": "operator",
                "controller": "test-operator",
            },
            public_key_hex(self.witness_key): {
                "public_key": public_key_hex(self.witness_key),
                "roles": ["outcome"],
                "independence": "orthogonal",
                "controller": "test-witness",
            },
        }})
        self.ledger = SessionLedger(self.root / "sessions.json")
        self.decisions = self.root / "decisions.jsonl"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def source(self, *, case: str = "one", action_type: str = "tool_call", response_hash: str = "00" * 32):
        return _agent_receipt(
            key=self.source_key,
            method=self.method,
            chain_id=f"run-{case}",
            session_id=f"session-{case}",
            action_id=f"act-{case}",
            action_type=action_type,
            response_hash=response_hash,
        )

    def binding(self, source: dict, case: str) -> dict:
        return self.ledger.issue_challenge(
            run_id=f"run-{case}",
            session_id=f"session-{case}",
            expected_source_hash=_source_hash(source),
        )

    def policy(self, **changes) -> PolicySpec:
        value = {
            "policy_id": "test-policy",
            "version": "1",
            "require_declared_coverage": True,
            "required_evidence_ids": ["result"],
        }
        value.update(changes)
        return PolicySpec.from_mapping(value)

    def request(self, source: dict, binding: dict, case: str, **changes) -> dict:
        request = {
            "schema": "openline.proof_to_policy.request.v0.2",
            "request_id": f"request-{case}",
            "action_type": source["credentialSubject"]["action"]["type"],
            "claim": "The action completed safely.",
            "source_receipts": [source],
            "binding": binding,
            "evidence": [],
        }
        request.update(changes)
        return request

    def evaluate(self, request: dict, policy: PolicySpec) -> dict:
        return evaluate_request(
            request,
            policy=policy,
            trust_store=self.store,
            signing_key=self.gate_key,
            issuer_id="test-gate",
            decision_path=self.decisions,
            session_ledger=self.ledger,
            base_dir=self.root,
        )

    @property
    def gate_public_key(self) -> str:
        return public_key_hex(self.gate_key)

    def complete_case(self, case: str = "complete") -> tuple[dict, dict, PolicySpec]:
        artifact = self.root / f"{case}.json"
        artifact.write_text('{"approved":true,"status":"completed"}\n', encoding="utf-8")
        artifact_hash = sha256_hex(artifact.read_bytes())
        source = self.source(case=case, response_hash=artifact_hash)
        source_hash = _source_hash(source)
        binding = self.binding(source, case)
        outcome = issue_outcome_receipt(
            source_receipt_hash=source_hash,
            outcome_status="pass",
            harmful=False,
            evidence_hash=artifact_hash,
            witness_id="test-witness",
            rollback_supported=False,
            key=self.witness_key,
        )
        request = self.request(source, binding, case,
            evidence=[{
                "id": "result",
                "artifact_path": artifact.name,
                "content_hash": artifact_hash,
                "source_commitment_path": "credentialSubject.outcome.response_hash",
                "supports": [f"act-{case}"],
            }],
            outcome_receipt=outcome,
        )
        policy = self.policy(
            require_outcome_witness=True,
            evidence_assertions=[{"evidence_id": "result", "path": "approved", "op": "equals", "value": True}],
        )
        return source, request, policy

    def test_agent_receipt_signature_and_declared_coverage(self) -> None:
        source = self.source()
        assessment = assess_source_bundle([source], self.store)
        self.assertEqual(assessment.integrity.status, PASS)
        self.assertEqual(assessment.profile.status, PASS)
        self.assertEqual(assessment.coverage.status, PASS)
        self.assertEqual(assessment.provenance.status, PASS)

    def test_published_agent_receipts_v050_vector_interoperates(self) -> None:
        fixture = json.loads(
            (Path(__file__).parent / "fixtures" / "agent-receipts-v050-runtime.json")
            .read_text(encoding="utf-8")
        )
        receipt = fixture["receipt"]
        method = receipt["proof"]["verificationMethod"]
        store = TrustStore.from_mapping({"keys": {method: {
            "public_key": fixture["public_key_raw_hex"],
            "roles": ["source"],
            "independence": "operator",
            "controller": "published-test-vector",
        }}})
        assessment = assess_source_bundle([receipt], store)
        self.assertEqual(assessment.integrity.status, PASS)
        self.assertEqual(assessment.profile.status, PASS)
        self.assertEqual(assessment.provenance.status, PASS)
        self.assertEqual(assessment.coverage.status, PARTIAL)
        self.assertEqual(assessment.primary_hash, fixture["expected_receipt_hash"])

    def test_agent_receipt_tamper_is_rejected(self) -> None:
        source = self.source()
        source["credentialSubject"]["outcome"]["status"] = "failed"
        assessment = assess_source_bundle([source], self.store)
        self.assertEqual(assessment.integrity.status, FAIL)

    def test_agent_terminal_marker_must_be_boolean(self) -> None:
        source = self.source(case="terminal-type")
        source["credentialSubject"]["chain"]["terminal"] = "true"
        assessment = assess_source_bundle([source], self.store)
        self.assertEqual(assessment.profile.status, FAIL)
        self.assertIn("chain_terminal_invalid", assessment.profile.reason_codes)

    def test_valid_signature_without_evidence_is_undecidable(self) -> None:
        source = self.source(case="missing")
        decision = self.evaluate(self.request(source, self.binding(source, "missing"), "missing"), self.policy())
        self.assertEqual((decision["verdict"], decision["decision"]), ("UNDECIDABLE", "QUARANTINE"))
        self.assertEqual(decision["assessments"]["integrity"]["status"], PASS)

    def test_complete_evidence_and_outcome_commit(self) -> None:
        _source, request, policy = self.complete_case()
        decision = self.evaluate(request, policy)
        self.assertEqual((decision["verdict"], decision["decision"]), ("VERIFIED", "COMMIT"))
        self.assertFalse(decision["privacy"]["raw_evidence_stored"])
        self.assertTrue(verify_decision_receipt(decision, [self.gate_public_key])["valid"])

    def test_exact_replay_is_denied_without_advancing_chain(self) -> None:
        _source, request, policy = self.complete_case("replay")
        first = self.evaluate(request, policy)
        replay = self.evaluate({**request, "request_id": "replayed"}, policy)
        self.assertEqual(first["decision"], "COMMIT")
        self.assertEqual((replay["verdict"], replay["decision"]), ("REJECTED", "DENY"))
        self.assertFalse(replay["chain_accepted"])
        self.assertTrue(verify_decision_log(self.decisions, [self.gate_public_key])["valid"])

    def test_cross_run_binding_is_denied(self) -> None:
        source = self.source(case="cross")
        binding = self.binding(source, "cross")
        binding["run_id"] = "run-other"
        decision = self.evaluate(self.request(source, binding, "cross"), self.policy())
        self.assertEqual(decision["decision"], "DENY")
        self.assertIn("freshness:source_run_id_mismatch", decision["reason_codes"])

    def test_evidence_hash_mismatch_is_denied(self) -> None:
        _source, request, policy = self.complete_case("bad-hash")
        request["evidence"][0]["content_hash"] = "00" * 32
        decision = self.evaluate(request, policy)
        self.assertEqual(decision["decision"], "DENY")
        self.assertEqual(decision["assessments"]["evidence"]["status"], FAIL)

    def test_evidence_path_cannot_escape_request_directory(self) -> None:
        outside = self.root.parent / f"outside-{self.root.name}.json"
        outside.write_text('{"approved":true}\n', encoding="utf-8")
        try:
            source = self.source(case="path-escape", response_hash=sha256_hex(outside.read_bytes()))
            request = self.request(
                source,
                self.binding(source, "path-escape"),
                "path-escape",
                evidence=[{
                    "id": "result",
                    "artifact_path": str(outside),
                    "content_hash": sha256_hex(outside.read_bytes()),
                    "source_commitment_path": "credentialSubject.outcome.response_hash",
                }],
            )
            decision = self.evaluate(request, self.policy())
            self.assertEqual(decision["decision"], "DENY")
            self.assertIn("evidence:evidence_artifact_unreadable:result", decision["reason_codes"])
        finally:
            outside.unlink(missing_ok=True)

    def test_policy_caps_evidence_size(self) -> None:
        artifact = self.root / "large.json"
        artifact.write_text('{"approved":true}\n', encoding="utf-8")
        artifact_hash = sha256_hex(artifact.read_bytes())
        source = self.source(case="size-cap", response_hash=artifact_hash)
        request = self.request(
            source,
            self.binding(source, "size-cap"),
            "size-cap",
            evidence=[{
                "id": "result",
                "artifact_path": artifact.name,
                "content_hash": artifact_hash,
                "source_commitment_path": "credentialSubject.outcome.response_hash",
            }],
        )
        decision = self.evaluate(request, self.policy(max_evidence_bytes=4))
        self.assertEqual(decision["decision"], "DENY")
        self.assertIn("evidence:evidence_artifact_unreadable:result", decision["reason_codes"])

    def test_outcome_rebound_to_other_source_is_denied(self) -> None:
        _source, request, policy = self.complete_case("bad-outcome")
        other = self.source(case="other")
        request["outcome_receipt"] = issue_outcome_receipt(
            source_receipt_hash=_source_hash(other),
            outcome_status="pass",
            harmful=False,
            evidence_hash=request["evidence"][0]["content_hash"],
            witness_id="test-witness",
            rollback_supported=False,
            key=self.witness_key,
        )
        decision = self.evaluate(request, policy)
        self.assertEqual(decision["decision"], "DENY")
        self.assertIn("outcome:outcome_source_binding_mismatch", decision["reason_codes"])

    def test_outcome_evidence_rebinding_is_denied(self) -> None:
        source, request, policy = self.complete_case("outcome-evidence")
        request["outcome_receipt"] = issue_outcome_receipt(
            source_receipt_hash=_source_hash(source),
            outcome_status="pass",
            harmful=False,
            evidence_hash="99" * 32,
            witness_id="test-witness",
            rollback_supported=False,
            key=self.witness_key,
        )
        decision = self.evaluate(request, policy)
        self.assertEqual(decision["decision"], "DENY")
        self.assertIn("outcome:outcome_evidence_binding_mismatch", decision["reason_codes"])

    def test_request_cannot_relabel_signed_action_type(self) -> None:
        source = self.source(case="relabel", action_type="tool_call")
        request = self.request(source, self.binding(source, "relabel"), "relabel")
        request["action_type"] = "eval_score_claim"
        decision = self.evaluate(request, self.policy())
        self.assertEqual((decision["verdict"], decision["decision"]), ("REJECTED", "DENY"))
        self.assertIn("profile:request_action_type_mismatch", decision["reason_codes"])

    def test_agent_evidence_commitment_path_cannot_be_chosen_by_requester(self) -> None:
        _source, request, policy = self.complete_case("commitment-path")
        request["evidence"][0]["source_commitment_path"] = "credentialSubject.action.id"
        decision = self.evaluate(request, policy)
        self.assertEqual(decision["decision"], "DENY")
        self.assertIn("evidence:source_commitment_path_invalid:result", decision["reason_codes"])

    def test_harmful_outcome_requests_rollback(self) -> None:
        source, request, policy = self.complete_case("harm")
        request["outcome_receipt"] = issue_outcome_receipt(
            source_receipt_hash=_source_hash(source),
            outcome_status="harmful_mutation",
            harmful=True,
            evidence_hash=request["evidence"][0]["content_hash"],
            witness_id="test-witness",
            rollback_supported=True,
            key=self.witness_key,
        )
        decision = self.evaluate(request, policy)
        self.assertEqual((decision["verdict"], decision["decision"]), ("REJECTED", "ROLLBACK_REQUEST"))

    def test_unsigned_legacy_source_cannot_earn_trusted_commit(self) -> None:
        legacy = {
            "schema": "openline.receipt_gate.v0.1.1",
            "receipt_id": "legacy",
            "parent_hash": None,
            "timestamp": 1,
            "action_type": "tool_call",
            "claim": "legacy",
            "evidence_hash": None,
            "result_hash": None,
            "status": "committed",
            "decision": "COMMIT",
            "policy_flags": [],
            "next_use_note": "legacy",
            "metadata": {},
        }
        from olp_gate.receipts import sha256_json
        legacy["receipt_hash"] = sha256_json(legacy)
        assessment = assess_source_bundle([legacy], self.store)
        self.assertEqual(assessment.integrity.status, PASS)
        self.assertEqual(assessment.provenance.status, UNAVAILABLE)

    def test_independent_source_requirement_is_not_earned_by_operator_key(self) -> None:
        source = self.source(case="independence")
        policy = self.policy(require_independent_source=True)
        decision = self.evaluate(self.request(source, self.binding(source, "independence"), "independence"), policy)
        self.assertEqual(decision["verdict"], "UNDECIDABLE")
        self.assertIn("independence:independent_source_witness_missing", decision["reason_codes"])

    def test_olp_wire_vector_is_integrity_valid_but_coverage_partial(self) -> None:
        vector = json.loads((Path(__file__).parent / "fixtures" / "olp-trace-receipt.json").read_text(encoding="utf-8"))
        key_id = vector["signature"]["public_key"]
        store = TrustStore.from_mapping({"keys": {key_id: {
            "public_key": key_id,
            "roles": ["source"],
            "independence": "self",
            "controller": "fixture",
        }}})
        assessment = assess_source_bundle([vector], store)
        self.assertEqual(assessment.integrity.status, PASS)
        self.assertEqual(assessment.coverage.status, PARTIAL)

    def test_decision_tamper_breaks_signature(self) -> None:
        _source, request, policy = self.complete_case("tamper")
        decision = self.evaluate(request, policy)
        decision["decision"] = "DENY"
        self.assertFalse(verify_decision_receipt(decision, [self.gate_public_key])["valid"])

    def test_resealed_semantic_forgery_is_recomputed_and_rejected(self) -> None:
        _source, request, policy = self.complete_case("recompute")
        decision = self.evaluate(request, policy)
        body = dict(decision)
        body.pop("payload_hash")
        body.pop("signature")
        body["decision"] = "DENY"
        forged = sign_olp_body(body, self.gate_key)
        result = verify_decision_receipt(forged, [self.gate_public_key])
        self.assertFalse(result["valid"])
        self.assertIn("decision_recompute_mismatch", result["errors"])

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaises(DuplicateKeyError):
            strict_json_loads('{"a":1,"a":2}')

    def test_decision_log_rejects_duplicate_json_keys(self) -> None:
        self.decisions.write_text(
            '{"kind":"proof_to_policy_decision_receipt","kind":"other"}\n',
            encoding="utf-8",
        )
        result = verify_decision_log(self.decisions, [self.gate_public_key])
        self.assertFalse(result["valid"])
        self.assertIn("json_parse_error:1", result["errors"])

    def test_private_key_permissions_are_enforced(self) -> None:
        path = self.root / "gate.key"
        generate_private_key_file(path)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        os.chmod(path, 0o644)
        from olp_gate.crypto import load_private_key
        with self.assertRaises(PermissionError):
            load_private_key(path)

    def test_only_one_challenge_can_be_pending_per_session(self) -> None:
        source = self.source(case="pending")
        self.binding(source, "pending")
        with self.assertRaisesRegex(ValueError, "pending challenge"):
            self.binding(source, "pending")

    def test_policy_without_replay_guard_does_not_claim_chain_acceptance(self) -> None:
        source = self.source(case="no-chain")
        request = self.request(source, {}, "no-chain")
        decision = self.evaluate(request, self.policy(require_replay_guard=False))
        self.assertFalse(decision["chain_accepted"])
        self.assertTrue(verify_decision_receipt(decision, [self.gate_public_key])["valid"])

    def test_policy_rejects_string_booleans_and_unknown_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be a boolean"):
            self.policy(require_evidence="false")
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            self.policy(permit_everything=True)

    def test_embedded_decision_key_is_not_implicitly_trusted(self) -> None:
        _source, request, policy = self.complete_case("gate-trust")
        decision = self.evaluate(request, policy)
        result = verify_decision_receipt(decision, ["00" * 32])
        self.assertFalse(result["valid"])
        self.assertIn("gate_key_not_trusted", result["errors"])

    def test_full_demo_passes(self) -> None:
        summary = run_demo(self.root / "demo")
        self.assertTrue(summary["passed"])
        self.assertTrue(summary["decision_log"]["valid"])
        self.assertEqual(summary["decision_receipt_count"], 5)

    def test_independent_node_verifier_accepts_demo_and_rejects_tamper(self) -> None:
        demo_root = self.root / "node-demo"
        run_demo(demo_root)
        verifier = Path(__file__).resolve().parents[1] / "verify-decision-node.mjs"
        log = demo_root / "decision_receipts.jsonl"
        accepted = subprocess.run(
            ["node", str(verifier), str(log), "--gate-key", public_key_hex(Ed25519PrivateKey.from_private_bytes(bytes.fromhex("33" * 32)))],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        self.assertTrue(json.loads(accepted.stdout)["valid"])
        untrusted = subprocess.run(
            ["node", str(verifier), str(log), "--gate-key", "00" * 32],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(untrusted.returncode, 1)
        self.assertTrue(any("gate_key_not_trusted" in error for error in json.loads(untrusted.stdout)["errors"]))
        log.write_text(log.read_text(encoding="utf-8").replace('"decision":"COMMIT"', '"decision":"DENY"', 1), encoding="utf-8")
        rejected = subprocess.run(
            ["node", str(verifier), str(log), "--gate-key", public_key_hex(Ed25519PrivateKey.from_private_bytes(bytes.fromhex("33" * 32)))],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(rejected.returncode, 1)
        self.assertFalse(json.loads(rejected.stdout)["valid"])
        log.write_text('{"kind":"one","kind":"two"}\n', encoding="utf-8")
        duplicate = subprocess.run(
            ["node", str(verifier), str(log), "--gate-key", public_key_hex(Ed25519PrivateKey.from_private_bytes(bytes.fromhex("33" * 32)))],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(duplicate.returncode, 1)
        self.assertIn("json_parse_error:1", json.loads(duplicate.stdout)["errors"])


if __name__ == "__main__":
    unittest.main()
