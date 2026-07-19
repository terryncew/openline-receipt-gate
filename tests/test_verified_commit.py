from __future__ import annotations

import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.adapters import TrustStore
from olp_gate.crypto import public_key_hex, sha256_hex
from olp_gate.demo import _agent_receipt, _source_hash
from olp_gate.evidence import issue_outcome_receipt
from olp_gate.gateway import evaluate_request, verify_decision_receipt
from olp_gate.policy import PolicySpec
from olp_gate.session import SessionLedger
from olp_gate.verified_commit import (
    VerifiedCommitLedger,
    execution_action_from_authorization,
    one_use_code_hash,
    settings_hash,
)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _copy(value: dict) -> dict:
    return json.loads(json.dumps(value))


class VerifiedCommitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="verified-commit-")
        self.root = Path(self.temp.name)
        self.source_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("61" * 32))
        self.witness_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("62" * 32))
        self.gate_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("63" * 32))
        self.source_method = "did:example:verified-commit-source#key-1"
        self.store = TrustStore.from_mapping(
            {
                "keys": {
                    self.source_method: {
                        "public_key": public_key_hex(self.source_key),
                        "roles": ["source"],
                        "independence": "operator",
                        "controller": "verified-commit-source",
                    },
                    public_key_hex(self.witness_key): {
                        "public_key": public_key_hex(self.witness_key),
                        "roles": ["outcome"],
                        "independence": "receiver",
                        "controller": "verified-commit-receiver",
                    },
                }
            }
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    @property
    def gate_public_key(self) -> str:
        return public_key_hex(self.gate_key)

    def issue(
        self,
        case: str,
        *,
        policy_requires_commit: bool = True,
        request_has_commit: bool = True,
        request_mutation: tuple[str, object] | None = None,
    ) -> tuple[dict, dict, str, datetime]:
        now = datetime.now(timezone.utc)
        artifact = self.root / f"{case}.json"
        artifact.write_text('{"approved":true,"status":"complete"}\n', encoding="utf-8")
        artifact_hash = sha256_hex(artifact.read_bytes())
        run_id = f"run-{case}"
        source = _agent_receipt(
            key=self.source_key,
            method=self.source_method,
            chain_id=run_id,
            session_id=f"session-{case}",
            action_id=f"action-{case}",
            action_type="tool_call",
            response_hash=artifact_hash,
            timestamp=_iso(now),
        )
        source_hash = _source_hash(source)
        session = SessionLedger(self.root / f"{case}-sessions.json")
        binding = session.issue_challenge(
            run_id=run_id,
            session_id=f"session-{case}",
            expected_source_hash=source_hash,
        )
        outcome = issue_outcome_receipt(
            source_receipt_hash=source_hash,
            outcome_status="pass",
            harmful=False,
            evidence_hash=artifact_hash,
            witness_id="verified-commit-receiver",
            rollback_supported=True,
            key=self.witness_key,
        )
        settings = {
            "content_sha256": sha256_hex(b"approved payload"),
            "mode": "create_new",
        }
        action = {
            "tool": "filesystem.write",
            "target": "artifact://approved.json",
            "settings": settings,
            "run_id": run_id,
            "capsule_hash": sha256_hex(f"capsule:{case}".encode("utf-8")),
            "evidence_hashes": [artifact_hash],
        }
        metadata: dict[str, object] = {}
        if policy_requires_commit:
            metadata["verified_commit"] = {
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
                "policy_id": "verified-commit.receiver-policy",
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
                "metadata": metadata,
            }
        )
        code = "ab" * 32
        expiry = now + timedelta(seconds=60)
        request = {
            "schema": "openline.proof_to_policy.request.v0.2",
            "request_id": f"request-{case}",
            "action_type": "tool_call",
            "claim": "The exact receiver-approved action may execute once.",
            "source_receipts": [source],
            "binding": binding,
            "evidence": [
                {
                    "id": "result",
                    "artifact_path": artifact.name,
                    "content_hash": artifact_hash,
                    "source_commitment_path": "credentialSubject.outcome.response_hash",
                }
            ],
            "outcome_receipt": outcome,
        }
        if request_has_commit:
            commit_request = {
                **action,
                "policy_hash": policy.policy_hash,
                "expires_at": _iso(expiry),
                "one_use_code": code,
            }
            if request_mutation is not None:
                name, value = request_mutation
                commit_request[name] = value
            request["commit_request"] = commit_request
        receipt = evaluate_request(
            request,
            policy=policy,
            trust_store=self.store,
            signing_key=self.gate_key,
            issuer_id="verified-commit-test-gate",
            decision_path=self.root / f"{case}-decisions.jsonl",
            session_ledger=session,
            base_dir=self.root,
            now=now,
        )
        action["policy_hash"] = policy.policy_hash
        return receipt, action, code, expiry

    def test_existing_commit_receipt_carries_exact_private_authorization(self) -> None:
        receipt, action, code, _expiry = self.issue("profile")
        self.assertEqual(receipt["kind"], "proof_to_policy_decision_receipt")
        self.assertEqual(receipt["receipt_version"], "0.4")
        self.assertEqual((receipt["verdict"], receipt["decision"]), ("VERIFIED", "COMMIT"))
        authorization = receipt["commit_authorization"]
        self.assertEqual(authorization["tool"], action["tool"])
        self.assertEqual(authorization["target"], action["target"])
        self.assertEqual(authorization["settings_hash"], settings_hash(action["settings"]))
        self.assertEqual(authorization["one_use_code_hash"], one_use_code_hash(code))
        self.assertNotIn(code, json.dumps(receipt, sort_keys=True))
        self.assertTrue(verify_decision_receipt(receipt, [self.gate_public_key])["valid"])

    def test_changed_fields_and_wrong_code_are_blocked_before_execution(self) -> None:
        receipt, exact, code, _expiry = self.issue("mutations")
        ledger = VerifiedCommitLedger(self.root / "mutations-ledger.json")
        mutations: list[tuple[str, dict, str]] = []
        for field, value, reason in (
            ("tool", "filesystem.delete", "tool_mismatch"),
            ("target", "artifact://wrong.json", "target_mismatch"),
            ("run_id", "run-wrong", "run_mismatch"),
            ("capsule_hash", "00" * 32, "capsule_mismatch"),
            ("evidence_hashes", ["00" * 32], "evidence_mismatch"),
            ("policy_hash", "00" * 32, "policy_mismatch"),
        ):
            changed = _copy(exact)
            changed[field] = value
            mutations.append((reason, changed, code))
        changed = _copy(exact)
        changed["settings"]["mode"] = "overwrite"
        mutations.append(("settings_mismatch", changed, code))
        mutations.append(("one_use_code_mismatch", _copy(exact), "00" * 32))
        calls: list[str] = []
        for reason, attempted, attempted_code in mutations:
            result = ledger.execute_once(
                receipt,
                attempted,
                one_use_code=attempted_code,
                trusted_gate_keys=[self.gate_public_key],
                executor=lambda reason=reason: calls.append(reason),
                attempt_label=reason,
            )
            self.assertFalse(result["authorized"])
            self.assertIn(reason, result["reason_codes"])
        self.assertEqual(calls, [])

    def test_expired_permission_is_blocked_before_execution(self) -> None:
        receipt, action, code, expiry = self.issue("expired")
        called: list[bool] = []
        result = VerifiedCommitLedger(self.root / "expired-ledger.json").execute_once(
            receipt,
            action,
            one_use_code=code,
            trusted_gate_keys=[self.gate_public_key],
            executor=lambda: called.append(True),
            now=expiry,
        )
        self.assertFalse(result["authorized"])
        self.assertIn("authorization_expired", result["reason_codes"])
        self.assertEqual(called, [])

    def test_exact_action_executes_once_then_replay_is_blocked(self) -> None:
        receipt, action, code, _expiry = self.issue("replay")
        ledger = VerifiedCommitLedger(self.root / "replay-ledger.json")
        calls: list[str] = []
        first = ledger.execute_once(
            receipt,
            action,
            one_use_code=code,
            trusted_gate_keys=[self.gate_public_key],
            executor=lambda: calls.append("executed") or {"ok": True},
        )
        replay = ledger.execute_once(
            receipt,
            action,
            one_use_code=code,
            trusted_gate_keys=[self.gate_public_key],
            executor=lambda: calls.append("replayed"),
        )
        self.assertTrue(first["authorized"])
        self.assertEqual(first["execution_status"], "completed")
        self.assertFalse(replay["authorized"])
        self.assertIn("authorization_replay", replay["reason_codes"])
        self.assertEqual(calls, ["executed"])

    def test_two_simultaneous_uses_allow_exactly_one_execution(self) -> None:
        receipt, action, code, _expiry = self.issue("concurrent")
        ledger = VerifiedCommitLedger(self.root / "concurrent-ledger.json")
        barrier = threading.Barrier(2)
        calls: list[int] = []

        def use(index: int) -> dict:
            barrier.wait()
            return ledger.execute_once(
                receipt,
                action,
                one_use_code=code,
                trusted_gate_keys=[self.gate_public_key],
                executor=lambda: calls.append(index) or {"index": index},
                attempt_label=f"simultaneous-{index}",
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(use, (1, 2)))
        self.assertEqual(sum(item["authorized"] for item in results), 1)
        self.assertEqual(len(calls), 1)
        blocked = next(item for item in results if not item["authorized"])
        self.assertIn("authorization_replay", blocked["reason_codes"])

    def test_tampered_receipt_is_blocked_before_execution(self) -> None:
        receipt, action, code, _expiry = self.issue("tampered")
        receipt["commit_authorization"]["target"] = "artifact://tampered.json"
        called: list[bool] = []
        result = VerifiedCommitLedger(self.root / "tampered-ledger.json").execute_once(
            receipt,
            action,
            one_use_code=code,
            trusted_gate_keys=[self.gate_public_key],
            executor=lambda: called.append(True),
        )
        self.assertFalse(result["authorized"])
        self.assertTrue(
            any(reason.startswith("decision_receipt_invalid:") for reason in result["reason_codes"])
        )
        self.assertEqual(called, [])

    def test_receiver_policy_mismatch_denies_authorization(self) -> None:
        receipt, _action, _code, _expiry = self.issue(
            "policy-mismatch",
            request_mutation=("target", "artifact://not-approved.json"),
        )
        self.assertEqual((receipt["verdict"], receipt["decision"]), ("REJECTED", "DENY"))
        self.assertIsNone(receipt["commit_authorization"])
        self.assertIn(
            "verified_commit:verified_commit_policy_target_mismatch",
            receipt["reason_codes"],
        )

    def test_required_permission_request_cannot_be_omitted(self) -> None:
        receipt, _action, _code, _expiry = self.issue(
            "missing-request",
            request_has_commit=False,
        )
        self.assertEqual(receipt["decision"], "DENY")
        self.assertIsNone(receipt["commit_authorization"])
        self.assertIn(
            "verified_commit:verified_commit_request_missing",
            receipt["reason_codes"],
        )

    def test_ordinary_commit_is_not_portable_tool_permission(self) -> None:
        receipt, action, code, _expiry = self.issue(
            "ordinary",
            policy_requires_commit=False,
            request_has_commit=False,
        )
        self.assertEqual(receipt["decision"], "COMMIT")
        self.assertIsNone(receipt["commit_authorization"])
        self.assertTrue(verify_decision_receipt(receipt, [self.gate_public_key])["valid"])
        called: list[bool] = []
        result = VerifiedCommitLedger(self.root / "ordinary-ledger.json").execute_once(
            receipt,
            action,
            one_use_code=code,
            trusted_gate_keys=[self.gate_public_key],
            executor=lambda: called.append(True),
        )
        self.assertFalse(result["authorized"])
        self.assertIn("commit_authorization_missing", result["reason_codes"])
        self.assertEqual(called, [])

    def test_executor_failure_spends_permission_and_fails_closed(self) -> None:
        receipt, action, code, _expiry = self.issue("executor-failure")
        ledger = VerifiedCommitLedger(self.root / "executor-failure-ledger.json")
        with self.assertRaisesRegex(RuntimeError, "tool failed"):
            ledger.execute_once(
                receipt,
                action,
                one_use_code=code,
                trusted_gate_keys=[self.gate_public_key],
                executor=lambda: (_ for _ in ()).throw(RuntimeError("tool failed")),
            )
        replay = ledger.execute_once(
            receipt,
            action,
            one_use_code=code,
            trusted_gate_keys=[self.gate_public_key],
            executor=lambda: {"unexpected": True},
        )
        self.assertFalse(replay["authorized"])
        self.assertIn("authorization_replay", replay["reason_codes"])
        state = ledger.read_state()
        authorized = [item for item in state["attempts"] if item["result"] == "AUTHORIZED"]
        self.assertEqual(len(authorized), 1)
        self.assertEqual(authorized[0]["execution_status"], "failed")


if __name__ == "__main__":
    unittest.main()
