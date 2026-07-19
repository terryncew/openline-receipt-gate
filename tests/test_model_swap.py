from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.model_swap import (
    ModelSwapError,
    build_model_swap_proof,
    build_ordinary_summary,
    run_verified_model_swap,
    verify_model_swap_output,
)
from olp_gate.verified_commit import (
    run_verified_commit_demo,
    verify_verified_commit_output,
)


def _half_life_fixture() -> tuple[Path, Path, Path] | None:
    root_value = os.environ.get("OLP_HALF_LIFE_ROOT")
    if not root_value:
        return None
    root = Path(root_value).resolve()
    output = root / "examples" / "demo_output"
    succession_key = root / "policy" / "succession_policy_public_key.hex"
    compaction_key = root / "policy" / "compaction_policy_public_key.hex"
    if not all(path.exists() for path in (output, succession_key, compaction_key)):
        return None
    try:
        import openline_half_life  # noqa: F401
    except ImportError:
        return None
    return output, succession_key, compaction_key


class ModelSwapPureTests(unittest.TestCase):
    def test_ordinary_summary_discloses_what_it_drops(self) -> None:
        summary = build_ordinary_summary(
            {
                "run_id": "run-1",
                "objective": "Ship safely",
                "supported_claims": [],
                "current_constraints": [],
                "commitments": [],
                "unresolved_questions": ["What changed?"],
                "tombstones": [{"identity": "claim:old"}],
            }
        )
        self.assertEqual(
            summary["summary_rule"],
            "active_state_without_negative_history_or_archive_custody",
        )
        self.assertIn("tombstones", summary["omitted_by_rule"])
        self.assertNotIn("tombstones", summary)
        self.assertEqual(len(summary["summary_hash"]), 64)


@unittest.skipUnless(
    _half_life_fixture() is not None,
    "optional Verified Model Swap integration missing: install requirements-model-swap.txt "
    "and set OLP_HALF_LIFE_ROOT",
)
class ModelSwapIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = _half_life_fixture()
        assert fixture is not None
        self.half_life_output, self.succession_key, self.compaction_key = fixture
        self.source_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("51" * 32))
        self.grader_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("52" * 32))
        self.gate_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("53" * 32))

    def proof(self, **changes):
        arguments = {
            "succession_policy_public_key_path": self.succession_key,
            "compaction_policy_public_key_path": self.compaction_key,
            "source_model": "fixture/source-model",
            "target_model": "fixture/target-model",
            "generated_at": "2026-01-01T00:00:00Z",
        }
        arguments.update(changes)
        return build_model_swap_proof(self.half_life_output, **arguments)

    def test_three_lane_proof_is_independently_graded(self) -> None:
        proof = self.proof()
        self.assertTrue(proof["independent_grade"]["passed"])
        self.assertTrue(proof["lanes"]["full_history"]["matches_oracle"])
        self.assertFalse(proof["lanes"]["ordinary_summary"]["matches_oracle"])
        self.assertTrue(proof["lanes"]["verified_capsule"]["matches_oracle"])
        self.assertEqual(len(proof["continuity"]["summary_lost"]), 7)
        self.assertEqual(
            proof["continuity"]["had_to_return_from_archive"],
            proof["continuity"]["summary_lost"],
        )
        self.assertFalse(proof["authority"]["candidate_self_grading_allowed"])
        self.assertFalse(proof["authority"]["dsm_grading_allowed"])

    def test_capsule_mismatch_holds_even_when_candidate_supplies_it(self) -> None:
        clean = self.proof()
        candidates = {
            lane: clean["lanes"][lane]["projection"]
            for lane in ("full_history", "ordinary_summary", "verified_capsule")
        }
        altered = dict(candidates["verified_capsule"])
        removed = next(key for key in altered if key.startswith("constraint:"))
        altered.pop(removed)
        candidates["verified_capsule"] = altered
        held = self.proof(candidate_lane_projections=candidates)
        self.assertFalse(held["independent_grade"]["passed"])
        self.assertFalse(held["independent_grade"]["capsule_matches_oracle"])
        self.assertIn(removed, held["lanes"]["verified_capsule"]["lost_decisions"])
        self.assertEqual(held["display"]["disposition"], "HOLD")

    def test_receiver_gate_commits_bound_swap_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="verified-model-swap-") as temporary:
            result = run_verified_model_swap(
                self.half_life_output,
                temporary,
                succession_policy_public_key_path=self.succession_key,
                compaction_policy_public_key_path=self.compaction_key,
                source_model="fixture/source-model",
                target_model="fixture/target-model",
                source_signing_key=self.source_key,
                grader_signing_key=self.grader_key,
                gate_signing_key=self.gate_key,
                gate_issuer="test-model-swap-gate",
            )
            self.assertTrue(result["passed"])
            self.assertEqual(result["decision"], "COMMIT")
            self.assertTrue(result["verification"]["valid"])

            def verify():
                return verify_model_swap_output(
                    temporary,
                    trusted_gate_keys=[result["gate_public_key"]],
                    half_life_output=self.half_life_output,
                    succession_policy_public_key_path=self.succession_key,
                    compaction_policy_public_key_path=self.compaction_key,
                )

            source_path = Path(temporary) / "source_receipt.json"
            original_source = source_path.read_bytes()
            source = json.loads(original_source)
            proof_value = source["proof"]["proofValue"]
            tamper_at = len(proof_value) // 2
            source["proof"]["proofValue"] = (
                proof_value[:tamper_at]
                + ("A" if proof_value[tamper_at] != "A" else "B")
                + proof_value[tamper_at + 1 :]
            )
            source_path.write_text(json.dumps(source, sort_keys=True) + "\n", encoding="utf-8")
            self.assertIn("source_receipt_integrity_invalid", verify()["errors"])
            source_path.write_bytes(original_source)

            outcome_path = Path(temporary) / "outcome_receipt.json"
            original_outcome = outcome_path.read_bytes()
            outcome = json.loads(original_outcome)
            outcome["outcome"]["status"] = "fail"
            outcome_path.write_text(json.dumps(outcome, sort_keys=True) + "\n", encoding="utf-8")
            self.assertIn("outcome_receipt_invalid", verify()["errors"])
            outcome_path.write_bytes(original_outcome)

            projection_path = Path(temporary) / "verified_model_swap.latest.json"
            original_projection = projection_path.read_bytes()
            projection = json.loads(original_projection)
            projection["integrity"]["decision_receipt_payload_hash"] = "00" * 32
            projection_path.write_text(
                json.dumps(projection, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            self.assertIn("dsm_projection_decision_hash_mismatch", verify()["errors"])
            projection_path.write_bytes(original_projection)
            self.assertTrue(verify()["valid"])

    def test_proof_card_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="verified-model-swap-") as temporary:
            result = run_verified_model_swap(
                self.half_life_output,
                temporary,
                succession_policy_public_key_path=self.succession_key,
                compaction_policy_public_key_path=self.compaction_key,
                source_model="fixture/source-model",
                target_model="fixture/target-model",
                source_signing_key=self.source_key,
                grader_signing_key=self.grader_key,
                gate_signing_key=self.gate_key,
                gate_issuer="test-model-swap-gate",
            )
            proof_path = Path(temporary) / "proof_card.json"
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            proof["independent_grade"]["capsule_matches_oracle"] = False
            proof_path.write_text(json.dumps(proof, sort_keys=True) + "\n", encoding="utf-8")
            verification = verify_model_swap_output(
                temporary,
                trusted_gate_keys=[result["gate_public_key"]],
                half_life_output=self.half_life_output,
                succession_policy_public_key_path=self.succession_key,
                compaction_policy_public_key_path=self.compaction_key,
            )
            self.assertFalse(verification["valid"])
            self.assertIn("proof_card_hash_mismatch", verification["errors"])
            self.assertIn(
                "decision_evidence_hash_binding_mismatch", verification["errors"]
            )

    def test_untrusted_half_life_policy_pin_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="verified-model-swap-pin-") as temporary:
            wrong_pin = Path(temporary) / "wrong.hex"
            wrong_pin.write_text("00" * 32 + "\n", encoding="ascii")
            with self.assertRaisesRegex(ModelSwapError, "receiver verification"):
                self.proof(succession_policy_public_key_path=wrong_pin)

    def test_source_grader_and_gate_keys_must_be_separate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="verified-model-swap-") as temporary:
            with self.assertRaisesRegex(ModelSwapError, "keys must differ"):
                run_verified_model_swap(
                    self.half_life_output,
                    temporary,
                    succession_policy_public_key_path=self.succession_key,
                    compaction_policy_public_key_path=self.compaction_key,
                    source_model="fixture/source-model",
                    target_model="fixture/target-model",
                    source_signing_key=self.source_key,
                    grader_signing_key=self.source_key,
                    gate_signing_key=self.gate_key,
                    gate_issuer="test-model-swap-gate",
                )

    def test_verified_commit_demo_blocks_mutations_replay_and_double_use(self) -> None:
        with tempfile.TemporaryDirectory(prefix="verified-commit-model-swap-") as temporary:
            result = run_verified_commit_demo(
                self.half_life_output,
                temporary,
                succession_policy_public_key_path=self.succession_key,
                compaction_policy_public_key_path=self.compaction_key,
                source_model="fixture/model-a",
                target_model="fixture/model-b",
                source_signing_key=self.source_key,
                grader_signing_key=self.grader_key,
                gate_signing_key=self.gate_key,
                gate_issuer="test-verified-commit-gate",
            )
            self.assertTrue(result["passed"])
            self.assertEqual(result["decision"], "COMMIT")
            self.assertEqual(result["mutation_count"], 9)
            self.assertEqual(result["mutations_blocked_before_execution"], 9)
            self.assertEqual(result["simultaneous_authorized"], 1)
            self.assertEqual(result["simultaneous_blocked"], 1)
            self.assertTrue(result["replay_blocked"])
            self.assertTrue(result["verification"]["valid"])

    def test_verified_commit_execution_record_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="verified-commit-tamper-") as temporary:
            result = run_verified_commit_demo(
                self.half_life_output,
                temporary,
                succession_policy_public_key_path=self.succession_key,
                compaction_policy_public_key_path=self.compaction_key,
                source_model="fixture/model-a",
                target_model="fixture/model-b",
                source_signing_key=self.source_key,
                grader_signing_key=self.grader_key,
                gate_signing_key=self.gate_key,
                gate_issuer="test-verified-commit-gate",
            )
            approved_path = Path(temporary) / "approved_action.json"
            approved = json.loads(approved_path.read_text(encoding="utf-8"))
            approved["target"] = "artifact://tampered.json"
            approved_path.write_text(
                json.dumps(approved, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            verification = verify_verified_commit_output(
                temporary,
                trusted_gate_keys=[result["gate_public_key"]],
                half_life_output=self.half_life_output,
                succession_policy_public_key_path=self.succession_key,
                compaction_policy_public_key_path=self.compaction_key,
            )
            self.assertFalse(verification["valid"])
            self.assertIn("executed_action_target_mismatch", verification["errors"])
            self.assertIn("executed_result_hash_mismatch", verification["errors"])


if __name__ == "__main__":
    unittest.main()
