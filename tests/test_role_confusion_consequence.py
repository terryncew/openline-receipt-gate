from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

from olp_gate.crypto import MAX_SAFE_INTEGER
from olp_gate.role_confusion import (
    COMMIT,
    DENY,
    QUARANTINE,
    ConsequenceGateError,
    appraise_consequence,
    execute_appraised_consequence,
    run_case_matrix,
)


ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmarks" / "role_confusion_consequence"
NOW = datetime(2026, 7, 30, 12, 0, 0, tzinfo=timezone.utc)


class RoleConfusionConsequenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads(
            (BENCH / "receiver-policy.json").read_text(encoding="utf-8")
        )
        cls.cases_document = json.loads(
            (BENCH / "cases.json").read_text(encoding="utf-8")
        )
        cls.cases = cls.cases_document["cases"]
        cls.by_id = {case["case_id"]: case for case in cls.cases}

    def test_frozen_matrix_matches_expected_with_real_effect_callbacks(self) -> None:
        report = run_case_matrix(self.cases_document, self.policy)
        self.assertTrue(report["passed"])
        self.assertEqual(report["case_count"], 13)
        for row in report["rows"]:
            with self.subTest(case=row["case_id"]):
                self.assertEqual(row["observed"], row["expected"])
                self.assertEqual(
                    row["effect_invocation_count"],
                    1 if row["observed"]["decision"] == COMMIT else 0,
                )

    def test_blocked_cases_never_invoke_the_protected_effect(self) -> None:
        for case in self.cases:
            calls: list[str] = []

            def executor() -> dict[str, bool]:
                calls.append(case["case_id"])
                return {"released": True}

            out = execute_appraised_consequence(
                case["request"],
                self.policy,
                now=NOW,
                consumed_nonces=case.get("consumed_nonces", []),
                executor=executor,
            )
            with self.subTest(case=case["case_id"]):
                should_execute = case["expected"]["decision"] == COMMIT
                self.assertEqual(out["protected_effect_executed"], should_execute)
                self.assertEqual(len(calls), 1 if should_execute else 0)

    def test_attack_text_and_labels_are_not_gate_inputs(self) -> None:
        forbidden = {
            "stimulus",
            "model_compromise_assumed",
            "class",
            "prompt",
            "model_reasoning",
            "injection_score",
        }
        for case in self.cases:
            self.assertEqual(
                set(case["request"]),
                {"schema", "request_id", "action", "evidence"},
            )
            self.assertFalse(forbidden & set(case["request"]))

    def test_same_action_untrusted_support_blocks_trusted_support_commits(self) -> None:
        bad = self.by_id["poisoned_webpage_only_support"]
        good = self.by_id["matched_legitimate_twin"]
        self.assertEqual(bad["request"]["action"], good["request"]["action"])
        bad_out = appraise_consequence(bad["request"], self.policy, now=NOW)
        good_out = appraise_consequence(good["request"], self.policy, now=NOW)
        self.assertEqual(bad_out["assessments"]["authorization"]["status"], "PASS")
        self.assertEqual(good_out["assessments"]["authorization"]["status"], "PASS")
        self.assertEqual(bad_out["decision"], QUARANTINE)
        self.assertEqual(good_out["decision"], COMMIT)

    def test_fresh_trusted_negative_vetoes_fresh_trusted_positive(self) -> None:
        case = self.by_id["trusted_negative_evidence"]
        out = appraise_consequence(case["request"], self.policy, now=NOW)
        support = out["assessments"]["evidence_support"]
        self.assertEqual(out["decision"], QUARANTINE)
        self.assertIn("trusted_action_support_conflict", support["reason_codes"])
        self.assertEqual(support["details"]["valid_support_ids"], ["E-trusted-ok"])
        self.assertEqual(
            support["details"]["negative_support_ids"],
            ["E-trusted-negative"],
        )

    def test_unrelated_untrusted_evidence_does_not_turn_gate_into_blocker(self) -> None:
        case = self.by_id["unrelated_untrusted_addition_does_not_block"]
        self.assertEqual(
            appraise_consequence(case["request"], self.policy, now=NOW)["decision"],
            COMMIT,
        )

    def test_mixed_trusted_exact_and_wrong_action_fails_closed_before_effect(self) -> None:
        case = self.by_id["mixed_trusted_exact_and_wrong_action"]
        out = appraise_consequence(case["request"], self.policy, now=NOW)
        support = out["assessments"]["evidence_support"]
        self.assertEqual(out["decision"], DENY)
        self.assertEqual(support["status"], "FAIL")
        self.assertEqual(support["details"]["valid_support_ids"], ["E-trusted-ok"])
        self.assertEqual(
            support["details"]["wrong_action_evidence_ids"],
            ["E-trusted-wrong-action"],
        )
        calls: list[str] = []
        executed = execute_appraised_consequence(
            case["request"],
            self.policy,
            now=NOW,
            executor=lambda: calls.append("effect"),
        )
        self.assertEqual(executed["decision"], DENY)
        self.assertFalse(executed["protected_effect_executed"])
        self.assertEqual(calls, [])

    def test_receiver_pinned_key_cannot_be_self_asserted(self) -> None:
        case = self.by_id["forged_trusted_origin_key"]
        out = appraise_consequence(case["request"], self.policy, now=NOW)
        self.assertEqual(out["decision"], DENY)
        self.assertEqual(out["assessments"]["authorization"]["status"], "PASS")
        self.assertTrue(
            out["assessments"]["evidence_origin"]["details"][
                "invalid_trusted_proof_ids"
            ]
        )

    def test_duplicate_evidence_ids_fail_closed(self) -> None:
        request = copy.deepcopy(
            self.by_id["clean_trusted_authorization"]["request"]
        )
        request["evidence"].append(copy.deepcopy(request["evidence"][0]))
        out = appraise_consequence(request, self.policy, now=NOW)
        self.assertEqual(out["decision"], "UNDECIDABLE")
        self.assertIn(
            "evidence_id_duplicate",
            out["assessments"]["input"]["reason_codes"],
        )

    def test_unsigned_signature_extensions_fail_closed(self) -> None:
        request = copy.deepcopy(
            self.by_id["clean_trusted_authorization"]["request"]
        )
        request["evidence"][0]["signature"]["unsigned_role"] = "receiver"
        out = appraise_consequence(request, self.policy, now=NOW)
        self.assertEqual(out["decision"], "UNDECIDABLE")
        self.assertIn(
            "evidence_signature_shape_invalid",
            out["assessments"]["input"]["reason_codes"],
        )

    def test_oversized_policy_integers_fail_closed_without_raw_exception(self) -> None:
        request = self.by_id["clean_trusted_authorization"]["request"]
        for path in ("max_evidence_age_seconds", "max_ttl_seconds"):
            policy = copy.deepcopy(self.policy)
            if path == "max_ttl_seconds":
                policy["action_template"][path] = MAX_SAFE_INTEGER + 1
            else:
                policy[path] = MAX_SAFE_INTEGER + 1
            with self.subTest(path=path):
                out = appraise_consequence(request, policy, now=NOW)
                self.assertEqual(out["decision"], "UNDECIDABLE")

    def test_malformed_request_is_undecidable_not_crash(self) -> None:
        out = appraise_consequence({"request_id": "broken"}, self.policy, now=NOW)
        self.assertEqual(out["decision"], "UNDECIDABLE")

    def test_policy_is_receiver_owned_not_request_supplied(self) -> None:
        case = self.by_id["poisoned_webpage_only_support"]
        forged = dict(case["request"])
        forged["receiver_policy"] = self.policy
        out = appraise_consequence(forged, self.policy, now=NOW)
        self.assertEqual(out["decision"], "UNDECIDABLE")

    def test_receiver_state_shape_fails_closed_without_raw_exception(self) -> None:
        case = self.by_id["clean_trusted_authorization"]
        values = (
            None,
            7,
            "nonce-clean-001",
            {"nonce-clean-001": True},
            [None],
            [7],
            ["x", "x"],
        )
        for bad in values:
            with self.subTest(consumed_nonces=bad):
                out = appraise_consequence(
                    case["request"],
                    self.policy,
                    now=NOW,
                    consumed_nonces=bad,
                )
                self.assertEqual(out["decision"], "UNDECIDABLE")

    def test_receiver_clock_shape_fails_closed_without_raw_exception(self) -> None:
        case = self.by_id["clean_trusted_authorization"]
        values = (
            "2026-07-30T12:00:00Z",
            7,
            datetime(2026, 7, 30, 12, 0, 0),
        )
        for bad in values:
            with self.subTest(now=bad):
                out = appraise_consequence(
                    case["request"],
                    self.policy,
                    now=bad,
                )
                self.assertEqual(out["decision"], "UNDECIDABLE")

    def test_invalid_executor_fails_before_effect(self) -> None:
        case = self.by_id["clean_trusted_authorization"]
        out = execute_appraised_consequence(
            case["request"],
            self.policy,
            now=NOW,
            executor=None,
        )
        self.assertEqual(out["decision"], "UNDECIDABLE")
        self.assertFalse(out["protected_effect_authorized"])
        self.assertFalse(out["protected_effect_executed"])
        self.assertFalse(out["execution"]["tool_invoked"])

    def test_case_matrix_shape_errors_are_bounded(self) -> None:
        malformed = (
            None,
            {},
            {"schema": "wrong", "frozen_now": "2026-07-30T12:00:00Z", "cases": []},
            {
                "schema": self.cases_document["schema"],
                "frozen_now": self.cases_document["frozen_now"],
                "cases": [],
            },
        )
        for value in malformed:
            with self.subTest(value=value):
                with self.assertRaises(ConsequenceGateError):
                    run_case_matrix(value, self.policy)

    def test_top_level_help_exposes_role_confusion_command(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-m", "olp_gate.command", "--help"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("role-confusion-suite", proc.stdout)

    def test_independent_verifier_passes(self) -> None:
        subprocess.run(
            [
                sys.executable,
                "benchmarks/role_confusion_consequence/run_suite.py",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        proc = subprocess.run(
            [sys.executable, "scripts/verify_role_confusion_consequence.py"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        report = json.loads(proc.stdout)
        self.assertTrue(report["valid"])
        self.assertTrue(report["independent_of_gate_module"])
        self.assertTrue(report["source_closure_verified"])


if __name__ == "__main__":
    unittest.main()
