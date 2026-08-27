from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
import tempfile
import unittest

from olp_gate.field_tiers import verify_field_tier_receipt

from benchmarks.temporal_authority_001.run_suite import (
    GATE_PUBLIC_KEY,
    VERDICT,
    run_suite,
)
from benchmarks.temporal_authority_001.verify_report import verify


ROOT = Path(__file__).resolve().parents[1]
SUITE = ROOT / "benchmarks" / "temporal_authority_001"
FROZEN_REPORT = SUITE / "results" / "temporal-authority-001-report.json"
FREEZE = SUITE / "FREEZE.json"
SOURCE = SUITE / "SOURCE.json"


class TemporalAuthority001Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = run_suite()
        cls.by_id = {row["case_id"]: row for row in cls.report["rows"]}

    def verify_document(self, value: dict) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            path.write_text(
                json.dumps(value, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return verify(
                path,
                freeze_path=FREEZE,
                source_path=SOURCE,
                root=ROOT,
            )

    def test_frozen_matrix_passes_without_new_authority_primitive(self) -> None:
        self.assertTrue(self.report["passed"])
        self.assertEqual(self.report["verdict"], VERDICT)
        self.assertEqual(self.report["case_count"], 7)
        self.assertEqual(self.report["policy_authority"], "NONE")
        self.assertTrue(all(row["passed"] for row in self.report["rows"]))

    def test_authorized_controls_execute_once(self) -> None:
        expected = {
            "stable_owner_control",
            "stable_owner_with_peer_go_deadline",
            "unrelated_receiver_change_sham",
            "fresh_owner_successor_control",
        }
        executed = {
            case_id
            for case_id, row in self.by_id.items()
            if row["observed"]["executed"]
        }
        self.assertEqual(executed, expected)
        for case_id in expected:
            observed = self.by_id[case_id]["observed"]
            self.assertEqual(observed["effect_delta"], 1)
            self.assertEqual(observed["execution_status"], "completed")

    def test_hostile_arms_consume_permission_and_stop_before_effect(self) -> None:
        for case_id in (
            "relevant_owner_supersession",
            "relevant_owner_supersession_with_peer_go",
            "hidden_payload_mutation",
        ):
            observed = self.by_id[case_id]["observed"]
            self.assertFalse(observed["executed"])
            self.assertEqual(observed["effect_delta"], 0)
            self.assertTrue(observed["permission_consumed"])
            self.assertEqual(
                observed["execution_status"], "preflight_blocked"
            )

    def test_peer_go_changes_neither_matched_outcome(self) -> None:
        def outcome(case_id: str) -> tuple:
            item = self.by_id[case_id]["observed"]
            return (
                item["executed"],
                item["blocked"],
                item["effect_delta"],
                item["execution_status"],
            )

        self.assertEqual(
            outcome("stable_owner_control"),
            outcome("stable_owner_with_peer_go_deadline"),
        )
        self.assertEqual(
            outcome("relevant_owner_supersession"),
            outcome("relevant_owner_supersession_with_peer_go"),
        )

    def test_unrelated_change_is_a_real_selectivity_control(self) -> None:
        sham = self.by_id["unrelated_receiver_change_sham"]["observed"]
        relevant = self.by_id["relevant_owner_supersession"]["observed"]
        self.assertTrue(sham["anchor_fired"])
        self.assertTrue(relevant["anchor_fired"])
        self.assertTrue(sham["executed"])
        self.assertFalse(relevant["executed"])

    def test_gate_surface_contains_no_coordination_context(self) -> None:
        expected = [
            "action_parameters_hash",
            "amount_cents",
            "recipient_domain",
        ]
        for row in self.report["rows"]:
            self.assertEqual(
                row["observed"]["gate_argument_fields"], expected
            )
            self.assertFalse(
                row["coordination"]["entered_gate_arguments"]
            )

    def test_public_field_receipts_are_valid_and_gate_bound(self) -> None:
        for row in self.report["rows"]:
            observed = row["observed"]
            receipt = observed["field_tier_receipt"]
            checked = verify_field_tier_receipt(
                receipt, [GATE_PUBLIC_KEY]
            )
            self.assertTrue(checked["valid"])
            self.assertEqual(checked["authority"], "EVIDENCE_ONLY")
            self.assertEqual(
                receipt["decision"]["receiver_decision_hash"],
                observed["gate_decision"]["payload_hash"],
            )

    def test_public_report_has_no_raw_or_minimized_fixture_values(self) -> None:
        rendered = json.dumps(self.report, sort_keys=True)
        for forbidden in (
            "Patient.778812@customer.example",
            "oncology discharge for patient 778812",
            "route-secret-4b7e2a",
            "customer.example",
            "substituted hidden payload after compile",
        ):
            self.assertNotIn(forbidden, rendered)
        self.assertEqual(self.report["privacy"]["forbidden_literal_count"], 0)

    def test_frozen_report_passes_independent_verification(self) -> None:
        result = verify(
            FROZEN_REPORT,
            freeze_path=FREEZE,
            source_path=SOURCE,
            root=ROOT,
        )
        self.assertTrue(result["valid"], result["errors"])
        self.assertGreaterEqual(result["source_file_count"], 10)

    def test_independent_verifier_imports_no_candidate_module(self) -> None:
        tree = ast.parse((SUITE / "verify_report.py").read_text(encoding="utf-8"))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
        self.assertFalse(
            any(
                name == "olp_gate"
                or name.startswith("olp_gate.")
                or name.startswith("benchmarks.temporal_authority_001")
                for name in imported
            )
        )

    def test_verifier_rejects_effect_count_tampering(self) -> None:
        tampered = copy.deepcopy(self.report)
        tampered["rows"][3]["observed"]["effect_delta"] = 1
        result = self.verify_document(tampered)
        self.assertFalse(result["valid"])
        self.assertTrue(
            any("effect_delta_mismatch" in error for error in result["errors"])
        )

    def test_verifier_rejects_receipt_binding_tampering(self) -> None:
        tampered = copy.deepcopy(self.report)
        tampered["rows"][0]["observed"]["field_tier_receipt"]["decision"][
            "receiver_decision_hash"
        ] = "00" * 32
        result = self.verify_document(tampered)
        self.assertFalse(result["valid"])
        self.assertTrue(
            any("field_receipt" in error for error in result["errors"])
        )

    def test_verifier_rejects_peer_message_tampering(self) -> None:
        tampered = copy.deepcopy(self.report)
        tampered["rows"][1]["coordination"]["message"]["directive"] = "VETO"
        result = self.verify_document(tampered)
        self.assertFalse(result["valid"])
        self.assertTrue(
            any("peer_signature_invalid" in error for error in result["errors"])
        )

    def test_verifier_rejects_public_literal_injection(self) -> None:
        tampered = copy.deepcopy(self.report)
        tampered["claim_boundary"].append("customer.example")
        result = self.verify_document(tampered)
        self.assertFalse(result["valid"])
        self.assertTrue(
            any(
                "public_report_forbidden_literal" in error
                for error in result["errors"]
            )
        )

    def test_verifier_rejects_missing_case(self) -> None:
        tampered = copy.deepcopy(self.report)
        tampered["rows"].pop()
        tampered["case_count"] -= 1
        result = self.verify_document(tampered)
        self.assertFalse(result["valid"])
        self.assertIn("case_count_mismatch", result["errors"])


if __name__ == "__main__":
    unittest.main()

