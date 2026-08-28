from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

EXP = Path(__file__).resolve().parents[1]
ROOT = EXP.parents[1]
if str(EXP) not in sys.path:
    sys.path.insert(0, str(EXP))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_mesh_identity001 import evaluate_case


class AgentMeshIdentity001Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = json.loads((EXP / "fixtures/cases.json").read_text())
        cls.oracle = json.loads((EXP / "oracle.json").read_text())

    def rows(self, arm: str) -> list[dict]:
        return [evaluate_case(case, arm) for case in self.fixture["cases"]]

    def test_design_lock_still_matches(self) -> None:
        lock = json.loads((EXP / "DESIGN_LOCK.json").read_text())
        for path, expected in lock["files"].items():
            observed = hashlib.sha256((EXP / path).read_bytes()).hexdigest()
            self.assertEqual(observed, expected, path)

    def test_five_paper_subsystems_are_frozen(self) -> None:
        self.assertEqual(
            {case["paper_subsystem"] for case in self.fixture["cases"]},
            {"circuit breaker", "effect ledger", "topology graph", "failure attribution", "work planner"},
        )

    def test_fixture_and_oracle_are_independent_files_with_same_answers(self) -> None:
        expected = {case["case_id"]: case["expected_relation"] for case in self.fixture["cases"]}
        self.assertEqual(self.oracle["cases"], expected)

    def test_paper_failed_identities_reproduce_all_five_errors(self) -> None:
        rows = self.rows("paper_failed_identity")
        self.assertEqual(sum(row["oracle_match"] for row in rows), 0)
        self.assertEqual(sum(row["outcome"] == "FALSE_COLLISION" for row in rows), 4)
        self.assertEqual(sum(row["outcome"] == "FALSE_SPLIT" for row in rows), 1)

    def test_existing_effect_binding_matches_all_five(self) -> None:
        rows = self.rows("current_receipt_gate_effect_binding")
        self.assertEqual(sum(row["oracle_match"] for row in rows), 5)
        self.assertEqual({row["outcome"] for row in rows}, {"PASS"})

    def test_effect_identity_ignores_delegation_provenance(self) -> None:
        case = next(item for item in self.fixture["cases"] if item["case_id"] == "effect-ledger-content")
        row = evaluate_case(case, "current_receipt_gate_effect_binding")
        self.assertNotEqual(case["left"]["proposal_id"], case["right"]["proposal_id"])
        self.assertNotEqual(case["left"]["producer_id"], case["right"]["producer_id"])
        self.assertEqual(row["observed_relation"], "EQUAL")

    def test_effect_identity_preserves_physical_target_distinction(self) -> None:
        case = next(item for item in self.fixture["cases"] if item["case_id"] == "topology-physical-resource")
        self.assertEqual(
            evaluate_case(case, "current_receipt_gate_effect_binding")["observed_relation"],
            "DISTINCT",
        )

    def test_effect_identity_preserves_state_progress_distinction(self) -> None:
        case = next(item for item in self.fixture["cases"] if item["case_id"] == "circuit-breaker-progress")
        self.assertNotEqual(case["left"]["state_hash"], case["right"]["state_hash"])
        self.assertEqual(
            evaluate_case(case, "current_receipt_gate_effect_binding")["observed_relation"],
            "DISTINCT",
        )

    def test_frozen_result_reproduces_exactly(self) -> None:
        before = (EXP / "result.json").read_bytes()
        proc = subprocess.run(
            [sys.executable, str(EXP / "scripts/run_experiment.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual((EXP / "result.json").read_bytes(), before)

    def test_independent_verifier_accepts_frozen_result(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(EXP / "scripts/verify_result.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main()
