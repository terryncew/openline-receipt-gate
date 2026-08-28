from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest


EXP = Path(__file__).resolve().parents[1]
if str(EXP) not in sys.path:
    sys.path.insert(0, str(EXP))
SCRIPTS = EXP / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from run_experiment import run  # noqa: E402
from sara_spec001 import (  # noqa: E402
    evaluate_broad_recall,
    evaluate_minimal_sara,
    evaluate_openline_recall,
    evaluate_published_sara,
)
from verify_result import verify  # noqa: E402


def load(name: str):
    return json.loads((EXP / name).read_text(encoding="utf-8"))


class SaraSpec001Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture = load("fixtures/scenario.json")
        cls.controls = {
            item["control_id"]: item for item in cls.fixture["controls"]
        }
        cls.oracle = load("oracle.json")["controls"]

    def test_design_was_locked_before_outcome(self) -> None:
        lock = load("DESIGN_LOCK.json")
        self.assertEqual(lock["run_status_at_lock"], "NOT_RUN")
        self.assertFalse(lock["amendments_allowed_after_lock"])
        for relative, expected in lock["files"].items():
            actual = hashlib.sha256((EXP / relative).read_bytes()).hexdigest()
            self.assertEqual(actual, expected, relative)

    def test_published_sara_is_out_of_scope_and_unscored(self) -> None:
        observed = evaluate_published_sara(
            self.fixture,
            self.controls["revoke_k1_after_task"],
        )
        self.assertEqual(observed["scope_status"], "OUT_OF_SCOPE_AFTER_TASK_END")
        self.assertFalse(observed["scored"])
        self.assertEqual(set(observed["dispositions"].values()), {"UNASSESSED"})

    def test_broad_recall_reopens_the_unrelated_decision(self) -> None:
        observed = evaluate_broad_recall(
            self.fixture,
            self.controls["revoke_k1_after_task"],
        )
        self.assertEqual(observed["dispositions"], {"D1": "REOPEN", "D2": "REOPEN"})

    def test_minimal_sara_matches_revocation_oracle_without_new_persistent_state(self) -> None:
        observed = evaluate_minimal_sara(
            self.fixture,
            self.controls["revoke_k1_after_task"],
        )
        self.assertEqual(
            {
                **observed["dispositions"],
                "historical_evidence": observed["historical_evidence"],
            },
            self.oracle["revoke_k1_after_task"],
        )
        self.assertEqual(
            observed["state_shape"],
            {
                "persisted_keys": ["F", "H", "K"],
                "extension_keys": ["standing_updates"],
                "new_persistent_structure_count": 0,
                "returns_derived_relationships": False,
            },
        )

    def test_openline_matches_revocation_oracle_with_explicit_relations(self) -> None:
        observed = evaluate_openline_recall(
            self.fixture,
            self.controls["revoke_k1_after_task"],
        )
        self.assertEqual(
            {
                **observed["dispositions"],
                "historical_evidence": observed["historical_evidence"],
            },
            self.oracle["revoke_k1_after_task"],
        )
        self.assertEqual(
            observed["persisted_support_relations"],
            [["A", "D1"], ["B", "D2"], ["K1", "A"], ["K2", "B"]],
        )

    def test_noop_preserves_both_decisions_in_every_scored_arm(self) -> None:
        control = self.controls["noop_k1_after_task"]
        for evaluator in (
            evaluate_broad_recall,
            evaluate_minimal_sara,
            evaluate_openline_recall,
        ):
            with self.subTest(evaluator=evaluator.__name__):
                observed = evaluator(self.fixture, control)
                self.assertEqual(observed["dispositions"], {"D1": "PRESERVE", "D2": "PRESERVE"})
                self.assertEqual(observed["historical_evidence"], "UNCHANGED")

    def test_minimal_sara_is_value_driven_instead_of_answer_coded(self) -> None:
        altered = copy.deepcopy(self.fixture)
        altered["decisions"][0]["basis_token"] = "f" * 64
        observed = evaluate_minimal_sara(
            altered,
            self.controls["revoke_k1_after_task"],
        )
        self.assertEqual(observed["dispositions"]["D1"], "PRESERVE")
        self.assertEqual(observed["dispositions"]["D2"], "PRESERVE")

    def test_frozen_result_reproduces_exactly(self) -> None:
        self.assertEqual(run(), load("result.json"))

    def test_independent_verifier_accepts_the_frozen_result(self) -> None:
        result = verify()
        self.assertTrue(result["valid"], json.dumps(result, indent=2, sort_keys=True))
        self.assertEqual(result["verified_verdict"], "SARA_EXTENSION_PARITY")
        self.assertEqual(result["verified_rows"], 8)


if __name__ == "__main__":
    unittest.main()
