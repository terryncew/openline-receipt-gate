from __future__ import annotations

import unittest

from benchmarks.standing_seam_001.run_suite import run_case_matrix


class StandingSeam001Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_case_matrix()
        cls.rows = {row["case"]: row for row in cls.report["rows"]}

    def test_frozen_claim_matrix_passes(self):
        self.assertTrue(self.report["passed"])

    def test_valid_approval_remains_cryptographically_valid_after_revoke(self):
        row = self.rows["relevant_revocation_selective_block"]
        self.assertTrue(row["approval_bytes_unchanged"])
        self.assertTrue(row["approval_signature_still_valid"])

    def test_relevant_revocation_blocks_same_unchanged_action(self):
        row = self.rows["relevant_revocation_selective_block"]
        self.assertTrue(row["initial"]["executed"])
        self.assertTrue(row["after_event"]["blocked"])
        self.assertEqual(row["after_event"]["effect_delta"], 0)

    def test_unrelated_action_survives_relevant_revocation(self):
        row = self.rows["relevant_revocation_selective_block"]
        self.assertTrue(row["unrelated"]["executed"])

    def test_other_standing_loss_events_block(self):
        for name in (
            "relevant_expire_blocks",
            "relevant_supersede_blocks",
            "relevant_correct_blocks",
        ):
            with self.subTest(name=name):
                self.assertTrue(self.rows[name]["passed"])

    def test_unrelated_revocation_does_not_overblock(self):
        self.assertTrue(self.rows["unrelated_revocation_preserves_action"]["passed"])

    def test_old_pre_revocation_projection_cannot_be_replayed(self):
        self.assertTrue(
            self.rows["old_pre_revocation_projection_replay_blocked"]["passed"]
        )

    def test_agent_cannot_self_restore_standing(self):
        row = self.rows["agent_fabricated_standing_restore_blocked"]
        self.assertTrue(row["passed"])
        self.assertTrue(row["receiver_rejected_forged_successor"])

    def test_receiver_admitted_successor_restores_action(self):
        self.assertTrue(
            self.rows["receiver_admitted_successor_restores_action"]["passed"]
        )


if __name__ == "__main__":
    unittest.main()
