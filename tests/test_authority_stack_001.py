from __future__ import annotations

import unittest

from benchmarks.authority_stack_001.run_suite import run_sequence


class AuthorityStack001Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_sequence()
        cls.rows = {row["stage"]: row for row in cls.report["rows"]}

    def test_end_to_end_composition_passes(self):
        self.assertTrue(self.report["passed"])
        self.assertEqual(self.report["verdict"], "AUTHORITY_STACK_COMPOSITION_PASS")
        self.assertEqual(self.report["policy_authority"], "NONE")

    def test_authorship_is_not_authority(self):
        row = self.rows["developer_proposes_without_owner_authority"]
        self.assertTrue(row["passed"])
        self.assertTrue(row["observed"]["blocked"])
        self.assertEqual(row["observed"]["effect_delta"], 0)

    def test_initial_action_uses_receiver_admitted_mandate(self):
        row = self.rows["active_standing_executes_exact_action"]
        self.assertTrue(row["passed"])
        self.assertTrue(row["observed"]["executed"])
        self.assertNotEqual(
            row["developer_draft_mandate_hash"],
            row["current_owner_mandate_hash"],
        )
        self.assertEqual(
            row["observed"]["compiled_mandate_hash"],
            row["current_owner_mandate_hash"],
        )

    def test_valid_receipt_can_lose_current_standing(self):
        row = self.rows["valid_receipt_loses_current_standing_selectively"]
        self.assertTrue(row["receipt_signature_still_valid"])
        self.assertTrue(row["receipt_bytes_unchanged"])
        self.assertTrue(row["receipt_hash_unchanged"])
        self.assertTrue(row["revoked_action"]["blocked"])
        self.assertEqual(row["revoked_action"]["effect_delta"], 0)

    def test_standing_loss_is_selective(self):
        row = self.rows["valid_receipt_loses_current_standing_selectively"]
        self.assertTrue(row["unrelated_action"]["executed"])
        self.assertEqual(row["unrelated_action"]["effect_delta"], 1)

    def test_superseded_mandate_remains_authentic_but_noncurrent(self):
        row = self.rows["superseded_mandate_authentic_but_noncurrent"]
        self.assertTrue(row["old_mandate_signature_still_valid"])
        self.assertTrue(row["old_mandate_bytes_unchanged"])
        self.assertTrue(row["old_mandate_verified"])
        self.assertFalse(row["old_mandate_current"])

    def test_current_mandate_not_old_mandate_governs(self):
        row = self.rows["superseded_mandate_authentic_but_noncurrent"]
        probe = row["governance_probe_90_under_current_80"]
        self.assertTrue(probe["blocked"])
        self.assertEqual(probe["effect_delta"], 0)

    def test_mandate_successor_cannot_silently_restore_standing(self):
        row = self.rows["mandate_successor_does_not_restore_revoked_standing"]
        self.assertTrue(row["passed"])
        self.assertTrue(row["observed"]["blocked"])

    def test_explicit_standing_successor_restores_under_current_mandate(self):
        row = self.rows["explicit_standing_successor_restores_execution"]
        self.assertTrue(row["passed"])
        self.assertTrue(row["observed"]["executed"])
        self.assertEqual(
            row["observed"]["compiled_mandate_hash"],
            row["current_mandate_hash"],
        )
        self.assertTrue(row["receipt_signature_still_valid"])
        self.assertTrue(row["receipt_bytes_unchanged"])

    def test_composition_uses_real_local_runtime_and_no_bypass(self):
        constraints = self.report["composition_constraints"]
        self.assertTrue(constraints["uses_local_authority_runtime"])
        self.assertFalse(constraints["custom_runtime_shim"])
        self.assertFalse(constraints["receipt_mutation_used"])
        self.assertFalse(constraints["bypass_flags_used"])
        self.assertFalse(constraints["standing_layer_rewrites_mandate"])
        self.assertFalse(constraints["mandate_successor_silently_restores_standing"])
        self.assertFalse(constraints["new_core_authority_primitive_added"])
        self.assertFalse(self.report["falsifier"]["triggered"])


if __name__ == "__main__":
    unittest.main()
