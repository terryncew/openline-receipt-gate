from __future__ import annotations

import unittest
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from benchmarks.mandate_owner_001.run_suite import (
    Harness,
    run_case_matrix,
    run_preflight_head_change_case,
)
from olp_gate.crypto import public_key_hex, verify_olp_signature
from olp_gate.mandate_owner import (
    MANDATE_AUTHORIZATION_SCHEMA,
    MandateAuthorityError,
    MandateOwnerView,
    issue_mandate_authorization,
)
from olp_gate.standing import ReceiverStandingView


class MandateOwner001Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_case_matrix()
        cls.rows = {row["case"]: row for row in cls.report["rows"]}

    def test_frozen_six_arm_matrix_passes(self):
        self.assertTrue(self.report["passed"])
        self.assertEqual(self.report["case_count"], 6)
        self.assertEqual(
            self.report["verdict"],
            "MANDATE_AUTHORSHIP_AUTHORITY_SEPARATION",
        )
        self.assertEqual(self.report["policy_authority"], "NONE")

    def test_valid_developer_authored_draft_has_no_authority(self):
        row = self.rows["developer_authored_valid_mandate_without_owner_admission"]
        self.assertEqual(row["claim_class"], "NEW_AUTHORSHIP_AUTHORITY_INVARIANT")
        self.assertTrue(row["observed"]["blocked"])
        self.assertEqual(row["observed"]["effect_delta"], 0)

    def test_developer_signature_cannot_promote_draft(self):
        row = self.rows["developer_signed_mandate_wrong_key"]
        self.assertTrue(row["receiver_rejected"])
        self.assertEqual(row["rejection_reason"], "mandate_authorization_owner_key_mismatch")
        self.assertTrue(row["observed"]["blocked"])

    def test_agent_signature_cannot_promote_own_mandate(self):
        row = self.rows["agent_signed_mandate_wrong_key"]
        self.assertTrue(row["receiver_rejected"])
        self.assertEqual(row["rejection_reason"], "mandate_authorization_owner_key_mismatch")
        self.assertTrue(row["observed"]["blocked"])

    def test_pinned_owner_can_confer_authority(self):
        row = self.rows["pinned_owner_admits_100_dollar_mandate"]
        self.assertTrue(row["observed"]["executed"])
        self.assertEqual(row["observed"]["effect_delta"], 1)

    def test_old_owner_signed_mandate_remains_authentic_but_not_current(self):
        row = self.rows["old_owner_signed_100_mandate_after_narrowing_to_50"]
        self.assertEqual(row["claim_class"], "COMPOSITION_WITH_CURRENT_HEAD_SEMANTICS")
        self.assertTrue(row["historical_authorization_verified"])
        self.assertFalse(row["historical_authorization_current"])
        self.assertTrue(row["historical_signature_still_valid"])
        self.assertTrue(row["historical_bytes_unchanged"])
        self.assertTrue(row["observed"]["blocked"])

    def test_owner_successor_restores_current_authority(self):
        row = self.rows["owner_admitted_100_successor_restores_75_action"]
        self.assertTrue(row["observed"]["executed"])

    def test_falsifier_is_not_triggered(self):
        falsifier = self.report["falsifier"]
        self.assertFalse(falsifier["receiver_standing_admit_reused_unmodified"])
        self.assertTrue(falsifier["new_owner_validation_path_present"])
        self.assertFalse(falsifier["triggered"])
        self.assertIsNot(MandateOwnerView.admit, ReceiverStandingView.admit)
        self.assertNotEqual(MANDATE_AUTHORIZATION_SCHEMA, "openline.standing_projection.v1")

    def test_second_owner_signed_initial_record_without_successor_order_is_rejected(self):
        h = Harness()
        first = h.mandate(10_000, version="v1")
        second = h.mandate(5_000, version="v2")
        h.admit_owner(first)
        unordered = h.authorization(
            second,
            key=h.owner_key,
            sequence=1,
            predecessor_hash=None,
        )
        with self.assertRaisesRegex(
            MandateAuthorityError,
            "mandate_authorization_successor_sequence_invalid",
        ):
            h.view.admit(unordered, second, now=h.now)

    def test_owner_identity_is_receiver_pinned_not_mandate_self_asserted(self):
        h = Harness()
        bad = h.mandate(10_000, version="other-principal")
        bad["principal_id"] = "mallory"
        record = issue_mandate_authorization(
            slot_id=h.SLOT_ID,
            owner_id="alice",
            mandate=bad,
            state="ACTIVE",
            sequence=1,
            predecessor_hash=None,
            issued_at=h.now,
            expires_at=h.now + timedelta(hours=1),
            key=h.owner_key,
        )
        valid_signature, _ = verify_olp_signature(record)
        self.assertTrue(valid_signature)
        with self.assertRaisesRegex(MandateAuthorityError, "mandate_principal_owner_mismatch"):
            h.view.admit(record, bad, now=h.now)

    def test_receiver_pinned_owner_key_is_required(self):
        with self.assertRaisesRegex(MandateAuthorityError, "mandate_owner_public_key_invalid"):
            MandateOwnerView({"slot": {"owner_id": "alice", "public_key": "00"}})

    def test_revoked_current_mandate_has_no_current_authority(self):
        h = Harness()
        mandate = h.mandate(10_000, version="v1")
        h.admit_owner(mandate)
        revoke = h.authorization(mandate, key=h.owner_key, state="REVOKED")
        h.view.admit(revoke, mandate, now=h.now)
        self.assertEqual(h.view.status(h.SLOT_ID, now=h.now), "REVOKED")
        self.assertIsNone(h.view.current_mandate(h.SLOT_ID, now=h.now))

    def test_head_change_between_compile_and_preflight_blocks(self):
        result = run_preflight_head_change_case()
        self.assertTrue(result["passed"])
        self.assertTrue(result["observed"]["blocked"])
        self.assertEqual(result["observed"]["effect_delta"], 0)

    def test_untrusted_key_can_sign_but_cannot_become_owner(self):
        h = Harness()
        mandate = h.mandate(50_000, version="v500")
        outsider = Ed25519PrivateKey.generate()
        self.assertNotEqual(public_key_hex(outsider), public_key_hex(h.owner_key))
        record = h.authorization(
            mandate,
            key=outsider,
            sequence=1,
            predecessor_hash=None,
        )
        valid_signature, _ = verify_olp_signature(record)
        self.assertTrue(valid_signature)
        with self.assertRaisesRegex(MandateAuthorityError, "mandate_authorization_owner_key_mismatch"):
            h.view.admit(record, mandate, now=h.now)


if __name__ == "__main__":
    unittest.main()
