from __future__ import annotations

import copy
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[1]
WALLET001_ROOT = REPO_ROOT / "experiments" / "wallet-standing-001"
for path in (REPO_ROOT, WALLET001_ROOT, ROOT, ROOT / "scripts"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from olp_gate.crypto import public_key_hex, sign_olp_body  # noqa: E402
from run_frozen import T0, T_RECOVERY, run_frozen  # noqa: E402
from wallet002 import (  # noqa: E402
    RootRecoveryError,
    accept_root_succession,
    create_recovery_policy,
    create_root_succession_event,
    initialize_root_view,
    verify_historical_epoch_certificate,
    verify_recovery_policy,
)


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(f"wallet002-test:{label}".encode()).digest()
    )


class WalletStanding002FrozenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = run_frozen()
        cls.rows = {row["arm_id"]: row for row in cls.result["rows"]}

    def test_frozen_verdict_is_earned(self):
        self.assertTrue(self.result["passed"])
        self.assertEqual(
            self.result["verdict"],
            "QUORUM_ROOT_SUCCESSION_ENFORCED_WITH_DECLARED_RECOVERY_LAG",
        )
        self.assertEqual(self.result["metrics"]["passed_arm_count"], 13)

    def test_compromised_root_exposure_is_visible(self):
        row = self.rows["02_compromised_root_before_recovery_acceptance"]
        self.assertTrue(row["declared_exposure"])
        self.assertEqual(row["observed"]["decision"], "PASS")
        self.assertEqual(self.result["metrics"]["recovery_lag_seconds"], 300)

    def test_old_root_has_zero_effect_after_acceptance(self):
        self.assertEqual(
            self.result["metrics"]["post_acceptance_old_root_execution_count"],
            0,
        )
        for arm in (
            "07_compromised_descendant_after_acceptance",
            "08_legitimate_old_descendant_after_acceptance",
        ):
            self.assertEqual(self.rows[arm]["observed"]["decision"], "BLOCK")

    def test_history_survives_without_execution_authority(self):
        observed = self.rows[
            "09_old_history_remains_authentic_noncurrent"
        ]["observed"]
        self.assertTrue(observed["cryptographically_authentic"])
        self.assertEqual(observed["status"], "HISTORICALLY_AUTHENTIC_NONCURRENT")
        self.assertEqual(observed["execution_authority"], "NONE")

    def test_successor_and_unrelated_control_both_pass(self):
        self.assertEqual(self.rows["10_successor_root_action"]["observed"]["decision"], "PASS")
        self.assertEqual(self.rows["11_unrelated_principal_control"]["observed"]["decision"], "PASS")
        self.assertEqual(
            self.result["metrics"]["unrelated_principal_collateral_loss_count"],
            0,
        )

    def test_threshold_compromise_is_declared_and_accepted(self):
        row = self.rows["13_recovery_threshold_compromise"]
        self.assertTrue(row["declared_exposure"])
        self.assertEqual(row["observed"]["decision"], "ACCEPT_SUCCESSION")
        self.assertEqual(
            self.result["metrics"]["declared_threshold_compromise_acceptance_count"],
            1,
        )

    def test_all_authority_labels_preserve_receiver_boundary(self):
        self.assertEqual(self.result["wallet_policy_authority"], "NONE")
        self.assertEqual(self.result["decision_authority"], "RECEIVER_GATE")
        for arm in ("03_old_root_self_declares_successor", "06_valid_two_of_three_root_succession"):
            receipt = self.rows[arm]["observed"]
            self.assertEqual(receipt["wallet_policy_authority"], "NONE")
            self.assertEqual(receipt["decision_authority"], "RECEIVER_GATE")

    def test_frozen_result_is_deterministic(self):
        first = json.dumps(run_frozen(), sort_keys=True, separators=(",", ":"))
        second = json.dumps(run_frozen(), sort_keys=True, separators=(",", ":"))
        self.assertEqual(first, second)


class RootRecoveryProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.old_root = _key("old-root")
        self.new_root = _key("new-root")
        self.guardians = {
            "guardian-1": _key("guardian-1"),
            "guardian-2": _key("guardian-2"),
            "guardian-3": _key("guardian-3"),
        }
        self.policy = create_recovery_policy(
            self.old_root,
            self.guardians,
            policy_id="policy-test",
            principal_id="principal-test",
            threshold=2,
            issued_at=T0,
        )
        self.view = initialize_root_view(
            self.policy,
            trusted_policy_hash=self.policy["policy_hash"],
        )

    def event(self, approvals=None, **overrides):
        values = {
            "event_id": "event-test",
            "prior_root_public_key": public_key_hex(self.old_root),
            "prior_generation": 1,
            "successor_root_public_key": public_key_hex(self.new_root),
            "successor_generation": 2,
            "reason": "COMPROMISED",
            "effective_at": T_RECOVERY,
        }
        values.update(overrides)
        return create_root_succession_event(
            self.policy,
            approvals
            or {
                "guardian-1": self.guardians["guardian-1"],
                "guardian-2": self.guardians["guardian-2"],
            },
            **values,
        )

    def test_receiver_pin_is_mandatory(self):
        with self.assertRaisesRegex(RootRecoveryError, "recovery_policy_pin_mismatch"):
            initialize_root_view(self.policy, trusted_policy_hash="00" * 32)

    def test_policy_unknown_field_fails_closed(self):
        tampered = copy.deepcopy(self.policy)
        tampered["wallet_says_ok"] = True
        with self.assertRaisesRegex(RootRecoveryError, "recovery_policy_shape_invalid"):
            verify_recovery_policy(
                tampered,
                expected_policy_hash=self.policy["policy_hash"],
            )

    def test_guardian_acceptance_threshold_is_required_at_policy_creation(self):
        incomplete = copy.deepcopy(self.policy)
        incomplete["guardian_acceptances"] = incomplete["guardian_acceptances"][:1]
        with self.assertRaisesRegex(
            RootRecoveryError, "guardian_acceptance_threshold_not_met"
        ):
            verify_recovery_policy(
                incomplete,
                expected_policy_hash=self.policy["policy_hash"],
            )

    def test_duplicate_guardian_key_is_rejected(self):
        duplicate = _key("duplicate")
        with self.assertRaisesRegex(RootRecoveryError, "guardian_key_duplicate"):
            create_recovery_policy(
                self.old_root,
                {"guardian-1": duplicate, "guardian-2": duplicate},
                policy_id="policy-duplicate",
                principal_id="principal-test",
                threshold=2,
                issued_at=T0,
            )

    def test_one_guardian_cannot_recover(self):
        event = self.event(
            approvals={"guardian-1": self.guardians["guardian-1"]}
        )
        next_view, receipt = accept_root_succession(
            self.view, self.policy, event, now=T_RECOVERY
        )
        self.assertEqual(next_view, self.view)
        self.assertEqual(receipt["reason_codes"], ["RECOVERY_THRESHOLD_NOT_MET"])

    def test_old_root_cannot_pose_as_guardian(self):
        event = self.event(approvals={"guardian-1": self.old_root})
        next_view, receipt = accept_root_succession(
            self.view, self.policy, event, now=T_RECOVERY
        )
        self.assertEqual(next_view, self.view)
        self.assertEqual(
            receipt["reason_codes"], ["GUARDIAN_APPROVAL_SIGNER_MISMATCH"]
        )

    def test_valid_quorum_succeeds_without_old_root_signature(self):
        event = self.event()
        signer_keys = {
            approval["signature"]["public_key"] for approval in event["approvals"]
        }
        self.assertNotIn(public_key_hex(self.old_root), signer_keys)
        next_view, receipt = accept_root_succession(
            self.view, self.policy, event, now=T_RECOVERY
        )
        self.assertTrue(receipt["accepted"])
        self.assertEqual(next_view.current_generation, 2)
        self.assertEqual(next_view.current_root_public_key, public_key_hex(self.new_root))

    def test_future_succession_is_rejected(self):
        event = self.event(effective_at=T_RECOVERY + timedelta(seconds=1))
        next_view, receipt = accept_root_succession(
            self.view, self.policy, event, now=T_RECOVERY
        )
        self.assertEqual(next_view, self.view)
        self.assertEqual(receipt["reason_codes"], ["SUCCESSION_NOT_EFFECTIVE"])

    def test_altered_event_is_rejected(self):
        event = self.event()
        event["body"]["successor_generation"] = 3
        next_view, receipt = accept_root_succession(
            self.view, self.policy, event, now=T_RECOVERY
        )
        self.assertEqual(next_view, self.view)
        self.assertEqual(receipt["reason_codes"], ["SUCCESSION_EVENT_HASH_INVALID"])

    def test_exact_event_replay_is_rejected(self):
        event = self.event()
        next_view, accepted = accept_root_succession(
            self.view, self.policy, event, now=T_RECOVERY
        )
        replay_view, replay = accept_root_succession(
            next_view, self.policy, event, now=T_RECOVERY + timedelta(seconds=1)
        )
        self.assertTrue(accepted["accepted"])
        self.assertEqual(replay_view, next_view)
        self.assertEqual(replay["reason_codes"], ["SUCCESSION_REPLAYED"])

    def test_rollback_to_old_root_is_rejected(self):
        next_view, _receipt = accept_root_succession(
            self.view, self.policy, self.event(), now=T_RECOVERY
        )
        rollback = self.event(
            event_id="event-rollback",
            prior_root_public_key=public_key_hex(self.new_root),
            prior_generation=2,
            successor_root_public_key=public_key_hex(self.old_root),
            successor_generation=3,
            effective_at=T_RECOVERY + timedelta(seconds=1),
        )
        unchanged, receipt = accept_root_succession(
            next_view,
            self.policy,
            rollback,
            now=T_RECOVERY + timedelta(seconds=1),
        )
        self.assertEqual(unchanged, next_view)
        self.assertEqual(receipt["reason_codes"], ["ROOT_ROLLBACK_FORBIDDEN"])

    def test_threshold_key_compromise_is_indistinguishable(self):
        attacker_root = _key("attacker-root")
        attacker_event = self.event(
            event_id="event-attacker",
            successor_root_public_key=public_key_hex(attacker_root),
        )
        attacker_view, receipt = accept_root_succession(
            self.view, self.policy, attacker_event, now=T_RECOVERY
        )
        self.assertTrue(receipt["accepted"])
        self.assertEqual(
            attacker_view.current_root_public_key,
            public_key_hex(attacker_root),
        )

    def test_historical_verifier_rejects_wrong_schema(self):
        record = sign_olp_body(
            {
                "schema": "openline.not_an_epoch.v1",
                "principal_id": "principal-test",
            },
            self.old_root,
        )
        result = verify_historical_epoch_certificate(self.view, record)
        self.assertEqual(result["verification"], "FAIL")
        self.assertEqual(
            result["reason_codes"], ["HISTORICAL_CERTIFICATE_SCHEMA_INVALID"]
        )

    def test_historical_verifier_requires_complete_epoch_shape(self):
        record = sign_olp_body(
            {
                "schema": "openline.wallet_epoch_certificate.v1",
                "principal_id": "principal-test",
                "epoch_id": "epoch-incomplete",
            },
            self.old_root,
        )
        result = verify_historical_epoch_certificate(self.view, record)
        self.assertEqual(result["verification"], "FAIL")
        self.assertEqual(
            result["reason_codes"], ["HISTORICAL_CERTIFICATE_SHAPE_INVALID"]
        )


class WalletStanding002ReleaseTests(unittest.TestCase):
    def test_release_verifier_passes(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "verify_release.py")],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("WALLET002_RELEASE_OK", completed.stdout)


if __name__ == "__main__":
    unittest.main()
