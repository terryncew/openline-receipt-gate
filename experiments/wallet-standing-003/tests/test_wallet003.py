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
WALLET002_ROOT = REPO_ROOT / "experiments" / "wallet-standing-002"
for path in (
    REPO_ROOT,
    WALLET001_ROOT,
    WALLET002_ROOT,
    ROOT,
    ROOT / "scripts",
):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from olp_gate.crypto import public_key_hex  # noqa: E402
from run_frozen import (  # noqa: E402
    T0,
    T_FORK,
    T_FREEZE,
    T_FREEZE_EXPIRES,
    T_SUCCESSION,
    _issue_bundle,
    _key as frozen_key,
    run_frozen,
)
from wallet002 import create_recovery_policy, create_root_succession_event  # noqa: E402
from wallet003 import (  # noqa: E402
    create_guardian_freeze,
    create_root_checkpoint,
    evaluate_distributed_bundle,
    ingest_guardian_freeze,
    ingest_root_checkpoint,
    ingest_root_succession,
    initialize_distributed_gate,
)
from wallet001 import AdmissionPolicy  # noqa: E402


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(f"wallet003-test:{label}".encode()).digest()
    )


class WalletStanding003FrozenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = run_frozen()
        cls.rows = {row["arm_id"]: row for row in cls.result["rows"]}

    def test_frozen_verdict_is_earned(self):
        self.assertTrue(self.result["passed"])
        self.assertEqual(
            self.result["verdict"],
            "RECEIVED_FREEZE_AND_FORK_QUARANTINE_ENFORCED_"
            "WITH_DECLARED_INFORMATION_LAG",
        )
        self.assertEqual(self.result["metrics"]["passed_arm_count"], 15)

    def test_received_freeze_has_zero_old_root_execution(self):
        self.assertEqual(
            self.result["metrics"]["freeze_received_old_root_execution_count"],
            0,
        )
        self.assertEqual(
            self.rows["02_received_freeze_blocks_old_root"]["observed"]["decision"],
            "BLOCK",
        )

    def test_information_lag_is_visible(self):
        for arm in (
            "03_unreceived_freeze_information_lag",
            "05_stale_freeze_is_not_backdated",
        ):
            self.assertTrue(self.rows[arm]["declared_exposure"])
        self.assertEqual(
            self.result["metrics"]["freeze_unreceived_old_root_execution_count"],
            1,
        )
        self.assertEqual(
            self.result["metrics"]["stale_freeze_old_root_execution_count"],
            1,
        )

    def test_single_guardian_dos_and_expiry_are_visible(self):
        self.assertTrue(
            self.rows["07_malicious_guardian_bounded_dos"]["declared_exposure"]
        )
        self.assertTrue(
            self.rows["08_exact_expiry_restores_current_root"]["declared_exposure"]
        )
        self.assertEqual(self.result["metrics"]["malicious_guardian_dos_seconds"], 600)
        self.assertEqual(
            self.result["metrics"]["post_expiry_legitimate_execution_count"], 1
        )

    def test_replay_never_extends_freeze(self):
        self.assertEqual(self.result["metrics"]["freeze_replay_extension_seconds"], 0)
        observed = self.rows["06_freeze_replay_cannot_extend"]["observed"]
        self.assertEqual(len(observed["observed_expiries"]), 1)

    def test_virgin_gate_checkpoint_boundary(self):
        self.assertEqual(
            self.result["metrics"]["virgin_without_checkpoint_execution_count"], 0
        )
        self.assertEqual(
            self.result["metrics"]["virgin_with_checkpoint_execution_count"], 1
        )

    def test_partition_exposure_then_quarantine(self):
        row = self.rows["15_partitioned_quorum_fork_quarantine"]
        self.assertTrue(row["declared_exposure"])
        self.assertEqual(
            self.result["metrics"]["partitioned_conflicting_branch_execution_count"],
            2,
        )
        self.assertEqual(
            self.result["metrics"]["post_fork_detection_execution_count"], 0
        )
        self.assertEqual(self.result["metrics"]["fork_quarantine_count"], 2)
        self.assertEqual(self.result["metrics"]["automatic_convergence_count"], 0)

    def test_authority_labels_are_stable(self):
        self.assertEqual(self.result["wallet_policy_authority"], "NONE")
        self.assertEqual(
            self.result["freeze_authority"],
            "ONE_PRECOMMITTED_GUARDIAN_REDUCE_ONLY",
        )
        self.assertEqual(
            self.result["succession_authority"],
            "PRECOMMITTED_GUARDIAN_QUORUM",
        )
        self.assertEqual(self.result["decision_authority"], "RECEIVER_GATE")

    def test_frozen_result_is_deterministic(self):
        first = json.dumps(run_frozen(), sort_keys=True, separators=(",", ":"))
        second = json.dumps(run_frozen(), sort_keys=True, separators=(",", ":"))
        self.assertEqual(first, second)


class DistributedStandingProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.old_root = _key("old-root")
        self.new_root = _key("new-root")
        self.other_root = _key("other-root")
        self.subject = frozen_key("principal-subject")
        self.guardians = {
            "guardian-1": _key("guardian-1"),
            "guardian-2": _key("guardian-2"),
            "guardian-3": _key("guardian-3"),
        }
        self.policy = create_recovery_policy(
            self.old_root,
            self.guardians,
            policy_id="policy-test-distributed",
            principal_id="principal-test",
            threshold=2,
            issued_at=T0,
        )
        self.state = self.gate("gate-test")

    def gate(self, gate_id: str, *, virgin: bool = False):
        return initialize_distributed_gate(
            self.policy,
            trusted_policy_hash=self.policy["policy_hash"],
            gate_id=gate_id,
            requires_checkpoint=virgin,
        )

    def freeze(self, **overrides):
        values = {
            "event_id": "freeze-test",
            "guardian_id": "guardian-1",
            "reason": "SUSPECTED_COMPROMISE",
            "issued_at": T_FREEZE,
            "expires_at": T_FREEZE_EXPIRES,
        }
        values.update(overrides)
        key = values.pop(
            "signing_key",
            self.guardians.get(values["guardian_id"], _key("unknown")),
        )
        return create_guardian_freeze(
            self.policy,
            key,
            self.state.root_view,
            **values,
        )

    def succession(self, *, successor=None, event_id="succession-test"):
        successor = successor or self.new_root
        return create_root_succession_event(
            self.policy,
            {
                "guardian-1": self.guardians["guardian-1"],
                "guardian-2": self.guardians["guardian-2"],
            },
            event_id=event_id,
            prior_root_public_key=public_key_hex(self.old_root),
            prior_generation=1,
            successor_root_public_key=public_key_hex(successor),
            successor_generation=2,
            reason="COMPROMISED",
            effective_at=T_SUCCESSION,
        )

    def checkpoint(self, state, *, approvals=None, **overrides):
        values = {
            "checkpoint_id": "checkpoint-test",
            "issued_at": T_SUCCESSION + timedelta(seconds=1),
            "expires_at": T_SUCCESSION + timedelta(seconds=121),
        }
        values.update(overrides)
        return create_root_checkpoint(
            self.policy,
            approvals
            or {
                "guardian-1": self.guardians["guardian-1"],
                "guardian-2": self.guardians["guardian-2"],
            },
            state.root_view,
            **values,
        )

    def test_fresh_guardian_freeze_is_reduce_only(self):
        next_state, receipt = ingest_guardian_freeze(
            self.state,
            self.policy,
            self.freeze(),
            now=T_FREEZE + timedelta(seconds=1),
        )
        self.assertEqual(receipt["decision"], "ACCEPT_FREEZE")
        self.assertEqual(receipt["freeze_authority"], "ONE_PRECOMMITTED_GUARDIAN_REDUCE_ONLY")
        self.assertEqual(next_state.root_view, self.state.root_view)
        self.assertIsNotNone(next_state.active_freeze)

    def test_unknown_field_fails_closed(self):
        event = self.freeze()
        event["wallet_says_ok"] = True
        next_state, receipt = ingest_guardian_freeze(
            self.state,
            self.policy,
            event,
            now=T_FREEZE + timedelta(seconds=1),
        )
        self.assertEqual(next_state, self.state)
        self.assertEqual(receipt["reason_codes"], ["FREEZE_EVENT_SHAPE_INVALID"])

    def test_tampered_freeze_fails_closed(self):
        event = self.freeze()
        event["expires_at"] = (T_FREEZE_EXPIRES + timedelta(seconds=1)).isoformat()
        next_state, receipt = ingest_guardian_freeze(
            self.state,
            self.policy,
            event,
            now=T_FREEZE + timedelta(seconds=1),
        )
        self.assertEqual(next_state, self.state)
        self.assertEqual(receipt["reason_codes"], ["FREEZE_SIGNATURE_INVALID"])

    def test_old_root_cannot_pose_as_guardian(self):
        event = self.freeze(signing_key=self.old_root)
        next_state, receipt = ingest_guardian_freeze(
            self.state,
            self.policy,
            event,
            now=T_FREEZE + timedelta(seconds=1),
        )
        self.assertEqual(next_state, self.state)
        self.assertEqual(
            receipt["reason_codes"], ["FREEZE_GUARDIAN_SIGNER_MISMATCH"]
        )

    def test_future_freeze_is_rejected(self):
        event = self.freeze(
            issued_at=T_FREEZE + timedelta(seconds=10),
            expires_at=T_FREEZE_EXPIRES + timedelta(seconds=10),
        )
        _, receipt = ingest_guardian_freeze(
            self.state, self.policy, event, now=T_FREEZE
        )
        self.assertEqual(receipt["reason_codes"], ["FREEZE_FROM_FUTURE"])

    def test_overlong_freeze_is_rejected(self):
        event = self.freeze(expires_at=T_FREEZE + timedelta(seconds=601))
        _, receipt = ingest_guardian_freeze(
            self.state,
            self.policy,
            event,
            now=T_FREEZE + timedelta(seconds=1),
        )
        self.assertEqual(
            receipt["reason_codes"], ["FREEZE_DURATION_EXCEEDS_POLICY"]
        )

    def test_exact_expiry_is_rejected_on_delivery(self):
        _, receipt = ingest_guardian_freeze(
            self.state,
            self.policy,
            self.freeze(),
            now=T_FREEZE_EXPIRES,
            max_event_age_seconds=1000,
        )
        self.assertEqual(receipt["reason_codes"], ["FREEZE_EXPIRED"])

    def test_stale_freeze_is_rejected(self):
        _, receipt = ingest_guardian_freeze(
            self.state,
            self.policy,
            self.freeze(),
            now=T_FREEZE + timedelta(seconds=61),
        )
        self.assertEqual(receipt["reason_codes"], ["FREEZE_STALE"])

    def test_replay_and_second_freeze_do_not_extend(self):
        frozen, accepted = ingest_guardian_freeze(
            self.state,
            self.policy,
            self.freeze(),
            now=T_FREEZE + timedelta(seconds=1),
        )
        original = frozen.active_freeze
        replayed, replay = ingest_guardian_freeze(
            frozen,
            self.policy,
            self.freeze(),
            now=T_FREEZE + timedelta(seconds=2),
        )
        second = self.freeze(
            event_id="freeze-second",
            guardian_id="guardian-2",
            issued_at=T_FREEZE + timedelta(seconds=1),
            expires_at=T_FREEZE_EXPIRES + timedelta(seconds=1),
        )
        repeated, repeated_receipt = ingest_guardian_freeze(
            frozen,
            self.policy,
            second,
            now=T_FREEZE + timedelta(seconds=2),
        )
        self.assertTrue(accepted["accepted"])
        self.assertEqual(replay["reason_codes"], ["FREEZE_REPLAYED"])
        self.assertEqual(
            repeated_receipt["reason_codes"], ["FREEZE_GENERATION_ALREADY_USED"]
        )
        self.assertEqual(replayed.active_freeze, original)
        self.assertEqual(repeated.active_freeze, original)

    def test_quorum_succession_clears_active_freeze(self):
        frozen, _ = ingest_guardian_freeze(
            self.state,
            self.policy,
            self.freeze(),
            now=T_FREEZE + timedelta(seconds=1),
        )
        advanced, receipt = ingest_root_succession(
            frozen, self.policy, self.succession(), now=T_SUCCESSION
        )
        self.assertEqual(receipt["decision"], "ACCEPT_SUCCESSION")
        self.assertTrue(receipt["freeze_cleared"])
        self.assertIsNone(advanced.active_freeze)
        self.assertEqual(advanced.root_view.current_generation, 2)

    def test_second_event_to_same_successor_is_not_a_fork(self):
        advanced, _ = ingest_root_succession(
            self.state, self.policy, self.succession(), now=T_SUCCESSION
        )
        duplicate_branch = self.succession(event_id="succession-same-root-new-event")
        unchanged, receipt = ingest_root_succession(
            advanced,
            self.policy,
            duplicate_branch,
            now=T_SUCCESSION + timedelta(seconds=1),
        )
        self.assertFalse(unchanged.fork_quarantined)
        self.assertEqual(
            receipt["reason_codes"], ["SUCCESSION_BRANCH_ALREADY_ACCEPTED"]
        )

    def test_conflicting_valid_successions_quarantine(self):
        advanced, _ = ingest_root_succession(
            self.state, self.policy, self.succession(), now=T_SUCCESSION
        )
        forked, receipt = ingest_root_succession(
            advanced,
            self.policy,
            self.succession(successor=self.other_root, event_id="succession-other"),
            now=T_SUCCESSION + timedelta(seconds=1),
        )
        self.assertTrue(forked.fork_quarantined)
        self.assertEqual(receipt["decision"], "FORK_DETECTED")
        self.assertEqual(receipt["resolution"], "EXTERNAL_RESOLUTION_REQUIRED")

    def test_virgin_gate_blocks_without_checkpoint(self):
        virgin = self.gate("gate-virgin", virgin=True)
        fixture = _issue_bundle(
            self.old_root,
            self.subject,
            principal_id="principal-test",
            epoch_id="epoch-virgin",
            mandate_id="mandate-virgin",
            action={"action": "transfer", "amount_cents": 100, "recipient": "a.example"},
            issued_at=T_FREEZE,
        )
        result = evaluate_distributed_bundle(
            virgin,
            fixture["bundle"],
            expected_action=fixture["action"],
            receiver_challenge="wallet-standing-003-gate",
            now=T_FREEZE + timedelta(seconds=1),
            policy=AdmissionPolicy(60, 600, ("action", "amount_cents", "recipient"), True),
        )
        self.assertEqual(result["reason_codes"], ["CURRENT_ROOT_CHECKPOINT_REQUIRED"])

    def test_valid_checkpoint_confirms_but_does_not_install_view(self):
        advanced, _ = ingest_root_succession(
            self.gate("gate-checkpoint", virgin=True),
            self.policy,
            self.succession(),
            now=T_SUCCESSION,
        )
        before_view = advanced.root_view
        checked, receipt = ingest_root_checkpoint(
            advanced,
            self.policy,
            self.checkpoint(advanced),
            now=T_SUCCESSION + timedelta(seconds=2),
        )
        self.assertEqual(receipt["decision"], "ACCEPT_CHECKPOINT")
        self.assertEqual(checked.root_view, before_view)
        self.assertIsNotNone(checked.checkpoint)

    def test_one_guardian_checkpoint_is_rejected(self):
        advanced, _ = ingest_root_succession(
            self.gate("gate-checkpoint-one", virgin=True),
            self.policy,
            self.succession(),
            now=T_SUCCESSION,
        )
        checkpoint = self.checkpoint(
            advanced,
            approvals={"guardian-1": self.guardians["guardian-1"]},
        )
        unchanged, receipt = ingest_root_checkpoint(
            advanced,
            self.policy,
            checkpoint,
            now=T_SUCCESSION + timedelta(seconds=2),
        )
        self.assertEqual(unchanged, advanced)
        self.assertEqual(receipt["reason_codes"], ["CHECKPOINT_THRESHOLD_NOT_MET"])

    def test_checkpoint_cannot_install_an_unknown_root(self):
        advanced, _ = ingest_root_succession(
            self.gate("gate-checkpoint-tamper", virgin=True),
            self.policy,
            self.succession(),
            now=T_SUCCESSION,
        )
        checkpoint = self.checkpoint(advanced)
        checkpoint["body"]["root_public_key"] = public_key_hex(self.other_root)
        unchanged, receipt = ingest_root_checkpoint(
            advanced,
            self.policy,
            checkpoint,
            now=T_SUCCESSION + timedelta(seconds=2),
        )
        self.assertEqual(unchanged, advanced)
        self.assertEqual(receipt["reason_codes"], ["CHECKPOINT_ROOT_MISMATCH"])

    def test_stale_checkpoint_is_rejected(self):
        advanced, _ = ingest_root_succession(
            self.gate("gate-checkpoint-stale", virgin=True),
            self.policy,
            self.succession(),
            now=T_SUCCESSION,
        )
        _, receipt = ingest_root_checkpoint(
            advanced,
            self.policy,
            self.checkpoint(advanced),
            now=T_SUCCESSION + timedelta(seconds=62),
        )
        self.assertEqual(receipt["reason_codes"], ["CHECKPOINT_STALE"])

    def test_fork_quarantine_rejects_all_state_updates(self):
        advanced, _ = ingest_root_succession(
            self.state, self.policy, self.succession(), now=T_SUCCESSION
        )
        forked, _ = ingest_root_succession(
            advanced,
            self.policy,
            self.succession(successor=self.other_root, event_id="succession-other"),
            now=T_SUCCESSION + timedelta(seconds=1),
        )
        same, freeze_receipt = ingest_guardian_freeze(
            forked,
            self.policy,
            self.freeze(),
            now=T_FREEZE + timedelta(seconds=1),
        )
        same_checkpoint, checkpoint_receipt = ingest_root_checkpoint(
            forked,
            self.policy,
            {},
            now=T_SUCCESSION + timedelta(seconds=2),
        )
        self.assertEqual(same, forked)
        self.assertEqual(same_checkpoint, forked)
        self.assertEqual(freeze_receipt["reason_codes"], ["ROOT_FORK_QUARANTINED"])
        self.assertEqual(
            checkpoint_receipt["reason_codes"], ["ROOT_FORK_QUARANTINED"]
        )

    def test_naive_gate_time_fails_closed(self):
        result = evaluate_distributed_bundle(
            self.state,
            {},
            expected_action={},
            receiver_challenge="challenge",
            now=T0.replace(tzinfo=None),
            policy=AdmissionPolicy(60, 600, ("action",), True),
        )
        self.assertEqual(result["decision"], "BLOCK")
        self.assertEqual(result["reason_codes"], ["GATE_TIME_TIMEZONE_REQUIRED"])


class WalletStanding003ReleaseTests(unittest.TestCase):
    def test_release_verifier_passes(self):
        verifier = ROOT / "scripts" / "verify_release.py"
        if not verifier.is_file():
            self.skipTest("release verifier is created after the frozen files")
        completed = subprocess.run(
            [sys.executable, str(verifier)],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("WALLET003_RELEASE_OK", completed.stdout)


if __name__ == "__main__":
    unittest.main()
