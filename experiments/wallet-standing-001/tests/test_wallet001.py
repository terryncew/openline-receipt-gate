from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from olp_gate.crypto import public_key_hex  # noqa: E402
from run_frozen import (  # noqa: E402
    HIGH_CHALLENGE,
    LOW_CHALLENGE,
    T0,
    T1,
    _bundle,
    _issue_fixture,
    _policy,
    run_frozen,
)
from wallet001 import (  # noqa: E402
    AdmissionPolicy,
    WalletProtocolError,
    build_presentation_bundle,
    evaluate_bundle,
    issue_epoch_certificate,
    issue_mandate,
)


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(f"wallet001-test:{label}".encode()).digest()
    )


class WalletStandingFrozenTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = run_frozen()
        cls.rows = {row["arm_id"]: row for row in cls.result["rows"]}

    def test_frozen_verdict_is_earned(self):
        self.assertTrue(self.result["passed"])
        self.assertEqual(
            self.result["verdict"],
            "EPOCH_REVOCATION_ENFORCED_WITH_BOUNDED_OFFLINE_LAG",
        )
        self.assertEqual(self.result["metrics"]["passed_arm_count"], 10)

    def test_high_risk_revoked_stale_and_missing_all_block(self):
        expected = {
            "02_high_fresh_revoked": "EPOCH_REVOKED",
            "03_high_stale_active_witness": "FRESHNESS_REQUIRED",
            "04_high_missing_witness": "FRESHNESS_REQUIRED",
        }
        for arm, reason in expected.items():
            with self.subTest(arm=arm):
                observed = self.rows[arm]["observed"]
                self.assertEqual(observed["decision"], "BLOCK")
                self.assertFalse(observed["executed"])
                self.assertIn(reason, observed["reason_codes"])

    def test_successor_and_independent_sibling_survive(self):
        for arm in (
            "05_high_successor_epoch",
            "06_high_independent_root_sibling",
        ):
            with self.subTest(arm=arm):
                self.assertEqual(self.rows[arm]["observed"]["decision"], "PASS")
        self.assertEqual(self.result["metrics"]["collateral_loss_count"], 0)

    def test_offline_revocation_lag_is_exposed_not_hidden(self):
        row = self.rows["08_low_revoked_but_unexpired_offline"]
        self.assertTrue(row["declared_exposure"])
        self.assertEqual(row["observed"]["decision"], "PASS")
        self.assertEqual(
            self.result["metrics"]["offline_exposure_ceiling_seconds"], 600
        )

    def test_low_risk_exact_expiry_blocks(self):
        row = self.rows["09_low_at_expiry_no_witness"]["observed"]
        self.assertEqual(row["decision"], "BLOCK")
        self.assertEqual(row["reason_codes"], ["MANDATE_EXPIRED"])

    def test_all_tamper_variants_block_without_effect(self):
        observed = self.rows["10_projection_and_holder_tampering"]["observed"]
        self.assertEqual(observed["decision"], "BLOCK_ALL")
        self.assertEqual(observed["effect_delta"], 0)
        self.assertFalse(observed["executed"])
        self.assertEqual(len(observed["variants"]), 4)

    def test_every_gate_result_denies_wallet_policy_authority(self):
        for row in self.result["rows"]:
            observed = row["observed"]
            variants = observed.get("variants", {})
            receipts = variants.values() if variants else [observed]
            for receipt in receipts:
                self.assertEqual(receipt["wallet_policy_authority"], "NONE")
                self.assertEqual(receipt["decision_authority"], "RECEIVER_GATE")

    def test_frozen_result_is_deterministic(self):
        first = json.dumps(run_frozen(), sort_keys=True, separators=(",", ":"))
        second = json.dumps(run_frozen(), sort_keys=True, separators=(",", ":"))
        self.assertEqual(first, second)


class WalletProtocolBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _issue_fixture()
        self.high_fields = ("action", "amount_cents", "recipient")
        self.high_policy = _policy(self.high_fields)
        self.high_bundle = _bundle(
            self.fixture["high1"],
            fields=self.high_fields,
            subject=self.fixture["subject"],
            challenge=HIGH_CHALLENGE,
            witness=self.fixture["active_epoch1"],
        )

    def test_untrusted_root_blocks(self):
        decision = evaluate_bundle(
            self.high_bundle,
            trusted_root_public_key=public_key_hex(_key("wrong-root")),
            expected_action=self.fixture["high_action"],
            receiver_challenge=HIGH_CHALLENGE,
            now=T0 + timedelta(seconds=30),
            policy=self.high_policy,
        )
        self.assertEqual(decision["decision"], "BLOCK")
        self.assertEqual(decision["reason_codes"], ["EPOCH_CERTIFICATE_SIGNER_MISMATCH"])

    def test_receiver_challenge_is_required(self):
        decision = evaluate_bundle(
            self.high_bundle,
            trusted_root_public_key=public_key_hex(self.fixture["root"]),
            expected_action=self.fixture["high_action"],
            receiver_challenge="different-receiver-challenge",
            now=T0 + timedelta(seconds=30),
            policy=self.high_policy,
        )
        self.assertEqual(decision["reason_codes"], ["HOLDER_CHALLENGE_MISMATCH"])

    def test_unexpected_disclosure_fails_closed(self):
        overdisclosed = build_presentation_bundle(
            self.fixture["high1"],
            disclose_fields=(
                "action",
                "amount_cents",
                "recipient",
                "private_purpose",
            ),
            subject_key=self.fixture["subject"],
            receiver_challenge=HIGH_CHALLENGE,
            standing_witness=self.fixture["active_epoch1"],
        )
        decision = evaluate_bundle(
            overdisclosed,
            trusted_root_public_key=public_key_hex(self.fixture["root"]),
            expected_action=self.fixture["high_action"],
            receiver_challenge=HIGH_CHALLENGE,
            now=T0 + timedelta(seconds=30),
            policy=self.high_policy,
        )
        self.assertEqual(decision["reason_codes"], ["UNEXPECTED_DISCLOSURE"])

    def test_low_risk_lifetime_above_receiver_ceiling_blocks(self):
        root = _key("root-long")
        epoch = _key("epoch-long")
        subject = _key("subject-long")
        cert = issue_epoch_certificate(
            root,
            epoch,
            principal_id="principal-long",
            epoch_id="epoch-long",
            sequence=1,
            issued_at=T0,
            expires_at=T0 + timedelta(days=1),
        )
        issued = issue_mandate(
            epoch,
            cert,
            mandate_id="mandate-long",
            subject_key=subject,
            risk_tier="LOW",
            fields={"action": "archive"},
            issued_at=T0,
            expires_at=T0 + timedelta(seconds=601),
            epoch_salt_registry=set(),
        )
        bundle = build_presentation_bundle(
            issued,
            disclose_fields=("action",),
            subject_key=subject,
            receiver_challenge=LOW_CHALLENGE,
            standing_witness=None,
        )
        decision = evaluate_bundle(
            bundle,
            trusted_root_public_key=public_key_hex(root),
            expected_action={"action": "archive"},
            receiver_challenge=LOW_CHALLENGE,
            now=T0 + timedelta(seconds=1),
            policy=AdmissionPolicy(60, 600, ("action",)),
        )
        self.assertEqual(decision["reason_codes"], ["OFFLINE_TTL_EXCEEDS_POLICY"])

    def test_duplicate_salt_source_is_rejected(self):
        root = _key("root-salt")
        epoch = _key("epoch-salt")
        subject = _key("subject-salt")
        cert = issue_epoch_certificate(
            root,
            epoch,
            principal_id="principal-salt",
            epoch_id="epoch-salt",
            sequence=1,
            issued_at=T0,
            expires_at=T0 + timedelta(days=1),
        )
        with self.assertRaisesRegex(WalletProtocolError, "salt_reuse_detected"):
            issue_mandate(
                epoch,
                cert,
                mandate_id="mandate-salt",
                subject_key=subject,
                risk_tier="LOW",
                fields={"action": "archive", "record_id": "R1"},
                issued_at=T0,
                expires_at=T0 + timedelta(minutes=1),
                epoch_salt_registry=set(),
                salt_source=lambda size: b"x" * size,
            )

    def test_salt_reuse_across_same_epoch_is_rejected(self):
        root = _key("root-epoch-salt")
        epoch = _key("epoch-epoch-salt")
        subject = _key("subject-epoch-salt")
        registry: set[str] = set()
        cert = issue_epoch_certificate(
            root,
            epoch,
            principal_id="principal-epoch-salt",
            epoch_id="epoch-epoch-salt",
            sequence=1,
            issued_at=T0,
            expires_at=T0 + timedelta(days=1),
        )
        issue_mandate(
            epoch,
            cert,
            mandate_id="mandate-epoch-salt-1",
            subject_key=subject,
            risk_tier="LOW",
            fields={"action": "archive"},
            issued_at=T0,
            expires_at=T0 + timedelta(minutes=1),
            epoch_salt_registry=registry,
            salt_source=lambda size: b"z" * size,
        )
        with self.assertRaisesRegex(WalletProtocolError, "salt_reuse_detected"):
            issue_mandate(
                epoch,
                cert,
                mandate_id="mandate-epoch-salt-2",
                subject_key=subject,
                risk_tier="LOW",
                fields={"action": "archive"},
                issued_at=T0,
                expires_at=T0 + timedelta(minutes=1),
                epoch_salt_registry=registry,
                salt_source=lambda size: b"z" * size,
            )

    def test_default_entropy_produces_unique_field_salts(self):
        root = _key("root-random")
        epoch = _key("epoch-random")
        subject = _key("subject-random")
        cert = issue_epoch_certificate(
            root,
            epoch,
            principal_id="principal-random",
            epoch_id="epoch-random",
            sequence=1,
            issued_at=T0,
            expires_at=T0 + timedelta(days=1),
        )
        issued = issue_mandate(
            epoch,
            cert,
            mandate_id="mandate-random",
            subject_key=subject,
            risk_tier="LOW",
            fields={"action": "archive", "record_id": "R1", "days": 30},
            issued_at=T0,
            expires_at=T0 + timedelta(minutes=1),
            epoch_salt_registry=set(),
        )
        salts = list(issued.salts.values())
        self.assertEqual(len(salts), len(set(salts)))
        self.assertTrue(all(len(bytes.fromhex(value)) == 32 for value in salts))

    def test_mandate_cannot_outlive_epoch(self):
        root = _key("root-life")
        epoch = _key("epoch-life")
        cert = issue_epoch_certificate(
            root,
            epoch,
            principal_id="principal-life",
            epoch_id="epoch-life",
            sequence=1,
            issued_at=T0,
            expires_at=T0 + timedelta(minutes=1),
        )
        with self.assertRaisesRegex(WalletProtocolError, "mandate_outside_epoch_lifetime"):
            issue_mandate(
                epoch,
                cert,
                mandate_id="mandate-life",
                subject_key=_key("subject-life"),
                risk_tier="LOW",
                fields={"action": "archive"},
                issued_at=T0,
                expires_at=T0 + timedelta(minutes=2),
                epoch_salt_registry=set(),
            )

    def test_naive_datetime_is_rejected_at_gate(self):
        decision = evaluate_bundle(
            self.high_bundle,
            trusted_root_public_key=public_key_hex(self.fixture["root"]),
            expected_action=self.fixture["high_action"],
            receiver_challenge=HIGH_CHALLENGE,
            now=datetime(2026, 8, 28, 12, 0, 30),
            policy=self.high_policy,
        )
        self.assertEqual(decision["reason_codes"], ["GATE_TIME_TIMEZONE_REQUIRED"])


class WalletReleaseTests(unittest.TestCase):
    def test_release_verifier_passes(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "verify_release.py")],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("WALLET001_RELEASE_OK", completed.stdout)


if __name__ == "__main__":
    unittest.main()
