from __future__ import annotations

import copy
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.adapters import FAIL, PARTIAL, PASS, UNAVAILABLE, TrustStore
from olp_gate.adapters_assay import assess_assay_bundle, find_assay_binary
from olp_gate.crypto import public_key_hex
from olp_gate.gateway import evaluate_request, verify_decision_receipt
from olp_gate.policy import PolicySpec
from olp_gate.session import SessionLedger


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "benchmarks" / "assay" / "fixtures"
ASSAY_BIN = find_assay_binary()
SOURCE_HASH = "06902924787b20aad33b5ec521fb82f3aeec361da290a3b2a862ea149946bc8b"


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(path)
    return value


class AssayAdapterFailClosedTests(unittest.TestCase):
    def test_path_escape_is_rejected_before_verifier_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inside = root / "inside"
            inside.mkdir()
            outside = root / "outside.tar.gz"
            outside.write_bytes(b"not a bundle")
            assessment = assess_assay_bundle(
                {
                    "format": "assay_evidence_bundle_v1",
                    "path": "../outside.tar.gz",
                    "sha256": "00" * 32,
                    "trust_basis_requirements": [],
                },
                base_dir=inside,
                assay_binary=ASSAY_BIN,
            )
        self.assertEqual(assessment.integrity.status, FAIL)
        self.assertIn("assay_bundle_path_escape", assessment.integrity.reason_codes)

    def test_request_cannot_select_a_verifier_executable(self) -> None:
        reference = {
            "format": "assay_evidence_bundle_v1",
            "path": "assay/openfeature-decision-receipts.tar.gz",
            "sha256": SOURCE_HASH,
            "trust_basis_requirements": [],
            "assay_binary": "/tmp/attacker-controlled",
        }
        assessment = assess_assay_bundle(
            reference,
            base_dir=FIXTURES,
            assay_binary="/definitely/not/an/executable",
        )
        self.assertEqual(assessment.integrity.status, UNAVAILABLE)
        self.assertIn("assay_verifier_unavailable", assessment.integrity.reason_codes)


@unittest.skipUnless(
    ASSAY_BIN is not None,
    "optional Assay integration missing: set OLP_ASSAY_BIN to the pinned assay 3.32.0 binary",
)
class AssayAdapterIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = PolicySpec.from_mapping(load_json(FIXTURES / "olp-policy.json"))
        self.trust = TrustStore.from_mapping(load_json(FIXTURES / "olp-trust.json"))
        self.gate_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("84" * 32))
        self.temporary = tempfile.TemporaryDirectory()
        self.temp = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def request(self, case_id: str) -> dict:
        return load_json(FIXTURES / f"{case_id}.request.json")

    def evaluate(self, case_id: str, *, mutate: bool = False) -> dict:
        request = copy.deepcopy(self.request(case_id))
        base_dir = FIXTURES
        if mutate:
            base_dir = self.temp / case_id
            (base_dir / "assay").mkdir(parents=True)
            (base_dir / "evidence").mkdir(parents=True)
            source = bytearray(
                (FIXTURES / "assay" / "openfeature-decision-receipts.tar.gz").read_bytes()
            )
            source[len(source) // 2] ^= 0x01
            (base_dir / "assay" / "openfeature-decision-receipts.tar.gz").write_bytes(source)
            shutil.copyfile(
                FIXTURES / "evidence" / "receiver-release-approval.json",
                base_dir / "evidence" / "receiver-release-approval.json",
            )

        ledger = SessionLedger(self.temp / f"{case_id}.ledger.json")
        binding = request["binding"]
        challenge = ledger.issue_challenge(
            run_id=binding["run_id"],
            session_id=binding["session_id"],
            expected_source_hash=binding["expected_source_hash"],
            ttl_seconds=300,
        )
        binding["challenge_nonce"] = challenge["challenge_nonce"]
        return evaluate_request(
            request,
            policy=self.policy,
            trust_store=self.trust,
            signing_key=self.gate_key,
            issuer_id="assay-test-receiver",
            decision_path=self.temp / f"{case_id}.decisions.jsonl",
            session_ledger=ledger,
            base_dir=base_dir,
            assay_binary=ASSAY_BIN,
        )

    def test_official_bundle_and_trust_basis_are_delegated_to_assay(self) -> None:
        reference = self.request("case-01-clean-with-receiver-evidence")["source_bundle"]
        assessment = assess_assay_bundle(
            reference,
            base_dir=FIXTURES,
            assay_binary=ASSAY_BIN,
        )
        self.assertEqual(assessment.primary_hash, SOURCE_HASH)
        self.assertEqual(assessment.integrity.status, PASS)
        self.assertEqual(assessment.profile.status, PASS)
        self.assertEqual(assessment.source_signal.status, PASS)
        self.assertEqual(assessment.coverage.status, PARTIAL)
        self.assertEqual(assessment.provenance.status, UNAVAILABLE)
        self.assertEqual(assessment.source_binding["run_id"], "olp_assay_h2h")
        self.assertEqual(
            assessment.source_binding["source_artifact_digests"],
            ["sha256:72b1eaa773be72f6ddfa56ae4547605c1f5e8be9e5db7841bd7947a4215979b0"],
        )

    def test_receiver_evidence_changes_only_olp_next_use_decision(self) -> None:
        clean = self.evaluate("case-01-clean-with-receiver-evidence")
        missing = self.evaluate("case-02-receiver-evidence-missing")
        self.assertEqual((clean["verdict"], clean["decision"]), ("VERIFIED", "COMMIT"))
        self.assertEqual(
            (missing["verdict"], missing["decision"]),
            ("UNDECIDABLE", "QUARANTINE"),
        )
        for decision in (clean, missing):
            self.assertEqual(decision["assessments"]["integrity"]["status"], PASS)
            self.assertEqual(decision["assessments"]["source_signal"]["status"], PASS)
            verified = verify_decision_receipt(decision, [public_key_hex(self.gate_key)])
            self.assertTrue(verified["valid"], verified["errors"])

    def test_native_trust_basis_failure_is_never_laundered(self) -> None:
        decision = self.evaluate("case-04-assay-registered-claim-missing")
        self.assertEqual((decision["verdict"], decision["decision"]), ("REJECTED", "DENY"))
        self.assertEqual(decision["assessments"]["source_signal"]["status"], FAIL)
        self.assertIn(
            "source_signal:assay_trust_basis_requirement_failed",
            decision["reason_codes"],
        )

    def test_tampered_archive_is_rejected_by_the_official_verifier(self) -> None:
        decision = self.evaluate("case-03-tampered-bundle", mutate=True)
        self.assertEqual((decision["verdict"], decision["decision"]), ("REJECTED", "DENY"))
        self.assertEqual(decision["assessments"]["integrity"]["status"], FAIL)
        self.assertIn("integrity:assay_bundle_invalid", decision["reason_codes"])

    def test_valid_assay_bundle_with_wrong_receiver_pin_is_denied(self) -> None:
        decision = self.evaluate("case-05-source-hash-substitution")
        self.assertEqual((decision["verdict"], decision["decision"]), ("REJECTED", "DENY"))
        self.assertIn("integrity:assay_bundle_sha256_mismatch", decision["reason_codes"])


if __name__ == "__main__":
    unittest.main()
