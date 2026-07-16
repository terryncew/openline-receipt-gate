from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PIPELOCK_VERIFY_AVAILABLE = (
    os.environ.get("OLP_TEST_DISABLE_PIPELOCK") != "1"
    and importlib.util.find_spec("pipelock_verify") is not None
)
if PIPELOCK_VERIFY_AVAILABLE:
    import pipelock_verify
else:  # pragma: no cover - exercised by the dependency-absent release gate
    pipelock_verify = None

from olp_gate.adapters import FAIL, PARTIAL, PASS, UNAVAILABLE, TrustStore, assess_source_bundle
from olp_gate.crypto import public_key_hex
from olp_gate.gateway import evaluate_request, verify_decision_receipt
from olp_gate.policy import PolicySpec


ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / "benchmarks" / "pipelock"
FIXTURES = BENCHMARK / "fixtures"
PIPELOCK_KEY = "890726e93f89e773fb3b4298271245a69c1884fd1003846c3358b8b65a2288fa"


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(path)
    return value


@unittest.skipUnless(
    PIPELOCK_VERIFY_AVAILABLE,
    "optional dependency missing: pip install -r requirements-pipelock.txt",
)
class PipelockAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = TrustStore.from_mapping(load_json(FIXTURES / "olp-trust.json"))
        self.policy = PolicySpec.from_mapping(load_json(FIXTURES / "olp-policy.json"))
        self.gate_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("73" * 32))
        self.temp = tempfile.TemporaryDirectory()
        self.decisions = Path(self.temp.name) / "decisions.jsonl"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def fixture(self, name: str) -> dict:
        return load_json(FIXTURES / "upstream" / name)

    def request(self, case_id: str) -> dict:
        return load_json(FIXTURES / "requests" / f"{case_id}.request.json")

    def evaluate(self, case_id: str) -> dict:
        return evaluate_request(
            self.request(case_id),
            policy=self.policy,
            trust_store=self.store,
            signing_key=self.gate_key,
            issuer_id="pipelock-test-gate",
            decision_path=self.decisions,
            session_ledger=None,
            base_dir=FIXTURES / "requests",
        )

    def test_published_pipelock_vector_interoperates(self) -> None:
        receipt = self.fixture("case-01-clean-allow.json")
        assert pipelock_verify is not None
        native = pipelock_verify.verify(receipt, public_key_hex=PIPELOCK_KEY)
        self.assertTrue(native.valid, native.error)
        self.assertEqual(native.verdict, "allow")

        assessment = assess_source_bundle([receipt], self.store)
        self.assertEqual(assessment.source_format, "pipelock_action_receipt_v1")
        self.assertEqual(assessment.integrity.status, PASS)
        self.assertEqual(assessment.profile.status, PASS)
        self.assertEqual(assessment.provenance.status, PASS)
        self.assertEqual(assessment.coverage.status, PARTIAL)
        self.assertEqual(assessment.source_signal.status, PASS)
        self.assertEqual(
            assessment.primary_hash,
            "34f2780dcb510c03f55fc31387c993066fad23e328a2bf5f64b630b8d58a0dfb",
        )

    def test_unpinned_signature_is_not_trusted_provenance(self) -> None:
        receipt = self.fixture("case-01-clean-allow.json")
        assessment = assess_source_bundle([receipt], TrustStore())
        self.assertEqual(assessment.integrity.status, PASS)
        self.assertEqual(assessment.provenance.status, UNAVAILABLE)
        self.assertFalse(assessment.provenance.details["signatures_verified"])
        self.assertTrue(assessment.provenance.details["embedded_key_self_consistency_only"])

    def test_broken_chain_delegates_rejection_to_native_verifier(self) -> None:
        receipts = [
            json.loads(line)
            for line in (FIXTURES / "upstream" / "case-03-broken-chain.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        ]
        assessment = assess_source_bundle(receipts, self.store)
        self.assertEqual(assessment.integrity.status, FAIL)
        self.assertIn("pipelock_chain_invalid", assessment.integrity.reason_codes)
        self.assertEqual(assessment.coverage.status, FAIL)
        self.assertEqual(assessment.profile.status, PASS)
        self.assertEqual(assessment.integrity.details["chain_broken_at_seq"], 3)

    def test_malformed_v1_is_profile_failure_not_bad_format_guess(self) -> None:
        assessment = assess_source_bundle(
            [self.fixture("case-05-malformed-v1.json")], self.store
        )
        self.assertEqual(assessment.integrity.status, FAIL)
        self.assertEqual(assessment.profile.status, FAIL)
        self.assertIn("pipelock_profile_invalid", assessment.profile.reason_codes)
        self.assertEqual(assessment.provenance.status, UNAVAILABLE)

    def test_genuine_v2_is_explicitly_unsupported_in_phase_one(self) -> None:
        receipt = load_json(Path(__file__).parent / "fixtures" / "pipelock-evidence-v2-proxy-decision.json")
        assessment = assess_source_bundle([receipt], self.store)
        self.assertEqual(assessment.source_format, "pipelock_evidence_receipt_v2")
        self.assertEqual(assessment.profile.status, FAIL)
        self.assertIn(
            "pipelock_evidence_receipt_v2_phase1_unsupported",
            assessment.profile.reason_codes,
        )
        self.assertIn("canonicalization_unsupported", assessment.integrity.reason_codes)

    def test_bound_evidence_commits_without_upgrading_native_allow(self) -> None:
        decision = self.evaluate("case-01-clean-allow")
        self.assertEqual((decision["verdict"], decision["decision"]), ("VERIFIED", "COMMIT"))
        self.assertEqual(decision["assessments"]["source_signal"]["status"], PASS)
        self.assertEqual(decision["assessments"]["evidence"]["status"], PASS)
        verified = verify_decision_receipt(decision, [public_key_hex(self.gate_key)])
        self.assertTrue(verified["valid"], verified["errors"])

    def test_valid_allow_without_required_evidence_is_undecidable(self) -> None:
        decision = self.evaluate("case-02-allow-missing-evidence")
        self.assertEqual(
            (decision["verdict"], decision["decision"]),
            ("UNDECIDABLE", "QUARANTINE"),
        )
        self.assertEqual(decision["assessments"]["integrity"]["status"], PASS)
        self.assertEqual(decision["assessments"]["source_signal"]["status"], PASS)
        self.assertEqual(decision["assessments"]["evidence"]["status"], UNAVAILABLE)

    def test_native_block_can_never_be_laundered_into_commit(self) -> None:
        decision = self.evaluate("case-04-native-block")
        self.assertEqual((decision["verdict"], decision["decision"]), ("REJECTED", "DENY"))
        self.assertEqual(decision["assessments"]["integrity"]["status"], PASS)
        self.assertEqual(decision["assessments"]["source_signal"]["status"], FAIL)
        self.assertIn(
            "source_signal:pipelock_source_verdict_block",
            decision["reason_codes"],
        )

    def test_broken_chain_and_malformed_receipt_are_denied(self) -> None:
        for case_id in ("case-03-broken-chain", "case-05-malformed-v1"):
            with self.subTest(case_id=case_id):
                decision = self.evaluate(case_id)
                self.assertEqual(
                    (decision["verdict"], decision["decision"]),
                    ("REJECTED", "DENY"),
                )


if __name__ == "__main__":
    unittest.main()
