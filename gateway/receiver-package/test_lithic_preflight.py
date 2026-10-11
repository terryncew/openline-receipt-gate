"""Real HTTP preflight with authenticated ASA bytes and real Wallet signatures."""
from __future__ import annotations

import base64
import concurrent.futures
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import sqlite3
import unittest
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from openline_receiver.lithic_adapter import SecureLithicAdapter, create_payment_intent, payment_details
from openline_receiver.lithic_server import PilotHTTPServer
from openline_receiver.openline_wallet import Wallet
from openline_receiver.openline_wallet.crypto import public_key_hex
from openline_receiver.wallet_bridge import worker_present

FIXTURE = Path(__file__).parent / "fixtures" / "official-asa-request.json"
TEST_ASA_KEY = b"synthetic-offline-ASA-key-32-bytes"
TEST_ASA_SECRET = "whsec_" + base64.b64encode(TEST_ASA_KEY).decode()


def authenticate(body):
    # Independently generated fixture, not the runtime verifier's output.
    message_id, timestamp = str(uuid.uuid4()), str(int(time.time()))
    signed = message_id.encode() + b"." + timestamp.encode() + b"." + body
    signature = base64.b64encode(hmac.new(TEST_ASA_KEY, signed, hashlib.sha256).digest()).decode()
    return {"webhook-id": message_id, "webhook-timestamp": timestamp,
            "webhook-signature": "v1," + signature, "Content-Type": "application/json"}


def independently_verify(receipt, pinned_public):
    # Never adopt the public key supplied by the receipt.
    body = {k: v for k, v in receipt.items() if k not in {"payload_hash", "signature"}}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    if hashlib.sha256(canonical).hexdigest() != receipt["payload_hash"]:
        raise InvalidSignature("Receipt hash changed")
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(pinned_public)).verify(
        bytes.fromhex(receipt["signature"]["value"]), canonical)


def save_budget(name, samples, concurrency):
    path = os.environ.get("OPENLINE_TEST_MEASUREMENT_DIR")
    if path:
        output = Path(path)
        output.mkdir(parents=True, exist_ok=True)
        (output / (name + ".json")).write_text(json.dumps({"concurrency": concurrency,
            "timing": "client through localhost HTTP; complete response body; seconds",
            "samples": [{"status": status, "result": body, "elapsed_seconds": elapsed}
                        for status, body, elapsed in samples]}, indent=2) + "\n")


class HTTPPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.db_path = self.path / "receiver.sqlite3"
        self.owner = Wallet.create(self.path / "owner")
        self.worker = Ed25519PrivateKey.generate()
        self.subject = "pilot-worker-1"
        self.gate = "lithic-pilot-http"
        self.request = json.loads(FIXTURE.read_text())
        self.request["token"] = str(uuid.uuid4())
        self.card = self.request["card"]["token"]
        self.grant = self.owner.grant(subject_id=self.subject, subject_public_key=public_key_hex(self.worker),
                                      scopes=["lithic:authorize"], expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
        self.mandate = self.grant["data"]["mandate_id"]
        self.bundle = self.owner.export_bundle()
        self.adapter = SecureLithicAdapter(self.db_path, gate_id=self.gate, signing_secrets=TEST_ASA_SECRET, initialize=True)
        self.pinned_public = self.adapter.get_receiver_public_key()  # Trusted local enrollment, before any ASA response.
        self.adapter.enroll_owner(self.owner.principal_id, self.owner.root_public_key)
        self.adapter.admit_bundle(self.owner.principal_id, self.bundle)
        self.adapter.bind_card(self.card, self.owner.principal_id, self.mandate, self.subject)
        self.bearer = "offline-integrator-" + "a" * 40
        self.adapter.enroll_integrator("pilot-integrator", self.bearer, self.owner.principal_id)
        self._start_server()
        self.addCleanup(self._stop_all)

    def _start_server(self):
        self.server = PilotHTTPServer(("127.0.0.1", 0), self.adapter)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port

    def _stop_all(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.adapter.close()

    def restart(self):
        self._stop_all()
        self.adapter = SecureLithicAdapter(self.db_path, gate_id=self.gate, signing_secrets=TEST_ASA_SECRET,
                                          expected_receiver_public_key=self.pinned_public)
        self._start_server()

    def authorize(self, request=None, worker=None, subject=None, mandate=None, bundle=None):
        request, worker, subject, mandate, bundle = (request or self.request, worker or self.worker,
                                                    subject or self.subject, mandate or self.mandate, bundle or self.bundle)
        challenge = self.adapter.issue_challenge(self.card)
        presentation = worker_present(bundle=bundle, mandate_id=mandate, subject_id=subject,
                                      subject_key=worker, action="lithic:authorize", challenge=challenge)
        details = payment_details(request)
        intent = create_payment_intent(gate_id=self.gate, details=details, presentation=presentation, subject_key=worker)
        result = self.adapter.pre_authorize(self.card, details, presentation, intent)
        self.assertTrue(result["authorized"], result)
        return result

    def http(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5.9)
        started = time.perf_counter()
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            content = response.read()
            return response.status, json.loads(content) if content else None, time.perf_counter() - started
        finally:
            connection.close()

    def asa(self, request=None, headers=None):
        raw = json.dumps(request or self.request, separators=(",", ":")).encode()
        return self.http("POST", "/asa", raw, authenticate(raw) if headers is None else headers)

    def receipt(self, token=None, bearer=None):
        return self.http("GET", "/receipts/" + (token or self.request["token"]),
                         headers={"Authorization": "Bearer " + (bearer or self.bearer)})

    def test_owner_approval_revocation_successor_http_sequence_and_restart(self):
        self.authorize()
        first_sample = self.asa()
        status, approved, elapsed = first_sample
        self.assertEqual((status, approved), (200, {"result": "APPROVED"}))
        self.assertLess(elapsed, 6)
        status, receipt, _ = self.receipt()
        self.assertEqual(status, 200)
        independently_verify(receipt, self.pinned_public)
        self.restart()
        self.assertEqual(self.asa()[:2], (200, {"result": "APPROVED"}))
        self.assertEqual(self.receipt()[1], receipt)
        # There is unconsumed valid authority when the owner revokes.
        self.authorize()
        self.owner.revoke(self.mandate, reason="offline pilot owner revocation")
        revoked = self.owner.export_bundle()
        self.adapter.admit_bundle(self.owner.principal_id, revoked)
        self.restart()
        new_request = copy.deepcopy(self.request)
        new_request["token"] = str(uuid.uuid4())
        revoked_sample = self.asa(new_request)
        self.assertEqual(revoked_sample[:2], (200, {"result": "CARD_PAUSED"}))
        revoked_receipt = self.receipt(new_request["token"])[1]
        independently_verify(revoked_receipt, self.pinned_public)
        # The same virtual card may be rebound only to valid successor authority.
        successor = Ed25519PrivateKey.generate()
        grant = self.owner.grant(subject_id="pilot-worker-2", subject_public_key=public_key_hex(successor),
                                scopes=["lithic:authorize"], expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
        bundle = self.owner.export_bundle()
        mandate = grant["data"]["mandate_id"]
        self.adapter.admit_bundle(self.owner.principal_id, bundle)
        self.adapter.bind_card(self.card, self.owner.principal_id, mandate, "pilot-worker-2")
        next_request = copy.deepcopy(self.request)
        next_request["token"] = str(uuid.uuid4())
        self.authorize(next_request, successor, "pilot-worker-2", mandate, bundle)
        self.restart()
        successor_sample = self.asa(next_request)
        self.assertEqual(successor_sample[:2], (200, {"result": "APPROVED"}))
        successor_receipt = self.receipt(next_request["token"])[1]
        independently_verify(successor_receipt, self.pinned_public)
        samples = [first_sample, revoked_sample, successor_sample]
        self.assertTrue(all(elapsed < 6 for _, _, elapsed in samples))
        save_budget("asa-sequence-budget", samples, 1)
        output = os.environ.get("OPENLINE_TEST_MEASUREMENT_DIR")
        if output:
            # Only public, synthetic evidence. No Wallet private keys, ASA
            # secret, bearer credential or receiver database is exported.
            public = {"receiver_public_key_pinned_before_asa": self.pinned_public,
                      "owner_root_public_key_pinned_before_admission": self.owner.root_public_key,
                      "principal_id": self.owner.principal_id,
                      "bundles": [self.bundle, revoked, bundle],
                      "receipts": [receipt, revoked_receipt, successor_receipt],
                      "stage_order": ["owner-approved", "owner-revoked", "successor-authorized"]}
            (Path(output) / "asa-sequence-public-evidence.json").write_text(json.dumps(public, indent=2) + "\n")

    def test_merchant_currency_and_operation_mismatch_do_not_consume_intent(self):
        self.authorize()
        mutations = [lambda r: r["merchant"].update(acceptor_id="OTHER-MERCHANT"),
                     lambda r: r["merchant"].update(descriptor="OTHER PURCHASE"),
                     lambda r: r["amounts"]["merchant"].update(currency="EUR"),
                     lambda r: r.update(status="FINANCIAL_AUTHORIZATION"),
                     lambda r: r.update(transaction_initiator="MERCHANT"),
                     lambda r: r.update(cash_amount=100),
                     lambda r: r.update(acquirer_fee=1),
                     lambda r: r.update(amount=500),
                     lambda r: r.update(authorization_amount=500),
                     lambda r: r.update(cardholder_currency="EUR"),
                     lambda r: r.update(network="MASTERCARD")]
        for mutation in mutations:
            request = copy.deepcopy(self.request)
            request["token"] = str(uuid.uuid4())
            mutation(request)
            with self.subTest(request=request):
                status, decision, _ = self.asa(request)
                self.assertEqual(status, 200)
                self.assertNotEqual(decision, {"result": "APPROVED"})
                self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM pending").fetchone()[0], 1)
        self.assertEqual(self.asa()[:2], (200, {"result": "APPROVED"}))

    def test_card_binding_and_missing_authentication_never_approve(self):
        self.assertEqual(self.asa()[:2], (200, {"result": "CARD_PAUSED"}))
        self.assertEqual(self.asa(headers={})[0], 401)
        self.authorize()
        next_request = copy.deepcopy(self.request)
        next_request["token"] = str(uuid.uuid4())
        self.assertEqual(self.asa(next_request, headers={})[0], 401)
        self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM pending").fetchone()[0], 1)
        self.assertEqual(self.asa(next_request)[:2], (200, {"result": "APPROVED"}))
        self.assertEqual(self.asa(next_request, headers={})[0], 401)

    def test_authenticated_receipt_retrieval_is_read_only_and_independently_pinned(self):
        self.authorize()
        self.assertEqual(self.asa()[1], {"result": "APPROVED"})
        changes = self.adapter.db.total_changes
        self.assertEqual(self.http("GET", "/receipts/" + self.request["token"])[0], 401)
        self.assertEqual(self.receipt(bearer="unrelated-integrator-" + "b" * 40)[0], 401)
        status, receipt, _ = self.receipt()
        self.assertEqual(status, 200)
        independently_verify(receipt, self.pinned_public)
        self.assertEqual(self.adapter.db.total_changes, changes)
        self.assertEqual(self.http("DELETE", "/receipts/" + self.request["token"])[0], 405)
        forged_key = Ed25519PrivateKey.generate()
        with self.assertRaises(InvalidSignature):
            independently_verify(receipt, public_key_hex(forged_key))
        changed = copy.deepcopy(receipt)
        changed["result"] = "CARD_PAUSED"
        with self.assertRaises(InvalidSignature):
            independently_verify(changed, self.pinned_public)

    def test_reused_token_changed_contents_is_refused_after_restart(self):
        self.authorize()
        self.assertEqual(self.asa()[1], {"result": "APPROVED"})
        original_receipt = self.receipt()[1]
        self.restart()
        modified = copy.deepcopy(self.request)
        modified["merchant"]["descriptor"] = "CHANGED"
        self.assertEqual(self.asa(modified)[:2], (200, {"result": "SUSPECTED_FRAUD"}))
        self.assertEqual(self.receipt()[1], original_receipt)

    def test_identical_purchase_ambiguity_is_explicit_and_one_use(self):
        self.authorize()
        # Lithic has not supplied a token at preauthorization. An otherwise
        # identical purchase is indistinguishable and consumes the allowance.
        identical = copy.deepcopy(self.request)
        identical["token"] = str(uuid.uuid4())
        self.assertEqual(self.asa(identical)[:2], (200, {"result": "APPROVED"}))
        self.assertEqual(self.asa()[:2], (200, {"result": "CARD_PAUSED"}))
        self.assertIn("next matching ASA", self.receipt(identical["token"])[1]["authorization_semantics"])

    def test_concurrent_http_duplicate_requests_meet_local_six_second_budget(self):
        self.authorize()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            samples = list(pool.map(lambda _: self.asa(), range(80)))
        self.assertTrue(all(status == 200 and body == {"result": "APPROVED"}
                            for status, body, _ in samples))
        self.assertLess(max(seconds for _, _, seconds in samples), 6)
        self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM decisions").fetchone()[0], 1)
        save_budget("http-duplicate-budget", samples, 8)

    def test_processing_failure_is_503_and_retry_acknowledges_only_committed_decision(self):
        self.authorize()
        actual_sign = self.adapter._sign_receipt
        def unavailable_signer(_):
            raise RuntimeError("Injected signer unavailable")
        self.adapter._sign_receipt = unavailable_signer
        self.assertEqual(self.asa()[:2], (503, None))
        self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM decisions").fetchone()[0], 0)
        self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM pending").fetchone()[0], 1)
        self.adapter._sign_receipt = actual_sign
        self.assertEqual(self.asa()[:2], (200, {"result": "APPROVED"}))
        self.assertEqual(self.asa()[:2], (200, {"result": "APPROVED"}))
        independently_verify(self.receipt()[1], self.pinned_public)

    def test_concurrent_http_unavailable_writer_fails_closed_within_budget(self):
        self.authorize()
        blocker = sqlite3.connect(self.db_path, isolation_level=None)
        try:
            blocker.execute("BEGIN IMMEDIATE")
            requests = [copy.deepcopy(self.request) for _ in range(8)]
            for request in requests:
                request["token"] = str(uuid.uuid4())
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                samples = list(pool.map(self.asa, requests))
            self.assertTrue(all(status == 503 and body is None for status, body, _ in samples))
            self.assertLess(max(elapsed for _, _, elapsed in samples), 6)
            self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM decisions").fetchone()[0], 0)
            self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM pending").fetchone()[0], 1)
            save_budget("http-unavailable-writer-budget", samples, 8)
            blocker.execute("ROLLBACK")
        finally:
            blocker.close()
        self.assertEqual(self.asa(requests[0])[:2], (200, {"result": "APPROVED"}))

    def test_sandbox_secret_and_loopback_are_mandatory(self):
        with self.assertRaises(ValueError):
            SecureLithicAdapter(self.path / "unauth.sqlite", initialize=True)
        with self.assertRaises(ValueError):
            PilotHTTPServer(("0.0.0.0", 0), self.adapter)


if __name__ == "__main__":
    unittest.main(verbosity=2)
