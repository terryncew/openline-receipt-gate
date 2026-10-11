"""Independent-process durability and fail-closed tests for the bounded ASA pilot.

Workers open independent SQLite connections. Crash injection terminates an OS
process during receipt signing, or immediately after the transaction context
has returned (therefore after COMMIT), rather than simulating an exception.
All cards, credentials and requests are synthetic; no provider API is called.
"""
from __future__ import annotations

from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import select
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openline_receiver.lithic_adapter import (
    ACTION, ReceiverStateError, SecureLithicAdapter, create_payment_intent,
    payment_details,
)
from openline_receiver.openline_wallet import Wallet
from openline_receiver.openline_wallet.crypto import public_key_hex, verify_record
from openline_receiver.wallet_bridge import worker_present


def official_shaped_request():
    """Synthetic values in current Lithic CardAuthorizationApprovalRequest shape."""
    return {
        "event_type": "card_authorization.approval_request",
        "token": str(uuid.uuid4()), "status": "AUTHORIZATION",
        "created": datetime.now(timezone.utc).isoformat(),
        "transaction_initiator": "CARDHOLDER", "amount": 100,
        "authorization_amount": 100, "merchant_amount": 100,
        "settled_amount": 0, "acquirer_fee": 0, "cash_amount": 0,
        "cardholder_currency": "USD", "merchant_currency": "USD",
        "amounts": {
            "cardholder": {"amount": 100, "currency": "USD", "conversion_rate": "1.000000"},
            "merchant": {"amount": 100, "currency": "USD"},
            "hold": None, "settlement": None,
        },
        "card": {
            "token": "00000000-0000-4000-8000-000000000001", "last_four": "0000",
            "memo": "OFFLINE SYNTHETIC PILOT CARD", "state": "OPEN", "type": "VIRTUAL",
            "spend_limit": 100, "spend_limit_duration": "TRANSACTION",
        },
        "merchant": {
            "acceptor_id": "OPENLINE-SYNTHETIC-001", "acquiring_institution_id": "000001",
            "descriptor": "OPENLINE OFFLINE PILOT", "mcc": "5999", "city": "NEW YORK",
            "country": "USA", "state": "NY", "phone_number": None,
            "postal_code": None, "street_address": None,
        },
        "avs": {"address": "", "zipcode": "", "address_on_file_match": "NOT_PRESENT"},
        "name_validation": None, "service_location": None, "network": "VISA",
        "pos": {"entry_mode": {"card": "NOT_PRESENT", "cardholder": "ELECTRONIC_ORDER",
                               "pan": "ECOMMERCE", "pin_entered": False}},
    }


def _worker(db_path, request_path, mode):
    """Subprocess entry point. The request timer starts after process readiness."""
    import os

    # The pre-pinned key is separate from the database being reopened.
    pinned_key = Path(request_path).with_suffix(".public-key").read_text()
    adapter = SecureLithicAdapter(db_path, sandbox=False, initialize=False,
                                 expected_receiver_public_key=pinned_key)
    request = json.loads(Path(request_path).read_text())
    if mode == "crash-sign":
        def crash_sign(_body):
            os._exit(73)
        adapter._sign_receipt = crash_sign
    elif mode == "crash-after-commit":
        transaction = adapter._transaction

        @contextmanager
        def crash_after_commit():
            with transaction():
                yield
            # The original context manager completed its successful COMMIT.
            os._exit(74)
        adapter._transaction = crash_after_commit
    print("READY", flush=True)
    if sys.stdin.readline().strip() != "go":
        raise RuntimeError("Parent did not release request")
    started = time.monotonic()
    result = adapter.handle_asa(request)
    elapsed = time.monotonic() - started
    print(json.dumps({"response": result, "elapsed_seconds": elapsed}), flush=True)
    adapter.close()


class AtomicityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="openline-lithic-atomicity-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.db_path = self.directory / "receiver.sqlite3"
        self.request = official_shaped_request()
        self.adapter = SecureLithicAdapter(self.db_path, sandbox=False, initialize=True)
        self.addCleanup(self._close_adapter)
        self.pinned_key = self.adapter.get_receiver_public_key()
        self.owner = Wallet.create(self.directory / "owner")
        self.worker_key = Ed25519PrivateKey.generate()
        grant = self.owner.grant(
            subject_id="worker-1", subject_public_key=public_key_hex(self.worker_key),
            scopes=[ACTION], expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        self.mandate_id = grant["data"]["mandate_id"]
        self.bundle = self.owner.export_bundle()
        self.adapter.enroll_owner(self.owner.principal_id, public_key_hex(self.owner.root_key))
        self.adapter.admit_bundle(self.owner.principal_id, self.bundle)
        self.adapter.bind_card(self.request["card"]["token"], self.owner.principal_id,
                               self.mandate_id, "worker-1")
        self._authorize_pending()

    def _close_adapter(self):
        if self.adapter is not None:
            self.adapter.close()
            self.adapter = None

    def _authorize_pending(self):
        challenge = self.adapter.issue_challenge(self.request["card"]["token"])
        presentation = worker_present(
            bundle=self.bundle, mandate_id=self.mandate_id, subject_id="worker-1",
            subject_key=self.worker_key, action=ACTION, challenge=challenge,
        )
        details = payment_details(self.request)
        intent = create_payment_intent(
            gate_id=self.adapter.gate_id, details=details, presentation=presentation,
            subject_key=self.worker_key,
        )
        self.assertTrue(self.adapter.pre_authorize(
            self.request["card"]["token"], details, presentation, intent,
        )["authorized"])

    def _snapshot(self):
        with sqlite3.connect(self.db_path, timeout=1) as db:
            pending = db.execute("SELECT count(*) FROM pending").fetchone()[0]
            decisions = db.execute("SELECT token,result,receipt FROM decisions ORDER BY token").fetchall()
            key = db.execute("SELECT public_key FROM metadata").fetchone()[0]
        return pending, decisions, key

    def _launch(self, requests, mode="normal"):
        processes = []
        try:
            for index, request in enumerate(requests):
                request_path = self.directory / f"request-{index}.json"
                request_path.write_text(json.dumps(request))
                request_path.with_suffix(".public-key").write_text(self.pinned_key)
                process = subprocess.Popen(
                    [sys.executable, str(Path(__file__).resolve()), "--worker", str(self.db_path),
                     str(request_path), mode], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True,
                )
                processes.append(process)
                ready, _, _ = select.select([process.stdout], [], [], 10)
                self.assertTrue(ready, "ASA worker did not become ready")
                line = process.stdout.readline().strip()
                if line != "READY":
                    _, error = process.communicate(timeout=5)
                    self.fail(f"ASA worker initialization failed: {line!r} {error}")
            # Every connection is initialized before any request is released.
            for process in processes:
                process.stdin.write("go\n")
                process.stdin.flush()
            results = []
            for process in processes:
                output, error = process.communicate(timeout=8)
                if mode == "normal":
                    self.assertEqual(process.returncode, 0, error)
                    results.append(json.loads(output))
                else:
                    self.assertEqual(process.returncode, 73 if mode == "crash-sign" else 74, error)
            return results
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=3)

    def test_independent_processes_unique_tokens_consume_pending_exactly_once(self):
        requests = [deepcopy(self.request) for _ in range(8)]
        for request in requests:
            request["token"] = str(uuid.uuid4())
        results = self._launch(requests)
        self.assertEqual(sum(item["response"]["result"] == "APPROVED" for item in results), 1)
        self.assertTrue(all(item["elapsed_seconds"] < 6 for item in results))
        pending, decisions, key = self._snapshot()
        self.assertEqual(pending, 0)
        self.assertEqual(len(decisions), 8)
        self.assertEqual(sum(result == "APPROVED" for _, result, _ in decisions), 1)
        self.assertEqual(key, self.pinned_key)
        for _, _, receipt in decisions:
            self.assertTrue(verify_record(json.loads(receipt), expected_public_key=self.pinned_key)[0])

    def test_independent_process_duplicate_retries_commit_one_identical_decision(self):
        results = self._launch([self.request] * 8)
        self.assertEqual([item["response"] for item in results], [{"result": "APPROVED"}] * 8)
        self.assertTrue(all(item["elapsed_seconds"] < 6 for item in results))
        pending, decisions, key = self._snapshot()
        self.assertEqual(pending, 0)
        self.assertEqual(len(decisions), 1)
        self.assertEqual(key, self.pinned_key)
        self._close_adapter()
        self.adapter = SecureLithicAdapter(self.db_path, sandbox=False,
                                           expected_receiver_public_key=self.pinned_key)
        self.assertEqual(self.adapter.handle_asa(self.request), {"result": "APPROVED"})

    def test_signing_exception_rolls_back_pending_and_decision_without_key_change(self):
        original_sign = self.adapter._sign_receipt

        def signing_failure(_body):
            raise RuntimeError("Injected signing failure")
        self.adapter._sign_receipt = signing_failure
        with self.assertRaises(ReceiverStateError):
            self.adapter.handle_asa(self.request)
        pending, decisions, key = self._snapshot()
        self.assertEqual((pending, len(decisions), key), (1, 0, self.pinned_key))
        self.adapter._sign_receipt = original_sign
        self.assertEqual(self.adapter.handle_asa(self.request), {"result": "APPROVED"})

    def test_process_exit_during_signing_rolls_back_consumption_and_recovers_after_restart(self):
        self._launch([self.request], "crash-sign")
        pending, decisions, key = self._snapshot()
        self.assertEqual((pending, len(decisions), key), (1, 0, self.pinned_key))
        self._close_adapter()
        self.adapter = SecureLithicAdapter(self.db_path, sandbox=False,
                                           expected_receiver_public_key=self.pinned_key)
        self.assertEqual(self.adapter.handle_asa(self.request), {"result": "APPROVED"})
        self.assertEqual(self._snapshot()[0], 0)

    def test_process_exit_after_commit_before_response_preserves_retry_and_signed_receipt(self):
        self._launch([self.request], "crash-after-commit")
        pending, decisions, key = self._snapshot()
        self.assertEqual((pending, len(decisions), key), (0, 1, self.pinned_key))
        self.assertEqual(decisions[0][1], "APPROVED")
        self.assertTrue(verify_record(json.loads(decisions[0][2]), expected_public_key=self.pinned_key)[0])
        self._close_adapter()
        self.adapter = SecureLithicAdapter(self.db_path, sandbox=False,
                                           expected_receiver_public_key=self.pinned_key)
        self.assertEqual(self.adapter.handle_asa(self.request), {"result": "APPROVED"})
        self.assertEqual(len(self._snapshot()[1]), 1)

    def test_reused_token_with_changed_contents_declines_without_replacing_receipt(self):
        self.assertEqual(self.adapter.handle_asa(self.request), {"result": "APPROVED"})
        prior = self._snapshot()[1]
        changed = deepcopy(self.request)
        changed["merchant"]["descriptor"] = "ANOTHER PURCHASE"
        self.assertEqual(self.adapter.handle_asa(changed), {"result": "SUSPECTED_FRAUD"})
        self.assertEqual(self._snapshot()[1], prior)

    def test_pending_details_corruption_cannot_change_worker_approved_merchant(self):
        changed = deepcopy(self.request)
        changed["merchant"]["descriptor"] = "ANOTHER UNAPPROVED PURCHASE"
        altered_details = payment_details(changed)
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE pending SET details=?", (json.dumps(altered_details),))
        with self.assertRaises(ReceiverStateError):
            self.adapter.handle_asa(changed)
        pending, decisions, key = self._snapshot()
        self.assertEqual((pending, len(decisions), key), (1, 0, self.pinned_key))

    def test_pending_expiry_corruption_cannot_extend_signed_authorization_lifetime(self):
        extended = datetime.now(timezone.utc) + timedelta(minutes=5)
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE pending SET expires=?", (extended.isoformat(),))
        with self.assertRaises(ReceiverStateError):
            self.adapter.handle_asa(self.request)
        self.assertEqual(self._snapshot()[0:2], (1, []))

    def test_signed_wallet_decision_tampering_cannot_authorize_pending(self):
        with sqlite3.connect(self.db_path) as db:
            proof = json.loads(db.execute("SELECT proof FROM pending").fetchone()[0])
            proof["wallet_decision"]["action"] = "another:action"
            db.execute("UPDATE pending SET proof=?", (json.dumps(proof),))
        with self.assertRaises(ReceiverStateError):
            self.adapter.handle_asa(self.request)
        self.assertEqual(self._snapshot()[0:2], (1, []))

    def test_malformed_pending_proof_fails_without_consuming_authorization(self):
        with sqlite3.connect(self.db_path) as db:
            proof = json.loads(db.execute("SELECT proof FROM pending").fetchone()[0])
            proof["wallet_decision"] = None
            db.execute("UPDATE pending SET proof=?", (json.dumps(proof),))
        with self.assertRaises(ReceiverStateError):
            self.adapter.handle_asa(self.request)
        self.assertEqual(self._snapshot()[0:2], (1, []))

    def test_corrupt_cached_result_cannot_turn_signed_decline_into_approval(self):
        changed = deepcopy(self.request)
        changed["merchant"]["descriptor"] = "UNAPPROVED MERCHANT"
        self.assertNotEqual(self.adapter.handle_asa(changed)["result"], "APPROVED")
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE decisions SET result='APPROVED'")
        with self.assertRaises(ReceiverStateError):
            self.adapter.handle_asa(changed)

    def test_corrupt_cached_fingerprint_cannot_rebind_valid_receipt_to_other_purchase(self):
        import hashlib

        self.assertEqual(self.adapter.handle_asa(self.request), {"result": "APPROVED"})
        changed = deepcopy(self.request)
        changed["merchant"]["descriptor"] = "UNAPPROVED MERCHANT"
        fingerprint = hashlib.sha256(json.dumps(
            changed, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode()).hexdigest()
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE decisions SET fingerprint=?", (fingerprint,))
        with self.assertRaises(ReceiverStateError):
            self.adapter.handle_asa(changed)

    def test_live_missing_or_corrupt_receiver_signing_metadata_fails_closed(self):
        with sqlite3.connect(self.db_path) as db:
            db.execute("DELETE FROM metadata")
        with self.assertRaises(ReceiverStateError):
            self.adapter.handle_asa(self.request)
        with sqlite3.connect(self.db_path) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM pending").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT count(*) FROM decisions").fetchone()[0], 0)
        self._close_adapter()
        with self.assertRaises(ReceiverStateError):
            SecureLithicAdapter(self.db_path, sandbox=False)

    def test_restart_rejects_changed_receiver_private_key(self):
        self._close_adapter()
        with sqlite3.connect(self.db_path) as db:
            db.execute("UPDATE metadata SET private_key=?", (Ed25519PrivateKey.generate().private_bytes_raw().hex(),))
        with self.assertRaises(ReceiverStateError):
            SecureLithicAdapter(self.db_path, sandbox=False)

    def test_writer_connection_preserves_wal_full_and_independent_receiver_pin(self):
        self.assertEqual(self.adapter.db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        self.assertEqual(self.adapter.db.execute("PRAGMA synchronous").fetchone()[0], 2)
        self._close_adapter()
        with self.assertRaises(ReceiverStateError):
            SecureLithicAdapter(self.db_path, sandbox=False,
                                expected_receiver_public_key=public_key_hex(Ed25519PrivateKey.generate()))
        self.adapter = SecureLithicAdapter(self.db_path, sandbox=False,
                                          expected_receiver_public_key=self.pinned_key)
        self.assertEqual(self.adapter.db.execute("PRAGMA synchronous").fetchone()[0], 2)

    def test_database_corruption_is_not_reinitialized(self):
        self._close_adapter()
        self.db_path.write_bytes(b"Corrupt receiver database, not a new state")
        with self.assertRaises(ReceiverStateError):
            SecureLithicAdapter(self.db_path, sandbox=False, initialize=True)
        self.assertEqual(self.db_path.read_bytes(), b"Corrupt receiver database, not a new state")

    def test_missing_state_is_not_implicitly_recreated_and_live_unavailability_fails(self):
        self.db_path.unlink()
        with self.assertRaises(ReceiverStateError):
            self.adapter.handle_asa(self.request)
        self._close_adapter()
        with self.assertRaises(ReceiverStateError):
            SecureLithicAdapter(self.db_path, sandbox=False, initialize=False)
        self.assertFalse(self.db_path.exists())

    def test_sqlite_writer_unavailability_fails_within_six_second_budget(self):
        blocker = sqlite3.connect(self.db_path, timeout=1, isolation_level=None)
        try:
            blocker.execute("BEGIN IMMEDIATE")
            started = time.monotonic()
            with self.assertRaises(ReceiverStateError):
                self.adapter.handle_asa(self.request)
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 6)
            blocker.execute("ROLLBACK")
        finally:
            blocker.close()
        pending, decisions, _ = self._snapshot()
        self.assertEqual((pending, len(decisions)), (1, 0))
        self.assertEqual(self.adapter.handle_asa(self.request), {"result": "APPROVED"})

    def test_concurrent_same_process_writer_unavailability_has_bounded_lock_wait(self):
        blocker = sqlite3.connect(self.db_path, timeout=1, isolation_level=None)
        barrier = threading.Barrier(8)

        def request_while_locked(index):
            request = deepcopy(self.request)
            request["token"] = str(uuid.uuid4())
            barrier.wait(timeout=3)
            started = time.monotonic()
            try:
                self.adapter.handle_asa(request)
            except ReceiverStateError:
                return True, time.monotonic() - started
            # Any successful decision response on unavailable state is wrong,
            # even a decline: it cannot be durably replayed after recovery.
            return False, time.monotonic() - started

        try:
            blocker.execute("BEGIN IMMEDIATE")
            with ThreadPoolExecutor(max_workers=8) as executor:
                results = list(executor.map(request_while_locked, range(8)))
            self.assertTrue(all(failed_closed for failed_closed, _ in results))
            self.assertLess(max(elapsed for _, elapsed in results), 6)
            blocker.execute("ROLLBACK")
        finally:
            blocker.close()
        self.assertEqual(self._snapshot()[0:2], (1, []))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        _worker(*sys.argv[2:])
    else:
        unittest.main(verbosity=2)
