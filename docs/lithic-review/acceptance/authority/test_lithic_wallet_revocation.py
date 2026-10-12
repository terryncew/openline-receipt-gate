#!/usr/bin/env python3
"""Independent owner-signed Wallet admission tests for the offline ASA pilot.

These tests create actual owner and worker Ed25519 keys, signed Wallet events,
root-signed bundles, challenge-bound presentations, and worker-signed intents.
No provider, card enrollment, network request, or synthetic authority stub is
used. sandbox=False isolates Wallet/state tests; sandbox HMAC is tested by the
separate official-verifier integration suite.
"""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from openline_receiver.lithic_adapter import (
    ACTION,
    ReceiverStateError,
    SecureLithicAdapter,
    create_payment_intent,
    payment_details,
)
from openline_receiver.openline_wallet import Wallet, WalletError, verify_bundle
from openline_receiver.openline_wallet.crypto import (
    public_key_hex,
    record_hash,
    sign_record,
    verify_record,
)
from openline_receiver.wallet_bridge import worker_present

FIXTURE = Path(__file__).parent / "fixtures" / "official-asa-request.json"


class WalletRevocationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.db_path = self.path / "receiver.sqlite3"
        self.gate_id = "lithic-wallet-preflight"
        self.owner = Wallet.create(self.path / "owner")
        shutil.copytree(self.path / "owner", self.path / "empty-owner")
        self.worker = Ed25519PrivateKey.generate()
        self.subject = "worker-1"
        grant = self.owner.grant(
            subject_id=self.subject,
            subject_public_key=public_key_hex(self.worker),
            scopes=[ACTION],
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        self.mandate = grant["data"]["mandate_id"]
        self.bundle = self.owner.export_bundle()
        self.principal = self.owner.principal_id
        self.request = json.loads(FIXTURE.read_text())
        self.card = self.request["card"]["token"]
        shutil.copytree(self.path / "owner", self.path / "old-owner")
        self.adapters = []
        self.addCleanup(self._close_all)
        self.adapter = self._open(initialize=True)
        self.adapter.enroll_owner(self.principal, self.owner.root_public_key)
        self.adapter.admit_bundle(self.principal, self.bundle)
        self.adapter.bind_card(self.card, self.principal, self.mandate, self.subject)

    def _close_all(self):
        for adapter in self.adapters:
            try:
                adapter.close()
            except Exception:
                pass

    def _open(self, *, initialize=False):
        adapter = SecureLithicAdapter(
            self.db_path, gate_id=self.gate_id, sandbox=False,
            initialize=initialize,
        )
        self.adapters.append(adapter)
        return adapter

    def _restart(self):
        self.adapter.close()
        self.adapters.remove(self.adapter)
        self.adapter = self._open()
        return self.adapter

    def _request(self, **changes):
        request = copy.deepcopy(self.request)
        request["token"] = str(uuid.uuid4())
        request.update(changes)
        return request

    def _preauthorize(self, *, adapter=None, bundle=None, worker=None,
                      mandate=None, subject=None, request=None,
                      presentation_key=None, expected=True):
        adapter = adapter or self.adapter
        bundle = bundle or self.bundle
        worker = worker or self.worker
        mandate = mandate or self.mandate
        subject = subject or self.subject
        request = request or self._request()
        details = payment_details(request)
        challenge = adapter.issue_challenge(self.card)
        presentation = worker_present(
            bundle=bundle, mandate_id=mandate, subject_id=subject,
            subject_key=presentation_key or worker, action=ACTION,
            challenge=challenge,
        )
        intent = create_payment_intent(
            gate_id=self.gate_id, details=details,
            presentation=presentation, subject_key=worker,
        )
        result = adapter.pre_authorize(self.card, details, presentation, intent)
        self.assertEqual(result["authorized"], expected, result)
        return request, presentation, intent, result

    def _revoke(self, *, adapter=None):
        revocation = self.owner.revoke(self.mandate)
        self.assertTrue(verify_record(revocation, expected_public_key=self.owner.root_public_key)[0])
        self.bundle = self.owner.export_bundle()
        verified, timeline = verify_bundle(self.bundle)
        self.assertEqual(timeline.mandates[self.mandate]["status"], "REVOKED")
        (adapter or self.adapter).admit_bundle(self.principal, verified)
        return self.bundle

    def _assert_declined(self, adapter, request):
        result = adapter.handle_asa(request)
        self.assertIn(result["result"], {
            "CARD_PAUSED", "UNAUTHORIZED_MERCHANT", "SUSPECTED_FRAUD",
        })
        self.assertNotEqual(result["result"], "APPROVED")
        return result

    def _assert_wallet_error(self, code, callback):
        with self.assertRaises(WalletError) as caught:
            callback()
        self.assertEqual(caught.exception.code, code)

    def test_binding_without_worker_authorization_declines(self):
        self._assert_declined(self.adapter, self._request())
        self._restart()
        self._assert_declined(self.adapter, self._request())

    def test_real_wallet_approve_revoke_successor_on_same_card(self):
        approved, _, _, _ = self._preauthorize()
        original = self.adapter.handle_asa(approved)
        self.assertEqual(original, {"result": "APPROVED"})
        # This authorization must be invalidated by signed bundle admission.
        pending_request, _, _, _ = self._preauthorize()
        self._revoke()
        self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM pending").fetchone()[0], 0)
        self._assert_declined(self.adapter, pending_request)
        self.assertEqual(self.adapter.handle_asa(approved), original)
        self._restart()
        self._assert_declined(self.adapter, self._request())
        self.assertEqual(self.adapter.handle_asa(approved), original)
        successor = Ed25519PrivateKey.generate()
        event = self.owner.grant(
            subject_id="worker-2", subject_public_key=public_key_hex(successor),
            scopes=[ACTION], expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        successor_mandate = event["data"]["mandate_id"]
        self.bundle = self.owner.export_bundle()
        self.adapter.admit_bundle(self.principal, self.bundle)
        self.adapter.bind_card(self.card, self.principal, successor_mandate, "worker-2")
        request, _, _, _ = self._preauthorize(worker=successor, mandate=successor_mandate, subject="worker-2")
        self.assertEqual(self.adapter.handle_asa(request), {"result": "APPROVED"})
        self._restart()
        request, _, _, _ = self._preauthorize(worker=successor, mandate=successor_mandate, subject="worker-2")
        self.assertEqual(self.adapter.handle_asa(request), {"result": "APPROVED"})

    def test_signed_revocation_invalidates_pending_after_restart(self):
        request, _, _, _ = self._preauthorize()
        self._restart()
        self._revoke()
        self._restart()
        self._assert_declined(self.adapter, request)
        self._assert_declined(self.adapter, self._request())

    def test_another_adapter_admission_is_seen_without_local_restart(self):
        request, _, _, _ = self._preauthorize()
        peer = self._open()
        self._revoke(adapter=peer)
        self._assert_declined(self.adapter, request)
        self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM pending").fetchone()[0], 0)

    def test_another_adapter_cannot_preauthorize_from_stale_local_authority(self):
        _, presentation, intent, _ = self._preauthorize()
        peer = self._open()
        self._revoke(adapter=peer)
        result = self.adapter.pre_authorize(self.card, intent["details"], presentation, intent)
        self.assertFalse(result["authorized"])
        self.assertEqual(result["reason"], "MANDATE_INACTIVE")

    def test_freshly_resigned_old_head_cannot_resurrect_revoked_authority(self):
        old_owner = Wallet.open(self.path / "old-owner")
        self._revoke()
        old_bundle = old_owner.export_bundle()
        self._assert_wallet_error("BUNDLE_HEAD_STALE", lambda: self.adapter.admit_bundle(self.principal, old_bundle))
        self._restart()
        self._assert_wallet_error("BUNDLE_HEAD_STALE", lambda: self.adapter.admit_bundle(self.principal, old_owner.export_bundle()))
        self._assert_declined(self.adapter, self._request())

    def test_expired_revocation_history_retains_monotonic_head_on_restart(self):
        self._revoke()
        future = datetime.now(timezone.utc) + timedelta(seconds=601)
        with patch("openline_receiver.openline_wallet.wallet.utc_now", return_value=future), \
             patch("openline_receiver.openline_wallet.receiver.utc_now", return_value=future), \
             patch("openline_receiver.lithic_adapter._now", return_value=future):
            self._restart()
            old_owner = Wallet.open(self.path / "old-owner")
            old_bundle = old_owner.export_bundle(now=future)
            self._assert_wallet_error("BUNDLE_HEAD_STALE", lambda: self.adapter.admit_bundle(self.principal, old_bundle))
            self._assert_declined(self.adapter, self._request())
        stored = self.adapter.db.execute("SELECT sequence,body FROM bundles WHERE principal=?", (self.principal,)).fetchone()
        self.assertEqual(stored[0], 2)
        self.assertEqual(json.loads(stored[1])["events"][-1]["event_type"], "MANDATE_REVOKED")

    def test_same_head_refresh_cannot_restore_revoked_mandate(self):
        self._revoke()
        refresh = self.owner.export_bundle()
        result = self.adapter.admit_bundle(self.principal, refresh)
        self.assertEqual(result["head_sequence"], 2)
        self._restart()
        self._assert_declined(self.adapter, self._request())
        self._assert_wallet_error("MANDATE_INACTIVE", lambda: self.adapter.issue_challenge(self.card))

    def test_owner_signed_fork_invalidates_still_unconsumed_pending(self):
        request, _, _, _ = self._preauthorize()
        fork_owner = Wallet.open(self.path / "empty-owner")
        fork_owner.grant(
            subject_id="fork-worker", subject_public_key=public_key_hex(Ed25519PrivateKey.generate()),
            scopes=[ACTION], expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        fork = fork_owner.export_bundle()
        self.assertEqual(fork["head"]["sequence"], self.bundle["head"]["sequence"])
        self._assert_wallet_error("BUNDLE_FORK_QUARANTINED", lambda: self.adapter.admit_bundle(self.principal, fork))
        self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM pending").fetchone()[0], 0)
        self._restart()
        self._assert_declined(self.adapter, request)
        self._assert_wallet_error("PRINCIPAL_FORK_QUARANTINED", lambda: self.adapter.issue_challenge(self.card))

    def test_owner_signed_same_height_fork_is_durably_quarantined(self):
        self._preauthorize()
        self._revoke()
        fork_owner = Wallet.open(self.path / "old-owner")
        successor = Ed25519PrivateKey.generate()
        fork_owner.grant(subject_id="other", subject_public_key=public_key_hex(successor), scopes=[ACTION], expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
        fork = fork_owner.export_bundle()
        self._assert_wallet_error("BUNDLE_FORK_QUARANTINED", lambda: self.adapter.admit_bundle(self.principal, fork))
        self.assertEqual(self.adapter.db.execute("SELECT quarantined FROM bundles").fetchone()[0], 1)
        self._restart()
        self._assert_wallet_error("PRINCIPAL_FORK_QUARANTINED", lambda: self.adapter.admit_bundle(self.principal, self.bundle))
        self._assert_declined(self.adapter, self._request())

    def test_owner_signed_non_descendant_higher_head_is_quarantined(self):
        self._revoke()
        fork_owner = Wallet.open(self.path / "old-owner")
        for subject in ("fork-2", "fork-3"):
            fork_owner.grant(subject_id=subject, subject_public_key=public_key_hex(Ed25519PrivateKey.generate()), scopes=[ACTION], expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
        fork = fork_owner.export_bundle()
        self.assertEqual(fork["head"]["sequence"], 3)
        self._assert_wallet_error("BUNDLE_FORK_QUARANTINED", lambda: self.adapter.admit_bundle(self.principal, fork))
        self._restart()
        self._assert_wallet_error("PRINCIPAL_FORK_QUARANTINED", lambda: self.adapter.issue_challenge(self.card))

    def test_epoch_signed_revocation_rejected_even_inside_root_signed_bundle(self):
        self._preauthorize()
        self.owner.revoke(self.mandate)
        forged = self.owner.export_bundle()
        event = forged["events"][-1]
        forged["events"][-1] = sign_record({k: v for k, v in event.items() if k not in {"payload_hash", "signature"}}, self.owner.epoch_key)
        forged["head"]["event_hash"] = record_hash(forged["events"][-1])
        forged = sign_record({k: v for k, v in forged.items() if k not in {"payload_hash", "signature"}}, self.owner.root_key)
        self._assert_wallet_error("EVENT_SIGNATURE_INVALID", lambda: self.adapter.admit_bundle(self.principal, forged))
        self.assertEqual(self.adapter.db.execute("SELECT sequence FROM bundles").fetchone()[0], 1)
        self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM pending").fetchone()[0], 1)

    def test_signed_narrowing_invalidates_superseded_pending_authority(self):
        request, _, _, _ = self._preauthorize()
        successor = self.owner.narrow(
            self.mandate, scopes=[ACTION],
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
        )
        self.bundle = self.owner.export_bundle()
        self.adapter.admit_bundle(self.principal, self.bundle)
        self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM pending").fetchone()[0], 0)
        self._restart()
        self._assert_declined(self.adapter, request)
        successor_mandate = successor["data"]["mandate_id"]
        self.adapter.bind_card(self.card, self.principal, successor_mandate, self.subject)
        request, _, _, _ = self._preauthorize(mandate=successor_mandate)
        self.assertEqual(self.adapter.handle_asa(request), {"result": "APPROVED"})

    def test_real_receiver_challenge_survives_restart_and_remains_one_use(self):
        request = self._request()
        details = payment_details(request)
        challenge = self.adapter.issue_challenge(self.card)
        presentation = worker_present(
            bundle=self.bundle, mandate_id=self.mandate, subject_id=self.subject,
            subject_key=self.worker, action=ACTION, challenge=challenge,
        )
        intent = create_payment_intent(
            gate_id=self.gate_id, details=details, presentation=presentation,
            subject_key=self.worker,
        )
        self._restart()
        self.assertTrue(self.adapter.pre_authorize(self.card, details, presentation, intent)["authorized"])
        self.assertEqual(self.adapter.handle_asa(request), {"result": "APPROVED"})
        self._restart()
        replay = self.adapter.pre_authorize(self.card, details, presentation, intent)
        self.assertEqual(replay, {"authorized": False, "reason": "CHALLENGE_UNKNOWN_OR_USED"})
        self._assert_declined(self.adapter, self._request())

    def test_asa_commits_first_then_admitted_revocation_blocks_new_decisions(self):
        request, _, _, _ = self._preauthorize()
        peer = self._open()
        self.owner.revoke(self.mandate)
        revoked = self.owner.export_bundle()
        asa_inside = threading.Event()
        admission_attempted = threading.Event()
        admission_finished = threading.Event()
        release_asa = threading.Event()
        original_sign = self.adapter._sign_receipt

        def blocked_sign(body):
            asa_inside.set()
            if not release_asa.wait(3):
                raise RuntimeError("Test did not release ASA transaction")
            return original_sign(body)

        def trace(statement):
            if statement == "BEGIN IMMEDIATE":
                admission_attempted.set()

        def admit():
            try:
                return peer.admit_bundle(self.principal, revoked)
            finally:
                admission_finished.set()

        peer.db.set_trace_callback(trace)
        with patch.object(self.adapter, "_sign_receipt", side_effect=blocked_sign), \
             ThreadPoolExecutor(max_workers=2) as pool:
            asa_future = pool.submit(self.adapter.handle_asa, request)
            try:
                self.assertTrue(asa_inside.wait(3), "ASA did not enter its decision transaction")
                admission_future = pool.submit(admit)
                self.assertTrue(admission_attempted.wait(3), "Revocation did not attempt its write transaction")
                self.assertFalse(admission_finished.is_set(), "Revocation passed an unfinished ASA transaction")
            finally:
                release_asa.set()
            self.assertEqual(asa_future.result(timeout=3), {"result": "APPROVED"})
            self.assertEqual(admission_future.result(timeout=3)["head_sequence"], 2)
        peer.db.set_trace_callback(None)
        self._assert_declined(self.adapter, self._request())
        # A completed authorization is immutable historical evidence.
        self.assertEqual(self.adapter.handle_asa(request), {"result": "APPROVED"})

    def test_admitted_revocation_commits_first_then_waiting_asa_declines(self):
        request, _, _, _ = self._preauthorize()
        peer = self._open()
        self.owner.revoke(self.mandate)
        revoked = self.owner.export_bundle()
        revocation_inside = threading.Event()
        asa_attempted = threading.Event()
        release_revocation = threading.Event()
        callback_timeout = threading.Event()

        def admission_trace(statement):
            if statement.startswith("DELETE FROM pending WHERE card="):
                revocation_inside.set()
                if not release_revocation.wait(3):
                    callback_timeout.set()

        def asa_trace(statement):
            if statement == "BEGIN IMMEDIATE":
                asa_attempted.set()

        peer.db.set_trace_callback(admission_trace)
        self.adapter.db.set_trace_callback(asa_trace)
        with ThreadPoolExecutor(max_workers=2) as pool:
            admission_future = pool.submit(peer.admit_bundle, self.principal, revoked)
            try:
                self.assertTrue(revocation_inside.wait(3), "Revocation did not reach pending invalidation")
                asa_future = pool.submit(self.adapter.handle_asa, request)
                self.assertTrue(asa_attempted.wait(3), "ASA did not attempt its write transaction")
            finally:
                release_revocation.set()
            self.assertEqual(admission_future.result(timeout=3)["head_sequence"], 2)
            self.assertEqual(asa_future.result(timeout=3), {"result": "CARD_PAUSED"})
        self.assertFalse(callback_timeout.is_set(), "Test did not release revocation transaction")
        peer.db.set_trace_callback(None)
        self.adapter.db.set_trace_callback(None)
        self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM pending").fetchone()[0], 0)
        self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM decisions WHERE result='APPROVED'").fetchone()[0], 0)
        self._restart()
        self.assertEqual(self.adapter.handle_asa(request), {"result": "CARD_PAUSED"})

    def test_other_principal_cannot_be_used_as_bundle_storage_key(self):
        self._assert_wallet_error("ROOT_NOT_PINNED", lambda: self.adapter.admit_bundle("different-principal", self.bundle))
        self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM bundles").fetchone()[0], 1)

    def test_invalid_worker_signature_does_not_create_pending_authorization(self):
        wrong_key = Ed25519PrivateKey.generate()
        _, _, _, result = self._preauthorize(presentation_key=wrong_key, expected=False)
        self.assertEqual(result["reason"], "SUBJECT_BINDING_MISMATCH")
        self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM pending").fetchone()[0], 0)
        self._assert_declined(self.adapter, self._request())

    def test_valid_json_corruption_of_pending_proof_cannot_authorize(self):
        request, _, _, _ = self._preauthorize()
        self.adapter.db.execute("UPDATE pending SET proof='{}' WHERE card=?", (self.card,))
        with self.assertRaises(ReceiverStateError):
            self.adapter.handle_asa(request)
        self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM decisions").fetchone()[0], 0)
        self.assertEqual(self.adapter.db.execute("SELECT proof FROM pending").fetchone()[0], "{}")
        self._restart()
        with self.assertRaises(ReceiverStateError):
            self.adapter.handle_asa(request)

    def test_corrupt_persisted_bundle_fails_closed_without_erasing_history(self):
        request, _, _, _ = self._preauthorize()
        self.adapter.db.execute("UPDATE bundles SET body='not-json' WHERE principal=?", (self.principal,))
        with self.assertRaises(ReceiverStateError):
            self.adapter.handle_asa(request)
        self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM decisions").fetchone()[0], 0)
        self.assertEqual(self.adapter.db.execute("SELECT body FROM bundles").fetchone()[0], "not-json")
        self.adapter.close()
        self.adapters.remove(self.adapter)
        with self.assertRaises(ReceiverStateError):
            self._open()

    def test_inconsistent_persisted_head_fails_closed_and_restart_refuses(self):
        request, _, _, _ = self._preauthorize()
        self.adapter.db.execute("UPDATE bundles SET sequence=99 WHERE principal=?", (self.principal,))
        with self.assertRaises(ReceiverStateError):
            self.adapter.handle_asa(request)
        self.assertEqual(self.adapter.db.execute("SELECT count(*) FROM decisions").fetchone()[0], 0)
        self.adapter.close()
        self.adapters.remove(self.adapter)
        with self.assertRaises(ReceiverStateError):
            self._open()


if __name__ == "__main__":
    unittest.main(verbosity=2)
