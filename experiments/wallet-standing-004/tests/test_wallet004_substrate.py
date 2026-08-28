from __future__ import annotations

import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from olp_gate.crypto import public_key_hex, sign_olp_body
from wallet004.clock import Calibration, tau_measurement
from wallet004.envelope import create_envelope, verify_envelope
from wallet004.store import DurableStore
from wallet004.wire import recv_json, reply_json, send_json


class EnvelopeTests(unittest.TestCase):
    def test_epoch_nanoseconds_are_signed_as_canonical_decimal_text(self):
        key = Ed25519PrivateKey.generate()
        emitted = time.time_ns()
        self.assertGreater(emitted, (1 << 53) - 1)
        envelope = create_envelope(
            {"schema": "fixture.v1", "value": 1},
            kind="FREEZE",
            emitted_ns=emitted,
            measurement_key=key,
        )
        self.assertEqual(envelope["emitted_ns"], str(emitted))
        valid, reason = verify_envelope(
            envelope, measurement_public_key=public_key_hex(key)
        )
        self.assertTrue(valid, reason)

    def test_noncanonical_emitted_ns_is_rejected(self):
        key = Ed25519PrivateKey.generate()
        envelope = create_envelope(
            {"schema": "fixture.v1", "value": 1},
            kind="FREEZE",
            emitted_ns=time.time_ns(),
            measurement_key=key,
        )
        body = dict(envelope)
        body.pop("payload_hash")
        body.pop("signature")
        body["emitted_ns"] = "01"
        malformed = sign_olp_body(body, key)
        valid, reason = verify_envelope(
            malformed, measurement_public_key=public_key_hex(key)
        )
        self.assertFalse(valid)
        self.assertEqual(reason, "emitted_ns_invalid")


class StoreTests(unittest.TestCase):
    def test_full_commit_advances_revision(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = DurableStore(Path(tmp) / "gate.sqlite")
            store.initialize({"gate": "a", "standing": 1})
            timing = store.commit_state(
                state={"gate": "a", "standing": 2},
                kind="FREEZE",
                event_hash="a" * 64,
                receipt={"decision": "ACCEPT_FREEZE"},
            )
            state, revision = store.load()
            self.assertEqual(revision, 1)
            self.assertEqual(state["standing"], 2)
            self.assertGreaterEqual(timing["commit_complete_ns"], timing["commit_started_ns"])
            store.close()

    def test_uncommitted_transaction_does_not_survive(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gate.sqlite"
            store = DurableStore(path)
            store.initialize({"standing": 1})
            store.conn.execute("BEGIN IMMEDIATE")
            store.conn.execute("UPDATE gate_state SET state_json='{}', revision=99 WHERE singleton=1")
            store.conn.rollback()
            state, revision = store.load()
            self.assertEqual(revision, 0)
            self.assertEqual(state["standing"], 1)
            store.close()


class WireTests(unittest.TestCase):
    def test_ndjson_round_trip(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def worker():
            conn, _ = server.accept()
            with conn:
                msg = recv_json(conn)
                reply_json(conn, {"ok": True, "echo": msg})
            server.close()

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        result = send_json("127.0.0.1", port, {"x": 1})
        self.assertEqual(result["echo"], {"x": 1})
        thread.join(timeout=2)


class ClockTests(unittest.TestCase):
    def test_tau_censored(self):
        cal = Calibration("g", 0, 1000, 2000, 7)
        result = tau_measurement(emitted_ns=1, commit_complete_ns=None, calibration=cal)
        self.assertEqual(result["status"], "CENSORED_UNDELIVERED")

    def test_tau_corrects_offset(self):
        cal = Calibration("g", 100, 10, 20, 7)
        result = tau_measurement(emitted_ns=1000, commit_complete_ns=2100, calibration=cal)
        self.assertEqual(result["raw_ns"], 1100)
        self.assertEqual(result["offset_corrected_ns"], 1000)


if __name__ == "__main__":
    unittest.main()
