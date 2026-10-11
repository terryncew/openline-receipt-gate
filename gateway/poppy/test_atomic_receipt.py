#!/usr/bin/env python3
"""Regression tests for receiver evidence and approval/effect atomicity.

No Envoy or paid provider needed. A signed receipt must describe the exact
committed effect, and the stored evidence must survive loss of HTTP response.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "mock_api.py"
sys.path.insert(0, str(ROOT))


class AtomicReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="atomic-receipt-")
        home = Path(self.temp.name)
        config = home / "config"
        config.mkdir()
        self.db_path = home / "ledger.sqlite"
        self.key = Ed25519PrivateKey.generate()
        from base64 import urlsafe_b64encode
        (config / "receiver.key").write_text(
            urlsafe_b64encode(self.key.private_bytes_raw()).rstrip(b"=").decode()
        )
        self.old_env = {
            k: os.environ.get(k) for k in ("GATEWAY_CONFIG", "GATEWAY_DB")
        }
        os.environ["GATEWAY_CONFIG"] = str(config)
        os.environ["GATEWAY_DB"] = str(self.db_path)
        # Reload under the isolated config so module globals cannot point at
        # another test's state.
        spec = importlib.util.spec_from_file_location(
            "mock_api_atomic_test", SOURCE
        )
        assert spec and spec.loader
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.ledger = self.module.LEDGER

    def tearDown(self):
        self.ledger.db.close()
        for k, value in self.old_env.items():
            if value is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = value
        self.temp.cleanup()

    def charge(self, decision="decision-1", approval="approval-1", key=None,
               merchant="test-merchant", amount=100):
        unsigned = {
            "receipt_id": f"receipt-{decision}",
            "decision_evidence": {
                "type": "poppy_decision",
                "decision": "ALLOWED",
                "delegated_authority": {"agent_id": "agent-1"},
            },
        }
        return self.ledger.transfer_with_approval_and_receipt(
            merchant, amount, decision, approval, unsigned,
            self.key if key is None else key
        )

    def test_signed_receipt_is_identical_to_durable_evidence(self):
        result = self.charge()
        self.assertTrue(result["ok"], result)
        receipt = result["poppy_receipt"]
        self.assertEqual(receipt["effect_evidence"]["effect_id"],
                         result["effect_id"])
        self.assertEqual(receipt["effect_evidence"]["treasury_delta_cents"],
                         -100)
        self.assertEqual(receipt["effect_evidence"]["merchant_delta_cents"],
                         100)
        signed_body = {
            k: v for k, v in receipt.items()
            if k not in ("receiver_signature", "receiver_public_key")
        }
        self.key.public_key().verify(
            self.module.b64u_decode(receipt["receiver_signature"]),
            self.module.canonical(signed_body),
        )
        stored = json.loads(self.ledger.db.execute(
            "SELECT body FROM effects WHERE effect_id=?",
            (result["effect_id"],)).fetchone()[0])
        self.assertEqual(json.loads(stored["receipt"]), receipt)
        self.assertEqual(self.ledger.balance("treasury"), 999900)
        self.assertEqual(self.ledger.balance("test-merchant"), 100)

        # If the caller never received its HTTP response, reconnecting to
        # the database must still recover independently verifiable evidence.
        other = sqlite3.connect(str(self.db_path))
        try:
            self.assertEqual(json.loads(
                json.loads(other.execute("SELECT body FROM effects").fetchone()[0])["receipt"]
            ), receipt)
        finally:
            other.close()

    def test_signing_failure_cannot_commit_effect_or_use_approval(self):
        class BrokenKey:
            def sign(self, _):
                raise RuntimeError("simulated signing outage")

        bad = self.charge(key=BrokenKey())
        self.assertFalse(bad["ok"])
        self.assertEqual(self.ledger.balance("treasury"), 1000000)
        self.assertEqual(self.ledger.db.execute(
            "SELECT COUNT(*) FROM effects").fetchone()[0], 0)
        self.assertEqual(self.ledger.db.execute(
            "SELECT COUNT(*) FROM used_approvals").fetchone()[0], 0)
        good = self.charge()
        self.assertTrue(good["ok"], good)

    def test_reuse_of_approval_does_not_double_execute(self):
        first = self.charge()
        second = self.charge("decision-2", "approval-1")
        self.assertTrue(first["ok"])
        self.assertFalse(second["ok"])
        self.assertIn("ALREADY_USED", second["error"])
        self.assertEqual(self.ledger.balance("treasury"), 999900)
        self.assertEqual(self.ledger.db.execute(
            "SELECT COUNT(*) FROM effects").fetchone()[0], 1)

    def test_invalid_amount_and_self_payment_cannot_move_money(self):
        self.assertFalse(self.charge(amount=-100)["ok"])
        self.assertFalse(self.charge(merchant="treasury")["ok"])
        self.assertEqual(self.ledger.balance("treasury"), 1000000)
        self.assertEqual(self.ledger.db.execute(
            "SELECT COUNT(*) FROM effects").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
