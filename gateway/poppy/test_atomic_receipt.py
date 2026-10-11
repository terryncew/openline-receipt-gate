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
import subprocess
import time
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

    def _run_separate_process(self, script, *, extra_env=None):
        env = os.environ.copy()
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            [sys.executable, "-c", script], env=env, capture_output=True,
            text=True, timeout=15,
        )

    def _child_boot(self):
        return (
            "import sys, os, json, time; "
            f"sys.path.insert(0, {str(ROOT)!r}); "
            "import mock_api; "
            "from cryptography.hazmat.primitives.asymmetric.ed25519 "
            "import Ed25519PrivateKey; "
            "from pathlib import Path; "
            "key = Ed25519PrivateKey.from_private_bytes("
            "mock_api.b64u_decode(Path(os.environ['GATEWAY_CONFIG'], "
            "'receiver.key').read_text().strip())); "
            "receipt = {'receipt_id':'multiprocess-receipt', "
            "'decision_evidence':{'decision':'ALLOWED'}}; "
        )

    def test_four_separate_processes_one_approval_one_effect(self):
        """SQLite atomicity must hold across independent OS processes."""
        barrier = Path(self.temp.name) / "go"
        children = []
        try:
            for index in range(4):
                ready = Path(self.temp.name) / f"ready-{index}"
                env = os.environ.copy()
                env["OPENLINE_TEST_READY"] = str(ready)
                env["OPENLINE_TEST_GO"] = str(barrier)
                env["OPENLINE_TEST_DECISION"] = f"race-{index}"
                code = self._child_boot() + (
                    "Path(os.environ['OPENLINE_TEST_READY']).touch(); "
                    "deadline=time.monotonic()+10; "
                    "\nwhile not Path(os.environ['OPENLINE_TEST_GO']).exists():"
                    "\n  assert time.monotonic()<deadline; time.sleep(.01)"
                    "\nr=mock_api.LEDGER.transfer_with_approval_and_receipt("
                    "'test-merchant',100,os.environ['OPENLINE_TEST_DECISION'],"
                    "'same-owner-approval',receipt,key)"
                    "\nprint(json.dumps({'ok':r['ok'],'error':r.get('error')}))"
                )
                children.append(subprocess.Popen(
                    [sys.executable, "-c", code], env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                ))
            deadline = time.monotonic() + 10
            while not all(
                (Path(self.temp.name) / f"ready-{i}").exists()
                for i in range(4)
            ):
                self.assertTrue(time.monotonic() < deadline,
                                "child did not initialize before race")
                time.sleep(.02)
            barrier.touch()
            results = []
            for child in children:
                out, err = child.communicate(timeout=15)
                self.assertEqual(child.returncode, 0, err)
                results.append(json.loads(out.strip().splitlines()[-1]))
            self.assertEqual(sum(x["ok"] for x in results), 1, results)
            self.assertTrue(all(
                x["ok"] or "ALREADY_USED" in x["error"] for x in results
            ), results)
            self.assertEqual(self.ledger.balance("treasury"), 999900)
            self.assertEqual(self.ledger.db.execute(
                "SELECT COUNT(*) FROM effects").fetchone()[0], 1)
            receipt_text = json.loads(self.ledger.db.execute(
                "SELECT body FROM effects").fetchone()[0])["receipt"]
            evidence = json.loads(receipt_text)
            unsigned = {
                k: v for k, v in evidence.items()
                if k not in ("receiver_signature", "receiver_public_key")
            }
            self.key.public_key().verify(
                self.module.b64u_decode(evidence["receiver_signature"]),
                self.module.canonical(unsigned)
            )
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                    child.wait()

    def test_crash_while_signing_rolls_back_ledger_effect(self):
        """Process death before SQLite COMMIT must consume no approval."""
        script = self._child_boot() + (
            "\nclass KillDuringSign:"
            "\n  def sign(self, payload):"
            "\n    os._exit(37)"
            "\nmock_api.LEDGER.transfer_with_approval_and_receipt("
            "'test-merchant',100,'crash-1','approval-1',receipt,"
            "KillDuringSign())"
        )
        child = self._run_separate_process(script)
        self.assertEqual(child.returncode, 37, child.stderr)
        self.assertEqual(self.ledger.balance("treasury"), 1000000)
        self.assertEqual(self.ledger.db.execute(
            "SELECT COUNT(*) FROM effects").fetchone()[0], 0)
        self.assertEqual(self.ledger.db.execute(
            "SELECT COUNT(*) FROM used_approvals").fetchone()[0], 0)
        self.assertTrue(self.charge()["ok"])

    def test_crash_after_commit_preserves_verifiable_evidence(self):
        """Lost HTTP response must not erase a committed receipt."""
        script = self._child_boot() + (
            "r=mock_api.LEDGER.transfer_with_approval_and_receipt("
            "'test-merchant',100,'post-commit-1','approval-1',receipt,key);"
            " assert r['ok'],r; os._exit(38)"
        )
        child = self._run_separate_process(script)
        self.assertEqual(child.returncode, 38, child.stderr)
        self.assertEqual(self.ledger.balance("treasury"), 999900)
        self.assertEqual(self.ledger.db.execute(
            "SELECT COUNT(*) FROM effects").fetchone()[0], 1)
        stored = json.loads(self.ledger.db.execute(
            "SELECT body FROM effects").fetchone()[0])
        receipt = json.loads(stored["receipt"])
        signed = {
            k: v for k, v in receipt.items()
            if k not in ("receiver_signature", "receiver_public_key")
        }
        self.key.public_key().verify(
            self.module.b64u_decode(receipt["receiver_signature"]),
            self.module.canonical(signed),
        )
        replay = self.charge(decision="post-commit-2", approval="approval-1")
        self.assertFalse(replay["ok"])
        self.assertIn("ALREADY_USED", replay["error"])

    def test_invalid_amount_and_self_payment_cannot_move_money(self):
        self.assertFalse(self.charge(amount=-100)["ok"])
        self.assertFalse(self.charge(merchant="treasury")["ok"])
        self.assertEqual(self.ledger.balance("treasury"), 1000000)
        self.assertEqual(self.ledger.db.execute(
            "SELECT COUNT(*) FROM effects").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
