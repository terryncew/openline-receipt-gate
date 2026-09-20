"""Unit tests for OWNER-CONTROL-002.

In-process, deterministic, pure unittest (no pytest import) so the
tests run under both pytest and the CI unittest-discovery environment.

Covers the seven bounded cases of the preregistration at the unit
level: owner authority accepted when current, worker cannot self-elevate,
succession advances the current owner, successor can act, superseded
owner cannot return, restart preserves the successor, history remains
verifiable without conferring currency.
"""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate._durable_heads import DurableHeadStore
from olp_gate.crypto import public_key_hex, verify_olp_signature
from olp_gate.mandate_owner import (
    MandateAuthorityError,
    MandateOwnerView,
    create_trust_root_store,
    issue_mandate_authorization,
    issue_owner_trust_root_succession,
)

SLOT = "owner/default"
OWNER_ID = "owner"
NOW = datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc)
LONG = timedelta(days=3650)


def _keys4():
    priv = [Ed25519PrivateKey.generate() for _ in range(4)]
    return priv, [public_key_hex(k) for k in priv]


def _mandate():
    return {
        "profile": "principal_mandate/v1",
        "mandate_id": "owner-control-002-mandate",
        "principal_id": OWNER_ID,
        "agent_id": "owner-control-002-agent",
        "purpose": "unit test",
        "allowed_action_types": ["authorize_payment"],
        "allowed_targets": ["payments://ledger"],
        "allowed_disclosure_classes": [],
        "forbidden_disclosure_classes": [],
        "max_settlement_cents": 0,
        "max_payment_cents": 100,
        "delegation_allowed": False,
        "expires_at": "2030-01-01T00:00:00Z",
        "version": "v1",
    }


def _auth(signer_key, state, sequence, predecessor, issued=NOW):
    return issue_mandate_authorization(
        slot_id=SLOT,
        owner_id=OWNER_ID,
        mandate=_mandate(),
        state=state,
        sequence=sequence,
        predecessor_hash=predecessor,
        issued_at=issued - timedelta(seconds=10),
        expires_at=issued + LONG,
        key=signer_key,
    )


def _succession(signer_key, successor_pub, seq, pred, issued=NOW):
    return issue_owner_trust_root_succession(
        slot_id=SLOT,
        owner_id=OWNER_ID,
        successor_owner_id=OWNER_ID,
        successor_public_key=successor_pub,
        succession_sequence=seq,
        predecessor_succession_hash=pred,
        issued_at=issued - timedelta(seconds=10),
        expires_at=issued + LONG,
        key=signer_key,
    )


class OwnerControl002Tests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pubs = _keys4()  # A, B, C, W
        self.view = MandateOwnerView(
            {SLOT: {"owner_id": OWNER_ID, "public_key": self.pubs[0]}}
        )

    def test_1_owner_stop_accepted_when_current(self):
        a1 = _auth(self.priv[0], "ACTIVE", 1, None)
        adm1 = self.view.admit(a1, _mandate(), now=NOW)
        self.assertTrue(adm1["admitted"])
        self.assertEqual(self.view.status(SLOT, now=NOW), "ACTIVE")
        a2 = _auth(self.priv[0], "REVOKED", 2, a1["payload_hash"])
        adm2 = self.view.admit(a2, _mandate(), now=NOW)
        self.assertTrue(adm2["admitted"])
        self.assertEqual(self.view.status(SLOT, now=NOW), "REVOKED")
        self.assertEqual(self.view.head_sequence(SLOT), 2)
        self.assertEqual(
            self.view.current_owner(SLOT)["public_key"], self.pubs[0]
        )

    def test_2_worker_cannot_self_elevate(self):
        a1 = _auth(self.priv[0], "ACTIVE", 1, None)
        a2 = _auth(self.priv[0], "REVOKED", 2, a1["payload_hash"])
        self.view.admit(a1, _mandate(), now=NOW)
        self.view.admit(a2, _mandate(), now=NOW)
        # W has the full mandate, the head hash, correct naming: everything
        # but the owner private key. Signing succeeds (authorship), admission
        # must fail at the owner-authority boundary.
        w3 = _auth(self.priv[3], "REVOKED", 3, a2["payload_hash"])
        valid, _ = verify_olp_signature(w3)
        self.assertTrue(valid, "SIGNATURE_VALID under W's own key")
        with self.assertRaises(MandateAuthorityError) as ctx:
            self.view.admit(w3, _mandate(), now=NOW)
        self.assertIn(
            "mandate_authorization_owner_key_mismatch", str(ctx.exception)
        )
        self.assertEqual(self.view.head_sequence(SLOT), 2)
        self.assertEqual(self.view.status(SLOT, now=NOW), "REVOKED")

    def test_3_succession_advances_current_owner(self):
        ev = _succession(self.priv[0], self.pubs[1], 1, None)
        adm = self.view.admit_trust_root_succession(ev, now=NOW)
        self.assertTrue(adm["admitted"])
        owner = self.view.current_owner(SLOT)
        self.assertEqual(owner["public_key"], self.pubs[1])
        self.assertEqual(self.view.succession_sequence(SLOT), 1)
        self.assertEqual(len(self.view.key_schedule(SLOT)), 2)

    def test_4_successor_can_exercise_owner_authority(self):
        a1 = _auth(self.priv[0], "ACTIVE", 1, None)
        self.view.admit(a1, _mandate(), now=NOW)
        ev = _succession(self.priv[0], self.pubs[1], 1, None)
        self.view.admit_trust_root_succession(ev, now=NOW)
        b2 = _auth(self.priv[1], "ACTIVE", 2, a1["payload_hash"])
        adm = self.view.admit(b2, _mandate(), now=NOW)
        self.assertTrue(adm["admitted"])
        b3 = _auth(self.priv[1], "REVOKED", 3, b2["payload_hash"])
        self.view.admit(b3, _mandate(), now=NOW)
        self.assertEqual(self.view.status(SLOT, now=NOW), "REVOKED")
        b4 = _auth(self.priv[1], "ACTIVE", 4, b3["payload_hash"])
        adm4 = self.view.admit(b4, _mandate(), now=NOW)
        self.assertTrue(adm4["admitted"])
        self.assertEqual(self.view.status(SLOT, now=NOW), "ACTIVE")

    def test_5_superseded_owner_cannot_return(self):
        a1 = _auth(self.priv[0], "ACTIVE", 1, None)
        self.view.admit(a1, _mandate(), now=NOW)
        ev = _succession(self.priv[0], self.pubs[1], 1, None)
        self.view.admit_trust_root_succession(ev, now=NOW)
        b2 = _auth(self.priv[1], "ACTIVE", 2, a1["payload_hash"])
        self.view.admit(b2, _mandate(), now=NOW)
        # A's fresh STOP: cryptographically valid, authority-refused.
        a3 = _auth(self.priv[0], "REVOKED", 3, b2["payload_hash"])
        valid, _ = verify_olp_signature(a3)
        self.assertTrue(valid, "SIGNATURE_VALID under A's key")
        with self.assertRaises(MandateAuthorityError) as ctx:
            self.view.admit(a3, _mandate(), now=NOW)
        self.assertIn(
            "mandate_authorization_owner_key_mismatch", str(ctx.exception)
        )
        self.assertEqual(self.view.head_sequence(SLOT), 2)
        self.assertEqual(self.view.status(SLOT, now=NOW), "ACTIVE")
        self.assertEqual(
            self.view.current_owner(SLOT)["public_key"], self.pubs[1]
        )

    def test_6_restart_preserves_successor(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            slots = {SLOT: {"owner_id": OWNER_ID, "public_key": self.pubs[0]}}
            create_trust_root_store(str(tmp_path / "trust_roots.json"), slots)
            DurableHeadStore.create(
                str(tmp_path / "heads.json"),
                {"view": "mandate_owner/v1", "slots": slots},
            )
            view = MandateOwnerView(
                slots,
                durable_path=str(tmp_path / "heads.json"),
                trust_root_path=str(tmp_path / "trust_roots.json"),
            )
            a1 = _auth(self.priv[0], "ACTIVE", 1, None)
            view.admit(a1, _mandate(), now=NOW)
            ev = _succession(self.priv[0], self.pubs[1], 1, None)
            view.admit_trust_root_succession(ev, now=NOW)
            # Restart: rebuild from durable state only.
            view2 = MandateOwnerView(
                slots,
                durable_path=str(tmp_path / "heads.json"),
                trust_root_path=str(tmp_path / "trust_roots.json"),
            )
            self.assertEqual(
                view2.current_owner(SLOT)["public_key"], self.pubs[1]
            )
            self.assertEqual(view2.succession_sequence(SLOT), 1)
            self.assertEqual(len(view2.key_schedule(SLOT)), 2)
            # B still authoritative; A still not.
            b2 = _auth(self.priv[1], "ACTIVE", 2, a1["payload_hash"])
            adm = view2.admit(b2, _mandate(), now=NOW)
            self.assertTrue(adm["admitted"])
            a3 = _auth(self.priv[0], "REVOKED", 3, b2["payload_hash"])
            with self.assertRaises(MandateAuthorityError) as ctx:
                view2.admit(a3, _mandate(), now=NOW)
            self.assertIn(
                "mandate_authorization_owner_key_mismatch", str(ctx.exception)
            )
            self.assertEqual(view2.head_sequence(SLOT), 2)

    def test_7_history_verifiable_without_currency(self):
        a1 = _auth(self.priv[0], "ACTIVE", 1, None)
        self.view.admit(a1, _mandate(), now=NOW)
        ev = _succession(self.priv[0], self.pubs[1], 1, None)
        self.view.admit_trust_root_succession(ev, now=NOW)
        b2 = _auth(self.priv[1], "ACTIVE", 2, a1["payload_hash"])
        self.view.admit(b2, _mandate(), now=NOW)

        old = self.view.assess(a1, _mandate(), now=NOW)
        self.assertTrue(old["verified"], "HISTORICALLY_VALID")
        self.assertFalse(old["current"])
        self.assertEqual(
            old["reason_codes"], ["trust_root_succession_historical_key"]
        )
        self.assertEqual(old["historical_public_key"], self.pubs[0])

        cur = self.view.assess(b2, _mandate(), now=NOW)
        self.assertTrue(cur["verified"])
        self.assertTrue(cur["current"])
        self.assertEqual(self.view.status(SLOT, now=NOW), "ACTIVE")


if __name__ == "__main__":
    unittest.main()
