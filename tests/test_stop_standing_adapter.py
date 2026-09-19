"""Unit tests for the stop-standing adapter: fail-closed behavior and
independent re-derivation, without the full receipt-issuance path."""
from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate._durable_heads import DurableHeadStore
from olp_gate.crypto import public_key_hex, sha256_hex, sign_olp_body
from olp_gate.mandate_owner import (
    MandateOwnerView,
    issue_mandate_authorization,
)
from olp_gate.standing import (
    STANDING_PROJECTION_SCHEMA,
    ReceiverStandingView,
)
from olp_gate.stop_standing import (
    derive_path_verdict,
    owner_mandate_stop_check,
    receiver_action_stop_check,
)
from olp_gate.verified_commit import VerifiedCommitLedger


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


SLOT_ID = "slot/a"
OWNER_ID = "alice"


def _mandate(now: datetime) -> dict:
    return {
        "profile": "principal_mandate/v1",
        "mandate_id": "m-1",
        "principal_id": OWNER_ID,
        "agent_id": "agent-1",
        "purpose": "t",
        "allowed_action_types": ["authorize_payment"],
        "allowed_targets": ["vendor"],
        "allowed_disclosure_classes": [],
        "forbidden_disclosure_classes": [],
        "max_settlement_cents": 0,
        "max_payment_cents": 100,
        "delegation_allowed": False,
        "expires_at": _iso(now + timedelta(days=1)),
        "version": "v1",
    }


def _projection(*, issuer_id, key, support_hash, action_hash, standing,
                event_type, sequence, predecessor_hash, now):
    body = {
        "schema": STANDING_PROJECTION_SCHEMA,
        "projection_id": f"{issuer_id}:{sequence}",
        "issuer_id": issuer_id,
        "support_hash": support_hash,
        "action_hash": action_hash,
        "standing": standing,
        "event_type": event_type,
        "sequence": sequence,
        "predecessor_hash": predecessor_hash,
        "issued_at": _iso(now),
        "expires_at": _iso(now + timedelta(hours=1)),
    }
    return sign_olp_body(body, key)


class OwnerMandateStopCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="stop-adapter-")
        self.root = Path(self.temp.name)
        self.now = datetime.now(timezone.utc)
        self.owner_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("b1" * 32))
        heads_path = str(self.root / "heads.json")
        DurableHeadStore.create(
            heads_path,
            {
                "view": "mandate_owner/v1",
                "slots": {
                    SLOT_ID: {
                        "owner_id": OWNER_ID,
                        "public_key": public_key_hex(self.owner_key),
                    }
                },
            },
        )
        self.view = MandateOwnerView(
            {SLOT_ID: {"owner_id": OWNER_ID, "public_key": public_key_hex(self.owner_key)}},
            durable_path=heads_path,
        )
        self.mandate = _mandate(self.now)

    def tearDown(self):
        self.temp.cleanup()

    def _admit(self, state, sequence, predecessor_hash):
        record = issue_mandate_authorization(
            slot_id=SLOT_ID,
            owner_id=OWNER_ID,
            mandate=self.mandate,
            state=state,
            sequence=sequence,
            predecessor_hash=predecessor_hash,
            issued_at=self.now,
            expires_at=self.now + timedelta(hours=1),
            key=self.owner_key,
        )
        return self.view.admit(record, self.mandate, now=self.now)

    def test_active_allows_with_head_seq(self):
        self._admit("ACTIVE", 1, None)
        obs = owner_mandate_stop_check(self.view, SLOT_ID, now=self.now)()
        self.assertTrue(obs["allowed"])
        self.assertEqual(obs["standing"], "ACTIVE")
        self.assertFalse(obs["terminal"])
        self.assertEqual(obs["head_seq"], 1)
        self.assertEqual(obs["reason_codes"], [])

    def test_revoked_refuses_terminal(self):
        self._admit("ACTIVE", 1, None)
        self._admit("REVOKED", 2, self.view.head_hash(SLOT_ID))
        obs = owner_mandate_stop_check(self.view, SLOT_ID, now=self.now)()
        self.assertFalse(obs["allowed"])
        self.assertTrue(obs["terminal"])
        self.assertEqual(obs["standing"], "REVOKED")
        self.assertEqual(obs["head_seq"], 2)
        self.assertEqual(obs["reason_codes"], ["owner_standing_revoked"])

    def test_missing_head_refuses_fail_closed_not_terminal(self):
        obs = owner_mandate_stop_check(self.view, SLOT_ID, now=self.now)()
        self.assertFalse(obs["allowed"])
        self.assertFalse(obs["terminal"])
        self.assertEqual(obs["standing"], "MISSING")
        self.assertIn("owner_standing_head_missing", obs["reason_codes"])


class ReceiverActionStopCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="stop-adapter-r-")
        self.root = Path(self.temp.name)
        self.now = datetime.now(timezone.utc)
        self.issuer_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("b2" * 32))
        self.issuer_id = "owner-issuer"
        self.trusted = {self.issuer_id: public_key_hex(self.issuer_key)}
        heads_path = str(self.root / "standing_heads.json")
        DurableHeadStore.create(
            heads_path, {"view": "standing/v1", "trusted_issuers": dict(self.trusted)}
        )
        self.view = ReceiverStandingView(self.trusted, durable_path=heads_path)
        self.support_hash = sha256_hex(b"support")
        self.action_hash = sha256_hex(b"action")

    def tearDown(self):
        self.temp.cleanup()

    def _admit(self, standing, event_type, sequence, predecessor_hash):
        projection = _projection(
            issuer_id=self.issuer_id,
            key=self.issuer_key,
            support_hash=self.support_hash,
            action_hash=self.action_hash,
            standing=standing,
            event_type=event_type,
            sequence=sequence,
            predecessor_hash=predecessor_hash,
            now=self.now,
        )
        return self.view.admit(projection, now=self.now)

    def test_active_allows(self):
        self._admit("ACTIVE", "ADMIT", 1, None)
        check = receiver_action_stop_check(
            self.view, self.support_hash, self.action_hash, now=self.now
        )
        obs = check()
        self.assertTrue(obs["allowed"])
        self.assertEqual(obs["standing"], "ACTIVE")

    def test_inactive_refuses_terminal(self):
        first = self._admit("ACTIVE", "ADMIT", 1, None)
        self._admit("INACTIVE", "REVOKE", 2, first["head_hash"])
        check = receiver_action_stop_check(
            self.view, self.support_hash, self.action_hash, now=self.now
        )
        obs = check()
        self.assertFalse(obs["allowed"])
        self.assertTrue(obs["terminal"])
        self.assertEqual(obs["standing"], "INACTIVE")
        self.assertEqual(obs["head_seq"], 2)
        self.assertEqual(obs["reason_codes"], ["owner_standing_revoked"])


class FailClosedTests(unittest.TestCase):
    def test_check_exception_fails_closed_and_records_unknown(self):
        ledger = VerifiedCommitLedger(
            str(tempfile.mkdtemp(prefix="stop-fc-") + "/ledger.json")
        )

        def boom():
            raise RuntimeError("standing store unreachable")

        # The receipt is garbage AND the check explodes: the attempt must be
        # BLOCKED with the inability to check recorded, not raised.
        ledger.check_and_consume(
            {},
            {},
            one_use_code="x",
            trusted_gate_keys=[],
            final_authority_check=boom,
        )
        state = ledger.read_state()
        # The receipt itself was invalid, so the attempt is BLOCKED; the
        # standing observation must record the inability to check.
        attempt = state["attempts"][0]
        final = attempt["standing_final_check_v1"]
        self.assertEqual(final["standing"], "CHECK_FAILED")
        self.assertIn("final_standing_check_failed", attempt["reason_codes"])
        self.assertEqual(
            attempt["path_verdict_v1"],
            {"verdict": "UNKNOWN", "ordering": "CHECK_FAILED",
             "stop_effective_seq": None},
        )

    def test_malformed_observation_fails_closed(self):
        ledger = VerifiedCommitLedger(
            str(tempfile.mkdtemp(prefix="stop-mo-") + "/ledger.json")
        )
        # Malformed observation ("allowed" is not a bool) fails closed.
        ledger.check_and_consume(
            {},
            {},
            one_use_code="x",
            trusted_gate_keys=[],
            final_authority_check=lambda: {"allowed": "yes"},
        )
        attempt = ledger.read_state()["attempts"][0]
        self.assertEqual(attempt["standing_final_check_v1"]["standing"], "CHECK_FAILED")
        self.assertIn("final_standing_check_failed", attempt["reason_codes"])


class DeriveVerdictTests(unittest.TestCase):
    def _attempt(self, **kw):
        base = {
            "attempt_id": "a1",
            "commit_seq": 3,
            "result": "BLOCKED",
            "reason_codes": ["owner_standing_revoked"],
            "execution_status": "not_started",
            "standing_final_check_v1": {
                "installed": True,
                "allowed": False,
                "standing": "REVOKED",
                "terminal": True,
                "head_seq": 2,
                "head_hash": "ab" * 32,
                "reason_codes": ["owner_standing_revoked"],
            },
        }
        base.update(kw)
        return base

    def test_not_covered_has_no_verdict(self):
        verdict = derive_path_verdict({"attempt_id": "x"}, [])
        self.assertIsNone(verdict["verdict"])
        self.assertIsNone(verdict["ordering"])

    def test_escaped_when_terminal_predates_commit_observation(self):
        attempt = self._attempt(
            result="AUTHORIZED",
            reason_codes=[],
            execution_status="completed",
            standing_final_check_v1={
                "installed": True,
                "allowed": True,
                "standing": "ACTIVE",
                "terminal": False,
                "head_seq": 5,
                "head_hash": "ab" * 32,
                "reason_codes": [],
            },
        )
        verdict = derive_path_verdict(
            attempt, [{"state": "REVOKED", "sequence": 4, "slot_id": SLOT_ID}]
        )
        self.assertEqual(verdict["verdict"], "ESCAPED")
        self.assertEqual(verdict["stop_effective_seq"], 4)

    def test_pre_stop_commit_when_terminal_admitted_later(self):
        attempt = self._attempt(
            result="AUTHORIZED",
            reason_codes=[],
            execution_status="completed",
            standing_final_check_v1={
                "installed": True,
                "allowed": True,
                "standing": "ACTIVE",
                "terminal": False,
                "head_seq": 1,
                "head_hash": "ab" * 32,
                "reason_codes": [],
            },
        )
        verdict = derive_path_verdict(
            attempt, [{"state": "REVOKED", "sequence": 2, "slot_id": SLOT_ID}]
        )
        self.assertIsNone(verdict["verdict"])
        self.assertEqual(verdict["ordering"], "PRE_STOP_COMMIT")
        self.assertEqual(verdict["stop_effective_seq"], 2)


if __name__ == "__main__":
    unittest.main()
