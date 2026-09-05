from __future__ import annotations

import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import public_key_hex
from olp_gate.mandate_owner import MandateOwnerView, issue_mandate_authorization
from olp_gate.subject_bound_commit import SubjectBoundCommitGate


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class OneUseLedgerDouble:
    """Only the already-proven one-use boundary needed by this composition test."""

    def __init__(self) -> None:
        self.calls = 0
        self.effects = 0
        self.consumed = False
        self._lock = threading.Lock()

    @staticmethod
    def _blocked(reason: str) -> dict:
        return {
            "authorized": False,
            "reason_codes": [reason],
            "attempt_id": "double",
            "decision_payload_hash": "11" * 32,
            "authorization_hash": "22" * 32,
            "action_hash": "33" * 32,
            "replay_scope_hash": None,
        }

    def check_and_consume(self, receipt, action, **kwargs):
        with self._lock:
            self.calls += 1
            if self.consumed:
                return self._blocked("authorization_replay")
            self.consumed = True
            return {
                "authorized": True,
                "reason_codes": [],
                "attempt_id": "double",
                "decision_payload_hash": "11" * 32,
                "authorization_hash": "22" * 32,
                "action_hash": "33" * 32,
                "replay_scope_hash": kwargs.get("replay_scope_hash"),
            }

    def execute_once(self, receipt, action, *, executor, preflight=None, **kwargs):
        with self._lock:
            self.calls += 1
            if self.consumed:
                return self._blocked("authorization_replay")
            # Match VerifiedCommitLedger's safety order: reserve before preflight/effect.
            self.consumed = True

        if preflight is not None:
            fresh = preflight()
            if not isinstance(fresh, dict) or fresh.get("allowed") is not True:
                return {
                    **self._blocked(
                        (fresh.get("reason_codes") or ["receiver_preflight_blocked"])[0]
                        if isinstance(fresh, dict)
                        else "receiver_preflight_result_invalid"
                    ),
                    "attempt_id": "double",
                }

        value = executor()
        self.effects += 1
        return {
            "authorized": True,
            "reason_codes": [],
            "attempt_id": "double",
            "decision_payload_hash": "11" * 32,
            "authorization_hash": "22" * 32,
            "action_hash": "33" * 32,
            "replay_scope_hash": kwargs.get("replay_scope_hash"),
            "execution_status": "completed",
            "tool_result": value,
        }


class StolenAuthority001Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 4, 20, 0, tzinfo=timezone.utc)
        self.owner_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("74" * 32))
        self.slot_id = "portable-agent/default"
        self.owner_id = "receiver-owner"
        self.agent_id = "portable-agent-7"
        self.mandate = {
            "profile": "principal_mandate/v1",
            "mandate_id": "stolen-authority-001-mandate",
            "principal_id": self.owner_id,
            "agent_id": self.agent_id,
            "purpose": "exercise subject-bound portable authority",
            "allowed_action_types": ["inspect"],
            "allowed_targets": ["fixture://effect"],
            "allowed_disclosure_classes": [],
            "forbidden_disclosure_classes": [],
            "max_settlement_cents": 0,
            "max_payment_cents": 0,
            "delegation_allowed": False,
            "expires_at": _iso(self.now + timedelta(days=1)),
            "version": "1",
        }
        self.view = MandateOwnerView(
            {
                self.slot_id: {
                    "owner_id": self.owner_id,
                    "public_key": public_key_hex(self.owner_key),
                }
            }
        )
        initial = issue_mandate_authorization(
            slot_id=self.slot_id,
            owner_id=self.owner_id,
            mandate=self.mandate,
            state="ACTIVE",
            sequence=1,
            predecessor_hash=None,
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(hours=2),
            key=self.owner_key,
        )
        self.view.admit(initial, self.mandate, now=self.now)
        self.receipt = {
            "payload_hash": "11" * 32,
            "commit_authorization": {
                "authorization_hash": "22" * 32,
                "action_hash": "33" * 32,
            },
        }
        self.action = {"tool": "fixture.effect"}
        self.code = "ab" * 32
        self.keys = ["44" * 32]

    def gate(self, ledger, subject_source):
        return SubjectBoundCommitGate(
            ledger,
            mandate_view=self.view,
            mandate_slot_id=self.slot_id,
            subject_source=subject_source,
        )

    def test_wrong_subject_is_blocked_before_ledger_or_effect(self) -> None:
        ledger = OneUseLedgerDouble()
        gate = self.gate(ledger, lambda: "agent-b")
        called = []
        result = gate.execute_once(
            self.receipt,
            self.action,
            one_use_code=self.code,
            trusted_gate_keys=self.keys,
            executor=lambda: called.append("effect"),
            now=self.now,
        )
        self.assertFalse(result["authorized"])
        self.assertEqual(result["reason_codes"], ["authority_subject_mismatch"])
        self.assertEqual(ledger.calls, 0)
        self.assertEqual(called, [])

    def test_thief_cannot_burn_rightful_permission(self) -> None:
        ledger = OneUseLedgerDouble()
        thief = self.gate(ledger, lambda: "agent-b")
        owner = self.gate(ledger, lambda: self.agent_id)
        effects = []

        stolen = thief.execute_once(
            self.receipt,
            self.action,
            one_use_code=self.code,
            trusted_gate_keys=self.keys,
            executor=lambda: effects.append("thief"),
            now=self.now,
        )
        rightful = owner.execute_once(
            self.receipt,
            self.action,
            one_use_code=self.code,
            trusted_gate_keys=self.keys,
            executor=lambda: effects.append("owner") or {"ok": True},
            now=self.now,
        )
        replay = owner.execute_once(
            self.receipt,
            self.action,
            one_use_code=self.code,
            trusted_gate_keys=self.keys,
            executor=lambda: effects.append("replay"),
            now=self.now,
        )

        self.assertFalse(stolen["authorized"])
        self.assertTrue(rightful["authorized"])
        self.assertFalse(replay["authorized"])
        self.assertIn("authorization_replay", replay["reason_codes"])
        self.assertEqual(effects, ["owner"])
        self.assertEqual(ledger.calls, 2)

    def test_concurrent_wrong_and_rightful_subject_only_spend_once(self) -> None:
        ledger = OneUseLedgerDouble()
        thief = self.gate(ledger, lambda: "agent-b")
        owner = self.gate(ledger, lambda: self.agent_id)
        barrier = threading.Barrier(2)
        effects = []

        def run(gate, label):
            barrier.wait()
            return gate.execute_once(
                self.receipt,
                self.action,
                one_use_code=self.code,
                trusted_gate_keys=self.keys,
                executor=lambda: effects.append(label),
                now=self.now,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            thief_future = pool.submit(run, thief, "thief")
            owner_future = pool.submit(run, owner, "owner")
            stolen = thief_future.result()
            rightful = owner_future.result()

        self.assertFalse(stolen["authorized"])
        self.assertTrue(rightful["authorized"])
        self.assertEqual(effects, ["owner"])
        self.assertEqual(ledger.calls, 1)

    def test_revoked_current_mandate_fails_before_ledger(self) -> None:
        predecessor = self.view.head_hash(self.slot_id)
        revoked = issue_mandate_authorization(
            slot_id=self.slot_id,
            owner_id=self.owner_id,
            mandate=self.mandate,
            state="REVOKED",
            sequence=2,
            predecessor_hash=predecessor,
            issued_at=self.now,
            expires_at=self.now + timedelta(hours=2),
            key=self.owner_key,
        )
        self.view.admit(revoked, self.mandate, now=self.now)

        ledger = OneUseLedgerDouble()
        gate = self.gate(ledger, lambda: self.agent_id)
        result = gate.check_and_consume(
            self.receipt,
            self.action,
            one_use_code=self.code,
            trusted_gate_keys=self.keys,
            now=self.now,
        )
        self.assertFalse(result["authorized"])
        self.assertEqual(
            result["reason_codes"],
            ["authority_subject_current_mandate_unavailable"],
        )
        self.assertEqual(ledger.calls, 0)

    def test_subject_source_error_fails_closed_before_ledger(self) -> None:
        ledger = OneUseLedgerDouble()

        def broken_subject():
            raise RuntimeError("receiver auth unavailable")

        gate = self.gate(ledger, broken_subject)
        result = gate.check_and_consume(
            self.receipt,
            self.action,
            one_use_code=self.code,
            trusted_gate_keys=self.keys,
            now=self.now,
        )
        self.assertFalse(result["authorized"])
        self.assertEqual(
            result["reason_codes"],
            ["authority_subject_resolution_failed"],
        )
        self.assertEqual(ledger.calls, 0)

    def test_provider_label_is_not_an_authority_identity_input(self) -> None:
        # Two providers may operate under the same receiver-authenticated stable
        # agent subject.  Provider/model labels never enter SubjectBoundCommitGate.
        for provider in ("provider-a", "provider-b"):
            with self.subTest(provider=provider):
                ledger = OneUseLedgerDouble()
                gate = self.gate(ledger, lambda: self.agent_id)
                result = gate.execute_once(
                    {**self.receipt, "untrusted_provider_label": provider},
                    self.action,
                    one_use_code=self.code,
                    trusted_gate_keys=self.keys,
                    executor=lambda provider=provider: provider,
                    now=self.now,
                )
                self.assertTrue(result["authorized"])
                self.assertEqual(result["tool_result"], provider)


if __name__ == "__main__":
    unittest.main()
