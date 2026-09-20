"""Unit tests for PLATFORM-EXIT-KILL-002.

In-process, deterministic, pure unittest (no pytest import) so the tests
run under both pytest and the CI unittest-discovery environment.

Covers the six bounded cases of the preregistration at the unit level:
A operates under owner authority; the owner STOP revokes A's standing;
refusal is standing (not format); B continues under the same regime with
no new trust root; A cannot resume by fresh attempt, replay, or restart;
history stays intact and verifiable without conferring currency on A.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[1]
HARNESS = REPO / "experiments" / "platform-exit-kill-002" / "harness"
for _p in (str(REPO), str(HARNESS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import gate_path as gp  # noqa: E402
from olp_gate._durable_heads import DurableHeadStore  # noqa: E402
from olp_gate.crypto import public_key_hex, verify_olp_signature  # noqa: E402
from olp_gate.mandate import MandateSpec  # noqa: E402
from olp_gate.mandate_owner import MandateOwnerView, issue_mandate_authorization  # noqa: E402
from olp_gate.stop_standing import derive_path_verdict  # noqa: E402
from olp_gate.verified_commit import VerifiedCommitLedger  # noqa: E402

SLOT_A = "agent-a/platform-exit-job"
SLOT_B = "agent-b/platform-exit-job"
OWNER_ID = "owner"
NOW = datetime(2026, 9, 19, 12, 0, 0, tzinfo=timezone.utc)
LONG = timedelta(days=3650)


class PlatformExitKill(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="platform-exit-kill-")
        self.root = Path(self.temp.name)
        self.owner_key = Ed25519PrivateKey.generate()
        self.gate_key = Ed25519PrivateKey.generate()
        self.witness_key = Ed25519PrivateKey.generate()
        self.source_key = Ed25519PrivateKey.generate()
        self.owner_pub = public_key_hex(self.owner_key)
        self.slots = {
            SLOT_A: {"owner_id": OWNER_ID, "public_key": self.owner_pub},
            SLOT_B: {"owner_id": OWNER_ID, "public_key": self.owner_pub},
        }
        self.heads_path = str(self.root / "owner_heads.json")
        DurableHeadStore.create(
            self.heads_path, {"view": "mandate_owner/v1", "slots": self.slots}
        )
        self.mandate_a = gp.build_mandate("agent-a")
        self.mandate_b = gp.build_mandate("agent-b")
        self.gate = gp.GatePath(
            root=self.root,
            run_now=NOW,
            gate_key=self.gate_key,
            witness_key=self.witness_key,
            source_key=self.source_key,
            source_method="did:example:unit-source#key-1",
        )
        self.admissions: list[dict] = []
        self.n = 0

    def tearDown(self) -> None:
        self.temp.cleanup()

    # -- helpers ------------------------------------------------------

    def _view(self) -> MandateOwnerView:
        return MandateOwnerView(self.slots, durable_path=self.heads_path)

    def _ledger(self) -> VerifiedCommitLedger:
        return VerifiedCommitLedger(self.root / "commit_ledger.json")

    def _admit(self, slot: str, mandate: dict, state: str, sequence: int,
               predecessor_hash: str | None) -> dict:
        record = issue_mandate_authorization(
            slot_id=slot, owner_id=OWNER_ID, mandate=mandate, state=state,
            sequence=sequence, predecessor_hash=predecessor_hash,
            issued_at=NOW, expires_at=NOW + LONG, key=self.owner_key,
        )
        admission = self._view().admit(record, mandate, now=NOW)
        self.admissions.append(
            {"slot": slot, "state": state, "sequence": sequence}
        )
        return admission

    def _attempt(self, agent: str, effect_id: str) -> dict:
        self.n += 1
        attempt_id = f"u{self.n}-{agent}-{effect_id}"
        mandate = self.mandate_a if agent == "a" else self.mandate_b
        spec = MandateSpec.from_mapping(mandate)
        effect = gp.build_effect(mandate, effect_id)
        settings = gp.compile_verified_commit_settings(spec, effect, now=NOW)
        preflight = gp.mandate_preflight(mandate, settings, now=NOW)
        receipt, action, code = self.gate.issue_decision_receipt(attempt_id, settings)
        marker, executor = gp.make_executor(
            self.root / "effects", f"agent-{agent}", "unit", attempt_id, effect_id
        )
        result = gp.execute_mandated_once(
            self._ledger(), receipt, action, mandate=spec, one_use_code=code,
            trusted_gate_keys=[public_key_hex(self.gate_key)],
            executor=executor, now=NOW, attempt_label=attempt_id,
            mandate_owner_view=self._view(),
            mandate_slot_id=SLOT_A if agent == "a" else SLOT_B,
        )
        result["preflight_allowed"] = preflight["allowed"] is True
        result["marker_exists"] = marker.exists()
        result["effect_id"] = effect_id
        result["attempt_id"] = attempt_id
        # Authoritative per-attempt fields live in the journal, not in the
        # early-refusal result dict.
        journal_hit = None
        for attempt in self._ledger().read_state().get("attempts", []):
            if attempt.get("attempt_label") == attempt_id:
                journal_hit = attempt
        assert journal_hit is not None, f"{attempt_id} missing from journal"
        result["journal_execution_status"] = journal_hit.get("execution_status")
        result["journal_result"] = journal_hit.get("result")
        return result

    # -- cases --------------------------------------------------------

    def test_1_a_operates_under_owner_authority(self):
        self._admit(SLOT_A, self.mandate_a, "ACTIVE", 1, None)
        view = self._view()
        self.assertEqual(view.status(SLOT_A, now=NOW), "ACTIVE")
        for effect_id in ("e1", "e2"):
            result = self._attempt("a", effect_id)
            self.assertTrue(result["authorized"], result.get("reason_codes"))
            self.assertEqual(result["journal_execution_status"], "completed")
            self.assertTrue(result["marker_exists"])
            self.assertTrue(result["preflight_allowed"])
        state = self._ledger().read_state()
        self.assertEqual([a["commit_seq"] for a in state["attempts"]], [1, 2])

    def test_2_owner_stop_revokes_a_standing(self):
        self._admit(SLOT_A, self.mandate_a, "ACTIVE", 1, None)
        self.assertEqual(self._view().status(SLOT_A, now=NOW), "ACTIVE")
        self._admit(SLOT_A, self.mandate_a, "REVOKED", 2,
                    self._view().head_hash(SLOT_A))
        self.assertEqual(self._view().status(SLOT_A, now=NOW), "REVOKED")
        result = self._attempt("a", "e3")
        self.assertFalse(result["authorized"])
        self.assertIn("owner_standing_revoked", result["reason_codes"])
        self.assertEqual(result["journal_execution_status"], "not_started")
        self.assertFalse(result["marker_exists"])

    def test_3_refusal_is_standing_not_format(self):
        self._admit(SLOT_A, self.mandate_a, "ACTIVE", 1, None)
        self._admit(SLOT_A, self.mandate_a, "REVOKED", 2,
                    self._view().head_hash(SLOT_A))
        result = self._attempt("a", "e4")
        self.assertFalse(result["authorized"])
        # Compiled mandate fit still passes: the refusal is authority
        # standing, not a malformed action.
        self.assertTrue(result["preflight_allowed"])

    def test_4_b_continues_under_same_regime_no_new_trust_root(self):
        self._admit(SLOT_A, self.mandate_a, "ACTIVE", 1, None)
        self._admit(SLOT_A, self.mandate_a, "REVOKED", 2,
                    self._view().head_hash(SLOT_A))
        self._admit(SLOT_B, self.mandate_b, "ACTIVE", 1, None)
        view = self._view()
        self.assertEqual(view.current_owner(SLOT_B)["public_key"], self.owner_pub)
        self.assertEqual(view.succession_sequence(SLOT_B), 0)
        self.assertEqual(len(view.key_schedule(SLOT_B)), 1)
        for effect_id in ("e5", "e6"):
            result = self._attempt("b", effect_id)
            self.assertTrue(result["authorized"], result.get("reason_codes"))
            self.assertEqual(result["journal_execution_status"], "completed")
            self.assertTrue(result["marker_exists"])
        # A's slot is untouched by B's operation.
        self.assertEqual(view.status(SLOT_A, now=NOW), "REVOKED")
        self.assertEqual(view.head_sequence(SLOT_A), 2)

    def test_5_a_cannot_resume_by_fresh_replay_or_restart(self):
        self._admit(SLOT_A, self.mandate_a, "ACTIVE", 1, None)
        first = self._attempt("a", "e7")
        self.assertTrue(first["authorized"])
        self._admit(SLOT_A, self.mandate_a, "REVOKED", 2,
                    self._view().head_hash(SLOT_A))
        self._admit(SLOT_B, self.mandate_b, "ACTIVE", 1, None)
        self.assertTrue(self._attempt("b", "e8")["authorized"])
        # Fresh attempt by A.
        fresh = self._attempt("a", "e9")
        self.assertFalse(fresh["authorized"])
        self.assertIn("owner_standing_revoked", fresh["reason_codes"])
        # Replay of the pre-STOP payload with a fresh one-use path.
        replay = self._attempt("a", "e7")
        self.assertFalse(replay["authorized"])
        self.assertIn("owner_standing_revoked", replay["reason_codes"])
        self.assertFalse(replay["marker_exists"])
        # Restart: brand-new objects over the same durable files.
        restarted = self._attempt("a", "e10")
        self.assertFalse(restarted["authorized"])
        self.assertIn("owner_standing_revoked", restarted["reason_codes"])
        view = self._view()
        self.assertEqual(view.head_sequence(SLOT_A), 2)
        self.assertEqual(view.head_sequence(SLOT_B), 1)

    def test_6_history_intact_and_verifiable_without_currency(self):
        view = self._view()
        active = issue_mandate_authorization(
            slot_id=SLOT_A, owner_id=OWNER_ID, mandate=self.mandate_a,
            state="ACTIVE", sequence=1, predecessor_hash=None,
            issued_at=NOW, expires_at=NOW + LONG, key=self.owner_key,
        )
        view.admit(active, self.mandate_a, now=NOW)
        self.assertTrue(self._attempt("a", "e11")["authorized"])
        self._admit(SLOT_A, self.mandate_a, "REVOKED", 2, view.head_hash(SLOT_A))
        self._admit(SLOT_B, self.mandate_b, "ACTIVE", 1, None)
        self.assertTrue(self._attempt("b", "e12")["authorized"])
        fresh = self._view()
        assessment = fresh.assess(active, self.mandate_a, now=NOW)
        self.assertTrue(assessment["verified"])
        self.assertFalse(assessment["current"])
        self.assertEqual(fresh.status(SLOT_A, now=NOW), "REVOKED")
        valid, _ = verify_olp_signature(active)
        self.assertTrue(valid)
        state = self._ledger().read_state()
        # Per-slot re-derivation: the STOP lived on slot A; slot B's
        # admissions must not leak into B-era verdicts.
        slot_of = {}
        for attempt in state["attempts"]:
            label = attempt["attempt_label"]
            agent = label.split("-")[1]
            slot_of[label] = SLOT_A if agent == "a" else SLOT_B
        by_slot = {SLOT_A: [], SLOT_B: []}
        for entry in self.admissions:
            by_slot[entry["slot"]].append(entry)
        for attempt in state["attempts"]:
            label = attempt["attempt_label"]
            item = derive_path_verdict(attempt, by_slot[slot_of[label]])
            stored = attempt.get("path_verdict_v1")
            if stored is None:
                # Observation-time verdict covers refusals only; committed
                # attempts re-derive to verdict None (PRE_STOP_COMMIT /
                # NO_STOP_ADMITTED ordering is the appraiser's classification).
                self.assertIsNone(item["verdict"], label)
            else:
                self.assertEqual(stored.get("verdict"), item["verdict"], label)
                self.assertEqual(stored.get("ordering"), item["ordering"], label)

    def test_7_receipt_distinctions_hold_per_attempt(self):
        self._admit(SLOT_A, self.mandate_a, "ACTIVE", 1, None)
        accepted = self._attempt("a", "e13")
        self._admit(SLOT_A, self.mandate_a, "REVOKED", 2,
                    self._view().head_hash(SLOT_A))
        refused = self._attempt("a", "e14")
        state = self._ledger().read_state()
        by_label = {a["attempt_label"]: a for a in state["attempts"]}
        acc = by_label[accepted["attempt_id"]]
        ref = by_label[refused["attempt_id"]]
        for attempt, expected_standing in ((acc, "ACTIVE"), (ref, "REVOKED")):
            final = attempt["standing_final_check_v1"]
            self.assertEqual(final["standing"], expected_standing)
            self.assertEqual(final["allowed"], expected_standing == "ACTIVE")
            self.assertEqual(attempt["result"] == "AUTHORIZED",
                             expected_standing == "ACTIVE")
            self.assertEqual(attempt["execution_status"] == "completed",
                             expected_standing == "ACTIVE")


if __name__ == "__main__":
    unittest.main()
