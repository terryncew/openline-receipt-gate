"""Discriminating composition test: portable owner-STOP at the Receipt Gate.

Uses the EXISTING Receipt Gate path (evaluate_request -> VerifiedCommitLedger)
with the stop-standing adapter installed. This is NOT the seven-path suite;
it is the frozen A/B/C/D shape from KILL-SWITCH-RECEIPT-INTEGRATION-001.

A. ACTIVE - owner authority current; worker presents valid action/mandate
   context; the protected consequence commits through execute_once; the
   effect is independently observed.
B. STOP - owner changes current standing through the existing owner-controlled
   path (admit a superseding owner-signed REVOKED record); old worker
   context/credentials left technically intact; the final consequence attempt
   reaches the existing boundary and is refused; effect ABSENCE is
   independently established (journal not_started + independent state query
   of the effect target), never inferred from REFUSE alone.
C. RESTART - receiver process restarts (new view + ledger over the same
   durable files); old authority remains non-current; the same consequence
   is still refused.
D. EVIDENCE - historical receipts remain authentic and unmodified (verified
   vs current split holds); standing shows revoked; no historical evidence
   rewritten; effect presence/absence recorded separately from the decision;
   one PRE_STOP_COMMIT case (effect commits before STOP_EFFECTIVE is
   admitted) honestly classified; every verdict re-derivable by an
   independent appraiser from the journal + admission history.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.adapters import TrustStore
from olp_gate.crypto import public_key_hex, sha256_hex, verify_olp_signature
from olp_gate._durable_heads import DurableHeadStore
from olp_gate.demo import _agent_receipt, _source_hash
from olp_gate.evidence import issue_outcome_receipt
from olp_gate.gateway import evaluate_request, verify_decision_receipt
from olp_gate.mandate_owner import (
    MandateOwnerView,
    issue_mandate_authorization,
)
from olp_gate.policy import PolicySpec
from olp_gate.session import SessionLedger
from olp_gate.stop_standing import (
    derive_path_verdicts,
    owner_mandate_stop_check,
)
from olp_gate.verified_commit import (
    VerifiedCommitLedger,
    settings_hash,
)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


SLOT_ID = "payments/default"
OWNER_ID = "alice"


def _mandate(now: datetime) -> dict:
    return {
        "profile": "principal_mandate/v1",
        "mandate_id": "payments-mandate",
        "principal_id": OWNER_ID,
        "agent_id": "payments-agent",
        "purpose": "customer payments",
        "allowed_action_types": ["authorize_payment"],
        "allowed_targets": ["payments://ledger"],
        "allowed_disclosure_classes": [],
        "forbidden_disclosure_classes": [],
        "max_settlement_cents": 0,
        "max_payment_cents": 10_000,
        "delegation_allowed": False,
        "expires_at": _iso(now + timedelta(days=1)),
        "version": "v1",
    }


class StopStandingComposition(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="stop-standing-")
        self.root = Path(self.temp.name)
        self.now = datetime.now(timezone.utc)

        self.owner_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("a1" * 32))
        self.gate_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("a2" * 32))
        self.source_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("a3" * 32))
        self.witness_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("a4" * 32))
        self.source_method = "did:example:stop-standing-source#key-1"
        self.store = TrustStore.from_mapping(
            {
                "keys": {
                    self.source_method: {
                        "public_key": public_key_hex(self.source_key),
                        "roles": ["source"],
                        "independence": "operator",
                        "controller": "stop-standing-source",
                    },
                    public_key_hex(self.witness_key): {
                        "public_key": public_key_hex(self.witness_key),
                        "roles": ["outcome"],
                        "independence": "receiver",
                        "controller": "stop-standing-receiver",
                    },
                }
            }
        )

        # Owner-controlled standing, durable across process restarts.
        self.heads_path = str(self.root / "owner_heads.json")
        DurableHeadStore.create(
            self.heads_path,
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
            durable_path=self.heads_path,
        )
        self.mandate = _mandate(self.now)
        active = issue_mandate_authorization(
            slot_id=SLOT_ID,
            owner_id=OWNER_ID,
            mandate=self.mandate,
            state="ACTIVE",
            sequence=1,
            predecessor_hash=None,
            issued_at=self.now,
            expires_at=self.now + timedelta(hours=1),
            key=self.owner_key,
        )
        self.active_admission = self.view.admit(active, self.mandate, now=self.now)
        self.active_record = active
        self.admissions = [dict(self.active_admission)]

        self.ledger = VerifiedCommitLedger(self.root / "commit_ledger.json")
        self.effects = self.root / "effects"
        self.effects.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    # -- helpers ---------------------------------------------------------

    def _issue(self, case: str, *, tool="filesystem.write",
               target="artifact://approved.json", settings=None):
        """Issue a signed COMMIT decision receipt through the existing path."""
        now = self.now
        artifact = self.root / f"{case}.json"
        artifact.write_text('{"approved":true,"status":"complete"}\n', encoding="utf-8")
        artifact_hash = sha256_hex(artifact.read_bytes())
        run_id = f"run-{case}"
        source = _agent_receipt(
            key=self.source_key,
            method=self.source_method,
            chain_id=run_id,
            session_id=f"session-{case}",
            action_id=f"action-{case}",
            action_type="tool_call",
            response_hash=artifact_hash,
            timestamp=_iso(now),
        )
        source_hash = _source_hash(source)
        session = SessionLedger(self.root / f"{case}-sessions.json")
        binding = session.issue_challenge(
            run_id=run_id,
            session_id=f"session-{case}",
            expected_source_hash=source_hash,
        )
        outcome = issue_outcome_receipt(
            source_receipt_hash=source_hash,
            outcome_status="pass",
            harmful=False,
            evidence_hash=artifact_hash,
            witness_id="stop-standing-receiver",
            rollback_supported=True,
            key=self.witness_key,
        )
        if settings is None:
            settings = {
                "content_sha256": sha256_hex(b"approved payload"),
                "mode": "create_new",
            }
        action = {
            "tool": tool,
            "target": target,
            "settings": settings,
            "run_id": run_id,
            "capsule_hash": sha256_hex(f"capsule:{case}".encode("utf-8")),
            "evidence_hashes": [artifact_hash],
        }
        policy = PolicySpec.from_mapping(
            {
                "policy_id": "stop-standing.receiver-policy",
                "version": "1",
                "require_declared_coverage": True,
                "require_outcome_witness": True,
                "required_evidence_ids": ["result"],
                "evidence_assertions": [
                    {
                        "evidence_id": "result",
                        "path": "approved",
                        "op": "equals",
                        "value": True,
                    }
                ],
                "metadata": {
                    "verified_commit": {
                        "required": True,
                        "tool": action["tool"],
                        "target": action["target"],
                        "settings_hash": settings_hash(settings),
                        "run_id": run_id,
                        "capsule_hash": action["capsule_hash"],
                        "evidence_hashes": action["evidence_hashes"],
                        "max_ttl_seconds": 120,
                    }
                },
            }
        )
        code = sha256_hex(f"one-use:{case}".encode("utf-8"))[:64]
        request = {
            "schema": "openline.proof_to_policy.request.v0.2",
            "request_id": f"request-{case}",
            "action_type": "tool_call",
            "claim": "The exact receiver-approved action may execute once.",
            "source_receipts": [source],
            "binding": binding,
            "evidence": [
                {
                    "id": "result",
                    "artifact_path": artifact.name,
                    "content_hash": artifact_hash,
                    "source_commitment_path": "credentialSubject.outcome.response_hash",
                }
            ],
            "outcome_receipt": outcome,
            "commit_request": {
                **action,
                "policy_hash": policy.policy_hash,
                "expires_at": _iso(now + timedelta(seconds=60)),
                "one_use_code": code,
            },
        }
        receipt = evaluate_request(
            request,
            policy=policy,
            trust_store=self.store,
            signing_key=self.gate_key,
            issuer_id="stop-standing-test-gate",
            decision_path=self.root / f"{case}-decisions.jsonl",
            session_ledger=session,
            base_dir=self.root,
            now=now,
        )
        action["policy_hash"] = policy.policy_hash
        return receipt, action, code

    def _effect(self, case: str):
        """The protected consequence: an independently observable effect."""
        marker = self.effects / f"{case}.json"

        def executor():
            marker.write_text(
                json.dumps({"case": case, "committed": True}, sort_keys=True),
                encoding="utf-8",
            )
            return {"effect": case}

        return marker, executor

    def _check(self):
        return owner_mandate_stop_check(self.view, SLOT_ID, now=self.now)

    def _admit_owner_stop(self):
        """Owner changes current standing via the existing owner-controlled path."""
        stop = issue_mandate_authorization(
            slot_id=SLOT_ID,
            owner_id=OWNER_ID,
            mandate=self.mandate,
            state="REVOKED",
            sequence=2,
            predecessor_hash=self.view.head_hash(SLOT_ID),
            issued_at=self.now,
            expires_at=self.now + timedelta(hours=1),
            key=self.owner_key,
        )
        admission = self.view.admit(stop, self.mandate, now=self.now)
        self.admissions.append(dict(admission))
        return admission

    # -- A. ACTIVE ----------------------------------------------------------

    def test_a_active_commits_and_effect_independently_observed(self):
        receipt, action, code = self._issue("a-active")
        marker, executor = self._effect("a-active")

        result = self.ledger.execute_once(
            receipt,
            action,
            one_use_code=code,
            trusted_gate_keys=[public_key_hex(self.gate_key)],
            executor=executor,
            now=self.now,
            attempt_label="a-active",
            final_authority_check=self._check(),
        )

        self.assertTrue(result["authorized"])
        self.assertEqual(result["execution_status"], "completed")
        # Effect independently observed: the marker exists on the effect
        # target, read directly, not via the ledger.
        observed = json.loads(marker.read_text(encoding="utf-8"))
        self.assertEqual(observed, {"case": "a-active", "committed": True})

        state = self.ledger.read_state()
        attempt = state["attempts"][0]
        self.assertEqual(attempt["commit_seq"], 1)
        self.assertEqual(attempt["result"], "AUTHORIZED")
        final = attempt["standing_final_check_v1"]
        self.assertTrue(final["installed"])
        self.assertTrue(final["allowed"])
        self.assertEqual(final["standing"], "ACTIVE")
        self.assertEqual(final["head_seq"], 1)
        self.assertIsNone(attempt["stop_effective_seq"])
        self.assertIsNone(attempt["path_verdict_v1"])

    # -- B. STOP ------------------------------------------------------------

    def test_b_owner_stop_refuses_and_absence_independently_established(self):
        # Worker holds valid pre-STOP context: receipt issued while ACTIVE.
        receipt, action, code = self._issue("b-stop")
        marker, executor = self._effect("b-stop")

        # Owner changes current standing through the existing owner-controlled
        # path. Old worker context/credentials are left technically intact.
        stop_admission = self._admit_owner_stop()
        self.assertEqual(stop_admission["state"], "REVOKED")
        self.assertEqual(stop_admission["sequence"], 2)
        self.assertEqual(self.view.status(SLOT_ID, now=self.now), "REVOKED")

        result = self.ledger.execute_once(
            receipt,
            action,
            one_use_code=code,
            trusted_gate_keys=[public_key_hex(self.gate_key)],
            executor=executor,
            now=self.now,
            attempt_label="b-stop",
            final_authority_check=self._check(),
        )

        self.assertFalse(result["authorized"])
        self.assertIn("owner_standing_revoked", result["reason_codes"])
        # Effect ABSENCE independently established: the journal shows
        # not_started AND the effect target has no marker.
        state = self.ledger.read_state()
        attempt = state["attempts"][0]
        self.assertEqual(attempt["result"], "BLOCKED")
        self.assertEqual(attempt["execution_status"], "not_started")
        self.assertIsNone(attempt["tool_result_hash"])
        self.assertFalse(marker.exists())
        # STOP_EFFECTIVE binding: terminal head sequence observed under lock.
        self.assertEqual(attempt["commit_seq"], 1)
        self.assertEqual(attempt["stop_effective_seq"], 2)
        self.assertEqual(
            attempt["path_verdict_v1"],
            {"verdict": "STOPPED", "ordering": "STOP_FIRST", "stop_effective_seq": 2},
        )
        # Independent appraiser re-derives the same verdict from the journal
        # plus the admission history, without trusting the live system.
        derived = derive_path_verdicts(state, self.admissions)
        self.assertEqual(len(derived), 1)
        self.assertEqual(derived[0]["verdict"], "STOPPED")
        self.assertEqual(derived[0]["ordering"], "STOP_FIRST")
        self.assertEqual(derived[0]["stop_effective_seq"], 2)

    # -- C. RESTART ---------------------------------------------------------

    def test_c_restart_does_not_restore_old_authority(self):
        receipt, action, code = self._issue("c-restart")
        marker, _executor = self._effect("c-restart")
        self._admit_owner_stop()

        # Restart the receiver process: brand-new view and ledger objects over
        # the same durable files.
        restarted_view = MandateOwnerView(
            {SLOT_ID: {"owner_id": OWNER_ID, "public_key": public_key_hex(self.owner_key)}},
            durable_path=str(self.root / "owner_heads.json"),
        )
        restarted_ledger = VerifiedCommitLedger(self.root / "commit_ledger.json")

        self.assertEqual(restarted_view.status(SLOT_ID, now=self.now), "REVOKED")

        result = restarted_ledger.execute_once(
            receipt,
            action,
            one_use_code=code,
            trusted_gate_keys=[public_key_hex(self.gate_key)],
            executor=_executor,
            now=self.now,
            attempt_label="c-restart",
            final_authority_check=owner_mandate_stop_check(
                restarted_view, SLOT_ID, now=self.now
            ),
        )

        self.assertFalse(result["authorized"])
        self.assertIn("owner_standing_revoked", result["reason_codes"])
        self.assertFalse(marker.exists())
        state = restarted_ledger.read_state()
        attempt = state["attempts"][0]
        self.assertEqual(attempt["execution_status"], "not_started")
        self.assertEqual(attempt["path_verdict_v1"]["verdict"], "STOPPED")

    # -- D. EVIDENCE --------------------------------------------------------

    def test_d_evidence_receipts_unmodified_and_pre_stop_commit_classified(self):
        # Sub-case 1: effect commits while ACTIVE (pre-STOP).
        receipt_pre, action_pre, code_pre = self._issue("d-pre")
        marker_pre, executor_pre = self._effect("d-pre")
        first = self.ledger.execute_once(
            receipt_pre,
            action_pre,
            one_use_code=code_pre,
            trusted_gate_keys=[public_key_hex(self.gate_key)],
            executor=executor_pre,
            now=self.now,
            attempt_label="d-pre",
            final_authority_check=self._check(),
        )
        self.assertTrue(first["authorized"])
        pre_snapshot = json.loads(json.dumps(self.ledger.read_state()["attempts"][0]))

        # Owner STOP admitted after the effect committed.
        self._admit_owner_stop()

        # Sub-case 2: post-STOP attempt refused.
        receipt_post, action_post, code_post = self._issue("d-post")
        marker_post, executor_post = self._effect("d-post")
        refused = self.ledger.execute_once(
            receipt_post,
            action_post,
            one_use_code=code_post,
            trusted_gate_keys=[public_key_hex(self.gate_key)],
            executor=executor_post,
            now=self.now,
            attempt_label="d-post",
            final_authority_check=self._check(),
        )
        self.assertFalse(refused["authorized"])
        self.assertFalse(marker_post.exists())

        state = self.ledger.read_state()

        # Historical receipts authentic and unmodified: the pre-STOP ACTIVE
        # authorization still verifies (authentic) but is not current.
        assessment = self.view.assess(self.active_record, self.mandate, now=self.now)
        self.assertTrue(assessment["verified"])
        self.assertFalse(assessment["current"])
        valid, _ = verify_olp_signature(self.active_record)
        self.assertTrue(valid)
        # Standing shows revoked.
        self.assertEqual(self.view.status(SLOT_ID, now=self.now), "REVOKED")
        # No historical evidence rewritten: the first attempt record is
        # byte-identical to its pre-STOP snapshot.
        self.assertEqual(state["attempts"][0], pre_snapshot)
        # Effect presence/absence recorded separately from the decision.
        self.assertEqual(state["attempts"][0]["execution_status"], "completed")
        self.assertIsNotNone(state["attempts"][0]["tool_result_hash"])
        self.assertTrue(marker_pre.exists())
        self.assertEqual(state["attempts"][1]["execution_status"], "not_started")
        self.assertIsNone(state["attempts"][1]["tool_result_hash"])
        self.assertFalse(marker_post.exists())
        # Monotonic commit sequence binding across attempts.
        self.assertEqual(
            [a["commit_seq"] for a in state["attempts"]], [1, 2]
        )

        # Independent appraiser re-derivation: the pre-STOP effect is honestly
        # classified PRE_STOP_COMMIT (not STOPPED, not ESCAPED); the refused
        # attempt is STOPPED.
        derived = derive_path_verdicts(state, self.admissions)
        self.assertEqual(len(derived), 2)
        pre, post = derived
        self.assertIsNone(pre["verdict"])
        self.assertEqual(pre["ordering"], "PRE_STOP_COMMIT")
        self.assertEqual(pre["stop_effective_seq"], 2)
        self.assertEqual(post["verdict"], "STOPPED")
        self.assertEqual(post["ordering"], "STOP_FIRST")
        # The stored observation-time verdict agrees with re-derivation.
        self.assertEqual(
            state["attempts"][1]["path_verdict_v1"]["verdict"], post["verdict"]
        )
        self.assertEqual(
            state["attempts"][1]["path_verdict_v1"]["ordering"], post["ordering"]
        )

    def test_decision_receipts_still_verify_after_stop(self):
        """Authentic vs current: the gate's signed receipts stay verifiable."""
        receipt, _action, _code = self._issue("d-receipt")
        self._admit_owner_stop()
        check = verify_decision_receipt(receipt, [public_key_hex(self.gate_key)])
        self.assertEqual(check.get("errors"), [])

    # -- mandate_gate closure ----------------------------------------------

    def test_mandated_path_consults_owner_view_at_finalize(self):
        """execute_mandated_once refuses after owner STOP even though the
        compiled mandate fit still passes: compiled authorization is
        non-authoritative at finalize time."""
        from olp_gate.mandate import (
            MandateSpec,
            compile_verified_commit_settings,
            validate_effect,
        )
        from olp_gate.mandate_gate import execute_mandated_once

        mandate = _mandate(self.now)
        # The owner slot mandate must name the slot owner as principal.
        mandate["allowed_action_types"] = ["authorize_payment"]
        mandate["allowed_targets"] = ["vendor"]
        spec = MandateSpec.from_mapping(mandate)
        effect = validate_effect(
            {
                "profile": "principal_effect/v1",
                "effect_id": "effect-1",
                "mandate_id": mandate["mandate_id"],
                "principal_id": OWNER_ID,
                "agent_id": "payments-agent",
                "purpose": "customer payments",
                "action_type": "authorize_payment",
                "target": "vendor",
                "disclosures": [],
                "value_cents": 60,
                "delegatee": None,
                "producer_model": "test",
            }
        )
        settings = compile_verified_commit_settings(spec, effect, now=self.now)

        def attempt(case: str):
            receipt, action, code = self._issue(
                case,
                tool="authorize_payment",
                target="vendor",
                settings=settings,
            )
            marker, executor = self._effect(case)
            result = execute_mandated_once(
                self.ledger,
                receipt,
                action,
                mandate=spec,
                one_use_code=code,
                trusted_gate_keys=[public_key_hex(self.gate_key)],
                executor=executor,
                now=self.now,
                attempt_label=case,
                mandate_owner_view=self.view,
                mandate_slot_id=SLOT_ID,
            )
            return result, marker

        # ACTIVE: the mandated consequence commits.
        result, marker = attempt("m-active")
        self.assertTrue(result["authorized"])
        self.assertTrue(marker.exists())

        # Owner STOP: the same compiled mandate fit still passes, but the
        # final-authority owner check refuses.
        self._admit_owner_stop()
        result, marker = attempt("m-stopped")
        self.assertFalse(result["authorized"])
        self.assertIn("owner_standing_revoked", result["reason_codes"])
        self.assertFalse(marker.exists())

    def test_mandated_path_without_owner_view_keeps_legacy_behavior(self):
        """Without an owner view, execute_mandated_once behaves as before."""
        from olp_gate.mandate import (
            MandateSpec,
            compile_verified_commit_settings,
            validate_effect,
        )
        from olp_gate.mandate_gate import execute_mandated_once

        mandate = _mandate(self.now)
        mandate["allowed_action_types"] = ["authorize_payment"]
        mandate["allowed_targets"] = ["vendor"]
        spec = MandateSpec.from_mapping(mandate)
        effect = validate_effect(
            {
                "profile": "principal_effect/v1",
                "effect_id": "effect-2",
                "mandate_id": mandate["mandate_id"],
                "principal_id": OWNER_ID,
                "agent_id": "payments-agent",
                "purpose": "customer payments",
                "action_type": "authorize_payment",
                "target": "vendor",
                "disclosures": [],
                "value_cents": 60,
                "delegatee": None,
                "producer_model": "test",
            }
        )
        settings = compile_verified_commit_settings(spec, effect, now=self.now)
        receipt, action, code = self._issue(
            "m-legacy", tool="authorize_payment", target="vendor", settings=settings
        )
        marker, executor = self._effect("m-legacy")
        result = execute_mandated_once(
            self.ledger,
            receipt,
            action,
            mandate=spec,
            one_use_code=code,
            trusted_gate_keys=[public_key_hex(self.gate_key)],
            executor=executor,
            now=self.now,
            attempt_label="m-legacy",
        )
        self.assertTrue(result["authorized"])
        self.assertTrue(marker.exists())
        attempt = self.ledger.read_state()["attempts"][0]
        self.assertNotIn("standing_final_check_v1", attempt)
