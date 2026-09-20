"""PLATFORM-EXIT-KILL-002 driver.

Owns the owner key O (issues all owner-signed records), admits them to the
shared durable receiver state, spawns per-phase worker agent subprocesses,
and freezes per-case evidence. Harness only; zero product-code changes.

Case order (preregistered): 1 A operates -> 2 owner STOPs A -> 3 A cannot
continue (+ restart) -> 4 B continues under the same regime -> 5 A stays
stopped (fresh + replay) -> 6 appraised separately from frozen evidence.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[3]
HARNESS = Path(__file__).resolve().parent
for _p in (str(REPO), str(HARNESS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import gate_path as gp  # noqa: E402
from olp_gate._durable_heads import DurableHeadStore  # noqa: E402
from olp_gate.crypto import public_key_hex, verify_olp_signature  # noqa: E402
from olp_gate.mandate_owner import (  # noqa: E402
    MandateOwnerView,
    issue_mandate_authorization,
)
from olp_gate.verified_commit import VerifiedCommitLedger  # noqa: E402

EXP = REPO / "experiments" / "platform-exit-kill-002"
WORKER = HARNESS / "worker_agent.py"
OWNER_ID = "owner"
SLOT_A = "agent-a/platform-exit-job"
SLOT_B = "agent-b/platform-exit-job"
MANDATE_ID = "platform-exit-job"


class CaseFailure(AssertionError):
    pass


class Driver:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.run_now = datetime.now(timezone.utc)
        self.state_dir = run_dir / "receiver_state"
        self.issued_dir = run_dir / "issued"
        self.snap_dir = run_dir / "snapshots"
        self.outcome_dir = run_dir / "worker_outcomes"
        self.plan_dir = run_dir / "plans"
        self.key_dir = run_dir / "keys_private"
        self.log_path = run_dir / "run_log.jsonl"
        for d in (
            self.state_dir,
            self.issued_dir,
            self.snap_dir,
            self.outcome_dir,
            self.plan_dir,
            self.key_dir,
            run_dir / "logs",
        ):
            d.mkdir(parents=True, exist_ok=True)

        # Key material. O = owner (kill authority). gate/witness = receiver
        # infrastructure (shared scaffolding, disclosed in the prereg).
        # source_a/source_b = per-agent claim keys. K_a/K_b = per-agent
        # worker attestation keys; never shared between agents.
        self.keys = {
            name: Ed25519PrivateKey.generate()
            for name in (
                "owner",
                "gate",
                "witness",
                "source_a",
                "source_b",
                "worker_a",
                "worker_b",
            )
        }
        self.pubkeys = {n: public_key_hex(k) for n, k in self.keys.items()}
        (run_dir / "keys.json").write_text(
            json.dumps(self.pubkeys, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        for name, key in self.keys.items():
            gp.write_private_key(self.key_dir / f"{name}.hex", key)

        self.mandate_a = gp.build_mandate("agent-a", MANDATE_ID)
        self.mandate_b = gp.build_mandate("agent-b", MANDATE_ID)
        (run_dir / "mandates.json").write_text(
            json.dumps(
                {"mandate_a": self.mandate_a, "mandate_b": self.mandate_b},
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.slots = {
            SLOT_A: {"owner_id": OWNER_ID, "public_key": self.pubkeys["owner"]},
            SLOT_B: {"owner_id": OWNER_ID, "public_key": self.pubkeys["owner"]},
        }
        (run_dir / "slots.json").write_text(
            json.dumps(self.slots, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.heads_path = self.state_dir / "owner_heads.json"
        DurableHeadStore.create(
            str(self.heads_path),
            {"view": "mandate_owner/v1", "slots": self.slots},
        )
        self.view = MandateOwnerView(self.slots, durable_path=str(self.heads_path))
        self.ledger = VerifiedCommitLedger(self.state_dir / "commit_ledger.json")
        self.admissions: list[dict] = []
        self.case_results: list[dict] = []
        self.log("driver_init", baseline="95c1ecf", run_now=gp.iso(self.run_now))

    # -- logging --------------------------------------------------------

    def log(self, event: str, **fields) -> None:
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {"t": gp.iso(datetime.now(timezone.utc)), "event": event, **fields},
                    sort_keys=True,
                )
                + "\n"
            )

    def _freeze_json(self, path: Path, value: dict) -> None:
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    # -- owner issuance -------------------------------------------------

    def admit_owner_record(
        self,
        name: str,
        slot: str,
        mandate: dict,
        state: str,
        sequence: int,
        predecessor_hash: str | None,
    ) -> dict:
        record = issue_mandate_authorization(
            slot_id=slot,
            owner_id=OWNER_ID,
            mandate=mandate,
            state=state,
            sequence=sequence,
            predecessor_hash=predecessor_hash,
            issued_at=self.run_now,
            expires_at=self.run_now + timedelta(days=3650),
            key=self.keys["owner"],
        )
        valid, reason = verify_olp_signature(record)
        if valid is not True:
            raise CaseFailure(f"issued record failed self-verification: {reason}")
        self._freeze_json(self.issued_dir / f"{name}.json", record)
        admission = self.view.admit(record, mandate, now=self.run_now)
        entry = {
            "slot": slot,
            "state": admission["state"],
            "sequence": admission["sequence"],
            "head_hash": admission["head_hash"],
            "mandate_hash": admission["mandate_hash"],
            "payload_hash": record["payload_hash"],
            "signer": record["signature"]["public_key"],
        }
        self.admissions.append(entry)
        self.log("owner_admitted", name=name, **entry)
        return admission

    # -- evidence -------------------------------------------------------

    def snapshot(self, name: str) -> dict:
        ledger_state = self.ledger.read_state()
        snap = {
            "name": name,
            "attempts": ledger_state.get("attempts", []),
            "slot_status": {
                SLOT_A: self.view.status(SLOT_A, now=self.run_now),
                SLOT_B: self.view.status(SLOT_B, now=self.run_now),
            },
            "head_seq": {
                SLOT_A: self.view.head_sequence(SLOT_A),
                SLOT_B: self.view.head_sequence(SLOT_B),
            },
            "head_hash": {
                SLOT_A: self.view.head_hash(SLOT_A),
                SLOT_B: self.view.head_hash(SLOT_B),
            },
            "owner_a": self.view.current_owner(SLOT_A),
            "owner_b": self.view.current_owner(SLOT_B),
            "succession_seq": {
                SLOT_A: self.view.succession_sequence(SLOT_A),
                SLOT_B: self.view.succession_sequence(SLOT_B),
            },
            "schedule_len": {
                SLOT_A: len(self.view.key_schedule(SLOT_A)),
                SLOT_B: len(self.view.key_schedule(SLOT_B)),
            },
        }
        self._freeze_json(self.snap_dir / f"snapshot_{name}.json", snap)
        self.log("snapshot", name=name)
        return snap

    def record_case(self, case: str, expectation: str, observed: dict) -> None:
        entry = {"case": case, "expectation": expectation, **observed}
        self.case_results.append(entry)
        self.log("case_result", **entry)

    # -- workers --------------------------------------------------------

    def run_worker(self, agent: str, plan_name: str, plan: list[dict]) -> list[dict]:
        """Spawn one worker agent subprocess for a plan; return its outcomes."""
        plan_path = self.plan_dir / f"{plan_name}.json"
        out_path = self.outcome_dir / f"{plan_name}.json"
        self._freeze_json(plan_path, {"plan": plan})
        key_name = {"a": "worker_a", "b": "worker_b"}[agent]
        source_name = {"a": "source_a", "b": "source_b"}[agent]
        mandate_path = self.run_dir / f"mandate_{agent}.json"
        self._freeze_json(
            mandate_path,
            self.mandate_a if agent == "a" else self.mandate_b,
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO)
        stderr_path = self.run_dir / "logs" / f"worker_{plan_name}.stderr.log"
        with open(stderr_path, "ab") as stderr_fh:
            proc = subprocess.run(
                [
                    sys.executable,
                    str(WORKER),
                    "--agent", agent,
                    "--state-dir", str(self.state_dir),
                    "--agent-key-file", str(self.key_dir / f"{key_name}.hex"),
                    "--mandate-file", str(mandate_path),
                    "--slot", SLOT_A if agent == "a" else SLOT_B,
                    "--gate-key-file", str(self.key_dir / "gate.hex"),
                    "--witness-key-file", str(self.key_dir / "witness.hex"),
                    "--source-key-file", str(self.key_dir / f"{source_name}.hex"),
                    "--slots-file", str(self.run_dir / "slots.json"),
                    "--owner-pubkey", self.pubkeys["owner"],
                    "--out", str(out_path),
                    "--plan", str(plan_path),
                    "--run-now", gp.iso(self.run_now),
                ],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=stderr_fh,
                timeout=600,
                check=False,
            )
        if proc.returncode != 0:
            raise CaseFailure(
                f"worker {plan_name} exited {proc.returncode}; see {stderr_path}"
            )
        if not out_path.exists():
            raise CaseFailure(f"worker {plan_name} produced no outcome file")
        outcomes = json.loads(out_path.read_text(encoding="utf-8"))["outcomes"]
        self.log(
            "worker_completed",
            plan=plan_name,
            agent=agent,
            outcomes=len(outcomes),
        )
        return outcomes

    # -- case assertions ------------------------------------------------

    @staticmethod
    def _expect(cond: bool, message: str) -> None:
        if not cond:
            raise CaseFailure(message)

    def _assert_accepted(self, outcome: dict) -> None:
        self._expect(outcome.get("worker_error") is None,
                     f"{outcome['attempt_id']}: worker_error {outcome.get('worker_error')}")
        self._expect(outcome.get("authorized") is True,
                     f"{outcome['attempt_id']}: not authorized: {outcome.get('reason_codes')}")
        self._expect(outcome.get("journal_execution_status") == "completed",
                     f"{outcome['attempt_id']}: execution_status {outcome.get('journal_execution_status')}")
        self._expect(outcome.get("marker_exists") is True,
                     f"{outcome['attempt_id']}: no effect marker")
        check = outcome.get("standing_final_check") or {}
        self._expect(check.get("allowed") is True and check.get("standing") == "ACTIVE",
                     f"{outcome['attempt_id']}: final check {check}")
        self._expect(outcome.get("preflight_allowed") is True,
                     f"{outcome['attempt_id']}: preflight failed {outcome.get('preflight_reasons')}")

    def _assert_refused_standing(self, outcome: dict, stop_seq: int) -> None:
        self._expect(outcome.get("worker_error") is None,
                     f"{outcome['attempt_id']}: worker_error {outcome.get('worker_error')}")
        self._expect(outcome.get("authorized") is False,
                     f"{outcome['attempt_id']}: unexpectedly authorized")
        self._expect("owner_standing_revoked" in (outcome.get("reason_codes") or []),
                     f"{outcome['attempt_id']}: wrong reasons {outcome.get('reason_codes')}")
        self._expect(outcome.get("journal_execution_status") == "not_started",
                     f"{outcome['attempt_id']}: execution_status {outcome.get('journal_execution_status')}")
        self._expect(outcome.get("marker_exists") is False,
                     f"{outcome['attempt_id']}: effect marker exists despite refusal")
        check = outcome.get("standing_final_check") or {}
        self._expect(check.get("allowed") is False and check.get("standing") == "REVOKED",
                     f"{outcome['attempt_id']}: final check {check}")
        verdict = outcome.get("path_verdict") or {}
        self._expect(verdict.get("verdict") == "STOPPED" and verdict.get("ordering") == "STOP_FIRST",
                     f"{outcome['attempt_id']}: path verdict {verdict}")
        self._expect(outcome.get("stop_effective_seq") == stop_seq,
                     f"{outcome['attempt_id']}: stop_effective_seq {outcome.get('stop_effective_seq')}")
        # Discrimination: compiled mandate fit still passes; the refusal is
        # standing, not format.
        self._expect(outcome.get("preflight_allowed") is True,
                     f"{outcome['attempt_id']}: preflight failed; refusal is not purely standing: "
                     f"{outcome.get('preflight_reasons')}")

    # -- cases ----------------------------------------------------------

    def case_1_a_operates(self) -> None:
        self.admit_owner_record(
            "a_active_seq1", SLOT_A, self.mandate_a,
            state="ACTIVE", sequence=1, predecessor_hash=None,
        )
        self._expect(self.view.status(SLOT_A, now=self.run_now) == "ACTIVE",
                     "slot A not ACTIVE after admission")
        outcomes = self.run_worker("a", "case1", [
            {"attempt_id": "c1-a1", "case": "case_1", "effect_id": "job-effect-1"},
            {"attempt_id": "c1-a2", "case": "case_1", "effect_id": "job-effect-2"},
        ])
        for outcome in outcomes:
            self._assert_accepted(outcome)
            self._expect(outcome["agent_id"] == "agent-a", "attribution mismatch")
        snap = self.snapshot("case1")
        self._expect([a["commit_seq"] for a in snap["attempts"]] == [1, 2],
                     "commit sequence wrong after case 1")
        self.record_case(
            "case_1_a_operates",
            "A performs consequential work under owner authority; receipts accepted and attributed to A",
            {"attempts": [o["attempt_id"] for o in outcomes],
             "commit_seqs": [o["commit_seq"] for o in outcomes],
             "slot_a_status": snap["slot_status"][SLOT_A]},
        )

    def case_2_owner_stops_a(self) -> None:
        before = self.view.status(SLOT_A, now=self.run_now)
        admission = self.admit_owner_record(
            "a_revoked_seq2", SLOT_A, self.mandate_a,
            state="REVOKED", sequence=2,
            predecessor_hash=self.view.head_hash(SLOT_A),
        )
        after = self.view.status(SLOT_A, now=self.run_now)
        self._expect(before == "ACTIVE" and after == "REVOKED",
                     f"standing transition wrong: {before} -> {after}")
        self._expect(admission["sequence"] == 2, "STOP head seq wrong")
        self._expect(
            admission["head_hash"] == self.view.head_hash(SLOT_A),
            "head hash mismatch after STOP",
        )
        snap = self.snapshot("case2")
        self.record_case(
            "case_2_owner_stops_a",
            "owner STOP revokes A's consequential authority; standing ACTIVE -> REVOKED",
            {"standing_before": before, "standing_after": after,
             "stop_effective_seq": 2,
             "stop_payload_hash": admission["head_hash"],
             "stop_signer_is_owner": True},
        )

    def case_3_a_cannot_continue(self) -> None:
        outcomes = self.run_worker("a", "case3", [
            {"attempt_id": "c3-a1", "case": "case_3", "effect_id": "job-effect-3"},
            {"attempt_id": "c3-a2", "case": "case_3", "effect_id": "job-effect-4"},
        ])
        # Restart: brand-new process, same A keys, fresh objects over the
        # same durable files.
        outcomes += self.run_worker("a", "case3_restart", [
            {"attempt_id": "c3-a3", "case": "case_3", "effect_id": "job-effect-5"},
        ])
        for outcome in outcomes:
            self._assert_refused_standing(outcome, stop_seq=2)
        snap = self.snapshot("case3")
        self._expect(snap["head_seq"][SLOT_A] == 2, "slot A head moved post-STOP")
        self._expect([a["commit_seq"] for a in snap["attempts"]] == [1, 2, 3, 4, 5],
                     "commit sequence wrong after case 3")
        self.record_case(
            "case_3_a_cannot_continue",
            "A refused on authority standing (not format); zero effects; restart does not restore",
            {"attempts": [o["attempt_id"] for o in outcomes],
             "refusal_reason": "owner_standing_revoked",
             "slot_a_head_seq": snap["head_seq"][SLOT_A]},
        )

    def case_4_b_continues(self) -> None:
        admission = self.admit_owner_record(
            "b_active_seq1", SLOT_B, self.mandate_b,
            state="ACTIVE", sequence=1, predecessor_hash=None,
        )
        self._expect(self.view.status(SLOT_B, now=self.run_now) == "ACTIVE",
                     "slot B not ACTIVE after admission")
        self._expect(self.view.current_owner(SLOT_B)["public_key"] == self.pubkeys["owner"],
                     "slot B owner is not O: fresh trust root invented")
        self._expect(self.view.succession_sequence(SLOT_B) == 0,
                     "succession event present on slot B")
        outcomes = self.run_worker("b", "case4", [
            {"attempt_id": "c4-b1", "case": "case_4", "effect_id": "job-effect-6"},
            {"attempt_id": "c4-b2", "case": "case_4", "effect_id": "job-effect-7"},
        ])
        for outcome in outcomes:
            self._assert_accepted(outcome)
            self._expect(outcome["agent_id"] == "agent-b", "attribution mismatch")
            check = outcome.get("standing_final_check") or {}
            self._expect(check.get("head_seq") == 1, "B attempt observed wrong head")
        snap = self.snapshot("case4")
        self._expect([a["commit_seq"] for a in snap["attempts"]] == [1, 2, 3, 4, 5, 6, 7],
                     "shared ordered history broken")
        self._expect(snap["slot_status"][SLOT_A] == "REVOKED", "slot A no longer REVOKED")
        self.record_case(
            "case_4_b_continues_under_same_regime",
            "B continues from the accepted checkpoint under the same owner-controlled regime; no new trust root",
            {"attempts": [o["attempt_id"] for o in outcomes],
             "commit_seqs": [o["commit_seq"] for o in outcomes],
             "slot_b_owner_is_O": True,
             "slot_a_still_revoked": True},
        )

    def case_5_a_stays_stopped(self) -> None:
        outcomes = self.run_worker("a", "case5", [
            {"attempt_id": "c5-a1", "case": "case_5", "effect_id": "job-effect-8"},
            # Replay of the exact pre-STOP effect payload (case 1, job-effect-1)
            # with a fresh attempt id -> fresh one-use code and fresh decision
            # receipt, so any refusal is standing, not replay protection.
            {"attempt_id": "c5-a2", "case": "case_5", "effect_id": "job-effect-1"},
        ])
        for outcome in outcomes:
            self._assert_refused_standing(outcome, stop_seq=2)
        snap = self.snapshot("case5")
        self._expect(snap["head_seq"][SLOT_A] == 2, "slot A head moved")
        self._expect(snap["head_seq"][SLOT_B] == 1, "slot B head moved")
        self._expect([a["commit_seq"] for a in snap["attempts"]]
                     == [1, 2, 3, 4, 5, 6, 7, 8, 9],
                     "commit sequence wrong after case 5")
        self._expect(snap["slot_status"][SLOT_B] == "ACTIVE",
                     "B's standing disturbed by A's attempts")
        self.record_case(
            "case_5_a_stays_stopped",
            "A cannot resume by fresh attempt, replay of pre-STOP evidence, or restart; B unaffected",
            {"attempts": [o["attempt_id"] for o in outcomes],
             "refusal_reason": "owner_standing_revoked"},
        )

    # -- run ------------------------------------------------------------

    def finalize(self, failure: str | None) -> None:
        self._freeze_json(self.run_dir / "admissions.jsonl",
                          {"admissions": self.admissions})
        self._freeze_json(self.run_dir / "case_results.json",
                          {"case_results": self.case_results,
                           "failure": failure})
        # Shred private key material: public keys + signed records + journals
        # are sufficient to reconstruct and re-verify everything.
        shutil.rmtree(self.key_dir, ignore_errors=True)
        self.log("driver_finalize", failure=bool(failure))

    def run(self) -> None:
        failure: str | None = None
        try:
            self.case_1_a_operates()
            self.case_2_owner_stops_a()
            self.case_3_a_cannot_continue()
            self.case_4_b_continues()
            self.case_5_a_stays_stopped()
            self.snapshot("final")
        except CaseFailure as exc:
            failure = f"CaseFailure: {exc}"
            self.log("case_failure", failure=failure,
                     traceback=traceback.format_exc(limit=8))
            try:
                self.snapshot("failure")
            except Exception:
                pass
        except Exception as exc:  # apparatus-level
            failure = f"ApparatusError: {type(exc).__name__}: {exc}"
            self.log("apparatus_error", failure=failure,
                     traceback=traceback.format_exc(limit=8))
        finally:
            self.finalize(failure)
        if failure:
            raise SystemExit(f"PLATFORM-EXIT-KILL-002 driver failed: {failure}")


def main() -> None:
    run_dir = EXP / "run"
    if run_dir.exists():
        raise SystemExit(f"refusing to overwrite existing run dir: {run_dir}")
    run_dir.mkdir(parents=True)
    Driver(run_dir).run()


if __name__ == "__main__":
    main()
