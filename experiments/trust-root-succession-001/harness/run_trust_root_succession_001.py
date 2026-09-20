"""TRUST-ROOT-SUCCESSION-001 driver.

Owns the owner keys (A current, B successor, C attacker, W non-owner
worker), issues all owner-signed records, delivers them to two independent
receiver worker processes, and freezes per-case evidence. Harness only.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[3]
EXP = REPO / "experiments" / "trust-root-succession-001"
WORKER = EXP / "harness" / "succession_worker.py"
sys.path.insert(0, str(REPO))

from olp_gate.crypto import public_key_hex, verify_olp_signature
from olp_gate.mandate_owner import (
    issue_mandate_authorization,
    issue_owner_trust_root_succession,
)

SLOT = "owner/default"
OWNER_ID = "owner"
RECEIVERS = ("r1", "r2")


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Driver:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.log_path = run_dir / "run_log.jsonl"
        self.issued_dir = run_dir / "issued"
        self.snap_dir = run_dir / "snapshots"
        for d in (self.issued_dir, self.snap_dir, run_dir / "logs"):
            d.mkdir(parents=True, exist_ok=True)
        # Owner key material. A = genesis owner, B = successor,
        # C = attacker, W = non-owner worker credential.
        self.keys = {
            name: Ed25519PrivateKey.generate() for name in ("A", "B", "C", "W")
        }
        self.pubkeys = {n: public_key_hex(k) for n, k in self.keys.items()}
        (run_dir / "keys.json").write_text(
            json.dumps(self.pubkeys, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self._own_pids: set[int] = set()
        # The mandate is pinned out-of-band before the experiment; owner and
        # receivers use the byte-identical mandate (mandate_hash is signed
        # into every authorization). Fixed far-future expiry so the mandate
        # itself never becomes the ceiling under test. principal_id must
        # equal the slot owner_id.
        self.mandate = {
            "profile": "principal_mandate/v1",
            "mandate_id": "trust-root-succession-mandate",
            "principal_id": OWNER_ID,
            "agent_id": "trust-root-succession-agent",
            "purpose": "trust root succession experiment",
            "allowed_action_types": ["authorize_payment"],
            "allowed_targets": ["payments://ledger"],
            "allowed_disclosure_classes": [],
            "forbidden_disclosure_classes": [],
            "max_settlement_cents": 0,
            "max_payment_cents": 10_000,
            "delegation_allowed": False,
            "expires_at": "2030-01-01T00:00:00Z",
            "version": "v1",
        }
        self.mandate_path = run_dir / "mandate.json"
        self.mandate_path.write_text(
            json.dumps(self.mandate, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.workers: dict[str, dict] = {}
        self.cmd_seq = 0
        self.case_results: list[dict] = []

    # -- logging ------------------------------------------------------

    def log(self, event: str, **fields) -> None:
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {"t": _iso(_now()), "event": event, **fields}, sort_keys=True
                )
                + "\n"
            )

    def record_case(self, case: str, expectation: str, observed: dict) -> None:
        entry = {"case": case, "expectation": expectation, **observed}
        self.case_results.append(entry)
        self.log("case_result", **entry)

    # -- owner issuance -------------------------------------------------

    def _freeze_issued(self, name: str, record: dict) -> dict:
        (self.issued_dir / f"{name}.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        valid, reason = verify_olp_signature(record)
        assert valid is True, f"issued record failed self-verification: {reason}"
        return record

    def issue_auth(
        self,
        name: str,
        signer: str,
        state: str,
        sequence: int,
        predecessor_hash: str | None,
    ) -> dict:
        now = _now()
        record = issue_mandate_authorization(
            slot_id=SLOT,
            owner_id=OWNER_ID,
            mandate=self.mandate,
            state=state,
            sequence=sequence,
            predecessor_hash=predecessor_hash,
            issued_at=now,
            expires_at=now + timedelta(days=3650),
            key=self.keys[signer],
        )
        self.log(
            "owner_issued_auth",
            name=name,
            signer=signer,
            state=state,
            sequence=sequence,
            payload_hash=record.get("payload_hash"),
        )
        return self._freeze_issued(name, record)

    def issue_succession(
        self,
        name: str,
        signer: str,
        successor: str,
        succession_sequence: int,
        predecessor_succession_hash: str | None,
        successor_owner_id: str = OWNER_ID,
    ) -> dict:
        now = _now()
        event = issue_owner_trust_root_succession(
            slot_id=SLOT,
            owner_id=OWNER_ID,
            successor_owner_id=successor_owner_id,
            successor_public_key=self.pubkeys[successor],
            succession_sequence=succession_sequence,
            predecessor_succession_hash=predecessor_succession_hash,
            issued_at=now,
            expires_at=now + timedelta(days=3650),
            key=self.keys[signer],
        )
        self.log(
            "owner_issued_succession",
            name=name,
            signer=signer,
            successor=successor,
            succession_sequence=succession_sequence,
            payload_hash=event.get("payload_hash"),
        )
        return self._freeze_issued(name, event)

    def deliver(self, record: dict, receiver: str, filename: str) -> None:
        inbox = self.run_dir / "inbox" / receiver
        inbox.mkdir(parents=True, exist_ok=True)
        (inbox / filename).write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.log("owner_delivered", receiver=receiver, file=filename)

    # -- workers -------------------------------------------------------

    def spawn(self, name: str, *, init: bool) -> None:
        # Fresh mailbox per spawn: a respawned worker must never reprocess
        # another lifetime's command files.
        for d in ("cmd", "res"):
            p = self.run_dir / d / name
            if p.exists():
                shutil.rmtree(p)
        self.sweep_stale_workers()
        state_dir = self.run_dir / "receivers" / name
        inbox_dir = self.run_dir / "inbox" / name
        cmd_dir = self.run_dir / "cmd" / name
        res_dir = self.run_dir / "res" / name
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO)
        stderr_path = self.run_dir / "logs" / f"worker_{name}.stderr.log"
        stderr_fh = open(stderr_path, "ab")
        proc = subprocess.Popen(
            [
                sys.executable,
                str(WORKER),
                "--state-dir", str(state_dir),
                "--inbox-dir", str(inbox_dir),
                "--cmd-dir", str(cmd_dir),
                "--res-dir", str(res_dir),
                "--slot", SLOT,
                "--owner-id", OWNER_ID,
                "--owner-pubkey", self.pubkeys["A"],
                "--mandate-file", str(self.mandate_path),
            ]
            + (["--init"] if init else []),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=stderr_fh,
        )
        self.workers[name] = {
            "proc": proc,
            "cmd_dir": cmd_dir,
            "res_dir": res_dir,
            "state_dir": state_dir,
            "stderr_fh": stderr_fh,
            "pid": proc.pid,
        }
        self._own_pids.add(proc.pid)
        ready = res_dir / "ready"
        deadline = time.time() + 30
        while not ready.exists():
            if time.time() > deadline or proc.poll() is not None:
                raise RuntimeError(f"worker {name} failed to start")
            time.sleep(0.05)
        self.log("worker_started", receiver=name, init=init)

    def command(self, name: str, cmd: dict, timeout: float = 60.0) -> dict:
        w = self.workers[name]
        self.cmd_seq += 1
        fname = f"cmd_{self.cmd_seq:04d}.json"
        (w["cmd_dir"] / fname).write_text(
            json.dumps(cmd, sort_keys=True) + "\n", encoding="utf-8"
        )
        res = w["res_dir"] / fname.replace("cmd_", "res_")
        deadline = time.time() + timeout
        while not res.exists():
            if time.time() > deadline:
                raise RuntimeError(f"worker {name} command {cmd} timed out")
            if w["proc"].poll() is not None:
                raise RuntimeError(f"worker {name} died during {cmd}")
            time.sleep(0.05)
        result = json.loads(res.read_text(encoding="utf-8"))
        self.log("worker_result", receiver=name, cmd=cmd.get("cmd"), result=result)
        return result

    def terminate(self, name: str) -> None:
        w = self.workers.get(name)
        if w is None:
            return
        try:
            self.command(name, {"cmd": "shutdown"}, timeout=10.0)
        except Exception:
            pass
        self.workers.pop(name, None)
        w["proc"].terminate()
        try:
            w["proc"].wait(timeout=10)
        except Exception:
            w["proc"].kill()
        self._own_pids.discard(w["pid"])
        try:
            w["stderr_fh"].close()
        except Exception:
            pass
        self.log("worker_terminated", receiver=name)

    def sweep_stale_workers(self) -> None:
        """Kill succession_worker processes that are not ours.

        Only ever called between spawns; any live worker not in _own_pids
        is a stale orphan from an earlier crashed run.
        """
        me = os.getpid()
        try:
            out = subprocess.run(
                ["pgrep", "-f", "succession_worker[.]py"],
                capture_output=True, text=True, check=False,
            )
        except Exception:
            return
        for line in out.stdout.splitlines():
            pid = line.strip()
            if not pid.isdigit():
                continue
            pid_i = int(pid)
            if pid_i == me or pid_i in self._own_pids:
                continue
            try:
                import signal
                os.kill(pid_i, signal.SIGKILL)
            except Exception:
                pass

    # -- case helpers ---------------------------------------------------

    def poll(self, receiver: str) -> list[dict]:
        result = self.command(receiver, {"cmd": "poll"})
        assert result["ok"], f"poll failed on {receiver}: {result}"
        return result["outcomes"]

    def status(self, receiver: str) -> dict:
        result = self.command(receiver, {"cmd": "status"})
        assert result["ok"], f"status failed on {receiver}: {result}"
        return result

    def snapshot(self, tag: str) -> None:
        dest = self.snap_dir / tag
        dest.mkdir(parents=True, exist_ok=True)
        for r in RECEIVERS:
            src = self.run_dir / "receivers" / r
            for fname in ("owner_heads.json", "trust_roots.json",
                          "admissions.jsonl", "seen_cmds.json"):
                p = src / fname
                if p.exists():
                    (dest / f"{r}_{fname}").write_bytes(p.read_bytes())
        self.log("snapshot", tag=tag)

    def expect_admitted(self, receiver: str, filename: str, **match) -> dict:
        outcomes = self.poll(receiver)
        hits = [o for o in outcomes if o["file"] == filename]
        assert len(hits) == 1, f"{receiver}: {filename} not polled once: {outcomes}"
        o = hits[0]
        assert o["admitted"] is True, f"{receiver}: {filename} refused: {o}"
        for k, v in match.items():
            assert o.get(k) == v, f"{receiver}: {filename} {k}={o.get(k)} != {v}"
        return o

    def expect_refused(self, receiver: str, filename: str, code: str) -> dict:
        outcomes = self.poll(receiver)
        hits = [o for o in outcomes if o["file"] == filename]
        assert len(hits) == 1, f"{receiver}: {filename} not polled once: {outcomes}"
        o = hits[0]
        assert o["admitted"] is False, f"{receiver}: {filename} ADMITTED (BAD): {o}"
        assert code in o.get("error", ""), (
            f"{receiver}: {filename} wrong reason: {o.get('error')}"
        )
        return o

    # -- cases ----------------------------------------------------------

    def run(self) -> None:
        for r in RECEIVERS:
            self.spawn(r, init=True)

        # CASE 1a: A-era owner authority works pre-succession.
        a_auth1 = self.issue_auth("a_active_seq1", "A", "ACTIVE", 1, None)
        for r in RECEIVERS:
            self.deliver(a_auth1, r, "a_active_seq1.json")
        for r in RECEIVERS:
            self.expect_admitted(r, "a_active_seq1.json", state="ACTIVE", sequence=1)
            st = self.status(r)
            assert st["status"] == "ACTIVE", st
            assert st["current_owner_pubkey"] == self.pubkeys["A"], st
        self.record_case("case_1a", "A-signed ACTIVE admitted pre-succession",
                         {"receivers": list(RECEIVERS)})

        # CASE 1b: A -> B succession admitted on both receivers.
        ab = self.issue_succession("a_to_b_seq1", "A", "B", 1, None)
        for r in RECEIVERS:
            self.deliver(ab, r, "a_to_b_seq1.json")
        for r in RECEIVERS:
            o = self.expect_admitted(r, "a_to_b_seq1.json",
                                     kind="trust_root_succession",
                                     succession_sequence=1)
            assert o["owner_id"] == OWNER_ID
            st = self.status(r)
            assert st["current_owner_pubkey"] == self.pubkeys["B"], st
            assert st["succession_seq"] == 1, st
            assert st["schedule_len"] == 2, st
        self.snapshot("case_1b_post_succession")
        self.record_case("case_1b", "A->B succession admitted; B current on both",
                         {"event_hash": ab["payload_hash"],
                          "receivers": list(RECEIVERS)})

        # CASE 1c: B exercises owner authority (ACTIVE / STOP / ACTIVE).
        pred = a_auth1["payload_hash"]
        b_auth2 = self.issue_auth("b_active_seq2", "B", "ACTIVE", 2, pred)
        b_stop3 = self.issue_auth("b_stop_seq3", "B", "REVOKED", 3,
                                  b_auth2["payload_hash"])
        b_auth4 = self.issue_auth("b_active_seq4", "B", "ACTIVE", 4,
                                  b_stop3["payload_hash"])
        for rec, fname, state, seq in (
            (b_auth2, "b_active_seq2.json", "ACTIVE", 2),
            (b_stop3, "b_stop_seq3.json", "REVOKED", 3),
            (b_auth4, "b_active_seq4.json", "ACTIVE", 4),
        ):
            for r in RECEIVERS:
                self.deliver(rec, r, fname)
            for r in RECEIVERS:
                self.expect_admitted(r, fname, state=state, sequence=seq)
                st = self.status(r)
                assert st["status"] == ("REVOKED" if state == "REVOKED" else "ACTIVE"), st
                assert st["current_owner_pubkey"] == self.pubkeys["B"], st
        self.record_case("case_1c", "B exercises owner authority incl. STOP",
                         {"receivers": list(RECEIVERS)})

        # CASE 2a: non-owner worker key cannot mint owner authority.
        w_stop = self.issue_auth("w_stop_seq5", "W", "REVOKED", 5,
                                 b_auth4["payload_hash"])
        for r in RECEIVERS:
            self.deliver(w_stop, r, "w_stop_seq5.json")
        for r in RECEIVERS:
            self.expect_refused(r, "w_stop_seq5.json",
                                "mandate_authorization_owner_key_mismatch")
            st = self.status(r)
            assert st["head_seq"] == 4, st
        self.record_case("case_2a", "W-signed owner STOP refused",
                         {"reason": "mandate_authorization_owner_key_mismatch"})

        # CASE 2b: old owner A cannot authorize new consequences post-succession.
        a_auth5 = self.issue_auth("a_active_seq5", "A", "ACTIVE", 5,
                                  b_auth4["payload_hash"])
        for r in RECEIVERS:
            self.deliver(a_auth5, r, "a_active_seq5.json")
        for r in RECEIVERS:
            self.expect_refused(r, "a_active_seq5.json",
                                "mandate_authorization_owner_key_mismatch")
            st = self.status(r)
            assert st["head_seq"] == 4, st
        self.record_case("case_2b", "A-signed fresh auth refused post-succession",
                         {"reason": "mandate_authorization_owner_key_mismatch"})

        # CASE 3: C cannot self-install as owner.
        c_self = self.issue_succession("c_self_seq2", "C", "C", 2,
                                       ab["payload_hash"])
        for r in RECEIVERS:
            self.deliver(c_self, r, "c_self_seq2.json")
        for r in RECEIVERS:
            self.expect_refused(r, "c_self_seq2.json",
                                "trust_root_succession_signer_not_current_owner")
            st = self.status(r)
            assert st["current_owner_pubkey"] == self.pubkeys["B"], st
            assert st["succession_seq"] == 1, st
        self.record_case("case_3", "C self-declaration refused",
                         {"reason": "trust_root_succession_signer_not_current_owner"})

        # CASE 4a: replay the admitted A->B event.
        for r in RECEIVERS:
            self.deliver(ab, r, "replay_a_to_b.json")
        for r in RECEIVERS:
            o = self.poll(r)
            hits = [x for x in o if x["file"] == "replay_a_to_b.json"]
            assert len(hits) == 1 and hits[0]["admitted"] is False, o
            st = self.status(r)
            assert st["succession_seq"] == 1, st
            assert st["current_owner_pubkey"] == self.pubkeys["B"], st
        self.record_case("case_4a", "replayed A->B event refused",
                         {"receivers": list(RECEIVERS)})

        # CASE 4b: duplicate succession sequence (B-signed, successor D-key).
        self.keys["D"] = Ed25519PrivateKey.generate()
        self.pubkeys["D"] = public_key_hex(self.keys["D"])
        dup = self.issue_succession("b_dup_seq1", "B", "D", 1, None)
        for r in RECEIVERS:
            self.deliver(dup, r, "b_dup_seq1.json")
        for r in RECEIVERS:
            self.expect_refused(r, "b_dup_seq1.json",
                                "trust_root_succession_sequence_invalid")
        self.record_case("case_4b", "duplicate succession sequence refused",
                         {"reason": "trust_root_succession_sequence_invalid"})

        # CASE 4c: wrong predecessor hash.
        bad_pred = self.issue_succession("b_badpred_seq2", "B", "D", 2,
                                         "00" * 32)
        for r in RECEIVERS:
            self.deliver(bad_pred, r, "b_badpred_seq2.json")
        for r in RECEIVERS:
            self.expect_refused(r, "b_badpred_seq2.json",
                                "trust_root_succession_predecessor_mismatch")
        self.record_case("case_4c", "wrong predecessor hash refused",
                         {"reason": "trust_root_succession_predecessor_mismatch"})

        # CASE 4d: old owner A forges a succession naming C.
        a_forge = self.issue_succession("a_forge_seq2", "A", "C", 2,
                                        ab["payload_hash"])
        for r in RECEIVERS:
            self.deliver(a_forge, r, "a_forge_seq2.json")
        for r in RECEIVERS:
            self.expect_refused(r, "a_forge_seq2.json",
                                "trust_root_succession_signer_not_current_owner")
            st = self.status(r)
            assert st["current_owner_pubkey"] == self.pubkeys["B"], st
        self.record_case("case_4d", "A-forged succession refused",
                         {"reason": "trust_root_succession_signer_not_current_owner"})

        # CASE 5: restart R1 across the succession boundary.
        self.snapshot("case_5_pre_restart")
        self.terminate("r1")
        self.spawn("r1", init=False)
        st = self.status("r1")
        assert st["current_owner_pubkey"] == self.pubkeys["B"], st
        assert st["succession_seq"] == 1, st
        assert st["schedule_len"] == 2, st
        assert st["status"] == "ACTIVE", st
        assert st["head_seq"] == 4, st
        # B still authoritative after restart.
        b_auth5 = self.issue_auth("b_active_seq5", "B", "ACTIVE", 5,
                                  b_auth4["payload_hash"])
        self.deliver(b_auth5, "r1", "b_active_seq5.json")
        self.expect_admitted("r1", "b_active_seq5.json", state="ACTIVE",
                             sequence=5)
        # A still not.
        a_auth6 = self.issue_auth("a_active_seq6", "A", "ACTIVE", 6,
                                  b_auth5["payload_hash"])
        self.deliver(a_auth6, "r1", "a_active_seq6.json")
        self.expect_refused("r1", "a_active_seq6.json",
                            "mandate_authorization_owner_key_mismatch")
        self.snapshot("case_5_post_restart")
        self.record_case("case_5", "restart preserves B; A stays refused",
                         {"receiver": "r1"})

        # CASE 6: historical verification.
        res = self.command("r2", {"cmd": "assess", "record": a_auth1})
        a_assess = res["assessment"]
        assert a_assess["verified"] is True, a_assess
        assert a_assess["current"] is False, a_assess
        assert a_assess["reason_codes"] == [
            "trust_root_succession_historical_key"], a_assess
        assert a_assess["historical_public_key"] == self.pubkeys["A"], a_assess
        res = self.command("r2", {"cmd": "assess", "record": b_auth4})
        b_assess = res["assessment"]
        assert b_assess["verified"] is True, b_assess
        assert b_assess["current"] is True, b_assess
        st = self.status("r2")
        assert st["status"] == "ACTIVE", st
        (self.run_dir / "case_6_assessments.json").write_text(
            json.dumps({"a_era": a_assess, "b_era": b_assess}, indent=2,
                       sort_keys=True) + "\n",
            encoding="utf-8",
        )
        self.record_case("case_6", "A-era receipt historically verifiable",
                         {"a_verified": True, "a_current": False,
                          "b_verified": True, "b_current": True})

        self.snapshot("final")
        (self.run_dir / "case_results.json").write_text(
            json.dumps(self.case_results, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        for r in RECEIVERS:
            self.terminate(r)


def _unique_failed_dir(base: str) -> Path:
    target = EXP / base
    i = 2
    while target.exists():
        target = EXP / f"{base}_{i}"
        i += 1
    return target


def main() -> int:
    run_dir = EXP / "run"
    # Pre-contact apparatus preservation: never overwrite a previous run.
    if run_dir.exists():
        run_dir.rename(_unique_failed_dir("run_attempt_unfinished"))
    run_dir.mkdir(parents=True)
    driver = Driver(run_dir)
    try:
        driver.run()
    except Exception as exc:  # noqa: BLE001 - harness must preserve failures
        driver.log("driver_failed", error=f"{type(exc).__name__}:{exc}")
        for r in list(driver.workers):
            try:
                driver.terminate(r)
            except Exception:
                pass
        run_dir.rename(
            _unique_failed_dir(f"run_attempt_failed_{type(exc).__name__}")
        )
        raise
    driver.log("driver_complete", cases=len(driver.case_results))
    print(f"TRUST-ROOT-SUCCESSION-001 driver complete: "
          f"{len(driver.case_results)} cases, evidence in {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
