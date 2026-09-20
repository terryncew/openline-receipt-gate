"""DISTRIBUTED-STOP-001 driver (owner + orchestrator).

Owns the owner key, issues ACTIVE/REVOKED mandate authorizations, delivers
them to per-receiver file inboxes with controlled timing, spawns receiver
worker subprocesses, runs DS1..DS5 per the frozen preregistration, and
writes the complete run log + frozen run directory for the independent
appraiser. Harness only; no product code changes.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import public_key_hex
from olp_gate.mandate_owner import issue_mandate_authorization

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent
WORKER = HERE / "receiver_worker.py"
SLOT = "payments/default"
OWNER_ID = "alice"


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Driver:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "issued").mkdir(exist_ok=True)
        (self.run_dir / "inbox").mkdir(exist_ok=True)
        self.log_path = self.run_dir / "run_log.jsonl"
        self.owner_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("b1" * 32))
        self.owner_pubkey = public_key_hex(self.owner_key)
        self.mandate = {
            "profile": "principal_mandate/v1",
            "mandate_id": "distributed-stop-mandate",
            "principal_id": OWNER_ID,
            "agent_id": "distributed-stop-agent",
            "purpose": "distributed stop experiment",
            "allowed_action_types": ["authorize_payment"],
            "allowed_targets": ["payments://ledger"],
            "allowed_disclosure_classes": [],
            "forbidden_disclosure_classes": [],
            "max_settlement_cents": 0,
            "max_payment_cents": 10_000,
            "delegation_allowed": False,
            "expires_at": _iso(_now() + timedelta(days=1)),
            "version": "v1",
        }
        self.workers: dict[str, dict] = {}
        self.cmd_seq = 0

    # -- logging ------------------------------------------------------

    def log(self, event: str, **fields) -> None:
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {"t": _iso(_now()), "event": event, **fields}, sort_keys=True
                )
                + "\n"
            )

    # -- owner ---------------------------------------------------------

    def issue(self, state: str, sequence: int, predecessor_hash: str | None,
              lease_seconds: int) -> dict:
        now = _now()
        record = issue_mandate_authorization(
            slot_id=SLOT,
            owner_id=OWNER_ID,
            mandate=self.mandate,
            state=state,
            sequence=sequence,
            predecessor_hash=predecessor_hash,
            issued_at=now,
            expires_at=now + timedelta(seconds=lease_seconds),
            key=self.owner_key,
        )
        path = self.run_dir / "issued" / f"seq{sequence}_{state}.json"
        path.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.log(
            "owner_issued",
            state=state,
            sequence=sequence,
            payload_hash=record.get("payload_hash"),
            issued_at=_iso(now),
            lease_seconds=lease_seconds,
        )
        return record

    def deliver(self, record: dict, receiver: str, filename: str) -> None:
        inbox = self.run_dir / "inbox" / receiver
        inbox.mkdir(parents=True, exist_ok=True)
        (inbox / filename).write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.log(
            "owner_delivered",
            receiver=receiver,
            file=filename,
            sequence=record.get("sequence"),
            state=record.get("state"),
        )

    # -- workers -------------------------------------------------------

    def spawn(self, name: str, *, init: bool) -> None:
        state_dir = self.run_dir / "receivers" / name
        inbox_dir = self.run_dir / "inbox" / name
        cmd_dir = self.run_dir / "cmd" / name
        res_dir = self.run_dir / "res" / name
        env = dict(os_environ())
        env["PYTHONPATH"] = str(REPO)
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
                "--owner-pubkey", self.owner_pubkey,
            ] + (["--init"] if init else []),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.workers[name] = {
            "proc": proc,
            "cmd_dir": cmd_dir,
            "res_dir": res_dir,
            "state_dir": state_dir,
        }
        # wait for ready
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
        w = self.workers.pop(name)
        try:
            self.command(name, {"cmd": "shutdown"}, timeout=10.0)
        except Exception:
            pass
        w["proc"].terminate()
        try:
            w["proc"].wait(timeout=10)
        except Exception:
            w["proc"].kill()
        self.log("worker_terminated", receiver=name)

    # -- scenario ------------------------------------------------------

    def run(self) -> None:
        self.log("run_start", preregistration="experiments/distributed-stop-001/preregistration.json")
        self.spawn("R1", init=True)
        self.spawn("R2", init=True)

        # ---- DS1: baseline, no STOP ----------------------------------
        active = self.issue("ACTIVE", 1, None, lease_seconds=3600)
        self.deliver(active, "R1", "seq1.json")
        self.deliver(active, "R2", "seq1.json")
        r = self.command("R1", {"cmd": "poll"}); assert r["outcomes"][0]["admitted"]
        r = self.command("R2", {"cmd": "poll"}); assert r["outcomes"][0]["admitted"]
        d1a = self.command("R1", {"cmd": "attempt", "case": "ds1-r1"})
        d1b = self.command("R2", {"cmd": "attempt", "case": "ds1-r2"})
        self.log("DS1_done", r1=d1a, r2=d1b)

        # ---- DS2: stale read -----------------------------------------
        revoked = self.issue("REVOKED", 2, active["payload_hash"], lease_seconds=3600)
        self.deliver(revoked, "R1", "seq2.json")
        r = self.command("R1", {"cmd": "poll"}); assert r["outcomes"][0]["admitted"]
        d2a = self.command("R1", {"cmd": "attempt", "case": "ds2-r1-poststop"})
        d2b = self.command("R2", {"cmd": "attempt", "case": "ds2-r2-stale"})
        self.deliver(revoked, "R2", "seq2.json")
        r = self.command("R2", {"cmd": "poll"}); assert r["outcomes"][0]["admitted"]
        d2c = self.command("R2", {"cmd": "attempt", "case": "ds2-r2-poststop"})
        self.log("DS2_done", r1_post=d2a, r2_stale=d2b, r2_post=d2c)

        # ---- DS3: propagation delay / partition (short lease) ---------
        # Fresh receivers with a 5s ACTIVE lease.
        # Snapshot DS1/DS2 journals first: the independent appraiser needs
        # them for re-derivation after the state dirs are reset.
        self.snapshot("ds1_ds2")
        self.terminate("R1"); self.terminate("R2")
        shutil.rmtree(self.run_dir / "receivers" / "R1", ignore_errors=True)
        shutil.rmtree(self.run_dir / "receivers" / "R2", ignore_errors=True)
        self.spawn("R1", init=True)
        self.spawn("R2", init=True)
        active3 = self.issue("ACTIVE", 1, None, lease_seconds=5)
        self.deliver(active3, "R1", "seq1.json")
        self.deliver(active3, "R2", "seq1.json")
        self.command("R1", {"cmd": "poll"})
        self.command("R2", {"cmd": "poll"})
        revoked3 = self.issue("REVOKED", 2, active3["payload_hash"], lease_seconds=3600)
        self.deliver(revoked3, "R1", "seq2.json")
        r = self.command("R1", {"cmd": "poll"}); assert r["outcomes"][0]["admitted"]
        d3a = self.command("R1", {"cmd": "attempt", "case": "ds3-r1-poststop"})
        # Hold R2's delivery past its ACTIVE expiry (5s lease).
        time.sleep(6.5)
        d3b = self.command("R2", {"cmd": "attempt", "case": "ds3-r2-partitioned"})
        self.deliver(revoked3, "R2", "seq2.json")
        r = self.command("R2", {"cmd": "poll"}); assert r["outcomes"][0]["admitted"]
        d3c = self.command("R2", {"cmd": "attempt", "case": "ds3-r2-poststop"})
        self.log("DS3_done", r1_post=d3a, r2_partitioned=d3b, r2_post=d3c)

        # ---- DS4: restart across the STOP boundary --------------------
        # R2 currently holds REVOKED (admitted in DS3). Restart it.
        self.terminate("R2")
        self.spawn("R2", init=False)  # resume: open existing durable files
        d4a = self.command("R2", {"cmd": "status"})
        d4b = self.command("R2", {"cmd": "attempt", "case": "ds4-r2-restarted"})
        self.log("DS4_done", status_after_restart=d4a, attempt=d4b)

        # ---- DS5: reordered arrival -----------------------------------
        self.spawn("R3", init=True)
        active5 = self.issue("ACTIVE", 1, None, lease_seconds=3600)
        revoked5 = self.issue("REVOKED", 2, active5["payload_hash"], lease_seconds=3600)
        self.deliver(revoked5, "R3", "a_seq2_first.json")
        d5a = self.command("R3", {"cmd": "poll"})
        self.deliver(active5, "R3", "b_seq1.json")
        d5b = self.command("R3", {"cmd": "poll"})
        self.deliver(revoked5, "R3", "c_seq2_again.json")
        d5c = self.command("R3", {"cmd": "poll"})
        d5d = self.command("R3", {"cmd": "attempt", "case": "ds5-r3"})
        self.deliver(active5, "R3", "d_seq1_replay.json")
        d5e = self.command("R3", {"cmd": "poll"})
        self.log("DS5_done", ooo_first=d5a, in_order=d5b, second=d5c,
                 attempt=d5d, replay=d5e)

        for name in list(self.workers):
            self.terminate(name)
        self.snapshot("final")
        self.log("run_complete")

    def snapshot(self, label: str) -> None:
        dest = self.run_dir / "snapshots" / label
        for name in ("R1", "R2", "R3"):
            src = self.run_dir / "receivers" / name
            if src.exists():
                shutil.copytree(src, dest / name, dirs_exist_ok=True)
        self.log("snapshot", label=label)


def os_environ() -> dict:
    import os

    return dict(os.environ)


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        HERE.parent / "run"
    )
    if out.exists():
        shutil.rmtree(out)
    Driver(out).run()
    print(f"run complete: {out}")


if __name__ == "__main__":
    main()
