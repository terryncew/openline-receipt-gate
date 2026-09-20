"""TRUST-ROOT-SUCCESSION-001 receiver worker.

One OS process = one independent receiver. Holds its own MandateOwnerView
(durable mandate heads + durable trust-root succession store) and admits
owner-signed records from its own file inbox. Harness only.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from olp_gate._durable_heads import DurableHeadStore
from olp_gate.mandate_owner import (
    TRUST_ROOT_SUCCESSION_SCHEMA,
    MandateOwnerView,
    create_trust_root_store,
)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Worker:
    def __init__(self, args) -> None:
        self.args = args
        self.state = Path(args.state_dir)
        self.inbox = Path(args.inbox_dir)
        self.cmd_dir = Path(args.cmd_dir)
        self.res_dir = Path(args.res_dir)
        for d in (self.state, self.inbox, self.cmd_dir, self.res_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.rejected = self.state / "rejected"
        self.rejected.mkdir(exist_ok=True)

        # One receiver identity = one live process. A second worker on the
        # same state dir is split-brain, not independence: refuse loudly.
        self._lock_fh = open(self.state / ".lock", "w", encoding="utf-8")
        try:
            fcntl.flock(self._lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            print(f"state dir locked: {self.state} (another worker owns this receiver)",
                  file=sys.stderr)
            sys.exit(2)

        self.slot = args.slot
        self.owner_id = args.owner_id
        # The mandate is pinned out-of-band (agreed by owner and receiver
        # before the experiment); the worker loads the driver's copy so the
        # mandate_hash in owner-signed records matches exactly.
        self.mandate = json.loads(
            Path(args.mandate_file).read_text(encoding="utf-8")
        )

        heads_path = str(self.state / "owner_heads.json")
        trust_path = str(self.state / "trust_roots.json")
        slots = {
            self.slot: {
                "owner_id": self.owner_id,
                "public_key": args.owner_pubkey,
            }
        }
        if args.init:
            DurableHeadStore.create(
                heads_path, {"view": "mandate_owner/v1", "slots": slots}
            )
            create_trust_root_store(trust_path, slots)
        self.view = MandateOwnerView(
            slots, durable_path=heads_path, trust_root_path=trust_path
        )
        self.admissions_path = self.state / "admissions.jsonl"

    # -- inbox ----------------------------------------------------------

    def cmd_poll(self, payload: dict) -> dict:
        outcomes = []
        for path in sorted(self.inbox.glob("*.json")):
            now = _now()
            outcome: dict = {"file": path.name}
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
                if (
                    isinstance(record, dict)
                    and record.get("schema") == TRUST_ROOT_SUCCESSION_SCHEMA
                ):
                    admission = self.view.admit_trust_root_succession(
                        record, now=now
                    )
                    outcome.update(
                        {
                            "admitted": True,
                            "kind": "trust_root_succession",
                            "succession_sequence": admission.get(
                                "succession_sequence"
                            ),
                            "event_hash": admission.get("event_hash"),
                            "owner_id": admission.get("owner_id"),
                        }
                    )
                else:
                    admission = self.view.admit(record, self.mandate, now=now)
                    outcome.update(
                        {
                            "admitted": True,
                            "kind": "mandate_authorization",
                            "state": admission.get("state"),
                            "sequence": admission.get("sequence"),
                            "head_hash": admission.get("head_hash"),
                        }
                    )
                with self.admissions_path.open("a", encoding="utf-8") as fh:
                    fh.write(
                        json.dumps(
                            {
                                "file": path.name,
                                "kind": outcome.get("kind"),
                                "admitted": True,
                                "admitted_at": _iso(now),
                                "detail": {
                                    k: v
                                    for k, v in outcome.items()
                                    if k not in ("file", "admitted", "kind")
                                },
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )
                path.unlink()
            except Exception as exc:  # harness: record, quarantine, do not crash
                outcome.update(
                    {
                        "admitted": False,
                        "error": f"{type(exc).__name__}:{exc}",
                    }
                )
                with self.admissions_path.open("a", encoding="utf-8") as fh:
                    fh.write(
                        json.dumps(
                            {
                                "file": path.name,
                                "admitted": False,
                                "admitted_at": _iso(now),
                                "error": outcome["error"],
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )
                # Quarantine: keep the evidence, keep the inbox clean.
                shutil.move(str(path), str(self.rejected / path.name))
            outcomes.append(outcome)
        return {"outcomes": outcomes}

    def cmd_status(self, payload: dict) -> dict:
        now = _now()
        owner = self.view.current_owner(self.slot)
        return {
            "status": self.view.status(self.slot, now=now),
            "head_seq": self.view.head_sequence(self.slot),
            "head_hash": self.view.head_hash(self.slot),
            "current_owner_id": owner["owner_id"],
            "current_owner_pubkey": owner["public_key"],
            "succession_seq": self.view.succession_sequence(self.slot),
            "schedule_len": len(self.view.key_schedule(self.slot)),
        }

    def cmd_assess(self, payload: dict) -> dict:
        record = payload["record"]
        result = self.view.assess(record, self.mandate, now=_now())
        return {"assessment": result}

    def _write_res(self, res_filename: str, payload: dict) -> None:
        # Atomic: the driver treats file-existence as response-readiness,
        # so the response must never be observable partially written.
        # res_filename already carries its extension (e.g. res_0001.json).
        tmp = self.res_dir / f".{res_filename}.tmp"
        tmp.write_text(
            json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8"
        )
        tmp.rename(self.res_dir / res_filename)

    def run(self) -> None:
        (self.res_dir / "ready").write_text("ready\n", encoding="utf-8")
        # Durable processed-command set: a respawned worker (resume mode)
        # must not re-execute another lifetime's commands.
        seen_path = self.state / "seen_cmds.json"
        try:
            seen = set(json.loads(seen_path.read_text(encoding="utf-8")))
        except Exception:
            seen = set()

        def mark_seen(name: str) -> None:
            seen.add(name)
            seen_path.write_text(json.dumps(sorted(seen)) + "\n", encoding="utf-8")

        handlers = {
            "poll": self.cmd_poll,
            "status": self.cmd_status,
            "assess": self.cmd_assess,
        }
        while True:
            progressed = False
            for path in sorted(self.cmd_dir.glob("cmd_*.json")):
                if path.name in seen:
                    continue
                mark_seen(path.name)
                progressed = True
                cmd = json.loads(path.read_text(encoding="utf-8"))
                name = str(cmd.get("cmd"))
                if name == "shutdown":
                    self._write_res(
                        path.name.replace("cmd_", "res_"),
                        {"ok": True, "shutdown": True},
                    )
                    return
                try:
                    result = handlers[name](cmd)
                    result = {"ok": True, **result}
                except Exception as exc:
                    result = {"ok": False, "error": f"{type(exc).__name__}:{exc}"}
                self._write_res(path.name.replace("cmd_", "res_"), result)
            if not progressed:
                time.sleep(0.05)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--inbox-dir", required=True)
    parser.add_argument("--cmd-dir", required=True)
    parser.add_argument("--res-dir", required=True)
    parser.add_argument("--slot", required=True)
    parser.add_argument("--owner-id", required=True)
    parser.add_argument("--owner-pubkey", required=True)
    parser.add_argument("--mandate-file", required=True)
    parser.add_argument("--receiver-id", default="")
    parser.add_argument("--init", action="store_true")
    args = parser.parse_args()
    Worker(args).run()


if __name__ == "__main__":
    main()
