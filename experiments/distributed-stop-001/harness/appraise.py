"""DISTRIBUTED-STOP-001 independent appraiser.

Reads only frozen run artifacts (snapshotted receiver state dirs, issued
records, run log). Re-derives every path verdict via
olp_gate.stop_standing.derive_path_verdicts without trusting the live
receivers, then checks the preregistered expectations. Writes
appraisal.json. Harness only.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from olp_gate.stop_standing import derive_path_verdicts


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def admissions_list(state_dir: Path) -> list[dict]:
    path = state_dir / "admissions.jsonl"
    if not path.exists():
        return []
    return [
        {"state": a["state"], "sequence": a["sequence"]}
        for a in load_jsonl(path)
    ]


def attempts_by_label(state_dir: Path) -> dict[str, dict]:
    ledger = load_json(state_dir / "commit_ledger.json")
    return {a["attempt_label"]: a for a in ledger.get("attempts", [])}


def rederived(state_dir: Path) -> dict[str, dict]:
    ledger = load_json(state_dir / "commit_ledger.json")
    verdicts = derive_path_verdicts(ledger, admissions_list(state_dir))
    return {v["attempt_id"]: v for v in verdicts}


def effect_present(state_dir: Path, case: str) -> bool:
    return (state_dir / "effects" / f"{case}.json").exists()


class Appraisal:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.checks: list[dict] = []

    def check(self, name: str, ok: bool, detail: str = "") -> None:
        self.checks.append({"name": name, "ok": bool(ok), "detail": detail})

    def attempt(self, snap: str, receiver: str, label: str) -> tuple[dict, dict]:
        state_dir = self.run_dir / "snapshots" / snap / receiver
        attempts = attempts_by_label(state_dir)
        assert label in attempts, f"missing attempt {label} in {snap}/{receiver}"
        rd = rederived(state_dir)
        attempt = attempts[label]
        return attempt, rd[attempt["attempt_id"]]

    def run(self) -> dict:
        r = self.run_dir

        # ---- DS1: baseline -------------------------------------------
        for recv, label in (("R1", "ds1-r1"), ("R2", "ds1-r2")):
            a, v = self.attempt("ds1_ds2", recv, label)
            self.check(f"DS1 {recv} authorized", a["result"] == "AUTHORIZED",
                       str(a["result"]))
            self.check(f"DS1 {recv} effect observed",
                       effect_present(r / "snapshots" / "ds1_ds2" / recv, label),
                       label)
            self.check(f"DS1 {recv} re-derived NO_STOP_ADMITTED",
                       v["ordering"] == "NO_STOP_ADMITTED", str(v))

        # ---- DS2: stale read ------------------------------------------
        a, v = self.attempt("ds1_ds2", "R1", "ds2-r1-poststop")
        self.check("DS2 R1 post-STOP blocked", a["result"] == "BLOCKED"
                   and "owner_standing_revoked" in a["reason_codes"],
                   str(a["reason_codes"]))
        self.check("DS2 R1 no effect",
                   not effect_present(r / "snapshots" / "ds1_ds2" / "R1", "ds2-r1-poststop"))
        self.check("DS2 R1 re-derived STOPPED/STOP_FIRST",
                   v["verdict"] == "STOPPED" and v["ordering"] == "STOP_FIRST", str(v))

        a, v = self.attempt("ds1_ds2", "R2", "ds2-r2-stale")
        self.check("DS2 R2 stale commit classified PRE_STOP_COMMIT (expected residual)",
                   a["result"] == "AUTHORIZED" and v["ordering"] == "PRE_STOP_COMMIT",
                   f"result={a['result']} ordering={v['ordering']}")
        self.check("DS2 R2 stale effect observed",
                   effect_present(r / "snapshots" / "ds1_ds2" / "R2", "ds2-r2-stale"))

        a, v = self.attempt("ds1_ds2", "R2", "ds2-r2-poststop")
        self.check("DS2 R2 post-admission blocked", a["result"] == "BLOCKED"
                   and "owner_standing_revoked" in a["reason_codes"],
                   str(a["reason_codes"]))
        self.check("DS2 R2 re-derived STOPPED", v["verdict"] == "STOPPED", str(v))

        # ---- DS3: partition -------------------------------------------
        a, v = self.attempt("final", "R1", "ds3-r1-poststop")
        self.check("DS3 R1 post-STOP blocked", a["result"] == "BLOCKED"
                   and "owner_standing_revoked" in a["reason_codes"],
                   str(a["reason_codes"]))
        self.check("DS3 R1 re-derived STOPPED", v["verdict"] == "STOPPED", str(v))

        a, v = self.attempt("final", "R2", "ds3-r2-partitioned")
        self.check("DS3 R2 partitioned attempt blocked",
                   a["result"] == "BLOCKED", str(a["result"]))
        self.check("DS3 R2 blocked for AUTHORIZATION_EXPIRED",
                   any("AUTHORIZATION_EXPIRED" in c for c in a["reason_codes"]),
                   str(a["reason_codes"]))
        self.check("DS3 R2 no effect while partitioned",
                   not effect_present(r / "snapshots" / "final" / "R2", "ds3-r2-partitioned"))
        self.check("DS3 R2 re-derived UNKNOWN/NOT_ESTABLISHED (fail-closed, expected)",
                   v["verdict"] == "UNKNOWN" and v["ordering"] == "NOT_ESTABLISHED",
                   str(v))

        a, v = self.attempt("final", "R2", "ds3-r2-poststop")
        self.check("DS3 R2 post-admission blocked", a["result"] == "BLOCKED"
                   and "owner_standing_revoked" in a["reason_codes"],
                   str(a["reason_codes"]))
        self.check("DS3 R2 re-derived STOPPED", v["verdict"] == "STOPPED", str(v))

        # ---- DS4: restart ----------------------------------------------
        a, v = self.attempt("final", "R2", "ds4-r2-restarted")
        self.check("DS4 R2 restarted still blocked", a["result"] == "BLOCKED"
                   and "owner_standing_revoked" in a["reason_codes"],
                   str(a["reason_codes"]))
        self.check("DS4 R2 no effect after restart",
                   not effect_present(r / "snapshots" / "final" / "R2", "ds4-r2-restarted"))
        self.check("DS4 R2 re-derived STOPPED", v["verdict"] == "STOPPED", str(v))
        status_events = [e for e in load_jsonl(r / "run_log.jsonl")
                         if e["event"] == "DS4_done"]
        restarted_status = status_events[0]["status_after_restart"]["status"]
        self.check("DS4 head survived restart as REVOKED",
                   restarted_status == "REVOKED", restarted_status)

        # ---- DS5: reordered --------------------------------------------
        ds5 = [e for e in load_jsonl(r / "run_log.jsonl") if e["event"] == "DS5_done"][0]
        self.check("DS5 out-of-order seq-2 admit refused",
                   ds5["ooo_first"]["outcomes"][0]["admitted"] is False,
                   str(ds5["ooo_first"]["outcomes"]))
        self.check("DS5 seq-1 admits", ds5["in_order"]["outcomes"][0]["admitted"] is True,
                   str(ds5["in_order"]["outcomes"]))
        self.check("DS5 seq-2 admits after seq-1",
                   ds5["second"]["outcomes"][0]["admitted"] is True,
                   str(ds5["second"]["outcomes"]))
        a, v = self.attempt("final", "R3", "ds5-r3")
        self.check("DS5 R3 blocked after ordered admission", a["result"] == "BLOCKED"
                   and "owner_standing_revoked" in a["reason_codes"],
                   str(a["reason_codes"]))
        self.check("DS5 replayed seq-1 admit refused",
                   ds5["replay"]["outcomes"][0]["admitted"] is False,
                   str(ds5["replay"]["outcomes"]))

        # ---- global: zero VIOLATIONs ------------------------------------
        violations: list[str] = []
        for snap in ("ds1_ds2", "final"):
            for recv_dir in sorted((r / "snapshots" / snap).iterdir()):
                if not recv_dir.is_dir():
                    continue
                ledger = load_json(recv_dir / "commit_ledger.json")
                rd = rederived(recv_dir)
                for attempt in ledger.get("attempts", []):
                    v = rd[attempt["attempt_id"]]
                    if v["verdict"] == "ESCAPED":
                        violations.append(
                            f"{snap}/{recv_dir.name}/{attempt['attempt_label']}: ESCAPED")
                    if (attempt.get("execution_status") == "completed"
                            and v["verdict"] == "ESCAPED"):
                        violations.append(
                            f"{snap}/{recv_dir.name}/{attempt['attempt_label']}: committed+ESCAPED")
        self.check("zero VIOLATIONs (no ESCAPED anywhere)", not violations,
                   "; ".join(violations))

        # No committed attempt may postdate its receiver's REVOKED admission
        # or its ACTIVE head expiry: covered by the ESCAPED/expiry checks
        # above; the journal's standing_final_check_v1 is the evidence.

        failed = [c for c in self.checks if not c["ok"]]
        return {
            "schema": "openline.distributed_stop_001.appraisal.v1",
            "run_dir": str(self.run_dir),
            "total_checks": len(self.checks),
            "failed_checks": len(failed),
            "terminal": "PASS" if not failed else "FAIL",
            "checks": self.checks,
        }


def main() -> None:
    run_dir = Path(sys.argv[1])
    result = Appraisal(run_dir).run()
    (run_dir / "appraisal.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"terminal={result['terminal']} failed={result['failed_checks']}/{result['total_checks']}")
    for c in result["checks"]:
        if not c["ok"]:
            print(f"  FAILED: {c['name']} :: {c['detail']}")
    sys.exit(0 if result["terminal"] == "PASS" else 1)


if __name__ == "__main__":
    main()
