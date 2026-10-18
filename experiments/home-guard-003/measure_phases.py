"""HOME-GUARD-004: monotonic phase timing for policy application.

Wraps policy_gate's phase functions WITHOUT modifying policy_gate.py.
Import this module and call timed_apply() instead of policy_gate.run().

Phases measured (monotonic, microseconds):
  t_submit          - before validate_signed
  t_validated       - after validate_signed returns
  t_kernel_start    - before apply_kernel
  t_conntrack_start - before conntrack -D invocation
  t_conntrack_end   - after conntrack -D returns
  t_kernel_end      - after apply_kernel returns (rules verified from kernel)
  t_receipt         - after signed receipt written

Usage (inside hg3-fw namespace):
  python measure_phases.py --policy <file> --ledger <db> --receipts <jsonl> \
      --snapshot <rules> --timings-out <json>
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

EXP = Path(__file__).resolve().parent
ROOT = EXP.parents[1]
for folder in (str(EXP.parents[0] / "home-guard-001"), str(ROOT)):
    if folder not in sys.path:
        sys.path.insert(0, folder)
sys.path.insert(0, str(EXP))

import policy_gate

TIMINGS: dict = {}


def now_us() -> int:
    return time.monotonic_ns() // 1000


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", required=True, type=Path)
    ap.add_argument("--ledger", required=True, type=Path)
    ap.add_argument("--receipts", required=True, type=Path)
    ap.add_argument("--snapshot", required=True, type=Path)
    ap.add_argument("--timings-out", required=True, type=Path)
    a = ap.parse_args()

    # Wrap validate_signed
    orig_validate = policy_gate.validate_signed

    def timed_validate(raw: bytes) -> dict:
        TIMINGS["t_submit"] = now_us()
        result = orig_validate(raw)
        TIMINGS["t_validated"] = now_us()
        return result

    # Wrap apply_kernel, with finer conntrack timing via subprocess interception
    orig_apply = policy_gate.apply_kernel
    orig_subprocess_run = subprocess.run

    def timed_subprocess_run(*args, **kwargs):
        cmd = args[0] if args else kwargs.get("args", [])
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
        is_conntrack = "conntrack" in cmd_str and "-D" in cmd_str
        if is_conntrack:
            TIMINGS["t_conntrack_start"] = now_us()
        result = orig_subprocess_run(*args, **kwargs)
        if is_conntrack:
            TIMINGS["t_conntrack_end"] = now_us()
            TIMINGS["conntrack_exit"] = result.returncode
            TIMINGS["conntrack_output"] = (result.stdout or "")[:200]
        return result

    def timed_apply(allow_tv: bool) -> str:
        TIMINGS["t_kernel_start"] = now_us()
        # Intercept conntrack invocation inside apply_kernel
        policy_gate.subprocess.run = timed_subprocess_run
        try:
            digest = orig_apply(allow_tv)
        finally:
            policy_gate.subprocess.run = orig_subprocess_run
        TIMINGS["t_kernel_end"] = now_us()
        return digest

    # Wrap record (receipt issuance)
    orig_record = policy_gate.record

    def timed_record(receipts: Path, **kwargs) -> dict:
        result = orig_record(receipts, **kwargs)
        TIMINGS["t_receipt"] = now_us()
        return result

    policy_gate.validate_signed = timed_validate
    policy_gate.apply_kernel = timed_apply
    policy_gate.record = timed_record

    try:
        rc = policy_gate.run(a.policy, a.ledger, a.receipts, a.snapshot)
    finally:
        policy_gate.validate_signed = orig_validate
        policy_gate.apply_kernel = orig_apply
        policy_gate.record = orig_record
        policy_gate.subprocess.run = orig_subprocess_run

    # Derive phase durations
    t = TIMINGS
    phases = {}
    if "t_submit" in t and "t_validated" in t:
        phases["validation_us"] = t["t_validated"] - t["t_submit"]
    if "t_kernel_start" in t and "t_kernel_end" in t:
        phases["kernel_apply_us"] = t["t_kernel_end"] - t["t_kernel_start"]
    if "t_conntrack_start" in t and "t_conntrack_end" in t:
        phases["conntrack_evict_us"] = t["t_conntrack_end"] - t["t_conntrack_start"]
    if "t_kernel_end" in t and "t_receipt" in t:
        phases["receipt_issuance_us"] = t["t_receipt"] - t["t_kernel_end"]
    if "t_submit" in t and "t_receipt" in t:
        phases["submit_to_receipt_us"] = t["t_receipt"] - t["t_submit"]

    out = {"monotonic_timings_us": t, "phase_durations_us": phases,
           "returncode": rc}
    a.timings_out.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
    print("TIMED_APPLY_PHASES=" + json.dumps(phases, sort_keys=True), flush=True)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
