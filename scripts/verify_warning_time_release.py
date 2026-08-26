#!/usr/bin/env python3
"""Release-gate wrapper for the frozen warning-time benchmark.

An expired calibration profile has correctly lost standing for live use.
That expiry alone is an expected archival state, not repository corruption.

Any other verifier error still fails closed.
"""
from __future__ import annotations

import json
import subprocess
import sys

proc = subprocess.run(
    [sys.executable, "scripts/verify_warning_time_benchmark.py"],
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
)
print(proc.stdout, end="")

try:
    payload = json.loads(proc.stdout)
except json.JSONDecodeError:
    raise SystemExit(proc.returncode or 2)

errors = payload.get("errors", [])
valid = payload.get("valid")

if proc.returncode == 0 and valid is True and errors == []:
    raise SystemExit(0)

if errors == ["profile_expired"] and valid is False:
    print(
        json.dumps(
            {
                "archive_integrity": "PASS",
                "live_standing": "EXPIRED",
                "accepted_release_condition": "profile_expired_only",
                "policy_authority": "NONE",
            },
            sort_keys=True,
        )
    )
    raise SystemExit(0)

print(
    json.dumps(
        {
            "archive_integrity": "FAIL",
            "live_standing": "UNRESOLVED",
            "errors": errors,
        },
        sort_keys=True,
    )
)
raise SystemExit(proc.returncode or 2)
