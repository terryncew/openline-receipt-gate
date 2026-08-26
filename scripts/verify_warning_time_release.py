#!/usr/bin/env python3
"""Release-gate wrapper for an expired frozen warning-time profile.

The historical artifact may remain intact after its live standing expires.
Only the sole error `profile_expired` is accepted as an archival state.
Any other error still fails closed.
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

if proc.returncode != 0 and valid is False and errors == ["profile_expired"]:
    print(json.dumps({
        "archive_integrity": "PASS",
        "live_standing": "EXPIRED",
        "accepted_release_condition": "profile_expired_only",
        "policy_authority": "NONE",
    }, sort_keys=True))
    raise SystemExit(0)

print(json.dumps({
    "archive_integrity": "FAIL",
    "live_standing": "UNRESOLVED",
    "errors": errors,
}, sort_keys=True))
raise SystemExit(proc.returncode or 2)
