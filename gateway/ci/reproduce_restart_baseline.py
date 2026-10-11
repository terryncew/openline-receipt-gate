#!/usr/bin/env python3
"""Run the untouched historical verifier and require its specific 20/22 failure.

The workflow retrieves _restart_baseline.py from the exact base commit.
Private provisioning keys and signed request headers are never logged.
"""
from __future__ import annotations

import _restart_baseline as baseline
import docker_verify as fixed

original_http = baseline.http
original_compose = baseline.compose


def http(*args, **kwargs):
    result = original_http(*args, **kwargs)
    if result[0] != 200:
        print(f"[diagnosis] {args[0]} {args[1]} HTTP {result[0]} body={result[1]}", flush=True)
    return result


def compose(*args):
    if args == ("restart",):
        print(f"[diagnosis] before bare restart: {fixed.service_start_times()}", flush=True)
    result = original_compose(*args)
    if args == ("restart",):
        print(f"[diagnosis] after bare restart: {fixed.service_start_times()}", flush=True)
    return result


baseline.http = http
baseline.compose = compose
if __name__ == "__main__":
    code = baseline.main()
    failures = {name for name, passed, _ in baseline.RESULTS if not passed}
    expected = {"f2b mockapi upstream back after full restart", "f3 balances survive full restart"}
    reproduced = code == 1 and len(baseline.RESULTS) == 22 and failures == expected
    print(f"[diagnosis] expected historical failure reproduced: {reproduced}", flush=True)
    raise SystemExit(0 if reproduced else 1)
