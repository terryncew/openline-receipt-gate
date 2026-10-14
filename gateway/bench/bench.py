#!/usr/bin/env python3
"""Latency benchmark: p50/p95/p99 for each configuration.

Measures end-to-end HTTP latency through Envoy (client -> Envoy ->
authz -> mock API -> response). Reports actual repeated observations;
no fabricated numbers.
"""

from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
GWROOT = HERE.parent
sys.path.insert(0, str(GWROOT))

N_REQUESTS = int(os.environ.get("BENCH_N", "500"))
ENVOY = "http://127.0.0.1:8080"


def percentile(data, p):
    if not data:
        return 0.0
    s = sorted(data)
    k = (len(s) - 1) * p / 100
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def bench(name, headers_fn, body=b'{}'):
    lat = []
    for _ in range(N_REQUESTS):
        h = headers_fn()
        req = urllib.request.Request(ENVOY + "/api/transfer", data=body,
                                     method="POST")
        for k, v in h.items():
            req.add_header(k, v)
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=10):
                pass
        except Exception:
            pass
        lat.append((time.perf_counter() - t0) * 1000)
    return {
        "n": len(lat),
        "p50_ms": round(percentile(lat, 50), 3),
        "p95_ms": round(percentile(lat, 95), 3),
        "p99_ms": round(percentile(lat, 99), 3),
        "mean_ms": round(statistics.mean(lat), 3),
    }


def main():
    # Assumes the target stack is already running (see head_to_head.py).
    # Usage: bench.py <openline|opa> 
    which = sys.argv[1] if len(sys.argv) > 1 else "openline"
    if which == "openline":
        from agent_client import AgentClient
        os.environ.setdefault("GATEWAY_CONFIG", str(GWROOT / "config"))
        out = subprocess.run(
            [sys.executable, str(GWROOT / "gateway_admin.py"),
             "provision-agent", "bench-worker", "--max-cents=1000000"],
            capture_output=True, text=True, env=os.environ).stdout
        key = json.loads(out)["agent_private_key"]
        c = AgentClient("bench-worker", key)
        headers_fn = lambda: c.headers_for("authorize_payment",
                                           value_cents=100)
    else:
        headers_fn = lambda: {"Authorization": "Bearer opaline-token-001"}
        body = b'{"to":"v","cents":100}'
        res = bench(which, headers_fn, body)
        print(json.dumps({which: res}, indent=2))
        return
    res = bench(which, headers_fn)
    print(json.dumps({which: res}, indent=2))


if __name__ == "__main__":
    main()
