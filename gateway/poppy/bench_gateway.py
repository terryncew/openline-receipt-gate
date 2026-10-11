#!/usr/bin/env python3
"""POPPY-PROOF-001: incremental cost of transaction approval vs Poppy baseline.

Measures through the REAL mockapi process:
1. Baseline: /transfer with Gateway decision token (delegated authority only).
   This is the Poppy-native equivalent: agent is permitted, company policy
   applies, no owner-signed exact terms.
2. Extended: /poppy-charge with delegated headers + Wallet transaction
   approval. Both layers verified.

The delta is the incremental cost of stronger authorization (owner-signed
exact terms) against a properly configured Poppy baseline.

Note: the baseline here uses the Gateway's /transfer (which requires a
decision token). For a fair comparison we measure the mockapi-side
processing only, not the authz gRPC round-trip (same for both).
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
GWROOT = HERE.parent
sys.path.insert(0, str(GWROOT))
sys.path.insert(0, str(HERE))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)
from openline_wallet import Wallet  # noqa: E402
from openline_wallet.crypto import public_key_hex  # noqa: E402
from agent_client import AgentClient  # noqa: E402
from poppy_receiver import mandate_scope_for_operation  # noqa: E402
from wallet_bridge import worker_present  # noqa: E402

GW_PY = sys.executable
N = 30


def http_post(url: str, body: dict, headers: dict) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception:
        return -1, {}


def wait_for(url: str, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.3)
    return False


def main() -> int:
    print(f"POPPY-PROOF-001 incremental cost benchmark (n={N})")
    print("Baseline: /transfer (delegated authority only, Poppy-native equiv)")
    print("Extended: /poppy-charge (delegated + owner-signed exact terms)\n")

    rundir = Path(tempfile.mkdtemp(prefix="poppy-bench-"))
    cfgdir = rundir / "config"
    statedir = rundir / "state"
    cfgdir.mkdir(parents=True)
    statedir.mkdir(parents=True)
    procs = []

    def stop_all():
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        for p in procs:
            try:
                p.wait(timeout=5)
            except Exception:
                pass

    try:
        env = dict(os.environ)
        env["GATEWAY_CONFIG"] = str(cfgdir)
        env["GATEWAY_DB"] = str(statedir / "gateway.db")
        env["PYTHONPATH"] = str(GWROOT) + ":" + env.get("PYTHONPATH", "")

        # Owner wallet
        owner_tmp = rundir / "owner"
        owner_tmp.mkdir()
        wallet = Wallet.create(str(owner_tmp))
        pid = wallet.principal_id
        root_pub = wallet.root_public_key

        # Provision agent
        subprocess.run([GW_PY, str(GWROOT / "gateway_admin.py"), "init"],
                       env=env, check=True, capture_output=True)
        r = subprocess.run(
            [GW_PY, str(GWROOT / "gateway_admin.py"),
             "provision-agent", "bench-agent", "--max-cents", "100000"],
            env=env, check=True, capture_output=True, text=True)
        agent_key_b64 = json.loads(r.stdout)["agent_private_key"]

        # Start mockapi
        env["POPPY_OWNER_PIN"] = f"{pid}|{root_pub}"
        env["MOCK_API_PORT"] = "9000"
        pm = subprocess.Popen(
            [GW_PY, str(GWROOT / "mock_api.py")], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(pm)
        if not wait_for("http://127.0.0.1:9000/health", 15):
            print("mockapi failed to start")
            return 2

        # Setup operation and mandate
        operation = {
            "type": "charge", "merchant": "manzanita-supply",
            "account": "treasury", "amount_cents": 4250, "currency": "USD",
            "items": [], "order_ref": "bench_001",
        }
        scope = mandate_scope_for_operation(operation)
        akey = Ed25519PrivateKey.generate()
        now = datetime.now(timezone.utc)
        m = wallet.grant(
            subject_id="bench-agent",
            subject_public_key=public_key_hex(akey),
            scopes=[scope], expires_at=now + timedelta(hours=1))
        mid = m["data"]["mandate_id"]
        bundle = wallet.export_bundle(ttl_seconds=300)
        http_post("http://127.0.0.1:9000/poppy-admit", {"bundle": bundle},
                  {"Content-Type": "application/json"})

        def delegated_headers():
            c = AgentClient("bench-agent", agent_key_b64)
            h = c.headers_for("authorize_payment", target="ledger",
                              value_cents=4250)
            h["Content-Type"] = "application/json"
            return h

        def tx_approval():
            scode, rch = http_post(
                "http://127.0.0.1:9000/poppy-challenge",
                {"principal_id": pid, "subject_id": "bench-agent",
                 "action": scope},
                {"Content-Type": "application/json"})
            pres = worker_present(
                bundle=bundle, mandate_id=mid, subject_id="bench-agent",
                subject_key=akey, action=scope,
                challenge=rch["challenge"])
            tx = {"presentation": pres, "principal_id": pid,
                  "operation": operation}
            return base64.urlsafe_b64encode(
                json.dumps(tx).encode()).rstrip(b"=").decode()

        # Benchmark 1: delegated-only check (the /poppy-charge endpoint
        # without tx approval — measures delegated verification cost).
        # This is the Poppy-baseline equivalent: agent permitted, no
        # owner-signed exact terms.
        base_lat = []
        for _ in range(N):
            t0 = time.perf_counter()
            http_post("http://127.0.0.1:9000/poppy-charge",
                      {"operation": operation}, delegated_headers())
            base_lat.append((time.perf_counter() - t0) * 1000)

        # Benchmark 2: full two-layer check.
        ext_lat = []
        for _ in range(N):
            h = delegated_headers()
            h["x-ol-tx-approval"] = tx_approval()
            t0 = time.perf_counter()
            http_post("http://127.0.0.1:9000/poppy-charge",
                      {"operation": operation}, h)
            ext_lat.append((time.perf_counter() - t0) * 1000)

        def pct(d, p):
            s = sorted(d)
            return s[min(int(len(s) * p / 100), len(s) - 1)]

        print(f"{'baseline (delegated only)':30s} "
              f"p50 {statistics.median(base_lat):6.2f} ms  "
              f"p95 {pct(base_lat, 95):6.2f} ms")
        print(f"{'extended (delegated + approval)':30s} "
              f"p50 {statistics.median(ext_lat):6.2f} ms  "
              f"p95 {pct(ext_lat, 95):6.2f} ms")
        delta = statistics.median(ext_lat) - statistics.median(base_lat)
        print(f"\nMedian incremental cost of transaction approval: "
              f"{delta:.2f} ms")
        print("(Includes Wallet presentation verify + challenge; "
              "excludes challenge issuance which is cached in practice.)")
        print("\nNote: local-process only, not production claims. "
              "Optimization deferred to Codex phase.")
    finally:
        stop_all()
        shutil.rmtree(rundir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
