#!/usr/bin/env python3
"""POPPY-PROOF-001: full-path benchmark (Envoy -> authz -> mockapi).

Measures end-to-end latency for comparable successful operations:
- Baseline: /transfer via Envoy (delegated authority only, Poppy-native
  equivalent). Requires a valid Gateway decision token.
- Extended: /poppy-charge via Envoy (delegated + owner-signed exact
  terms). Requires decision token + Wallet approval.

Reports p50, p95, p99. Local only, not production claims.
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
ENVOY_BIN = Path.home() / "workspace" / ".envoy-binary"
N = 50


def http_post(url, body, headers, timeout=15):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, {}
    except Exception:
        return -1, {}


def wait_for(url, timeout=20.0):
    dl = time.time() + timeout
    while time.time() < dl:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.4)
    return False


def pct(data, p):
    s = sorted(data)
    idx = min(int(len(s) * p / 100), len(s) - 1)
    return s[idx]


def main():
    print(f"POPPY-PROOF-001 full-path benchmark (n={N})")
    print("Path: client -> Envoy :8080 -> authz :50051 -> mockapi :9000")
    print("Baseline: /transfer (delegated only). Extended: /poppy-charge.\n")

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

        owner_tmp = rundir / "owner"
        owner_tmp.mkdir()
        wallet = Wallet.create(str(owner_tmp))
        pid = wallet.principal_id
        root_pub = wallet.root_public_key

        subprocess.run([GW_PY, str(GWROOT / "gateway_admin.py"), "init"],
                       env=env, check=True, capture_output=True)
        r = subprocess.run(
            [GW_PY, str(GWROOT / "gateway_admin.py"),
             "provision-agent", "bench-agent", "--max-cents", "1000000"],
            env=env, check=True, capture_output=True, text=True)
        agent_key_b64 = json.loads(r.stdout)["agent_private_key"]

        pa = subprocess.Popen(
            [GW_PY, str(GWROOT / "authz_server.py"), "50051"], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(pa)

        env["POPPY_OWNER_PIN"] = f"{pid}|{root_pub}"
        env["MOCK_API_PORT"] = "9000"
        pm = subprocess.Popen(
            [GW_PY, str(GWROOT / "mock_api.py")], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(pm)
        assert wait_for("http://127.0.0.1:9000/health", 15)

        cfg_path = rundir / "envoy.yaml"
        cfg_path.write_text(
            (GWROOT / "envoy" / "envoy-openline.yaml").read_text())
        pe = subprocess.Popen([str(ENVOY_BIN), "-c", str(cfg_path)],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        procs.append(pe)
        time.sleep(4)

        # Baseline: /transfer needs a decision token. We'll use the
        # /transfer endpoint which requires x-ol-decision (from authz).
        # The authz mints it via Envoy ext_authz.
        def baseline_headers():
            c = AgentClient("bench-agent", agent_key_b64)
            h = c.headers_for("authorize_payment", target="ledger",
                              value_cents=100)
            h["Content-Type"] = "application/json"
            return h

        # Extended: /poppy-charge needs decision token + Wallet approval.
        akey = Ed25519PrivateKey.generate()
        now = datetime.now(timezone.utc)

        def make_extended_headers(idx):
            op = {
                "type": "charge", "merchant": "bench-merchant",
                "account": "treasury", "amount_cents": 100,
                "currency": "USD", "items": [],
                "order_ref": f"bench_{idx:04d}",
            }
            scope = mandate_scope_for_operation(op)
            m = wallet.grant(
                subject_id=f"bench-subj-{idx}",
                subject_public_key=public_key_hex(akey),
                scopes=[scope], expires_at=now + timedelta(hours=1))
            mid = m["data"]["mandate_id"]
            bundle = wallet.export_bundle(ttl_seconds=300)
            http_post("http://127.0.0.1:9000/poppy-admit", {"bundle": bundle},
                      {"Content-Type": "application/json"})
            scode, rch = http_post(
                "http://127.0.0.1:9000/poppy-challenge",
                {"principal_id": pid, "subject_id": f"bench-subj-{idx}",
                 "action": scope},
                {"Content-Type": "application/json"})
            pres = worker_present(
                bundle=bundle, mandate_id=mid,
                subject_id=f"bench-subj-{idx}", subject_key=akey,
                action=scope, challenge=rch["challenge"])
            tx = {"presentation": pres, "principal_id": pid,
                  "operation": op}
            appr = base64.urlsafe_b64encode(
                json.dumps(tx).encode()).rstrip(b"=").decode()
            c = AgentClient("bench-agent", agent_key_b64)
            h = c.headers_for("authorize_payment", target="ledger",
                              value_cents=100)
            h["Content-Type"] = "application/json"
            h["x-ol-tx-approval"] = appr
            return h, op

        # Warmup.
        for _ in range(5):
            http_post("http://127.0.0.1:8080/api/transfer",
                      {"to": "vendor", "cents": 100}, baseline_headers())

        # Benchmark baseline.
        base_lat = []
        for _ in range(N):
            t0 = time.perf_counter()
            s, _ = http_post("http://127.0.0.1:8080/api/transfer",
                             {"to": "vendor", "cents": 100},
                             baseline_headers())
            if s == 200:
                base_lat.append((time.perf_counter() - t0) * 1000)

        # Benchmark extended.
        ext_lat = []
        for i in range(N):
            h, op = make_extended_headers(i)
            t0 = time.perf_counter()
            s, _ = http_post("http://127.0.0.1:8080/api/poppy-charge",
                             {"operation": op}, h)
            if s == 200:
                ext_lat.append((time.perf_counter() - t0) * 1000)

        print(f"Baseline (delegated only, n={len(base_lat)}):")
        print(f"  p50 {statistics.median(base_lat):7.2f} ms")
        print(f"  p95 {pct(base_lat, 95):7.2f} ms")
        print(f"  p99 {pct(base_lat, 99):7.2f} ms")
        print(f"\nExtended (delegated + approval, n={len(ext_lat)}):")
        print(f"  p50 {statistics.median(ext_lat):7.2f} ms")
        print(f"  p95 {pct(ext_lat, 95):7.2f} ms")
        print(f"  p99 {pct(ext_lat, 99):7.2f} ms")
        d50 = statistics.median(ext_lat) - statistics.median(base_lat)
        d95 = pct(ext_lat, 95) - pct(base_lat, 95)
        d99 = pct(ext_lat, 99) - pct(base_lat, 99)
        print(f"\nIncremental (extended - baseline):")
        print(f"  p50 +{d50:.2f} ms")
        print(f"  p95 +{d95:.2f} ms")
        print(f"  p99 +{d99:.2f} ms")
        print("\nNote: local only, includes Envoy+authz+mockapi. "
              "Not production claims.")
    finally:
        stop_all()
        shutil.rmtree(rundir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
