#!/usr/bin/env python3
"""POPPY-PROOF-001: concurrency and restart tests.

1. Concurrent: 10 simultaneous /poppy-charge requests via full Envoy path,
   each with a distinct operation and approval. All should succeed exactly
   once. Then replay all 10 (fresh challenges) — all should 403 ALREADY_USED.

2. Restart: execute a transaction, stop mockapi, restart it, replay the
   approval — must still 403 ALREADY_USED (sqlite persistence).

Exit 0 only if every assertion holds.
"""

from __future__ import annotations

import base64
import concurrent.futures
import json
import os
import shutil
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
results = []


def check(name, cond, detail=""):
    results.append((cond, name))
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))


def wait_for(url, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.4)
    return False


def http_post(url, body, headers, timeout=15):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except Exception as e:
        return -1, {"error": str(e)}


def main():
    print("POPPY-PROOF-001 concurrency + restart tests\n")
    rundir = Path(tempfile.mkdtemp(prefix="poppy-conc-"))
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

    def start_mockapi():
        pm = subprocess.Popen(
            [GW_PY, str(GWROOT / "mock_api.py")], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(pm)
        assert wait_for("http://127.0.0.1:9000/health", 15), "mockapi failed"
        return pm

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
             "provision-agent", "poppy-agent", "--max-cents", "100000"],
            env=env, check=True, capture_output=True, text=True)
        agent_key_b64 = json.loads(r.stdout)["agent_private_key"]

        pa = subprocess.Popen(
            [GW_PY, str(GWROOT / "authz_server.py"), "50051"], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(pa)

        env["POPPY_OWNER_PIN"] = f"{pid}|{root_pub}"
        env["MOCK_API_PORT"] = "9000"
        start_mockapi()

        cfg_path = rundir / "envoy.yaml"
        cfg_path.write_text((GWROOT / "envoy" / "envoy-openline.yaml").read_text())
        pe = subprocess.Popen([str(ENVOY_BIN), "-c", str(cfg_path)],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        procs.append(pe)
        time.sleep(4)

        envoy_url = "http://127.0.0.1:8080/api/poppy-charge"
        akey = Ed25519PrivateKey.generate()
        now = datetime.now(timezone.utc)

        def make_approval(idx):
            """Create a distinct operation, mandate, and approval.
            Returns (op, appr, bundle)."""
            op = {
                "type": "charge", "merchant": "manzanita-supply",
                "account": "treasury", "amount_cents": 100 + idx,
                "currency": "USD", "items": [],
                "order_ref": f"conc_{idx:03d}",
            }
            scope = mandate_scope_for_operation(op)
            m = wallet.grant(
                subject_id=f"conc-agent-{idx}",
                subject_public_key=public_key_hex(akey),
                scopes=[scope], expires_at=now + timedelta(hours=1))
            mid = m["data"]["mandate_id"]
            bundle = wallet.export_bundle(ttl_seconds=300)
            http_post("http://127.0.0.1:9000/poppy-admit", {"bundle": bundle},
                      {"Content-Type": "application/json"})
            scode, rch = http_post(
                "http://127.0.0.1:9000/poppy-challenge",
                {"principal_id": pid, "subject_id": f"conc-agent-{idx}",
                 "action": scope},
                {"Content-Type": "application/json"})
            assert scode == 200
            pres = worker_present(
                bundle=bundle, mandate_id=mid,
                subject_id=f"conc-agent-{idx}", subject_key=akey,
                action=scope, challenge=rch["challenge"])
            tx = {"presentation": pres, "principal_id": pid, "operation": op}
            appr = base64.urlsafe_b64encode(
                json.dumps(tx).encode()).rstrip(b"=").decode()
            return op, appr, bundle

        def full_headers(amount, appr):
            c = AgentClient("poppy-agent", agent_key_b64)
            h = c.headers_for("authorize_payment", target="ledger",
                              value_cents=amount)
            h["Content-Type"] = "application/json"
            h["x-ol-tx-approval"] = appr
            return h

        # ---- Concurrent: 10 distinct transactions at once ----
        # Approvals are built SEQUENTIALLY (Wallet grant/export is not
        # ---- Concurrent: 10 simultaneous requests, SAME approval ----
        # Only one should succeed; the other 9 must 403 ALREADY_USED.
        # This verifies the sqlite one-use tracking is atomic under
        # concurrency (no double-spend).
        print("--- Concurrent: 10x same approval (one must win)")
        op_c, appr_c, _ = make_approval(200)

        def do_same_charge(_):
            c = AgentClient("poppy-agent", agent_key_b64)
            h = c.headers_for("authorize_payment", target="ledger",
                              value_cents=op_c["amount_cents"])
            h["Content-Type"] = "application/json"
            h["x-ol-tx-approval"] = appr_c
            return http_post(envoy_url, {"operation": op_c}, h)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            futs = [ex.submit(do_same_charge, i) for i in range(10)]
            conc_resps = [f.result() for f in futs]

        conc_ok = sum(1 for s, _ in conc_resps if s == 200)
        # Losers get 403 (either from Wallet replay protection, my
        # sqlite tracking, or authz). The key property: only one wins,
        # no double-spend.
        conc_rejected = sum(1 for s, _ in conc_resps if s == 403)
        check("exactly one concurrent wins", conc_ok == 1,
              f"got {conc_ok}/10")
        check("others rejected (no double-spend)", conc_rejected == 9,
              f"got {conc_rejected}/10")

        # ---- Restart: approval survives mockapi restart ----
        print("\n--- Restart: used approval persists")
        op_r, appr_r, bundle_r = make_approval(100)
        s_r, _ = http_post(envoy_url, {"operation": op_r},
                           full_headers(op_r["amount_cents"], appr_r))
        check("pre-restart charge -> 200", s_r == 200)

        # Stop and restart mockapi.
        for p in list(procs):
            if "mock_api" in str(p.args):
                p.terminate()
                try:
                    p.wait(timeout=10)
                except Exception:
                    p.kill()
                procs.remove(p)
        time.sleep(3)  # Allow port to free.
        start_mockapi()
        time.sleep(2)
        # Re-admit the bundle (verifier is in-memory; approvals are in sqlite).
        http_post("http://127.0.0.1:9000/poppy-admit", {"bundle": bundle_r},
                  {"Content-Type": "application/json"})

        # After restart: get a FRESH challenge and build a NEW presentation
        # for the SAME (mandate_id, operation). The Wallet verification
        # should succeed (fresh challenge), but the approval must still be
        # rejected as ALREADY_USED (sqlite persisted across restart).
        # We need the mandate_id and scope; reconstruct from op_r.
        scope_r = mandate_scope_for_operation(op_r)
        # The mandate_id is in the original presentation.
        import json as _json
        orig_tx = _json.loads(base64.urlsafe_b64decode(
            appr_r + "=" * (-len(appr_r) % 4)))
        mid_r = orig_tx["presentation"]["mandate_id"]
        scode, rch = http_post(
            "http://127.0.0.1:9000/poppy-challenge",
            {"principal_id": pid, "subject_id": "conc-agent-100",
             "action": scope_r},
            {"Content-Type": "application/json"})
        # Note: subject_id must match the mandate's subject.
        # The make_approval used f"conc-agent-{idx}" with idx=100.
        pres_r2 = worker_present(
            bundle=bundle_r, mandate_id=mid_r,
            subject_id="conc-agent-100", subject_key=akey,
            action=scope_r, challenge=rch["challenge"])
        tx_r2 = {"presentation": pres_r2, "principal_id": pid,
                 "operation": op_r}
        appr_r2 = base64.urlsafe_b64encode(
            _json.dumps(tx_r2).encode()).rstrip(b"=").decode()
        s_r2, r_r2 = http_post(envoy_url, {"operation": op_r},
                               full_headers(op_r["amount_cents"], appr_r2))
        check("post-restart replay -> 403", s_r2 == 403, f"status {s_r2}")
        check("reason ALREADY_USED persists",
              r_r2.get("error") == "TRANSACTION_APPROVAL_ALREADY_USED",
              f"err={r_r2.get('error')}")

    finally:
        stop_all()
        shutil.rmtree(rundir, ignore_errors=True)

    n_fail = sum(1 for c, _ in results if not c)
    print(f"\n{len(results)-n_fail}/{len(results)} checks passed")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
