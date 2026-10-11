#!/usr/bin/env python3
"""POPPY-PROOF-001: Gateway integration test — delegated vs transaction approval.

Tests through the ACTUAL business API (real mock_api.py process):
  Test client -> mockapi :9000 /poppy-charge -> ledger

The /poppy-charge endpoint enforces the strict distinction:
1. Delegated authority: verified via Gateway DB (agent signature +
   mandate limits). Proves the AGENT is permitted. Uses the REAL
   Gateway provisioning (gateway_admin.py) and REAL signature
   verification (same crypto as authz_server.py).
2. Transaction approval: verified via Wallet (owner-signed exact terms).
   Proves the HUMAN approved THIS transaction. Uses the REAL vendored
   Wallet contracts.

Test cases:
- Delegated only (no tx approval) -> 403 DELEGATED_AUTHORITY_NOT_TRANSACTION_APPROVAL.
- Delegated + valid tx approval -> 200, ledger moves exactly.
- Delegated + tx approval for different terms -> 403 TRANSACTION_TERMS_MISMATCH.
- Delegated + revoked tx approval -> 403 TRANSACTION_APPROVAL_INVALID.
- Invalid delegated (bad signature) -> 403.
- Tx approval exceeding delegated limit -> 403 DELEGATED_LIMIT_EXCEEDED.

Fictional owner, agent, merchant, funds. No real payments.
Exit 0 only if every assertion holds.
"""

from __future__ import annotations

import base64
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
PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((PASS if cond else FAIL, name))
    print(f"[{PASS if cond else FAIL}] {name}" + (f" — {detail}" if detail else ""))


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


def http_post(url: str, body: dict, headers: dict) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except Exception as e:
        return -1, {"error": str(e)}


def http_get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())


def main() -> int:
    print("POPPY-PROOF-001 Gateway integration test")
    print("Path: client -> mockapi :9000 /poppy-charge (real process) -> ledger")
    print("Delegated authority: real Gateway DB + signature verification")
    print("Transaction approval: real Wallet contracts\n")

    rundir = Path(tempfile.mkdtemp(prefix="poppy-gw-"))
    cfgdir = rundir / "config"
    statedir = rundir / "state"
    cfgdir.mkdir(parents=True)
    statedir.mkdir(parents=True)
    procs: list[subprocess.Popen] = []

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
                try:
                    p.kill()
                except Exception:
                    pass

    try:
        env = dict(os.environ)
        env["GATEWAY_CONFIG"] = str(cfgdir)
        env["GATEWAY_DB"] = str(statedir / "gateway.db")
        env["PYTHONPATH"] = str(GWROOT) + ":" + env.get("PYTHONPATH", "")

        # ---- Owner: Wallet for transaction approvals ----
        owner_tmp = rundir / "owner-wallet"
        owner_tmp.mkdir()
        wallet = Wallet.create(str(owner_tmp))
        principal_id = wallet.principal_id
        root_pub = wallet.root_public_key
        print(f"owner principal: {principal_id[:32]}...")

        # ---- Gateway: init + provision agent (delegated authority) ----
        print("== gateway init")
        subprocess.run([GW_PY, str(GWROOT / "gateway_admin.py"), "init"],
                       env=env, check=True, capture_output=True)
        print("== provision agent (delegated: up to $50)")
        r = subprocess.run(
            [GW_PY, str(GWROOT / "gateway_admin.py"),
             "provision-agent", "poppy-agent", "--max-cents", "5000"],
            env=env, check=True, capture_output=True, text=True)
        agent_key_b64 = json.loads(r.stdout)["agent_private_key"]

        # ---- Start real mockapi ----
        print("== start mockapi :9000")
        env["POPPY_OWNER_PIN"] = f"{principal_id}|{root_pub}"
        env["MOCK_API_PORT"] = "9000"
        env["GATEWAY_DB"] = str(statedir / "gateway.db")
        logf = (rundir / "mockapi.log").open("w")
        pm = subprocess.Popen(
            [GW_PY, str(GWROOT / "mock_api.py")],
            env=env, stdout=logf, stderr=subprocess.STDOUT)
        procs.append(pm)
        if not wait_for("http://127.0.0.1:9000/health", 15):
            print("mockapi did not start")
            return 2
        print("== mockapi ready\n")

        # ---- Setup: operation, mandate, bundle ----
        operation = {
            "type": "charge",
            "merchant": "manzanita-supply",
            "account": "treasury",
            "amount_cents": 4250,
            "currency": "USD",
            "items": [{"sku": "JKT-RAIN-042", "qty": 1, "price_cents": 4250}],
            "order_ref": "ord_gw_001",
        }
        scope = mandate_scope_for_operation(operation)
        agent_key = Ed25519PrivateKey.generate()
        now = datetime.now(timezone.utc)
        mandate = wallet.grant(
            subject_id="poppy-agent",
            subject_public_key=public_key_hex(agent_key),
            scopes=[scope],
            expires_at=now + timedelta(hours=1),
        )
        mandate_id = mandate["data"]["mandate_id"]
        bundle = wallet.export_bundle(ttl_seconds=300)

        # Admit bundle to mockapi's verifier.
        sa, ra = http_post("http://127.0.0.1:9000/poppy-admit",
                           {"bundle": bundle},
                           {"Content-Type": "application/json"})
        check("authority bundle admitted", sa == 200 and ra.get("ok") is True)

        def make_tx_approval(op: dict, bndl: dict, mid: str) -> str:
            sc = mandate_scope_for_operation(op)
            scode, rch = http_post(
                "http://127.0.0.1:9000/poppy-challenge",
                {"principal_id": principal_id, "subject_id": "poppy-agent",
                 "action": sc},
                {"Content-Type": "application/json"})
            assert scode == 200, f"challenge failed: {rch}"
            pres = worker_present(
                bundle=bndl, mandate_id=mid, subject_id="poppy-agent",
                subject_key=agent_key, action=sc, challenge=rch["challenge"])
            tx = {"presentation": pres, "principal_id": principal_id,
                  "operation": op}
            return base64.urlsafe_b64encode(
                json.dumps(tx).encode()).rstrip(b"=").decode()

        def delegated_headers(value_cents: int) -> dict:
            client = AgentClient("poppy-agent", agent_key_b64)
            h = client.headers_for("authorize_payment", target="ledger",
                                   value_cents=value_cents)
            h["Content-Type"] = "application/json"
            return h

        url = "http://127.0.0.1:9000/poppy-charge"
        body = {"operation": operation}

        # ---- Case 1: Delegated ONLY ----
        print("\n--- Case 1: delegated authority without transaction approval")
        s1, r1 = http_post(url, body, delegated_headers(4250))
        check("delegated-only -> 403", s1 == 403, f"status {s1}")
        check("reason DELEGATED_AUTHORITY_NOT_TRANSACTION_APPROVAL",
              r1.get("error") == "DELEGATED_AUTHORITY_NOT_TRANSACTION_APPROVAL",
              f"error={r1.get('error')}")
        check("delegated marked valid", r1.get("delegated_authority") == "valid")
        check("approval marked missing",
              r1.get("transaction_approval") == "missing")

        # ---- Case 2: Delegated + valid approval ----
        print("\n--- Case 2: delegated + owner-approved exact transaction")
        h2 = delegated_headers(4250)
        h2["x-ol-tx-approval"] = make_tx_approval(operation, bundle, mandate_id)
        s2, r2 = http_post(url, body, h2)
        check("delegated+approval -> 200", s2 == 200,
              f"status {s2}, error={r2.get('error')}")
        pr = r2.get("poppy_receipt", {})
        check("receipt documents both verifications",
              "verified" in pr.get("delegated_authority", "")
              and "verified" in pr.get("transaction_approval", ""),
              f"{pr}")
        check("receipt has operation hash",
              bool(pr.get("operation_hash")))
        tb = http_get("http://127.0.0.1:9000/balance/treasury")["cents"]
        mb = http_get("http://127.0.0.1:9000/balance/manzanita-supply")["cents"]
        check("ledger moved exactly $42.50",
              tb == 1000000 - 4250 and mb == 4250,
              f"treasury={tb} merchant={mb}")

        # ---- Case 3: Terms mismatch ----
        print("\n--- Case 3: approval for different terms than requested")
        # The tx approval is for the $42.50 operation at manzanita-supply,
        # but the request changes the merchant. The hashes don't match.
        tampered = {"operation": dict(operation, merchant="evil-corp")}
        h3 = delegated_headers(4250)
        h3["x-ol-tx-approval"] = make_tx_approval(operation, bundle, mandate_id)
        s3, r3 = http_post(url, tampered, h3)
        check("terms mismatch -> 403", s3 == 403, f"status {s3}")
        check("reason TRANSACTION_TERMS_MISMATCH",
              r3.get("error") == "TRANSACTION_TERMS_MISMATCH",
              f"error={r3.get('error')}")

        # ---- Case 4: Revoked approval ----
        print("\n--- Case 4: revoked transaction approval")
        wallet.revoke(mandate_id, reason="USER_REVOKED")
        bundle_v2 = wallet.export_bundle(ttl_seconds=300)
        sa2, _ = http_post("http://127.0.0.1:9000/poppy-admit",
                           {"bundle": bundle_v2},
                           {"Content-Type": "application/json"})
        check("revocation admitted", sa2 == 200)
        h4 = delegated_headers(4250)
        h4["x-ol-tx-approval"] = make_tx_approval(operation, bundle_v2,
                                                  mandate_id)
        s4, r4 = http_post(url, body, h4)
        check("revoked -> 403", s4 == 403, f"status {s4}")
        check("reason TRANSACTION_APPROVAL_INVALID",
              r4.get("error") == "TRANSACTION_APPROVAL_INVALID",
              f"error={r4.get('error')}")
        check("revocation surfaced",
              any("REVOKED" in str(x) for x in r4.get("reasons", [])))

        # ---- Case 5: Invalid delegated (bad signature) ----
        print("\n--- Case 5: invalid delegated authority")
        bad_key = Ed25519PrivateKey.generate()
        import base64 as _b64
        bad_b64 = _b64.urlsafe_b64encode(
            bad_key.private_bytes_raw()).rstrip(b"=").decode()
        bad_client = AgentClient("poppy-agent", bad_b64)
        h5 = bad_client.headers_for("authorize_payment", target="ledger",
                                    value_cents=4250)
        h5["Content-Type"] = "application/json"
        h5["x-ol-tx-approval"] = make_tx_approval(operation, bundle_v2,
                                                  mandate_id)
        s5, r5 = http_post(url, body, h5)
        check("bad signature -> 403", s5 == 403, f"status {s5}")

        # ---- Case 6: Approval exceeds delegated limit ----
        print("\n--- Case 6: approval amount exceeds delegated limit")
        # New mandate for $99.99 (owner approves), but delegated limit $50.
        big_op = dict(operation, amount_cents=9999,
                      order_ref="ord_gw_002")
        big_scope = mandate_scope_for_operation(big_op)
        big_key = Ed25519PrivateKey.generate()
        big_m = wallet.grant(
            subject_id="poppy-agent-2",
            subject_public_key=public_key_hex(big_key),
            scopes=[big_scope],
            expires_at=now + timedelta(hours=1),
        )
        big_mid = big_m["data"]["mandate_id"]
        big_bundle = wallet.export_bundle(ttl_seconds=300)
        http_post("http://127.0.0.1:9000/poppy-admit", {"bundle": big_bundle},
                  {"Content-Type": "application/json"})
        sc = big_scope
        scode, rch = http_post(
            "http://127.0.0.1:9000/poppy-challenge",
            {"principal_id": principal_id, "subject_id": "poppy-agent-2",
             "action": sc},
            {"Content-Type": "application/json"})
        big_pres = worker_present(
            bundle=big_bundle, mandate_id=big_mid,
            subject_id="poppy-agent-2", subject_key=big_key,
            action=sc, challenge=rch["challenge"])
        big_tx = {"presentation": big_pres, "principal_id": principal_id,
                  "operation": big_op}
        # Delegated headers authorize up to the $50 limit (valid), but the
        # transaction approval is for $99.99 (exceeds delegated limit).
        h6 = delegated_headers(4250)
        h6["x-ol-tx-approval"] = base64.urlsafe_b64encode(
            json.dumps(big_tx).encode()).rstrip(b"=").decode()
        s6, r6 = http_post(url, {"operation": big_op}, h6)
        check("exceeds delegated limit -> 403", s6 == 403, f"status {s6}")
        check("reason DELEGATED_LIMIT_EXCEEDED",
              r6.get("error") == "DELEGATED_LIMIT_EXCEEDED",
              f"error={r6.get('error')}")

    finally:
        stop_all()
        shutil.rmtree(rundir, ignore_errors=True)

    n_fail = sum(1 for s, _ in results if s == FAIL)
    print(f"\n{len(results) - n_fail}/{len(results)} checks passed")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
