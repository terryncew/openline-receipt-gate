#!/usr/bin/env python3
"""POPPY-PROOF-001: full-path Gateway integration test.

Complete request path (no substitutions):
  client -> Envoy :8080 -> authz :50051 (ext_authz) -> mockapi :9000 -> ledger

- Delegated authority: real Gateway authz verifies agent signature and
  mandate, mints decision token. Envoy injects x-ol-decision.
- Transaction approval: real Wallet contracts verify owner-signed exact
  terms. One-use semantics: second execution with fresh challenge fails.

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
    Ed25519PrivateKey, Ed25519PublicKey,
)

from openline_wallet import Wallet  # noqa: E402
from openline_wallet.crypto import public_key_hex  # noqa: E402
from agent_client import AgentClient  # noqa: E402
from poppy_receiver import mandate_scope_for_operation  # noqa: E402
from wallet_bridge import worker_present  # noqa: E402
# The verifier intentionally does NOT import mock_api: that would create
# receiver state and load the configured signing key before test setup.
def _b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


# Local end-to-end probes must not leak loopback traffic through a
# developer environment's HTTP(S) proxy (which can itself return 403).
_LOOPBACK = urllib.request.build_opener(urllib.request.ProxyHandler({}))

GW_PY = sys.executable
ENVOY_BIN = Path(os.environ.get("ENVOY_BIN", str(Path.home()
                                                / "workspace" / ".envoy-binary")))
PASS, FAIL = "PASS", "FAIL"
results: list[tuple[str, str]] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    results.append((PASS if cond else FAIL, name))
    print(f"[{PASS if cond else FAIL}] {name}" + (f" — {detail}" if detail else ""))


def wait_for(url: str, timeout: float = 20.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with _LOOPBACK.open(url, timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.4)
    return False


def http_post(url: str, body: dict, headers: dict) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method="POST")
    try:
        with _LOOPBACK.open(req, timeout=15) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except Exception as e:
        return -1, {"error": str(e)}


def http_get(url: str) -> dict:
    with _LOOPBACK.open(url, timeout=5) as r:
        return json.loads(r.read())


def verify_receipt_signature(receipt: dict) -> bool:
    """Independently verify the receiver's signature on the receipt."""
    sig_b64 = receipt.get("receiver_signature")
    pub_b64 = receipt.get("receiver_public_key")
    if not sig_b64 or not pub_b64:
        return False
    try:
        # Reconstruct the signed payload (receipt without signature fields).
        payload = {k: v for k, v in receipt.items()
                   if k not in ("receiver_signature", "receiver_public_key",
                                "signature_error")}
        pub = Ed25519PublicKey.from_public_bytes(_b64u_decode(pub_b64))
        pub.verify(_b64u_decode(sig_b64), _canonical(payload))
        return True
    except Exception:
        return False


def main() -> int:
    print("POPPY-PROOF-001 full-path Gateway integration test")
    print("Path: client -> Envoy :8080 -> authz :50051 -> mockapi :9000")
    print("No substitutions: real Gateway enforcement, real Wallet.\n")

    rundir = Path(tempfile.mkdtemp(prefix="poppy-full-"))
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

        # Owner wallet
        owner_tmp = rundir / "owner"
        owner_tmp.mkdir()
        wallet = Wallet.create(str(owner_tmp))
        principal_id = wallet.principal_id
        root_pub = wallet.root_public_key
        print(f"owner: {principal_id[:32]}...")

        # Gateway init + provision
        print("== gateway init")
        subprocess.run([GW_PY, str(GWROOT / "gateway_admin.py"), "init"],
                       env=env, check=True, capture_output=True)
        print("== provision agent (up to $50)")
        r = subprocess.run(
            [GW_PY, str(GWROOT / "gateway_admin.py"),
             "provision-agent", "poppy-agent", "--max-cents", "5000"],
            env=env, check=True, capture_output=True, text=True)
        agent_key_b64 = json.loads(r.stdout)["agent_private_key"]

        # Start authz
        print("== start authz :50051")
        palog = (rundir / "authz.log").open("w")
        pa = subprocess.Popen(
            [GW_PY, str(GWROOT / "authz_server.py"), "50051"],
            env=env, stdout=palog, stderr=subprocess.STDOUT)
        procs.append(pa)

        # Start mockapi
        print("== start mockapi :9000")
        env["POPPY_OWNER_PIN"] = f"{principal_id}|{root_pub}"
        env["MOCK_API_PORT"] = "9000"
        pmlog = (rundir / "mockapi.log").open("w")
        pm = subprocess.Popen(
            [GW_PY, str(GWROOT / "mock_api.py")],
            env=env, stdout=pmlog, stderr=subprocess.STDOUT)
        procs.append(pm)

        # Start Envoy
        print("== start Envoy :8080")
        cfg_src = GWROOT / "envoy" / "envoy-openline.yaml"
        cfg_dst = rundir / "envoy.yaml"
        cfg_dst.write_text(cfg_src.read_text())
        envlog = (rundir / "envoy.log").open("w")
        penvoy = subprocess.Popen(
            [str(ENVOY_BIN), "-c", str(cfg_dst)],
            stdout=envlog, stderr=subprocess.STDOUT)
        procs.append(penvoy)

        if not wait_for("http://127.0.0.1:9000/health", 15):
            print("mockapi failed")
            return 2
        # Envoy health: try the poppy endpoint via Envoy (will 403 without
        # auth, but proves Envoy is up and routing).
        if not wait_for("http://127.0.0.1:8080/health", 20):
            print(f"Envoy /health did not become ready; exit={penvoy.poll()}")
            if (rundir / "envoy.log").exists():
                print("\n".join((rundir / "envoy.log").read_text(
                    errors="replace").splitlines()[-80:]))
            return 2
        print("== stack ready\\n")

        # Setup: operation, mandate, bundle (via mockapi test endpoints).
        operation = {
            "type": "charge", "merchant": "manzanita-supply",
            "account": "treasury", "amount_cents": 4250, "currency": "USD",
            "items": [{"sku": "JKT-RAIN-042", "qty": 1,
                       "price_cents": 4250}],
            "order_ref": "ord_full_001",
        }
        scope = mandate_scope_for_operation(operation)
        akey = Ed25519PrivateKey.generate()
        now = datetime.now(timezone.utc)
        m = wallet.grant(
            subject_id="poppy-agent",
            subject_public_key=public_key_hex(akey),
            scopes=[scope], expires_at=now + timedelta(hours=1))
        mid = m["data"]["mandate_id"]
        bundle = wallet.export_bundle(ttl_seconds=300)
        sa, _ = http_post("http://127.0.0.1:9000/poppy-admit",
                          {"bundle": bundle},
                          {"Content-Type": "application/json"})
        check("bundle admitted", sa == 200)

        def tx_approval(op: dict, bndl: dict, mid_: str,
                        subj: str = "poppy-agent") -> str:
            sc = mandate_scope_for_operation(op)
            scode, rch = http_post(
                "http://127.0.0.1:9000/poppy-challenge",
                {"principal_id": principal_id, "subject_id": subj,
                 "action": sc},
                {"Content-Type": "application/json"})
            assert scode == 200, f"challenge: {rch}"
            pres = worker_present(
                bundle=bndl, mandate_id=mid_, subject_id=subj,
                subject_key=akey, action=sc, challenge=rch["challenge"])
            tx = {"presentation": pres, "principal_id": principal_id,
                  "operation": op}
            return base64.urlsafe_b64encode(
                json.dumps(tx).encode()).rstrip(b"=").decode()

        def full_path_headers(amount_cents: int,
                              approval_b64: str | None = None) -> dict:
            # Gateway headers: verified by live authz via Envoy ext_authz.
            c = AgentClient("poppy-agent", agent_key_b64)
            h = c.headers_for("authorize_payment", target="ledger",
                              value_cents=amount_cents)
            h["Content-Type"] = "application/json"
            if approval_b64:
                h["x-ol-tx-approval"] = approval_b64
            return h

        envoy_url = "http://127.0.0.1:8080/api/poppy-charge"
        body = {"operation": operation}

        # Case 1: Delegated only (via full path).
        print("\n--- Case 1: delegated only, no transaction approval")
        s1, r1 = http_post(envoy_url, body, full_path_headers(4250))
        check("delegated-only -> 403", s1 == 403, f"status {s1}")
        check("reason DELEGATED_AUTHORITY_NOT_TRANSACTION_APPROVAL",
              r1.get("error") == "DELEGATED_AUTHORITY_NOT_TRANSACTION_APPROVAL")

        # Case 2: Delegated + approval (via full path).
        print("\n--- Case 2: full path, both layers")
        appr = tx_approval(operation, bundle, mid)
        s2, r2 = http_post(envoy_url, body, full_path_headers(4250, appr))
        check("full path -> 200", s2 == 200,
              f"status {s2} response={str(r2)[:450]}")
        receipt = r2.get("poppy_receipt", {})
        check("receipt present", bool(receipt))
        check("receipt signature verifies independently",
              verify_receipt_signature(receipt))
        de = receipt.get("decision_evidence", {})
        ee = receipt.get("effect_evidence", {})
        check("decision evidence separate",
              de.get("type") == "poppy_decision"
              and de.get("decision") == "ALLOWED")
        check("effect evidence separate",
              ee.get("type") == "poppy_ledger_effect"
              and ee.get("treasury_delta_cents") == -4250
              and ee.get("merchant_delta_cents") == 4250)
        check("amount binding documented",
              de.get("amount_binding", {}).get("match") is True)

        # Case 3: Second execution with fresh challenge (one-use).
        print("\n--- Case 3: replay approval with fresh challenge")
        appr2 = tx_approval(operation, bundle, mid)  # fresh challenge
        s3, r3 = http_post(envoy_url, body, full_path_headers(4250, appr2))
        check("second execution -> 403", s3 == 403, f"status {s3}")
        check("reason TRANSACTION_APPROVAL_ALREADY_USED",
              r3.get("error") == "TRANSACTION_APPROVAL_ALREADY_USED",
              f"err={r3.get('error')}")
        # Ledger must not have moved again.
        tb = http_get("http://127.0.0.1:9000/balance/treasury")["cents"]
        check("ledger unchanged after replay",
              tb == 1000000 - 4250, f"treasury={tb}")

        # Case 4: $0-signed action cannot authorize $42.50.
        print("\n--- Case 4: amount binding ($0 token vs $42.50 op)")
        # New operation/mandate for a clean approval.
        op4 = dict(operation, order_ref="ord_full_004")
        scope4 = mandate_scope_for_operation(op4)
        # The Wallet permits only one active mandate per subject.
        wallet.revoke(mid, reason="TEST_ROTATE_AFTER_ONE_USE")
        m4 = wallet.grant(
            subject_id="poppy-agent",
            subject_public_key=public_key_hex(akey),
            scopes=[scope4], expires_at=now + timedelta(hours=1))
        mid4 = m4["data"]["mandate_id"]
        bundle4 = wallet.export_bundle(ttl_seconds=300)
        http_post("http://127.0.0.1:9000/poppy-admit", {"bundle": bundle4},
                  {"Content-Type": "application/json"})
        appr4 = tx_approval(op4, bundle4, mid4)
        # Agent signs for $0 but presents $42.50 approval.
        s4, r4 = http_post(envoy_url, {"operation": op4},
                           full_path_headers(0, appr4))
        check("$0 token -> 403", s4 == 403, f"status {s4}")
        check("reason AMOUNT_BINDING_MISMATCH",
              r4.get("error") == "AMOUNT_BINDING_MISMATCH",
              f"err={r4.get('error')}")

        # Case 5: Terms mismatch.
        print("\n--- Case 5: approval for different terms")
        op5 = dict(operation, order_ref="ord_full_005",
                   merchant="manzanita-supply")
        scope5 = mandate_scope_for_operation(op5)
        wallet.revoke(mid4, reason="TEST_ROTATE_AFTER_AMOUNT_REFUSAL")
        m5 = wallet.grant(
            subject_id="poppy-agent",
            subject_public_key=public_key_hex(akey),
            scopes=[scope5], expires_at=now + timedelta(hours=1))
        mid5 = m5["data"]["mandate_id"]
        bundle5 = wallet.export_bundle(ttl_seconds=300)
        http_post("http://127.0.0.1:9000/poppy-admit", {"bundle": bundle5},
                  {"Content-Type": "application/json"})
        appr5 = tx_approval(op5, bundle5, mid5)
        tampered = {"operation": dict(op5, merchant="evil-corp")}
        s5, r5 = http_post(envoy_url, tampered,
                           full_path_headers(4250, appr5))
        check("terms mismatch -> 403", s5 == 403, f"status {s5}")
        check("reason TRANSACTION_TERMS_MISMATCH",
              r5.get("error") == "TRANSACTION_TERMS_MISMATCH")

        # Explicit negative test: a signed Wallet presentation for a
        # different agent cannot be combined with a valid Gateway token.
        print("\\n--- Case 5b: cross-agent approval must be refused")
        op_mixed = dict(operation, order_ref="ord_full_mixed")
        scope_mixed = mandate_scope_for_operation(op_mixed)
        m_mixed = wallet.grant(
            subject_id="unrelated-agent",
            subject_public_key=public_key_hex(akey),
            scopes=[scope_mixed], expires_at=now + timedelta(hours=1))
        mid_mixed = m_mixed["data"]["mandate_id"]
        bundle_mixed = wallet.export_bundle(ttl_seconds=300)
        http_post("http://127.0.0.1:9000/poppy-admit", {"bundle": bundle_mixed},
                  {"Content-Type": "application/json"})
        mixed_appr = tx_approval(
            op_mixed, bundle_mixed, mid_mixed, "unrelated-agent")
        mixed_status, mixed_body = http_post(
            envoy_url, {"operation": op_mixed},
            full_path_headers(4250, mixed_appr))
        check("mixed agent refused -> 403", mixed_status == 403,
              f"status {mixed_status} response={str(mixed_body)[:450]}")
        check("mixed agent identity reason", 
              mixed_body.get("error") == "IDENTITY_MISMATCH")

        # A registered Gateway worker must not sign a request claiming to
        # BE a different Wallet-approved worker. The raw header selects the
        # real registered key/mandate; the signed body must match that ID.
        # Without the authz check, the issued receiver token could carry
        # "unrelated-agent" and combine with this valid Wallet presentation.
        print("\\n--- Case 5c: signed action agent ID substitution")
        impostor = AgentClient("poppy-agent", agent_key_b64)
        spoof_headers = impostor.headers_for(
            "authorize_payment", target="ledger", value_cents=4250)
        spoof_action = json.loads(_b64u_decode(spoof_headers["x-ol-action"]))
        spoof_action["agent_id"] = "unrelated-agent"
        spoof_payload = _canonical(spoof_action)
        spoof_headers["x-ol-action"] = base64.urlsafe_b64encode(
            spoof_payload).rstrip(b"=").decode()
        spoof_headers["x-ol-sig"] = base64.urlsafe_b64encode(
            impostor.key.sign(spoof_payload)).rstrip(b"=").decode()
        spoof_headers["x-ol-tx-approval"] = mixed_appr
        spoof_headers["Content-Type"] = "application/json"
        spoof_status, spoof_body = http_post(
            envoy_url, {"operation": op_mixed}, spoof_headers)
        check("signed agent ID substitution -> 403",
              spoof_status == 403,
              f"status {spoof_status}, body={str(spoof_body)[:450]}")
        check("denied at Gateway identity check",
              "action_agent_id_mismatch" in
              spoof_body.get("reasons", []),
              f"body={str(spoof_body)[:450]}")
        check("forged identity caused no ledger debit",
              http_get("http://127.0.0.1:9000/balance/treasury")["cents"]
              == 1000000 - 4250)

        # Case 6: Revoked approval.
        print("\n--- Case 6: revoked transaction approval")
        wallet.revoke(mid5, reason="USER_REVOKED")
        bundle6 = wallet.export_bundle(ttl_seconds=300)
        http_post("http://127.0.0.1:9000/poppy-admit", {"bundle": bundle6},
                  {"Content-Type": "application/json"})
        appr6 = tx_approval(op5, bundle6, mid5)
        s6, r6 = http_post(envoy_url, {"operation": op5},
                           full_path_headers(4250, appr6))
        check("revoked -> 403", s6 == 403, f"status {s6}")
        check("reason TRANSACTION_APPROVAL_INVALID",
              r6.get("error") == "TRANSACTION_APPROVAL_INVALID")

    finally:
        stop_all()
        if any(s == FAIL for s, _ in results):
            # Preserve actionable diagnostics on a failing run, rather than
            # deleting the temp logs before the failure has been explained.
            for name in ("authz.log", "mockapi.log", "envoy.log"):
                log = rundir / name
                if log.exists():
                    print(f"\\n--- {name} (last 40 lines) ---")
                    print("\\n".join(log.read_text(errors="replace").splitlines()[-40:]))
        shutil.rmtree(rundir, ignore_errors=True)

    n_fail = sum(1 for s, _ in results if s == FAIL)
    print(f"\n{len(results) - n_fail}/{len(results)} checks passed")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
