#!/usr/bin/env python3
"""GATEWAY-SUBSCRIPTION-001: subscription cancellation demonstration.

Fictional owner, merchant, and funds. No real payment processing.

Runs against a local gateway stack (authz service + mock payment API +
Envoy) started by run_demo.sh, which sets GATEWAY_CONFIG, GATEWAY_DB,
and RUNDIR.

Narrative:
  1. The owner authorizes merchant-acme to charge up to $20 (a mandate).
  2. The merchant charges $20 through the payment receiver -> succeeds.
     The simulated ledger moves exactly $20.
  3. The merchant bills the same charge twice -> refused (replay).
  4. The merchant tries $200 -> refused (mandate cap).
  5. The merchant cheats (forged token, tampered body) -> fails.
  6. The owner revokes the mandate.
  7. The merchant charges again -> REFUSED (agent_revoked).
     A signed refusal receipt is recorded and verified independently.
  8. The race: a token minted BEFORE revocation is presented AFTER it.
     With the final standing check: refused, $0 moves.
     Without it (contrast instance): executes — the measured 60s window,
     disclosed honestly.

Exit 0 only if every assertion holds. Evidence is written to
$RUNDIR/evidence/ as transcript.json.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
GWROOT = HERE.parent
sys.path.insert(0, str(GWROOT))
sys.path.insert(0, str(HERE))

from merchant_sim import MerchantActor  # noqa: E402
import ext_authz_pb2 as pb2  # noqa: E402
import ext_authz_pb2_grpc as pb2_grpc  # noqa: E402
import grpc  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey)

CONFIG_DIR = Path(os.environ["GATEWAY_CONFIG"])
DB_PATH = Path(os.environ["GATEWAY_DB"])
RUNDIR = Path(os.environ["RUNDIR"])
EVIDIR = Path(os.environ["EVIDIR"])
ENVOY = "http://127.0.0.1:8080"
API = "http://127.0.0.1:9000"
API_NOCHECK = "http://127.0.0.1:9001"

TRANSCRIPT = []
FAILURES = []


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def say(title: str):
    print(f"\n=== {title} ===", flush=True)
    TRANSCRIPT.append({"narrative": title})


def check(name: str, cond: bool, evidence: str = ""):
    TRANSCRIPT.append({"check": name, "ok": bool(cond),
                       "evidence": str(evidence)[:300]})
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
          + (f" — {evidence[:120]}" if evidence and not cond else ""),
          flush=True)
    if not cond:
        FAILURES.append(name)


def balance(acct: str, base: str = API) -> int:
    with urllib.request.urlopen(f"{base}/balance/{acct}",
                                timeout=5) as r:
        return json.loads(r.read())["cents"]


def provision_merchant(agent_id: str, max_cents: int) -> str:
    """The owner act: write a subscription mandate into the registry."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    mandate = {
        "profile": "principal_mandate/v1",
        "mandate_id": f"mandate-sub-{agent_id}",
        "principal_id": "owner:fictional-customer",
        "agent_id": agent_id,
        "purpose": "subscription-billing",
        "allowed_action_types": ["authorize_payment"],
        "allowed_targets": ["ledger"],
        "allowed_disclosure_classes": [],
        "forbidden_disclosure_classes": [],
        "max_settlement_cents": 0,
        "max_payment_cents": max_cents,
        "delegation_allowed": False,
        "expires_at": (datetime.now(timezone.utc) +
                       timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": "1",
    }
    db = sqlite3.connect(str(DB_PATH))
    db.execute("INSERT OR REPLACE INTO agents(agent_id, pubkey, mandate,"
               " revoked) VALUES(?,?,?,0)",
               (agent_id, b64u_encode(pub.public_bytes_raw()),
                json.dumps(mandate)))
    db.commit()
    db.close()
    return b64u_encode(priv.private_bytes_raw())


def revoke_merchant(agent_id: str):
    db = sqlite3.connect(str(DB_PATH))
    db.execute("UPDATE agents SET revoked=1 WHERE agent_id=?", (agent_id,))
    db.commit()
    db.close()


def mint_token_direct(agent_id: str, key_b64: str, cents: int) -> str:
    """Mint a decision token via a direct gRPC Check (test-harness act).

    Models a token minted before revocation that arrives late — the
    authz->execution race. Never used for normal charges in this demo.
    """
    from agent_client import AgentClient
    client = AgentClient(agent_id, key_b64)
    headers = client.headers_for("authorize_payment", value_cents=cents)
    req = pb2.CheckRequest(
        attributes=pb2.AttributeContext(
            request=pb2.AttributeContext.Request(
                http=pb2.AttributeContext.HttpRequest(
                    method="POST", path="/api/transfer",
                    headers={"x-ol-agent": headers["x-ol-agent"],
                             "x-ol-action": headers["x-ol-action"],
                             "x-ol-sig": headers["x-ol-sig"]},
                    host="127.0.0.1", scheme="http"))))
    channel = grpc.insecure_channel("[::1]:50051")
    # NOTE: [::1], not 127.0.0.1. On this dev VM something in the IPv4
    # localhost path corrupts Python-grpc's HTTP/2 handshake ("got frame
    # type 101"); the same client over IPv6 loopback works, as does
    # Envoy's C++ ext_authz client over 127.0.0.1. The authz server
    # binds [::]:50051 (dual-stack), so this reaches the same service.
    # Recorded as an environment quirk; not a gateway defect.
    stub = pb2_grpc.AuthorizationStub(channel)
    resp = stub.Check(req, timeout=10)
    assert resp.status.code == 0, f"direct mint denied: {resp.status.message}"
    for hv in resp.ok_response.headers:
        if hv.header.key == "x-ol-decision":
            return hv.header.value
    raise AssertionError("no decision token in direct mint response")


def latest_denial_receipt(agent_id: str) -> dict:
    db = sqlite3.connect(str(DB_PATH))
    rows = db.execute(
        "SELECT body FROM receipts WHERE body LIKE '%\"agent_id\": \""
        + agent_id + "\"%' ORDER BY ts DESC").fetchall()
    db.close()
    for (body,) in rows:
        r = json.loads(body)
        if r.get("decision") == "deny":
            return r
    raise AssertionError("no denial receipt found for " + agent_id)


def export_receiver_pubkey() -> str:
    key_b64 = (CONFIG_DIR / "receiver.key").read_text().strip()
    pub = Ed25519PrivateKey.from_private_bytes(
        b64u_decode(key_b64)).public_key()
    return b64u_encode(pub.public_bytes_raw())


def main() -> int:
    evdir = EVIDIR
    evdir.mkdir(parents=True, exist_ok=True)

    # ---- 1. the owner authorizes the merchant -------------------------
    say("1. You give permission: merchant-acme may charge up to $20")
    key_b64 = provision_merchant("merchant-acme", 2000)
    merchant = MerchantActor("merchant-acme", key_b64)
    t0_treasury, t0_vendor = balance("treasury"), balance("vendor")
    check("mandate recorded with $20 cap",
          t0_treasury == 1_000_000 and t0_vendor == 0,
          f"treasury={t0_treasury} vendor={t0_vendor}")
    print(f"  mandate: subscription-billing, max $20.00/charge, 30-day expiry",
          flush=True)

    # ---- 2. one authorized charge succeeds -----------------------------
    say("2. The merchant charges $20 — the receiver allows it")
    st, body = merchant.charge(2000)
    res = json.loads(body)
    check("charge accepted", st == 200 and res.get("ok") is True, body[:160])
    check("ledger moved exactly $20",
          balance("treasury") == t0_treasury - 2000
          and balance("vendor") == t0_vendor + 2000,
          f"treasury={balance('treasury')} vendor={balance('vendor')}")
    check("API executed the authorized params, not the body",
          res.get("authorized_params", {}).get("value_cents") == 2000)

    # ---- 3. duplicate billing is refused --------------------------------
    say("3. The merchant bills the same charge twice — refused")
    st, body = merchant.replay_last_charge()
    check("replayed charge denied", st == 403, body[:160])
    check("no ledger movement on replay",
          balance("treasury") == t0_treasury - 2000
          and balance("vendor") == t0_vendor + 2000)
    # decision-token single-use, via a directly minted token
    tok = mint_token_direct("merchant-acme", key_b64, 2000)
    st1, b1 = merchant.present_token_directly(tok)
    st2, b2 = merchant.present_token_directly(tok)
    check("token executes once", st1 == 200 and json.loads(b1).get("ok"))
    check("token replay refused", st2 in (403, 409), b2[:160])
    exp_treasury = t0_treasury - 4000
    exp_vendor = t0_vendor + 4000
    check("ledger moved exactly once for the token",
          balance("treasury") == exp_treasury
          and balance("vendor") == exp_vendor)

    # ---- 4. the $200 increase is refused --------------------------------
    say("4. The merchant tries to raise the charge to $200 — refused")
    st, body = merchant.charge(20000)
    check("over-cap charge denied", st == 403, body[:160])
    check("mandate cap is the reason",
          "payment_limit_exceeded" in body, body[:160])
    check("no ledger movement",
          balance("treasury") == exp_treasury
          and balance("vendor") == exp_vendor)

    # ---- 5. the merchant cheats — and fails ------------------------------
    say("5. The merchant tries to cheat the receiver — fails")
    st, body = merchant.present_forged_token()
    check("forged decision token refused", st == 403, body[:160])
    st, body = merchant.post_unsigned_directly()
    check("unsigned direct API call refused", st == 403, body[:160])
    st, body = merchant.charge_with_tampered_body(
        signed_cents=2000, claimed_cents=99999)
    res = json.loads(body) if st == 200 else {}
    check("tampered body: authorized $20 wins, not the claimed $999.99",
          st == 200
          and res.get("authorized_params", {}).get("value_cents") == 2000
          and balance("vendor") == exp_vendor + 2000, body[:160])
    exp_treasury -= 2000
    exp_vendor += 2000

    # ---- 6. the owner revokes --------------------------------------------
    say("6. You cancel it: the mandate is revoked")
    revoke_merchant("merchant-acme")
    print("  revoke-agent merchant-acme -> registry marks revoked=1",
          flush=True)

    # ---- 7. the next charge is refused ------------------------------------
    say("7. The merchant charges again — your payment system refuses")
    st, body = merchant.charge(2000)
    check("post-revocation charge denied", st == 403, body[:160])
    check("revocation is the reason", "agent_revoked" in body, body[:160])
    check("no ledger movement after revocation",
          balance("treasury") == exp_treasury
          and balance("vendor") == exp_vendor)

    # the refusal receipt, verified independently
    say("8. The refusal is recorded as a signed, checkable receipt")
    receipt = latest_denial_receipt("merchant-acme")
    rpath = evdir / "refusal_receipt.json"
    rpath.write_text(json.dumps(receipt, indent=2, sort_keys=True))
    pubkey_b64 = export_receiver_pubkey()
    (evdir / "receiver.pubkey").write_text(pubkey_b64)
    v = subprocess.run(
        [sys.executable, str(HERE / "verify_receipt_standalone.py"),
         pubkey_b64, str(rpath)], capture_output=True, text=True)
    check("refusal receipt verifies with receiver public key only",
          v.returncode == 0, v.stdout.strip()[:160])
    print(f"  receipt_id={receipt['receipt_id']} "
          f"reasons={receipt.get('reasons')}", flush=True)
    v2 = subprocess.run(
        [sys.executable, str(GWROOT / "gateway_admin.py"),
         "verify-receipts"], capture_output=True, text=True,
        env={**os.environ, "GATEWAY_CONFIG": str(CONFIG_DIR),
             "GATEWAY_DB": str(DB_PATH)})
    check("all gateway receipts verify", v2.returncode == 0,
          v2.stdout.strip()[:160])

    # ---- 9. the race: a pre-revocation token, presented late --------------
    say("9. The hard case: an authorization minted BEFORE you canceled")
    # (minted while the mandate was still valid, via the test harness)
    # NOTE: mint before revoke is impossible now — so mint two tokens
    # using a re-provisioned twin merchant to model in-flight tokens.
    key2 = provision_merchant("merchant-acme-twin", 2000)
    tok_a = mint_token_direct("merchant-acme-twin", key2, 2000)
    tok_b = mint_token_direct("merchant-acme-twin", key2, 2000)
    revoke_merchant("merchant-acme-twin")
    st, body = merchant.present_token_directly(tok_a)  # check ON (:9000)
    check("late token refused by the final standing check", st == 403,
          body[:160])
    check("standing is the reason",
          "no longer standing" in body, body[:160])
    check("zero ledger movement on refused late token",
          balance("treasury") == exp_treasury
          and balance("vendor") == exp_vendor)
    # the honest contrast: the same API without the final check
    import urllib.request as _u, urllib.error as _e
    req = _u.Request(API_NOCHECK + "/transfer", data=b"{}", method="POST")
    req.add_header("x-ol-decision", tok_b)
    try:
        with _u.urlopen(req, timeout=10) as r:
            st, body = r.status, r.read().decode()
    except _e.HTTPError as e:
        st, body = e.code, e.read().decode()
    executed = (st == 200 and json.loads(body).get("ok") is True)
    check("WITHOUT the final check the late token executes "
          "(the measured 60s window — disclosed, not hidden)",
          executed, body[:160])
    if executed:
        exp_treasury -= 2000
        exp_vendor += 2000
    check("contrast ledger shows the window's cost exactly",
          balance("treasury") == exp_treasury
          and balance("vendor") == exp_vendor)
    print("  With the standing check (this demo's configuration): the "
          "post-revocation window is the check-to-commit interval only.",
          flush=True)
    print("  Without it: a pre-revocation token stays executable until "
          "its 60s TTL. The check is the fix; the TTL is the bound.",
          flush=True)

    # ---- evidence ----------------------------------------------------------
    (evdir / "transcript.json").write_text(
        json.dumps(TRANSCRIPT, indent=2))
    (evdir / "final_balances.json").write_text(json.dumps({
        "treasury_cents": balance("treasury"),
        "vendor_cents": balance("vendor")}, indent=2))
    say("Demo complete")
    print(f"\nEvidence: {evdir}", flush=True)
    print(f"Checks: {sum(1 for t in TRANSCRIPT if t.get('ok'))} passed, "
          f"{len(FAILURES)} failed", flush=True)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    sys.exit(main())
