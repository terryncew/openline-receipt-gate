#!/usr/bin/env python3
"""OPENLINE-GATEWAY-001 adversarial scenario runner.

Exercises the installed gateway through the real Envoy and asserts the
security properties. Each scenario is independent and reports PASS/FAIL
with evidence. Exit code 0 only if all pass.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

HERE = Path(__file__).resolve().parent
GWROOT = HERE.parent
sys.path.insert(0, str(GWROOT))
os.environ.setdefault("GATEWAY_CONFIG", str(GWROOT / "config"))
os.environ.setdefault("GATEWAY_DB", str(GWROOT / "state" / "gateway.db"))

from agent_client import AgentClient  # noqa: E402

ENVOY = "http://127.0.0.1:8080"
API_DIRECT = "http://127.0.0.1:9000"
RESULTS = []


def check(name, cond, evidence=""):
    RESULTS.append((name, bool(cond), str(evidence)[:160]))
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" +
          (f" — {evidence[:100]}" if evidence and not cond else ""))


def post_envoy(headers, body=b'{}', path="/api/transfer"):
    req = urllib.request.Request(ENVOY + path, data=body, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def post_direct(headers, body=b'{}', path="/transfer"):
    req = urllib.request.Request(API_DIRECT + path, data=body, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def admin(*args):
    return subprocess.run(
        [sys.executable, str(GWROOT / "gateway_admin.py"), *args],
        capture_output=True, text=True, env=os.environ).stdout


def restart_authz():
    """Kill the authz server, wait for the port to free, start fresh."""
    try:
        pid = open("/tmp/gw-authz.pid").read().strip().split()[0]
        if pid.isdigit():
            subprocess.run(["kill", pid], check=False)
    except Exception:
        pass
    for _ in range(20):
        time.sleep(0.5)
        s = subprocess.run(["ss", "-tln"], capture_output=True, text=True)
        if ":50051" not in s.stdout:
            break
    env = dict(os.environ)
    env["PYTHONPATH"] = str(GWROOT) + ":" + env.get("PYTHONPATH", "")
    p = subprocess.Popen(
        [sys.executable, str(GWROOT / "authz_server.py"), "50051"],
        stdout=open("/tmp/gw-authz.log", "a"),
        stderr=subprocess.STDOUT, env=env, start_new_session=True)
    time.sleep(2)
    s = subprocess.run(["ss", "-tln"], capture_output=True, text=True)
    assert ":50051" in s.stdout, "authz server did not bind :50051"
    open("/tmp/gw-authz.pid", "w").write(str(p.pid))
    return p


def treasury():
    """Read the simulated treasury balance direct from the mock API
    (read-only; not a consequential action)."""
    req = urllib.request.Request(API_DIRECT + "/balance/treasury")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())["cents"]


def provision(agent_id, max_cents=10000):
    out = admin("provision-agent", agent_id, f"--max-cents={max_cents}")
    if not out.strip().startswith("{"):
        raise SystemExit(f"provision failed: {out[:200]}")
    return json.loads(out)["agent_private_key"]


def main():
    key_a = provision("s-worker-a", max_cents=5000)
    a = AgentClient("s-worker-a", key_a)

    # 01 valid transfer
    s, b = post_envoy(a.headers_for("authorize_payment", value_cents=1000))
    ok = s == 200 and json.loads(b).get("ok") is True
    check("01 valid transfer allowed", ok, b)

    # 02 replay
    h = a.headers_for("authorize_payment", value_cents=100)
    s1, _ = post_envoy(h)
    s2, b2 = post_envoy(h)
    check("02 replay denied", s1 == 200 and s2 == 403, f"{s1}/{s2}")

    # 03 tampered signature
    h = a.headers_for("authorize_payment", value_cents=100)
    h["x-ol-sig"] = h["x-ol-sig"][:-4] + "AAAA"
    s, b = post_envoy(h)
    check("03 tampered signature denied", s == 403, b)

    # 04 over limit (mandate max 5000)
    s, b = post_envoy(a.headers_for("authorize_payment", value_cents=99999))
    check("04 over-mandate-limit denied", s == 403, b)

    # 05 unknown agent
    fake = AgentClient("nobody", key_a)
    s, b = post_envoy(fake.headers_for("authorize_payment", value_cents=10))
    check("05 unknown agent denied", s == 403, b)

    # 06 revoked agent
    key_r = provision("s-worker-rev")
    r = AgentClient("s-worker-rev", key_r)
    s1, _ = post_envoy(r.headers_for("authorize_payment", value_cents=10))
    admin("revoke-agent", "s-worker-rev")
    s2, b2 = post_envoy(r.headers_for("authorize_payment", value_cents=10))
    check("06 revoked agent denied", s1 == 200 and s2 == 403,
          f"{s1}/{s2}")

    # 07 worker replacement
    key_b = provision("s-worker-b", max_cents=5000)
    b_cli = AgentClient("s-worker-b", key_b)
    admin("revoke-agent", "s-worker-a")
    s_old, _ = post_envoy(a.headers_for("authorize_payment", value_cents=10))
    s_new, _ = post_envoy(
        b_cli.headers_for("authorize_payment", value_cents=10))
    check("07 worker replacement: old stopped, new continues",
          s_old == 403 and s_new == 200, f"old={s_old} new={s_new}")

    # 08 bypass: direct API without token
    s, b = post_direct({}, b'{"to":"vendor"}')
    check("08 bypass without token refused", s == 403, b)

    # 09 bypass: forged token
    s, b = post_direct({"x-ol-decision": "Zm9yZ2Vk"}, b'{"to":"vendor"}')
    check("09 forged decision token refused", s == 403, b)

    # 10 tampered params: body lies, authorized params win
    s, b = post_envoy(
        b_cli.headers_for("authorize_payment", value_cents=100),
        body=b'{"to":"attacker","cents":999999}')
    try:
        executed = json.loads(b).get("authorized_params", {}).get(
            "value_cents")
    except Exception:
        executed = None
    check("10 authorized params win over body",
          s == 200 and executed == 100, f"executed={executed}")

    # 11 stale timestamp
    h = b_cli.headers_for("authorize_payment", value_cents=10,
                          ts=time.time() - 3600)
    s, b = post_envoy(h)
    check("11 stale action claim denied", s == 403, b)

    # 12 receiver restart: replay still detected after restart
    h = b_cli.headers_for("authorize_payment", value_cents=10)
    s1, _ = post_envoy(h)
    print("    (restarting authz service...)")
    restart_authz()
    s2, _ = post_envoy(h)
    check("12 replay survives receiver restart",
          s1 == 200 and s2 == 403, f"{s1}/{s2}")

    # 13 observe mode labels would-deny without enforcing
    admin("set-mode", "observe")
    restart_authz()
    s, b = post_envoy(b_cli.headers_for("authorize_payment",
                                        value_cents=99999))
    try:
        res = json.loads(b)
        labeled = "would-deny" in res.get("observe_decision", "") or \
            "warning" in res
    except Exception:
        labeled = False
    check("13 observe mode executes but labels would-deny",
          s == 200 and labeled, b[:120])
    admin("set-mode", "enforce")
    restart_authz()

    # 14 EFFECTS: replay executes exactly once (ledger, not just HTTP)
    key_e = provision("s-worker-eff", max_cents=100000)
    e_cli = AgentClient("s-worker-eff", key_e)
    t0 = treasury()
    h = e_cli.headers_for("authorize_payment", value_cents=1000)
    s1, _ = post_envoy(h)
    s2, _ = post_envoy(h)
    delta = t0 - treasury()
    check("14 replay: treasury debited exactly once",
          s1 == 200 and s2 == 403 and delta == 1000,
          f"delta={delta} http={s1}/{s2}")

    # 15 EFFECTS: tampered body moves exactly the authorized amount
    t0 = treasury()
    s, b = post_envoy(
        e_cli.headers_for("authorize_payment", value_cents=200),
        body=b'{"to":"attacker","cents":999999}')
    delta = t0 - treasury()
    check("15 tampered body: ledger moves authorized 200, not 999999",
          s == 200 and delta == 200, f"delta={delta}")

    # 16 TIME: revoke, then immediate burst — nothing executes after
    key_t = provision("s-worker-time", max_cents=100000)
    t_cli = AgentClient("s-worker-time", key_t)
    t0 = treasury()
    admin("revoke-agent", "s-worker-time")
    allowed = 0
    for _ in range(10):
        s, _ = post_envoy(
            t_cli.headers_for("authorize_payment", value_cents=100))
        if s == 200:
            allowed += 1
    delta = t0 - treasury()
    check("16 post-revocation burst: 0 executions, 0 cents moved",
          allowed == 0 and delta == 0,
          f"allowed={allowed} delta={delta}")

    # 17 TIME: the honest revocation bound. A decision token minted
    # BEFORE revocation remains valid until its TTL (60s) — revocation
    # stops new authorizations immediately, not in-flight tokens.
    import base64 as _b64

    def _b64d(s):
        return _b64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    def _cano(o):
        return json.dumps(o, sort_keys=True,
                          separators=(",", ":")).encode()

    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey)
    rkey = Ed25519PrivateKey.from_private_bytes(_b64d(
        open(GWROOT / "config" / "receiver.key").read().strip()))
    tok = {"decision_id": "race-test-001", "agent_id": "s-worker-time",
           "action_type": "authorize_payment", "target": "ledger",
           "value_cents": 50, "nonce": "race-nonce-001",
           "issued_at": int(time.time()), "ttl": 60}
    tok["sig"] = _b64.urlsafe_b64encode(
        rkey.sign(_cano(tok))).rstrip(b"=").decode()
    tok_b64 = _b64.urlsafe_b64encode(
        _cano(tok)).rstrip(b"=").decode()
    t0 = treasury()
    s, b = post_direct({"x-ol-decision": tok_b64}, b'{}')
    delta = t0 - treasury()
    check("17 pre-revocation token executes within TTL (bound documented)",
          s == 200 and delta == 50,
          f"http={s} delta={delta} (TTL=60s is the revocation bound)")

    print(f"\n{sum(1 for _, c, _ in RESULTS if c)}/{len(RESULTS)} passed")
    (GWROOT / "scenarios" / "results.json").write_text(json.dumps(
        [{"scenario": n, "pass": c, "evidence": e}
         for n, c, e in RESULTS], indent=2))
    sys.exit(0 if all(c for _, c, _ in RESULTS) else 1)


if __name__ == "__main__":
    main()
