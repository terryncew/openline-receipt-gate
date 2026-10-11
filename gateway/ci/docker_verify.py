#!/usr/bin/env python3
"""GATEWAY-SUBSCRIPTION-001 Step 1: Docker Compose verification.

Runs against a live `docker compose --profile openline` stack with
Envoy on 127.0.0.1:8080 (see .github/workflows/
gateway-subscription-001-docker.yml). Exercises:

  a. Full HTTP path: signed transfer -> 200; tampered sig -> 403;
     replay of the same headers -> 403.
  b. ACTUAL ledger effects: treasury/vendor balances before and after
     a 100-cent transfer; asserts exact +/-100 deltas.
  c. Receipt verification: gateway_admin.py verify-receipts exits 0
     with 0 invalid.
  d. Persistence: restart mockapi; balances must survive.
  e. Revocation: revoke-agent -> next fresh request 403.
  f. Restart behavior: restart whole stack; balances and receipts
     survive.

Agent signing uses the repo's agent_client.AgentClient unmodified.
Exit code 0 only if every check passes. All values printed are
measured, never invented.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

CI_DIR = Path(__file__).resolve().parent
GWROOT = CI_DIR.parent
COMPOSE_DIR = GWROOT / "compose"
sys.path.insert(0, str(GWROOT))
from agent_client import AgentClient  # noqa: E402  (repo code, unmodified)

ENVOY = "http://127.0.0.1:8080"
AGENT_ID = "ci-verify-agent"
RESULTS: list[tuple[str, bool, str]] = []
LATENCIES: list[float] = []


def check(name: str, cond: bool, evidence: str = ""):
    RESULTS.append((name, bool(cond), str(evidence)[:200]))
    tag = "PASS" if cond else "FAIL"
    extra = f" -- {evidence[:160]}" if evidence else ""
    print(f"[{tag}] {name}{extra}", flush=True)


def compose(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "--profile", "openline", *args],
        cwd=COMPOSE_DIR, capture_output=True, text=True, timeout=180)


def cexec(service: str, *args: str) -> subprocess.CompletedProcess:
    return compose("exec", "-T", service, *args)


def http(method: str, path: str, headers: dict | None = None,
         body: bytes = b"{}",
         timeout: int = 15) -> tuple[int, str, float]:
    req = urllib.request.Request(
        ENVOY + path,
        data=body if method == "POST" else None, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            ms = (time.perf_counter() - t0) * 1000
            return r.status, r.read().decode(), ms
    except urllib.error.HTTPError as e:
        ms = (time.perf_counter() - t0) * 1000
        return e.code, e.read().decode(), ms


def wait_for(desc: str, fn, tries: int = 45, gap: float = 2.0):
    """Poll fn() until it returns truthy; return last value."""
    last = None
    for _ in range(tries):
        try:
            last = fn()
        except Exception:
            last = None
        if last:
            print(f"[wait] {desc}: ready", flush=True)
            return last
        time.sleep(gap)
    print(f"[wait] {desc}: TIMEOUT after {tries * gap:.0f}s", flush=True)
    return last


def provision(agent_id: str = AGENT_ID) -> AgentClient:
    if agent_id == AGENT_ID:
        p = cexec("authz", "python3", "/app/gateway/gateway_admin.py",
                  "provision-agent", AGENT_ID, "--max-cents", "5000")
    else:
        # A separate, inspection-only identity must survive the payment
        # agent's revocation. Keep its private key in memory, never logs.
        p = cexec("authz", "python3", "-c",
                  "from gateway.gateway_admin import cmd_provision; "
                  f"cmd_provision({agent_id!r}, max_cents=0, actions=('inspect',))")
    label = "" if agent_id == AGENT_ID else "inspector "
    check(label + "provision-agent exits 0", p.returncode == 0, p.stderr[:160])
    try:
        key = json.loads(p.stdout)["agent_private_key"]
    except Exception as e:
        check(label + "provision-agent prints key JSON", False, str(e)[:120])
        sys.exit(1)
    check(label + "provision-agent prints key JSON", True)
    return AgentClient(agent_id, key)


def service_start_times() -> dict[str, str]:
    """Prove a full restart occurred; a successful Compose no-op is insufficient."""
    p = compose("ps", "-q", "envoy", "authz", "mockapi")
    if p.returncode != 0 or len(p.stdout.split()) != 3:
        return {}
    p = subprocess.run(
        ["docker", "inspect", "--format",
         '{{ index .Config.Labels "com.docker.compose.service" }} '
         '{{.State.StartedAt}} {{.State.Running}}', *p.stdout.split()],
        capture_output=True, text=True, timeout=15)
    if p.returncode != 0:
        return {}
    return {service: started for service, started, running in
            (line.split() for line in p.stdout.splitlines()) if running == "true"}


def get_balance(client: AgentClient, acct: str) -> tuple[int, int]:
    s, b, _ = http("GET", f"/api/balance/{acct}",
                   client.headers_for("inspect", value_cents=0))
    if s != 200:
        return s, -1
    return s, int(json.loads(b)["cents"])


def verify_receipts() -> tuple[bool, str]:
    p = cexec("authz", "python3", "/app/gateway/gateway_admin.py",
              "verify-receipts")
    ok = p.returncode == 0 and "0 invalid" in p.stdout
    return ok, p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""


def main() -> int:
    print("== GATEWAY-SUBSCRIPTION-001 docker verification ==", flush=True)
    print(f"envoy={ENVOY} compose={COMPOSE_DIR}", flush=True)

    client = provision()

    # Readiness: the full Envoy -> authz -> mockapi chain is live when a
    # signed transfer returns 200.
    def ready():
        s, b, _ = http("POST", "/api/transfer",
                       client.headers_for("authorize_payment",
                                          value_cents=1))
        return s == 200 and json.loads(b).get("ok") is True
    check("stack ready (signed transfer -> 200)",
          bool(wait_for("signed transfer", ready)),
          "authz/mockapi/envoy chain not live")

    # (a) HTTP path: allow / tamper / replay
    h = client.headers_for("authorize_payment", value_cents=25)
    s, b, ms = http("POST", "/api/transfer", h)
    LATENCIES.append(ms)
    ok_body = s == 200 and json.loads(b).get("ok") is True
    check("a1 signed transfer -> 200", ok_body,
          f"http={s} body={b[:120]} ({ms:.1f}ms)")

    ht = client.headers_for("authorize_payment", value_cents=25)
    ht["x-ol-sig"] = ht["x-ol-sig"][:-4] + "AAAA"
    s, b, _ = http("POST", "/api/transfer", ht)
    check("a2 tampered signature -> 403",
          s == 403 and "signature_invalid" in b, f"http={s} {b[:120]}")

    s, b, _ = http("POST", "/api/transfer", h)  # replay of a1 headers
    check("a3 replay of same headers -> 403",
          s == 403 and "replay_detected" in b, f"http={s} {b[:120]}")

    # (b) Actual ledger effects: exact deltas on a 100-cent transfer
    _, t0 = get_balance(client, "treasury")
    _, v0 = get_balance(client, "vendor")
    check("b0 balances readable via Envoy", t0 >= 0 and v0 >= 0,
          f"treasury={t0} vendor={v0}")
    s, b, ms = http("POST", "/api/transfer",
                    client.headers_for("authorize_payment", value_cents=100))
    LATENCIES.append(ms)
    check("b1 100-cent transfer -> 200", s == 200,
          f"http={s} ({ms:.1f}ms) {b[:120]}")
    _, t1 = get_balance(client, "treasury")
    _, v1 = get_balance(client, "vendor")
    check("b2 treasury decreased by exactly 100", t0 - t1 == 100,
          f"{t0} -> {t1} (delta {t0 - t1})")
    check("b3 vendor increased by exactly 100", v1 - v0 == 100,
          f"{v0} -> {v1} (delta {v1 - v0})")

    # (c) Receipt verification
    ok, summary = verify_receipts()
    check("c verify-receipts exits 0, 0 invalid", ok, summary)
    try:
        n0 = int(summary.split(" valid")[0].split(": ")[1])
    except Exception:
        n0 = -1

    # (d) Persistence across mockapi restart
    r = compose("restart", "mockapi")
    check("d0 mockapi restart exits 0", r.returncode == 0,
          r.stderr[:120])

    def api_back():
        s, _ = get_balance(client, "treasury")
        return s == 200
    check("d1 mockapi back after restart",
          bool(wait_for("mockapi balance", api_back)))
    _, t2 = get_balance(client, "treasury")
    _, v2 = get_balance(client, "vendor")
    check("d2 balances survive mockapi restart",
          t1 >= 0 and v1 >= 0 and t2 == t1 and v2 == v1,
          f"treasury={t2} vendor={v2} (baseline {t1}/{v1})")

    # Provision the observer before restart, proving its receiver-owned
    # mandate also persists. Never undo the payment agent's revocation.
    inspector = provision("ci-verify-inspector")

    # (e) Revocation
    r = cexec("authz", "python3", "/app/gateway/gateway_admin.py",
              "revoke-agent", AGENT_ID)
    check("e0 revoke-agent reports revoked",
          r.returncode == 0 and "revoked" in r.stdout, r.stdout.strip())
    s, b, _ = http("POST", "/api/transfer",
                   client.headers_for("authorize_payment", value_cents=10))
    check("e1 fresh request after revoke -> 403",
          s == 403 and "agent_revoked" in b, f"http={s} {b[:120]}")

    # (f) Full-stack restart: balances and receipts survive
    before_restart = service_start_times()
    r = compose("restart")
    after_restart = service_start_times()
    print(f"[restart] before={before_restart} after={after_restart}", flush=True)
    services = {"envoy", "authz", "mockapi"}
    restarted = (before_restart.keys() == after_restart.keys() == services
                 and all(after_restart[s] > before_restart[s] for s in services))
    check("f0 stack restart exits 0 and all three services restarted",
          r.returncode == 0 and restarted,
          f"before={before_restart} after={after_restart} {r.stderr[:120]}")

    def envoy_back():
        try:
            with urllib.request.urlopen(ENVOY + "/health",
                                        timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False
    check("f1 envoy /health after restart",
          bool(wait_for("envoy health", envoy_back)))

    def chain_back():
        # Unsigned request: authz chain is live iff we get the
        # structured deny (missing_action_claim). An unreachable authz
        # service yields an EMPTY 403 (fail closed at Envoy).
        s, b, _ = http("POST", "/api/transfer", {})
        return s == 403 and "missing_action_claim" in b
    check("f2 authz chain live after restart",
          bool(wait_for("authz chain", chain_back)))
    s, b, _ = http("GET", "/api/balance/treasury",
                   client.headers_for("inspect", value_cents=0))
    check("f2a revoked agent remains denied after restart",
          s == 403 and "agent_revoked" in b, f"http={s} {b[:120]}")
    def api_back_full():
        s, _ = get_balance(inspector, "treasury")
        return s == 200
    check("f2b mockapi upstream back after full restart",
          bool(wait_for("mockapi balance (full restart)", api_back_full)))
    _, t3 = get_balance(inspector, "treasury")
    _, v3 = get_balance(inspector, "vendor")
    check("f3 balances survive full restart",
          t1 >= 0 and v1 >= 0 and t3 == t1 and v3 == v1,
          f"treasury={t3} vendor={v3} (baseline {t1}/{v1})")
    ok, summary = verify_receipts()
    try:
        n1 = int(summary.split(" valid")[0].split(": ")[1])
    except Exception:
        n1 = -1
    check("f4 receipts survive full restart (0 invalid, none lost)",
          ok and n0 >= 0 and n1 >= n0,
          f"{summary} (before restart: {n0} valid)")

    if LATENCIES:
        print(f"[latency] transfer samples (ms): "
              + ", ".join(f"{x:.1f}" for x in LATENCIES), flush=True)

    passed = sum(1 for _, c, _ in RESULTS if c)
    total = len(RESULTS)
    print(f"\n{passed}/{total} checks passed", flush=True)
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
