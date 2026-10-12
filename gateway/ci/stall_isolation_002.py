#!/usr/bin/env python3
"""STALL-ISOLATION-002: single synthetic authorized-path restart probe."""
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ROOT / "gateway" / "compose"
OUT = Path("/tmp/stall-isolation-002")
OUT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT / "gateway"))
from agent_client import AgentClient

EXPECTED = {"treasury": 1000000, "vendor": 0}
AGENT = "ci-stall-002-inspector"
RESULT = {"experiment": "STALL-ISOLATION-002", "verdict": "INCONCLUSIVE",
          "reason": "not yet complete", "run_id": os.getenv("GITHUB_RUN_ID"),
          "sha": os.getenv("GITHUB_SHA"), "baseline": {}, "observations": 0,
          "recovery_seconds": None, "max_poll_seconds": 90}


def now():
    return datetime.now(timezone.utc).isoformat()


def cmd(args, cwd=ROOT, timeout=180):
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, timeout=timeout)


def compose(*args, timeout=180):
    return cmd(["docker", "compose", "--profile", "openline", *args], cwd=COMPOSE, timeout=timeout)


def record(obj):
    with (OUT / "observations.jsonl").open("a") as f:
        f.write(json.dumps(obj, sort_keys=True) + "\n")
    print(json.dumps(obj, sort_keys=True), flush=True)


def ensure(condition, why):
    if not condition:
        raise RuntimeError(why)


def capture(name, args, cwd=ROOT):
    try:
        p = cmd(args, cwd=cwd, timeout=25)
        content = "returncode=" + str(p.returncode) + "\nSTDOUT\n" + p.stdout + "\nSTDERR\n" + p.stderr
    except Exception as exc:
        content = "capture_error=" + repr(exc)
    (OUT / (name + ".txt")).write_text(content)


def diagnostics():
    base = ["docker", "compose", "--profile", "openline"]
    capture("compose-ps", base + ["ps", "-a"], COMPOSE)
    capture("compose-logs", base + ["logs", "--no-color"], COMPOSE)
    direct = (
        "import socket,urllib.request;"
        "[(print('DNS',h,socket.gethostbyname_ex(h))) for h in ('envoy','authz','mockapi')];"
        "r=urllib.request.urlopen('http://mockapi:9000/balance/treasury',timeout=3);"
        "print('DIRECT',r.status,r.read().decode())"
    )
    capture("dns-and-direct-mockapi", base + ["exec", "-T", "authz", "python3", "-c", direct], COMPOSE)
    capture("envoy-clusters", base + ["exec", "-T", "envoy", "bash", "-c",
        "exec 3<>/dev/tcp/127.0.0.1/9901; "
        "printf 'GET /clusters?format=json HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' >&3; cat <&3"], COMPOSE)
    ids = compose("ps", "-q", "envoy", "authz", "mockapi")
    if ids.returncode == 0 and ids.stdout.split():
        capture("docker-inspect", ["docker", "inspect", *ids.stdout.split()])


def containment():
    for svc in ("envoy", "authz", "mockapi"):
        p = compose("ps", "-q", svc)
        ensure(p.returncode == 0 and len(p.stdout.split()) == 1, "Missing container: " + svc)
        q = cmd(["docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}", p.stdout.strip()])
        ensure(q.returncode == 0, "Port inspection failed: " + svc)
        ports = json.loads(q.stdout)
        binds = [b for group in ports.values() if group for b in group]
        if svc == "envoy":
            ensure(binds and all(b.get("HostPort") == "8080" for b in binds),
                   "Unexpected Envoy published port")
        else:
            ensure(not binds, "Containment failure: " + svc + " has host-published port")
    mode = compose("exec", "-T", "authz", "python3", "-c",
                   "import json;print(json.load(open('/config/policy.json'))['mode'])")
    ensure(mode.returncode == 0 and mode.stdout.strip() == "enforce", "Policy mode is not enforce")
    record({"kind": "containment", "status": "PASS", "ts": now(), "published": "envoy:8080 only"})


def inspector():
    # Same cmd_provision inspection-only path used by the original CI verifier.
    call = "from gateway.gateway_admin import cmd_provision;cmd_provision('ci-stall-002-inspector',max_cents=0,actions=('inspect',))"
    p = compose("exec", "-T", "authz", "python3", "-c", call)
    ensure(p.returncode == 0, "Inspector provisioning failed")
    data = json.loads(p.stdout)
    ensure(data.get("agent_id") == AGENT and data.get("agent_private_key"),
           "Provisioner returned an invalid identity")
    # Verify the RECEIVER'S recorded mandate, not merely the signing key.
    check = (
        "import json,sqlite3;"
        "c=sqlite3.connect('/state/gateway.db');"
        "r=c.execute('SELECT mandate,revoked FROM agents WHERE agent_id=?',"
        "('ci-stall-002-inspector',)).fetchone();"
        "print(json.dumps({'mandate':json.loads(r[0]),'revoked':r[1]}))"
    )
    q = compose("exec", "-T", "authz", "python3", "-c", check)
    ensure(q.returncode == 0, "Cannot verify stored mandate")
    stored = json.loads(q.stdout)
    m = stored["mandate"]
    ensure(stored["revoked"] == 0 and m["allowed_action_types"] == ["inspect"]
           and m["allowed_targets"] == ["ledger"]
           and m["max_payment_cents"] == 0 and m["delegation_allowed"] is False,
           "Inspector mandate exceeded allowed bounds")
    record({"kind": "mandate", "status": "PASS", "action": "inspect",
            "max_payment_cents": 0, "ts": now()})
    # Keep key only in memory. Never print command output or signed headers.
    return AgentClient(AGENT, data["agent_private_key"])


def probe(client, acct, phase, restart_start=None, budget=10):
    body_path = OUT / "response.tmp"
    body_path.unlink(missing_ok=True)
    args = ["curl", "--silent", "--show-error", "--max-time", f"{budget:.3f}",
            "--connect-timeout", f"{min(3., budget):.3f}",
            "--output", str(body_path), "--write-out", "%{http_code} %{time_total}"]
    for key, value in client.headers_for("inspect", value_cents=0).items():
        args += ["--header", key + ": " + value]
    args += ["http://127.0.0.1:8080/api/balance/" + acct]
    started = time.monotonic()
    try:
        p = cmd(args, timeout=budget + 1)
        parts = p.stdout.strip().split()
        code = parts[0] if parts else "000"
        curl_elapsed = float(parts[1]) if len(parts) > 1 else None
        exit_code = p.returncode
        stderr = p.stderr.strip()[:150]
    except subprocess.TimeoutExpired:
        code, curl_elapsed, exit_code, stderr = "000", None, 124, "subprocess_timeout"
    finished = time.monotonic()
    body = body_path.read_text(errors="replace") if body_path.exists() else ""
    body_path.unlink(missing_ok=True)
    valid, balance, response_kind = False, None, "non_json"
    try:
        parsed = json.loads(body)
        if (isinstance(parsed, dict) and type(parsed.get("cents")) is int
                and parsed.get("acct") == acct):
            valid, balance, response_kind = True, parsed["cents"], "balance_json"
        elif isinstance(parsed, dict):
            response_kind = str(parsed.get("error", "other_json"))[:120]
    except (ValueError, TypeError):
        pass
    observation = {"kind": "probe", "phase": phase, "account": acct, "ts": now(),
        "http_code": code, "curl_exit_code": exit_code, "curl_time_s": curl_elapsed,
        "elapsed_s": round(finished-started, 6),
        "since_restart_s": round(finished-restart_start, 6) if restart_start else None,
        "response_valid": valid, "balance_cents": balance,
        "response_kind": response_kind, "curl_error": stderr}
    record(observation)
    RESULT["observations"] += 1
    if code == "403":
        raise RuntimeError("Unexpected authorization denial: " + phase + " " + acct)
    return observation


def recovered(obs):
    return (obs["http_code"] == "200" and obs["curl_exit_code"] == 0
            and obs["response_valid"] and obs["balance_cents"] == EXPECTED[obs["account"]])


def execute():
    p = compose("up", "-d", "--build", timeout=240)
    (OUT / "compose-up.txt").write_text("returncode=" + str(p.returncode) + "\n" + p.stdout + p.stderr)
    ensure(p.returncode == 0, "Compose setup failed")
    containment()
    client = inspector()
    baseline_deadline = time.monotonic() + 35
    while True:
        baseline = {account: probe(client, account, "baseline") for account in EXPECTED}
        if all(recovered(v) for v in baseline.values()):
            RESULT["baseline"] = {k: v["balance_cents"] for k, v in baseline.items()}
            break
        ensure(time.monotonic() < baseline_deadline, "Authorized baseline not established in 35s")
        time.sleep(2)
    record({"kind": "baseline", "status": "PASS", "balances": RESULT["baseline"], "ts": now()})
    # Exact full-stack restart variant used in original failing test.
    p = compose("restart", timeout=150)
    (OUT / "compose-restart.txt").write_text("returncode=" + str(p.returncode) + "\n" + p.stdout + p.stderr)
    ensure(p.returncode == 0, "Full-stack restart command failed")
    t0 = time.monotonic()
    record({"kind": "restart", "status": "COMPLETED",
            "command": "docker compose --profile openline restart", "ts": now()})
    deadline = t0 + 90.0
    while time.monotonic() < deadline:
        readings = {}
        for account in EXPECTED:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            readings[account] = probe(client, account, "post_restart", t0, min(10.0, remaining))
        if len(readings) == len(EXPECTED) and all(recovered(v) for v in readings.values()):
            RESULT["verdict"] = "NOT_REPRODUCED"
            RESULT["reason"] = "Both authorized balances recovered with valid HTTP 200 and matching values"
            RESULT["recovery_seconds"] = max(v["since_restart_s"] for v in readings.values())
            record({"kind": "recovery", "status": "PASS",
                    "elapsed_s": RESULT["recovery_seconds"], "ts": now()})
            return
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(2, remaining))
    RESULT["verdict"] = "REPRODUCED"
    RESULT["reason"] = "Authorized expected balance reads did not recover within 90s"


def main():
    try:
        ensure(os.getenv("GITHUB_REF") == "refs/heads/temp/stall-isolation-001",
               "Unexpected branch")
        execute()
    except Exception as exc:
        RESULT["verdict"] = "INCONCLUSIVE"
        RESULT["reason"] = str(exc)[:350]
        print("STOP: " + RESULT["reason"], flush=True)
    finally:
        diagnostics()
        RESULT["finished_at"] = now()
        (OUT / "result.json").write_text(json.dumps(RESULT, sort_keys=True, indent=2) + "\n")
        print("FINAL_RESULT=" + json.dumps(RESULT, sort_keys=True), flush=True)
    return 0 if RESULT["verdict"] == "NOT_REPRODUCED" else 1


if __name__ == "__main__":
    sys.exit(main())
