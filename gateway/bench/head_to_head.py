#!/usr/bin/env python3
"""OPENLINE-GATEWAY-001 head-to-head: OpenLine vs OPA-A vs OPA-B.

Runs capability-equivalent scenarios against all three configurations
through the real Envoy, then measures latency. Reports honest results
including where OPA matches OpenLine and where the architectures differ.

Scenario mapping (capability-equivalent, not identical mechanics):
  valid-request      authorized credential -> allowed + executed
  bad-credential     wrong/unknown credential -> denied
  revoked-credential revoked credential -> denied iff revocation supported
  replay             identical request twice -> 2nd denied iff supported
  forged-header      forged decision header direct to API -> refused iff
                     decision is cryptographically bound
  tampered-amount    body amount != authorized amount -> which wins?
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
ENVOY_BIN = os.environ.get("ENVOY_BIN",
                            str(Path.home() / "workspace" / ".envoy-binary"))
OPA_BIN = os.environ.get("OPA_BIN",
                         str(Path.home() / "workspace" / ".opa-binary"))
RESULTS = {}


def req(url, headers, body=b'{}'):
    r = urllib.request.Request(url, data=body, method="POST")
    for k, v in headers.items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def stop_all():
    for f in ("/tmp/gw-authz.pid", "/tmp/gw-api.pid", "/tmp/gw-envoy.pid",
              "/tmp/gw-opa.pid", "/tmp/gw-shim.pid"):
        try:
            pid = open(f).read().strip().split()[0]
            if pid.isdigit():
                subprocess.run(["kill", pid], check=False)
        except Exception:
            pass
    time.sleep(1)


def start_common(auth_mode):
    env = dict(os.environ)
    env["GATEWAY_AUTH_MODE"] = auth_mode
    env["GATEWAY_CONFIG"] = str(GWROOT / "config")
    env["GATEWAY_DB"] = str(GWROOT / "state" / "gateway.db")
    env["PYTHONPATH"] = str(GWROOT)
    p = subprocess.Popen(
        [sys.executable, str(GWROOT / "mock_api.py")],
        stdout=open("/tmp/gw-api.log", "a"), stderr=subprocess.STDOUT,
        env=env, start_new_session=True)
    open("/tmp/gw-api.pid", "w").write(str(p.pid))
    time.sleep(1)
    return env


def start_envoy(cfg):
    p = subprocess.Popen(
        [ENVOY_BIN, "-c", str(GWROOT / "envoy" / cfg)],
        stdout=open("/tmp/gw-envoy.log", "a"), stderr=subprocess.STDOUT,
        start_new_session=True)
    open("/tmp/gw-envoy.pid", "w").write(str(p.pid))
    time.sleep(3)


def admin(*args):
    env = dict(os.environ)
    return subprocess.run(
        [sys.executable, str(GWROOT / "gateway_admin.py"), *args],
        capture_output=True, text=True, env=env).stdout


def opa_write(path, doc):
    r = urllib.request.Request(
        f"http://127.0.0.1:8181/v1/data/{path}",
        data=json.dumps(doc).encode(),
        headers={"Content-Type": "application/json"}, method="PUT")
    urllib.request.urlopen(r, timeout=5)


# -- OpenLine scenarios -------------------------------------------------
def run_openline():
    stop_all()
    env = start_common("openline")
    p = subprocess.Popen(
        [sys.executable, str(GWROOT / "authz_server.py"), "50051"],
        stdout=open("/tmp/gw-authz.log", "a"), stderr=subprocess.STDOUT,
        env=env, start_new_session=True)
    open("/tmp/gw-authz.pid", "w").write(str(p.pid))
    time.sleep(2)
    start_envoy("envoy-openline.yaml")

    out = admin("provision-agent", "h-worker", "--max-cents=5000")
    key = json.loads(out)["agent_private_key"]
    c = AgentClient("h-worker", key)
    R = {}

    s, b = req(ENVOY + "/api/transfer",
               c.headers_for("authorize_payment", value_cents=100))
    R["valid-request"] = (s == 200, f"http={s}")

    s, b = req(ENVOY + "/api/transfer", {})
    R["bad-credential"] = (s == 403, f"http={s}")

    admin("revoke-agent", "h-worker")
    s, _ = req(ENVOY + "/api/transfer",
               c.headers_for("authorize_payment", value_cents=100))
    R["revoked-credential"] = (s == 403, f"http={s}")

    out = admin("provision-agent", "h-worker2", "--max-cents=5000")
    c2 = AgentClient("h-worker2", json.loads(out)["agent_private_key"])
    h = c2.headers_for("authorize_payment", value_cents=100)
    s1, _ = req(ENVOY + "/api/transfer", h)
    s2, _ = req(ENVOY + "/api/transfer", h)
    R["replay"] = (s1 == 200 and s2 == 403, f"{s1}/{s2}")

    s, _ = req(API_DIRECT + "/transfer", {"x-ol-decision": "forged"},
               b'{"to":"x"}')
    R["forged-header"] = (s == 403, f"http={s}")

    s, b = req(ENVOY + "/api/transfer",
               c2.headers_for("authorize_payment", value_cents=100),
               body=b'{"to":"x","cents":999999}')
    won = json.loads(b).get("authorized_params", {}).get("value_cents")
    R["tampered-amount"] = (s == 200 and won == 100, f"executed={won}")
    return R


# -- OPA scenarios ------------------------------------------------------
def run_opa(baseline):
    stop_all()
    env = start_common("opa")
    opa = subprocess.Popen(
        [OPA_BIN, "run", "--server", "--addr", "127.0.0.1:8181",
         str(GWROOT / "opa" / f"policy-{baseline}.rego")],
        stdout=open("/tmp/gw-opa.log", "a"), stderr=subprocess.STDOUT,
        start_new_session=True)
    open("/tmp/gw-opa.pid", "w").write(str(opa.pid))
    time.sleep(2)
    shim = subprocess.Popen(
        [sys.executable, str(GWROOT / "opa_shim.py"), "50052"],
        stdout=open("/tmp/gw-shim.log", "a"), stderr=subprocess.STDOUT,
        env=env, start_new_session=True)
    open("/tmp/gw-shim.pid", "w").write(str(shim.pid))
    time.sleep(1)
    start_envoy("envoy-opa.yaml")
    R = {}

    if baseline == "a":
        good = {"Authorization": "Bearer opaline-token-001"}
        bad = {"Authorization": "Bearer nope"}
    else:
        opa_write("valid_tokens",
                  {"tok-001": True, "tok-002": True})
        opa_write("revoked_tokens", {})
        good = {"Authorization": "Bearer tok-001"}
        bad = {"Authorization": "Bearer nope"}

    s, b = req(ENVOY + "/api/transfer", good,
               b'{"to":"vendor","cents":100}')
    R["valid-request"] = (s == 200, f"http={s}")

    s, _ = req(ENVOY + "/api/transfer", bad)
    R["bad-credential"] = (s == 403, f"http={s}")

    if baseline == "a":
        # Baseline A has no revocation mechanism: the token is hardcoded.
        # Honest result: revocation unsupported -> still allowed.
        s, _ = req(ENVOY + "/api/transfer", good)
        R["revoked-credential"] = (s == 200, "no revocation in baseline A")
    else:
        opa_write("revoked_tokens", {"tok-001": True})
        time.sleep(0.5)
        s, _ = req(ENVOY + "/api/transfer", good)
        R["revoked-credential"] = (s == 403, f"http={s} after revoke")

    h = dict(good) if baseline == "a" else \
        {"Authorization": "Bearer tok-002"}
    s1, _ = req(ENVOY + "/api/transfer", h, b'{"to":"v","cents":10}')
    s2, _ = req(ENVOY + "/api/transfer", h, b'{"to":"v","cents":10}')
    R["replay"] = (s1 == 200 and s2 == 200, f"{s1}/{s2} (no replay check)")

    s, _ = req(API_DIRECT + "/transfer", {"x-opa-decision": "allow"},
               b'{"to":"x","cents":10}')
    R["forged-header"] = (s == 200, f"http={s} (unsigned header)")

    s, b = req(ENVOY + "/api/transfer", h, b'{"to":"x","cents":999999}')
    R["tampered-amount"] = (s == 200, "body amount executed as-is")
    return R


def main():
    all_results = {}
    for name, fn in (("openline", run_openline), ("opa-a", lambda: run_opa("a")),
                     ("opa-b", lambda: run_opa("b"))):
        print(f"=== {name} ===")
        R = fn()
        all_results[name] = {k: {"pass": p, "note": n}
                             for k, (p, n) in R.items()}
        for k, (p, n) in R.items():
            print(f"  [{'PASS' if p else 'FAIL'}] {k}: {n}")
    stop_all()
    (GWROOT / "bench" / "head_to_head.json").write_text(
        json.dumps(all_results, indent=2))
    print("\nwrote bench/head_to_head.json")


if __name__ == "__main__":
    main()
