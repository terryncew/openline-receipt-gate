#!/usr/bin/env python3
"""Mock business API: simulated consequential actions.

Simulated ledger only: no real money, credentials, customer data, or
production resources. The API NEVER trusts the agent's request body for
consequential fields. In enforce mode it executes exactly the action
described in the receiver-signed decision token (x-ol-decision), which
only the authorization service can mint. Decision tokens are single-use:
replaying one is refused.

In observe mode (read from shared policy.json) the API executes the
requested action normally and logs the x-ol-observe-decision header, so
operators can see what WOULD have been decided.

Set GW_LOG_HEADERS=1 to log received x-ol-* headers (debugging).
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey)
from profiling import profiled, set_trace, span

HERE = Path(__file__).resolve().parent
CONFIG_DIR = Path(os.environ.get("GATEWAY_CONFIG", HERE / "config"))
DB_PATH = Path(os.environ.get("GATEWAY_DB", HERE / "state" / "gateway.db"))
PORT = int(os.environ.get("MOCK_API_PORT", "9000"))
# Bind address: 127.0.0.1 is correct for ./up.sh (all processes share
# the host loopback), but inside Docker Compose Envoy reaches this API
# via the container's bridge IP, so it must bind 0.0.0.0 there. Set
# MOCK_API_HOST=0.0.0.0 in the compose file (the port is not published
# to the host; only the compose network can reach it).
HOST = os.environ.get("MOCK_API_HOST", "127.0.0.1")
# GATEWAY_AUTH_MODE=openline (default): require receiver-signed decision
# token. =opa: accept OPA's unsigned x-opa-decision header (used for the
# head-to-head baselines; see the report for the security implications).
AUTH_MODE = os.environ.get("GATEWAY_AUTH_MODE", "openline")
# GATEWAY_STANDING_CHECK=1: before executing, re-verify with the authz
# service that the decision is still standing (experimental; see
# docs/STANDING-CHECK.md). Narrows the post-revocation window from the
# token TTL to the check-to-commit interval. Fail-closed.
STANDING_CHECK = os.environ.get("GATEWAY_STANDING_CHECK") == "1"
STANDING_URL = os.environ.get("GATEWAY_STANDING_URL",
                              "http://127.0.0.1:50053/standing")


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def receiver_pubkey():
    key_b64 = (CONFIG_DIR / "receiver.key").read_text().strip()
    return Ed25519PrivateKey.from_private_bytes(
        b64u_decode(key_b64)).public_key()


def mode() -> str:
    try:
        return json.loads((CONFIG_DIR / "policy.json").read_text()
                          ).get("mode", "enforce")
    except Exception:
        return "enforce"


class Ledger:
    """Simulated balances. Survives process restarts via sqlite."""

    def __init__(self, db_path: Path):
        self.db = sqlite3.connect(str(db_path), check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS balances("
                        "acct TEXT PRIMARY KEY, cents INTEGER)")
        self.db.execute("CREATE TABLE IF NOT EXISTS used_decisions("
                        "decision_id TEXT PRIMARY KEY, ts INTEGER)")
        self.db.execute("CREATE TABLE IF NOT EXISTS effects("
                        "effect_id TEXT PRIMARY KEY, ts TEXT, body TEXT)")
        for acct, cents in (("treasury", 1_000_000), ("ops", 50_000)):
            self.db.execute("INSERT OR IGNORE INTO balances VALUES(?,?)",
                            (acct, cents))
        self.db.commit()

    @profiled("api.protected_execution")
    def transfer(self, to_acct: str, cents: int, decision_id: str) -> dict:
        if self.db.execute("SELECT 1 FROM used_decisions WHERE decision_id=?",
                           (decision_id,)).fetchone():
            return {"ok": False, "error": "decision token already used"}
        cur = self.db.execute("SELECT cents FROM balances WHERE acct=?",
                              ("treasury",))
        bal = cur.fetchone()[0]
        if bal < cents:
            return {"ok": False, "error": "insufficient simulated funds"}
        self.db.execute("UPDATE balances SET cents=cents-? WHERE acct=?",
                        (cents, "treasury"))
        self.db.execute("INSERT OR IGNORE INTO balances(acct, cents)"
                        " VALUES(?,0)", (to_acct,))
        self.db.execute("UPDATE balances SET cents=cents+? WHERE acct=?",
                        (cents, to_acct))
        self.db.execute("INSERT INTO used_decisions VALUES(?,?)",
                        (decision_id, int(time.time())))
        effect_id = f"fx-{decision_id}"
        self.db.execute(
            "INSERT INTO effects VALUES(?,?,?)",
            (effect_id, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
             json.dumps({"to": to_acct, "cents": cents,
                         "decision_id": decision_id})))
        with span("sqlite.ledger_durable_commit"):
            self.db.commit()
        return {"ok": True, "effect_id": effect_id,
                "treasury_cents": bal - cents}

    def balance(self, acct: str) -> int:
        row = self.db.execute("SELECT cents FROM balances WHERE acct=?",
                              (acct,)).fetchone()
        return row[0] if row else 0


LEDGER = Ledger(DB_PATH)
PUB = receiver_pubkey()


@profiled("crypto.decision_verification")
def verify_decision_token(token_b64: str):
    """Return the authorized action dict, or None."""
    try:
        token = json.loads(b64u_decode(token_b64))
        sig = b64u_decode(token.pop("sig"))
        PUB.verify(sig, canonical(token))
        if time.time() - token["issued_at"] > token["ttl"]:
            return None
        return token
    except Exception:
        return None


@profiled("api.standing_roundtrip")
def _standing_ok(token) -> bool:
    """Ask the authz service whether this decision is still standing."""
    import urllib.request as _url
    from urllib.parse import urlencode
    qs = urlencode({"decision_id": token["decision_id"],
                    "agent_id": token.get("agent_id", ""),
                    "issued_at": token["issued_at"]})
    try:
        with _url.urlopen(STANDING_URL + "?" + qs, timeout=2) as r:
            return json.loads(r.read()).get("standing") is True
    except Exception:
        # Fail closed: if the standing service is unreachable, do not
        # execute. This is a new availability dependency — documented in
        # docs/STANDING-CHECK.md.
        return False


class Handler(BaseHTTPRequestHandler):
    server_version = "MockLedger/0.1"

    @profiled("api.response_write")
    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

    @profiled("api.request")
    def do_GET(self):
        set_trace(self.headers.get("x-request-id"))
        if self.path == "/health":
            return self._send(200, {"ok": True})
        if self.path.startswith("/balance"):
            acct = self.path.rsplit("/", 1)[-1] or "treasury"
            return self._send(200, {"acct": acct,
                                   "cents": LEDGER.balance(acct)})
        return self._send(404, {"error": "not found"})

    @profiled("api.request")
    def do_POST(self):
        set_trace(self.headers.get("x-request-id"))
        if os.environ.get("GW_LOG_HEADERS"):
            with open("/tmp/gw-headers.log", "a") as f:
                f.write(json.dumps(dict(self.headers)) + "\n")
        with span("api.request_handling"):
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw)
            except Exception:
                body = {}
        if self.path == "/transfer":
            return self._transfer(body)
        return self._send(404, {"error": "not found"})

    def _transfer(self, body):
        with span("api.policy_read"):
            current_mode = mode()
        if current_mode == "observe":
            decided = self.headers.get("x-ol-observe-decision", "unknown")
            to_acct = body.get("to", "vendor")
            cents = int(body.get("cents", 0))
            res = LEDGER.transfer(to_acct, cents,
                                  f"observe-{time.time_ns()}")
            res["observe_decision"] = decided
            res["warning"] = "OBSERVE MODE: executed without enforcement"
            return self._send(200, res)
        if AUTH_MODE == "opa":
            # Head-to-head baseline: OPA's decision arrives as an unsigned
            # header. The security boundary here is the network (Envoy as
            # the only ingress), not cryptography — this is the honest
            # architectural difference under test.
            if self.headers.get("x-opa-decision") != "allow":
                return self._send(403, {"ok": False,
                                        "error": "OPA did not allow"})
            to_acct = body.get("to", "vendor")
            cents = int(body.get("cents", 0))
            res = LEDGER.transfer(to_acct, cents,
                                  f"opa-{time.time_ns()}")
            res["note"] = "executed per OPA allow (unsigned header)"
            return self._send(200 if res["ok"] else 409, res)
        # ENFORCE: only a receiver-signed, single-use decision token
        # authorizes execution. The body is NOT trusted for amount or
        # destination; the token's authorized params are executed.
        token = verify_decision_token(
            self.headers.get("x-ol-decision", ""))
        if token is None:
            return self._send(403, {"ok": False,
                                    "error": "missing or invalid decision "
                                             "token (bypass refused)"})
        if token["action_type"] != "authorize_payment":
            return self._send(403, {"ok": False,
                                    "error": "decision token does not "
                                             "authorize this endpoint"})
        check_at = None
        if STANDING_CHECK:
            # Execution-time standing verification: is this decision
            # still good RIGHT NOW, not just at authorization time?
            check_at = time.time()
            if not _standing_ok(token):
                return self._send(403, {"ok": False,
                                        "error": "decision no longer "
                                                 "standing at execution"})
        # TEST-ONLY hook (no-op unless GATEWAY_TEST_PRE_COMMIT_DELAY_MS
        # is set): sleep between the standing check and the ledger
        # commit so kill -9 tests can land the process inside that
        # window. Never set in production.
        _pre = os.environ.get("GATEWAY_TEST_PRE_COMMIT_DELAY_MS")
        if _pre:
            try:
                time.sleep(float(_pre) / 1000.0)
            except ValueError:
                pass
        res = LEDGER.transfer("vendor", token["value_cents"],
                              token["decision_id"])
        if check_at is not None:
            # The irreducible race, measured: revocation landing between
            # the standing check and the ledger commit still executes.
            res["standing_to_commit_ms"] = round(
                (time.time() - check_at) * 1000, 3)
        res["authorized_params"] = {
            "value_cents": token["value_cents"],
            "agent": token.get("agent_id")}
        return self._send(200 if res["ok"] else 409, res)


if __name__ == "__main__":
    print(f"[mock-api] on {HOST}:{PORT}", flush=True)
    HTTPServer((HOST, PORT), Handler).serve_forever()
