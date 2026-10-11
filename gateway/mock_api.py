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

POPPY-PROOF-001 extension (experimental): the /poppy-charge endpoint
enforces a strict distinction between delegated authority and
transaction approval:
- Delegated authority (x-ol-decision token): the agent is permitted to
  perform actions within limits. Proves the AGENT is permitted.
- Transaction approval (x-ol-tx-approval header): the owner explicitly
  authorized THIS EXACT operation. Proves the HUMAN approved.
Delegated authority alone NEVER counts as transaction approval.

Set GW_LOG_HEADERS=1 to log received x-ol-* headers (debugging).
Set POPPY_OWNER_PIN=principal_id:root_pubkey_hex to enable the
/popppy-charge transaction-approval check.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey)

# POPPY-PROOF-001: Wallet verifier for transaction approval.
# Added to sys.path so the vendored contracts are importable when
# mockapi runs from the Docker image (PYTHONPATH=/app) or directly.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from openline_wallet import ReferenceGate
    from openline_wallet.errors import WalletError
    _WALLET_AVAILABLE = True
except ImportError:
    _WALLET_AVAILABLE = False

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
        self.db.commit()
        return {"ok": True, "effect_id": effect_id,
                "treasury_cents": bal - cents}

    def balance(self, acct: str) -> int:
        row = self.db.execute("SELECT cents FROM balances WHERE acct=?",
                              (acct,)).fetchone()
        return row[0] if row else 0


LEDGER = Ledger(DB_PATH)
PUB = receiver_pubkey()


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


# ---- POPPY-PROOF-001: transaction-approval verifier ----
#
# Module-level singleton: the business API pins the owner's root key
# at startup (from POPPY_OWNER_PIN). This is the business's own trust
# decision — it decides whose transaction approvals it accepts.

_poppy_verifier = None


def get_poppy_verifier():
    """Return the Wallet verifier for transaction approvals, or None."""
    global _poppy_verifier
    if _poppy_verifier is not None:
        return _poppy_verifier
    if not _WALLET_AVAILABLE:
        return None
    # Format: <principal_id>|<root_pubkey_hex>. The principal_id contains
    # colons (openline:principal:...), so we split on the LAST pipe.
    # Actually: principal_id has no pipes, root key is hex (no pipes).
    pin = os.environ.get("POPPY_OWNER_PIN", "")
    if not pin or "|" not in pin:
        return None
    principal_id, root_key = pin.rsplit("|", 1)
    gate = ReferenceGate("mockapi-poppy", max_bundle_age_seconds=300)
    gate.pin_principal(principal_id.strip(), root_key.strip())
    _poppy_verifier = gate
    return _poppy_verifier


def verify_delegated_headers(agent_id: str, action_b64: str,
                             sig_b64: str) -> dict:
    """Verify Gateway-style delegated authority headers directly.

    Same verification the authz service performs: look up the agent in
    the Gateway DB, verify the Ed25519 signature, check the mandate
    limits. Used by /poppy-charge when no decision token is present
    (integration test path).

    Returns {"ok": True, "max_cents": N} or {"ok": False, "reason": ...}.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey)
    try:
        action = json.loads(b64u_decode(action_b64))
        sig = b64u_decode(sig_b64)
    except Exception:
        return {"ok": False, "reason": "malformed_action_claim"}
    for f in ("action_type", "target", "value_cents", "nonce", "ts"):
        if f not in action:
            return {"ok": False, "reason": f"action_field_missing:{f}"}
    # Look up the agent in the Gateway DB.
    db_path = os.environ.get("GATEWAY_DB", "")
    if not db_path:
        return {"ok": False, "reason": "gateway_db_not_configured"}
    try:
        db = sqlite3.connect(db_path)
        row = db.execute(
            "SELECT pubkey, mandate, revoked FROM agents WHERE agent_id=?",
            (agent_id,)).fetchone()
        if row is None:
            return {"ok": False, "reason": "unknown_agent"}
        pubkey_b64, mandate_json, revoked = row
        if revoked:
            return {"ok": False, "reason": "agent_revoked"}
        pub = Ed25519PublicKey.from_public_bytes(b64u_decode(pubkey_b64))
        pub.verify(sig, canonical(action))
    except Exception as e:
        return {"ok": False, "reason": f"signature_invalid: {e}"}
    try:
        mandate = json.loads(mandate_json)
        max_cents = int(mandate.get("max_payment_cents", 0))
    except Exception:
        return {"ok": False, "reason": "mandate_parse_error"}
    if action["action_type"] not in mandate.get("allowed_action_types", []):
        return {"ok": False, "reason": "action_not_in_mandate"}
    if int(action.get("value_cents", 0)) > max_cents:
        return {"ok": False, "reason": "exceeds_delegated_limit"}
    return {"ok": True, "max_cents": max_cents}


class Handler(BaseHTTPRequestHandler):
    server_version = "MockLedger/0.1"

    def _send(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/health":
            return self._send(200, {"ok": True})
        if self.path.startswith("/balance"):
            acct = self.path.rsplit("/", 1)[-1] or "treasury"
            return self._send(200, {"acct": acct,
                                   "cents": LEDGER.balance(acct)})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if os.environ.get("GW_LOG_HEADERS"):
            with open("/tmp/gw-headers.log", "a") as f:
                f.write(json.dumps(dict(self.headers)) + "\n")
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw)
        except Exception:
            body = {}
        if self.path == "/transfer":
            return self._transfer(body)
        if self.path == "/poppy-charge":
            return self._poppy_charge(body)
        if self.path == "/poppy-admit":
            return self._poppy_admit(body)
        if self.path == "/poppy-challenge":
            return self._poppy_challenge(body)
        return self._send(404, {"error": "not found"})

    def _poppy_challenge(self, body):
        """POPPY-PROOF-001 test-only endpoint: issue a presentation challenge.

        EXPERIMENTAL — not for production. In a real deployment the
        business issues challenges through its own channel.
        """
        verifier = get_poppy_verifier()
        if verifier is None:
            return self._send(500, {"ok": False,
                                    "error": "POPPY_OWNER_PIN not configured"})
        principal_id = body.get("principal_id", "")
        subject_id = body.get("subject_id", "")
        action = body.get("action", "")
        if not principal_id or not subject_id or not action:
            return self._send(400, {"ok": False,
                                    "error": "missing principal_id, "
                                             "subject_id, or action"})
        try:
            ch = verifier.issue_challenge(
                principal_id=principal_id, subject_id=subject_id,
                action=action)
            return self._send(200, {"ok": True, "challenge": ch})
        except Exception as e:
            return self._send(500, {"ok": False, "error": str(e)})

    def _poppy_admit(self, body):
        """POPPY-PROOF-001 test-only endpoint: admit an authority bundle.

        In a real deployment the business admits bundles through its own
        operational process. This endpoint exists so the integration test
        can drive bundle admission without a separate admin channel.
        EXPERIMENTAL — not for production.
        """
        verifier = get_poppy_verifier()
        if verifier is None:
            return self._send(500, {"ok": False,
                                    "error": "POPPY_OWNER_PIN not configured"})
        bundle = body.get("bundle")
        if not bundle:
            return self._send(400, {"ok": False,
                                    "error": "missing bundle"})
        try:
            result = verifier.admit_bundle(bundle)
            return self._send(200, {"ok": True, "result": result})
        except WalletError as e:
            return self._send(403, {"ok": False, "error": str(e)})
        except Exception as e:
            return self._send(500, {"ok": False, "error": str(e)})

    # ---- POPPY-PROOF-001: strict delegated vs transaction distinction ----
    #
    # Delegated authority (x-ol-decision): the Gateway verified the agent's
    # signature against its provisioned mandate. This proves the AGENT is
    # permitted to act within limits. It does NOT prove the human approved
    # this specific transaction.
    #
    # Transaction approval (x-ol-tx-approval): a Wallet presentation proving
    # the owner explicitly authorized THIS EXACT operation (terms hash
    # match). This proves the HUMAN approved.
    #
    # Both are required. Delegated authority alone is NEVER sufficient.

    def _poppy_charge(self, body):
        """POPPY-PROOF-001 experimental endpoint.

        Requires BOTH:
        1. Delegated authority: valid Gateway decision token OR valid
           Gateway headers verified against the DB.
        2. Valid Wallet transaction approval for the exact operation
           (x-ol-tx-approval header: base64 JSON with presentation,
           principal_id, and operation).
        """
        try:
            return self._poppy_charge_inner(body)
        except Exception as e:
            import traceback
            traceback.print_exc()
            return self._send(500, {"ok": False,
                                    "error": f"internal: {e}"})

    def _poppy_charge_inner(self, body):
        if not _WALLET_AVAILABLE:
            return self._send(500, {"ok": False,
                                    "error": "wallet contracts unavailable"})
        verifier = get_poppy_verifier()
        if verifier is None:
            return self._send(500, {"ok": False,
                                    "error": "POPPY_OWNER_PIN not configured"})

        # Layer 1: Delegated authority.
        # Proves the agent is permitted. Does NOT prove human approval.
        #
        # Two modes:
        # - Full Gateway path: valid x-ol-decision token (minted by authz).
        # - Direct test path: valid x-ol-agent/x-ol-action/x-ol-sig headers,
        #   verified against the Gateway DB (same crypto the authz uses).
        #   Used by the integration test when the gRPC authz is not in the
        #   loop. The verification logic is identical.
        token = verify_decision_token(
            self.headers.get("x-ol-decision", ""))
        delegated_via = None
        agent_id = None
        delegated_limit = None
        if token is not None:
            if token["action_type"] != "authorize_payment":
                return self._send(403, {"ok": False,
                                        "error": "decision token does not "
                                                 "authorize this endpoint"})
            delegated_via = "decision_token"
            agent_id = token.get("agent_id")
            delegated_limit = int(token.get("value_cents", 0))
        else:
            # Direct header verification (test path).
            agent_id = self.headers.get("x-ol-agent", "")
            action_b64 = self.headers.get("x-ol-action", "")
            sig_b64 = self.headers.get("x-ol-sig", "")
            if not agent_id or not action_b64 or not sig_b64:
                return self._send(403, {"ok": False,
                                        "error": "missing or invalid decision "
                                                 "token (delegated authority "
                                                 "not established)"})
            verified = verify_delegated_headers(agent_id, action_b64, sig_b64)
            if not verified["ok"]:
                return self._send(403, {"ok": False,
                                        "error": "delegated authority invalid: "
                                                 + verified["reason"]})
            delegated_via = "direct_headers"
            delegated_limit = verified["max_cents"]

        # Layer 2: Transaction approval — owner-signed exact terms.
        # Proves the human approved THIS transaction. Never inferred
        # from delegated authority.
        tx_b64 = self.headers.get("x-ol-tx-approval", "")
        if not tx_b64:
            return self._send(403, {
                "ok": False,
                "error": "DELEGATED_AUTHORITY_NOT_TRANSACTION_APPROVAL",
                "detail": "The agent holds delegated authority (decision "
                          "token valid), but the owner did not approve this "
                          "specific transaction. Delegated authority is not "
                          "proof of human approval.",
                "delegated_authority": "valid",
                "transaction_approval": "missing",
            })
        try:
            tx = json.loads(base64.urlsafe_b64decode(tx_b64 + "=="))
            presentation = tx["presentation"]
            principal_id = tx["principal_id"]
            operation = tx["operation"]
        except Exception:
            return self._send(403, {"ok": False,
                                    "error": "malformed transaction approval",
                                    "delegated_authority": "valid",
                                    "transaction_approval": "malformed"})

        # The operation in the approval must match the requested operation.
        # The Gateway token carries the authorized amount; the Wallet
        # approval carries the exact terms. Both must agree.
        op_hash = hashlib.sha256(
            json.dumps(operation, sort_keys=True,
                       separators=(",", ":")).encode()).hexdigest()
        req_hash = hashlib.sha256(
            json.dumps(body.get("operation", {}), sort_keys=True,
                       separators=(",", ":")).encode()).hexdigest()
        if op_hash != req_hash:
            return self._send(403, {
                "ok": False,
                "error": "TRANSACTION_TERMS_MISMATCH",
                "detail": "The approved operation differs from the requested "
                          "operation. The owner approved different terms.",
                "delegated_authority": "valid",
                "transaction_approval": "terms_mismatch",
            })

        # Verify the Wallet presentation (owner signature, exact terms).
        expected_scope = f"poppy:op:{op_hash[:32]}"
        try:
            verifier.protect_action(
                expected_scope, required_recipient_scopes=[expected_scope])
        except WalletError:
            pass  # Already protected (idempotent for hash-derived names).
        decision = verifier.evaluate(presentation,
                                     expected_action=expected_scope)
        if decision.get("decision") != "ALLOWED":
            reasons = (decision.get("reason_codes")
                       or decision.get("reasons") or ["DENIED"])
            return self._send(403, {
                "ok": False,
                "error": "TRANSACTION_APPROVAL_INVALID",
                "detail": f"Owner transaction approval failed: {reasons}",
                "delegated_authority": "valid",
                "transaction_approval": "invalid",
                "reasons": reasons,
            })

        # Both layers passed: execute the exact approved terms.
        # The amount comes from the Wallet-approved operation — the human's
        # approval is authoritative for the terms. The delegated limit must
        # cover it (defense in depth: both layers constrain).
        amount = int(operation.get("amount_cents", 0))
        merchant = operation.get("merchant", "vendor")
        if delegated_limit < amount:
            return self._send(403, {
                "ok": False,
                "error": "DELEGATED_LIMIT_EXCEEDED",
                "detail": "Transaction approval exceeds delegated authority "
                          "limit.",
                "delegated_authority": "valid",
                "transaction_approval": "valid",
            })
        # The mock ledger debits treasury and credits the merchant.
        # The operation's account must be treasury (the funded account).
        res = LEDGER.transfer(merchant, amount,
                              f"poppy-{time.time_ns()}")
        res["poppy_receipt"] = {
            "delegated_authority": f"verified (via {delegated_via})",
            "transaction_approval": "verified (owner-signed exact terms)",
            "operation_hash": op_hash,
            "amount_cents": amount,
            "merchant": merchant,
        }
        return self._send(200 if res["ok"] else 409, res)

    def _transfer(self, body):
        if mode() == "observe":
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
