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
import uuid
from datetime import datetime, timezone
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


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


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
        # POPPY-PROOF-001: one-use transaction approvals. Each
        # (mandate_id, operation_hash) may execute at most once.
        # Survives restart via sqlite.
        self.db.execute("CREATE TABLE IF NOT EXISTS used_approvals("
                        "approval_id TEXT PRIMARY KEY, ts INTEGER)")
        for acct, cents in (("treasury", 1_000_000), ("ops", 50_000)):
            self.db.execute("INSERT OR IGNORE INTO balances VALUES(?,?)",
                            (acct, cents))
        self.db.commit()

    def approval_used(self, approval_id: str) -> bool:
        return self.db.execute(
            "SELECT 1 FROM used_approvals WHERE approval_id=?",
            (approval_id,)).fetchone() is not None

    def mark_approval_used(self, approval_id: str) -> None:
        self.db.execute("INSERT OR IGNORE INTO used_approvals VALUES(?,?)",
                        (approval_id, int(time.time())))
        self.db.commit()

    def transfer_with_approval_and_receipt(self, to_acct: str, cents: int,
                               decision_id: str, approval_id: str,
                               receipt_json: str) -> dict:
        """Atomic transfer + approval + signed receipt storage.
        
        All three happen in a single sqlite transaction. If the process
        crashes, either all persist or none do. A committed effect is
        never left without its signed evidence.
        """
        try:
            self.db.execute("BEGIN IMMEDIATE")
            
            if self.db.execute(
                "SELECT 1 FROM used_approvals WHERE approval_id=?",
                (approval_id,)).fetchone():
                self.db.execute("ROLLBACK")
                return {"ok": False, "error": "TRANSACTION_APPROVAL_ALREADY_USED"}
            
            if self.db.execute(
                "SELECT 1 FROM used_decisions WHERE decision_id=?",
                (decision_id,)).fetchone():
                self.db.execute("ROLLBACK")
                return {"ok": False, "error": "decision token already used"}
            
            cur = self.db.execute("SELECT cents FROM balances WHERE acct=?",
                                  ("treasury",))
            bal = cur.fetchone()[0]
            if bal < cents:
                self.db.execute("ROLLBACK")
                return {"ok": False, "error": "insufficient simulated funds"}
            
            self.db.execute("UPDATE balances SET cents=cents-? WHERE acct=?",
                            (cents, "treasury"))
            self.db.execute("INSERT OR IGNORE INTO balances(acct, cents)"
                            " VALUES(?,0)", (to_acct,))
            self.db.execute("UPDATE balances SET cents=cents+? WHERE acct=?",
                            (cents, to_acct))
            self.db.execute("INSERT INTO used_decisions VALUES(?,?)",
                            (decision_id, int(time.time())))
            self.db.execute("INSERT INTO used_approvals VALUES(?,?)",
                            (approval_id, int(time.time())))
            
            effect_id = f"fx-{decision_id}"
            self.db.execute(
                "INSERT INTO effects VALUES(?,?,?)",
                (effect_id, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 json.dumps({"to": to_acct, "cents": cents,
                             "decision_id": decision_id,
                             "receipt": receipt_json})))
            
            self.db.commit()
            return {"ok": True, "effect_id": effect_id,
                    "treasury_cents": bal - cents}
        except Exception as e:
            try:
                self.db.execute("ROLLBACK")
            except Exception:
                pass
            return {"ok": False, "error": f"transaction failed: {e}"}

    def transfer_with_approval(self, to_acct: str, cents: int,
                               decision_id: str, approval_id: str) -> dict:
        """Atomic transfer + approval consumption.
        
        Both the ledger transfer and the approval marking happen in a
        single sqlite transaction. If the process crashes, either both
        persist or neither does — no double-spend window.
        
        Returns {"ok": True, ...} or {"ok": False, "error": ...}.
        """
        try:
            # Start transaction (sqlite is in autocommit; BEGIN starts txn)
            self.db.execute("BEGIN IMMEDIATE")
            
            # Check approval not already used (within txn)
            if self.db.execute(
                "SELECT 1 FROM used_approvals WHERE approval_id=?",
                (approval_id,)).fetchone():
                self.db.execute("ROLLBACK")
                return {"ok": False, "error": "TRANSACTION_APPROVAL_ALREADY_USED"}
            
            # Check decision not already used
            if self.db.execute(
                "SELECT 1 FROM used_decisions WHERE decision_id=?",
                (decision_id,)).fetchone():
                self.db.execute("ROLLBACK")
                return {"ok": False, "error": "decision token already used"}
            
            # Check funds
            cur = self.db.execute("SELECT cents FROM balances WHERE acct=?",
                                  ("treasury",))
            bal = cur.fetchone()[0]
            if bal < cents:
                self.db.execute("ROLLBACK")
                return {"ok": False, "error": "insufficient simulated funds"}
            
            # Do transfer
            self.db.execute("UPDATE balances SET cents=cents-? WHERE acct=?",
                            (cents, "treasury"))
            self.db.execute("INSERT OR IGNORE INTO balances(acct, cents)"
                            " VALUES(?,0)", (to_acct,))
            self.db.execute("UPDATE balances SET cents=cents+? WHERE acct=?",
                            (cents, to_acct))
            self.db.execute("INSERT INTO used_decisions VALUES(?,?)",
                            (decision_id, int(time.time())))
            
            # Mark approval used (within same txn)
            self.db.execute("INSERT INTO used_approvals VALUES(?,?)",
                            (approval_id, int(time.time())))
            
            # Record effect
            effect_id = f"fx-{decision_id}"
            self.db.execute(
                "INSERT INTO effects VALUES(?,?,?)",
                (effect_id, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 json.dumps({"to": to_acct, "cents": cents,
                             "decision_id": decision_id})))
            
            self.db.commit()
            return {"ok": True, "effect_id": effect_id,
                    "treasury_cents": bal - cents}
        except Exception as e:
            try:
                self.db.execute("ROLLBACK")
            except Exception:
                pass
            return {"ok": False, "error": f"transaction failed: {e}"}

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

        # Layer 1: Delegated authority — Gateway decision token ONLY.
        # Proves the agent is permitted. Does NOT prove human approval.
        #
        # The token must come from the live Gateway authorization service
        # via Envoy ext_authz. Direct header verification was removed
        # (2026-10-11 review): the test must exercise the complete path,
        # not substitute its own verification for the Gateway's.
        token = verify_decision_token(
            self.headers.get("x-ol-decision", ""))
        if token is None:
            return self._send(403, {"ok": False,
                                    "error": "missing or invalid decision "
                                             "token (delegated authority "
                                             "not established via Gateway)"})
        if token["action_type"] != "authorize_payment":
            return self._send(403, {"ok": False,
                                    "error": "decision token does not "
                                             "authorize this endpoint"})
        delegated_via = "decision_token"
        agent_id = token.get("agent_id")
        # Amount binding (finding 3): the token's authorized amount must
        # EXACTLY match the operation amount. An action signed for $0
        # cannot authorize a $42.50 execution, even if the mandate
        # ceiling is $50.
        token_amount = int(token.get("value_cents", 0))

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

        # One-use semantics (finding 2): a transaction approval authorizes
        # exactly ONE execution. A second execution with a fresh challenge
        # but the same (mandate_id, operation_hash) is rejected. This
        # distinguishes "owner approved these terms" (the mandate) from
        # "owner approved this execution" (the one-use approval).
        mandate_id = presentation.get("mandate_id", "")
        
        # Identity binding: the Wallet mandate's subject must match the
        # Gateway's agent_id. Prevents mixing: Agent B cannot use Owner's
        # approval issued to Agent A.
        # The presentation contains the subject_id from the mandate.
        mandate_subject = presentation.get("subject_id", "")
        if mandate_subject and mandate_subject != agent_id:
            return self._send(403, {
                "ok": False,
                "error": "IDENTITY_MISMATCH",
                "detail": f"Wallet mandate issued to '{mandate_subject}' "
                          f"but Gateway token is for '{agent_id}'. "
                          f"Owner, agent, and operation identities must match.",
                "delegated_authority": "valid",
                "transaction_approval": "valid",
            })
        
        approval_id = f"{mandate_id}:{op_hash}"
        if LEDGER.approval_used(approval_id):
            return self._send(403, {
                "ok": False,
                "error": "TRANSACTION_APPROVAL_ALREADY_USED",
                "detail": "This owner approval was already executed. A "
                          "fresh challenge does not create a fresh approval. "
                          "The owner must issue a new approval for another "
                          "execution.",
                "delegated_authority": "valid",
                "transaction_approval": "already_used",
            })

        # Both layers passed: execute the exact approved terms.
        # The amount comes from the Wallet-approved operation — the human's
        # approval is authoritative for the terms.
        #
        # Amount binding (finding 3): the Gateway token's authorized amount
        # must EXACTLY equal the operation amount. An action signed for $0
        # cannot authorize a $42.50 execution, even if the mandate ceiling
        # is $50. The token binds the delegated amount; the Wallet binds
        # the approved amount; they must agree exactly.
        amount = int(operation.get("amount_cents", 0))
        merchant = operation.get("merchant", "vendor")
        if token_amount != amount:
            return self._send(403, {
                "ok": False,
                "error": "AMOUNT_BINDING_MISMATCH",
                "detail": f"Gateway authorized ${token_amount/100:.2f} but "
                          f"operation requests ${amount/100:.2f}. The "
                          f"delegated amount must exactly match the approved "
                          f"transaction amount.",
                "delegated_authority": "valid",
                "transaction_approval": "valid",
                "token_amount_cents": token_amount,
                "operation_amount_cents": amount,
            })
        # The mock ledger debits treasury and credits the merchant.
        # The operation's account must be treasury (the funded account).
        #
        # TRANSACTION BOUNDARY (corrected):
        # A committed effect must not leave the system without recoverable
        # signed evidence. Therefore:
        # 1. Build receipt with expected post-transfer balances.
        # 2. Sign it. If signing fails, FAIL BEFORE any state change.
        # 3. Atomic transfer + store signed receipt in single txn.
        treasury_before = LEDGER.balance("treasury")
        merchant_before = LEDGER.balance(merchant)
        # Expected balances (transfer is atomic, so these WILL be actual)
        treasury_after = treasury_before - amount
        merchant_after = merchant_before + amount
        
        decision_evidence = {
            "type": "poppy_decision",
            "decision": "ALLOWED",
            "delegated_authority": {
                "verified_via": delegated_via,
                "agent_id": agent_id,
                "token_amount_cents": token_amount,
            },
            "transaction_approval": {
                "verified": "owner-signed exact terms",
                "mandate_id": mandate_id,
                "principal_id": principal_id,
                "operation_hash": op_hash,
            },
            "amount_binding": {
                "token_amount_cents": token_amount,
                "operation_amount_cents": amount,
                "match": token_amount == amount,
            },
            "decided_at": datetime.now(timezone.utc).isoformat(),
        }
        effect_evidence = {
            "type": "poppy_ledger_effect",
            "treasury_before_cents": treasury_before,
            "treasury_after_cents": treasury_after,
            "treasury_delta_cents": treasury_after - treasury_before,
            "merchant": merchant,
            "merchant_before_cents": merchant_before,
            "merchant_after_cents": merchant_after,
            "merchant_delta_cents": merchant_after - merchant_before,
            "amount_cents": amount,
            "measured_at": datetime.now(timezone.utc).isoformat(),
        }
        receipt_unsigned = {
            "receipt_id": f"poppy-{uuid.uuid4().hex[:16]}",
            "decision_evidence": decision_evidence,
            "effect_evidence": effect_evidence,
        }
        # Sign BEFORE the transfer. If this fails, no effect is committed.
        try:
            key_b64 = (CONFIG_DIR / "receiver.key").read_text().strip()
            rkey = Ed25519PrivateKey.from_private_bytes(b64u_decode(key_b64))
            sig = rkey.sign(canonical(receipt_unsigned))
            receipt = dict(receipt_unsigned)
            receipt["receiver_signature"] = b64u_encode(sig)
            receipt["receiver_public_key"] = b64u_encode(
                rkey.public_key().public_bytes_raw())
        except Exception as e:
            # Fail closed BEFORE any state change. No committed effect
            # without signed evidence.
            return self._send(500, {"ok": False,
                                    "error": "receipt signing failed",
                                    "detail": str(e)})
        
        # ATOMIC: transfer + approval + store signed receipt in single txn.
        res = LEDGER.transfer_with_approval_and_receipt(
            merchant, amount, f"poppy-{time.time_ns()}", approval_id,
            json.dumps(receipt, sort_keys=True))
        if not res.get("ok"):
            err = res.get("error", "")
            if "ALREADY_USED" in err:
                return self._send(403, {
                    "ok": False,
                    "error": "TRANSACTION_APPROVAL_ALREADY_USED",
                    "detail": "This owner approval was already executed.",
                    "delegated_authority": "valid",
                    "transaction_approval": "already_used",
                })
            return self._send(409, res)

        # Update effect_id in receipt (from atomic txn)
        receipt["effect_evidence"]["effect_id"] = res.get("effect_id")
        res["poppy_receipt"] = receipt
        return self._send(200, res)

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
