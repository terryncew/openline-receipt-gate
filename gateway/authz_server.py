#!/usr/bin/env python3
"""OpenLine Gateway authorization service: Envoy ext_authz v3 Check API.

The receiver — not the agent — owns the authorization policy and trusted
keys. Per CheckRequest the service:

  1. extracts the agent's proposed action from request headers,
  2. verifies the agent is known and not revoked (receiver-owned registry),
  3. verifies the Ed25519 signature over the canonical action bytes,
  4. rejects replayed nonces (durable sqlite),
  5. re-evaluates the owner's principal_mandate/v1 via olp_gate at
     consequence time (compile then re-verify),
  6. mints a short-lived, single-use downstream decision token signed
     with the RECEIVER key (the mock API verifies this, not the agent's
     word),
  7. appends a signed decision receipt to durable storage.

OBSERVE mode: evaluates and records everything, returns OK regardless
(clearly labeled non-protective). ENFORCE mode: denies unless all checks
pass. Mode is an administrator action (policy.json + restart/SIGHUP);
agent headers can never select the mode.
"""

from __future__ import annotations

import base64
import json
import os
import signal
import sqlite3
import sys
import time
import uuid
from concurrent import futures
from datetime import datetime, timezone
from pathlib import Path

import grpc
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))  # olp_gate

import ext_authz_pb2 as pb2
import ext_authz_pb2_grpc as pb2_grpc
from olp_gate.mandate_gate import mandate_preflight
from olp_gate.mandate import compile_verified_commit_settings

CONFIG_DIR = Path(os.environ.get("GATEWAY_CONFIG", HERE / "config"))
DB_PATH = Path(os.environ.get("GATEWAY_DB", HERE / "state" / "gateway.db"))
NONCE_SKEW_SECONDS = 300
DECISION_TTL_SECONDS = 60

# google.rpc.Code values used in CheckResponse.status
CODE_OK = 0
CODE_PERMISSION_DENIED = 7


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class GatewayState:
    """Durable receiver-owned state: nonces, receipts, agent registry."""

    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS nonces("
            "nonce TEXT PRIMARY KEY, ts INTEGER)")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS receipts("
            "receipt_id TEXT PRIMARY KEY, ts TEXT, body TEXT)")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS agents("
            "agent_id TEXT PRIMARY KEY, pubkey TEXT, mandate TEXT, "
            "revoked INTEGER DEFAULT 0)")
        self.db.commit()

    def nonce_seen(self, nonce: str) -> bool:
        row = self.db.execute(
            "SELECT 1 FROM nonces WHERE nonce=?", (nonce,)).fetchone()
        return row is not None

    def mark_nonce(self, nonce: str):
        self.db.execute(
            "INSERT OR IGNORE INTO nonces(nonce, ts) VALUES(?,?)",
            (nonce, int(time.time())))
        self.db.commit()

    def add_receipt(self, receipt: dict):
        self.db.execute(
            "INSERT INTO receipts(receipt_id, ts, body) VALUES(?,?,?)",
            (receipt["receipt_id"], receipt["ts"],
             json.dumps(receipt, sort_keys=True)))
        self.db.commit()

    def get_agent(self, agent_id: str):
        row = self.db.execute(
            "SELECT pubkey, mandate, revoked FROM agents WHERE agent_id=?",
            (agent_id,)).fetchone()
        if not row:
            return None
        return {"pubkey": row[0], "mandate": json.loads(row[1]),
                "revoked": bool(row[2])}


class Authorizer(pb2_grpc.AuthorizationServicer):
    def __init__(self):
        self.state = GatewayState(DB_PATH)
        self.reload_config()
        signal.signal(signal.SIGHUP, lambda *_: self.reload_config())

    def reload_config(self):
        cfg = json.loads((CONFIG_DIR / "policy.json").read_text())
        self.mode = cfg.get("mode", "enforce")
        assert self.mode in ("observe", "enforce"), "bad mode"
        key_b64 = (CONFIG_DIR / "receiver.key").read_text().strip()
        self.receiver_key = Ed25519PrivateKey.from_private_bytes(
            b64u_decode(key_b64))
        print(f"[authz] config reloaded: mode={self.mode}", flush=True)

    def Check(self, request, context):
        t0 = time.perf_counter()
        http = request.attributes.request.http
        headers = dict(http.headers)
        agent_id = headers.get("x-ol-agent", "")
        action_b64 = headers.get("x-ol-action", "")
        sig_b64 = headers.get("x-ol-sig", "")
        decision, reasons, detail = self._evaluate(
            agent_id, action_b64, sig_b64)
        latency_ms = (time.perf_counter() - t0) * 1000

        receipt = {
            "receipt_id": f"gw-{uuid.uuid4().hex[:12]}",
            "ts": datetime.now(timezone.utc).isoformat(),
            "mode": self.mode,
            "agent_id": agent_id,
            "http_method": http.method,
            "http_path": http.path,
            "decision": decision,
            "reasons": reasons,
            "latency_ms": round(latency_ms, 3),
            "detail": detail,
        }
        sig = self.receiver_key.sign(canonical(
            {k: receipt[k] for k in sorted(receipt)}))
        receipt["receiver_sig"] = b64u_encode(sig)
        self.state.add_receipt(receipt)

        if self.mode == "observe":
            # Non-protective by explicit labeling: evaluate + record,
            # allow regardless.
            return pb2.CheckResponse(
                status=pb2.RpcStatus(code=CODE_OK),
                ok_response=pb2.OkHttpResponse(headers=[
                    pb2.HeaderValueOption(header=pb2.HeaderValue(
                        key="x-ol-observe-decision",
                        value=f"{decision}:{','.join(reasons)}")),
                ]))

        if decision == "allow":
            token = self._mint_decision_token(detail)
            return pb2.CheckResponse(
                status=pb2.RpcStatus(code=CODE_OK),
                ok_response=pb2.OkHttpResponse(headers=[
                    pb2.HeaderValueOption(header=pb2.HeaderValue(
                        key="x-ol-decision", value=token)),
                ]))
        return pb2.CheckResponse(
            status=pb2.RpcStatus(code=CODE_PERMISSION_DENIED,
                                 message=";".join(reasons)),
            denied_response=pb2.DeniedHttpResponse(
                status=pb2.HttpStatus(code=403),
                body=json.dumps({"denied": True, "reasons": reasons})))

    def _evaluate(self, agent_id, action_b64, sig_b64):
        if not action_b64 or not agent_id or not sig_b64:
            return ("deny", ["missing_action_claim"],
                    {"note": "no OpenLine action headers present"})
        agent = self.state.get_agent(agent_id)
        if agent is None:
            return ("deny", ["unknown_agent"], {})
        if agent["revoked"]:
            return ("deny", ["agent_revoked"], {})
        try:
            action = json.loads(b64u_decode(action_b64))
            sig = b64u_decode(sig_b64)
        except Exception:
            return ("deny", ["malformed_action_claim"], {})
        for f in ("action_type", "target", "value_cents", "nonce", "ts"):
            if f not in action:
                return ("deny", ["action_field_missing:" + f], {})
        try:
            pub = Ed25519PublicKey.from_public_bytes(
                b64u_decode(agent["pubkey"]))
            pub.verify(sig, canonical(action))
        except Exception:
            return ("deny", ["signature_invalid"], {})
        now = time.time()
        if abs(now - action["ts"]) > NONCE_SKEW_SECONDS:
            return ("deny", ["stale_action_claim"], {})
        if self.state.nonce_seen(action["nonce"]):
            return ("deny", ["replay_detected"], {})
        # Consequence-time mandate evaluation (receiver-owned, olp_gate):
        # compile the settings, then re-verify immediately before the
        # decision — the receiver never trusts the producer's word.
        mandate = agent["mandate"]
        effect = {
            "profile": "principal_effect/v1",
            "effect_id": f"fx-{action['nonce']}",
            "mandate_id": mandate["mandate_id"],
            "principal_id": mandate["principal_id"],
            "agent_id": agent_id,
            "purpose": mandate["purpose"],
            "action_type": action["action_type"],
            "target": action["target"],
            "disclosures": [],
            "value_cents": action["value_cents"],
            "delegatee": None,
            "producer_model": "unknown",
        }
        try:
            now_dt = datetime.now(timezone.utc)
            settings = compile_verified_commit_settings(
                mandate, effect, now=now_dt)
            pre = mandate_preflight(mandate, settings, now=now_dt)
        except PermissionError as exc:
            return ("deny", str(exc).split(",") or ["mandate_denied"], {})
        except Exception as exc:
            return ("deny", ["mandate_eval_error"],
                    {"error": str(exc)[:120]})
        if not pre["allowed"]:
            return ("deny", pre["reason_codes"], {})
        self.state.mark_nonce(action["nonce"])
        return ("allow", [], {"action": action,
                              "mandate_id": mandate["mandate_id"]})

    def _mint_decision_token(self, detail) -> str:
        action = detail["action"]
        token = {
            "decision_id": uuid.uuid4().hex[:16],
            "agent_id": action.get("agent_id", ""),
            "action_type": action["action_type"],
            "target": action["target"],
            "value_cents": action["value_cents"],
            "nonce": action["nonce"],
            "issued_at": int(time.time()),
            "ttl": DECISION_TTL_SECONDS,
        }
        sig = self.receiver_key.sign(canonical(token))
        token["sig"] = b64u_encode(sig)
        return b64u_encode(canonical(token))


def serve(port=50051):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=32))
    pb2_grpc.add_AuthorizationServicer_to_server(Authorizer(), server)
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    print(f"[authz] listening on :{port}", flush=True)
    server.wait_for_termination()


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 50051)
