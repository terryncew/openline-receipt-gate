#!/usr/bin/env python3
"""Gateway admin: owner-only provisioning and control.

  gateway_admin.py init                          create receiver key + policy
  gateway_admin.py provision-agent <id> [--max-cents N]
      issues a principal_mandate/v1 and prints the agent's private key
      (shown once; the gateway stores only the public key)
  gateway_admin.py revoke-agent <id>
  gateway_admin.py set-mode <observe|enforce>
  gateway_admin.py verify-receipts                verify receiver signatures

All state lives in the gateway DB. Agents never touch this tool.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey)

HERE = Path(__file__).resolve().parent
CONFIG_DIR = Path(os.environ.get("GATEWAY_CONFIG", HERE / "config"))
DB_PATH = Path(os.environ.get("GATEWAY_DB", HERE / "state" / "gateway.db"))


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def cmd_init():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    key_path = CONFIG_DIR / "receiver.key"
    if not key_path.exists():
        key_path.write_text(b64u_encode(
            Ed25519PrivateKey.generate().private_bytes_raw()))
        os.chmod(key_path, 0o600)
        print(f"receiver key created: {key_path} (0600)")
    pol = CONFIG_DIR / "policy.json"
    if not pol.exists():
        pol.write_text(json.dumps({
            "mode": "enforce",
            "note": "OBSERVE evaluates and records without enforcing. "
                    "Mode changes are administrator actions only.",
        }, indent=2))
        print(f"policy created: {pol} (mode=enforce)")
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(DB_PATH))
    db.execute("CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY,"
               " ts INTEGER)")
    db.execute("CREATE TABLE IF NOT EXISTS receipts(receipt_id TEXT PRIMARY"
               " KEY, ts TEXT, body TEXT)")
    db.execute("CREATE TABLE IF NOT EXISTS agents(agent_id TEXT PRIMARY KEY,"
               " pubkey TEXT, mandate TEXT, revoked INTEGER DEFAULT 0)")
    db.commit()
    print(f"db ready: {DB_PATH}")


def cmd_provision(agent_id, max_cents=10000,
                  actions=("authorize_payment", "inspect")):
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    mandate = {
        "profile": "principal_mandate/v1",
        "mandate_id": f"mandate-{uuid.uuid4().hex[:8]}",
        "principal_id": "owner:gateway-owner",
        "agent_id": agent_id,
        "purpose": "gateway-pilot",
        "allowed_action_types": sorted(actions),
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
    print(json.dumps({
        "agent_id": agent_id,
        "mandate_id": mandate["mandate_id"],
        "agent_private_key": b64u_encode(priv.private_bytes_raw()),
        "warning": "private key shown once; store it with the agent, "
                   "never in the gateway",
    }, indent=2))


def cmd_revoke(agent_id):
    db = sqlite3.connect(str(DB_PATH))
    cur = db.execute("UPDATE agents SET revoked=1 WHERE agent_id=?",
                     (agent_id,))
    db.commit()
    print("revoked" if cur.rowcount else "unknown agent", agent_id)


def cmd_mode(mode):
    assert mode in ("observe", "enforce")
    pol = json.loads((CONFIG_DIR / "policy.json").read_text())
    pol["mode"] = mode
    (CONFIG_DIR / "policy.json").write_text(json.dumps(pol, indent=2))
    print(f"mode set to {mode}; restart the authz service (or SIGHUP) "
          f"to apply")


def cmd_verify():
    key_b64 = (CONFIG_DIR / "receiver.key").read_text().strip()
    pub = Ed25519PrivateKey.from_private_bytes(
        b64u_decode(key_b64)).public_key()
    db = sqlite3.connect(str(DB_PATH))
    rows = db.execute("SELECT body FROM receipts ORDER BY ts").fetchall()
    ok, bad = 0, 0
    for (body,) in rows:
        r = json.loads(body)
        sig = b64u_decode(r.pop("receiver_sig"))
        try:
            pub.verify(sig, canonical({k: r[k] for k in sorted(r)}))
            ok += 1
        except Exception:
            bad += 1
            print("BAD SIGNATURE:", r.get("receipt_id"))
    print(f"receipts: {ok} valid, {bad} invalid (of {len(rows)})")


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: init|provision-agent|revoke-agent|set-mode|"
                 "verify-receipts")
    cmd = sys.argv[1]
    if cmd == "init":
        cmd_init()
    elif cmd == "provision-agent":
        agent_id = sys.argv[2]
        kw = {}
        args = sys.argv[3:]
        i = 0
        while i < len(args):
            a = args[i]
            if a.startswith("--max-cents="):
                kw["max_cents"] = int(a.split("=", 1)[1])
            elif a == "--max-cents" and i + 1 < len(args):
                kw["max_cents"] = int(args[i + 1])
                i += 1
            i += 1
        cmd_provision(agent_id, **kw)
    elif cmd == "revoke-agent":
        cmd_revoke(sys.argv[2])
    elif cmd == "set-mode":
        cmd_mode(sys.argv[2])
    elif cmd == "verify-receipts":
        cmd_verify()
    else:
        sys.exit(f"unknown command {cmd}")


if __name__ == "__main__":
    main()
