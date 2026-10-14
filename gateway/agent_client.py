"""Test agent client: builds signed OpenLine action headers.

Used by the scenario runner and benchmarks. In a real deployment the
agent is any software holding its provisioned private key.
"""

from __future__ import annotations

import base64
import json
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey)


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class AgentClient:
    def __init__(self, agent_id: str, private_key_b64: str):
        self.agent_id = agent_id
        self.key = Ed25519PrivateKey.from_private_bytes(
            base64.urlsafe_b64decode(private_key_b64 + "=="))

    def headers_for(self, action_type: str, target: str = "ledger",
                    value_cents: int = 0, nonce: str | None = None,
                    ts: float | None = None) -> dict:
        action = {
            "agent_id": self.agent_id,
            "action_type": action_type,
            "target": target,
            "value_cents": value_cents,
            "nonce": nonce or uuid.uuid4().hex[:16],
            "ts": ts if ts is not None else time.time(),
        }
        sig = self.key.sign(canonical(action))
        return {
            "x-ol-agent": self.agent_id,
            "x-ol-action": b64u_encode(canonical(action)),
            "x-ol-sig": b64u_encode(sig),
        }
