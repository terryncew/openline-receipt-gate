"""GATEWAY-SUBSCRIPTION-001: the merchant actor.

A fictional merchant ("merchant-acme") holding a provisioned private key.
It can attempt legitimate charges and adversarial ones. It cannot alter
owner permissions, change trusted keys, or bypass the receiver boundary —
the demo asserts each of those attempts fails.

Fictional funds, fictional parties. No real payment processing.
"""

from __future__ import annotations

import sys
import urllib.request
import urllib.error
from pathlib import Path

HERE = Path(__file__).resolve().parent
GWROOT = HERE.parent
sys.path.insert(0, str(GWROOT))

from agent_client import AgentClient  # noqa: E402

ENVOY = "http://127.0.0.1:8080"
API_DIRECT = "http://127.0.0.1:9000"


def _post(url, headers, body=b"{}", path_suffix=""):
    req = urllib.request.Request(url + path_suffix, data=body, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


class MerchantActor:
    """The merchant's billing software, holding only its own key."""

    def __init__(self, agent_id: str, private_key_b64: str):
        self.agent_id = agent_id
        self.client = AgentClient(agent_id, private_key_b64)
        self.last_headers = None

    def charge(self, cents: int, body: bytes = b"{}"):
        """A normal billing attempt through the payment receiver."""
        headers = self.client.headers_for("authorize_payment", value_cents=cents)
        self.last_headers = headers
        return _post(ENVOY, headers, body, "/api/transfer")

    def replay_last_charge(self):
        """Resend the exact signed headers of the previous charge."""
        assert self.last_headers is not None, "no charge to replay yet"
        return _post(ENVOY, dict(self.last_headers), b"{}", "/api/transfer")

    def charge_with_tampered_body(self, signed_cents: int, claimed_cents: int,
                                  claimed_to: str = "attacker"):
        """Sign for one amount, but claim another in the request body.

        The receiver must execute the AUTHORIZED params, never the body.
        """
        import json
        headers = self.client.headers_for("authorize_payment",
                                          value_cents=signed_cents)
        body = json.dumps({"cents": claimed_cents, "to": claimed_to}).encode()
        return _post(ENVOY, headers, body, "/api/transfer")

    def present_token_directly(self, token_b64: str):
        """Present a decision token straight to the payment API,
        bypassing Envoy (models an in-flight token, not an external
        attacker — production non-bypassability rests on network
        isolation, documented in the demo README)."""
        return _post(API_DIRECT, {"x-ol-decision": token_b64}, b"{}",
                     "/transfer")

    def present_forged_token(self):
        """A token the receiver never signed."""
        import base64, json
        fake = base64.urlsafe_b64encode(json.dumps({
            "decision_id": "forged-1", "agent_id": self.agent_id,
            "action_type": "authorize_payment", "target": "ledger",
            "value_cents": 2000, "nonce": "forged",
            "issued_at": 9999999999, "ttl": 60,
            "sig": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        }).encode()).rstrip(b"=").decode()
        return _post(API_DIRECT, {"x-ol-decision": fake}, b"{}",
                     "/transfer")

    def post_unsigned_directly(self):
        """No token at all, straight to the API."""
        return _post(API_DIRECT, {}, b"{}", "/transfer")
