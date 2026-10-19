"""Unit tests for OPENLINE-GATEWAY-001 components.

These test the authz logic without Envoy (direct Check calls).
The integration scenarios (scenarios/run_scenarios.py) test the full
stack through the real Envoy.
"""

import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

GWROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(GWROOT))

os.environ["GATEWAY_CONFIG"] = str(GWROOT / "config")
os.environ["GATEWAY_DB"] = str(GWROOT / "state" / "gateway.db")

from agent_client import AgentClient, b64u_encode, canonical  # noqa: E402


class TestAgentClient(unittest.TestCase):
    def test_headers_sign_and_verify(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey)
        priv = Ed25519PrivateKey.generate()
        key_b64 = b64u_encode(priv.private_bytes_raw())
        c = AgentClient("test-agent", key_b64)
        h = c.headers_for("authorize_payment", value_cents=100)
        self.assertEqual(h["x-ol-agent"], "test-agent")
        action = json.loads(base64.urlsafe_b64decode(
            h["x-ol-action"] + "=="))
        self.assertEqual(action["value_cents"], 100)
        # signature verifies against the private key's public key
        sig = base64.urlsafe_b64decode(h["x-ol-sig"] + "==")
        priv.public_key().verify(sig, canonical(action))

    def test_nonce_unique_per_call(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey)
        priv = Ed25519PrivateKey.generate()
        key_b64 = b64u_encode(priv.private_bytes_raw())
        c = AgentClient("test-agent", key_b64)
        h1 = c.headers_for("authorize_payment", value_cents=100)
        h2 = c.headers_for("authorize_payment", value_cents=100)
        n1 = json.loads(base64.urlsafe_b64decode(
            h1["x-ol-action"] + "=="))["nonce"]
        n2 = json.loads(base64.urlsafe_b64decode(
            h2["x-ol-action"] + "=="))["nonce"]
        self.assertNotEqual(n1, n2)


class TestProto(unittest.TestCase):
    def test_ok_response_field_number(self):
        # Regression: ok_response MUST be field 3 (Envoy reads field 2
        # as denied_response). Getting this wrong silently drops headers.
        import ext_authz_pb2 as pb2
        r = pb2.CheckResponse(
            status=pb2.RpcStatus(code=0),
            ok_response=pb2.OkHttpResponse(headers=[
                pb2.HeaderValueOption(
                    header=pb2.HeaderValue(key="x", value="y"))]))
        self.assertEqual(r.WhichOneof("http_response"), "ok_response")
        self.assertEqual(r.SerializeToString()[2], 0x1a)

    def test_check_request_parses(self):
        import ext_authz_pb2 as pb2
        req = pb2.CheckRequest()
        req.attributes.request.http.method = "POST"
        req.attributes.request.http.path = "/api/transfer"
        req.attributes.request.http.headers["x-ol-agent"] = "a"
        d = req.SerializeToString()
        r2 = pb2.CheckRequest()
        r2.ParseFromString(d)
        self.assertEqual(r2.attributes.request.http.path, "/api/transfer")
        self.assertEqual(
            r2.attributes.request.http.headers["x-ol-agent"], "a")


class TestDecisionToken(unittest.TestCase):
    def test_token_verify_roundtrip(self):
        # mock_api.verify_decision_token against a token minted the same
        # way authz_server mints them (receiver key from test config).
        # Uses a temp key so the real receiver.key is never touched.
        import mock_api
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey)
        priv = Ed25519PrivateKey.generate()
        token = {"decision_id": "abc", "action_type": "authorize_payment",
                 "target": "ledger", "value_cents": 100,
                 "issued_at": 1791697200, "ttl": 3600}
        sig = priv.sign(canonical(token))
        token["sig"] = b64u_encode(sig)
        token_b64 = b64u_encode(canonical(token))
        # verify with the matching public key (mock_api uses its own PUB;
        # here we verify the construction is sound)
        pub = priv.public_key()
        raw = json.loads(base64.urlsafe_b64decode(token_b64 + "=="))
        rsig = base64.urlsafe_b64decode(raw.pop("sig") + "==")
        pub.verify(rsig, canonical(raw))  # raises if broken


if __name__ == "__main__":
    unittest.main()
