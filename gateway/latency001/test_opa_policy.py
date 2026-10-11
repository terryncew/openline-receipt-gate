#!/usr/bin/env python3
"""Real-OPA parity and fail-closed checks for the benchmark-only construction.

Run with a real OPA server loading policy-stateful.rego, for example:
  python3 gateway/latency001/test_opa_policy.py --url http://127.0.0.1:8189/v1/data/gateway_mandate/decision
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import random
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def policy_cases():
    now = datetime(2026, 10, 11, 0, 0, tzinfo=timezone.utc)
    mandate = {
        "profile": "principal_mandate/v1", "mandate_id": "m-test",
        "principal_id": "p-test", "agent_id": "a-test", "purpose": "testing",
        "allowed_action_types": ["inspect", "authorize_payment", "accept_settlement"],
        "allowed_targets": ["ledger"], "allowed_disclosure_classes": ["public"],
        "forbidden_disclosure_classes": ["secret"], "max_settlement_cents": 500,
        "max_payment_cents": 100, "delegation_allowed": False,
        "expires_at": (now + timedelta(days=1)).isoformat(), "version": "1",
    }
    effect = {
        "profile": "principal_effect/v1", "effect_id": "fx-test",
        "mandate_id": "m-test", "principal_id": "p-test", "agent_id": "a-test",
        "purpose": "testing", "action_type": "authorize_payment", "target": "ledger",
        "disclosures": [], "value_cents": 100, "delegatee": None,
        "producer_model": "unknown",
    }
    yield "allowed-payment-limit", mandate, effect, now
    for field in ("mandate_id", "principal_id", "agent_id", "purpose", "target"):
        changed = dict(effect, **{field: "mismatch"})
        yield field + "-mismatch", mandate, changed, now
    for label, changes in (
        ("payment-over-limit", {"value_cents": 101}),
        ("settlement-limit", {"action_type": "accept_settlement", "value_cents": 500}),
        ("settlement-over-limit", {"action_type": "accept_settlement", "value_cents": 501}),
        ("forbidden-disclosure", {"disclosures": ["secret"]}),
        ("outside-disclosure", {"disclosures": ["private"]}),
        ("allowed-disclosure", {"disclosures": ["public"]}),
        ("unexpected-delegatee", {"delegatee": "someone"}),
        ("delegate-without-permission", {"action_type": "delegate", "delegatee": "someone"}),
        ("delegate-missing", {"action_type": "delegate"}),
    ):
        yield label, mandate, dict(effect, **changes), now
    yield "expires-exactly-now", dict(mandate, expires_at=now.isoformat()), effect, now
    yield "expires-one-microsecond-later", dict(mandate, expires_at=(now + timedelta(microseconds=1)).isoformat()), effect, now
    yield "empty-target-allowlist", dict(mandate, allowed_targets=[]), dict(effect, target="anything"), now
    yield "delegation-allowed", dict(mandate, allowed_action_types=["delegate"], delegation_allowed=True), dict(effect, action_type="delegate", delegatee="someone"), now
    rng = random.Random(102001)
    for index in range(300):
        altered = copy.deepcopy(mandate)
        proposed = copy.deepcopy(effect)
        altered["allowed_action_types"] = rng.sample(
            ["inspect", "draft", "send", "accept_settlement", "authorize_payment", "delegate"], rng.randrange(7))
        altered["allowed_targets"] = rng.choice([[], ["ledger"], ["other"]])
        altered["delegation_allowed"] = bool(rng.randrange(2))
        altered["max_payment_cents"] = rng.randrange(200)
        altered["max_settlement_cents"] = rng.randrange(200)
        altered["expires_at"] = (now + timedelta(seconds=rng.choice([-1, 0, 1]))).isoformat()
        proposed["action_type"] = rng.choice(["inspect", "draft", "send", "accept_settlement", "authorize_payment", "delegate"])
        proposed["value_cents"] = rng.randrange(300)
        proposed["target"] = rng.choice(["ledger", "other"])
        proposed["delegatee"] = rng.choice([None, "someone"])
        proposed["disclosures"] = rng.sample(["public", "private", "secret"], rng.randrange(4))
        if rng.randrange(2):
            proposed[rng.choice(["mandate_id", "principal_id", "agent_id", "purpose"])] = "mismatch"
        yield f"seeded-{index}", altered, proposed, now
    for field, value in (("value_cents", True), ("value_cents", -1),
                         ("disclosures", ["public", "public"]),
                         ("action_type", ""), ("delegatee", "")):
        yield "invalid-effect-" + field + repr(value), mandate, dict(effect, **{field: value}), now
    yield "invalid-mandate-shape", dict(mandate, extra="bad"), effect, now
    yield "invalid-mandate-date", dict(mandate, expires_at="bad"), effect, now


def run_parity(comparator):
    from olp_gate.mandate import assess_effect
    count = 0
    for label, mandate, effect, now in policy_cases():
        try:
            expected = assess_effect(mandate, effect, now=now)
        except (TypeError, ValueError) as expected_error:
            try:
                comparator.assess_effect(mandate, effect, now=now)
            except type(expected_error):
                count += 1
                continue
            raise AssertionError(f"{label}: invalid shape accepted")
        observed = comparator.assess_effect(mandate, effect, now=now)
        assert observed == expected, (label, expected, observed)
        count += 1
    return count


def run_fail_closed(comparator, config):
    # Exercise the actual Authorizer boundary. OPA service errors and invalid
    # responses must produce a signed refusal receipt and consume no nonce.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    import authz_server
    from agent_client import AgentClient
    import ext_authz_pb2 as pb2

    class Failure(BaseHTTPRequestHandler):
        mode = "http-error"
        def log_message(self, *args):
            pass
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if self.mode == "timeout":
                time.sleep(0.15)
            status = 503 if self.mode == "http-error" else 200
            value = {"result": {"allowed": True, "reason_codes": ["denied"]}}
            if self.mode == "undefined":
                value = {}
            elif self.mode == "invalid-json":
                value = None
            payload = b"invalid JSON" if value is None else json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Failure)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    authz_server.CONFIG_DIR = config
    authz_server.DB_PATH = config / "test.db"
    private = Ed25519PrivateKey.generate()
    (config / "receiver.key").write_text(authz_server.b64u_encode(private.private_bytes_raw()))
    (config / "policy.json").write_text('{"mode":"enforce"}')
    authorizer = authz_server.Authorizer()
    _, mandate, _, _ = next(policy_cases())
    mandate = dict(mandate, expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat())
    agent_key = Ed25519PrivateKey.generate()
    authorizer.state.db.execute("INSERT INTO agents VALUES(?,?,?,0)", (
        "a-test", authz_server.b64u_encode(agent_key.public_key().public_bytes_raw()), json.dumps(mandate)))
    authorizer.state.db.commit()
    agent = AgentClient("a-test", authz_server.b64u_encode(agent_key.private_bytes_raw()))
    old_client = comparator.CLIENT
    comparator.install_policy_engine()
    outcomes = {}
    for mode in ("http-error", "undefined", "invalid-json", "invalid-result", "timeout", "connection-error"):
        Failure.mode = mode
        port = server.server_port if mode != "connection-error" else 1
        comparator.CLIENT = comparator.OpaClient(f"http://127.0.0.1:{port}/decision", timeout=0.05)
        headers = agent.headers_for("authorize_payment", value_cents=100)
        request = pb2.CheckRequest()
        request.attributes.request.http.method = "POST"
        request.attributes.request.http.path = "/api/transfer"
        request.attributes.request.http.headers.update(headers)
        response = authorizer.Check(request, None)
        assert response.status.code == 7, (mode, response)
        receipt = json.loads(authorizer.state.db.execute(
            "SELECT body FROM receipts ORDER BY rowid DESC LIMIT 1").fetchone()[0])
        assert receipt["decision"] == "deny", (mode, receipt)
        assert "mandate_eval_error" in receipt["reasons"], (mode, receipt)
        signature = authz_server.b64u_decode(receipt.pop("receiver_sig"))
        private.public_key().verify(signature, authz_server.canonical(receipt))
        action = json.loads(authz_server.b64u_decode(headers["x-ol-action"]))
        assert not authorizer.state.nonce_seen(action["nonce"]), mode
        outcomes[mode] = "signed refusal; nonce unconsumed"
    comparator.CLIENT = old_client
    server.shutdown()
    return outcomes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8189/v1/data/gateway_mandate/decision")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    os.environ["LATENCY_OPA_URL"] = args.url
    from gateway.latency001 import opa_stateful_authz as comparator
    parity_count = run_parity(comparator)
    with tempfile.TemporaryDirectory(prefix="gateway-opa-policy-") as path:
        failures = run_fail_closed(comparator, Path(path))
    result = {"parity_cases_passed": parity_count, "fail_closed": failures}
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
