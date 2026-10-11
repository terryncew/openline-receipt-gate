"""Security and durability invariants for GATEWAY-LATENCY-001.

Uses isolated real authz/API subprocesses plus one deterministic in-process
nonce race. It does not run Envoy: the complete Compose verifier remains a
separate required check. No benchmark thresholds are security assertions.
"""

from __future__ import annotations

import base64
import copy
import importlib.util
import json
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

GWROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(GWROOT))
sys.path.insert(0, str(GWROOT / "tests"))

import grpc  # noqa: E402
import ext_authz_pb2 as pb2  # noqa: E402
import ext_authz_pb2_grpc as pb2_grpc  # noqa: E402
from test_standing_races import RaceStack, b64u_encode, http_json  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey)


def request(headers: dict) -> pb2.CheckRequest:
    result = pb2.CheckRequest()
    result.attributes.request.http.method = "POST"
    result.attributes.request.http.path = "/api/transfer"
    result.attributes.request.http.headers.update(headers)
    return result


def decision_token(response: pb2.CheckResponse) -> str:
    return {h.header.key: h.header.value for h in
            response.ok_response.headers}["x-ol-decision"]


class LatencySecurityRegressions(unittest.TestCase):
    def setUp(self):
        self.stack = RaceStack(standing_check=True)
        self.addCleanup(self.stack.close)

    def rows(self, query: str, parameters=()):
        with sqlite3.connect(str(self.stack.db)) as connection:
            return connection.execute(query, parameters).fetchall()

    def receipts(self):
        return [json.loads(row[0]) for row in
                self.rows("SELECT body FROM receipts ORDER BY receipt_id")]

    def check(self, headers):
        return self.stack.stub.Check(request(headers), timeout=20)

    def public_key(self) -> str:
        encoded = (self.stack.cfg / "receiver.key").read_text().strip()
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        return b64u_encode(Ed25519PrivateKey.from_private_bytes(raw)
                           .public_key().public_bytes_raw())

    def independent_verify(self, receipts):
        key_path = self.stack.tmp / "receiver.pubkey"
        export_path = self.stack.tmp / "receipts.jsonl"
        key_path.write_text(self.public_key())
        export_path.write_text("".join(json.dumps(r) + "\n"
                                       for r in receipts))
        result = subprocess.run(
            [sys.executable, str(GWROOT / "ci" / "verify_receipt_export.py"),
             "--public-key", str(key_path), "--receipts", str(export_path)],
            capture_output=True, text=True, timeout=15)
        return result.returncode, json.loads(result.stdout)

    def test_simultaneous_nonce_claim_mints_exactly_one_token(self):
        """Force contenders past verification before the nonce write.

        The former SELECT followed by INSERT OR IGNORE lets every request
        allow. An atomic late nonce claim must allow exactly one contender.
        """
        import authz_server
        headers = self.stack.agent.headers_for("authorize_payment",
                                               value_cents=10)
        workers = 8
        ready = threading.Barrier(workers)
        original_compile = authz_server.compile_verified_commit_settings

        def synchronized_compile(*args, **kwargs):
            result = original_compile(*args, **kwargs)
            ready.wait(timeout=15)
            return result

        with mock.patch.object(authz_server, "DB_PATH", self.stack.db), \
                mock.patch.object(authz_server, "CONFIG_DIR", self.stack.cfg), \
                mock.patch.object(signal, "signal"), \
                mock.patch.object(authz_server,
                                  "compile_verified_commit_settings",
                                  synchronized_compile):
            authorizer = authz_server.Authorizer()
            # Serialize complete writes only in this controlled test so the
            # old shared-connection API misuse cannot obscure the nonce
            # race. The compiler barrier still forces every early precheck
            # to see an absent nonce; the late insert must choose one winner.
            # The separate unique-load test exercises unmodified concurrency.
            write_lock = threading.Lock()
            original_mark = authorizer.state.mark_nonce
            original_add = authorizer.state.add_receipt

            def serialized_mark(*args, **kwargs):
                with write_lock:
                    return original_mark(*args, **kwargs)

            def serialized_add(*args, **kwargs):
                with write_lock:
                    return original_add(*args, **kwargs)

            with mock.patch.object(authorizer.state, "mark_nonce",
                                   serialized_mark), \
                    mock.patch.object(authorizer.state, "add_receipt",
                                      serialized_add):
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = [executor.submit(authorizer.Check,
                                               request(headers), None)
                               for _ in range(workers)]
                    responses = [future.result(timeout=30)
                                 for future in futures]
        allowed = [r for r in responses if r.status.code == 0]
        refused = [r for r in responses if r.status.code != 0]
        self.assertEqual(len(allowed), 1,
                         "a signed nonce authorized more than one decision")
        self.assertEqual(len(refused), workers - 1)
        self.assertTrue(all("replay_detected" in r.status.message
                            for r in refused))
        receipts = self.receipts()
        self.assertEqual(len(receipts), workers)
        self.assertEqual(sum(r["decision"] == "allow" for r in receipts), 1)
        self.assertEqual(len(self.rows("SELECT nonce FROM nonces")), 1)
        code, summary = self.independent_verify(receipts)
        self.assertEqual(code, 0, summary)
        self.assertEqual(summary["valid"], workers)
        status, body, _ = self.stack.execute(decision_token(allowed[0]))
        self.assertEqual(status, 200, body)
        self.assertEqual(self.stack.effect_count(), 1)

    def test_concurrent_unique_requests_preserve_every_receipt_and_effect(self):
        count = 64
        headers = [self.stack.agent.headers_for("authorize_payment",
                                                value_cents=1)
                   for _ in range(count)]
        with ThreadPoolExecutor(max_workers=16) as executor:
            responses = list(executor.map(self.check, headers))
        self.assertTrue(all(r.status.code == 0 for r in responses),
                        [r.status.message for r in responses])
        receipts = self.receipts()
        self.assertEqual(len(receipts), count)
        self.assertEqual(len(self.rows("SELECT nonce FROM nonces")), count)
        self.assertTrue(all(r["decision"] == "allow" for r in receipts))
        code, summary = self.independent_verify(receipts)
        self.assertEqual(code, 0, summary)
        self.assertEqual(summary["valid"], count)
        treasury, vendor = self.stack.balance(), self.stack.balance("vendor")
        for response in responses:
            status, body, _ = self.stack.execute(decision_token(response))
            self.assertEqual(status, 200, body)
        self.assertEqual(self.stack.effect_count(), count)
        self.assertEqual(self.stack.balance(), treasury - count)
        self.assertEqual(self.stack.balance("vendor"), vendor + count)

    def test_permission_updates_and_revocation_are_read_fresh(self):
        headers = self.stack.agent.headers_for("authorize_payment",
                                               value_cents=100)
        self.assertEqual(self.check(headers).status.code, 0)
        mandate = json.loads(self.rows(
            "SELECT mandate FROM agents WHERE agent_id=?",
            (self.stack.agent_id,))[0][0])
        updates = [({"max_payment_cents": 1}, "payment_limit_exceeded"),
                   ({"allowed_targets": ["another-ledger"]},
                    "target_not_allowed"),
                   ({"expires_at": "2000-01-01T00:00:00Z"},
                    "mandate_expired")]
        for update, expected in updates:
            changed = dict(mandate, **update)
            with sqlite3.connect(str(self.stack.db)) as connection:
                connection.execute("UPDATE agents SET mandate=? WHERE "
                                   "agent_id=?", (json.dumps(changed),
                                                 self.stack.agent_id))
            response = self.check(self.stack.agent.headers_for(
                "authorize_payment", value_cents=100))
            self.assertEqual(response.status.code, 7)
            self.assertIn(expected, response.status.message)
        self.stack.revoke()
        for _ in range(8):
            response = self.check(self.stack.agent.headers_for(
                "authorize_payment", value_cents=1))
            self.assertEqual(response.status.code, 7)
            self.assertIn("agent_revoked", response.status.message)
        self.assertEqual(self.stack.effect_count(), 0)

    def test_tampering_cannot_change_authorized_execution(self):
        headers = self.stack.agent.headers_for("authorize_payment",
                                               value_cents=10)
        action = json.loads(base64.urlsafe_b64decode(headers["x-ol-action"]
                                                    + "=="))
        action["value_cents"] = 1000
        altered = dict(headers)
        altered["x-ol-action"] = b64u_encode(json.dumps(action).encode())
        response = self.check(altered)
        self.assertEqual(response.status.code, 7)
        self.assertIn("signature_invalid", response.status.message)
        response = self.check(headers)
        self.assertEqual(response.status.code, 0)
        token = decision_token(response)
        decoded = json.loads(base64.urlsafe_b64decode(token + "=="))
        decoded["value_cents"] = 1000
        status, body, _ = self.stack.execute(
            b64u_encode(json.dumps(decoded).encode()))
        self.assertEqual(status, 403, body)
        treasury = self.stack.balance()
        status, body = http_json(
            "POST", self.stack.api_base + "/transfer",
            headers={"x-ol-decision": token},
            body={"to": "attacker", "cents": 900000})
        self.assertEqual(status, 200, body)
        self.assertEqual(self.stack.balance(), treasury - 10)
        self.assertEqual(self.stack.balance("vendor"), 10)
        self.assertEqual(self.stack.balance("attacker"), 0)
        self.assertEqual(self.stack.effect_count(), 1)

    def test_signed_action_cannot_substitute_another_standing_identity(self):
        """A valid agent signature cannot relabel the downstream identity.

        Otherwise a token minted for a second, unrevoked agent would evade
        the original agent's execution-time revocation check.
        """
        self.stack._admin("provision-agent", "other-unrevoked-agent")
        headers = self.stack.agent.headers_for("authorize_payment",
                                               value_cents=10)
        action = json.loads(base64.urlsafe_b64decode(headers["x-ol-action"]
                                                    + "=="))
        action["agent_id"] = "other-unrevoked-agent"
        encoded = json.dumps(action, sort_keys=True,
                             separators=(",", ":")).encode()
        headers["x-ol-action"] = b64u_encode(encoded)
        headers["x-ol-sig"] = b64u_encode(self.stack.agent.key.sign(encoded))
        response = self.check(headers)
        self.assertEqual(response.status.code, 7)
        self.assertIn("action_agent_mismatch", response.status.message)
        self.assertEqual(len(self.rows("SELECT nonce FROM nonces")), 0)
        self.assertEqual(self.stack.effect_count(), 0)
        self.assertEqual(self.receipts()[0]["decision"], "deny")

    def test_acknowledged_state_survives_sigkill_and_full_process_restart(self):
        headers = self.stack.agent.headers_for("authorize_payment",
                                               value_cents=10)
        response = self.check(headers)
        self.assertEqual(response.status.code, 0)
        token = decision_token(response)
        treasury, vendor = self.stack.balance(), self.stack.balance("vendor")
        status, body, _ = self.stack.execute(token)
        self.assertEqual(status, 200, body)
        before = {r["receipt_id"] for r in self.receipts()}
        self.assertTrue(before)
        self.stack.api.kill()
        self.stack.authz.kill()
        self.stack.api.wait(timeout=10)
        self.stack.authz.wait(timeout=10)
        self.assertEqual(self.rows("PRAGMA integrity_check"), [("ok",)])
        self.stack.channel.close()
        authz_env = dict(self.stack.env,
                         GATEWAY_STANDING_PORT=str(self.stack.standing_port))
        api_env = dict(self.stack.env, MOCK_API_PORT=str(self.stack.api_port),
                       GATEWAY_STANDING_CHECK="1",
                       GATEWAY_STANDING_URL=(
                           f"http://127.0.0.1:{self.stack.standing_port}/standing"))
        self.stack.authz = subprocess.Popen(
            [sys.executable, str(GWROOT / "authz_server.py"),
             str(self.stack.authz_port)], env=authz_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
            start_new_session=True)
        self.stack.api = subprocess.Popen(
            [sys.executable, str(GWROOT / "mock_api.py")], env=api_env,
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
            start_new_session=True)
        self.stack._wait_ready()
        self.stack.channel = grpc.insecure_channel(
            f"[::1]:{self.stack.authz_port}",
            options=[("grpc.enable_http_proxy", 0)])
        self.stack.stub = pb2_grpc.AuthorizationStub(self.stack.channel)
        self.assertEqual(self.stack.balance(), treasury - 10)
        self.assertEqual(self.stack.balance("vendor"), vendor + 10)
        self.assertEqual(self.stack.effect_count(), 1)
        response = self.check(headers)
        self.assertEqual(response.status.code, 7)
        self.assertIn("replay_detected", response.status.message)
        status, body, _ = self.stack.execute(token)
        self.assertEqual(status, 409, body)
        self.assertIn("already used", body["error"])
        receipts = self.receipts()
        self.assertTrue(before <= {r["receipt_id"] for r in receipts})
        code, summary = self.independent_verify(receipts)
        self.assertEqual(code, 0, summary)
        fresh = self.stack.mint_token(value_cents=10)
        status, body, _ = self.stack.execute(fresh)
        self.assertEqual(status, 200, body)
        self.assertEqual(self.stack.balance(), treasury - 20)
        self.assertEqual(self.stack.balance("vendor"), vendor + 20)
        self.assertEqual(self.stack.effect_count(), 2)

    def test_authorization_ack_is_durable_before_protected_api_execution(self):
        """Kill directly after Check returns, before any downstream work.

        This forbids buffered acknowledgements that postpone durable nonce
        or receipt persistence until later requests or API execution.
        """
        headers = self.stack.agent.headers_for("authorize_payment",
                                               value_cents=10)
        response = self.check(headers)
        self.assertEqual(response.status.code, 0)
        self.stack.authz.kill()
        self.stack.authz.wait(timeout=10)
        action = json.loads(base64.urlsafe_b64decode(headers["x-ol-action"]
                                                    + "=="))
        self.assertEqual(self.rows("SELECT nonce FROM nonces"),
                         [(action["nonce"],)])
        receipts = self.receipts()
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["decision"], "allow")
        self.assertEqual(receipts[0]["detail"]["action"]["nonce"],
                         action["nonce"])
        self.assertEqual(self.stack.effect_count(), 0)
        code, summary = self.independent_verify(receipts)
        self.assertEqual(code, 0, summary)

    def test_independent_verifier_rejects_tampering_duplicates_and_empty_log(self):
        self.stack.mint_token(value_cents=1)
        receipts = self.receipts()
        code, summary = self.independent_verify(receipts)
        self.assertEqual(code, 0, summary)
        altered = copy.deepcopy(receipts)
        altered[0]["decision"] = "deny"
        for invalid in (altered, receipts + receipts, []):
            code, summary = self.independent_verify(invalid)
            self.assertEqual(code, 1, summary)
            self.assertGreater(summary["invalid"], 0)

    def test_authorization_and_ledger_connections_retain_full_durability(self):
        """Check the actual writer connections, not another SQLite default.

        Process-kill tests cover acknowledged persistence, but do not model
        power loss. FULL is required on both WAL writers to preserve the
        original fsync-per-acknowledged-commit contract.
        """
        import authz_server
        state = authz_server.GatewayState(self.stack.tmp / "config-state.db")
        self.addCleanup(state.db.close)
        api_path = self.stack.tmp / "config-ledger.db"
        with mock.patch.dict(os.environ, {"GATEWAY_CONFIG": str(self.stack.cfg),
                                          "GATEWAY_DB": str(api_path)}):
            spec = importlib.util.spec_from_file_location(
                "latency_config_mock_api", GWROOT / "mock_api.py")
            api = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(api)
        self.addCleanup(api.LEDGER.db.close)
        for connection in (state.db, api.LEDGER.db):
            self.assertEqual(connection.execute("PRAGMA journal_mode")
                             .fetchone()[0].lower(), "wal")
            self.assertEqual(connection.execute("PRAGMA synchronous")
                             .fetchone()[0], 2)


if __name__ == "__main__":
    unittest.main()
