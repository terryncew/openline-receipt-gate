"""Tests for benchmark integrity, especially fast failures and body timing."""
from __future__ import annotations

import http.server
import json
from pathlib import Path
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import benchmark


class BenchmarkIntegrityTests(unittest.TestCase):
    def test_floor_renews_tokens_without_extending_their_ttl(self):
        class Compose:
            batches = 0

            def mint_floor_decisions(self, agent_id, count, amount):
                self.batches += 1
                return {"issued_at": 100 if self.batches == 1 else 151,
                        "ttl": 60,
                        "tokens": [f"batch-{self.batches}-{i}" for i in range(count)]}

        compose = Compose()
        pool = benchmark.FloorDecisions(compose, "test-agent", 2, 1)
        with patch.object(benchmark.time, "time", return_value=151):
            token = pool.take()
        self.assertEqual(token, "batch-2-0")
        self.assertEqual(pool.ttl, 60)
        self.assertEqual(pool.remaining, 1)
        self.assertEqual(pool.mint_batches, 2)

    def test_http_200_failed_effect_and_wrong_amount_are_rejected(self):
        args = ("transfer", 1, True, "http", 100)
        failed, _ = benchmark.validate_response(200, b'{"ok": false}', *args)
        wrong, _ = benchmark.validate_response(
            200, b'{"ok":true,"effect_id":"fx-a","authorized_params":{"value_cents":2}}', *args)
        denied, _ = benchmark.validate_response(403, b'{}', *args)
        self.assertTrue(failed)
        self.assertTrue(wrong)
        self.assertTrue(denied)

    def test_latency_includes_complete_response_body(self):
        class SlowBody(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.flush()
                time.sleep(.08)
                self.wfile.write(b"{}")

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SlowBody)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for client in ("close", "persistent"):
                transport = benchmark.HttpTransport(
                    f"http://127.0.0.1:{server.server_port}", client, 2)
                try:
                    status, body, complete_ms, headers_ms, _ = transport.request("GET", "/", {}, None)
                    self.assertEqual(status, 200)
                    self.assertEqual(body, b"{}")
                    self.assertGreater(complete_ms - headers_ms, 50)
                finally:
                    transport.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_failed_requests_are_all_saved_and_fail_the_case(self):
        class Compose:
            def ledger_snapshot(self):
                return {"balances": {"treasury": 100}, "effects": 0, "receipts": None}

        class Transport:
            counter = 0
            lock = threading.Lock()

            def __init__(self, *args):
                pass

            def close(self):
                pass

            def request(self, *args):
                with self.lock:
                    type(self).counter += 1
                    status = 503 if self.counter % 3 == 0 else 200
                return status, b'{"acct":"treasury","cents":100}', 1., .8, None

        args = SimpleNamespace(mode="opa-a", transport="http", profile_files=[],
                               url="http://127.0.0.1:8080", timeout=1, warmup=2,
                               samples=20, amount=1)
        with tempfile.TemporaryDirectory() as directory, patch.object(benchmark, "HttpTransport", Transport):
            output = Path(directory)
            summary = benchmark.run_case(args, Compose(), None, "inspect", "close", 2, output)
            raw = json.loads(next(output.glob("*.raw.json")).read_text())
        measured = [sample for sample in raw if sample["phase"] == "measured"]
        self.assertEqual(len(measured), 20)
        self.assertFalse(summary["passed"])
        self.assertGreater(summary["failures"], 0)
        self.assertEqual(sum(summary["status_counts"].values()), 20)
        self.assertEqual(summary["all_attempted_latency"]["n"], 20)
        self.assertEqual(summary["successful_latency"]["n"], 20 - summary["failures"])


if __name__ == "__main__":
    unittest.main()
