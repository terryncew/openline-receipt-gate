#!/usr/bin/env python3
"""Race tests for the execution-time standing check (GATEWAY-SUBSCRIPTION-001, Step 2).

What is under test
------------------
The authz service mints 60 s-TTL single-use decision tokens at request
time; the mock API executes the token's authorized params. Without an
execution-time check, a token minted before revocation stays executable
until its TTL. With ``GATEWAY_STANDING_CHECK=1`` the mock API re-queries
the authz service's standing endpoint immediately before committing and
refuses to execute unless the decision is still standing (fail-closed).

How these tests run
-------------------
Each test spins up REAL ``authz_server`` and ``mock_api`` subprocesses on
localhost with an isolated config dir + sqlite DB, mints tokens through
the real gRPC ``Check`` path (signed agent action via ``AgentClient``),
revokes via the real ``gateway_admin revoke-agent`` path, and executes
via HTTP POST to the mock API.

Envoy is bypassed: the execution-time check lives entirely between the
mock API and the authz service, so Envoy's ext_authz plumbing adds
nothing to the race question being measured. This is an honest
limitation of the harness, not of the property: the standing query and
the ledger commit happen inside mock_api exactly as they would behind
Envoy. See gateway/subscription001/EVIDENCE-races.md.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import socket
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

GWROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(GWROOT))

from agent_client import AgentClient  # noqa: E402
import ext_authz_pb2 as pb2  # noqa: E402
import ext_authz_pb2_grpc as pb2_grpc  # noqa: E402
import grpc  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey)

# Measurements collected across tests; written to JSON by tearDownModule.
MEASUREMENTS: dict = {"standing_endpoint_rtt_ms": [],
                      "standing_to_commit_ms": [],
                      "post_rtt_ms_check_on": [],
                      "post_rtt_ms_check_off": [],
                      "race_rounds": []}

MEASUREMENTS_PATH = (GWROOT / "subscription001" /
                     "measurements-2026-10-11.json")


def b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def http_json(method, url, headers=None, body=None, timeout=15):
    data = json.dumps(body).encode() if body is not None else b"{}"
    req = urllib.request.Request(url, data=data if method == "POST" else None,
                                 method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode())
        except Exception:
            payload = {"error": "unparseable"}
        return e.code, payload


class RaceStack:
    """A live authz_server + mock_api pair with isolated state."""

    def __init__(self, standing_check=True, standing_url_override=None,
                 pre_commit_delay_ms=0):
        self.tmp = Path(tempfile.mkdtemp(prefix="standing-race-"))
        self.cfg = self.tmp / "config"
        self.cfg.mkdir()
        self.db = self.tmp / "state" / "gateway.db"
        self.db.parent.mkdir(parents=True)
        # Fresh receiver key per run: full isolation, real key never touched.
        key = Ed25519PrivateKey.generate()
        (self.cfg / "receiver.key").write_text(
            b64u_encode(key.private_bytes_raw()))
        os.chmod(self.cfg / "receiver.key", 0o600)
        (self.cfg / "policy.json").write_text(
            json.dumps({"mode": "enforce"}))
        self.env = dict(os.environ)
        self.env["GATEWAY_CONFIG"] = str(self.cfg)
        self.env["GATEWAY_DB"] = str(self.db)
        self.env["PYTHONPATH"] = str(GWROOT) + ":" + self.env.get(
            "PYTHONPATH", "")
        self.agent_id = "race-agent"
        self._admin("init")
        out = self._admin("provision-agent", self.agent_id,
                          "--max-cents=100000")
        self.agent = AgentClient(self.agent_id,
                                 json.loads(out)["agent_private_key"])
        self.authz_port = free_port()
        self.standing_port = free_port()
        self.api_port = free_port()
        aenv = dict(self.env)
        aenv["GATEWAY_STANDING_PORT"] = str(self.standing_port)
        self.authz = subprocess.Popen(
            [sys.executable, str(GWROOT / "authz_server.py"),
             str(self.authz_port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, env=aenv,
            start_new_session=True)
        menv = dict(self.env)
        menv["MOCK_API_PORT"] = str(self.api_port)
        if standing_check:
            menv["GATEWAY_STANDING_CHECK"] = "1"
            menv["GATEWAY_STANDING_URL"] = (
                standing_url_override or
                f"http://127.0.0.1:{self.standing_port}/standing")
        if pre_commit_delay_ms:
            menv["GATEWAY_TEST_PRE_COMMIT_DELAY_MS"] = str(
                pre_commit_delay_ms)
        self.api = subprocess.Popen(
            [sys.executable, str(GWROOT / "mock_api.py")],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, env=menv,
            start_new_session=True)
        self.api_base = f"http://127.0.0.1:{self.api_port}"
        self._wait_ready()
        # VM QUIRK (measured 2026-10-11, independently confirmed by the
        # coordinator): the Python grpc client cannot complete an HTTP/2
        # handshake over IPv4 loopback on this VM ("got frame type 101";
        # reproduced with a bare grpc server, no authz_server involved;
        # raw TCP to 127.0.0.1 and Envoy's ext_authz over 127.0.0.1 are
        # fine). IPv6 loopback works consistently, so the mint path uses
        # [::1] (the server binds [::] dual-stack). HTTP/1.1 via urllib
        # to 127.0.0.1 is unaffected. See EVIDENCE-races.md.
        self.channel = grpc.insecure_channel(
            f"[::1]:{self.authz_port}",
            options=[("grpc.enable_http_proxy", 0)])
        self.stub = pb2_grpc.AuthorizationStub(self.channel)

    def _admin(self, *args):
        r = subprocess.run(
            [sys.executable, str(GWROOT / "gateway_admin.py"), *args],
            capture_output=True, text=True, env=self.env, timeout=30)
        if r.returncode != 0:
            raise RuntimeError(f"gateway_admin {' '.join(args)} failed: "
                               f"{r.stderr[:300]}")
        return r.stdout

    def _wait_ready(self):
        deadline = time.time() + 25
        while time.time() < deadline:
            try:
                s, _ = http_json("GET", self.api_base + "/health", timeout=2)
                if s != 200:
                    raise RuntimeError("api not ready")
                s, b = http_json(
                    "GET",
                    f"http://127.0.0.1:{self.standing_port}/standing"
                    f"?decision_id=x&agent_id={self.agent_id}&issued_at=0",
                    timeout=2)
                if s == 200 and isinstance(b, dict) and "standing" in b:
                    return
            except (urllib.error.URLError, ConnectionError, OSError):
                pass
            if self.authz.poll() is not None or self.api.poll() is not None:
                raise RuntimeError("a subprocess exited during startup")
            time.sleep(0.2)
        raise RuntimeError("stack did not become ready in 25s")

    def mint_token(self, value_cents=100) -> str:
        """Mint a decision token through the real gRPC Check path."""
        headers = self.agent.headers_for("authorize_payment",
                                         value_cents=value_cents)
        req = pb2.CheckRequest()
        http = req.attributes.request.http
        http.method = "POST"
        http.path = "/api/transfer"
        for k, v in headers.items():
            http.headers[k] = v
        resp = self.stub.Check(req, timeout=10)
        assert resp.status.code == 0, \
            f"Check denied: {resp.status.message}"
        hdrs = {h.header.key: h.header.value
                for h in resp.ok_response.headers}
        return hdrs["x-ol-decision"]

    def execute(self, token, timeout=15):
        t0 = time.perf_counter()
        try:
            s, b = http_json("POST", self.api_base + "/transfer",
                             headers={"x-ol-decision": token}, timeout=timeout)
        finally:
            rtt_ms = (time.perf_counter() - t0) * 1000
        return s, b, rtt_ms

    def balance(self, acct="treasury") -> int:
        s, b = http_json("GET", f"{self.api_base}/balance/{acct}")
        assert s == 200
        return b["cents"]

    def effect_count(self) -> int:
        db = sqlite3.connect(str(self.db))
        try:
            return db.execute("SELECT COUNT(*) FROM effects").fetchone()[0]
        finally:
            db.close()

    def revoke(self):
        self._admin("revoke-agent", self.agent_id)

    def use_agent(self, agent_id):
        """Provision a fresh agent and switch the harness to it."""
        out = self._admin("provision-agent", agent_id,
                          "--max-cents=100000")
        self.agent_id = agent_id
        self.agent = AgentClient(agent_id,
                                 json.loads(out)["agent_private_key"])

    def close(self):
        for p in (self.api, self.authz):
            if p and p.poll() is None:
                p.terminate()
        deadline = time.time() + 5
        for p in (self.api, self.authz):
            if p and p.poll() is None:
                try:
                    p.wait(timeout=max(0, deadline - time.time()))
                except subprocess.TimeoutExpired:
                    p.kill()
        try:
            self.channel.close()
        except Exception:
            pass
        shutil.rmtree(self.tmp, ignore_errors=True)


class StandingRaceTests(unittest.TestCase):
    def setUp(self):
        self.stack = None

    def tearDown(self):
        if self.stack is not None:
            self.stack.close()
            self.stack = None

    # 1. Post-revocation token, standing check ON -> 403, zero effect.
    def test_post_revocation_blocked_with_check(self):
        self.stack = RaceStack(standing_check=True)
        st = self.stack
        token = st.mint_token(value_cents=100)
        t0, v0, e0 = st.balance("treasury"), st.balance("vendor"), \
            st.effect_count()
        st.revoke()
        status, body, _ = st.execute(token)
        self.assertEqual(status, 403, f"expected 403, got {status}: {body}")
        self.assertIn("no longer standing", body.get("error", ""),
                      f"unexpected error text: {body}")
        self.assertEqual(st.balance("treasury"), t0)
        self.assertEqual(st.balance("vendor"), v0)
        self.assertEqual(st.effect_count(), e0)

    # 2. Control: same scenario WITHOUT the check -> executes (known TTL bound).
    def test_post_revocation_executes_without_check(self):
        self.stack = RaceStack(standing_check=False)
        st = self.stack
        token = st.mint_token(value_cents=100)
        t0, v0, e0 = st.balance("treasury"), st.balance("vendor"), \
            st.effect_count()
        st.revoke()
        status, body, _ = st.execute(token)
        # This is the documented TTL-bound behavior, not a bug: without
        # an execution-time check the pre-revocation token stays valid.
        self.assertEqual(status, 200, f"control did not execute: {body}")
        self.assertTrue(body.get("ok"))
        self.assertEqual(st.balance("treasury"), t0 - 100)
        self.assertEqual(st.balance("vendor"), v0 + 100)
        self.assertEqual(st.effect_count(), e0 + 1)
        self.assertNotIn("standing_to_commit_ms", body)

    # 3. Decision-token replay: same token twice -> at most one execution.
    def test_decision_token_replay_refused(self):
        self.stack = RaceStack(standing_check=True)
        st = self.stack
        token = st.mint_token(value_cents=100)
        t0, v0 = st.balance("treasury"), st.balance("vendor")
        s1, b1, _ = st.execute(token)
        self.assertEqual(s1, 200, f"first presentation failed: {b1}")
        self.assertIn("standing_to_commit_ms", b1)
        MEASUREMENTS["standing_to_commit_ms"].append(
            b1["standing_to_commit_ms"])
        s2, b2, _ = st.execute(token)
        self.assertNotEqual(s2, 200, "replayed token executed twice")
        self.assertIn("already used", b2.get("error", ""))
        # Exactly one ledger effect total.
        self.assertEqual(st.balance("treasury"), t0 - 100)
        self.assertEqual(st.balance("vendor"), v0 + 100)
        self.assertEqual(st.effect_count(), 1)

    # 4. Standing service unreachable -> fail-closed 403, zero effect.
    def test_standing_unreachable_fail_closed(self):
        dead_port = free_port()  # nothing listens here
        self.stack = RaceStack(
            standing_check=True,
            standing_url_override=f"http://127.0.0.1:{dead_port}/standing")
        st = self.stack
        token = st.mint_token(value_cents=100)
        t0, v0, e0 = st.balance("treasury"), st.balance("vendor"), \
            st.effect_count()
        status, body, _ = st.execute(token)
        self.assertEqual(status, 403, f"expected fail-closed 403: {body}")
        self.assertIn("no longer standing", body.get("error", ""))
        self.assertEqual(st.balance("treasury"), t0)
        self.assertEqual(st.balance("vendor"), v0)
        self.assertEqual(st.effect_count(), e0)

    # 5. Concurrency: revoke landing mid-stream.
    def test_concurrent_revocation_race(self):
        self.stack = RaceStack(standing_check=True)
        st = self.stack
        # Phase A: pre-revocation baseline — all 10 must execute.
        pre_tokens = [st.mint_token(value_cents=100) for _ in range(10)]
        pre_ok = sum(1 for t in pre_tokens
                     if st.execute(t)[0] == 200)
        self.assertEqual(pre_ok, 10, "pre-revocation baseline failed")
        # Phase B: revoke, then fire 10 post-revocation attempts at once.
        post_tokens = [st.mint_token(value_cents=100) for _ in range(10)]
        st.revoke()
        barrier = threading.Barrier(11)
        results = []

        def worker(tok):
            barrier.wait()
            try:
                s, b, _ = st.execute(tok)
            except Exception as e:  # connection-level flake: record, don't lose
                results.append(("ERR", f"{type(e).__name__}"))
            else:
                results.append((s, b.get("error", "")[:60]))

        threads = [threading.Thread(target=worker, args=(t,))
                   for t in post_tokens]
        for th in threads:
            th.start()
        barrier.wait()
        for th in threads:
            th.join(timeout=30)
        self.assertEqual(len(results), 10)
        executed = sum(1 for s, _ in results if s == 200)
        refused = sum(1 for s, _ in results if s == 403)
        errored = sum(1 for s, _ in results if s == "ERR")
        self.assertEqual(executed, 0,
                         f"post-revocation attempts executed: {results}")
        self.assertEqual(refused + errored, 10)
        for s, err in results:
            if s == 403:
                self.assertIn("no longer standing", err)
        # Ledger reconciliation: no effect from any post-revocation attempt.
        self.assertEqual(st.effect_count(), 10)  # only the 10 pre-revocation
        # Phase C: the true race — revoke lands while 20 requests are
        # in flight. Record the distribution; classify attempts by
        # whether they started after revocation was confirmed.
        for round_no in range(3):
            # Fresh agent per round (the previous round's is revoked).
            st.use_agent(f"race-agent-c{round_no}")
            st2_tokens = [st.mint_token(value_cents=100)
                          for _ in range(20)]
            e_before = st.effect_count()
            t_before = st.balance("treasury")
            b2 = threading.Barrier(21)
            recs = []
            rev = {}

            def w(tok):
                b2.wait()
                t_start = time.monotonic()
                try:
                    s, b, _ = st.execute(tok)
                except Exception as e:
                    # Connection-level flake (e.g. RST under burst on
                    # this VM's loopback): record it; the ledger
                    # reconciliation below is the ground truth for
                    # whether it executed.
                    recs.append((t_start, time.monotonic(), "ERR",
                                 {"error": f"{type(e).__name__}: {e}"}))
                else:
                    recs.append((t_start, time.monotonic(), s, b))

            ths = [threading.Thread(target=w, args=(t,))
                   for t in st2_tokens]
            for th in ths:
                th.start()
            b2.wait()
            rev["start"] = time.monotonic()
            st.revoke()
            rev["done"] = time.monotonic()
            for th in ths:
                th.join(timeout=30)
            self.assertEqual(len(recs), 20)
            pre = [r for r in recs if r[1] <= rev["start"]]
            post = [r for r in recs if r[0] >= rev["done"]]
            straddle = [r for r in recs
                        if r not in pre and r not in post]
            post_exec = sum(1 for r in post if r[2] == 200)
            # Fail-closed invariant: any attempt that began after the
            # revocation was confirmed must have been refused.
            self.assertEqual(post_exec, 0,
                             f"round {round_no}: post-revocation execution!")
            for r in post:
                self.assertEqual(r[2], 403)
                self.assertIn("no longer standing",
                              r[3].get("error", ""))
            executed = sum(1 for r in recs if r[2] == 200)
            errored = sum(1 for r in recs if r[2] == "ERR")
            # Ledger reconciliation (ground truth): every recorded
            # execution produced exactly one effect, and no errored
            # attempt secretly committed.
            effects_added = st.effect_count() - e_before
            self.assertEqual(effects_added, executed,
                             f"round {round_no}: ledger/effect mismatch "
                             f"(executed={executed}, effects={effects_added},"
                             f" errored={errored})")
            self.assertEqual(t_before - st.balance("treasury"),
                             executed * 100)
            MEASUREMENTS["race_rounds"].append({
                "round": round_no,
                "pre_attempts": len(pre),
                "pre_executed": sum(1 for r in pre if r[2] == 200),
                "post_attempts": len(post),
                "post_executed": post_exec,
                "straddle_attempts": len(straddle),
                "straddle_executed": sum(
                    1 for r in straddle if r[2] == 200),
                "straddle_refused": sum(
                    1 for r in straddle if r[2] == 403),
                "straddle_errored": sum(
                    1 for r in straddle if r[2] == "ERR"),
                "revoke_subprocess_ms": round(
                    (rev["done"] - rev["start"]) * 1000, 1),
            })

    # 6. Retry storm: same token 50x rapidly -> exactly one execution.
    def test_retry_storm_single_execution(self):
        self.stack = RaceStack(standing_check=True)
        st = self.stack
        token = st.mint_token(value_cents=100)
        t0, v0 = st.balance("treasury"), st.balance("vendor")
        from concurrent.futures import ThreadPoolExecutor

        def attempt():
            try:
                return st.execute(token)[0]
            except Exception:
                return "ERR"

        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(attempt) for _ in range(50)]
            statuses = [f.result(timeout=60) for f in futs]
        ok = sum(1 for s in statuses if s == 200)
        not_ok = sum(1 for s in statuses if s != 200)
        self.assertEqual(ok, 1, f"expected exactly 1 execution: {statuses}")
        self.assertEqual(not_ok, 49)
        self.assertEqual(st.balance("treasury"), t0 - 100)
        self.assertEqual(st.balance("vendor"), v0 + 100)
        self.assertEqual(st.effect_count(), 1)

    # 7. kill -9 between the standing check and the commit.
    def test_process_kill_between_check_and_commit(self):
        self.stack = RaceStack(standing_check=True, pre_commit_delay_ms=3000)
        st = self.stack
        token = st.mint_token(value_cents=100)
        t0, v0, e0 = st.balance("treasury"), st.balance("vendor"), \
            st.effect_count()
        outcome = {}

        def do_execute():
            try:
                outcome["result"] = st.execute(token, timeout=10)
            except Exception as e:  # connection dies with the process
                outcome["error"] = f"{type(e).__name__}: {e}"

        th = threading.Thread(target=do_execute)
        th.start()
        time.sleep(1.0)  # land inside the 3 s instrumented pre-commit window
        self.assertTrue(th.is_alive(), "execute finished before the kill")
        st.api.kill()  # SIGKILL, no cleanup
        th.join(timeout=15)
        self.assertFalse(th.is_alive())
        self.assertIn("error", outcome, f"unexpected: {outcome}")
        # The ledger must show zero effect from the killed attempt.
        self.assertEqual(st.effect_count(), e0)
        # Restart the API against the same DB; the token was never
        # marked used (commit never ran), so one retry must succeed.
        menv = dict(st.env)
        menv["MOCK_API_PORT"] = str(st.api_port)
        menv["GATEWAY_STANDING_CHECK"] = "1"
        menv["GATEWAY_STANDING_URL"] = (
            f"http://127.0.0.1:{st.standing_port}/standing")
        st.api = subprocess.Popen(
            [sys.executable, str(GWROOT / "mock_api.py")],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, env=menv,
            start_new_session=True)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                s, _ = http_json("GET", st.api_base + "/health", timeout=2)
                if s == 200:
                    break
            except (urllib.error.URLError, OSError):
                time.sleep(0.2)
        s, b, _ = st.execute(token)
        self.assertEqual(s, 200, f"retry after kill failed: {b}")
        self.assertEqual(st.balance("treasury"), t0 - 100)
        self.assertEqual(st.balance("vendor"), v0 + 100)
        self.assertEqual(st.effect_count(), e0 + 1)

    # 8a. Standing endpoint latency (direct measurement).
    def test_measure_standing_endpoint_latency(self):
        self.stack = RaceStack(standing_check=True)
        st = self.stack
        url = (f"http://127.0.0.1:{st.standing_port}/standing"
               f"?decision_id=d&agent_id={st.agent_id}&issued_at="
               f"{int(time.time())}")
        rtts = []
        for _ in range(100):
            t0 = time.perf_counter()
            s, b = http_json("GET", url, timeout=5)
            rtts.append((time.perf_counter() - t0) * 1000)
            assert s == 200 and b.get("standing") is True
        MEASUREMENTS["standing_endpoint_rtt_ms"] = rtts

    # 8b. Check-to-commit interval distribution (from the API's own report).
    def test_measure_check_to_commit(self):
        self.stack = RaceStack(standing_check=True)
        st = self.stack
        vals = []
        for _ in range(30):
            tok = st.mint_token(value_cents=100)
            s, b, rtt = st.execute(tok)
            self.assertEqual(s, 200, b)
            self.assertIn("standing_to_commit_ms", b)
            vals.append(b["standing_to_commit_ms"])
            MEASUREMENTS["post_rtt_ms_check_on"].append(rtt)
        MEASUREMENTS["standing_to_commit_ms"] = vals

    # 8c. A/B: end-to-end POST latency with the check on vs off.
    def test_measure_added_latency_ab(self):
        for label, check in (("on", True), ("off", False)):
            self.stack = RaceStack(standing_check=check)
            st = self.stack
            try:
                for _ in range(20):
                    tok = st.mint_token(value_cents=100)
                    s, b, rtt = st.execute(tok)
                    assert s == 200, b
                    MEASUREMENTS[f"post_rtt_ms_check_{label}"].append(rtt)
            finally:
                st.close()
                self.stack = None


def _pct(vals, q):
    if not vals:
        return None
    s = sorted(vals)
    i = min(len(s) - 1, int(q * len(s)))
    return round(s[i], 3)


def tearDownModule():
    summary = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                      time.gmtime()),
        "note": "localhost VM; authz_server + mock_api subprocesses; "
                "Envoy bypassed (see EVIDENCE-races.md).",
        "standing_endpoint_rtt_ms": {
            "n": len(MEASUREMENTS["standing_endpoint_rtt_ms"]),
            "mean": round(statistics.fmean(
                MEASUREMENTS["standing_endpoint_rtt_ms"]), 3)
            if MEASUREMENTS["standing_endpoint_rtt_ms"] else None,
            "p50": _pct(MEASUREMENTS["standing_endpoint_rtt_ms"], 0.5),
            "p99": _pct(MEASUREMENTS["standing_endpoint_rtt_ms"], 0.99),
            "max": round(max(MEASUREMENTS["standing_endpoint_rtt_ms"]), 3)
            if MEASUREMENTS["standing_endpoint_rtt_ms"] else None,
        },
        "standing_to_commit_ms": {
            "n": len(MEASUREMENTS["standing_to_commit_ms"]),
            "mean": round(statistics.fmean(
                MEASUREMENTS["standing_to_commit_ms"]), 3)
            if MEASUREMENTS["standing_to_commit_ms"] else None,
            "p50": _pct(MEASUREMENTS["standing_to_commit_ms"], 0.5),
            "p99": _pct(MEASUREMENTS["standing_to_commit_ms"], 0.99),
            "max": round(max(MEASUREMENTS["standing_to_commit_ms"]), 3)
            if MEASUREMENTS["standing_to_commit_ms"] else None,
        },
        "post_rtt_ms_check_on": {
            "n": len(MEASUREMENTS["post_rtt_ms_check_on"]),
            "p50": _pct(MEASUREMENTS["post_rtt_ms_check_on"], 0.5),
        },
        "post_rtt_ms_check_off": {
            "n": len(MEASUREMENTS["post_rtt_ms_check_off"]),
            "p50": _pct(MEASUREMENTS["post_rtt_ms_check_off"], 0.5),
        },
        "race_rounds": MEASUREMENTS["race_rounds"],
    }
    MEASUREMENTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    MEASUREMENTS_PATH.write_text(json.dumps(summary, indent=2))
    print("\n[measurements] " + json.dumps(summary))


if __name__ == "__main__":
    unittest.main()
