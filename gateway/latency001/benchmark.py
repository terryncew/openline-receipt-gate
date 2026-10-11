#!/usr/bin/env python3
"""Strict, closed-loop benchmark of an already running isolated Compose stack.

Every response is completely read and checked. A failed request makes the
case and process fail; it never becomes a fast successful latency sample.
The first client request is separate from warmup and steady-state samples.
This is not a process-cold measurement: start the stack separately and
record its startup when measuring process startup.

Example (from any directory, COMPOSE_FILE/COMPOSE_PROJECT_NAME honored):
  python3 gateway/latency001/benchmark.py --mode openline --samples 1000 \
      --concurrency 1 8 32 --clients close persistent --workloads transfer \
      --output /tmp/openline-benchmark
"""

from __future__ import annotations

import argparse
import concurrent.futures
from collections import Counter, defaultdict, deque
import http.client
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

GWROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GWROOT))
SIGNED_MODES = {"openline", "opa-stateful"}
FLOOR_MODE = "trusted-envoy-floor"


def distribution(values):
    """Linear interpolation at (n - 1) * quantile; retain raw observations."""
    if not values:
        return {"n": 0, "p50_ms": None, "p95_ms": None,
                "p99_ms": None, "mean_ms": None, "max_ms": None}
    ordered = sorted(values)

    def percentile(p):
        k = (len(ordered) - 1) * p
        lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
        return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)

    return {"n": len(values), "p50_ms": percentile(.50),
            "p95_ms": percentile(.95), "p99_ms": percentile(.99),
            "mean_ms": statistics.mean(values), "max_ms": max(values)}


class Compose:
    def __init__(self, directory, profile):
        self.directory = Path(directory).resolve()
        self.base = ["docker", "compose"]
        if profile:
            self.base.extend(["--profile", profile])

    def exec(self, service, code):
        # Never include captured stdout in an exception: provision outputs a key.
        result = subprocess.run(
            self.base + ["exec", "-T", service, "python3", "-c", code],
            cwd=self.directory, capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise RuntimeError(f"compose exec {service} failed, exit {result.returncode}")
        return result.stdout

    def provision(self, agent_id, max_cents):
        from agent_client import AgentClient
        code = ("from gateway.gateway_admin import cmd_provision; "
                f"cmd_provision({agent_id!r}, max_cents={max_cents!r})")
        payload = json.loads(self.exec("authz", code))
        # Keep the private key in memory only, never in output artifacts.
        return AgentClient(agent_id, payload["agent_private_key"])

    def ledger_snapshot(self):
        code = """import json, os, sqlite3
d=sqlite3.connect(os.environ['GATEWAY_DB'])
b=dict(d.execute('SELECT acct,cents FROM balances'))
tables={r[0] for r in d.execute("SELECT name FROM sqlite_master WHERE type='table'")}
print(json.dumps({'balances':b,'effects':d.execute('SELECT count(*) FROM effects').fetchone()[0],
'receipts':d.execute('SELECT count(*) FROM receipts').fetchone()[0] if 'receipts' in tables else None,
'journal_mode':d.execute('PRAGMA journal_mode').fetchone()[0]}))
"""
        return json.loads(self.exec("mockapi", code))

    def runtime_flags(self, service):
        # Whitelist only nonsecret experiment switches, never dump env.
        names = ("GATEWAY_AUTH_MODE", "GATEWAY_STANDING_CHECK", "GATEWAY_STANDING_URL",
                 "GATEWAY_STANDING_PORT", "GATEWAY_PROFILE",
                 "GATEWAY_TEST_PRE_COMMIT_DELAY_MS")
        code = ("import os,json; "
                f"print(json.dumps({{k:os.environ.get(k) for k in {names!r}}}))")
        return json.loads(self.exec(service, code))

    def mint_floor_decisions(self, agent_id, count, amount):
        """LAB ONLY: pre-sign unique capabilities inside the receiver container.

        The receiver private key never leaves its container. These tokens
        measure the protected API/network floor, not authorization. Its
        ordinary signature/TTL/standing/single-use checks stay enabled.
        """
        code = f"""import json, os, time, uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from gateway.authz_server import Authorizer, DECISION_TTL_SECONDS, b64u_decode
a=object.__new__(Authorizer)
a.receiver_key=Ed25519PrivateKey.from_private_bytes(b64u_decode((Path(os.environ['GATEWAY_CONFIG'])/'receiver.key').read_text().strip()))
issued=int(time.time())
tokens=[a._mint_decision_token({{'action':{{'agent_id':{agent_id!r},'action_type':'authorize_payment','target':'ledger','value_cents':{amount!r},'nonce':uuid.uuid4().hex}}}}) for _ in range({count!r})]
print(json.dumps({{'issued_at':issued,'ttl':DECISION_TTL_SECONDS,'tokens':tokens}}))
"""
        return json.loads(self.exec("authz", code))

    def profile_offset(self, service, path):
        code = ("import os; "
                f"print(os.path.getsize({path!r}) if os.path.exists({path!r}) else 0)")
        return int(self.exec(service, code).strip())

    def profile_records(self, service, path, offset):
        code = ("import os,sys; "
                f"p={path!r}; "
                "f=open(p,'rb') if os.path.exists(p) else None; "
                f"f.seek({offset}) if f else None; "
                "sys.stdout.buffer.write(f.read() if f else b'')")
        content = self.exec(service, code)
        records, malformed = [], 0
        for line in content.splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                malformed += 1
        return records, malformed


class HttpTransport:
    def __init__(self, url, client, timeout):
        self.url = urllib.parse.urlsplit(url)
        if self.url.scheme not in {"http", "https"}:
            raise ValueError("URL must use http or https")
        self.client, self.timeout = client, timeout
        self.connection = None

    def close(self):
        if self.connection:
            self.connection.close()
            self.connection = None

    def request(self, method, path, headers, body):
        address = self.url.path.rstrip("/") + path
        start = time.perf_counter_ns()
        if self.client == "close":
            # Match historical urllib connection-per-request behavior while
            # ALSO measuring until the complete body is consumed.
            req = urllib.request.Request(
                urllib.parse.urlunsplit((self.url.scheme, self.url.netloc,
                                        address, "", "")),
                method=method, data=body, headers={**headers, "Connection": "close"})
            try:
                response = urllib.request.urlopen(req, timeout=self.timeout)
            except urllib.error.HTTPError as error:
                response = error
            header_end = time.perf_counter_ns()
            with response:
                status, payload = response.status, response.read()
                response_trace = response.headers.get("x-request-id")
        else:
            if self.connection is None:
                connection_type = (http.client.HTTPSConnection
                                   if self.url.scheme == "https"
                                   else http.client.HTTPConnection)
                self.connection = connection_type(self.url.hostname, self.url.port,
                                                  timeout=self.timeout)
            self.connection.request(method, address, body=body, headers=headers)
            response = self.connection.getresponse()
            header_end = time.perf_counter_ns()
            status, payload = response.status, response.read()
            response_trace = response.headers.get("x-request-id")
        end = time.perf_counter_ns()
        return (status, payload, (end - start) / 1e6,
                (header_end - start) / 1e6, response_trace)


class GrpcTransport:
    """Diagnostic direct Check RPC; authorizes but does not execute the API."""
    def __init__(self, target, client, timeout):
        import grpc
        import ext_authz_pb2_grpc
        self.grpc = grpc
        self.target, self.client, self.timeout = target, client, timeout
        self.channel = None
        self.stub_type = ext_authz_pb2_grpc.AuthorizationStub

    def close(self):
        if self.channel:
            self.channel.close()
            self.channel = None

    def request(self, method, path, headers, body):
        import ext_authz_pb2
        request = ext_authz_pb2.CheckRequest()
        request.attributes.request.http.method = method
        request.attributes.request.http.path = path
        request.attributes.request.http.headers.update(headers)
        request.attributes.request.http.body = (body or b"").decode()
        start = time.perf_counter_ns()
        if self.channel is None:
            self.channel = self.grpc.insecure_channel(self.target)
        response = self.stub_type(self.channel).Check(request, timeout=self.timeout)
        end = time.perf_counter_ns()
        if self.client == "close":
            self.close()
        data = {"rpc_status": response.status.code,
                "decision_present": any(h.header.key == "x-ol-decision"
                                        for h in response.ok_response.headers)}
        return (200 if response.status.code == 0 else 403,
                json.dumps(data).encode(), (end-start)/1e6, (end-start)/1e6,
                headers.get("x-request-id"))


class FloorDecisions:
    """Token batches stay in memory and retain the repository's ordinary TTL."""
    def __init__(self, compose, agent_id, count, amount):
        self.compose, self.agent_id, self.amount = compose, agent_id, amount
        self.remaining, self.count = count, count
        self.lock = threading.Lock()
        self.mint_elapsed_seconds = 0.
        self.mint_batches = 0
        self.tokens = deque()
        self._mint()

    def _mint(self):
        started = time.perf_counter()
        batch = self.compose.mint_floor_decisions(self.agent_id, self.remaining, self.amount)
        self.mint_elapsed_seconds += time.perf_counter() - started
        self.mint_batches += 1
        self.issued_at, self.ttl = batch["issued_at"], batch["ttl"]
        self.tokens = deque(batch["tokens"])

    def take(self):
        with self.lock:
            # Renew outside the timed network request, not by extending TTL.
            # A request that still expires in flight is retained as a failure.
            # Elapsed achieved throughput includes any renewal stalls.
            if time.time() - self.issued_at >= self.ttl - 10:
                self._mint()
            token = self.tokens.popleft()
            self.remaining -= 1
            return token


def validate_response(status, payload, workload, amount, signed, transport,
                      expected_balance):
    if status != 200:
        return f"HTTP/RPC mapped status {status}", None
    try:
        obj = json.loads(payload)
    except (ValueError, UnicodeError):
        return "response is not JSON", None
    if transport == "grpc":
        if obj.get("rpc_status") != 0 or obj.get("decision_present") is not True:
            return "Check did not return a successful signed decision", None
    elif workload == "inspect":
        if (obj.get("acct") != "treasury" or type(obj.get("cents")) is not int
                or obj["cents"] != expected_balance):
            return "balance response differs from durable ledger snapshot", None
    else:
        if obj.get("ok") is not True or not isinstance(obj.get("effect_id"), str):
            return "transfer did not report a successful ledger effect", None
        if signed and obj.get("authorized_params", {}).get("value_cents") != amount:
            return "executed amount differs from signed authorized amount", None
        return None, obj["effect_id"]
    return None, None


def summarize_profiles(records, samples):
    by_trace = defaultdict(dict)
    stages = defaultdict(list)
    counts = Counter()
    traces = {sample["trace_id"] for sample in samples if sample["success"]}
    for record in records:
        if record.get("trace_id") not in traces:
            continue
        component = record["component"]
        counts[component] += 1
        by_trace[record["trace_id"]][component] = record["elapsed_ms"]
        stages[f"{component}.total"].append(record["elapsed_ms"])
        for stage, value in record.get("stages_ms", {}).items():
            stages[f"{component}.{stage}"].append(value)
    residual = []
    for sample in samples:
        timings = by_trace.get(sample["trace_id"], {})
        if "authz.request" in timings and "api.request" in timings:
            residual.append(sample["latency_ms"] - timings["authz.request"]
                            - timings["api.request"])
    return {"record_counts": dict(counts), "successful_measured_requests": len(traces),
            "unique_traces_with_profiles": len(by_trace),
            "stages": {stage: distribution(values) for stage, values in stages.items()},
            "network_envoy_scheduling_and_profile_output_residual": distribution(residual),
            "note": "Nested stages are inclusive and must not be summed. Residual also includes profiling output, serialization and queueing."}


def run_case(args, compose, agent, workload, client, concurrency, output):
    signed = args.mode in SIGNED_MODES or args.mode == FLOOR_MODE
    case_id = f"{args.mode}-{args.transport}-{workload}-{client}-c{concurrency}"
    floor_decisions = (FloorDecisions(compose, agent.agent_id,
                                     1 + args.warmup * concurrency + args.samples,
                                     args.amount)
                       if args.mode == FLOOR_MODE and workload == "transfer" else None)
    before = compose.ledger_snapshot()
    offsets = {(service, path): compose.profile_offset(service, path)
               for service, path in args.profile_files}
    direct = args.mode == "trusted-direct"
    path = ("" if direct else "/api") + ("/balance/treasury" if workload == "inspect"
                                            else "/transfer")
    method = "GET" if workload == "inspect" else "POST"
    body = None if method == "GET" else json.dumps({"to": "vendor", "cents": args.amount}).encode()
    transports = [(GrpcTransport(args.grpc_target, client, args.timeout)
                   if args.transport == "grpc" else HttpTransport(args.url, client, args.timeout))
                  for _ in range(concurrency)]

    def request(worker, index, phase):
        start = time.perf_counter_ns()
        trace_id = str(uuid.uuid4())
        try:
            if args.mode == FLOOR_MODE:
                headers = {"x-ol-decision": floor_decisions.take()} if floor_decisions else {}
            elif signed:
                headers = agent.headers_for("inspect" if workload == "inspect"
                                            else "authorize_payment",
                                            value_cents=0 if workload == "inspect" else args.amount)
            elif direct:
                # Trusted backend/network floor, not equivalent authorization.
                headers = {"x-opa-decision": "allow"}
            else:
                headers = {"Authorization": "Bearer opaline-token-001"}
            headers.update({"x-request-id": trace_id, "Content-Type": "application/json"})
        except Exception as error:
            return {"index": index, "worker": worker, "phase": phase,
                    "trace_id": trace_id, "client_prepare_ms": (time.perf_counter_ns()-start)/1e6,
                    "status": None, "success": False, "effect_id": None,
                    "latency_ms": 0., "response_headers_ms": None,
                    "error": "client_prepare_" + type(error).__name__}
        prepare_ms = (time.perf_counter_ns() - start) / 1e6
        sample = {"index": index, "worker": worker, "phase": phase,
                  "trace_id": trace_id, "client_prepare_ms": prepare_ms,
                  "status": None, "success": False, "effect_id": None}
        request_start = time.perf_counter_ns()
        try:
            status, payload, latency, header_latency, response_trace = transports[worker].request(
                method, path, headers, body)
            # Envoy may replace an externally supplied request UUID. Its
            # returned UUID is the one observed by authz and the backend.
            if response_trace:
                try:
                    sample["trace_id"] = str(uuid.UUID(response_trace))
                except (ValueError, TypeError, AttributeError):
                    pass
            error, effect = validate_response(status, payload, workload, args.amount,
                                              signed, args.transport,
                                              before["balances"]["treasury"])
            sample.update({"status": status, "latency_ms": latency,
                           "response_headers_ms": header_latency,
                           "response_bytes": len(payload), "effect_id": effect,
                           "success": error is None, "error": error})
        except Exception as error:
            # Do not log headers, keys or request/response bodies on errors.
            sample.update({"latency_ms": (time.perf_counter_ns()-request_start)/1e6,
                           "response_headers_ms": None,
                           "error": type(error).__name__})
            transports[worker].close()
        return sample

    all_samples = [request(0, -1, "first_client_request")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        def warm_worker(worker):
            return [request(worker, i, "warmup") for i in range(args.warmup)]
        for batch in executor.map(warm_worker, range(concurrency)):
            all_samples.extend(batch)
        barrier = threading.Barrier(concurrency + 1)

        def timed_worker(worker):
            barrier.wait()
            return [request(worker, index, "measured")
                    for index in range(worker, args.samples, concurrency)]

        futures = [executor.submit(timed_worker, worker) for worker in range(concurrency)]
        started = time.perf_counter()
        barrier.wait()
        measured = []
        for future in futures:
            measured.extend(future.result())
        elapsed = time.perf_counter() - started
    all_samples.extend(measured)
    for transport in transports:
        transport.close()
    # Save attempts before diagnostics: even a failing post-run Docker/DB
    # inspection must not lose the request-level evidence.
    (output / f"{case_id}.raw.json").write_text(json.dumps(all_samples, indent=2) + "\n")
    after = compose.ledger_snapshot()
    effects = [sample["effect_id"] for sample in all_samples if sample["effect_id"]]
    transfer_count = len(effects) if args.transport == "http" else 0
    expected_delta = transfer_count * args.amount
    ledger_ok = (before["balances"]["treasury"] - after["balances"]["treasury"] == expected_delta
                 and after["balances"].get("vendor", 0) - before["balances"].get("vendor", 0) == expected_delta
                 and after["effects"] - before["effects"] == transfer_count
                 and len(set(effects)) == len(effects))
    successful = [sample for sample in measured if sample["success"]]
    records, malformed = [], 0
    for (service, path), offset in offsets.items():
        batch, errors = compose.profile_records(service, path, offset)
        records.extend(batch)
        malformed += errors
    summary = {
        "case": case_id, "samples_requested": args.samples,
        "concurrency": concurrency, "client": client, "workload": workload,
        "amount_cents": args.amount, "passed": ledger_ok and all(s["success"] for s in all_samples),
        "status_counts": dict(Counter(str(s["status"]) for s in measured)),
        "failures": len(measured) - len(successful),
        "all_attempted_latency": distribution([s["latency_ms"] for s in measured]),
        "successful_latency": distribution([s["latency_ms"] for s in successful]),
        "successful_response_headers_latency": distribution([s["response_headers_ms"] for s in successful]),
        "client_prepare": distribution([s["client_prepare_ms"] for s in measured]),
        "elapsed_seconds": elapsed,
        "achieved_successful_requests_per_second": len(successful) / elapsed,
        "first_client_request": all_samples[0],
        "warmup_requests_per_worker": args.warmup,
        "ledger": {"passed": ledger_ok, "before": before, "after": after,
                   "expected_transfer_count_including_first_and_warmup": transfer_count,
                   "expected_delta_cents": expected_delta},
        "profiling": summarize_profiles(records, measured),
        "profile_malformed_lines": malformed,
    }
    if args.mode == FLOOR_MODE:
        summary["floor"] = {
            "lab_only": True, "authorization_bypassed": True,
            "protected_api_signature_ttl_single_use_and_standing_checks": "unchanged",
            "token_mint_batches": floor_decisions.mint_batches if floor_decisions else 0,
            "token_mint_elapsed_seconds": floor_decisions.mint_elapsed_seconds if floor_decisions else 0,
            "note": "Tokens pre-minted inside receiver; private key never exported; token TTL unchanged; renewal before timed requests appears in client preparation and elapsed throughput. This is a network/backend floor, not a secure authorization alternative."}
    (output / f"{case_id}.profile.jsonl").write_text("".join(json.dumps(r)+"\n" for r in records))
    (output / f"{case_id}.summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["openline", "opa-stateful", "opa-a", "opa-b", "trusted-direct", FLOOR_MODE], required=True)
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--compose-dir", default=str(GWROOT / "compose"))
    parser.add_argument("--profile", default="openline")
    parser.add_argument("--samples", type=int, default=1000)
    parser.add_argument("--concurrency", nargs="+", type=int, default=[1, 8, 32])
    parser.add_argument("--clients", nargs="+", choices=["close", "persistent"], default=["persistent"])
    parser.add_argument("--workloads", nargs="+", choices=["inspect", "transfer"], default=["transfer"])
    parser.add_argument("--amount", type=int, default=1)
    parser.add_argument("--warmup", type=int, default=10, help="excluded warmup requests per worker")
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--transport", choices=["http", "grpc"], default="http")
    parser.add_argument("--grpc-target", default="127.0.0.1:50051")
    parser.add_argument("--profile-file", action="append", default=[], metavar="SERVICE:PATH")
    parser.add_argument("--output", required=True)
    parser.add_argument("--label", default="", help="human label, e.g. baseline commit or optimized commit")
    args = parser.parse_args(argv)
    if args.samples <= 0 or args.amount <= 0 or args.warmup < 0 or any(c <= 0 or c > args.samples for c in args.concurrency):
        parser.error("positive samples/amount/concurrency, concurrency <= samples, warmup >= 0 required")
    if args.transport == "grpc" and args.mode not in SIGNED_MODES:
        parser.error("direct gRPC measurement requires a signed Gateway mode")
    args.profile_files = [item.split(":", 1) for item in args.profile_file]
    if any(len(item) != 2 for item in args.profile_files):
        parser.error("--profile-file expects SERVICE:PATH")
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    compose = Compose(args.compose_dir, args.profile)
    agent_id = "latency-" + uuid.uuid4().hex[:12]
    agent = compose.provision(agent_id, max_cents=max(1_000_000, args.amount)) if args.mode in SIGNED_MODES or args.mode == FLOOR_MODE else None
    results = []
    metadata = {"label": args.label, "mode": args.mode, "transport": args.transport,
                "url": args.url, "python": platform.python_version(),
                "platform": platform.platform(), "command": sys.argv,
                "compose_file": os.environ.get("COMPOSE_FILE"),
                "compose_project_name": os.environ.get("COMPOSE_PROJECT_NAME"),
                "agent_id": agent_id if agent else None,
                "measurement": "closed-loop, no think time; full response body consumed; request signing separate; elapsed throughput includes client preparation and result collection; no retries",
                "percentiles": "linear interpolation (n-1)*p; successful samples only, any failure fails case"}
    try:
        metadata["runtime_flags"] = {"mockapi": compose.runtime_flags("mockapi")}
        if agent:
            metadata["runtime_flags"]["authz"] = compose.runtime_flags("authz")
        for workload in args.workloads:
            for client in args.clients:
                for concurrency in args.concurrency:
                    result = run_case(args, compose, agent, workload, client, concurrency, output)
                    results.append(result)
                    if not result["passed"]:
                        raise RuntimeError(f"benchmark case failed: {result['case']}")
        report = {"metadata": metadata, "passed": True, "cases": results}
    except Exception as error:
        report = {"metadata": metadata, "passed": False, "cases": results,
                  "error": str(error) if isinstance(error, RuntimeError) else type(error).__name__}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
