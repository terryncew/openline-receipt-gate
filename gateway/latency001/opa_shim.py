#!/usr/bin/env python3
"""Benchmark protocol adapter: Envoy ext_authz gRPC to real OPA HTTP.

OPA makes the policy decision. Connections belong to individual gRPC
worker threads, so concurrent checks cannot share an in-flight HTTP request.
Errors fail closed and are never retried as an authorization decision.
"""
from __future__ import annotations

import http.client
import json
import os
import sys
import threading
from concurrent import futures
from pathlib import Path
from urllib.parse import urlsplit

import grpc

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ext_authz_pb2 as pb2
import ext_authz_pb2_grpc as pb2_grpc


class OpaClient:
    def __init__(self, url=None, timeout=2):
        self.url = urlsplit(url or os.environ.get(
            "LATENCY_OPA_URL", "http://opa:8181/v1/data/envoy/authz"))
        if self.url.scheme not in {"http", "https"}:
            raise ValueError("OPA URL must use HTTP or HTTPS")
        self.timeout = timeout
        self.local = threading.local()

    def query(self, value):
        conn = getattr(self.local, "connection", None)
        if conn is None:
            cls = (http.client.HTTPSConnection if self.url.scheme == "https"
                   else http.client.HTTPConnection)
            conn = cls(self.url.hostname, self.url.port, timeout=self.timeout)
            self.local.connection = conn
        try:
            path = self.url.path + ("?" + self.url.query if self.url.query else "")
            conn.request("POST", path, body=json.dumps({"input": value}),
                         headers={"Content-Type": "application/json"})
            response = conn.getresponse()
            payload = response.read()
            if response.status != 200:
                raise RuntimeError(f"OPA HTTP {response.status}")
            result = json.loads(payload).get("result")
            if not isinstance(result, dict):
                raise ValueError("OPA result is not an object")
            return result
        except Exception:
            conn.close()
            self.local.connection = None
            raise


class OpaShim(pb2_grpc.AuthorizationServicer):
    def __init__(self):
        self.client = OpaClient()

    def Check(self, request, context):
        http = request.attributes.request.http
        value = {"attributes": {"request": {"http": {
            "method": http.method, "path": http.path,
            "headers": dict(http.headers)}}}}
        try:
            result = self.client.query(value)
        except Exception as exc:
            return pb2.CheckResponse(status=pb2.RpcStatus(
                code=2, message=f"OPA unavailable: {type(exc).__name__}"))
        if result.get("allow") is True:
            headers = [pb2.HeaderValueOption(header=pb2.HeaderValue(key=k, value=v))
                       for k, v in result.get("headers", {}).items()]
            return pb2.CheckResponse(status=pb2.RpcStatus(code=0),
                                    ok_response=pb2.OkHttpResponse(headers=headers))
        return pb2.CheckResponse(
            status=pb2.RpcStatus(code=7, message="opa denied"),
            denied_response=pb2.DeniedHttpResponse(
                status=pb2.HttpStatus(code=403),
                body=json.dumps({"denied": True, "by": "opa"})))


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 50052
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=32))
    pb2_grpc.add_AuthorizationServicer_to_server(OpaShim(), server)
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    print(f"[latency-opa-shim] listening on :{port}", flush=True)
    server.wait_for_termination()
