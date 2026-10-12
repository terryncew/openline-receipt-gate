#!/usr/bin/env python3
"""OPA ext_authz shim: translates Envoy ext_authz gRPC Check to OPA's REST API.

The authorization DECISION is made entirely by OPA evaluating Rego
(POST /v1/data/envoy/authz). This shim only translates protocols: it
adds no policy logic of its own. Used for the head-to-head baselines
because stock OPA binaries no longer bundle the envoy gRPC plugin.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from concurrent import futures
from pathlib import Path

import grpc

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import ext_authz_pb2 as pb2
import ext_authz_pb2_grpc as pb2_grpc

OPA_URL = "http://127.0.0.1:8181/v1/data/envoy/authz"


class OpaShim(pb2_grpc.AuthorizationServicer):
    def Check(self, request, context):
        http = request.attributes.request.http
        opa_input = {
            "input": {
                "attributes": {
                    "request": {
                        "http": {
                            "method": http.method,
                            "path": http.path,
                            "headers": dict(http.headers),
                        }
                    }
                }
            }
        }
        req = urllib.request.Request(
            OPA_URL, data=json.dumps(opa_input).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                result = json.loads(r.read()).get("result", {})
        except Exception as exc:
            return pb2.CheckResponse(
                status=pb2.RpcStatus(code=2, message=f"opa error: {exc}"))
        if result.get("allow"):
            headers = [
                pb2.HeaderValueOption(header=pb2.HeaderValue(key=k, value=v))
                for k, v in result.get("headers", {}).items()
            ]
            return pb2.CheckResponse(
                status=pb2.RpcStatus(code=0),
                ok_response=pb2.OkHttpResponse(headers=headers))
        return pb2.CheckResponse(
            status=pb2.RpcStatus(code=7, message="opa denied"),
            denied_response=pb2.DeniedHttpResponse(
                status=pb2.HttpStatus(code=403),
                body=json.dumps({"denied": True, "by": "opa"})))


def serve(port=50052):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=16))
    pb2_grpc.add_AuthorizationServicer_to_server(OpaShim(), server)
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    print(f"[opa-shim] listening on :{port} -> {OPA_URL}", flush=True)
    server.wait_for_termination()


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 50052)
