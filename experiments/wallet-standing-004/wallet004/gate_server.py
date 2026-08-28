"""One isolated Gate process with its own durable state and TCP endpoint."""
from __future__ import annotations

import argparse
import base64
import json
import socket
import time

from .gate_runtime import GateRuntime
from .wire import recv_json, reply_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gate-id", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--policy-b64", required=True)
    parser.add_argument("--policy-hash", required=True)
    parser.add_argument("--measurement-public-key", required=True)
    parser.add_argument("--requires-checkpoint", action="store_true")
    args = parser.parse_args()

    policy = json.loads(base64.urlsafe_b64decode(args.policy_b64.encode("ascii")).decode("utf-8"))
    runtime = GateRuntime(
        gate_id=args.gate_id,
        db_path=args.db,
        recovery_policy=policy,
        trusted_policy_hash=args.policy_hash,
        measurement_public_key=args.measurement_public_key,
        requires_checkpoint=args.requires_checkpoint,
    )
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(32)
    try:
        while True:
            conn, _addr = server.accept()
            with conn:
                gate_receive_ns = time.time_ns()
                try:
                    message = recv_json(conn)
                    op = message.get("op")
                    if op == "CALIBRATE":
                        gate_send_ns = time.time_ns()
                        reply_json(conn, {"ok": True, "gate_id": args.gate_id, "gate_receive_ns": gate_receive_ns, "gate_send_ns": gate_send_ns})
                    elif op == "INGEST":
                        result = runtime.ingest(message["envelope"], crash_before_commit=bool(message.get("crash_before_commit", False)))
                        result["gate_receive_ns"] = gate_receive_ns
                        reply_json(conn, result)
                    elif op == "EVALUATE":
                        result = runtime.evaluate(
                            bundle=message["bundle"],
                            expected_action=message["expected_action"],
                            receiver_challenge=message["receiver_challenge"],
                            admission_policy=message["admission_policy"],
                        )
                        reply_json(conn, result)
                    elif op == "STATE":
                        reply_json(conn, runtime.summary())
                    elif op == "SHUTDOWN":
                        reply_json(conn, {"ok": True, "gate_id": args.gate_id})
                        break
                    else:
                        reply_json(conn, {"ok": False, "error": "unknown_op", "gate_id": args.gate_id})
                except Exception as exc:
                    try:
                        reply_json(conn, {"ok": False, "gate_id": args.gate_id, "error": type(exc).__name__, "detail": str(exc)})
                    except Exception:
                        pass
    finally:
        runtime.close()
        server.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
