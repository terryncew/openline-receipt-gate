"""Untrusted relay: delay, duplicate, reorder (by caller order), or drop.

The relay never reads a Gate database and owns no signing key or authority.
"""
from __future__ import annotations

import argparse
import socket
import time

from .wire import recv_json, reply_json, send_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(64)
    try:
        while True:
            conn, _addr = server.accept()
            with conn:
                try:
                    message = recv_json(conn)
                    op = message.get("op")
                    if op == "SHUTDOWN":
                        reply_json(conn, {"ok": True})
                        break
                    if op != "FORWARD":
                        reply_json(conn, {"ok": False, "error": "unknown_op"})
                        continue
                    delay_ms = int(message.get("delay_ms", 0))
                    duplicates = int(message.get("duplicates", 1))
                    if delay_ms < 0 or duplicates < 1 or duplicates > 200:
                        reply_json(conn, {"ok": False, "error": "relay_parameter_invalid"})
                        continue
                    if bool(message.get("drop", False)):
                        reply_json(conn, {"ok": True, "relay": "DROPPED", "responses": []})
                        continue
                    if delay_ms:
                        time.sleep(delay_ms / 1000.0)
                    target_host = str(message["target_host"])
                    target_port = int(message["target_port"])
                    inner = message["message"]
                    responses = []
                    for _ in range(duplicates):
                        try:
                            responses.append(send_json(target_host, target_port, inner, timeout=float(message.get("timeout", 5.0))))
                        except Exception as exc:
                            responses.append({"ok": False, "transport_error": type(exc).__name__, "detail": str(exc)})
                    reply_json(conn, {"ok": True, "relay": "FORWARDED", "responses": responses})
                except Exception as exc:
                    try:
                        reply_json(conn, {"ok": False, "error": type(exc).__name__, "detail": str(exc)})
                    except Exception:
                        pass
    finally:
        server.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
