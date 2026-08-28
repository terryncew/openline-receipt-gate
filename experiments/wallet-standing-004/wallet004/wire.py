"""Small length-bounded NDJSON socket helpers."""
from __future__ import annotations

import json
import socket
from typing import Any

MAX_MESSAGE_BYTES = 2_000_000


def _encode(obj: Any) -> bytes:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(raw) > MAX_MESSAGE_BYTES:
        raise ValueError("message_too_large")
    return raw + b"\n"


def recv_json(conn: socket.socket) -> dict[str, Any]:
    chunks: list[bytes] = []
    size = 0
    while True:
        piece = conn.recv(65536)
        if not piece:
            break
        chunks.append(piece)
        size += len(piece)
        if size > MAX_MESSAGE_BYTES + 1:
            raise ValueError("message_too_large")
        if b"\n" in piece:
            break
    raw = b"".join(chunks)
    line, _sep, _rest = raw.partition(b"\n")
    value = json.loads(line.decode("ascii"))
    if not isinstance(value, dict):
        raise ValueError("message_not_object")
    return value


def send_json(host: str, port: int, obj: dict[str, Any], *, timeout: float = 5.0) -> dict[str, Any]:
    with socket.create_connection((host, int(port)), timeout=timeout) as conn:
        conn.settimeout(timeout)
        conn.sendall(_encode(obj))
        return recv_json(conn)


def reply_json(conn: socket.socket, obj: dict[str, Any]) -> None:
    conn.sendall(_encode(obj))
