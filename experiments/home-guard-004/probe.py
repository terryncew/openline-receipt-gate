"""Uncooperative synthetic TCP probe. A timeout alone is NOT proof of a DROP."""
from __future__ import annotations
import json
import socket
import sys
import time

label, host, port_str = sys.argv[1:4]
port = int(port_str)
started_ns = time.time_ns()
status = "UNKNOWN"
reply = ""
try:
    with socket.create_connection((host, port), timeout=0.9) as sock:
        sock.settimeout(0.9)
        data = ("HG4:" + label).encode()
        sock.sendall(data)
        reply = sock.recv(256).decode(errors="replace")
        status = "ACK" if reply else "EOF"
except socket.timeout:
    status = "TIMEOUT"
except OSError as exc:
    status = type(exc).__name__
print(json.dumps({"label": label, "host": host, "port": port,
                  "status": status, "reply": reply, "start_ns": started_ns,
                  "end_ns": time.time_ns()}, sort_keys=True))
