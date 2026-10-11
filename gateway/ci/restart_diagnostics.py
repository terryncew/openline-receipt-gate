#!/usr/bin/env python3
"""Capture restart evidence without printing private keys or signed headers."""
from __future__ import annotations

import json
import subprocess
import uuid

import docker_verify as verify


def capture(label: str, command: list[str]) -> None:
    print(f"\n== {label} ==", flush=True)
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        print(f"exit={result.returncode}\n{result.stdout}\n{result.stderr}", flush=True)
    except subprocess.TimeoutExpired:
        print("diagnostic command timed out", flush=True)


def main() -> None:
    ids = verify.compose("ps", "-aq", "envoy", "authz", "mockapi").stdout.split()
    if ids:
        capture("container state and networking", ["docker", "inspect", "--format",
                '{{.Name}} {{json .State}} {{json .NetworkSettings.Networks}}', *ids])
        for container in ids:
            capture(f"processes: {container}", ["docker", "top", container])
    p = verify.cexec("authz", "python3", "-c", '''
import json, socket, urllib.request
for host in ("authz", "mockapi", "envoy"):
    print("DNS", host, socket.gethostbyname_ex(host))
for path in ("health", "balance/treasury", "balance/vendor"):
    with urllib.request.urlopen("http://mockapi:9000/" + path, timeout=3) as response:
        print("direct", path, response.status, response.read().decode())
''')
    print(f"\n== DNS and direct mock API ==\nexit={p.returncode}\n{p.stdout}\n{p.stderr}", flush=True)
    p = verify.cexec("envoy", "bash", "-c",
                    'exec 3<>/dev/tcp/127.0.0.1/9901; '
                    'printf "GET /clusters?format=json HTTP/1.1\\r\\nHost: localhost\\r\\n'
                    'Connection: close\\r\\n\\r\\n" >&3; cat <&3')
    print(f"\n== Envoy cluster health ==\nexit={p.returncode}\n{p.stdout}\n{p.stderr}", flush=True)
    # Unique diagnostic identity: never reset the revoked test agent.
    observer = verify.provision("ci-diagnostic-" + uuid.uuid4().hex[:8])
    for account in ("treasury", "vendor"):
        status, cents = verify.get_balance(observer, account)
        print(json.dumps({"probe": "proxied inspection", "account": account,
                          "http_status": status, "cents": cents}), flush=True)


if __name__ == "__main__":
    main()
