"""HOME-GUARD-005 trusted witness: a separate process outside the file-attacker scope.

Research only. The fixture private key and history are outside the
simulated local attack directory, NOT secure against runner/root compromise.
No remote service, hardware, cloud, or paid API.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import socketserver
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

SCHEMA = "hg5.witness.current.v1"
POLICY_ID = "hg3-isolated-veth-network"


def canon(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def create_key(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    path = directory / "witness-private.hex"
    pub = directory / "witness-public.hex"
    if path.exists():
        raise ValueError("never replace an existing witness signing key")
    key = Ed25519PrivateKey.generate()
    path.write_text(key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption()).hex())
    path.chmod(0o600)
    pub.write_text(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex() + "\n")
    pub.chmod(0o644)


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        raw = self.rfile.readline(4096)
        try:
            request = json.loads(raw.decode())
            if set(request) != {"nonce", "policy_id"} or request["policy_id"] != POLICY_ID:
                return
            nonce = request["nonce"]
            if not isinstance(nonce, str) or len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
                return
            # Trusted owner process changes this file; simulated local attacker
            # cannot edit the trusted directory or witness process.
            policy = (self.server.trusted_dir / "current-policy.json").read_bytes()
            signed = json.loads(policy)
            if signed["policy_id"] != POLICY_ID:
                return
            t = time.time_ns()
            body = {"schema": SCHEMA, "policy_id": POLICY_ID, "nonce": nonce,
                    "version": signed["version"],
                    "policy_sha256": hashlib.sha256(policy).hexdigest(),
                    "issued_ns": t, "expires_ns": t + 1_500_000_000}
            response = {"body": body, "signature": self.server.key.sign(canon(body)).hex()}
            self.wfile.write(canon(response) + b"\n")
        except (ValueError, KeyError, OSError, TypeError, json.JSONDecodeError):
            return


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trusted", type=Path, required=True)
    parser.add_argument("--socket", type=Path, required=True)
    args = parser.parse_args()
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(
        (args.trusted/"witness-private.hex").read_text().strip()))
    args.socket.parent.mkdir(parents=True, exist_ok=True)
    if args.socket.exists():
        args.socket.unlink()
    with Server(str(args.socket), Handler) as s:
        s.trusted_dir = args.trusted
        s.key = key
        args.socket.chmod(0o666)  # simulated attacker can query, cannot sign
        print("WITNESS_READY " + str(args.socket), flush=True)
        s.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    main()
