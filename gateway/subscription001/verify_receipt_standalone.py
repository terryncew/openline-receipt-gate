#!/usr/bin/env python3
"""Independently verify a gateway decision receipt.

Uses ONLY the receiver's public key and the receipt JSON — none of the
gateway's own code paths. An outside engineer can run this against the
receipt published by the demo to check it without trusting this repo's
server implementation.

Usage:
    python3 verify_receipt_standalone.py <receiver_pubkey_b64> <receipt.json>

Prints VALID or INVALID and exits 0/1.
"""

from __future__ import annotations

import base64
import json
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey)


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def main() -> int:
    if len(sys.argv) != 3:
        sys.exit("usage: verify_receipt_standalone.py "
                 "<receiver_pubkey_b64> <receipt.json>")
    pub = Ed25519PublicKey.from_public_bytes(b64u_decode(sys.argv[1]))
    receipt = json.loads(open(sys.argv[2]).read())
    sig = b64u_decode(receipt.pop("receiver_sig"))
    try:
        pub.verify(sig, canonical({k: receipt[k] for k in sorted(receipt)}))
    except Exception as exc:
        print(f"INVALID: {exc}")
        return 1
    print(f"VALID: receipt {receipt.get('receipt_id')} "
          f"decision={receipt.get('decision')} "
          f"agent={receipt.get('agent_id')} ts={receipt.get('ts')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
