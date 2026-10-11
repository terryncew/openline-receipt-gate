#!/usr/bin/env python3
"""Verify an exported JSONL receipt log using only a receiver public key.

This verifier deliberately imports no Gateway code and never opens its DB
or private key. Export public evidence inside the trusted environment, then
run ``python3 gateway/ci/verify_receipt_export.py --public-key receiver.pubkey
--receipts receipts.jsonl``. Any invalid, duplicate, malformed, or empty log
fails. Public keys use the Gateway's unpadded base64url encoding.
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def decode(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4),
                            altchars=b"-_", validate=True)


def verify(public_key: str, receipts: list[dict]) -> dict:
    pub = Ed25519PublicKey.from_public_bytes(decode(public_key.strip()))
    seen = set()
    valid, errors = 0, []
    for index, original in enumerate(receipts, 1):
        try:
            receipt = dict(original)
            signature = decode(receipt.pop("receiver_sig"))
            identifier = receipt["receipt_id"]
            if not isinstance(identifier, str) or not identifier:
                raise ValueError("missing receipt identifier")
            if identifier in seen:
                raise ValueError("duplicate receipt identifier")
            seen.add(identifier)
            message = json.dumps(receipt, sort_keys=True,
                                 separators=(",", ":")).encode()
            pub.verify(signature, message)
            valid += 1
        except Exception as exc:
            errors.append({"line": index, "error": type(exc).__name__})
    if not receipts:
        errors.append({"line": 0, "error": "empty_receipt_export"})
    return {"valid": valid, "invalid": len(errors), "total": len(receipts),
            "errors": errors}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipts = [json.loads(line) for line in args.receipts.read_text()
                    .splitlines() if line.strip()]
        result = verify(args.public_key.read_text(), receipts)
    except Exception as exc:
        result = {"valid": 0, "invalid": 1, "total": 0,
                  "errors": [{"line": 0, "error": type(exc).__name__}]}
    print(json.dumps(result, sort_keys=True))
    return 1 if result["invalid"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
