"""Verify public pilot receipts against a separately supplied trusted key.

This verifier imports neither the adapter nor Wallet/Gateway verification code.
It proves receipt signatures, not settlement or an external payment effect.
"""
import argparse
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--pinned-public-key", type=Path, required=True)
    arguments = parser.parse_args()
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(arguments.pinned_public_key.read_text().strip()))
    evidence = json.loads(arguments.evidence.read_text())
    receipts = evidence["receipts"]
    if len(receipts) != 3:
        raise ValueError("Expected three nonempty pilot sequence receipts")
    for receipt in receipts:
        signature = receipt["signature"]
        if signature.get("algorithm") != "Ed25519":
            raise ValueError("Unsupported signature algorithm")
        body = {k: v for k, v in receipt.items() if k not in {"payload_hash", "signature"}}
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
        if hashlib.sha256(encoded).hexdigest() != receipt["payload_hash"]:
            raise ValueError("Receipt hash mismatch")
        key.verify(bytes.fromhex(signature["value"]), encoded)
    results = [receipt["result"] for receipt in receipts]
    if results != ["APPROVED", "CARD_PAUSED", "APPROVED"]:
        raise ValueError("Unexpected pilot sequence")
    print(json.dumps({"result": "PASS", "independently_verified_receipts": len(receipts),
                      "decision_sequence": results, "key_source": "explicit independent pin file; embedded receipt keys not trusted"}))


if __name__ == "__main__":
    main()
