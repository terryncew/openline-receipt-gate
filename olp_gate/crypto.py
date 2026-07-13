"""Cryptographic helpers for proof-to-policy receipts.

The legacy v0.1 JSONL chain remains in :mod:`olp_gate.receipts`.  This module
implements the stronger v0.2 boundary: strict parsing, OLP integer-canonical
JSON, the integer-only portion of RFC 8785 used by Agent Receipts, and Ed25519
signing/verification.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


MAX_SAFE_INTEGER = (1 << 53) - 1
OLP_CANONICALIZATION_ID = "olp-canonical-json-int-v1"


class DuplicateKeyError(ValueError):
    """Raised when JSON input contains a duplicate object key."""


class UnsupportedCanonicalValue(ValueError):
    """Raised when a value is outside a supported canonicalization profile."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json_loads(text: str) -> Any:
    """Parse JSON while rejecting duplicate keys and non-finite numbers."""

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    return json.loads(
        text,
        object_pairs_hook=_strict_object,
        parse_constant=reject_constant,
    )


def strict_json_load(path: str | Path) -> Any:
    return strict_json_loads(Path(path).read_text(encoding="utf-8"))


def _validate_olp(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_SAFE_INTEGER:
            raise UnsupportedCanonicalValue(f"{path}: integer outside interoperable range")
        return
    if isinstance(value, float):
        raise UnsupportedCanonicalValue(f"{path}: floats are forbidden")
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_olp(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or not key.isascii():
                raise UnsupportedCanonicalValue(f"{path}: keys must be ASCII strings")
            _validate_olp(item, f"{path}.{key}")
        return
    raise UnsupportedCanonicalValue(f"{path}: unsupported {type(value).__name__}")


def olp_canonical_json(value: Any) -> bytes:
    """Return bytes for ``olp-canonical-json-int-v1``."""

    _validate_olp(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _utf16_sort_key(value: str) -> bytes:
    try:
        return value.encode("utf-16be")
    except UnicodeEncodeError as exc:
        raise UnsupportedCanonicalValue("unpaired Unicode surrogate") from exc


def _validate_jcs_subset(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str):
            _utf16_sort_key(value)
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > MAX_SAFE_INTEGER:
            raise UnsupportedCanonicalValue(f"{path}: integer outside RFC 8785 exact range")
        return
    if isinstance(value, float):
        # RFC 8785 supports IEEE-754 numbers, but Python's serializer does not
        # reproduce ECMAScript formatting for every edge case.  Refusing the
        # value is safer than returning a false signature failure.
        raise UnsupportedCanonicalValue(f"{path}: floating-point JCS needs a full RFC 8785 backend")
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_jcs_subset(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise UnsupportedCanonicalValue(f"{path}: object key is not a string")
            _utf16_sort_key(key)
            _validate_jcs_subset(item, f"{path}.{key}")
        return
    raise UnsupportedCanonicalValue(f"{path}: unsupported {type(value).__name__}")


def jcs_integer_canonical_json(value: Any) -> bytes:
    """Canonicalize the integer-only Agent Receipts/RFC 8785 wire subset.

    Agent Receipts v0.5 fields are strings, booleans, nulls, arrays, objects,
    and interoperable integers.  A receipt containing a float is reported as
    unsupported instead of being misclassified as a bad signature.
    """

    _validate_jcs_subset(value)

    def encode(item: Any) -> str:
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, int) and not isinstance(item, bool):
            return str(item)
        if isinstance(item, str):
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if isinstance(item, (list, tuple)):
            return "[" + ",".join(encode(value) for value in item) + "]"
        if isinstance(item, Mapping):
            keys = sorted(item, key=_utf16_sort_key)
            return "{" + ",".join(
                json.dumps(key, ensure_ascii=False) + ":" + encode(item[key]) for key in keys
            ) + "}"
        raise UnsupportedCanonicalValue(f"unsupported {type(item).__name__}")

    return encode(value).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def public_key_hex(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    public = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def sign_olp_body(body: Mapping[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    if "payload_hash" in body or "signature" in body:
        raise ValueError("signed body must not contain payload_hash or signature")
    canonical = olp_canonical_json(dict(body))
    return {
        **dict(body),
        "payload_hash": sha256_hex(canonical),
        "signature": {
            "algorithm": "Ed25519",
            "public_key": public_key_hex(key),
            "value": key.sign(canonical).hex(),
        },
    }


def verify_olp_signature(receipt: Mapping[str, Any]) -> tuple[bool, str | None]:
    try:
        body = dict(receipt)
        signature = body.pop("signature")
        payload_hash = body.pop("payload_hash")
        if not isinstance(signature, Mapping) or signature.get("algorithm") != "Ed25519":
            return False, "unsupported_signature_algorithm"
        canonical = olp_canonical_json(body)
        if payload_hash != sha256_hex(canonical):
            return False, "payload_hash_mismatch"
        public = bytes.fromhex(str(signature["public_key"]))
        value = bytes.fromhex(str(signature["value"]))
        if len(public) != 32 or len(value) != 64:
            return False, "invalid_signature_encoding"
        Ed25519PublicKey.from_public_bytes(public).verify(value, canonical)
        return True, None
    except UnsupportedCanonicalValue:
        return False, "canonicalization_unsupported"
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False, "signature_invalid"


def _decode_u_base64url(value: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("u"):
        raise ValueError("expected u-prefixed base64url")
    encoded = value[1:]
    padding = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(encoded + padding)


_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58btc_decode(value: str) -> bytes:
    if not value.startswith("z"):
        raise ValueError("did:key must use base58btc multibase")
    number = 0
    for char in value[1:]:
        number = number * 58 + _BASE58_ALPHABET.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zeroes = len(value[1:]) - len(value[1:].lstrip("1"))
    return b"\x00" * zeroes + raw


def did_key_ed25519_public_bytes(verification_method: str) -> bytes:
    did = verification_method.split("#", 1)[0]
    if not did.startswith("did:key:"):
        raise ValueError("unsupported verification method")
    decoded = _base58btc_decode(did[len("did:key:"):])
    if not decoded.startswith(b"\xed\x01") or len(decoded) != 34:
        raise ValueError("verification method is not Ed25519 did:key")
    return decoded[2:]


def resolve_agent_receipt_key(
    verification_method: str,
    trusted_key: str | bytes | None = None,
) -> bytes:
    if trusted_key is not None:
        if isinstance(trusted_key, bytes):
            raw = trusted_key
        else:
            candidate = trusted_key.removeprefix("ed25519:")
            try:
                raw = bytes.fromhex(candidate)
            except ValueError:
                padding = "=" * (-len(candidate) % 4)
                raw = base64.urlsafe_b64decode(candidate + padding)
        if len(raw) != 32:
            raise ValueError("trusted Ed25519 key must be 32 bytes")
        return raw
    return did_key_ed25519_public_bytes(verification_method)


def verify_agent_receipt_signature(
    receipt: Mapping[str, Any],
    trusted_key: str | bytes | None = None,
) -> tuple[bool | None, str | None, str | None]:
    """Verify an Agent Receipts v0.1-v0.5 embedded Ed25519 proof.

    Returns ``(valid, reason, verification_method)``.  ``valid is None`` means
    verification could not be performed, which is different from a bad proof.
    """

    try:
        proof = receipt.get("proof")
        if not isinstance(proof, Mapping):
            return False, "proof_missing", None
        if proof.get("type") != "Ed25519Signature2020":
            return None, "unsupported_agent_receipt_proof", str(proof.get("verificationMethod", ""))
        method = str(proof["verificationMethod"])
        body = dict(receipt)
        body.pop("proof")
        canonical = jcs_integer_canonical_json(body)
        signature = _decode_u_base64url(str(proof["proofValue"]))
        if len(signature) != 64:
            return False, "invalid_signature_encoding", method
        try:
            public = resolve_agent_receipt_key(method, trusted_key)
        except ValueError:
            return None, "verification_key_unavailable", method
        Ed25519PublicKey.from_public_bytes(public).verify(signature, canonical)
        return True, None, method
    except UnsupportedCanonicalValue:
        return None, "canonicalization_unsupported", None
    except InvalidSignature:
        return False, "signature_invalid", str(receipt.get("proof", {}).get("verificationMethod", ""))
    except (KeyError, TypeError, ValueError):
        return False, "malformed_agent_receipt", None


def generate_private_key_file(path: str | Path) -> str:
    target = Path(path)
    if target.exists():
        raise FileExistsError(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(raw.hex() + "\n")
    return public_key_hex(key)


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    target = Path(path)
    mode = target.stat().st_mode & 0o777
    if mode & 0o077:
        raise PermissionError(f"private key must not be group/world accessible: {oct(mode)}")
    raw = bytes.fromhex(target.read_text(encoding="ascii").strip())
    if len(raw) != 32:
        raise ValueError("private key must contain 32-byte lowercase hex")
    return Ed25519PrivateKey.from_private_bytes(raw)
