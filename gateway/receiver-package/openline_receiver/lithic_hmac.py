"""Authenticate ASA bytes using Lithic's Standard Webhooks HMAC format.

The secret is the program's ASA secret from ``/v1/auth_stream/secret``,
not its API key or an unrelated event-subscription signing secret. Lithic's
official SDK v0.132.0 verifies ``webhook-id.webhook-timestamp.raw_body`` with
HMAC-SHA256 and Base64-encoded ``v1`` signatures. String secrets are Base64
decoded after removing an optional ``whsec_`` prefix. The SDK permits a
five-minute timestamp window and multiple space-separated signatures.

This small dependency-free verifier does no JSON parsing or serialization.
It deliberately requires canonical integer timestamps and rejects duplicate
case-insensitive authentication headers. Rotation keys must be explicitly
configured; callers must remove the retired key when Lithic retires it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import math
import re
import time
from collections.abc import Mapping, Sequence


class LithicAuthenticationError(ValueError):
    """The request or ASA signing configuration cannot be authenticated."""


def decode_asa_secret(secret: str) -> bytes:
    """Decode the actual Base64 ASA secret, including an optional whsec_ prefix."""
    if not isinstance(secret, str) or not secret:
        raise LithicAuthenticationError("ASA signing secret is required")
    encoded = secret.removeprefix("whsec_")
    try:
        key = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise LithicAuthenticationError("ASA signing secret must be Base64") from exc
    if not key:
        raise LithicAuthenticationError("ASA signing secret is empty")
    return key


def verify_lithic_hmac(
    raw_body: bytes,
    headers: Mapping[str, str],
    secrets: str | Sequence[str],
    *,
    now: float | None = None,
    tolerance_seconds: int = 300,
) -> None:
    """Raise on authentication failure; never authenticate a reserialized body.

    ``secrets`` contains the current ASA signing secret and, only during the
    rotation interval, an explicitly retained previous secret. Any configured
    key may match any supported v1 signature. Invalid or missing configuration
    always fails closed. ``now`` is an injected clock for deterministic tests.
    """
    if not isinstance(raw_body, bytes):
        raise LithicAuthenticationError("Original raw request bytes are required")
    if not isinstance(tolerance_seconds, int) or isinstance(tolerance_seconds, bool) or not 0 <= tolerance_seconds <= 300:
        raise LithicAuthenticationError("Timestamp tolerance must be at most 300 seconds")
    if isinstance(secrets, str):
        secrets = (secrets,)
    if not isinstance(secrets, Sequence) or not secrets:
        raise LithicAuthenticationError("ASA signing secret is required")
    keys = [decode_asa_secret(secret) for secret in secrets]
    required = {"webhook-id", "webhook-timestamp", "webhook-signature"}
    values: dict[str, str] = {}
    if not isinstance(headers, Mapping):
        raise LithicAuthenticationError("Authentication headers are required")
    for name, value in headers.items():
        if not isinstance(name, str):
            raise LithicAuthenticationError("Invalid authentication headers")
        normalized = name.lower()
        if normalized in required:
            if normalized in values or not isinstance(value, str) or not value:
                raise LithicAuthenticationError("Duplicate or invalid authentication headers")
            values[normalized] = value
    if values.keys() != required:
        raise LithicAuthenticationError("Missing authentication headers")
    message_id = values["webhook-id"]
    timestamp_text = values["webhook-timestamp"]
    if not re.fullmatch(r"[\x21-\x7e]{1,512}", message_id):
        raise LithicAuthenticationError("Invalid webhook ID")
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", timestamp_text):
        raise LithicAuthenticationError("Invalid webhook timestamp")
    timestamp = int(timestamp_text)
    current = time.time() if now is None else now
    if not isinstance(current, (int, float)) or not math.isfinite(current):
        raise LithicAuthenticationError("Invalid verification clock")
    if timestamp < current - tolerance_seconds or timestamp > current + tolerance_seconds:
        raise LithicAuthenticationError("Webhook timestamp is outside the allowed window")
    signed_bytes = message_id.encode("ascii") + b"." + timestamp_text.encode("ascii") + b"." + raw_body
    expected = [hmac.new(key, signed_bytes, hashlib.sha256).digest() for key in keys]
    candidates = values["webhook-signature"].split()
    if len(candidates) > 32:
        raise LithicAuthenticationError("Too many webhook signatures")
    for candidate in candidates:
        version, separator, encoded = candidate.partition(",")
        if not separator or version != "v1":
            continue
        try:
            signature = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            continue
        if len(signature) == hashlib.sha256().digest_size:
            for digest in expected:
                if hmac.compare_digest(digest, signature):
                    return
    raise LithicAuthenticationError("No matching ASA signature")
