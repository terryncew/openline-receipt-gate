"""Local fixture codecs for the independent receiver example.

The native owner authorization is an existing Receipt Gate format. The worker
call below is an example-specific signed envelope, not a new OpenLine protocol.
The conventional arm uses compact EdDSA JWTs with independently pinned keys.
Neither codec decides whether a head is the latest: the receiver owns that
durable, transactional frontier and its freshness policy.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import re
from typing import Any, Mapping

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from olp_gate.crypto import (
    MAX_SAFE_INTEGER,
    olp_canonical_json,
    sign_olp_body,
    strict_json_loads,
    verify_olp_signature,
)
from olp_gate.mandate import MandateSpec, assess_effect, validate_effect
from olp_gate.mandate_owner import validate_mandate_authorization


CALL_SCHEMA = "receiver-kit-call/v1"
_COMMON = {"iss", "sub", "aud", "iat", "nbf", "exp", "jti"}
_HEAD = _COMMON | {
    "seq", "prev", "state", "scope", "targets", "mandate_id", "purpose",
    "mandate_hash",
}
_CALL = _COMMON | {"policy_hash", "head_hash", "effect", "document"}
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_SEGMENT = re.compile(r"[A-Za-z0-9_-]+\Z")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label}_not_object")
    # This also rejects floats, unsafe integers and non-ASCII object keys.
    return strict_json_loads(olp_canonical_json(dict(value)).decode("ascii"))


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError(f"{label}_invalid")
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HEX.fullmatch(value) is None:
        raise ValueError(f"{label}_invalid")
    return value


def _integer(value: Any, label: str) -> int:
    if (not isinstance(value, int) or isinstance(value, bool)
            or not 0 <= value <= MAX_SAFE_INTEGER):
        raise ValueError(f"{label}_invalid")
    return value


def _mode(mode: str) -> None:
    if mode not in {"openline", "conventional"}:
        raise ValueError("mode_invalid")


def _time(at: int) -> datetime:
    return datetime.fromtimestamp(_integer(at, "receiver_time"), timezone.utc)


def _epoch(value: str) -> int:
    timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError("timestamp_timezone_required")
    # Flooring expiry is conservative; owner validation above uses exact time.
    return _integer(int(timestamp.timestamp()), "timestamp")


def _times(claims: Mapping[str, Any], at: int) -> None:
    now = _integer(at, "receiver_time")
    issued = _integer(claims.get("iat"), "iat")
    not_before = _integer(claims.get("nbf"), "nbf")
    expires = _integer(claims.get("exp"), "exp")
    if expires <= max(issued, not_before):
        raise ValueError("credential_lifetime_invalid")
    if issued > now:
        raise ValueError("credential_from_future")
    if not_before > now:
        raise ValueError("credential_not_yet_valid")
    if expires <= now:
        raise ValueError("credential_expired")


def _jwt_decode(token: Any, *, public_key: str, issuer: str,
                audience: str, at: int) -> dict[str, Any]:
    if not isinstance(token, str):
        raise ValueError("jwt_not_text")
    segments = token.split(".")
    if len(segments) != 3 or any(_SEGMENT.fullmatch(s) is None for s in segments):
        raise ValueError("jwt_compact_invalid")
    # PyJWT verifies the compact signing input. Inspect its JSON independently
    # first so duplicate keys cannot acquire parser-dependent meanings.
    decoded = []
    for segment in segments[:2]:
        try:
            raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
            if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != segment:
                raise ValueError("jwt_encoding_noncanonical")
            decoded.append(strict_json_loads(raw.decode("utf-8")))
        except (ValueError, UnicodeError) as exc:
            raise ValueError("jwt_json_invalid") from exc
    header, payload = decoded
    if header != {"alg": "EdDSA", "typ": "JWT"}:
        raise ValueError("jwt_header_invalid")
    payload = _object(payload, "jwt_claims")
    try:
        claims = jwt.decode(
            token,
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(_hash(public_key, "signer_key"))),
            algorithms=["EdDSA"], issuer=issuer, audience=audience,
            options={"require": sorted(_COMMON), "verify_exp": False,
                     "verify_iat": False, "verify_nbf": False,
                     "strict_aud": True},
        )
    except jwt.PyJWTError as exc:
        raise ValueError(f"jwt_invalid:{type(exc).__name__}") from exc
    if claims != payload:
        raise ValueError("jwt_parser_disagreement")
    if claims.get("iss") != issuer or claims.get("aud") != audience:
        raise ValueError("credential_issuer_or_audience_mismatch")
    for key in ("iss", "sub", "aud", "jti"):
        _text(claims.get(key), key)
    _times(claims, at)
    return claims


def _jwt_encode(claims: Mapping[str, Any], key: Any) -> str:
    return jwt.encode(_object(claims, "jwt_claims"), key, algorithm="EdDSA",
                      headers={"typ": "JWT"})


def parse_head(mode: str, packet: Mapping[str, Any],
               config: Mapping[str, Any], at: int) -> dict[str, Any]:
    """Verify externally supplied authority; do not install it or assert latest."""
    _mode(mode)
    item = _object(packet, "head_packet")
    if mode == "openline":
        if set(item) != {"mandate", "authorization"}:
            raise ValueError("head_packet_shape_invalid")
        authorization = validate_mandate_authorization(
            item["authorization"], expected_slot_id=config["slot_id"],
            expected_owner_id=config["owner_id"],
            expected_public_key=config["owner_key"], now=_time(at),
        )
        mandate = MandateSpec.from_mapping(item["mandate"])
        if mandate.principal_id != config["owner_id"]:
            raise ValueError("mandate_principal_owner_mismatch")
        if mandate.mandate_hash != authorization["mandate_hash"]:
            raise ValueError("mandate_authorization_hash_mismatch")
        expires = min(_epoch(authorization["expires_at"]), _epoch(mandate.expires_at))
        if expires <= at:
            raise ValueError("mandate_expired")
        return {
            "hash": authorization["payload_hash"], "seq": authorization["sequence"],
            "prev": authorization["predecessor_hash"], "state": authorization["state"],
            "issued": _epoch(authorization["issued_at"]), "expires": expires,
            "subject": _hash(mandate.agent_id, "mandate_worker_key"),
            "scope": sorted(mandate.allowed_action_types),
            "targets": sorted(mandate.allowed_targets), "mandate_id": mandate.mandate_id,
            "purpose": mandate.purpose, "principal": mandate.principal_id,
            "mandate_hash": mandate.mandate_hash,
        }
    if set(item) != {"credential"}:
        raise ValueError("head_packet_shape_invalid")
    claims = _jwt_decode(item["credential"], public_key=config["owner_key"],
                         issuer=config["owner_id"], audience=config["receiver_id"], at=at)
    if set(claims) != _HEAD:
        raise ValueError("head_claims_shape_invalid")
    sequence = _integer(claims["seq"], "head_sequence")
    if sequence < 1:
        raise ValueError("head_sequence_invalid")
    previous = claims["prev"]
    if previous is not None:
        _hash(previous, "head_predecessor")
    if claims["state"] not in {"ACTIVE", "REVOKED"}:
        raise ValueError("head_state_invalid")
    for name in ("scope", "targets"):
        values = claims[name]
        if (not isinstance(values, list) or any(not isinstance(v, str) or not v for v in values)
                or len(set(values)) != len(values)):
            raise ValueError(f"head_{name}_invalid")
    # Keep the conventional action vocabulary equal to the native mandate.
    if not set(claims["scope"]) <= {
        "inspect", "draft", "send", "accept_settlement", "authorize_payment", "delegate"
    }:
        raise ValueError("head_scope_invalid")
    return {
        "hash": hashlib.sha256(item["credential"].encode("ascii")).hexdigest(),
        "seq": sequence, "prev": previous, "state": claims["state"],
        "issued": claims["iat"], "expires": claims["exp"],
        "subject": _hash(claims["sub"], "mandate_worker_key"),
        "scope": sorted(claims["scope"]), "targets": sorted(claims["targets"]),
        "mandate_id": _text(claims["mandate_id"], "mandate_id"),
        "purpose": _text(claims["purpose"], "purpose"), "principal": claims["iss"],
        "mandate_hash": _hash(claims["mandate_hash"], "mandate_hash"),
    }


def assess(mode: str, packet: Mapping[str, Any], effect: Mapping[str, Any],
           at: int) -> list[str]:
    """Check effect scope; receiver separately enforces standing and fixed tool."""
    _mode(mode)
    if mode == "openline":
        return assess_effect(packet["mandate"], effect, now=_time(at))["reason_codes"]
    effect = validate_effect(_object(effect, "effect"))
    # Signature validation is parse_head's responsibility. This routine is also
    # useful to the independent verifier after it verifies that exact packet.
    token = packet["credential"]
    payload_segment = token.split(".")[1]
    payload = strict_json_loads(base64.urlsafe_b64decode(
        payload_segment + "=" * (-len(payload_segment) % 4)).decode("utf-8"))
    reasons = []
    for name, expected in {
        "principal_id": payload["iss"], "agent_id": payload["sub"],
        "mandate_id": payload["mandate_id"], "purpose": payload["purpose"],
    }.items():
        if effect[name] != expected:
            reasons.append(f"{name}_mismatch")
    if effect["action_type"] not in payload["scope"]:
        reasons.append("action_not_allowed")
    if payload["targets"] and effect["target"] not in payload["targets"]:
        reasons.append("target_not_allowed")
    # This conventional descriptor supports only this example's no-money,
    # no-disclosure, no-delegation record submission, matching its fixtures.
    if effect["action_type"] != "send":
        reasons.append("fixture_action_not_send")
    if effect["value_cents"] != 0:
        reasons.append("fixture_money_forbidden")
    if effect["disclosures"]:
        reasons.append("fixture_disclosures_forbidden")
    if effect["delegatee"] is not None:
        reasons.append("unexpected_delegatee")
    if payload["exp"] <= at:
        reasons.append("mandate_expired")
    return sorted(set(reasons))


def decode_call(mode: str, token: Any, subject: str,
                config: Mapping[str, Any], at: int) -> dict[str, Any]:
    """Authenticate worker possession and return the identical common claims."""
    _mode(mode)
    _hash(subject, "worker_key")
    if mode == "conventional":
        claims = _jwt_decode(token, public_key=subject, issuer=subject,
                             audience=config["receiver_id"], at=at)
        if set(claims) != _CALL:
            raise ValueError("call_shape_invalid")
    else:
        signed = _object(token, "call")
        if set(signed) != _CALL | {"schema", "payload_hash", "signature"}:
            raise ValueError("call_shape_invalid")
        if signed["schema"] != CALL_SCHEMA:
            raise ValueError("call_schema_invalid")
        signature = signed["signature"]
        if (not isinstance(signature, dict)
                or set(signature) != {"algorithm", "public_key", "value"}
                or signature["public_key"] != subject):
            raise ValueError("call_worker_key_mismatch")
        valid, reason = verify_olp_signature(signed)
        if not valid:
            raise ValueError(f"call_signature_invalid:{reason}")
        claims = {name: signed[name] for name in _CALL}
        _times(claims, at)
    if claims["iss"] != subject or claims["sub"] != subject:
        raise ValueError("call_subject_mismatch")
    if claims["aud"] != config["receiver_id"]:
        raise ValueError("call_audience_mismatch")
    for name in ("iss", "sub", "aud", "jti"):
        _text(claims[name], name)
    for name in ("policy_hash", "head_hash"):
        _hash(claims[name], name)
    claims["effect"] = validate_effect(_object(claims["effect"], "effect"))
    document = _object(claims["document"], "document")
    if (set(document) != {"record_id", "text"}
            or not isinstance(document["record_id"], str) or not document["record_id"]
            or not isinstance(document["text"], str)):
        raise ValueError("document_invalid")
    claims["document"] = document
    return claims


def encode_call(mode: str, claims: Mapping[str, Any], key: Any) -> Any:
    """Fixture helper; the receiver never receives the worker private key."""
    _mode(mode)
    item = _object(claims, "call_claims")
    if set(item) != _CALL:
        raise ValueError("call_shape_invalid")
    return (sign_olp_body({"schema": CALL_SCHEMA, **item}, key)
            if mode == "openline" else _jwt_encode(item, key))


def encode_conventional_head(claims: Mapping[str, Any], key: Any) -> str:
    """Fixture helper for an external conventional owner issuer."""
    if set(claims) != _HEAD:
        raise ValueError("head_claims_shape_invalid")
    return _jwt_encode(claims, key)
