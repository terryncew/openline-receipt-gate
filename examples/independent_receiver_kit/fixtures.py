"""Public, deterministic TEST-ONLY keys and independent receiver fixtures.

Every key in this module is public fixture material. Never use these keys for
an owner, worker, or receiver outside the local demonstration. The fixture
configuration exports public keys only; the local test receiver separately
holds ``OUTCOME`` when signing its outcomes.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import olp_canonical_json, public_key_hex
from olp_gate.mandate import MandateSpec
from olp_gate.mandate_owner import issue_mandate_authorization

from . import formats


T0 = 1792260000  # 2026-10-17T18:00:00Z, deterministic fixture clock only.


def key(seed_hexbyte: str) -> Ed25519PrivateKey:
    """Return a reproducible TEST-ONLY key from one repeated hexadecimal byte."""
    if not isinstance(seed_hexbyte, str) or len(seed_hexbyte) != 2:
        raise ValueError("test_key_seed_must_be_one_hex_byte")
    seed = bytes.fromhex(seed_hexbyte)
    if len(seed) != 1:
        raise ValueError("test_key_seed_must_be_one_hex_byte")
    return Ed25519PrivateKey.from_private_bytes(seed * 32)


OWNER = key("71")
A = key("72")
B = key("73")
OUTCOME = key("74")
ATTACKER = key("75")


def digest(value: Mapping[str, Any]) -> str:
    """Hash the same strict, integer-only canonical JSON used by the kit."""
    return hashlib.sha256(olp_canonical_json(dict(value))).hexdigest()


def _timestamp(epoch: int) -> datetime:
    return datetime.fromtimestamp(epoch, tz=timezone.utc)


def _mandate(worker: Ed25519PrivateKey, name: str) -> dict[str, Any]:
    return {
        "profile": "principal_mandate/v1",
        "mandate_id": f"mandate:worker-{name}",
        "principal_id": "owner:external",
        "agent_id": public_key_hex(worker),
        "purpose": "submit local document",
        "allowed_action_types": ["send"],
        "allowed_targets": ["records://local-lab/intake"],
        "allowed_disclosure_classes": [],
        "forbidden_disclosure_classes": [],
        "max_settlement_cents": 0,
        "max_payment_cents": 0,
        "delegation_allowed": False,
        "expires_at": _timestamp(T0 + 300).isoformat().replace("+00:00", "Z"),
        "version": "1",
    }


def _head_hash(mode: str, event: Mapping[str, Any]) -> str:
    if mode == "openline":
        return str(event["authorization"]["payload_hash"])
    if mode == "conventional":
        return hashlib.sha256(event["credential"].encode("utf-8")).hexdigest()
    raise ValueError("fixture_mode_invalid")


def fixture(mode: str = "openline") -> dict[str, Any]:
    """Issue equivalent owner-controlled A/revocation/B histories.

    Native records use Receipt Gate's existing owner authorization issuer.
    Conventional records use EdDSA JWT claims with the same owner, subjects,
    target, lifetime, sequence and predecessor constraints. This is an explicit
    comparison fixture, not a claim that Wallet exports either representation.
    """
    if mode not in {"openline", "conventional"}:
        raise ValueError("fixture_mode_invalid")
    config = {
        "receiver_id": "receiver:local-lab",
        "owner_id": "owner:external",
        "owner_key": public_key_hex(OWNER),
        "slot_id": "intake/default",
        "outcome_key": public_key_hex(OUTCOME),
        "policy": {
            "version": 1,
            "tool": "intake.submit",
            "target": "records://local-lab/intake",
            "max_document_chars": 128,
            "freshness_seconds": 60,
        },
    }
    events: list[dict[str, Any]] = []
    predecessor: str | None = None
    for sequence, name, worker, state, issued in (
        (1, "a", A, "ACTIVE", T0),
        (2, "a", A, "REVOKED", T0 + 10),
        (3, "b", B, "ACTIVE", T0 + 20),
    ):
        mandate = _mandate(worker, name)
        if mode == "openline":
            authorization = issue_mandate_authorization(
                slot_id=config["slot_id"],
                owner_id=config["owner_id"],
                mandate=mandate,
                state=state,
                sequence=sequence,
                predecessor_hash=predecessor,
                issued_at=_timestamp(issued),
                expires_at=_timestamp(T0 + 300),
                key=OWNER,
                authorization_id=f"head-{sequence}",
            )
            event = {"mandate": mandate, "authorization": authorization}
        else:
            claims = {
                "iss": config["owner_id"],
                "sub": public_key_hex(worker),
                "aud": config["receiver_id"],
                "iat": issued,
                "nbf": issued,
                "exp": T0 + 300,
                "jti": f"head-{sequence}",
                "seq": sequence,
                "prev": predecessor,
                "state": state,
                "scope": ["send"],
                "targets": list(mandate["allowed_targets"]),
                "mandate_id": mandate["mandate_id"],
                "purpose": mandate["purpose"],
                "mandate_hash": MandateSpec.from_mapping(mandate).mandate_hash,
            }
            event = {"credential": formats.encode_conventional_head(claims, OWNER)}
        events.append(event)
        predecessor = _head_hash(mode, event)
    return {
        "config": config,
        "events": events,
        "workers": {
            "a": "72" * 32,
            "b": "73" * 32,
        },
    }


def call(
    f: Mapping[str, Any],
    mode: str,
    worker: str = "a",
    at: int = T0,
    nonce: str = "nonce:local-call",
    record_id: str = "record:local-call",
    text: str = "hello",
    head_index: int | None = None,
) -> Any:
    """Sign one exact local call using the selected worker's public test key."""
    if worker not in {"a", "b"}:
        raise ValueError("fixture_worker_invalid")
    if mode not in {"openline", "conventional"}:
        raise ValueError("fixture_mode_invalid")
    worker_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(f["workers"][worker]))
    subject = public_key_hex(worker_key)
    selected = 0 if worker == "a" else 2
    event = f["events"][selected if head_index is None else head_index]
    mandate = _mandate(worker_key, worker)
    claims = {
        "iss": subject,
        "sub": subject,
        "aud": f["config"]["receiver_id"],
        "iat": at,
        "nbf": at,
        "exp": at + 30,
        "jti": nonce,
        "policy_hash": digest(f["config"]["policy"]),
        "head_hash": _head_hash(mode, event),
        "effect": {
            "profile": "principal_effect/v1",
            "effect_id": record_id,
            "mandate_id": mandate["mandate_id"],
            "principal_id": mandate["principal_id"],
            "agent_id": subject,
            "purpose": mandate["purpose"],
            "action_type": "send",
            "target": f["config"]["policy"]["target"],
            "disclosures": [],
            "value_cents": 0,
            "delegatee": None,
            "producer_model": f"Provider {worker.upper()} (simulated)",
        },
        "document": {"record_id": record_id, "text": text},
    }
    return formats.encode_call(mode, claims, worker_key)
