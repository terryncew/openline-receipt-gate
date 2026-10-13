"""Boundary 1 — receiver-owned AI action authority (offline simulation).

The Receiver holds:
  * the registry of the owner's Ed25519 public key (trust root for mandates),
  * the revocation list,
  * the nonce replay cache,
  * its own Ed25519 key used to sign every decision receipt.

The assistant never holds a device credential. A device executes an action
only when presented with a Receiver-signed ALLOW decision receipt bound to
the exact (device, action, params) triple and a fresh nonce. DENY means no
effect, by construction: there is no other code path to a device effect.

Receipts reuse openline-receipt-gate's OLP signing contract
(olp_gate.crypto.sign_olp_body / verify_olp_signature).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import sign_olp_body, verify_olp_signature
from olp_gate.receipts import sha256_json

from . import keys

MANDATE_SCHEMA = "openline.home_guard.mandate.v1"
DECISION_SCHEMA = "openline.home_guard.decision.v1"
REVOCATION_SCHEMA = "openline.home_guard.revocation.v1"


class FixedClock:
    """Deterministic clock for frozen tests. `now()` returns fixed ISO text."""

    def __init__(self, fixed: str = "2026-10-13T09:39:55-07:00"):
        self.fixed = fixed

    def now(self) -> str:
        return self.fixed


@dataclass
class Mandate:
    """Owner-signed grant of scoped actions to one assistant identity."""

    mandate_id: str
    grantee_pub: str
    scope: list[dict[str, str]]  # [{device, action}, ...]
    issued_at: str
    expires_at: str
    signed: Mapping[str, Any] = field(repr=False)

    @staticmethod
    def issue(
        mandate_id: str,
        grantee_name: str,
        scope: list[dict[str, str]],
        issued_at: str,
        expires_at: str,
    ) -> "Mandate":
        owner_key = keys.private_key("owner")
        body = {
            "schema": MANDATE_SCHEMA,
            "mandate_id": mandate_id,
            "grantee_pub": keys.public_key_hex_of(grantee_name),
            "scope": scope,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        signed = sign_olp_body(body, owner_key)
        return Mandate(mandate_id, keys.public_key_hex_of(grantee_name), scope,
                       issued_at, expires_at, signed)


@dataclass
class Proposal:
    mandate_id: str
    device: str
    action: str
    params: Mapping[str, Any]
    nonce: str
    proposed_at: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "mandate_id": self.mandate_id,
            "device": self.device,
            "action": self.action,
            "params": dict(self.params),
            "nonce": self.nonce,
            "proposed_at": self.proposed_at,
        }


class HomeGuardReceiver:
    """Evaluates assistant proposals against admitted mandates; signs decisions."""

    def __init__(self, owner_pub: str, clock: FixedClock | None = None):
        self.owner_pub = owner_pub
        self.clock = clock or FixedClock()
        self._key: Ed25519PrivateKey = keys.private_key("receiver")
        self.mandates: dict[str, Mandate] = {}
        self.revoked: dict[str, dict[str, Any]] = {}
        self.seen_nonces: set[str] = set()
        self.decisions: list[Mapping[str, Any]] = []

    @property
    def public_key_hex(self) -> str:
        return keys.public_key_hex_of("receiver")

    # -- mandate lifecycle -------------------------------------------------
    def admit_mandate(self, signed_mandate: Mapping[str, Any]) -> Mandate:
        ok, reason = verify_olp_signature(signed_mandate)
        if not ok:
            raise ValueError(f"mandate signature invalid: {reason}")
        body = dict(signed_mandate)
        sig = body.get("signature", {})
        if sig.get("public_key") != self.owner_pub:
            raise ValueError("mandate not signed by registered owner")
        if body.get("schema") != MANDATE_SCHEMA:
            raise ValueError("unexpected mandate schema")
        if body.get("expires_at", "") <= self.clock.now():
            raise ValueError("mandate expired at admission")
        m = Mandate(
            mandate_id=body["mandate_id"],
            grantee_pub=body["grantee_pub"],
            scope=body["scope"],
            issued_at=body["issued_at"],
            expires_at=body["expires_at"],
            signed=signed_mandate,
        )
        self.mandates[m.mandate_id] = m
        return m

    def revoke(self, mandate_id: str, reason: str = "owner_revoked") -> Mapping[str, Any]:
        record = sign_olp_body(
            {
                "schema": REVOCATION_SCHEMA,
                "mandate_id": mandate_id,
                "reason": reason,
                "revoked_at": self.clock.now(),
            },
            self._key,
        )
        self.revoked[mandate_id] = record
        return record

    # -- authorization ------------------------------------------------------
    def authorize(self, proposal: Proposal) -> Mapping[str, Any]:
        p = proposal.as_dict()
        decision, reason = self._evaluate(p)
        body = {
            "schema": DECISION_SCHEMA,
            "decision": decision,
            "reason_code": reason,
            "mandate_id": p["mandate_id"],
            "device": p["device"],
            "action": p["action"],
            "params_sha256": sha256_json(p["params"]),
            "proposal_sha256": sha256_json(p),
            "nonce": p["nonce"],
            "decided_at": self.clock.now(),
        }
        receipt = sign_olp_body(body, self._key)
        if decision == "ALLOW":
            self.seen_nonces.add(p["nonce"])
        self.decisions.append(receipt)
        return receipt

    def _evaluate(self, p: dict[str, Any]) -> tuple[str, str]:
        m = self.mandates.get(p["mandate_id"])
        if m is None:
            return "DENY", "unknown_mandate"
        if p["mandate_id"] in self.revoked:
            return "DENY", "mandate_revoked"
        if m.expires_at <= self.clock.now():
            return "DENY", "mandate_expired"
        if not any(s["device"] == p["device"] and s["action"] == p["action"]
                   for s in m.scope):
            return "DENY", "not_in_mandate_scope"
        if p["nonce"] in self.seen_nonces:
            return "DENY", "replay_nonce"
        return "ALLOW", "in_scope"

    def verify_decision(self, receipt: Mapping[str, Any]) -> tuple[bool, str | None]:
        ok, reason = verify_olp_signature(receipt)
        if not ok:
            return False, reason
        if receipt.get("signature", {}).get("public_key") != self.public_key_hex:
            return False, "untrusted_signer"
        return True, None
