from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
from typing import Any

from olp_gate.authority_link import EVIDENCE_PROFILE, POLICY_PROFILE, PROPOSAL_PROFILE, effect_hash

NOW = datetime(2026, 8, 23, 20, 30, tzinfo=timezone.utc)
H = lambda value: hashlib.sha256(value.encode("utf-8")).hexdigest()

POLICY = {
    "profile": POLICY_PROFILE,
    "policy_id": "dpl002.receiver.settlement",
    "version": "1",
    "routes": [
        {
            "route_id": "immediate-tier1-settlement",
            "tool": "payments.settle_now",
            "target": "account:operating",
            "requirements": [
                {"requirement_id":"principal_mandate","kind":"authority","accepted_issuers":["receiver-mandate"],"max_age_seconds":86400,"independent_from_producer":True},
                {"requirement_id":"tier1_vendor","kind":"evidence","accepted_issuers":["vendor-registry"],"max_age_seconds":3600,"independent_from_producer":True},
                {"requirement_id":"liquidity_gt_50000","kind":"evidence","accepted_issuers":["treasury-ledger"],"max_age_seconds":60,"independent_from_producer":True},
                {"requirement_id":"invoice_open","kind":"evidence","accepted_issuers":["ap-ledger"],"max_age_seconds":300,"independent_from_producer":True},
            ],
            "unknown_behavior": "QUARANTINE",
            "max_authorization_ttl_seconds": 30,
        },
        {
            "route_id": "net30-settlement",
            "tool": "payments.schedule_net30",
            "target": "account:operating",
            "requirements": [
                {"requirement_id":"principal_mandate","kind":"authority","accepted_issuers":["receiver-mandate"],"max_age_seconds":86400,"independent_from_producer":True},
                {"requirement_id":"invoice_open","kind":"evidence","accepted_issuers":["ap-ledger"],"max_age_seconds":300,"independent_from_producer":True},
            ],
            "unknown_behavior": "QUARANTINE",
            "max_authorization_ttl_seconds": 30,
        },
    ],
}


def proposal(*, producer: str = "optimizer-A", model: str | None = None, advisory: str = "utility-99", vendor: str = "VENDOR-ALPHA", tier: int = 1, amount_cents: int = 500000, immediate: bool = True, state: str = "state-1") -> dict[str, Any]:
    tool = "payments.settle_now" if immediate else "payments.schedule_net30"
    timing = "immediate" if immediate else "net30"
    return {
        "profile": PROPOSAL_PROFILE,
        "proposal_id": f"{producer}:{vendor}:{timing}:{amount_cents}:{advisory}",
        "producer_id": producer,
        "producer_model": model or producer,
        "objective": "minimize settlement cost subject to principal mandate",
        "tool": tool,
        "target": "account:operating",
        "settings": {
            "vendor_id": vendor,
            "vendor_tier_claimed": tier,
            "invoice_id": "INV-2048",
            "amount_cents": amount_cents,
            "currency": "USD",
            "settlement_timing": timing,
        },
        "state_hash": H(state),
        "advisory_hash": H(advisory),
    }


def evidence(p: dict[str, Any], rid: str, kind: str, issuer: str, *, age: int = 5, verified: str = "VERIFIED", revoked: bool = False, subject: str | None = None) -> dict[str, Any]:
    return {
        "profile": EVIDENCE_PROFILE,
        "requirement_id": rid,
        "kind": kind,
        "subject_hash": subject or effect_hash(p),
        "issuer_id": issuer,
        "issued_at": (NOW - timedelta(seconds=age)).isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "artifact_hash": H(f"artifact:{rid}:{issuer}:{effect_hash(p)}:{age}"),
        "verification_receipt_hash": H(f"verify:{rid}:{issuer}:{effect_hash(p)}:{age}"),
        "receiver_verification_status": verified,
        "revoked": revoked,
    }


def evidence_for(p: dict[str, Any], *, tier1: bool = True, liquidity: bool = True, liquidity_age: int = 5, self_granted: bool = False, revoked_liquidity: bool = False) -> list[dict[str, Any]]:
    out = [
        evidence(p, "principal_mandate", "authority", "receiver-mandate"),
        evidence(p, "invoice_open", "evidence", "ap-ledger"),
    ]
    if p["tool"] == "payments.settle_now":
        if tier1:
            issuer = p["producer_id"] if self_granted else "vendor-registry"
            out.append(evidence(p, "tier1_vendor", "evidence", issuer))
        if liquidity:
            out.append(evidence(p, "liquidity_gt_50000", "evidence", "treasury-ledger", age=liquidity_age, revoked=revoked_liquidity))
    return out
