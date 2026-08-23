"""Strong capability-control baseline for DPL-002.

This is intentionally not toy RBAC.  It models a receiver-issued bearer
capability with exact-effect binding, state binding, expiry, one-use replay
protection, and third-party discharge-style evidence caveats.  If this control
matches DPL across the hostile matrix, the experiment's strong falsifier fires.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import secrets
from typing import Any, Mapping, Sequence

from olp_gate.authority_link import (
    canonical_hash,
    canonical_json,
    effect_binding,
    evidence_hash,
    validate_evidence,
    validate_policy,
    validate_proposal,
)

CHALLENGE_PROFILE = "caveated_capability_challenge/v1"
TOKEN_PROFILE = "caveated_capability_token/v1"


class CapabilityError(ValueError):
    pass


def _parse_time(value: str) -> datetime:
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(candidate)
    if parsed.tzinfo is None:
        raise CapabilityError("timestamp_timezone_required")
    return parsed.astimezone(timezone.utc)


def _route_for(policy: Mapping[str, Any], proposal: Mapping[str, Any]) -> dict[str, Any] | None:
    pol = validate_policy(policy)
    prop = validate_proposal(proposal)
    matches = [
        route for route in pol["routes"]
        if route["tool"] == prop["tool"] and route["target"] == prop["target"]
    ]
    if len(matches) > 1:
        raise CapabilityError("capability_route_ambiguous")
    return matches[0] if matches else None


def compile_challenge(policy: Mapping[str, Any], proposal: Mapping[str, Any]) -> dict[str, Any]:
    pol = validate_policy(policy)
    prop = validate_proposal(proposal)
    route = _route_for(pol, prop)
    if route is None:
        raise PermissionError("capability_route_not_authorized")
    body = {
        "profile": CHALLENGE_PROFILE,
        "policy_hash": canonical_hash(pol),
        "route_id": route["route_id"],
        "effect_hash": canonical_hash(effect_binding(prop)),
        "state_hash": prop["state_hash"],
        "requirements": route["requirements"],
        "max_authorization_ttl_seconds": route["max_authorization_ttl_seconds"],
        "holder_mode": "bearer",
    }
    return {**body, "challenge_hash": canonical_hash(body)}


def assess_challenge(
    challenge: Mapping[str, Any],
    proposal: Mapping[str, Any],
    evidence: Sequence[Mapping[str, Any]],
    *,
    now: datetime,
    current_state_hash: str,
) -> dict[str, Any]:
    prop = validate_proposal(proposal)
    effect_digest = canonical_hash(effect_binding(prop))
    reasons: list[str] = []
    used: list[str] = []

    if challenge.get("profile") != CHALLENGE_PROFILE:
        raise CapabilityError("capability_challenge_profile_invalid")
    body = dict(challenge)
    observed_hash = body.pop("challenge_hash", None)
    if observed_hash != canonical_hash(body):
        raise CapabilityError("capability_challenge_hash_mismatch")
    if challenge.get("effect_hash") != effect_digest:
        reasons.append("effect_changed_since_challenge")
    if challenge.get("state_hash") != current_state_hash:
        reasons.append("state_changed_since_challenge")

    normalized = [validate_evidence(item) for item in evidence]
    now_utc = now.astimezone(timezone.utc)
    for requirement in challenge.get("requirements", []):
        rid = requirement["requirement_id"]
        candidates = [
            item for item in normalized
            if item["requirement_id"] == rid and item["kind"] == requirement["kind"]
        ]
        if not candidates:
            reasons.append(f"requirement_missing:{rid}")
            continue
        valid = []
        for item in candidates:
            local = []
            if item["subject_hash"] != effect_digest:
                local.append(f"subject_mismatch:{rid}")
            if item["issuer_id"] not in requirement["accepted_issuers"]:
                local.append(f"issuer_not_accepted:{rid}")
            # A bearer capability need not bind caller identity.  Independence
            # is enforced as a caveat on evidence provenance instead.
            if requirement["independent_from_producer"] and item["issuer_id"] == prop["producer_id"]:
                local.append(f"self_evidence_forbidden:{rid}")
            issued = _parse_time(item["issued_at"])
            expires = _parse_time(item["expires_at"])
            if issued > now_utc:
                local.append(f"evidence_from_future:{rid}")
            if item["receiver_verification_status"] != "VERIFIED":
                local.append(f"evidence_unverified:{rid}")
            if item["revoked"]:
                local.append(f"evidence_revoked:{rid}")
            if expires <= now_utc:
                local.append(f"evidence_expired:{rid}")
            if (now_utc - issued).total_seconds() > requirement["max_age_seconds"]:
                local.append(f"evidence_stale:{rid}")
            if not local:
                valid.append(item)
            else:
                reasons.extend(local)
        if valid:
            chosen = sorted(valid, key=evidence_hash)[0]
            used.append(evidence_hash(chosen))

    allowed = not reasons
    result = {
        "profile": "caveated_capability_assessment/v1",
        "allowed": allowed,
        "decision": "ALLOW" if allowed else "BLOCK",
        "reason_codes": sorted(set(reasons)),
        "challenge_hash": challenge["challenge_hash"],
        "effect_hash": effect_digest,
        "state_hash": current_state_hash,
        "used_evidence_hashes": sorted(set(used)),
    }
    return {**result, "assessment_hash": canonical_hash(result)}


def mint_token(
    challenge: Mapping[str, Any],
    assessment: Mapping[str, Any],
    *,
    receiver_key: bytes,
    now: datetime,
    ttl_seconds: int = 20,
    nonce: str | None = None,
) -> dict[str, Any]:
    if assessment.get("allowed") is not True:
        raise PermissionError("capability_not_allowed")
    max_ttl = int(challenge["max_authorization_ttl_seconds"])
    if ttl_seconds <= 0 or ttl_seconds > max_ttl:
        raise CapabilityError("capability_ttl_invalid")
    raw_nonce = nonce or secrets.token_hex(32)
    nonce_hash = hashlib.sha256(raw_nonce.encode("ascii")).hexdigest()
    expires = now.astimezone(timezone.utc).timestamp() + ttl_seconds
    expires_at = datetime.fromtimestamp(expires, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    body = {
        "profile": TOKEN_PROFILE,
        "challenge_hash": challenge["challenge_hash"],
        "assessment_hash": assessment["assessment_hash"],
        "effect_hash": assessment["effect_hash"],
        "state_hash": assessment["state_hash"],
        "used_evidence_hashes": assessment["used_evidence_hashes"],
        "expires_at": expires_at,
        "nonce_hash": nonce_hash,
    }
    signature = hmac.new(receiver_key, canonical_json(body), hashlib.sha256).hexdigest()
    return {**body, "signature": signature, "_nonce": raw_nonce}


@dataclass
class CapabilityLedger:
    consumed_signatures: set[str]
    consumed_nonces: set[str]

    @classmethod
    def empty(cls) -> "CapabilityLedger":
        return cls(set(), set())

    def execute_once(
        self,
        token: Mapping[str, Any],
        attempted_proposal: Mapping[str, Any],
        *,
        receiver_key: bytes,
        current_state_hash: str,
        now: datetime,
    ) -> dict[str, Any]:
        prop = validate_proposal(attempted_proposal)
        attempted_effect = canonical_hash(effect_binding(prop))
        reasons: list[str] = []
        if token.get("profile") != TOKEN_PROFILE:
            reasons.append("token_profile_invalid")
        body = {k: token[k] for k in token if k not in {"signature", "_nonce"}}
        expected_sig = hmac.new(receiver_key, canonical_json(body), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(token.get("signature", "")), expected_sig):
            reasons.append("token_signature_invalid")
        if token.get("effect_hash") != attempted_effect:
            reasons.append("effect_hash_mismatch")
        if token.get("state_hash") != current_state_hash:
            reasons.append("state_hash_mismatch")
        if _parse_time(str(token.get("expires_at", "1970-01-01T00:00:00Z"))) <= now.astimezone(timezone.utc):
            reasons.append("token_expired")
        signature = str(token.get("signature", ""))
        nonce_hash = str(token.get("nonce_hash", ""))
        if signature in self.consumed_signatures:
            reasons.append("token_replay")
        if nonce_hash in self.consumed_nonces:
            reasons.append("nonce_replay")
        if reasons:
            return {"authorized": False, "reason_codes": sorted(set(reasons)), "executed": False}
        self.consumed_signatures.add(signature)
        self.consumed_nonces.add(nonce_hash)
        return {"authorized": True, "reason_codes": [], "executed": True}
