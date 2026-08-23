"""Receiver-owned principal mandate profile.

This module does not create fiduciary duty and does not replace Verified Commit.
It answers one narrower question before exact-action authorization:

    Does this proposed consequential effect fit inside the principal's
    still-valid reusable mandate?

Verified Commit remains responsible for binding and atomically consuming the
resulting exact action authorization at the effect boundary.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib, json
from typing import Any, Mapping

MANDATE_PROFILE = "principal_mandate/v1"
EFFECT_PROFILE = "principal_effect/v1"
_ALLOWED_ACTION_TYPES = {
    "inspect","draft","send","accept_settlement","authorize_payment","delegate"
}

def _parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp_invalid")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError("timestamp_invalid") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp_timezone_required")
    return parsed.astimezone(timezone.utc)

def _canonical_hash(value: Mapping[str, Any]) -> str:
    payload=json.dumps(dict(value),sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    return hashlib.sha256(payload).hexdigest()

@dataclass(frozen=True)
class MandateSpec:
    mandate_id: str
    principal_id: str
    agent_id: str
    purpose: str
    allowed_action_types: tuple[str, ...]
    allowed_targets: tuple[str, ...]
    allowed_disclosure_classes: tuple[str, ...]
    forbidden_disclosure_classes: tuple[str, ...]
    max_settlement_cents: int
    max_payment_cents: int
    delegation_allowed: bool
    expires_at: str
    version: str = "1"

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "MandateSpec":
        required={
            "profile","mandate_id","principal_id","agent_id","purpose",
            "allowed_action_types","allowed_targets","allowed_disclosure_classes",
            "forbidden_disclosure_classes","max_settlement_cents",
            "max_payment_cents","delegation_allowed","expires_at","version",
        }
        if set(value)!=required: raise ValueError("mandate_shape_invalid")
        if value.get("profile")!=MANDATE_PROFILE: raise ValueError("mandate_profile_invalid")
        for name in ("mandate_id","principal_id","agent_id","purpose","expires_at","version"):
            if not isinstance(value.get(name),str) or not value[name]:
                raise ValueError(f"{name}_invalid")
        lists={}
        for name in ("allowed_action_types","allowed_targets","allowed_disclosure_classes","forbidden_disclosure_classes"):
            raw=value.get(name)
            if not isinstance(raw,list) or not all(isinstance(x,str) and x for x in raw) or len(set(raw))!=len(raw):
                raise ValueError(f"{name}_invalid")
            lists[name]=tuple(sorted(raw))
        if not set(lists["allowed_action_types"]) <= _ALLOWED_ACTION_TYPES:
            raise ValueError("allowed_action_types_invalid")
        if set(lists["allowed_disclosure_classes"]) & set(lists["forbidden_disclosure_classes"]):
            raise ValueError("disclosure_policy_overlap")
        for name in ("max_settlement_cents","max_payment_cents"):
            v=value.get(name)
            if not isinstance(v,int) or isinstance(v,bool) or v<0:
                raise ValueError(f"{name}_invalid")
        if not isinstance(value.get("delegation_allowed"),bool):
            raise ValueError("delegation_allowed_invalid")
        _parse_time(value["expires_at"])
        return cls(
            mandate_id=value["mandate_id"], principal_id=value["principal_id"],
            agent_id=value["agent_id"], purpose=value["purpose"],
            allowed_action_types=lists["allowed_action_types"],
            allowed_targets=lists["allowed_targets"],
            allowed_disclosure_classes=lists["allowed_disclosure_classes"],
            forbidden_disclosure_classes=lists["forbidden_disclosure_classes"],
            max_settlement_cents=value["max_settlement_cents"],
            max_payment_cents=value["max_payment_cents"],
            delegation_allowed=value["delegation_allowed"],
            expires_at=value["expires_at"], version=value["version"],
        )

    def as_dict(self) -> dict[str, Any]:
        out=asdict(self); out["profile"]=MANDATE_PROFILE
        for k in ("allowed_action_types","allowed_targets","allowed_disclosure_classes","forbidden_disclosure_classes"):
            out[k]=list(out[k])
        return out

    @property
    def mandate_hash(self)->str:
        return _canonical_hash(self.as_dict())

def validate_effect(value: Mapping[str, Any]) -> dict[str, Any]:
    required={
        "profile","effect_id","mandate_id","principal_id","agent_id","purpose",
        "action_type","target","disclosures","value_cents","delegatee","producer_model",
    }
    if set(value)!=required: raise ValueError("effect_shape_invalid")
    if value.get("profile")!=EFFECT_PROFILE: raise ValueError("effect_profile_invalid")
    for name in ("effect_id","mandate_id","principal_id","agent_id","purpose","action_type","target","producer_model"):
        if not isinstance(value.get(name),str) or not value[name]:
            raise ValueError(f"{name}_invalid")
    d=value.get("disclosures")
    if not isinstance(d,list) or not all(isinstance(x,str) and x for x in d) or len(set(d))!=len(d):
        raise ValueError("disclosures_invalid")
    amount=value.get("value_cents")
    if not isinstance(amount,int) or isinstance(amount,bool) or amount<0:
        raise ValueError("value_cents_invalid")
    delegatee=value.get("delegatee")
    if delegatee is not None and (not isinstance(delegatee,str) or not delegatee):
        raise ValueError("delegatee_invalid")
    out=dict(value); out["disclosures"]=sorted(d); return out

def assess_effect(mandate_value: MandateSpec|Mapping[str,Any], effect_value: Mapping[str,Any], *, now: datetime)->dict[str,Any]:
    mandate=mandate_value if isinstance(mandate_value,MandateSpec) else MandateSpec.from_mapping(mandate_value)
    effect=validate_effect(effect_value)
    reasons=[]
    if _parse_time(mandate.expires_at) <= now.astimezone(timezone.utc):
        reasons.append("mandate_expired")
    for name,expected in {
        "mandate_id":mandate.mandate_id,"principal_id":mandate.principal_id,
        "agent_id":mandate.agent_id,"purpose":mandate.purpose,
    }.items():
        if effect[name]!=expected: reasons.append(f"{name}_mismatch")
    action=effect["action_type"]
    if action not in mandate.allowed_action_types: reasons.append("action_not_allowed")
    if mandate.allowed_targets and effect["target"] not in mandate.allowed_targets:
        reasons.append("target_not_allowed")
    disclosures=set(effect["disclosures"])
    allowed=set(mandate.allowed_disclosure_classes)
    forbidden=set(mandate.forbidden_disclosure_classes)
    if disclosures & forbidden: reasons.append("forbidden_disclosure")
    if not disclosures <= allowed: reasons.append("disclosure_outside_allowlist")
    if action=="accept_settlement" and effect["value_cents"]>mandate.max_settlement_cents:
        reasons.append("settlement_limit_exceeded")
    if action=="authorize_payment" and effect["value_cents"]>mandate.max_payment_cents:
        reasons.append("payment_limit_exceeded")
    if action=="delegate":
        if not mandate.delegation_allowed: reasons.append("delegation_not_allowed")
        if effect["delegatee"] is None: reasons.append("delegatee_missing")
    elif effect["delegatee"] is not None:
        reasons.append("unexpected_delegatee")
    allowed_effect=not reasons
    return {
        "schema":"openline.principal_mandate.assessment.v1",
        "allowed":allowed_effect,
        "decision":"COMMIT_ELIGIBLE" if allowed_effect else "DENY",
        "reason_codes":sorted(set(reasons)),
        "mandate_hash":mandate.mandate_hash,
        "effect_hash":_canonical_hash(effect),
        "policy_authority":"NONE",
    }

def compile_verified_commit_settings(mandate_value: MandateSpec|Mapping[str,Any], effect_value: Mapping[str,Any], *, now: datetime)->dict[str,Any]:
    assessment=assess_effect(mandate_value,effect_value,now=now)
    if not assessment["allowed"]:
        raise PermissionError(",".join(assessment["reason_codes"]))
    effect=validate_effect(effect_value)
    return {
        "profile":"principal_mandate_effect/v1",
        "mandate_hash":assessment["mandate_hash"],
        "effect_hash":assessment["effect_hash"],
        "effect":effect,
    }
