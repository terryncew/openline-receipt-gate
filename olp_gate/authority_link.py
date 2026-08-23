"""Decision -> permission bridge for receiver-owned authorization.

The optimizer is allowed to propose an exact action. It is never allowed to
turn decision quality, confidence, rank, or rationale into permission.

This module converts an untrusted decision proposal into a receiver-owned proof
obligation, evaluates receiver-verified evidence against that obligation, and
emits deterministic settings that can be bound and single-use consumed by
OpenLine Verified Commit.

It deliberately does *not* execute tools, verify signatures, or create mandate
authority. Those remain separate receiver-side responsibilities.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Mapping, Sequence

PROPOSAL_PROFILE = "decision_proposal/v1"
POLICY_PROFILE = "decision_permission_policy/v1"
EVIDENCE_PROFILE = "permission_evidence/v1"
OBLIGATION_PROFILE = "decision_permission_obligation/v1"
ASSESSMENT_PROFILE = "decision_permission_assessment/v1"
VERIFIED_COMMIT_SETTINGS_PROFILE = "decision_permission_link/v1"

_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_KINDS = {"authority", "evidence"}
_ALLOWED_UNKNOWN = {"QUARANTINE"}


class AuthorityLinkError(ValueError):
    """Raised when a link artifact has an invalid or ambiguous shape."""


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and _HEX_256.fullmatch(value) is not None


def _validate_canonical(value: Any, path: str = "$") -> None:
    """Restrict link artifacts to deterministic JSON values.

    Floats are intentionally excluded from permission-bearing material. Models
    may score however they like, but scores belong behind ``advisory_hash``.
    """
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise AuthorityLinkError(f"canonical_float_forbidden:{path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_canonical(item, f"{path}[{index}]")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise AuthorityLinkError(f"canonical_key_invalid:{path}")
            _validate_canonical(item, f"{path}.{key}")
        return
    raise AuthorityLinkError(f"canonical_type_unsupported:{path}:{type(value).__name__}")


def canonical_json(value: Mapping[str, Any]) -> bytes:
    _validate_canonical(value)
    return json.dumps(
        dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise AuthorityLinkError("timestamp_invalid")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise AuthorityLinkError("timestamp_invalid") from exc
    if parsed.tzinfo is None:
        raise AuthorityLinkError("timestamp_timezone_required")
    return parsed.astimezone(timezone.utc)


def _normalized_strings(value: Any, name: str, *, nonempty: bool = False) -> list[str]:
    if not isinstance(value, list):
        raise AuthorityLinkError(f"{name}_invalid")
    if nonempty and not value:
        raise AuthorityLinkError(f"{name}_empty")
    if not all(isinstance(item, str) and item for item in value):
        raise AuthorityLinkError(f"{name}_invalid")
    if len(set(value)) != len(value):
        raise AuthorityLinkError(f"{name}_duplicate")
    return sorted(value)


def validate_proposal(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "profile", "proposal_id", "producer_id", "producer_model", "objective",
        "tool", "target", "settings", "state_hash", "advisory_hash",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        raise AuthorityLinkError("proposal_shape_invalid")
    if value.get("profile") != PROPOSAL_PROFILE:
        raise AuthorityLinkError("proposal_profile_invalid")
    for name in (
        "proposal_id", "producer_id", "producer_model", "objective", "tool", "target"
    ):
        if not isinstance(value.get(name), str) or not value[name]:
            raise AuthorityLinkError(f"proposal_{name}_invalid")
    if not isinstance(value.get("settings"), Mapping):
        raise AuthorityLinkError("proposal_settings_invalid")
    for name in ("state_hash", "advisory_hash"):
        if not _is_hash(value.get(name)):
            raise AuthorityLinkError(f"proposal_{name}_invalid")
    out = dict(value)
    out["settings"] = dict(value["settings"])
    _validate_canonical(out)
    return out


def proposal_hash(proposal: Mapping[str, Any]) -> str:
    return canonical_hash(validate_proposal(proposal))


def effect_binding(proposal: Mapping[str, Any]) -> dict[str, Any]:
    item = validate_proposal(proposal)
    return {
        "tool": item["tool"],
        "target": item["target"],
        "settings": item["settings"],
        "state_hash": item["state_hash"],
    }


def effect_hash(proposal: Mapping[str, Any]) -> str:
    return canonical_hash(effect_binding(proposal))


def validate_policy(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {"profile", "policy_id", "version", "routes"}
    if not isinstance(value, Mapping) or set(value) != required:
        raise AuthorityLinkError("policy_shape_invalid")
    if value.get("profile") != POLICY_PROFILE:
        raise AuthorityLinkError("policy_profile_invalid")
    for name in ("policy_id", "version"):
        if not isinstance(value.get(name), str) or not value[name]:
            raise AuthorityLinkError(f"policy_{name}_invalid")
    routes = value.get("routes")
    if not isinstance(routes, list) or not routes:
        raise AuthorityLinkError("policy_routes_invalid")
    normalized_routes: list[dict[str, Any]] = []
    route_ids: set[str] = set()
    route_keys: set[tuple[str, str]] = set()
    for raw_route in routes:
        if not isinstance(raw_route, Mapping) or set(raw_route) != {
            "route_id", "tool", "target", "requirements", "unknown_behavior",
            "max_authorization_ttl_seconds",
        }:
            raise AuthorityLinkError("policy_route_shape_invalid")
        route = dict(raw_route)
        for name in ("route_id", "tool", "target"):
            if not isinstance(route.get(name), str) or not route[name]:
                raise AuthorityLinkError(f"policy_route_{name}_invalid")
        if route["route_id"] in route_ids:
            raise AuthorityLinkError("policy_route_id_duplicate")
        route_ids.add(route["route_id"])
        route_key = (route["tool"], route["target"])
        if route_key in route_keys:
            raise AuthorityLinkError("policy_route_ambiguous")
        route_keys.add(route_key)
        if route.get("unknown_behavior") not in _ALLOWED_UNKNOWN:
            raise AuthorityLinkError("policy_unknown_behavior_invalid")
        ttl = route.get("max_authorization_ttl_seconds")
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
            raise AuthorityLinkError("policy_ttl_invalid")
        raw_requirements = route.get("requirements")
        if not isinstance(raw_requirements, list) or not raw_requirements:
            raise AuthorityLinkError("policy_requirements_invalid")
        requirement_ids: set[str] = set()
        requirements: list[dict[str, Any]] = []
        for raw_requirement in raw_requirements:
            if not isinstance(raw_requirement, Mapping) or set(raw_requirement) != {
                "requirement_id", "kind", "accepted_issuers", "max_age_seconds",
                "independent_from_producer",
            }:
                raise AuthorityLinkError("policy_requirement_shape_invalid")
            requirement = dict(raw_requirement)
            rid = requirement.get("requirement_id")
            if not isinstance(rid, str) or not rid:
                raise AuthorityLinkError("policy_requirement_id_invalid")
            if rid in requirement_ids:
                raise AuthorityLinkError("policy_requirement_id_duplicate")
            requirement_ids.add(rid)
            if requirement.get("kind") not in _ALLOWED_KINDS:
                raise AuthorityLinkError("policy_requirement_kind_invalid")
            requirement["accepted_issuers"] = _normalized_strings(
                requirement.get("accepted_issuers"), "accepted_issuers", nonempty=True
            )
            age = requirement.get("max_age_seconds")
            if not isinstance(age, int) or isinstance(age, bool) or age <= 0:
                raise AuthorityLinkError("policy_requirement_age_invalid")
            if not isinstance(requirement.get("independent_from_producer"), bool):
                raise AuthorityLinkError("policy_requirement_independence_invalid")
            requirements.append(requirement)
        route["requirements"] = sorted(requirements, key=lambda item: item["requirement_id"])
        normalized_routes.append(route)
    out = {
        "profile": POLICY_PROFILE,
        "policy_id": value["policy_id"],
        "version": value["version"],
        "routes": sorted(normalized_routes, key=lambda item: item["route_id"]),
    }
    _validate_canonical(out)
    return out


def policy_hash(policy: Mapping[str, Any]) -> str:
    return canonical_hash(validate_policy(policy))


def _route_for(policy: Mapping[str, Any], proposal: Mapping[str, Any]) -> dict[str, Any] | None:
    normalized_policy = validate_policy(policy)
    normalized_proposal = validate_proposal(proposal)
    matches = [
        route for route in normalized_policy["routes"]
        if route["tool"] == normalized_proposal["tool"]
        and route["target"] == normalized_proposal["target"]
    ]
    if len(matches) > 1:
        raise AuthorityLinkError("policy_route_ambiguous")
    return matches[0] if matches else None


def compile_obligation(policy: Mapping[str, Any], proposal: Mapping[str, Any]) -> dict[str, Any]:
    normalized_policy = validate_policy(policy)
    normalized_proposal = validate_proposal(proposal)
    route = _route_for(normalized_policy, normalized_proposal)
    if route is None:
        raise PermissionError("proposal_route_not_authorized")
    body = {
        "profile": OBLIGATION_PROFILE,
        "policy_id": normalized_policy["policy_id"],
        "policy_version": normalized_policy["version"],
        "policy_hash": canonical_hash(normalized_policy),
        "route_id": route["route_id"],
        "proposal_hash": canonical_hash(normalized_proposal),
        "effect_hash": canonical_hash(effect_binding(normalized_proposal)),
        "state_hash": normalized_proposal["state_hash"],
        "producer_id": normalized_proposal["producer_id"],
        "requirements": route["requirements"],
        "unknown_behavior": route["unknown_behavior"],
        "max_authorization_ttl_seconds": route["max_authorization_ttl_seconds"],
    }
    return {**body, "obligation_hash": canonical_hash(body)}


def validate_obligation(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "profile", "policy_id", "policy_version", "policy_hash", "route_id",
        "proposal_hash", "effect_hash", "state_hash", "producer_id", "requirements",
        "unknown_behavior", "max_authorization_ttl_seconds", "obligation_hash",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        raise AuthorityLinkError("obligation_shape_invalid")
    if value.get("profile") != OBLIGATION_PROFILE:
        raise AuthorityLinkError("obligation_profile_invalid")
    for name in (
        "policy_id", "policy_version", "route_id", "producer_id"
    ):
        if not isinstance(value.get(name), str) or not value[name]:
            raise AuthorityLinkError(f"obligation_{name}_invalid")
    for name in ("policy_hash", "proposal_hash", "effect_hash", "state_hash", "obligation_hash"):
        if not _is_hash(value.get(name)):
            raise AuthorityLinkError(f"obligation_{name}_invalid")
    if value.get("unknown_behavior") not in _ALLOWED_UNKNOWN:
        raise AuthorityLinkError("obligation_unknown_behavior_invalid")
    ttl = value.get("max_authorization_ttl_seconds")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
        raise AuthorityLinkError("obligation_ttl_invalid")
    requirements = value.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        raise AuthorityLinkError("obligation_requirements_invalid")
    # Reuse policy validation to validate requirement shapes without inventing a
    # second rule language.
    synthetic_policy = {
        "profile": POLICY_PROFILE,
        "policy_id": value["policy_id"],
        "version": value["policy_version"],
        "routes": [{
            "route_id": value["route_id"],
            "tool": "validation-only",
            "target": "validation-only",
            "requirements": requirements,
            "unknown_behavior": value["unknown_behavior"],
            "max_authorization_ttl_seconds": ttl,
        }],
    }
    checked_requirements = validate_policy(synthetic_policy)["routes"][0]["requirements"]
    body = {key: value[key] for key in required if key != "obligation_hash"}
    body["requirements"] = checked_requirements
    expected_hash = canonical_hash(body)
    if value["obligation_hash"] != expected_hash:
        raise AuthorityLinkError("obligation_hash_mismatch")
    return {**body, "obligation_hash": expected_hash}


def validate_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "profile", "requirement_id", "kind", "subject_hash", "issuer_id",
        "issued_at", "expires_at", "artifact_hash", "verification_receipt_hash",
        "receiver_verification_status", "revoked",
    }
    if not isinstance(value, Mapping) or set(value) != required:
        raise AuthorityLinkError("evidence_shape_invalid")
    if value.get("profile") != EVIDENCE_PROFILE:
        raise AuthorityLinkError("evidence_profile_invalid")
    for name in ("requirement_id", "issuer_id", "issued_at", "expires_at"):
        if not isinstance(value.get(name), str) or not value[name]:
            raise AuthorityLinkError(f"evidence_{name}_invalid")
    if value.get("kind") not in _ALLOWED_KINDS:
        raise AuthorityLinkError("evidence_kind_invalid")
    for name in ("subject_hash", "artifact_hash", "verification_receipt_hash"):
        if not _is_hash(value.get(name)):
            raise AuthorityLinkError(f"evidence_{name}_invalid")
    _parse_time(value["issued_at"])
    _parse_time(value["expires_at"])
    if value.get("receiver_verification_status") not in {"VERIFIED", "UNVERIFIED"}:
        raise AuthorityLinkError("evidence_verification_status_invalid")
    if not isinstance(value.get("revoked"), bool):
        raise AuthorityLinkError("evidence_revoked_invalid")
    out = dict(value)
    _validate_canonical(out)
    return out


def evidence_hash(value: Mapping[str, Any]) -> str:
    return canonical_hash(validate_evidence(value))


def _assessment_body(
    *, decision: str,
    reason_codes: Sequence[str],
    proposal_digest: str,
    effect_digest: str,
    obligation: Mapping[str, Any] | None,
    current_state_hash: str,
    current_policy_hash: str,
    used_evidence_hashes: Sequence[str],
) -> dict[str, Any]:
    return {
        "profile": ASSESSMENT_PROFILE,
        "decision": decision,
        "reason_codes": sorted(set(reason_codes)),
        "proposal_hash": proposal_digest,
        "effect_hash": effect_digest,
        "obligation_hash": obligation["obligation_hash"] if obligation else None,
        "policy_hash": current_policy_hash,
        "state_hash": current_state_hash,
        "used_evidence_hashes": sorted(set(used_evidence_hashes)),
        "policy_authority": "RECEIVER",
    }


def assess_permission(
    policy: Mapping[str, Any],
    proposal: Mapping[str, Any],
    evidence: Sequence[Mapping[str, Any]],
    *,
    now: datetime,
    current_state_hash: str,
    obligation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Assess permission without using the optimizer's advisory output.

    Missing/refreshable evidence quarantines. Structural substitution attempts,
    unauthorized routes, policy drift, and state drift deny the old proposal.
    """
    normalized_policy = validate_policy(policy)
    normalized_proposal = validate_proposal(proposal)
    if not _is_hash(current_state_hash):
        raise AuthorityLinkError("current_state_hash_invalid")
    p_hash = canonical_hash(normalized_proposal)
    e_hash = canonical_hash(effect_binding(normalized_proposal))
    current_p_hash = canonical_hash(normalized_policy)

    if obligation is None:
        try:
            normalized_obligation = compile_obligation(normalized_policy, normalized_proposal)
        except PermissionError:
            body = _assessment_body(
                decision="DENY",
                reason_codes=["proposal_route_not_authorized"],
                proposal_digest=p_hash,
                effect_digest=e_hash,
                obligation=None,
                current_state_hash=current_state_hash,
                current_policy_hash=current_p_hash,
                used_evidence_hashes=[],
            )
            return {**body, "assessment_hash": canonical_hash(body)}
    else:
        normalized_obligation = validate_obligation(obligation)

    hard_reasons: list[str] = []
    quarantine_reasons: list[str] = []
    used_hashes: list[str] = []

    if normalized_obligation["policy_hash"] != current_p_hash:
        hard_reasons.append("policy_changed_since_obligation")
    if normalized_obligation["proposal_hash"] != p_hash:
        hard_reasons.append("proposal_changed_since_obligation")
    if normalized_obligation["effect_hash"] != e_hash:
        hard_reasons.append("effect_changed_since_obligation")
    if normalized_obligation["state_hash"] != current_state_hash:
        hard_reasons.append("state_changed_since_proposal")
    if normalized_obligation["producer_id"] != normalized_proposal["producer_id"]:
        hard_reasons.append("producer_changed_since_obligation")

    normalized_evidence: list[dict[str, Any]] = []
    for item in evidence:
        normalized_evidence.append(validate_evidence(item))

    for requirement in normalized_obligation["requirements"]:
        rid = requirement["requirement_id"]
        kind = requirement["kind"]
        candidates = [
            item for item in normalized_evidence
            if item["requirement_id"] == rid and item["kind"] == kind
        ]
        if not candidates:
            quarantine_reasons.append(f"requirement_missing:{rid}")
            continue

        valid: list[dict[str, Any]] = []
        candidate_hard: list[str] = []
        candidate_soft: list[str] = []
        for item in candidates:
            local_hard: list[str] = []
            local_soft: list[str] = []
            if item["subject_hash"] != e_hash:
                local_hard.append(f"subject_mismatch:{rid}")
            if item["issuer_id"] not in requirement["accepted_issuers"]:
                local_hard.append(f"issuer_not_accepted:{rid}")
            if requirement["independent_from_producer"] and item["issuer_id"] == normalized_proposal["producer_id"]:
                local_hard.append(f"self_evidence_forbidden:{rid}")
            issued = _parse_time(item["issued_at"])
            expires = _parse_time(item["expires_at"])
            now_utc = now.astimezone(timezone.utc)
            if issued > now_utc:
                local_hard.append(f"evidence_from_future:{rid}")
            if item["receiver_verification_status"] != "VERIFIED":
                local_soft.append(f"evidence_unverified:{rid}")
            if item["revoked"]:
                local_soft.append(f"evidence_revoked:{rid}")
            if expires <= now_utc:
                local_soft.append(f"evidence_expired:{rid}")
            if (now_utc - issued).total_seconds() > requirement["max_age_seconds"]:
                local_soft.append(f"evidence_stale:{rid}")
            if not local_hard and not local_soft:
                valid.append(item)
            else:
                candidate_hard.extend(local_hard)
                candidate_soft.extend(local_soft)

        if valid:
            chosen = sorted(valid, key=lambda item: evidence_hash(item))[0]
            used_hashes.append(evidence_hash(chosen))
        elif candidate_hard:
            hard_reasons.extend(candidate_hard)
        else:
            quarantine_reasons.extend(candidate_soft or [f"requirement_unsatisfied:{rid}"])

    if hard_reasons:
        decision = "DENY"
        reasons = hard_reasons + quarantine_reasons
    elif quarantine_reasons:
        decision = normalized_obligation["unknown_behavior"]
        reasons = quarantine_reasons
    else:
        decision = "COMMIT_ELIGIBLE"
        reasons = []

    body = _assessment_body(
        decision=decision,
        reason_codes=reasons,
        proposal_digest=p_hash,
        effect_digest=e_hash,
        obligation=normalized_obligation,
        current_state_hash=current_state_hash,
        current_policy_hash=current_p_hash,
        used_evidence_hashes=used_hashes,
    )
    return {**body, "assessment_hash": canonical_hash(body)}


def compile_verified_commit_settings(
    proposal: Mapping[str, Any],
    obligation: Mapping[str, Any],
    assessment: Mapping[str, Any],
) -> dict[str, Any]:
    """Compile permission result into settings for existing Verified Commit.

    Verified Commit remains the exact-action, TTL, one-use, replay-safe effect
    boundary. This function only provides the permission-bearing settings it
    should hash and bind.
    """
    normalized_proposal = validate_proposal(proposal)
    normalized_obligation = validate_obligation(obligation)
    if not isinstance(assessment, Mapping) or assessment.get("profile") != ASSESSMENT_PROFILE:
        raise AuthorityLinkError("assessment_invalid")
    if assessment.get("decision") != "COMMIT_ELIGIBLE":
        raise PermissionError("permission_not_commit_eligible")
    if assessment.get("proposal_hash") != canonical_hash(normalized_proposal):
        raise AuthorityLinkError("assessment_proposal_hash_mismatch")
    if assessment.get("effect_hash") != canonical_hash(effect_binding(normalized_proposal)):
        raise AuthorityLinkError("assessment_effect_hash_mismatch")
    if assessment.get("obligation_hash") != normalized_obligation["obligation_hash"]:
        raise AuthorityLinkError("assessment_obligation_hash_mismatch")
    if assessment.get("policy_hash") != normalized_obligation["policy_hash"]:
        raise AuthorityLinkError("assessment_policy_hash_mismatch")
    if assessment.get("state_hash") != normalized_obligation["state_hash"]:
        raise AuthorityLinkError("assessment_state_hash_mismatch")
    body = {key: assessment[key] for key in assessment if key != "assessment_hash"}
    if assessment.get("assessment_hash") != canonical_hash(body):
        raise AuthorityLinkError("assessment_hash_mismatch")
    settings = {
        "profile": VERIFIED_COMMIT_SETTINGS_PROFILE,
        "proposal_id": normalized_proposal["proposal_id"],
        "proposal_hash": assessment["proposal_hash"],
        "effect_hash": assessment["effect_hash"],
        "state_hash": assessment["state_hash"],
        "policy_hash": assessment["policy_hash"],
        "obligation_hash": assessment["obligation_hash"],
        "permission_assessment_hash": assessment["assessment_hash"],
        "evidence_receipt_hashes": sorted(assessment.get("used_evidence_hashes", [])),
        "effect_settings": normalized_proposal["settings"],
    }
    _validate_canonical(settings)
    return settings


def compile_link(
    policy: Mapping[str, Any],
    proposal: Mapping[str, Any],
    evidence: Sequence[Mapping[str, Any]],
    *,
    now: datetime,
    current_state_hash: str,
) -> dict[str, Any]:
    """Convenience wrapper: proposal -> obligation -> assessment -> settings."""
    try:
        obligation = compile_obligation(policy, proposal)
    except PermissionError:
        assessment = assess_permission(
            policy, proposal, evidence, now=now, current_state_hash=current_state_hash
        )
        return {"obligation": None, "assessment": assessment, "verified_commit_settings": None}
    assessment = assess_permission(
        policy, proposal, evidence, now=now, current_state_hash=current_state_hash,
        obligation=obligation,
    )
    settings = None
    if assessment["decision"] == "COMMIT_ELIGIBLE":
        settings = compile_verified_commit_settings(proposal, obligation, assessment)
    return {
        "obligation": obligation,
        "assessment": assessment,
        "verified_commit_settings": settings,
    }
