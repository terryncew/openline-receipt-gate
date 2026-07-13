"""Policy schema for the OpenLine proof-to-policy gate."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping

from .crypto import olp_canonical_json, sha256_hex


@dataclass(frozen=True)
class PolicySpec:
    policy_id: str
    version: str
    require_trusted_source: bool = True
    require_independent_source: bool = False
    require_declared_coverage: bool = False
    require_replay_guard: bool = True
    require_evidence: bool = True
    require_source_bound_evidence: bool = True
    require_outcome_witness: bool = False
    required_evidence_ids: tuple[str, ...] = ()
    required_claim_ids: tuple[str, ...] = ()
    evidence_assertions: tuple[dict[str, Any], ...] = ()
    max_source_age_seconds: int | None = 300
    max_evidence_bytes: int = 10_000_000
    no_badge_action_types: tuple[str, ...] = ("eval_score_claim",)
    deny_risk_levels: tuple[str, ...] = ()
    rollback_on_harm: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "PolicySpec":
        required = {"policy_id", "version"}
        if missing := required - set(value):
            raise ValueError(f"policy missing fields: {sorted(missing)}")
        allowed = set(cls.__dataclass_fields__)
        if unknown := set(value) - allowed:
            raise ValueError(f"policy has unknown fields: {sorted(unknown)}")
        if not isinstance(value["policy_id"], str) or not value["policy_id"]:
            raise ValueError("policy_id must be a nonempty string")
        if not isinstance(value["version"], str) or not value["version"]:
            raise ValueError("policy version must be a nonempty string")
        bool_fields = {
            "require_trusted_source",
            "require_independent_source",
            "require_declared_coverage",
            "require_replay_guard",
            "require_evidence",
            "require_source_bound_evidence",
            "require_outcome_witness",
            "rollback_on_harm",
        }
        for name in bool_fields:
            if name in value and not isinstance(value[name], bool):
                raise ValueError(f"{name} must be a boolean")
        list_fields = {
            "required_evidence_ids",
            "required_claim_ids",
            "no_badge_action_types",
            "deny_risk_levels",
        }
        for name in list_fields:
            if name in value and not isinstance(value[name], list):
                raise ValueError(f"{name} must be an array")
        metadata = value.get("metadata", {})
        if not isinstance(metadata, Mapping):
            raise ValueError("metadata must be an object")
        age = value.get("max_source_age_seconds", 300)
        if age is not None and (not isinstance(age, int) or isinstance(age, bool) or age < 0):
            raise ValueError("max_source_age_seconds must be a nonnegative integer or null")
        max_evidence_bytes = value.get("max_evidence_bytes", 10_000_000)
        if (
            not isinstance(max_evidence_bytes, int)
            or isinstance(max_evidence_bytes, bool)
            or max_evidence_bytes < 1
        ):
            raise ValueError("max_evidence_bytes must be a positive integer")
        assertions = value.get("evidence_assertions", [])
        if not isinstance(assertions, list) or not all(isinstance(item, Mapping) for item in assertions):
            raise ValueError("evidence_assertions must be an array of objects")
        return cls(
            policy_id=value["policy_id"],
            version=value["version"],
            require_trusted_source=value.get("require_trusted_source", True),
            require_independent_source=value.get("require_independent_source", False),
            require_declared_coverage=value.get("require_declared_coverage", False),
            require_replay_guard=value.get("require_replay_guard", True),
            require_evidence=value.get("require_evidence", True),
            require_source_bound_evidence=value.get("require_source_bound_evidence", True),
            require_outcome_witness=value.get("require_outcome_witness", False),
            required_evidence_ids=tuple(str(item) for item in value.get("required_evidence_ids", [])),
            required_claim_ids=tuple(str(item) for item in value.get("required_claim_ids", [])),
            evidence_assertions=tuple(dict(item) for item in assertions),
            max_source_age_seconds=age,
            max_evidence_bytes=max_evidence_bytes,
            no_badge_action_types=tuple(str(item) for item in value.get("no_badge_action_types", ["eval_score_claim"])),
            deny_risk_levels=tuple(str(item) for item in value.get("deny_risk_levels", [])),
            rollback_on_harm=value.get("rollback_on_harm", True),
            metadata=dict(metadata),
        )

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        for name in (
            "required_evidence_ids",
            "required_claim_ids",
            "evidence_assertions",
            "no_badge_action_types",
            "deny_risk_levels",
        ):
            value[name] = list(value[name])
        return value

    @property
    def policy_hash(self) -> str:
        return sha256_hex(olp_canonical_json(self.as_dict()))
