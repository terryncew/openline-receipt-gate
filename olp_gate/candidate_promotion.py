from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping, Sequence


class PromotionDecision(str, Enum):
    COMMIT = "COMMIT"
    QUARANTINE = "QUARANTINE"
    DENY = "DENY"


@dataclass(frozen=True)
class DimensionRule:
    assay_type: str
    operator: str
    threshold: float
    units: str
    acceptable_methods: tuple[str, ...] = ()
    max_age_days: int | None = None
    acceptable_evidence_classes: tuple[str, ...] = ("INDEPENDENT_ASSAY",)


@dataclass(frozen=True)
class CandidateIdentity:
    candidate_id: str
    sequence_sha256: str
    construct_id: str
    batch_id: str


@dataclass(frozen=True)
class AssayReceipt:
    candidate_id: str
    sequence_sha256: str
    construct_id: str
    batch_id: str
    target: str
    assay_type: str
    measurement: float | None
    units: str
    method: str
    method_version: str
    verifier: str
    observed_at: str
    raw_evidence_sha256: str
    evidence_class: str = "INDEPENDENT_ASSAY"
    status: str = "CURRENT"


@dataclass(frozen=True)
class PromotionPolicy:
    policy_id: str
    version: str
    effective_at: str
    target: str
    rules: tuple[DimensionRule, ...]
    missing_evidence: str = "QUARANTINE"

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "effective_at": self.effective_at,
            "target": self.target,
            "missing_evidence": self.missing_evidence,
            "rules": [
                {
                    "assay_type": r.assay_type,
                    "operator": r.operator,
                    "threshold": r.threshold,
                    "units": r.units,
                    "acceptable_methods": list(r.acceptable_methods),
                    "acceptable_evidence_classes": list(r.acceptable_evidence_classes),
                    "max_age_days": r.max_age_days,
                }
                for r in self.rules
            ],
        }

    @property
    def policy_sha256(self) -> str:
        blob = json.dumps(self.canonical_payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PromotionResult:
    decision: PromotionDecision
    candidate_id: str
    policy_id: str
    policy_version: str
    policy_sha256: str
    flags: tuple[str, ...]
    evidence_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "openline.candidate_promotion.v0.1",
            "decision": self.decision.value,
            "candidate_id": self.candidate_id,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "flags": list(self.flags),
            "evidence_sha256": self.evidence_sha256,
        }


def _parse_time(value: str) -> datetime:
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _is_sha256(value: str) -> bool:
    if len(value) != 64:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _passes(value: float, operator: str, threshold: float) -> bool:
    if operator == "<=":
        return value <= threshold
    if operator == "<":
        return value < threshold
    if operator == ">=":
        return value >= threshold
    if operator == ">":
        return value > threshold
    raise ValueError(f"unsupported operator: {operator}")


def _canonical_hash(items: Any) -> str:
    blob = json.dumps(items, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def evaluate_candidate(
    *,
    candidate: CandidateIdentity,
    receipts: Sequence[AssayReceipt],
    policy: PromotionPolicy,
    decision_time: str,
) -> PromotionResult:
    """Evaluate one candidate under a receiver-owned, non-compensatory policy.

    Fail semantics are deliberately asymmetric:
      * declared threshold failure, identity mismatch, revoked evidence, or unacceptable
        evidence -> DENY;
      * absent/unknown/stale required evidence -> QUARANTINE;
      * only complete passing evidence -> COMMIT.
    """
    now = _parse_time(decision_time)
    hard_fail: list[str] = []
    uncertain: list[str] = []

    if policy.missing_evidence != "QUARANTINE":
        hard_fail.append("invalid_policy_missing_evidence_behavior")
    if now < _parse_time(policy.effective_at):
        hard_fail.append("policy_not_effective")
    if not candidate.candidate_id or not _is_sha256(candidate.sequence_sha256):
        hard_fail.append("invalid_candidate_identity")
    if not candidate.construct_id or not candidate.batch_id:
        hard_fail.append("incomplete_candidate_identity")

    by_assay: dict[str, list[AssayReceipt]] = {}
    for receipt in receipts:
        by_assay.setdefault(receipt.assay_type, []).append(receipt)

    used: list[dict[str, Any]] = []
    for rule in policy.rules:
        matches = by_assay.get(rule.assay_type, [])
        if not matches:
            uncertain.append(f"missing:{rule.assay_type}")
            continue
        if len(matches) != 1:
            hard_fail.append(f"ambiguous_receipts:{rule.assay_type}")
            continue

        r = matches[0]
        used.append(r.__dict__)

        if (
            r.candidate_id != candidate.candidate_id
            or r.sequence_sha256 != candidate.sequence_sha256
            or r.construct_id != candidate.construct_id
            or r.batch_id != candidate.batch_id
        ):
            hard_fail.append(f"identity_mismatch:{rule.assay_type}")
            continue
        if r.target != policy.target:
            hard_fail.append(f"target_mismatch:{rule.assay_type}")
            continue
        if r.units != rule.units:
            hard_fail.append(f"units_mismatch:{rule.assay_type}")
            continue
        if rule.acceptable_methods and r.method not in rule.acceptable_methods:
            hard_fail.append(f"unacceptable_method:{rule.assay_type}")
            continue
        if rule.acceptable_evidence_classes and r.evidence_class not in rule.acceptable_evidence_classes:
            hard_fail.append(f"unacceptable_evidence_class:{rule.assay_type}")
            continue
        if not r.method_version:
            hard_fail.append(f"missing_method_version:{rule.assay_type}")
            continue
        if not r.verifier:
            hard_fail.append(f"missing_verifier:{rule.assay_type}")
            continue
        if not _is_sha256(r.raw_evidence_sha256):
            hard_fail.append(f"invalid_evidence_hash:{rule.assay_type}")
            continue
        if r.status == "REVOKED":
            hard_fail.append(f"revoked:{rule.assay_type}")
            continue
        if r.status == "UNKNOWN" or r.measurement is None:
            uncertain.append(f"unknown:{rule.assay_type}")
            continue
        if r.status != "CURRENT":
            hard_fail.append(f"invalid_status:{rule.assay_type}")
            continue

        observed = _parse_time(r.observed_at)
        if observed > now:
            hard_fail.append(f"future_evidence:{rule.assay_type}")
            continue
        if rule.max_age_days is not None and (now - observed).total_seconds() > rule.max_age_days * 86400:
            uncertain.append(f"stale:{rule.assay_type}")
            continue
        if not _passes(float(r.measurement), rule.operator, rule.threshold):
            hard_fail.append(f"threshold_fail:{rule.assay_type}")

    if hard_fail:
        decision = PromotionDecision.DENY
        flags = tuple(sorted(set(hard_fail + uncertain)))
    elif uncertain:
        decision = PromotionDecision.QUARANTINE
        flags = tuple(sorted(set(uncertain)))
    else:
        decision = PromotionDecision.COMMIT
        flags = ()

    evidence_sha256 = _canonical_hash({
        "candidate": candidate.__dict__,
        "used_receipts": sorted(used, key=lambda x: x["assay_type"]),
        "decision_time": decision_time,
    })
    return PromotionResult(
        decision=decision,
        candidate_id=candidate.candidate_id,
        policy_id=policy.policy_id,
        policy_version=policy.version,
        policy_sha256=policy.policy_sha256,
        flags=flags,
        evidence_sha256=evidence_sha256,
    )


def policy_from_dict(data: Mapping[str, Any]) -> PromotionPolicy:
    rules = tuple(
        DimensionRule(
            assay_type=str(r["assay_type"]),
            operator=str(r["operator"]),
            threshold=float(r["threshold"]),
            units=str(r["units"]),
            acceptable_methods=tuple(str(x) for x in r.get("acceptable_methods", [])),
            acceptable_evidence_classes=tuple(str(x) for x in r.get("acceptable_evidence_classes", ["INDEPENDENT_ASSAY"])),
            max_age_days=(None if r.get("max_age_days") is None else int(r["max_age_days"])),
        )
        for r in data["rules"]
    )
    return PromotionPolicy(
        policy_id=str(data["policy_id"]),
        version=str(data["version"]),
        effective_at=str(data["effective_at"]),
        target=str(data["target"]),
        rules=rules,
        missing_evidence=str(data.get("missing_evidence", "QUARANTINE")),
    )



def to_receipt_gate_policy_mapping(
    *,
    policy: PromotionPolicy,
    candidate: CandidateIdentity,
) -> dict[str, Any]:
    """Compile the domain profile into the existing Receipt Gate PolicySpec shape.

    The existing proof-to-policy gateway remains the signed decision authority.
    This compiler supplies deterministic evidence assertions and requires trusted,
    independent, source-bound evidence plus replay protection.
    """
    required_ids: list[str] = []
    assertions: list[dict[str, Any]] = []
    op_map = {"<=": "lte", ">=": "gte"}
    for rule in policy.rules:
        if rule.operator not in op_map:
            raise ValueError("Receipt Gate evidence assertions support <= and >= for candidate promotion")
        evidence_id = f"candidate_assay:{rule.assay_type}"
        required_ids.append(evidence_id)
        for path, value in (
            ("candidate_id", candidate.candidate_id),
            ("sequence_sha256", candidate.sequence_sha256),
            ("construct_id", candidate.construct_id),
            ("batch_id", candidate.batch_id),
            ("target", policy.target),
            ("assay_type", rule.assay_type),
            ("units", rule.units),
            ("status", "CURRENT"),
        ):
            assertions.append({"evidence_id": evidence_id, "path": path, "op": "equals", "value": value})
        if rule.acceptable_methods:
            assertions.append({"evidence_id": evidence_id, "path": "method", "op": "in", "value": list(rule.acceptable_methods)})
        if rule.acceptable_evidence_classes:
            assertions.append({"evidence_id": evidence_id, "path": "evidence_class", "op": "in", "value": list(rule.acceptable_evidence_classes)})
        assertions.append({"evidence_id": evidence_id, "path": "measurement", "op": op_map[rule.operator], "value": rule.threshold})

    return {
        "policy_id": policy.policy_id,
        "version": policy.version,
        "require_trusted_source": True,
        "require_independent_source": True,
        "require_declared_coverage": True,
        "require_replay_guard": True,
        "require_evidence": True,
        "require_source_bound_evidence": True,
        "required_evidence_ids": required_ids,
        "evidence_assertions": assertions,
        "metadata": {
            "profile": "candidate_promotion",
            "candidate_id": candidate.candidate_id,
            "sequence_sha256": candidate.sequence_sha256,
            "construct_id": candidate.construct_id,
            "batch_id": candidate.batch_id,
            "candidate_promotion_policy_sha256": policy.policy_sha256,
            "missing_evidence_behavior": "QUARANTINE",
            "ranker_authority": "ADVISORY_ONLY",
        },
    }

def candidate_from_dict(data: Mapping[str, Any]) -> CandidateIdentity:
    return CandidateIdentity(
        candidate_id=str(data["candidate_id"]),
        sequence_sha256=str(data["sequence_sha256"]),
        construct_id=str(data["construct_id"]),
        batch_id=str(data["batch_id"]),
    )


def receipts_from_dicts(items: Iterable[Mapping[str, Any]]) -> tuple[AssayReceipt, ...]:
    return tuple(
        AssayReceipt(
            candidate_id=str(r["candidate_id"]),
            sequence_sha256=str(r["sequence_sha256"]),
            construct_id=str(r["construct_id"]),
            batch_id=str(r["batch_id"]),
            target=str(r["target"]),
            assay_type=str(r["assay_type"]),
            measurement=(None if r.get("measurement") is None else float(r["measurement"])),
            units=str(r["units"]),
            method=str(r["method"]),
            method_version=str(r.get("method_version", "")),
            verifier=str(r.get("verifier", "")),
            observed_at=str(r["observed_at"]),
            raw_evidence_sha256=str(r["raw_evidence_sha256"]),
            evidence_class=str(r.get("evidence_class", "INDEPENDENT_ASSAY")),
            status=str(r.get("status", "CURRENT")),
        )
        for r in items
    )
