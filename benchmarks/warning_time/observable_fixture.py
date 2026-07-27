"""Deterministic observable state for the warning-time benchmark.

The corruption selector is used only by the experiment fixture to mutate the
observable record. Metric code never receives the selector, the ground-truth
case label, or the injection step.
"""

from __future__ import annotations

import copy
import hashlib
from typing import Any, Mapping

CORRUPTIONS = ("dropped_counterevidence", "unflagged_contradiction")


def _content_hash(seed: int, label: str) -> str:
    return hashlib.sha256(f"{seed}:{label}".encode("utf-8")).hexdigest()


def _base_state(seed: int, step: int) -> dict[str, Any]:
    evidence: dict[str, dict[str, Any]] = {
        "primary_assessment": {
            "sha256": _content_hash(seed, "primary_assessment"),
            "kind": "primary_evidence",
            "fresh_at_step": step,
        }
    }
    required = ["primary_assessment"]
    if step >= 2:
        evidence["counter_assessment"] = {
            "sha256": _content_hash(seed, "counter_assessment"),
            "kind": "counter_evidence",
            "fresh_at_step": step,
        }
        required.append("counter_assessment")

    claims: list[dict[str, Any]] = []
    if step >= 3:
        claims.append({
            "id": "deployment_region_claim",
            "slot": "deployment_region",
            "value": "us-west",
            "material": True,
            "evidence_refs": list(required),
        })
    if step >= 4:
        claims.append({
            "id": "budget_claim",
            "slot": "budget_limit_usd",
            "value": 100000,
            "material": True,
            "evidence_refs": ["primary_assessment"],
        })

    state: dict[str, Any] = {
        "schema": "openline.warning-time.observable-state.v1",
        "required_evidence_ids": required,
        "evidence": evidence,
        "claims": claims,
        "constraints": [
            {
                "id": "region_constraint",
                "slot": "deployment_region",
                "operator": "equals",
                "value": "us-west",
                "active": True,
            },
            {
                "id": "budget_constraint",
                "slot": "budget_limit_usd",
                "operator": "lte",
                "value": 100000,
                "active": True,
            },
        ],
        "flagged_contradictions": [],
        "unresolved_questions": [
            "Does the fallback region preserve the same privacy boundary?"
        ],
        "completed_events": [
            f"step_{index}" for index in range(1, step + 1)
        ],
    }
    return state


def observable_state_for_step(
    seed: int,
    step: int,
    *,
    corruption: str | None,
    injection_step: int,
) -> dict[str, Any]:
    """Return the record visible to the metric and gate layers.

    ``corruption`` is experiment control input. It is not included in the
    returned state and is never passed to the metric function.
    """

    if corruption is not None and corruption not in CORRUPTIONS:
        raise ValueError(f"unsupported corruption: {corruption}")
    state = copy.deepcopy(_base_state(seed, step))
    if corruption is None or step < injection_step:
        return state

    if corruption == "dropped_counterevidence":
        state["evidence"].pop("counter_assessment", None)
        # Preserve the declared requirement and claim reference. The observable
        # inconsistency is the signal; no hidden case marker is added.
    elif corruption == "unflagged_contradiction":
        state["claims"].append({
            "id": "conflicting_region_claim",
            "slot": "deployment_region",
            "value": "eu-central",
            "material": True,
            "evidence_refs": ["primary_assessment"],
        })
        # The contradiction is intentionally not added to flagged_contradictions.
    return state


def gate_observation(state: Mapping[str, Any]) -> dict[str, Any]:
    """Project raw observable state into the Receipt Gate evidence artifact."""

    evidence_ids = set(str(key) for key in state.get("evidence", {}))
    required_ids = set(str(value) for value in state.get("required_evidence_ids", []))
    missing_required = sorted(required_ids - evidence_ids)

    active_constraints = {
        str(item["slot"]): item
        for item in state.get("constraints", [])
        if item.get("active") is True
    }
    unflagged_conflicts: list[dict[str, Any]] = []
    flagged = {
        (str(item.get("claim_id")), str(item.get("constraint_id")))
        for item in state.get("flagged_contradictions", [])
    }
    for claim in state.get("claims", []):
        constraint = active_constraints.get(str(claim.get("slot")))
        if constraint is None:
            continue
        operator = constraint.get("operator")
        value = claim.get("value")
        allowed = constraint.get("value")
        conflict = (
            operator == "equals" and value != allowed
        ) or (
            operator == "lte" and isinstance(value, int) and value > int(allowed)
        )
        pair = (str(claim.get("id")), str(constraint.get("id")))
        if conflict and pair not in flagged:
            unflagged_conflicts.append({
                "claim_id": pair[0],
                "constraint_id": pair[1],
            })

    return {
        "counterevidence_present": "counter_assessment" in evidence_ids,
        "claim_consistent": not unflagged_conflicts,
        "required_constraint_preserved": True,
        "missing_required_evidence_ids": missing_required,
        "unflagged_conflicts": unflagged_conflicts,
        "observable_state_sha256": hashlib.sha256(
            repr(sorted((str(key), repr(value)) for key, value in state.items())).encode("utf-8")
        ).hexdigest(),
    }
