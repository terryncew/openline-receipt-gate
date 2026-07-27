"""Observable-state metric proxies for the warning-time fixture.

The functions in this module accept only the disclosed state visible at the
current and previous step. They do not accept a case label, corruption label,
injection step, expected outcome, or bad-action label.

These are deterministic synthetic proxies, not live COLE implementations.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

METRICS = ("kappa_micros", "delta_hol_micros", "vkd_micros")
METRIC_VERSIONS = {
    "kappa_micros": "dsm.observable-kappa-proxy.v2",
    "delta_hol_micros": "dsm.observable-delta-hol-proxy.v2",
    "vkd_micros": "dsm.observable-vkd-proxy.v2",
}


def _jitter(seed: int, step: int, channel: int) -> int:
    digest = hashlib.sha256(f"{seed}:{step}:{channel}".encode("ascii")).digest()
    return int.from_bytes(digest[:2], "big") % 8001 - 4000


def _constraint_conflicts(observation: Mapping[str, Any]) -> int:
    active = {
        str(item.get("slot")): item
        for item in observation.get("constraints", [])
        if item.get("active") is True
    }
    flagged = {
        (str(item.get("claim_id")), str(item.get("constraint_id")))
        for item in observation.get("flagged_contradictions", [])
    }
    count = 0
    for claim in observation.get("claims", []):
        constraint = active.get(str(claim.get("slot")))
        if constraint is None:
            continue
        operator = constraint.get("operator")
        claim_value = claim.get("value")
        constraint_value = constraint.get("value")
        conflict = (
            operator == "equals" and claim_value != constraint_value
        ) or (
            operator == "lte"
            and isinstance(claim_value, int)
            and isinstance(constraint_value, int)
            and claim_value > constraint_value
        )
        pair = (str(claim.get("id")), str(constraint.get("id")))
        if conflict and pair not in flagged:
            count += 1
    return count


def observable_features(
    observation: Mapping[str, Any],
    previous_observation: Mapping[str, Any] | None,
) -> dict[str, int]:
    evidence_ids = set(str(key) for key in observation.get("evidence", {}))
    required_ids = set(str(value) for value in observation.get("required_evidence_ids", []))
    claim_refs = {
        str(ref)
        for claim in observation.get("claims", [])
        if claim.get("material") is True
        for ref in claim.get("evidence_refs", [])
    }
    previous_evidence = set()
    previous_claim_ids = set()
    if previous_observation is not None:
        previous_evidence = set(str(key) for key in previous_observation.get("evidence", {}))
        previous_claim_ids = {
            str(item.get("id")) for item in previous_observation.get("claims", [])
        }
    current_claim_ids = {str(item.get("id")) for item in observation.get("claims", [])}

    return {
        "missing_required_evidence": len(required_ids - evidence_ids),
        "orphaned_material_references": len(claim_refs - evidence_ids),
        "unflagged_constraint_conflicts": _constraint_conflicts(observation),
        "evidence_edges_lost": len(previous_evidence - evidence_ids),
        "claim_nodes_added": len(current_claim_ids - previous_claim_ids),
    }


def metrics_for_observation(
    seed: int,
    step: int,
    observation: Mapping[str, Any],
    previous_observation: Mapping[str, Any] | None,
) -> dict[str, int]:
    """Compute disclosed proxies from observable state only."""

    features = observable_features(observation, previous_observation)
    missing = features["missing_required_evidence"]
    orphaned = features["orphaned_material_references"]
    conflicts = features["unflagged_constraint_conflicts"]
    lost = features["evidence_edges_lost"]
    added = features["claim_nodes_added"]

    return {
        "kappa_micros": (
            96_000
            + _jitter(seed, step, 1)
            + 88_000 * missing
            + 64_000 * orphaned
            + 132_000 * conflicts
            + 48_000 * lost
            + 2_000 * added
        ),
        "delta_hol_micros": (
            61_000
            + _jitter(seed, step, 2)
            + 74_000 * missing
            + 58_000 * orphaned
            + 121_000 * conflicts
            + 72_000 * lost
            + 3_000 * added
        ),
        "vkd_micros": (
            44_000
            + _jitter(seed, step, 3)
            + 126_000 * missing
            + 91_000 * orphaned
            + 103_000 * conflicts
            + 51_000 * lost
            + 1_000 * added
        ),
    }
