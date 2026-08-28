"""Evaluate the frozen Agent Mesh identity pairs against existing Gate code."""
from __future__ import annotations

from typing import Any, Mapping

from olp_gate.authority_link import canonical_hash, effect_hash


def identity_relation(left: str, right: str) -> str:
    return "EQUAL" if left == right else "DISTINCT"


def _outcome(expected: str, observed: str) -> str:
    if observed == expected:
        return "PASS"
    if expected == "DISTINCT" and observed == "EQUAL":
        return "FALSE_COLLISION"
    if expected == "EQUAL" and observed == "DISTINCT":
        return "FALSE_SPLIT"
    raise ValueError("identity_relation_invalid")


def _identities(case: Mapping[str, Any], arm: str) -> tuple[str, str]:
    if arm == "paper_failed_identity":
        failed = case["failed_identity"]
        return canonical_hash(failed["left"]), canonical_hash(failed["right"])
    if arm == "current_receipt_gate_effect_binding":
        return effect_hash(case["left"]), effect_hash(case["right"])
    raise ValueError(f"unknown_arm:{arm}")


def evaluate_case(case: Mapping[str, Any], arm: str) -> dict[str, Any]:
    left, right = _identities(case, arm)
    expected = str(case["expected_relation"])
    observed = identity_relation(left, right)
    return {
        "arm": arm,
        "case_id": str(case["case_id"]),
        "expected_relation": expected,
        "left_identity": left,
        "observed_relation": observed,
        "oracle_match": observed == expected,
        "outcome": _outcome(expected, observed),
        "paper_subsystem": str(case["paper_subsystem"]),
        "right_identity": right,
    }

