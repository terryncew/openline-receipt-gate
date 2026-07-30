from __future__ import annotations

from typing import Any, Mapping, Sequence

from .evidence import build_evidence_index, evidence_is_fresh
from .schema import validate_turn
from .util import canonical_json, sha256_bytes


def _packet(body: dict[str, Any]) -> dict[str, Any]:
    return {**body, "packet_hash": sha256_bytes(canonical_json(body))}


def build_full_history_handoff(
    turns: Sequence[Mapping[str, Any]],
    retirement_turn: int,
    policy_hash: str,
) -> dict[str, Any]:
    normalized = [validate_turn(turn, expected_turn=index) for index, turn in enumerate(turns, 1)]
    selected = [dict(turn) for turn in normalized if turn["turn"] <= retirement_turn]
    if not selected or selected[-1]["turn"] != retirement_turn:
        raise ValueError("retirement turn is not present in the trajectory")
    body = {
        "schema": "openline.half-life.full-history-handoff.v1",
        "handoff_type": "full_history",
        "run_id": selected[0]["run_id"],
        "retirement_turn": retirement_turn,
        "policy_hash": policy_hash,
        "resolution_policy": {
            "claims": "frequency_then_recency",
            "constraints": "latest_turn_only",
            "outcomes": "latest_observation_by_id",
        },
        "turns": selected,
    }
    return _packet(body)


def _references_are_fresh(
    refs: Sequence[str],
    evidence_index: Mapping[str, Mapping[str, object]],
    at_turn: int,
) -> bool:
    return bool(refs) and all(
        ref in evidence_index and evidence_is_fresh(evidence_index[ref], at_turn)
        for ref in refs
    )


def build_verified_residue_handoff(
    turns: Sequence[Mapping[str, Any]],
    retirement_turn: int,
    policy_hash: str,
) -> dict[str, Any]:
    normalized = [validate_turn(turn, expected_turn=index) for index, turn in enumerate(turns, 1)]
    selected = [turn for turn in normalized if turn["turn"] <= retirement_turn]
    if not selected or selected[-1]["turn"] != retirement_turn:
        raise ValueError("retirement turn is not present in the trajectory")
    evidence_index = build_evidence_index(selected, through_turn=retirement_turn)

    supported_by_slot: dict[str, Mapping[str, Any]] = {}
    excluded_claims: list[dict[str, Any]] = []
    for turn in selected:
        for claim in turn["claims"]:
            refs = claim["evidence_refs"]
            reason = None
            if claim["support_status"] != "supported":
                reason = "unsupported_or_unresolved"
            elif not refs:
                reason = "missing_evidence_reference"
            elif any(ref not in evidence_index for ref in refs):
                reason = "missing_evidence_artifact"
            elif not _references_are_fresh(refs, evidence_index, retirement_turn):
                reason = "stale_evidence"
            if reason is not None:
                excluded_claims.append({"claim_id": claim["id"], "slot": claim["slot"], "reason": reason})
                continue
            current = supported_by_slot.get(claim["slot"])
            if current is None or claim["last_verified_turn"] >= current["last_verified_turn"]:
                supported_by_slot[claim["slot"]] = claim

    constraints_by_id: dict[str, Mapping[str, Any]] = {}
    for turn in selected:
        for constraint in turn["constraints"]:
            current = constraints_by_id.get(constraint["id"])
            if current is None or constraint["last_verified_turn"] >= current["last_verified_turn"]:
                constraints_by_id[constraint["id"]] = constraint
    current_constraints = [
        dict(constraint)
        for constraint in constraints_by_id.values()
        if constraint["active"]
        and _references_are_fresh(constraint["evidence_refs"], evidence_index, retirement_turn)
    ]

    # Outcomes are state transitions, not append-only facts. The latest event for
    # an outcome ID wins, including an explicit confirmed=false retraction.
    latest_outcomes: dict[str, tuple[int, Mapping[str, Any]]] = {}
    for turn in selected:
        for outcome in turn["outcomes"]:
            latest_outcomes[outcome["id"]] = (int(turn["turn"]), outcome)

    confirmed_outcomes: list[dict[str, Any]] = []
    excluded_outcomes: list[dict[str, Any]] = []
    for outcome_id, (observed_turn, outcome) in latest_outcomes.items():
        refs = outcome["evidence_refs"]
        if not outcome["confirmed"]:
            excluded_outcomes.append(
                {"outcome_id": outcome_id, "observed_turn": observed_turn, "reason": "retracted"}
            )
        elif not refs:
            excluded_outcomes.append(
                {"outcome_id": outcome_id, "observed_turn": observed_turn, "reason": "missing_evidence_reference"}
            )
        elif any(ref not in evidence_index for ref in refs):
            excluded_outcomes.append(
                {"outcome_id": outcome_id, "observed_turn": observed_turn, "reason": "missing_evidence_artifact"}
            )
        elif not _references_are_fresh(refs, evidence_index, retirement_turn):
            excluded_outcomes.append(
                {"outcome_id": outcome_id, "observed_turn": observed_turn, "reason": "stale_evidence"}
            )
        else:
            confirmed_outcomes.append(dict(outcome))

    unresolved: list[str] = []
    for turn in selected:
        for question in turn["unresolved_questions"]:
            if question not in unresolved:
                unresolved.append(question)

    used_refs = {
        ref
        for claim in supported_by_slot.values()
        for ref in claim["evidence_refs"]
    } | {
        ref
        for constraint in current_constraints
        for ref in constraint["evidence_refs"]
    } | {
        ref
        for outcome in confirmed_outcomes
        for ref in outcome["evidence_refs"]
    }

    body = {
        "schema": "openline.half-life.verified-residue-handoff.v1",
        "handoff_type": "verified_residue",
        "run_id": selected[0]["run_id"],
        "retirement_turn": retirement_turn,
        "generation_index": 1,
        "parent_hash": sha256_bytes(canonical_json(selected)),
        "policy_hash": policy_hash,
        "objective": selected[-1]["objective"],
        "supported_claims": sorted((dict(item) for item in supported_by_slot.values()), key=lambda item: item["slot"]),
        "current_constraints": sorted(current_constraints, key=lambda item: item["id"]),
        "confirmed_outcomes": sorted(confirmed_outcomes, key=lambda item: item["id"]),
        "unresolved_questions": unresolved,
        "evidence_references": sorted((dict(evidence_index[ref]) for ref in used_refs), key=lambda item: item["id"]),
        "excluded_claims": sorted(excluded_claims, key=lambda item: (item["slot"], item["claim_id"])),
        "excluded_outcomes": sorted(excluded_outcomes, key=lambda item: item["outcome_id"]),
        "uncertainty_policy": (
            "Unsupported, unresolved, missing, stale, or retracted material is excluded rather than promoted."
        ),
    }
    return _packet(body)
