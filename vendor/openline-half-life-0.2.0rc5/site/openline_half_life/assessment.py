from __future__ import annotations

from typing import Any, Mapping, Sequence

from .evidence import build_evidence_index, evidence_is_fresh
from .policy import verify_policy
from .util import canonical_json, sha256_bytes
from .vendor.openline_endurance_gate import succession as canonical


def _current_material_staleness(turns: Sequence[Mapping[str, Any]], current: Mapping[str, Any]) -> list[str]:
    index = build_evidence_index(turns, through_turn=int(current["turn"]))
    stale: list[str] = []
    for claim in current["claims"]:
        if not claim["material"] or claim["support_status"] != "supported":
            continue
        refs = claim["evidence_refs"]
        if not refs or any(ref not in index or not evidence_is_fresh(index[ref], int(current["turn"])) for ref in refs):
            stale.append(claim["id"])
    return stale

def assess_trajectory(
    turns: Sequence[Mapping[str, Any]],
    policy: Mapping[str, Any],
    *,
    expected_policy_public_keys: set[str] | None = None,
) -> list[dict[str, Any]]:
    verification = verify_policy(policy, expected_policy_public_keys)
    if not verification["valid"]:
        raise ValueError("policy verification failed: " + ",".join(verification["reason_codes"]))

    persistence = policy["persistence"]
    minimum = persistence["minimum_metric_breaches"]
    window = persistence["persistence_window"]
    required = persistence["persistence_required"]
    recent_signals: list[bool] = []
    assessments: list[dict[str, Any]] = []

    for turn in turns:
        values = {metric: turn["measurements"][metric] for metric in canonical.METRICS}
        row = {"values": values}
        votes = canonical._metric_votes(row, policy["thresholds"])
        signal = sum(votes.values()) >= minimum
        recent_signals.append(signal)
        recent = recent_signals[-window:]

        stale_material = _current_material_staleness(turns, turn)
        ucr = turn["measurements"]["ucr_micros"]
        support_complete = ucr == 0 and not stale_material
        persistence_met = len(recent) == window and sum(recent) >= required

        if not support_complete:
            mark = "WATCH"
            disposition = "insufficient_evidence"
            reasons = []
            if ucr != 0:
                reasons.append("UNSUPPORTED_MATERIAL_PRESENT")
            if stale_material:
                reasons.append("STALE_MATERIAL_EVIDENCE")
        elif persistence_met:
            mark = "RETIRE"
            disposition = "succession_candidate"
            reasons = ["CALIBRATED_PERSISTENCE_RULE_MET"]
        elif signal:
            mark = "WATCH"
            disposition = "prepare_handoff"
            reasons = ["CHECKPOINT_SIGNAL_WITHOUT_REQUIRED_PERSISTENCE"]
        else:
            mark = "KEEP"
            disposition = "continue_observation"
            reasons = ["CALIBRATED_PERSISTENCE_RULE_NOT_MET"]

        metrics: dict[str, Any] = {}
        for metric, direction in canonical.METRICS.items():
            spec = policy["thresholds"][metric]
            metrics[metric] = {
                "value_micros": values[metric],
                "threshold_micros": spec["threshold_micros"],
                "direction": direction,
                "breached": votes[metric],
            }
        metrics["ucr_micros"] = {
            "value_micros": ucr,
            "threshold_micros": 0,
            "direction": "must_equal",
            "breached": ucr != 0,
            "role": "separate_evidence_gate_not_health_score",
        }
        body = {
            "schema": "openline.half-life.turn-assessment.v1",
            "run_id": turn["run_id"],
            "turn": turn["turn"],
            "mark": mark,
            "disposition": disposition,
            "reason_codes": reasons,
            "metrics": metrics,
            "metric_breach_count": sum(votes.values()),
            "minimum_metric_breaches": minimum,
            "evidence_sufficiency": {
                "support_complete": support_complete,
                "stale_material_claim_ids": stale_material,
                "ucr_micros": ucr,
            },
            "persistence": {
                "window": window,
                "required": required,
                "observed": sum(recent),
                "recent_checkpoint_signals": recent,
            },
            "automatic_retirement_authorized": False,
            "receiver_approval_required": True,
            "policy_hash": policy["payload_hash"],
        }
        assessments.append({**body, "assessment_hash": sha256_bytes(canonical_json(body))})
    return assessments


def first_retirement_turn(assessments: Sequence[Mapping[str, Any]]) -> int | None:
    for assessment in assessments:
        if assessment["mark"] == "RETIRE":
            return int(assessment["turn"])
    return None
