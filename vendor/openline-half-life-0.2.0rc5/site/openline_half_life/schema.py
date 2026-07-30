from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping

from .util import load_jsonl

TURN_SCHEMA = "openline.half-life.turn.v1"
HASH256 = re.compile(r"^[0-9a-f]{64}$")
MEASUREMENT_FIELDS = {
    "kappa_micros",
    "epsilon_micros",
    "delta_hol_micros",
    "phi_star_micros",
    "ucr_micros",
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _micros(value: Any, field: str) -> int:
    _require(isinstance(value, int) and not isinstance(value, bool), f"{field} must be an integer")
    _require(0 <= value <= 1_000_000, f"{field} must be in [0, 1000000]")
    return value


def validate_turn(turn: Mapping[str, Any], expected_turn: int | None = None) -> dict[str, Any]:
    required = {
        "schema",
        "run_id",
        "turn",
        "objective",
        "summary",
        "measurements",
        "claims",
        "evidence",
        "constraints",
        "outcomes",
        "unresolved_questions",
        "cost",
    }
    _require(set(turn) == required, f"turn field mismatch: {sorted(set(turn) ^ required)}")
    _require(turn["schema"] == TURN_SCHEMA, "unsupported turn schema")
    _require(isinstance(turn["run_id"], str) and turn["run_id"], "run_id must be non-empty")
    _require(isinstance(turn["turn"], int) and not isinstance(turn["turn"], bool), "turn must be an integer")
    if expected_turn is not None:
        _require(turn["turn"] == expected_turn, f"turn sequence must be contiguous; expected {expected_turn}")
    _require(isinstance(turn["objective"], str) and turn["objective"], "objective must be non-empty")
    _require(isinstance(turn["summary"], str), "summary must be a string")

    measurements = turn["measurements"]
    _require(isinstance(measurements, Mapping), "measurements must be an object")
    _require(set(measurements) == MEASUREMENT_FIELDS, "measurements must remain separate and complete")
    normalized_measurements = {name: _micros(measurements[name], name) for name in sorted(MEASUREMENT_FIELDS)}

    evidence = turn["evidence"]
    _require(isinstance(evidence, list), "evidence must be an array")
    evidence_ids: set[str] = set()
    for item in evidence:
        _require(isinstance(item, Mapping), "evidence item must be an object")
        _require(set(item) == {"id", "sha256", "observed_turn", "expires_after_turns"}, "evidence field mismatch")
        _require(isinstance(item["id"], str) and item["id"], "evidence id must be non-empty")
        _require(item["id"] not in evidence_ids, "duplicate evidence id within turn")
        evidence_ids.add(item["id"])
        _require(isinstance(item["sha256"], str) and HASH256.fullmatch(item["sha256"]) is not None, "invalid evidence hash")
        _require(
            isinstance(item["observed_turn"], int) and item["observed_turn"] == turn["turn"],
            "evidence observed_turn must equal the containing turn",
        )
        _require(
            isinstance(item["expires_after_turns"], int)
            and not isinstance(item["expires_after_turns"], bool)
            and item["expires_after_turns"] >= 0,
            "invalid evidence expiry",
        )

    claims = turn["claims"]
    _require(isinstance(claims, list), "claims must be an array")
    for claim in claims:
        _require(isinstance(claim, Mapping), "claim must be an object")
        _require(
            set(claim) == {"id", "slot", "value", "material", "support_status", "evidence_refs", "last_verified_turn"},
            "claim field mismatch",
        )
        _require(claim["support_status"] in {"supported", "unsupported", "unresolved"}, "invalid claim support_status")
        _require(isinstance(claim["material"], bool), "claim material must be boolean")
        _require(
            isinstance(claim["evidence_refs"], list)
            and all(isinstance(ref, str) and ref for ref in claim["evidence_refs"]),
            "claim evidence_refs must contain non-empty strings",
        )
        _require(
            isinstance(claim["last_verified_turn"], int)
            and not isinstance(claim["last_verified_turn"], bool)
            and 1 <= claim["last_verified_turn"] <= turn["turn"],
            "claim last_verified_turn must be an existing turn no later than its containing turn",
        )

    constraints = turn["constraints"]
    _require(isinstance(constraints, list), "constraints must be an array")
    for constraint in constraints:
        _require(isinstance(constraint, Mapping), "constraint must be an object")
        _require(
            set(constraint) == {"id", "text", "active", "evidence_refs", "last_verified_turn"},
            "constraint field mismatch",
        )
        _require(isinstance(constraint["active"], bool), "constraint active must be boolean")
        _require(
            isinstance(constraint["evidence_refs"], list)
            and all(isinstance(ref, str) and ref for ref in constraint["evidence_refs"]),
            "constraint evidence_refs must contain non-empty strings",
        )
        _require(
            isinstance(constraint["last_verified_turn"], int)
            and not isinstance(constraint["last_verified_turn"], bool)
            and 1 <= constraint["last_verified_turn"] <= turn["turn"],
            "constraint last_verified_turn must be an existing turn no later than its containing turn",
        )

    outcomes = turn["outcomes"]
    _require(isinstance(outcomes, list), "outcomes must be an array")
    for outcome in outcomes:
        _require(isinstance(outcome, Mapping), "outcome must be an object")
        _require(set(outcome) == {"id", "text", "confirmed", "evidence_refs"}, "outcome field mismatch")
        _require(isinstance(outcome["confirmed"], bool), "outcome confirmed must be boolean")
        _require(
            isinstance(outcome["evidence_refs"], list)
            and all(isinstance(ref, str) and ref for ref in outcome["evidence_refs"]),
            "outcome evidence_refs must contain non-empty strings",
        )

    _require(
        isinstance(turn["unresolved_questions"], list)
        and all(isinstance(item, str) for item in turn["unresolved_questions"]),
        "unresolved_questions must contain strings",
    )
    cost = turn["cost"]
    _require(isinstance(cost, Mapping) and set(cost) == {"input_tokens", "output_tokens"}, "cost field mismatch")
    _require(
        all(isinstance(cost[name], int) and not isinstance(cost[name], bool) and cost[name] >= 0 for name in cost),
        "cost values must be non-negative integers",
    )

    normalized = dict(turn)
    normalized["measurements"] = normalized_measurements
    return normalized


def load_trajectory(path: Path) -> list[dict[str, Any]]:
    rows = load_jsonl(path)
    _require(bool(rows), "trajectory must contain at least one turn")
    run_id = rows[0].get("run_id")
    normalized: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        turn = validate_turn(row, expected_turn=index)
        _require(turn["run_id"] == run_id, "trajectory cannot cross run_id boundaries")
        normalized.append(turn)

    # Evidence IDs are immutable content addresses within a trajectory. A later
    # observation may refresh the same artifact, but may not rebind the ID to a
    # different hash. Keep this at the schema boundary so every downstream
    # consumer receives the same evidence namespace.
    from .evidence import build_evidence_index

    build_evidence_index(normalized)
    return normalized
