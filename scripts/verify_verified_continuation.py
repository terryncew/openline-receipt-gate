#!/usr/bin/env python3
"""Independent stdlib-only verifier for the frozen continuation fixture.

This script deliberately does not import ``olp_gate`` or the benchmark runner.
It verifies the frozen source closure, recomputes the direct lane counts, and
confirms that synthetic data was not upgraded into a continuation claim.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / "benchmarks" / "verified_continuation"
LANES = ("self_summary", "no_prior_state", "olp_capsule")
FROZEN_TRIAL_SPEC_HASH = (
    "549bba4c904261cb7513e3e9d618941bc51184e8ec3fe5bc8dd75afe7b67c271"
)
EXPECTED_OUTCOMES = {
    "self_summary": {
        "tool_calls": 9,
        "repeated_exploration": 3,
        "trace_errors": 1,
        "terminal_defects": 1,
        "budget_max_tool_calls": 12,
        "budget_exceeded": False,
    },
    "no_prior_state": {
        "tool_calls": 11,
        "repeated_exploration": 4,
        "trace_errors": 1,
        "terminal_defects": 1,
        "budget_max_tool_calls": 12,
        "budget_exceeded": False,
    },
    "olp_capsule": {
        "tool_calls": 5,
        "repeated_exploration": 0,
        "trace_errors": 0,
        "terminal_defects": 0,
        "budget_max_tool_calls": 12,
        "budget_exceeded": False,
    },
}


def _reject_constant(value: str) -> None:
    raise ValueError(f"nonfinite_json_number:{value}")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate_json_key:{key}")
        value[key] = item
    return value


def load_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=_object_pairs,
        parse_constant=_reject_constant,
    )


def json_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def derive(lane: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, int]]]:
    seen: set[tuple[str, str]] = set()
    repeated = 0
    errors = 0
    trajectory: list[dict[str, int]] = []
    trace = lane["trace"]
    for index, event in enumerate(trace, start=1):
        if event["step"] != index:
            raise ValueError(f"{lane['lane_id']}:trace_not_contiguous")
        if event["kind"] in {"search", "read"}:
            key = (event["kind"], event["target"])
            if key in seen:
                repeated += 1
            else:
                seen.add(key)
        if event["status"] == "error":
            errors += 1
        trajectory.append(
            {
                "step": index,
                "tool_calls": index,
                "repeated_exploration": repeated,
                "errors": errors,
            }
        )
    defects = sum(
        test["status"] == "FAIL" for test in lane["terminal_tests"]
    )
    budget = lane["controls"]["budget"]["max_tool_calls"]
    return (
        {
            "tool_calls": len(trace),
            "repeated_exploration": repeated,
            "trace_errors": errors,
            "terminal_defects": defects,
            "budget_max_tool_calls": budget,
            "budget_exceeded": len(trace) > budget,
        },
        trajectory,
    )


def verify() -> dict[str, Any]:
    errors: list[str] = []
    freeze = load_json(BENCHMARK / "FREEZE.json")
    if freeze.get("schema") != "openline.verified-continuation.freeze.v1":
        errors.append("freeze_schema_invalid")
    files = freeze.get("files")
    if not isinstance(files, dict) or not files:
        return {"valid": False, "errors": ["freeze_files_invalid"]}
    for relative, expected in sorted(files.items()):
        path = ROOT / relative
        if not path.is_file():
            errors.append(f"frozen_file_missing:{relative}")
        elif file_hash(path) != expected:
            errors.append(f"frozen_file_hash_mismatch:{relative}")

    spec = load_json(BENCHMARK / "trial_spec.json")
    lane_values = {
        lane_id: load_json(BENCHMARK / "lanes" / f"{lane_id}.json")
        for lane_id in LANES
    }
    report = load_json(BENCHMARK / "results" / "continuation_report.json")
    projection = load_json(BENCHMARK / "results" / "dsm_projection.json")
    if spec.get("status") != "FROZEN" or spec.get("lanes") != list(LANES):
        errors.append("trial_spec_not_frozen")
    if json_hash(spec) != FROZEN_TRIAL_SPEC_HASH:
        errors.append("trial_spec_hash_mismatch")
    if len({lane["run_id"] for lane in lane_values.values()}) != 3:
        errors.append("lane_run_ids_not_distinct")
    if {lane["evidence_class"] for lane in lane_values.values()} != {
        "synthetic_conformance"
    }:
        errors.append("fixture_evidence_class_invalid")
    if {lane["provider_execution_attested"] for lane in lane_values.values()} != {
        False
    }:
        errors.append("fixture_provider_attestation_invalid")
    controls = [lane["controls"] for lane in lane_values.values()]
    if not all(control == controls[0] for control in controls):
        errors.append("fixture_controls_mismatch")

    outcomes: dict[str, dict[str, Any]] = {}
    trajectories: dict[str, list[dict[str, int]]] = {}
    for lane_id, lane in lane_values.items():
        outcome, trajectory = derive(lane)
        outcomes[lane_id] = outcome
        trajectories[lane_id] = trajectory
    if outcomes != EXPECTED_OUTCOMES:
        errors.append("derived_outcomes_mismatch")
    if report.get("outcomes") != outcomes:
        errors.append("report_outcomes_not_independently_reproduced")
    if report.get("trajectory") != trajectories:
        errors.append("report_trajectory_not_independently_reproduced")

    continuation = report.get("continuation_claim", {})
    if not (
        continuation.get("disposition") == "UNDECIDABLE"
        and continuation.get("mechanism_rule_passed") is True
        and continuation.get("external_evidence_sufficient") is False
        and continuation.get("reason_codes")
        == ["outside_provider_execution_not_established"]
    ):
        errors.append("synthetic_claim_boundary_violated")
    authorization = report.get("authorization_claim", {})
    if authorization.get("disposition") != "NOT_EVALUATED":
        errors.append("authorization_claim_was_conflated")
    report_body = dict(report)
    observed_report_hash = report_body.pop("report_hash", None)
    if observed_report_hash != json_hash(report_body):
        errors.append("continuation_report_hash_invalid")
    if projection.get("report_hash") != observed_report_hash:
        errors.append("dsm_projection_report_hash_mismatch")
    if projection.get("display_only") is not True:
        errors.append("dsm_projection_not_display_only")
    if projection.get("lanes") != trajectories:
        errors.append("dsm_projection_trajectory_mismatch")
    metrics = projection.get("coherence_dynamics", {})
    if not all(
        isinstance(metrics.get(name), dict)
        and metrics[name].get("status") == "UNDECIDABLE"
        for name in ("kappa", "phi_star", "vkd")
    ):
        errors.append("dsm_metric_was_invented")
    return {
        "valid": not errors,
        "errors": sorted(errors),
        "source_closure_file_count": len(files),
        "continuation_disposition": continuation.get("disposition"),
        "mechanism_rule_passed": continuation.get("mechanism_rule_passed"),
        "authorization_disposition": authorization.get("disposition"),
        "report_hash": observed_report_hash,
        "outcomes": outcomes,
    }


if __name__ == "__main__":
    result = verify()
    print(json.dumps(result, indent=2, sort_keys=True))
    raise SystemExit(0 if result["valid"] else 2)
