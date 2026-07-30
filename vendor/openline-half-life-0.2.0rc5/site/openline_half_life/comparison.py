from __future__ import annotations

from typing import Any, Mapping

from .util import canonical_json, sha256_bytes


def compare_results(full: Mapping[str, Any], residue: Mapping[str, Any]) -> dict[str, Any]:
    if full["exam_hash"] != residue["exam_hash"]:
        raise ValueError("exam hashes differ")
    fm = full["metrics"]
    rm = residue["metrics"]
    if fm["error_count"] == 0:
        error_reduction_micros = 0
    else:
        error_reduction_micros = (fm["error_count"] - rm["error_count"]) * 1_000_000 // fm["error_count"]
    legitimate_preserved = (
        rm["legitimate_completion_correct"] == rm["legitimate_completion_required"]
        and rm["legitimate_completion_correct"] >= fm["legitimate_completion_correct"]
    )
    passed = (
        legitimate_preserved
        and rm["accuracy_micros"] >= fm["accuracy_micros"]
        and rm["unsupported_claim_count"] <= fm["unsupported_claim_count"]
        and rm["constraint_violation_count"] <= fm["constraint_violation_count"]
        and rm["error_count"] < fm["error_count"]
    )
    body = {
        "schema": "openline.half-life.comparison.v1",
        "exam_hash": full["exam_hash"],
        "same_exam_verified": True,
        "full_history": full,
        "verified_residue": residue,
        "delta": {
            "accuracy_micros": rm["accuracy_micros"] - fm["accuracy_micros"],
            "error_count": rm["error_count"] - fm["error_count"],
            "error_reduction_micros": error_reduction_micros,
            "unsupported_claim_count": rm["unsupported_claim_count"] - fm["unsupported_claim_count"],
            "constraint_violation_count": rm["constraint_violation_count"] - fm["constraint_violation_count"],
            "estimated_input_tokens": rm["estimated_input_tokens"] - fm["estimated_input_tokens"],
        },
        "legitimate_task_completion_preserved": legitimate_preserved,
        "passed": passed,
        "claim_boundary": (
            "This comparison is limited to the disclosed deterministic adapter, fixture, and held-out exam. "
            "It does not establish universal model support."
        ),
    }
    return {**body, "comparison_hash": sha256_bytes(canonical_json(body))}
