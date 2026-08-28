#!/usr/bin/env python3
"""Independent stdlib-only verifier; imports neither runner nor Gate code."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

EXP = Path(__file__).resolve().parents[1]


def load(path: str) -> dict[str, Any]:
    return json.loads((EXP / path).read_text(encoding="utf-8"))


def canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def file_hash(path: str) -> str:
    return hashlib.sha256((EXP / path).read_bytes()).hexdigest()


def relation(left: str, right: str) -> str:
    return "EQUAL" if left == right else "DISTINCT"


def outcome(expected: str, observed: str) -> str:
    if expected == observed:
        return "PASS"
    return "FALSE_COLLISION" if expected == "DISTINCT" else "FALSE_SPLIT"


def effect_identity(proposal: dict[str, Any]) -> str:
    return digest(
        {
            "settings": proposal["settings"],
            "state_hash": proposal["state_hash"],
            "target": proposal["target"],
            "tool": proposal["tool"],
        }
    )


def expected_row(case: dict[str, Any], arm: str) -> dict[str, Any]:
    if arm == "paper_failed_identity":
        left = digest(case["failed_identity"]["left"])
        right = digest(case["failed_identity"]["right"])
    elif arm == "current_receipt_gate_effect_binding":
        left = effect_identity(case["left"])
        right = effect_identity(case["right"])
    else:
        raise ValueError("arm_invalid")
    observed = relation(left, right)
    expected = case["expected_relation"]
    return {
        "arm": arm,
        "case_id": case["case_id"],
        "expected_relation": expected,
        "left_identity": left,
        "observed_relation": observed,
        "oracle_match": observed == expected,
        "outcome": outcome(expected, observed),
        "paper_subsystem": case["paper_subsystem"],
        "right_identity": right,
    }


def main() -> int:
    errors: list[str] = []
    fixture = load("fixtures/cases.json")
    oracle = load("oracle.json")
    result = load("result.json")
    lock = load("DESIGN_LOCK.json")

    for path, expected in lock["files"].items():
        if file_hash(path) != expected:
            errors.append("design_lock_mismatch:" + path)
    if len(fixture.get("cases", [])) != 5:
        errors.append("case_count_invalid")
    if oracle.get("cases") != {
        case["case_id"]: case["expected_relation"] for case in fixture["cases"]
    }:
        errors.append("oracle_fixture_mismatch")

    arms = ["paper_failed_identity", "current_receipt_gate_effect_binding"]
    expected_rows = [
        expected_row(case, arm)
        for case in sorted(fixture["cases"], key=lambda item: item["case_id"])
        for arm in arms
    ]
    if result.get("rows") != expected_rows:
        errors.append("serialized_rows_mismatch")

    summaries: dict[str, dict[str, int]] = {}
    for arm in arms:
        rows = [row for row in expected_rows if row["arm"] == arm]
        summaries[arm] = {
            "false_collisions": sum(row["outcome"] == "FALSE_COLLISION" for row in rows),
            "false_splits": sum(row["outcome"] == "FALSE_SPLIT" for row in rows),
            "oracle_matches": sum(bool(row["oracle_match"]) for row in rows),
            "total": len(rows),
        }
    if result.get("summaries") != summaries:
        errors.append("summary_mismatch")

    control_matches = summaries["paper_failed_identity"]["oracle_matches"]
    current_matches = summaries["current_receipt_gate_effect_binding"]["oracle_matches"]
    if control_matches != 0:
        verdict = "INVALID_REPRODUCTION_CONTROL"
    elif current_matches == 5:
        verdict = "CURRENT_EFFECT_BINDING_COVERS_ALL_FIVE_CASES"
    else:
        verdict = "SEMANTIC_IDENTITY_GAP_DETECTED"
    if result.get("verdict") != verdict:
        errors.append("verdict_mismatch")
    if result.get("experiment_valid") != (verdict != "INVALID_REPRODUCTION_CONTROL"):
        errors.append("validity_mismatch")
    if result.get("fixture_sha256") != file_hash("fixtures/cases.json"):
        errors.append("fixture_hash_mismatch")
    if result.get("oracle_sha256") != file_hash("oracle.json"):
        errors.append("oracle_hash_mismatch")
    if result.get("design_lock_sha256") != file_hash("DESIGN_LOCK.json"):
        errors.append("design_lock_hash_mismatch")

    report = {
        "errors": errors,
        "paper_failed_identity_errors": 5 - control_matches,
        "production_oracle_matches": current_matches,
        "valid": not errors,
        "verified_rows": len(expected_rows),
        "verified_verdict": verdict,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())

