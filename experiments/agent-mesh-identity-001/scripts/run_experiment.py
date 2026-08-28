#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

EXP = Path(__file__).resolve().parents[1]
ROOT = EXP.parents[1]
if str(EXP) not in sys.path:
    sys.path.insert(0, str(EXP))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_mesh_identity001 import evaluate_case


def load(path: str) -> dict:
    return json.loads((EXP / path).read_text(encoding="utf-8"))


def file_hash(path: str) -> str:
    return hashlib.sha256((EXP / path).read_bytes()).hexdigest()


def main() -> int:
    fixture = load("fixtures/cases.json")
    oracle = load("oracle.json")
    arms = ["paper_failed_identity", "current_receipt_gate_effect_binding"]
    rows = []
    for case in sorted(fixture["cases"], key=lambda item: item["case_id"]):
        if oracle["cases"].get(case["case_id"]) != case["expected_relation"]:
            raise SystemExit("fixture_oracle_mismatch:" + case["case_id"])
        for arm in arms:
            rows.append(evaluate_case(case, arm))

    summaries = {}
    for arm in arms:
        arm_rows = [row for row in rows if row["arm"] == arm]
        summaries[arm] = {
            "false_collisions": sum(row["outcome"] == "FALSE_COLLISION" for row in arm_rows),
            "false_splits": sum(row["outcome"] == "FALSE_SPLIT" for row in arm_rows),
            "oracle_matches": sum(bool(row["oracle_match"]) for row in arm_rows),
            "total": len(arm_rows),
        }

    control = summaries["paper_failed_identity"]
    current = summaries["current_receipt_gate_effect_binding"]
    if control["oracle_matches"] != 0:
        verdict = "INVALID_REPRODUCTION_CONTROL"
    elif current["oracle_matches"] == len(fixture["cases"]):
        verdict = "CURRENT_EFFECT_BINDING_COVERS_ALL_FIVE_CASES"
    else:
        verdict = "SEMANTIC_IDENTITY_GAP_DETECTED"

    result = {
        "base_commit": "0d5666a1b0097ef2bac316a99cc1834ba73460bf",
        "case_count": len(fixture["cases"]),
        "claim_limit": "Existing effect_hash can represent all five paper-derived identity relations only when the receiver adapter supplies the semantically load-bearing tool, target, settings, and state fields.",
        "design_lock_sha256": file_hash("DESIGN_LOCK.json"),
        "evidence_tier": "PAPER_DERIVED_REGRESSION_FIXTURE_PACK",
        "experiment_id": "Agent-Mesh-Identity-001",
        "experiment_valid": verdict != "INVALID_REPRODUCTION_CONTROL",
        "fixture_sha256": file_hash("fixtures/cases.json"),
        "oracle_sha256": file_hash("oracle.json"),
        "policy_authority": "NONE",
        "production_primitive": "olp_gate.authority_link.effect_hash",
        "rows": rows,
        "schema": "openline.agent_mesh_identity_001.result.v1",
        "summaries": summaries,
        "verdict": verdict,
    }
    (EXP / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"valid": result["experiment_valid"], "verdict": verdict}))
    return 0 if result["experiment_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

