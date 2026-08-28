#!/usr/bin/env python3
"""Run the frozen SARA-SPEC-001 four-arm comparison once."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Callable, Mapping


EXP = Path(__file__).resolve().parents[1]
if str(EXP) not in sys.path:
    sys.path.insert(0, str(EXP))

from sara_spec001 import (  # noqa: E402
    evaluate_broad_recall,
    evaluate_minimal_sara,
    evaluate_openline_recall,
    evaluate_published_sara,
)


RESULT_SCHEMA = "openline.sara_spec_001.result.v1"
EXPERIMENT = "SARA-SPEC-001"
FROZEN_RUN_AT = "2026-08-28T16:30:00Z"


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verify_design_lock() -> None:
    lock = _load(EXP / "DESIGN_LOCK.json")
    for relative, expected in lock["files"].items():
        path = EXP / relative
        if not path.is_file() or _sha(path) != expected:
            raise RuntimeError(f"design_lock_mismatch:{relative}")


def _observed_for_oracle(value: Mapping[str, Any]) -> dict[str, str]:
    return {
        "D1": value["dispositions"]["D1"],
        "D2": value["dispositions"]["D2"],
        "historical_evidence": value["historical_evidence"],
    }


def run() -> dict[str, Any]:
    _verify_design_lock()
    fixture = _load(EXP / "fixtures" / "scenario.json")
    oracle = _load(EXP / "oracle.json")
    prereg = _load(EXP / "preregistration.json")
    arm_functions: dict[str, Callable[[Mapping[str, Any], Mapping[str, Any]], dict[str, Any]]] = {
        "published_sara": evaluate_published_sara,
        "broad_recall": evaluate_broad_recall,
        "minimal_sara_extension": evaluate_minimal_sara,
        "openline_selective_recall": evaluate_openline_recall,
    }
    scored_by_arm = {item["arm_id"]: item["scored"] for item in prereg["arms"]}
    rows: list[dict[str, Any]] = []
    exact: dict[str, bool] = {
        arm_id: True for arm_id, scored in scored_by_arm.items() if scored
    }

    for arm_id, arm_function in arm_functions.items():
        for control in fixture["controls"]:
            observed = arm_function(fixture, control)
            expected = oracle["controls"][control["control_id"]]
            scored = scored_by_arm[arm_id]
            match = _observed_for_oracle(observed) == expected if scored else None
            if scored:
                exact[arm_id] = exact[arm_id] and bool(match)
            rows.append(
                {
                    "arm_id": arm_id,
                    "control_id": control["control_id"],
                    "scored": scored,
                    "exact_oracle_match": match,
                    "expected": expected if scored else None,
                    "observed": observed,
                }
            )

    minimal_rows = [
        row for row in rows if row["arm_id"] == "minimal_sara_extension"
    ]
    budget_ok = all(
        row["observed"]["state_shape"]
        == {
            "persisted_keys": ["F", "H", "K"],
            "extension_keys": ["standing_updates"],
            "new_persistent_structure_count": 0,
            "returns_derived_relationships": False,
        }
        for row in minimal_rows
    )
    openline_exact = exact["openline_selective_recall"]
    minimal_exact = exact["minimal_sara_extension"] and budget_ok
    if not budget_ok:
        verdict = "INCONCLUSIVE_SPEC_RECONSTRUCTION"
    elif not openline_exact:
        verdict = "NO_SELECTIVE_RECALL"
    elif minimal_exact:
        verdict = "SARA_EXTENSION_PARITY"
    else:
        verdict = "POST_TASK_STANDING_RECALL_DISTINCT"

    passed = verdict in {
        "SARA_EXTENSION_PARITY",
        "POST_TASK_STANDING_RECALL_DISTINCT",
    }
    return {
        "schema": RESULT_SCHEMA,
        "experiment_id": EXPERIMENT,
        "run_at_utc": FROZEN_RUN_AT,
        "evidence_tier": "PAPER_SPEC_RECONSTRUCTION",
        "design_lock_sha256": _sha(EXP / "DESIGN_LOCK.json"),
        "source_pin_sha256": _sha(EXP / "SOURCE_PIN.json"),
        "counts": {
            "arms": 4,
            "controls": 2,
            "rows": len(rows),
            "scored_arms": 3,
        },
        "rows": rows,
        "arm_exactness": exact,
        "minimal_extension_budget_valid": budget_ok,
        "published_sara_disposition": "OUT_OF_SCOPE_AFTER_TASK_END",
        "verdict": verdict,
        "passed": passed,
        "openline_novelty_falsifier_triggered": verdict == "SARA_EXTENSION_PARITY",
        "earned_claim": (
            "In this sealed paper-spec reconstruction, persisted SARA K/F/H plus only a K standing update matched OpenLine selective post-task recall: D1 reopened after K1 revocation, D2 was preserved, the no-op changed neither decision, and historical evidence remained unchanged."
            if verdict == "SARA_EXTENSION_PARITY"
            else "See verdict and frozen claim boundary."
        ),
        "claim_boundary": {
            "published_sara_scored_as_failure": False,
            "cold_external_integration": False,
            "agentdojo_agentdyn_reproduced": False,
            "production_code_changed": False,
        },
        "policy_authority": "NONE",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=EXP / "result.json",
    )
    args = parser.parse_args()
    result = run()
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"passed": result["passed"], "verdict": result["verdict"]}, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
