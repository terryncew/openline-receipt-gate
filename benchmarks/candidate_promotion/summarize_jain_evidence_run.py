from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    verdict = report["primary_verdict"]
    summary = {
        "schema": "openline.cpg001.jain_evidence_run_summary.v0.2",
        "experiment_id": "CPG-001",
        "execution_id": os.environ.get("CPG_EXECUTION_ID", "CPG-001-JAIN-EVIDENCE-02"),
        "execution_status": "COMPLETE",
        "scientific_verdict": verdict["verdict"],
        "scientific_verdict_is_ci_verdict": False,
        "claim_scope": report["claim_scope"],
        "affinity_in_scope": report["affinity_in_scope"],
        "complete_case_candidate_count": report["complete_case_candidate_count"],
        "complete_case_coverage_fraction": report["complete_case_coverage_fraction"],
        "folds_with_ge_10pp_reduction": verdict["folds_with_ge_10pp_reduction"],
        "pooled_fill_rate": verdict["pooled_fill_rate"],
        "pooled_control_heldout_flag_rate": verdict["pooled_control_heldout_flag_rate"],
        "pooled_treatment_heldout_flag_rate": verdict["pooled_treatment_heldout_flag_rate"],
        "authority_parity_pass": verdict["authority_parity_pass"],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
