from __future__ import annotations
import argparse, json
from pathlib import Path

HERE = Path(__file__).resolve().parent
F = json.loads((HERE / "FREEZE.json").read_text(encoding="utf-8"))

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("report")
    a = p.parse_args()
    r = json.loads(Path(a.report).read_text(encoding="utf-8"))
    errors = []
    if r.get("experiment") != "RGV-PILOT":
        errors.append("wrong experiment")
    if r.get("policy_authority") != "NONE":
        errors.append("policy_authority changed")
    if r.get("evidence_grade") != "EXPLORATORY_INTERNAL_PILOT":
        errors.append("evidence grade changed")
    if r.get("verdict") not in set(F["verdicts"].values()):
        errors.append("unknown verdict")
    if r.get("source_receipt", {}).get("cohort_rule", {}).get("hard_coded_candidate_count") != "FORBIDDEN":
        errors.append("source-derived cohort invariant missing")
    if r.get("verdict") != F["verdicts"]["coverage"]:
        c = r.get("cohort", {})
        if c.get("candidate_count") != r.get("source_receipt", {}).get("included_candidates"):
            errors.append("reported N does not equal source-derived N")
        arms = r.get("arms", {})
        for k in ("simple_sequence_descriptor", "ginkgo_TAP_feature_linear", "RGV", "random_matched"):
            if k not in arms:
                errors.append(f"missing arm:{k}")
        if r.get("verdict") == F["verdicts"]["signal"]:
            m = arms["RGV"]
            b = F["pilot_bar"]
            if m["clean_retention"] < b["clean_retention_min"]:
                errors.append("signal below clean-retention floor")
            if m["experiments_avoided"] < b["experiments_avoided_min"]:
                errors.append("signal below avoidance floor")
            if m["matched_random_one_sided_hypergeom_p"] > b["matched_random_enrichment_one_sided_p_max"]:
                errors.append("signal fails matched-random enrichment")
            if r["comparison"]["pareto_dominated_by_nonrandom_baselines"]:
                errors.append("signal Pareto dominated")
    print(json.dumps({"valid": not errors, "errors": errors, "verdict": r.get("verdict")}, indent=2))
    return 0 if not errors else 1

if __name__ == "__main__":
    raise SystemExit(main())
