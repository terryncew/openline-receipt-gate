from __future__ import annotations
import argparse, json
from pathlib import Path

HERE = Path(__file__).resolve().parent
F = json.loads((HERE/"FREEZE.json").read_text())

def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("report"); a=p.parse_args()
    r=json.loads(Path(a.report).read_text())
    errs=[]
    if r.get("experiment")!="RGV-P34": errs.append("wrong experiment")
    if r.get("policy_authority")!="NONE": errs.append("policy_authority changed")
    if r.get("evidence_grade")!="EXPLORATORY_INTERNAL_PILOT": errs.append("evidence grade changed")
    allowed=set(F["verdicts"].values())
    if r.get("verdict") not in allowed: errs.append("unknown verdict")
    if r.get("verdict") != F["verdicts"]["coverage"]:
        c=r.get("cohort",{})
        if c.get("candidate_count") != F["cohort_binding"]["expected_candidate_count"]:
            errs.append("P34 candidate count drift")
        arms=r.get("arms",{})
        for k in ("simple_sequence_descriptor","ginkgo_TAP_feature_linear","RGV","random_matched"):
            if k not in arms: errs.append(f"missing arm:{k}")
        if r.get("verdict")==F["verdicts"]["signal"]:
            m=arms["RGV"]; b=F["pilot_bar"]
            if m["clean_retention"] < b["clean_retention_min"]: errs.append("signal below retention floor")
            if m["experiments_avoided"] < b["experiments_avoided_min"]: errs.append("signal below avoidance floor")
            if m["matched_random_one_sided_hypergeom_p"] > b["matched_random_enrichment_one_sided_p_max"]:
                errs.append("signal fails random enrichment")
            if r["comparison"]["pareto_dominated_by_nonrandom_baselines"]:
                errs.append("signal is Pareto dominated")
    print(json.dumps({"valid":not errs,"errors":errs,"verdict":r.get("verdict")}, indent=2))
    return 0 if not errs else 1

if __name__=="__main__":
    raise SystemExit(main())
