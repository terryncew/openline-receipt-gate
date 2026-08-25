from __future__ import annotations
import argparse, json
from pathlib import Path

HERE = Path(__file__).resolve().parent
FREEZE = json.loads((HERE / "FREEZE.json").read_text())
PASS = FREEZE["verdicts"]["pass"]
FAIL = FREEZE["verdicts"]["fail"]
COVERAGE = FREEZE["verdicts"]["coverage"]

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("report")
    a = p.parse_args()
    r = json.loads(Path(a.report).read_text())
    errors = []
    if r.get("experiment") != "RGV-001": errors.append("wrong experiment")
    if r.get("policy_authority") != "NONE": errors.append("policy authority must remain NONE")
    if r.get("verdict") not in {PASS, FAIL, COVERAGE}: errors.append("unknown verdict")
    if r.get("verdict") != COVERAGE:
        arms = r.get("arms", {})
        for key in ("random_matched","simple_sequence_descriptor","ginkgo_TAP_feature_linear","RGV"):
            if key not in arms: errors.append(f"missing arm {key}")
        if r.get("verdict") == PASS:
            m = arms["RGV"]
            b = FREEZE["primary_bar"]
            if m["clean_retention"] < b["external_clean_retention_min"]: errors.append("pass violates clean retention floor")
            if m["experiments_avoided"] < b["external_experiments_avoided_min"]: errors.append("pass violates avoidance floor")
            if r["comparison"]["RGV_margin_over_best_nonrandom_baseline"] < b["margin_over_best_nonrandom_baseline_experiments_avoided"]:
                errors.append("pass violates baseline margin")
            if r["robustness"]["passed"] is not True: errors.append("pass violates robustness")
    print(json.dumps({"valid": not errors, "errors": errors, "verdict": r.get("verdict")}, indent=2))
    return 0 if not errors else 1

if __name__ == "__main__":
    raise SystemExit(main())
