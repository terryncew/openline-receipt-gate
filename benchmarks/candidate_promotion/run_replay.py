from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from olp_gate.candidate_promotion import candidate_from_dict, evaluate_candidate, policy_from_dict, receipts_from_dicts


def passes(value, operator, threshold):
    return {">=": value >= threshold, ">": value > threshold, "<=": value <= threshold, "<": value < threshold}[operator]


def run(profile_path: Path, data_path: Path) -> dict:
    policy = policy_from_dict(json.loads(profile_path.read_text()))
    dataset = json.loads(data_path.read_text())
    rows = sorted(dataset["candidates"], key=lambda x: float(x["rank_score"]), reverse=True)
    top_k = int(dataset["top_k"])

    decisions = {}
    for row in rows:
        result = evaluate_candidate(
            candidate=candidate_from_dict(row),
            receipts=receipts_from_dicts(row["receipts"]),
            policy=policy,
            decision_time=dataset["decision_time"],
        )
        decisions[row["candidate_id"]] = result.as_dict()

    control = rows[:top_k]
    commits = [r for r in rows if decisions[r["candidate_id"]]["decision"] == "COMMIT"]
    treatment = commits[:top_k]

    def declared_liability(row):
        flags = decisions[row["candidate_id"]]["flags"]
        return any(f.startswith("threshold_fail:") for f in flags)

    heldout = dataset["heldout"]
    def heldout_pass_rate(selected):
        if not selected:
            return None
        return sum(passes(float(r["heldout_value"]), heldout["operator"], float(heldout["threshold"])) for r in selected) / len(selected)

    return {
        "schema": "openline.cpg001.run.v0.1",
        "policy_sha256": policy.policy_sha256,
        "candidate_count": len(rows),
        "top_k": top_k,
        "decisions": decisions,
        "control": {
            "selected": [r["candidate_id"] for r in control],
            "masked_declared_liabilities_promoted": sum(declared_liability(r) for r in control),
            "top_k_fill_rate": len(control) / top_k,
            "heldout_assay_pass_rate": heldout_pass_rate(control),
        },
        "treatment": {
            "selected": [r["candidate_id"] for r in treatment],
            "masked_declared_liabilities_promoted": sum(declared_liability(r) for r in treatment),
            "top_k_fill_rate": len(treatment) / top_k,
            "eligible_candidate_yield": len(commits) / len(rows),
            "heldout_assay_pass_rate": heldout_pass_rate(treatment),
        },
    }


def main():
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", type=Path, default=here / "PROFILE.synthetic.json")
    ap.add_argument("--data", type=Path, default=here / "fixtures" / "synthetic.json")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    result = run(args.profile, args.data)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(text)
    print(text, end="")

if __name__ == "__main__":
    main()
