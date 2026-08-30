from __future__ import annotations
from pathlib import Path
import csv, hashlib, json

def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def _write(rows, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ["context_id","action_id","lag","target_id","constraint_set_id","trial_id","outcome_success"]
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

def generate(outdir: Path) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    good, one_action, no_remedy = [], [], []

    for i in range(60):
        cid = f"ctx-{i:03d}"
        for action in ("A","B","C"):
            for lag in (0,100,200):
                if action == "A":
                    y = 1
                elif action == "B":
                    y = 1 if lag <= 100 else 0
                else:
                    y = 0
                good.append({
                    "context_id":cid,"action_id":action,"lag":lag,
                    "target_id":"safe","constraint_set_id":"default",
                    "trial_id":f"{cid}-{action}-{lag}","outcome_success":y
                })

        for lag in (0,100,200):
            one_action.append({
                "context_id":cid,"action_id":"A","lag":lag,
                "target_id":"safe","constraint_set_id":"default",
                "trial_id":f"{cid}-A-{lag}","outcome_success":int(lag==0)
            })

        for action in ("A","B","C"):
            for lag in (0,100,200):
                no_remedy.append({
                    "context_id":cid,"action_id":action,"lag":lag,
                    "target_id":"safe","constraint_set_id":"default",
                    "trial_id":f"{cid}-{action}-{lag}","outcome_success":int(lag<=100)
                })

    datasets = {
        "pass": good,
        "fail_one_action": one_action,
        "fail_no_remedy_divergence": no_remedy
    }
    result = {}
    for name, rows in datasets.items():
        p = outdir/f"{name}.csv"
        _write(rows, p)
        m = {
            "candidate_id":f"SYNTHETIC-{name.upper()}",
            "domain":"synthetic-control",
            "evidence_mode":"deterministic_rollout",
            "dataset_receipt_sha256":_sha(p),
            "context_definition":"Exact synthetic context identity.",
            "matching_procedure":"Exact context_id equality.",
            "matching_frozen_before_outcome_analysis":True,
            "target_definition":"safe",
            "constraint_definition":"default",
            "lag_unit":"milliseconds",
            "action_definition":"Synthetic interventions A/B/C.",
            "model_validation_receipt_sha256":None
        }
        mp = outdir/f"{name}.manifest.json"
        mp.write_text(json.dumps(m, indent=2)+"\n")
        result[name] = {"csv":str(p),"manifest":str(mp)}
    return result
