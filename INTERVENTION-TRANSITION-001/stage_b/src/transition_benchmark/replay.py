from __future__ import annotations
from collections import defaultdict
from itertools import combinations
from pathlib import Path
import csv, json
import numpy as np
from sklearn.metrics import roc_auc_score, average_precision_score
from .common import load_lock, sha256_file, brier
from .data import load_cells

MODEL_COLS={
    "state_only":"state_only_p_fail",
    "state_plus_lag":"state_plus_lag_p_fail",
    "state_plus_action":"state_plus_action_p_fail",
    "direct_action_lag":"direct_action_lag_p_fail",
    "action_lag_global":"action_lag_global_p_fail",
}


def _jaccard(a,b):
    a=set(a); b=set(b)
    if not a and not b:return 1.0
    return len(a&b)/len(a|b)


def _metrics(y,p):
    out={"brier":brier(y,p)}
    if len(set(y))>1:
        out["auroc_failure"]=float(roc_auc_score(y,p))
        out["auprc_failure"]=float(average_precision_score(y,p))
    else:
        out["auroc_failure"]=None; out["auprc_failure"]=None
    return out


def _bootstrap_gain(contexts, truth_by_context, pred_a_by_context, pred_b_by_context, reps, seed):
    rng=np.random.default_rng(seed)
    vals=[]
    n=len(contexts)
    for _ in range(int(reps)):
        sample=rng.choice(contexts,size=n,replace=True)
        y=[]; pa=[]; pb=[]
        for c in sample:
            y.extend(truth_by_context[c]); pa.extend(pred_a_by_context[c]); pb.extend(pred_b_by_context[c])
        vals.append(brier(y,pa)-brier(y,pb))
    arr=np.asarray(vals)
    return {"mean":float(arr.mean()),"ci95_low":float(np.quantile(arr,0.025)),"ci95_high":float(np.quantile(arr,0.975)),"positive_fraction":float(np.mean(arr>0))}


def run_replay(stage_a_dir: Path, calibration_dir: Path, outdir: Path, project_root: Path) -> dict:
    lock=load_lock(project_root); split=lock["split"]; hold=set(split["holdout"])
    cal=json.loads((calibration_dir/"calibration_lock.json").read_text())
    pred_path=calibration_dir/"holdout_predictions.csv"
    if sha256_file(pred_path)!=cal["holdout_predictions_sha256"]:
        raise RuntimeError("Frozen holdout predictions hash mismatch")
    if cal["holdout_labels_consumed"] is not False:
        raise RuntimeError("Calibration receipt does not preserve holdout barrier")

    pred_rows={}
    with pred_path.open(newline="") as f:
        for r in csv.DictReader(f):
            key=(r["context_id"],r["action_id"],int(r["lag"]))
            pred_rows[key]={name:float(r[col]) for name,col in MODEL_COLS.items()}
    truth_rows=load_cells(stage_a_dir/"intervention_sufficiency_input.csv", hold)
    truth=[r for r in truth_rows if r["context_id"] in hold]
    if len(truth)!=300: raise RuntimeError(f"Expected 300 holdout cells, got {len(truth)}")
    for r in truth:
        if r["y_fail"] is None: raise RuntimeError("Holdout label missing at replay")
        if (r["context_id"],r["action_id"],r["lag"]) not in pred_rows: raise RuntimeError("Missing frozen prediction")

    y=[r["y_fail"] for r in truth]
    preds={name:[pred_rows[(r["context_id"],r["action_id"],r["lag"])][name] for r in truth] for name in MODEL_COLS}
    model_metrics={name:_metrics(y,p) for name,p in preds.items()}

    by_context_truth=defaultdict(list); by_context_pred={name:defaultdict(list) for name in MODEL_COLS}
    for i,r in enumerate(truth):
        c=r["context_id"]; by_context_truth[c].append(y[i])
        for name in MODEL_COLS: by_context_pred[name][c].append(preds[name][i])
    boot=lock["bootstrap"]
    action_gain=_bootstrap_gain(split["holdout"],by_context_truth,by_context_pred["state_plus_lag"],by_context_pred["direct_action_lag"],boot["replicates"],boot["seed"])
    lag_gain=_bootstrap_gain(split["holdout"],by_context_truth,by_context_pred["state_plus_action"],by_context_pred["direct_action_lag"],boot["replicates"],boot["seed"]+1)
    action_gain["observed"]=model_metrics["state_plus_lag"]["brier"]-model_metrics["direct_action_lag"]["brier"]
    lag_gain["observed"]=model_metrics["state_plus_action"]["brier"]-model_metrics["direct_action_lag"]["brier"]

    # Feasible action sets at every held-out context×lag.
    truth_groups=defaultdict(dict); pred_groups={name:defaultdict(dict) for name in MODEL_COLS}
    for r in truth:
        key=(r["context_id"],r["lag"]); a=r["action_id"]
        truth_groups[key][a]=(r["y_fail"]==0)
        pr=pred_rows[(r["context_id"],a,r["lag"])]
        for name in MODEL_COLS:
            pred_groups[name][key][a]=(1.0-pr[name])>=float(lock["model"]["feasible_threshold"])
    divergent=[k for k,d in truth_groups.items() if len(set(d.values()))>1]
    set_metrics={}
    for name in MODEL_COLS:
        js=[]; exact=[]; feasible_recalls=[]; infeasible_specs=[]
        for k in divergent:
            gt={a for a,v in truth_groups[k].items() if v}; pp={a for a,v in pred_groups[name][k].items() if v}
            js.append(_jaccard(gt,pp)); exact.append(float(gt==pp))
            feasible_recalls.append(len(gt&pp)/len(gt) if gt else 1.0)
            bad=set(truth_groups[k])-gt
            infeasible_specs.append(len(bad-(pp&bad))/len(bad) if bad else 1.0)
        set_metrics[name]={
            "groups":len(divergent),
            "mean_jaccard":float(np.mean(js)) if js else None,
            "exact_set_accuracy":float(np.mean(exact)) if exact else None,
            "feasible_action_recall":float(np.mean(feasible_recalls)) if feasible_recalls else None,
            "infeasible_action_specificity":float(np.mean(infeasible_specs)) if infeasible_specs else None,
        }

    # Comparable scalar danger, different remedies.
    risk={}
    for c in split["holdout"]:
        risk[c]=pred_rows[(c,"CONTINUE",0)]["state_only"]
    eps=float(lock["secondary_matched_risk_test"]["risk_tolerance_absolute"])
    matched=[]
    for c1,c2 in combinations(split["holdout"],2):
        if abs(risk[c1]-risk[c2])>eps: continue
        for lag in (0,40,80,120,160):
            gt1={a for a,v in truth_groups[(c1,lag)].items() if v}; gt2={a for a,v in truth_groups[(c2,lag)].items() if v}
            if gt1==gt2: continue
            item={"context_a":c1,"context_b":c2,"lag":lag,"risk_a":risk[c1],"risk_b":risk[c2]}
            for name in ("direct_action_lag","state_only","state_plus_lag"):
                p1={a for a,v in pred_groups[name][(c1,lag)].items() if v}; p2={a for a,v in pred_groups[name][(c2,lag)].items() if v}
                item[name+"_predicts_different_sets"]=(p1!=p2)
            matched.append(item)
    matched_summary={"units":len(matched),"minimum_for_interpretation":lock["secondary_matched_risk_test"]["minimum_pairs_for_interpretation"]}
    for name in ("direct_action_lag","state_only","state_plus_lag"):
        matched_summary[name+"_divergence_recall"]=(float(np.mean([x[name+"_predicts_different_sets"] for x in matched])) if matched else None)

    enough=(sum(y)>=20 and len(divergent)>=5)
    action_pass=(action_gain["observed"]>0 and action_gain["ci95_low"]>0)
    lag_pass=(lag_gain["observed"]>0 and lag_gain["ci95_low"]>0)
    remedy_pass=(
        set_metrics["direct_action_lag"]["mean_jaccard"] is not None and
        set_metrics["direct_action_lag"]["mean_jaccard"]>set_metrics["state_plus_lag"]["mean_jaccard"] and
        set_metrics["direct_action_lag"]["mean_jaccard"]>set_metrics["state_only"]["mean_jaccard"]
    )
    if not enough:
        verdict="INSUFFICIENT_HELDOUT_SUPPORT"
    elif action_pass and lag_pass and remedy_pass:
        verdict="SUPPORTS_ACTION_CONDITIONED_TRANSITION_CLAIM"
    else:
        verdict="FAILS_ACTION_CONDITIONED_TRANSITION_CLAIM"

    result={
        "experiment_id":lock["experiment_id"],
        "stage":"STAGE_B_ONE_SHOT_HELDOUT_REPLAY",
        "status":"COMPLETE_HELDOUT_REPLAY",
        "verdict":verdict,
        "holdout":{"contexts":len(split["holdout"]),"cells":len(y),"failure_cells":int(sum(y)),"success_cells":int(len(y)-sum(y)),"remedy_divergent_context_lag_groups":len(divergent)},
        "model_metrics":model_metrics,
        "action_conditioning_gain":action_gain,
        "lag_conditioning_gain":lag_gain,
        "remedy_set_metrics":set_metrics,
        "matched_risk_different_remedy":matched_summary,
        "criteria":{"enough_support":enough,"action_conditioning":action_pass,"lag_conditioning":lag_pass,"remedy_set_recovery":remedy_pass},
        "frozen_prediction_sha256":sha256_file(pred_path),
        "stage_a_dataset_sha256":lock["stage_a_dataset_sha256"],
        "boundary":"Result applies to the frozen Unitree G1 controller/model/action/lag/target regime. No Terrynce scalar is evaluated."
    }
    outdir.mkdir(parents=True,exist_ok=True)
    rp=outdir/"stage_b_heldout_result.json"; rp.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    (outdir/"stage_b_heldout_result.sha256").write_text(sha256_file(rp)+"  stage_b_heldout_result.json\n")
    if matched:
        mp=outdir/"matched_risk_pairs.json"; mp.write_text(json.dumps(matched,indent=2,sort_keys=True)+"\n")
    return result
