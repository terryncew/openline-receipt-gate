from __future__ import annotations
from pathlib import Path
import csv, json
import numpy as np
from .common import load_lock, sha256_file, brier
from .data import load_cells
from .model import MODELS, build_outcome_index, fit_state_embedding, predict_one


def run_calibration(stage_a_dir: Path, feature_dir: Path, outdir: Path, project_root: Path) -> dict:
    lock=load_lock(project_root)
    split=lock["split"]
    train=set(split["train"]); validation=set(split["validation"]); holdout=set(split["holdout"])
    labeled=train|validation
    rows=load_cells(stage_a_dir/"intervention_sufficiency_input.csv", labeled)

    npz=np.load(feature_dir/"state_features.npz",allow_pickle=False)
    context_ids=[str(x) for x in npz["context_ids"].tolist()]
    X=np.asarray(npz["X"],dtype=float)
    pos={c:i for i,c in enumerate(context_ids)}
    if set(context_ids)!=train|validation|holdout:
        raise RuntimeError("Feature context set does not match frozen split")

    Z,scaler,pca=fit_state_embedding(context_ids,X,split["train"],lock["model"]["pca_components_max"])
    train_z=np.stack([Z[pos[c]] for c in split["train"]])
    index=build_outcome_index(rows,train)

    val_rows=[r for r in rows if r["context_id"] in validation]
    if any(r["y_fail"] is None for r in val_rows): raise RuntimeError("Validation labels missing")
    selected_k={}
    validation_scores={}
    for model_name in MODELS:
        scored=[]
        for k in lock["model"]["k_grid"]:
            preds=[predict_one(model_name,Z[pos[r["context_id"]]],r["action_id"],r["lag"],train_z,split["train"],index,int(k)) for r in val_rows]
            score=brier([r["y_fail"] for r in val_rows],preds)
            scored.append((score,int(k)))
        scored.sort(key=lambda x:(x[0],x[1]))
        selected_k[model_name]=scored[0][1]
        validation_scores[model_name]={"selected_k":scored[0][1],"brier":scored[0][0],"grid":[{"k":k,"brier":s} for s,k in scored]}
    validation_scores["action_lag_global"]={"selected_k":None,"brier":brier(
        [r["y_fail"] for r in val_rows],
        [predict_one("action_lag_global",Z[pos[r["context_id"]]],r["action_id"],r["lag"],train_z,split["train"],index,1) for r in val_rows]
    )}

    # Holdout metadata are loaded without parsing outcome_success.
    unlabeled_rows=load_cells(stage_a_dir/"intervention_sufficiency_input.csv", set())
    hold_rows=[r for r in unlabeled_rows if r["context_id"] in holdout]
    if any(r["y_fail"] is not None for r in hold_rows):
        raise RuntimeError("Holdout label barrier violated")

    outdir.mkdir(parents=True,exist_ok=True)
    pred_path=outdir/"holdout_predictions.csv"
    fields=["context_id","action_id","lag","state_only_p_fail","state_plus_lag_p_fail","state_plus_action_p_fail","direct_action_lag_p_fail","action_lag_global_p_fail"]
    with pred_path.open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
        for r in hold_rows:
            cid=r["context_id"]; a=r["action_id"]; lag=r["lag"]
            row={"context_id":cid,"action_id":a,"lag":lag}
            for name in MODELS:
                row[name+"_p_fail"]=predict_one(name,Z[pos[cid]],a,lag,train_z,split["train"],index,selected_k[name])
            row["action_lag_global_p_fail"]=predict_one("action_lag_global",Z[pos[cid]],a,lag,train_z,split["train"],index,1)
            w.writerow(row)

    bundle=outdir/"state_embedding.npz"
    np.savez_compressed(bundle, scaler_mean=scaler.mean_, scaler_scale=scaler.scale_, pca_components=pca.components_, pca_mean=pca.mean_, explained_variance_ratio=pca.explained_variance_ratio_)
    receipt={
        "experiment_id":lock["experiment_id"],
        "stage":"STAGE_B_CALIBRATION_LOCK",
        "status":"FROZEN_HOLDOUT_PREDICTIONS",
        "stage_a_dataset_sha256":lock["stage_a_dataset_sha256"],
        "feature_receipt_sha256":sha256_file(feature_dir/"feature_receipt.json"),
        "pca_components":int(pca.n_components_),
        "selected_k":selected_k,
        "validation_scores":validation_scores,
        "holdout_contexts":split["holdout"],
        "holdout_rows":len(hold_rows),
        "holdout_labels_consumed":False,
        "holdout_predictions_sha256":sha256_file(pred_path),
        "state_embedding_sha256":sha256_file(bundle),
        "feasible_threshold":lock["model"]["feasible_threshold"],
        "boundary":"Model selection used train+validation only. Holdout outcome_success values were not parsed by calibration."
    }
    rp=outdir/"calibration_lock.json"
    rp.write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    (outdir/"calibration_lock.sha256").write_text(sha256_file(rp)+"  calibration_lock.json\n")
    return receipt
