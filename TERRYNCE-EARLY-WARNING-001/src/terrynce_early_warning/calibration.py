from __future__ import annotations

from collections import defaultdict
from datetime import date
from pathlib import Path
import csv, hashlib, json, math, statistics

from .episode_lock import (
    _parse_date, _months_between, _read_csv, _find_one, _split_name,
    _twsa_observed_series, _feature_row, _canonical_hash
)
from .inventory import inventory
from .modeling import (
    fit_logistic, predict_logistic, metrics, threshold_at_fpr,
    chronological_cv_brier
)
from .protocol import project_root, load_protocol, protocol_sha256


def _failure_warning_threshold(y_recovery: list[int], p_recovery: list[float], budget: float) -> dict:
    """Freeze an alert threshold for loss of recoverability.

    Positive class is failure to recover within 24 months.
    False positives are warnings on episodes that ultimately recover.
    """
    y_failure = [1 - int(y) for y in y_recovery]
    failure_risk = [1.0 - float(p) for p in p_recovery]
    out = threshold_at_fpr(y_failure, failure_risk, budget)
    return {
        **out,
        "positive_class": "non_recovery_within_24m",
        "score": "1 - P(recovery)",
        "false_positive_definition": "warning_on_episode_that_recovers_within_24m",
    }


def _num(v):
    try:
        x = float(v)
        return x if math.isfinite(x) else None
    except Exception:
        return None


def _median_positive(xs):
    ys = [float(x) for x in xs if x is not None and math.isfinite(float(x)) and float(x) > 1e-12]
    return statistics.median(ys) if ys else 1.0


def _label_history_record(row: dict, rr: dict) -> dict:
    t0 = _parse_date(row["relief_t0"])
    min_d = _parse_date(rr["min_TWSA_Date"])
    lag = max(0, _months_between(t0, min_d))
    y = int(row["recovered_within_24m"])
    capacity = None
    if y == 1 and row.get("label_first_crossing"):
        hit = _parse_date(row["label_first_crossing"])
        months = max(1, _months_between(min_d, hit))
        init = _num(rr.get("init_TWSA"))
        minv = _num(rr.get("min_TWSA"))
        if init is not None and minv is not None:
            amplitude = max(0.0, 0.90 * (init - minv))
            capacity = amplitude / months
    return {"lag": float(lag), "y": y, "capacity": capacity}


def _prior_summary(pool: list[dict]) -> dict:
    if not pool:
        raise ValueError("empty history pool")
    lag = statistics.median([r["lag"] for r in pool])
    rate = sum(r["y"] for r in pool) / len(pool)
    caps = [r["capacity"] for r in pool if r["capacity"] is not None and r["capacity"] > 0]
    medcap = statistics.median(caps) if caps else 0.0
    return {
        "response_lag_months": float(lag),
        "history_recovery_rate": float(rate),
        "historical_recovery_capacity_per_month": float(rate * medcap),
        "history_n": len(pool),
        "successful_capacity_n": len(caps),
    }


def _augment_train_history(rows: list[dict], rec_idx: dict, burn_in: int, basin_min: int) -> tuple[list[dict], dict]:
    rows = sorted(rows, key=lambda r: (r["relief_t0"], r["ID"], r["group"]))
    global_hist = []
    basin_hist = defaultdict(list)
    out = []
    used_basin = 0
    used_global = 0

    for i, raw in enumerate(rows):
        r = dict(raw)
        k = (str(r["ID"]), str(r["group"]))
        if i >= burn_in and global_hist:
            bh = basin_hist[str(r["ID"])]
            pool = bh if len(bh) >= basin_min else global_hist
            s = _prior_summary(pool)
            r.update(s)
            r["history_source"] = "basin" if pool is bh else "global"
            used_basin += int(pool is bh)
            used_global += int(pool is global_hist)
            out.append(r)

        rec = _label_history_record(r, rec_idx[k])
        global_hist.append(rec)
        basin_hist[str(r["ID"])].append(rec)

    return out, {
        "burn_in": burn_in,
        "fit_rows": len(out),
        "history_source_basin_rows": used_basin,
        "history_source_global_rows": used_global,
    }


def _augment_fixed_training_history(rows: list[dict], train_rows: list[dict], rec_idx: dict, basin_min: int) -> tuple[list[dict], dict]:
    global_hist = []
    basin_hist = defaultdict(list)
    for r in sorted(train_rows, key=lambda q: (q["relief_t0"], q["ID"], q["group"])):
        k = (str(r["ID"]), str(r["group"]))
        rec = _label_history_record(r, rec_idx[k])
        global_hist.append(rec)
        basin_hist[str(r["ID"])].append(rec)

    out = []
    used_basin = 0
    used_global = 0
    for raw in rows:
        r = dict(raw)
        bh = basin_hist[str(r["ID"])]
        pool = bh if len(bh) >= basin_min else global_hist
        s = _prior_summary(pool)
        r.update(s)
        r["history_source"] = "basin" if pool is bh else "global"
        used_basin += int(pool is bh)
        used_global += int(pool is global_hist)
        out.append(r)
    return out, {"rows": len(out), "history_source_basin_rows": used_basin, "history_source_global_rows": used_global}


def _rm_components(r: dict) -> dict:
    state = max(0.0, float(r["state_deficit"]))
    momentum = max(0.0, float(r["adverse_momentum"])) * float(r["response_lag_months"])
    drought = max(0.0, float(r["duration_months"])) * max(0.0, float(r["mean_p_drought"]))
    avail = float(r["historical_recovery_capacity_per_month"]) * max(0.0, 24.0 - float(r["response_lag_months"]))
    return {
        "rm_state_burden_raw": state,
        "rm_momentum_burden_raw": momentum,
        "rm_drought_burden_raw": drought,
        "rm_available_recovery_raw": avail,
    }


def _fit_rm_scales(train: list[dict]) -> dict:
    comps = [_rm_components(r) for r in train]
    return {
        "state": _median_positive([c["rm_state_burden_raw"] for c in comps]),
        "momentum": _median_positive([c["rm_momentum_burden_raw"] for c in comps]),
        "drought": _median_positive([c["rm_drought_burden_raw"] for c in comps]),
        "available": _median_positive([c["rm_available_recovery_raw"] for c in comps]),
    }


def _attach_rm(rows: list[dict], scales: dict) -> list[dict]:
    out = []
    for raw in rows:
        r = dict(raw)
        c = _rm_components(r)
        r.update(c)
        state = c["rm_state_burden_raw"] / scales["state"]
        mom = c["rm_momentum_burden_raw"] / scales["momentum"]
        drought = c["rm_drought_burden_raw"] / scales["drought"]
        avail = c["rm_available_recovery_raw"] / scales["available"]
        r["recoverability_margin"] = avail - state - mom - drought
        r["log1p_pre_relief_variance"] = math.log1p(max(0.0, float(r["pre_relief_variance"])))
        out.append(r)
    return out


def _read_train_validation(path: Path) -> tuple[list[dict], list[dict]]:
    rows = _read_csv(path)
    numeric = {
        "state_baseline", "state_current", "state_deficit", "pre_relief_slope",
        "adverse_momentum", "pre_relief_ar1", "pre_relief_variance",
        "duration_months", "extreme_duration_months", "mean_p_drought",
        "peak_p_extreme", "static_AI", "static_pIRR", "static_pSNOW",
        "static_MAP", "static_MAT", "static_area_log", "static_fReser_MAP",
        "label_threshold"
    }
    for r in rows:
        for k in numeric:
            if k in r and r[k] != "":
                r[k] = float(r[k])
        r["recovered_within_24m"] = int(r["recovered_within_24m"])
    return ([r for r in rows if r["split"] == "train"],
            [r for r in rows if r["split"] == "validation"])


def _reconstruct_holdout_features(root: Path, proto: dict) -> list[dict]:
    data_root = root / "data" / "work" / "data_bundle"
    severe = _read_csv(_find_one(data_root, "severe_drought_events_ensemble.csv"))
    basin_attr = _read_csv(_find_one(data_root, "basin_attr.csv"))
    spei = _read_csv(_find_one(data_root, "basin_ensemble_spei06.csv"))
    twsa_obs, _ = _twsa_observed_series(_find_one(data_root, "data_TWSA_all_filled_stl.csv"))

    attr_idx = {str(r["ID"]).strip(): r for r in basin_attr}
    spei_idx = defaultdict(list)
    for r in spei:
        spei_idx[str(r["ID"]).strip()].append(r)

    rows = []
    for ev in severe:
        t0 = _parse_date(ev["EndDate"])
        if _split_name(t0, proto) != "holdout":
            continue
        iid = str(ev["ID"]).strip()
        if iid not in attr_idx:
            continue
        feat, reason = _feature_row(ev, twsa_obs.get(iid, []), spei_idx.get(iid, []), attr_idx[iid])
        if feat is not None:
            feat["split"] = "holdout"
            rows.append(feat)
    return rows


def _fit_simple_model(train, val, name, features, target="recovered_within_24m", l2=0.1):
    model = fit_logistic(train, features, target, l2=l2)
    pv = predict_logistic(model, val)
    yv = [int(r[target]) for r in val]
    return model, pv, metrics(yv, pv)


def _pick_lambda(train, val, features, grid):
    yv = [int(r["recovered_within_24m"]) for r in val]
    candidates = []
    for lam in grid:
        model = fit_logistic(train, features, "recovered_within_24m", l2=lam)
        p = predict_logistic(model, val)
        met = metrics(yv, p)
        candidates.append({"lambda": lam, "model": model, "validation": met, "pred": p})
    candidates.sort(key=lambda x: (x["validation"]["brier"], x["lambda"]))
    return candidates[0], [
        {"lambda": c["lambda"], "validation": c["validation"]} for c in candidates
    ]


def calibrate(root: Path | None = None) -> dict:
    root = root or project_root()
    proto = load_protocol(root)
    cal = json.loads((root / "config" / "calibration_protocol.frozen.json").read_text())

    # Reconstruct and freeze the exact episode table first.
    from .episode_lock import build_episode_lock
    ep_report = build_episode_lock(root)
    if ep_report["status"] != "PASS_EPISODE_LOCK":
        raise SystemExit(2)

    inventory(root)
    data_root = root / "data" / "work" / "data_bundle"
    recovery = _read_csv(_find_one(data_root, "TWSA_recovery_one_95.csv"))
    rec_idx = {(str(r["ID"]).strip(), str(r["group"]).strip()): r for r in recovery}

    train_raw, val_raw = _read_train_validation(root / "artifacts" / "episode_lock_train_validation.csv")
    burn = cal["history"]["training_burn_in_episodes"]
    basin_min = cal["history"]["basin_min_prior_completed_episodes"]

    train_hist, train_hist_diag = _augment_train_history(train_raw, rec_idx, burn, basin_min)
    val_hist, val_hist_diag = _augment_fixed_training_history(val_raw, train_raw, rec_idx, basin_min)

    holdout_raw = _reconstruct_holdout_features(root, proto)
    holdout_hist, holdout_hist_diag = _augment_fixed_training_history(holdout_raw, train_raw, rec_idx, basin_min)

    # Prove the holdout feature reconstruction is identical to the Episode Lock hashes.
    hlock = json.loads((root / "artifacts" / "holdout_feature_hashes.json").read_text())
    expected = {(r["ID"], r["group"], r["relief_t0"]): r["feature_sha256"] for r in hlock["rows"]}
    actual = {(r["ID"], r["group"], r["relief_t0"]): _canonical_hash({k:v for k,v in r.items() if k not in {
        "response_lag_months", "history_recovery_rate", "historical_recovery_capacity_per_month",
        "history_n", "successful_capacity_n", "history_source"
    }}) for r in holdout_hist}
    # holdout_raw contains the exact Episode Lock feature row; compare that instead of augmented row.
    actual_raw = {(r["ID"], r["group"], r["relief_t0"]): _canonical_hash(r) for r in holdout_raw}
    hash_match = expected == actual_raw
    if not hash_match:
        raise ValueError("holdout causal feature hashes do not match Episode Lock")

    rm_scales = _fit_rm_scales(train_hist)
    train = _attach_rm(train_hist, rm_scales)
    val = _attach_rm(val_hist, rm_scales)
    holdout = _attach_rm(holdout_hist, rm_scales)

    yv = [int(r["recovered_within_24m"]) for r in val]
    fpr_budget = float(cal["validation"]["false_positive_budget"])
    fixed_l2 = float(cal["modeling"]["regularization_fixed_simple"])

    models = {}
    validation = {}
    thresholds = {}

    # RM-only probability mapping.
    m, pv, met = _fit_simple_model(train, val, "recoverability_margin", ["recoverability_margin"], l2=fixed_l2)
    models["recoverability_margin"] = m
    validation["recoverability_margin"] = met
    thresholds["recoverability_margin"] = _failure_warning_threshold(yv, pv, fpr_budget)

    simple_defs = {
        "state_only": cal["baselines"]["state_only"],
        "trend_only": cal["baselines"]["trend_only"],
        "drought_severity_duration": cal["baselines"]["drought_severity_duration"],
        "critical_slowing": cal["baselines"]["critical_slowing"],
    }
    for name, features in simple_defs.items():
        m, pv, met = _fit_simple_model(train, val, name, features, l2=fixed_l2)
        models[name] = m
        validation[name] = met
        thresholds[name] = _failure_warning_threshold(yv, pv, fpr_budget)

    # History/persistence is a direct causal probability, not a fitted model.
    hp = [min(max(float(r["history_recovery_rate"]), 0.0), 1.0) for r in val]
    models["history_persistence"] = {"family": "direct_probability", "feature": "history_recovery_rate"}
    validation["history_persistence"] = metrics(yv, hp)
    thresholds["history_persistence"] = _failure_warning_threshold(yv, hp, fpr_budget)

    # Best single observable: selection uses training labels only.
    cv = []
    for feature in cal["best_single"]["candidates"]:
        score = chronological_cv_brier(train, feature, "recovered_within_24m", blocks=5, l2=fixed_l2)
        cv.append({"feature": feature, "train_cv_brier": score})
    cv.sort(key=lambda x: (x["train_cv_brier"], x["feature"]))
    best_single_feature = cv[0]["feature"]
    m, pv, met = _fit_simple_model(train, val, "best_single", [best_single_feature], l2=fixed_l2)
    models["best_single"] = m
    validation["best_single"] = {**met, "selected_feature": best_single_feature}
    thresholds["best_single"] = _failure_warning_threshold(yv, pv, fpr_budget)

    # Hard conventional model and augmented model select regularization on validation.
    conv_features = list(cal["baselines"]["conventional_multivariable"])
    aug_features = conv_features + ["recoverability_margin"]
    grid = cal["modeling"]["regularization_grid_conventional"]

    best_conv, conv_grid = _pick_lambda(train, val, conv_features, grid)
    best_aug, aug_grid = _pick_lambda(train, val, aug_features, grid)
    models["conventional_multivariable"] = best_conv["model"]
    models["rm_augmented_conventional"] = best_aug["model"]
    validation["conventional_multivariable"] = best_conv["validation"]
    validation["rm_augmented_conventional"] = best_aug["validation"]
    thresholds["conventional_multivariable"] = _failure_warning_threshold(yv, best_conv["pred"], fpr_budget)
    thresholds["rm_augmented_conventional"] = _failure_warning_threshold(yv, best_aug["pred"], fpr_budget)

    # Validation is diagnostic/calibration only; no success verdict is made here.
    validation_incremental_brier = (
        validation["conventional_multivariable"]["brier"] -
        validation["rm_augmented_conventional"]["brier"]
    )

    # Freeze predictions before labels are ever constructed.
    pred_rows = []
    for r in holdout:
        row = {"ID": r["ID"], "group": r["group"], "relief_t0": r["relief_t0"]}
        for name, model in models.items():
            if model["family"] == "direct_probability":
                pr = min(max(float(r[model["feature"]]), 0.0), 1.0)
            else:
                pr = predict_logistic(model, [r])[0]
            row[f"{name}_probability"] = pr
            row[f"{name}_failure_risk"] = 1.0 - pr
            row[f"{name}_warn"] = int((1.0 - pr) >= thresholds[name]["threshold"])
        row["recoverability_margin_raw"] = float(r["recoverability_margin"])
        pred_rows.append(row)

    pred_path = root / "artifacts" / "holdout_predictions.lock.csv"
    fields = list(pred_rows[0].keys()) if pred_rows else []
    with pred_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(pred_rows)
    pred_sha = hashlib.sha256(pred_path.read_bytes()).hexdigest()
    (root / "artifacts" / "holdout_predictions.lock.sha256").write_text(
        pred_sha + "  holdout_predictions.lock.csv\n"
    )

    # Prove this amendment did not alter any fitted probability or RM value.
    probability_fields = [
        "ID", "group", "relief_t0",
        "recoverability_margin_probability",
        "state_only_probability",
        "trend_only_probability",
        "drought_severity_duration_probability",
        "critical_slowing_probability",
        "history_persistence_probability",
        "best_single_probability",
        "conventional_multivariable_probability",
        "rm_augmented_conventional_probability",
        "recoverability_margin_raw",
    ]
    prob_path = root / "artifacts" / "holdout_probabilities.lock.csv"
    with prob_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=probability_fields)
        w.writeheader()
        w.writerows([{k: r[k] for k in probability_fields} for r in pred_rows])
    prob_sha = hashlib.sha256(prob_path.read_bytes()).hexdigest()
    (root / "artifacts" / "holdout_probabilities.lock.sha256").write_text(
        prob_sha + "  holdout_probabilities.lock.csv\n"
    )
    amendment = json.loads((root / "config" / "pre_holdout_warning_amendment.json").read_text())
    if prob_sha != amendment["source_probability_only_sha256"]:
        raise ValueError(
            "pre-holdout warning amendment changed frozen model probabilities; "
            f"expected {amendment['source_probability_only_sha256']} got {prob_sha}"
        )

    lock = {
        "experiment_id": proto["experiment_id"],
        "stage": "CALIBRATION_LOCK",
        "protocol_sha256": protocol_sha256(root),
        "episode_definition_sha256": ep_report["episode_definition_sha256"],
        "calibration_protocol_sha256": hashlib.sha256(
            (root / "config" / "calibration_protocol.frozen.json").read_bytes()
        ).hexdigest(),
        "training_rows_after_history_burnin": len(train),
        "validation_rows": len(val),
        "holdout_prediction_rows": len(holdout),
        "history_diagnostics": {
            "train": train_hist_diag,
            "validation": val_hist_diag,
            "holdout": holdout_hist_diag,
        },
        "rm_scales": rm_scales,
        "best_single_training_cv": cv,
        "best_single_feature": best_single_feature,
        "models": models,
        "validation_metrics": validation,
        "validation_incremental_brier": validation_incremental_brier,
        "regularization_search": {
            "conventional": conv_grid,
            "rm_augmented_conventional": aug_grid,
        },
        "thresholds": thresholds,
        "holdout_features_match_episode_lock": hash_match,
        "holdout_predictions_sha256": pred_sha,
        "holdout_probabilities_sha256": prob_sha,
        "probabilities_unchanged_from_pre_amendment": True,
        "warning_semantics": "loss_of_recoverability = 1 - P(recovery)",
        "holdout_labels_constructed": False,
        "final_verdict": "WITHHELD_PENDING_UNTOUCHED_HOLDOUT",
        "success_rule": cal["success_rule_unchanged"],
    }
    lock_path = root / "artifacts" / "calibration.lock.json"
    lock_path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n")
    lock_sha = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    (root / "artifacts" / "calibration.lock.sha256").write_text(
        lock_sha + "  calibration.lock.json\n"
    )

    report = {
        "experiment_id": proto["experiment_id"],
        "stage": "CALIBRATION_LOCK",
        "status": "PASS_CALIBRATION_LOCK",
        "calibration_lock_sha256": lock_sha,
        "counts": {
            "train_after_burnin": len(train),
            "validation": len(val),
            "holdout_predictions_frozen": len(holdout),
        },
        "best_single_feature": best_single_feature,
        "validation_metrics": validation,
        "validation_incremental_brier": validation_incremental_brier,
        "thresholds": thresholds,
        "holdout_predictions_sha256": pred_sha,
        "holdout_probabilities_sha256": prob_sha,
        "probabilities_unchanged_from_pre_amendment": True,
        "warning_semantics": "loss_of_recoverability = 1 - P(recovery)",
        "holdout_labels_constructed": False,
        "next_gate": "Pin this calibration lock and prediction hash in source, then open 2019-2022 labels exactly once and score the frozen predictions.",
        "boundary": "Validation may look good or bad; it does not decide the claim. No RM/model/threshold changes are allowed before held-out replay once this lock is pinned.",
    }
    rp = root / "artifacts" / "calibration_report.json"
    rp.write_text(json.dumps(report, indent=2) + "\n")
    (root / "artifacts" / "calibration_report.sha256").write_text(
        hashlib.sha256(rp.read_bytes()).hexdigest() + "  calibration_report.json\n"
    )
    return report
