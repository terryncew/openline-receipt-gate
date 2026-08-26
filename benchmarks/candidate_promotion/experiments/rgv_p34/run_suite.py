from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from scipy.stats import hypergeom
from sklearn.linear_model import Ridge
from sklearn.preprocessing import StandardScaler

from benchmarks.candidate_promotion.experiments.rgv_001.run_suite import (
    descriptor_features,
    kmer_features,
)
from benchmarks.trial_selector.external_001.external_selector import (
    load_json,
    load_primary_candidates,
    verify_bound_inputs,
)

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
FREEZE = json.loads((HERE / "FREEZE.json").read_text(encoding="utf-8"))
PRIMARY = FREEZE["primary_viability_region"]
ALPHAS = [0.1, 1.0, 10.0, 100.0]
QGRID = [float(x) for x in FREEZE["nesting"]["residual_quantile_grid"]]


def clean_mask(df: pd.DataFrame) -> np.ndarray:
    mask = np.ones(len(df), dtype=bool)
    for assay, spec in PRIMARY.items():
        vals = df[assay].to_numpy(float)
        if spec["bad_if"] == ">":
            mask &= vals <= float(spec["threshold"])
        else:
            mask &= vals >= float(spec["threshold"])
    return mask


def read_bound_cohort(csv_path: Path) -> tuple[pd.DataFrame, dict[str, Any]]:
    config_path = REPO / "benchmarks/trial_selector/external_001/CONFIG.json"
    source_contract_path = REPO / "benchmarks/candidate_promotion/gdpa1_002/SOURCE.json"
    policy_path = REPO / "benchmarks/candidate_promotion/gdpa1_002/promotion-policy.json"
    jain_path = REPO / "benchmarks/candidate_promotion/results/jain_canonical_01/JAIN_2017_CANONICAL_COHORT.json"

    config = load_json(config_path)
    source_contract, policy, jain = verify_bound_inputs(
        config, source_contract_path, policy_path, jain_path
    )
    candidates, receipt = load_primary_candidates(
        csv_path, config, source_contract, policy, jain
    )

    expected = int(FREEZE["cohort_binding"]["expected_candidate_count"])
    if len(candidates) != expected:
        return pd.DataFrame(), {
            **receipt,
            "coverage_error": f"exact_P34_cohort_mismatch:{len(candidates)}!={expected}",
        }

    wanted = {str(c["candidate_id"]): c for c in candidates}
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        rows = []
        for raw in csv.DictReader(f):
            cid = str(raw["antibody_id"]).strip()
            if cid not in wanted:
                continue
            vals = wanted[cid]["assays"]
            rows.append({
                "antibody_id": cid,
                "antibody_name": str(raw["antibody_name"]).strip(),
                "vh_protein_sequence": str(raw["vh_protein_sequence"]).replace("*","").strip(),
                "vl_protein_sequence": str(raw["vl_protein_sequence"]).replace("*","").strip(),
                **{a: float(vals[a]) for a in vals},
            })
    df = pd.DataFrame(rows).sort_values("antibody_id").reset_index(drop=True)
    if len(df) != expected or df["antibody_id"].nunique() != expected:
        return pd.DataFrame(), {
            **receipt,
            "coverage_error": "sequence_identity_binding_failed",
        }
    receipt["p34_candidate_ids"] = df["antibody_id"].tolist()
    receipt["p34_candidate_ids_sha256"] = hashlib.sha256(
        json.dumps(receipt["p34_candidate_ids"], separators=(",",":")).encode()
    ).hexdigest()
    return df, receipt


def load_tap_features(path: Path, cohort: pd.DataFrame) -> np.ndarray:
    tap = pd.read_csv(path)
    id_cols = [c for c in tap.columns if str(c).strip().lower() in {
        "antibody_id","id","antibody","name","antibody_name"
    }]
    id_col = id_cols[0] if id_cols else tap.columns[0]
    tap = tap.copy()
    tap["_join"] = tap[id_col].astype(str).str.strip()
    ref = cohort[["antibody_id"]].copy()
    ref["_join"] = ref["antibody_id"].astype(str).str.strip()
    merged = ref.merge(tap, on="_join", how="left", validate="one_to_one")
    drop = {"antibody_id_x","antibody_id_y",id_col,"_join","antibody_id"}
    numeric = {}
    for c in merged.columns:
        if c in drop:
            continue
        x = pd.to_numeric(merged[c], errors="coerce")
        if x.notna().any():
            numeric[c] = x
    if not numeric:
        raise ValueError("no numeric TAP features after identity join")
    feat = pd.DataFrame(numeric)
    feat = feat.fillna(feat.median(numeric_only=True)).fillna(0.0)
    if len(feat) != len(cohort):
        raise ValueError("TAP join row-count mismatch")
    return feat.to_numpy(float)


def fit_predict_inner_loocv(
    x: np.ndarray, y: np.ndarray, outer_train: np.ndarray, outer_i: int
) -> tuple[np.ndarray, float, float]:
    """Return inner OOF predictions aligned to outer_train, outer prediction, alpha."""
    xtr = x[outer_train]
    ytr = y[outer_train]
    valid = np.isfinite(ytr)
    valid_idx = np.where(valid)[0]
    if len(valid_idx) < 10:
        raise ValueError("too few finite training labels")

    best = None
    for alpha in ALPHAS:
        pred = np.full(len(outer_train), np.nan)
        for local_hold in valid_idx:
            mask = valid.copy()
            mask[local_hold] = False
            scaler = StandardScaler().fit(xtr[mask])
            model = Ridge(alpha=alpha).fit(scaler.transform(xtr[mask]), ytr[mask])
            pred[local_hold] = model.predict(scaler.transform(xtr[[local_hold]]))[0]
        mse = float(np.nanmean((pred[valid] - ytr[valid]) ** 2))
        candidate = (mse, alpha, pred)
        if best is None or (candidate[0], candidate[1]) < (best[0], best[1]):
            best = candidate

    assert best is not None
    _, alpha, inner_pred = best
    scaler = StandardScaler().fit(xtr[valid])
    model = Ridge(alpha=alpha).fit(scaler.transform(xtr[valid]), ytr[valid])
    outer_pred = float(model.predict(scaler.transform(x[[outer_i]]))[0])
    return inner_pred, outer_pred, float(alpha)


def residual_radius(pred: np.ndarray, truth: np.ndarray, q: float) -> float:
    valid = np.isfinite(pred) & np.isfinite(truth)
    return float(np.quantile(np.abs(pred[valid] - truth[valid]), q))


def veto_vector(
    pred_by_assay: dict[str, np.ndarray],
    truth_for_residuals: pd.DataFrame,
    q: float,
) -> np.ndarray:
    n = len(next(iter(pred_by_assay.values())))
    out = np.zeros(n, dtype=bool)
    for assay, spec in PRIMARY.items():
        pred = pred_by_assay[assay]
        truth = truth_for_residuals[assay].to_numpy(float)
        rad = residual_radius(pred, truth, q)
        threshold = float(spec["threshold"])
        if spec["bad_if"] == ">":
            out |= (pred - rad) > threshold
        else:
            out |= (pred + rad) < threshold
    return out


def choose_q(inner_preds: dict[str, np.ndarray], train_truth: pd.DataFrame) -> float:
    clean = clean_mask(train_truth)
    floor = float(FREEZE["nesting"]["inner_clean_retention_floor"])
    candidates = []
    for q in QGRID:
        veto = veto_vector(inner_preds, train_truth, q)
        retention = 1.0 - float(veto[clean].mean()) if clean.any() else 0.0
        avoided = float(veto.mean())
        if retention >= floor:
            candidates.append((avoided, q))
    if not candidates:
        return max(QGRID)
    # Maximize useful rejection; tie -> more conservative residual quantile.
    return float(sorted(candidates, key=lambda z: (z[0], z[1]), reverse=True)[0][1])


def nested_arm(name: str, x: np.ndarray, truth: pd.DataFrame) -> dict[str, Any]:
    n = len(truth)
    decisions = np.zeros(n, dtype=bool)
    trace = []
    for outer_i in range(n):
        train_idx = np.array([i for i in range(n) if i != outer_i], dtype=int)
        train_truth = truth.iloc[train_idx].reset_index(drop=True)

        inner = {}
        outer_preds = {}
        alphas = {}
        for assay in PRIMARY:
            y = truth[assay].to_numpy(float)
            inner_pred, outer_pred, alpha = fit_predict_inner_loocv(
                x, y, train_idx, outer_i
            )
            inner[assay] = inner_pred
            outer_preds[assay] = outer_pred
            alphas[assay] = alpha

        q = choose_q(inner, train_truth)
        high_conf_bad = False
        assay_receipts = {}
        for assay, spec in PRIMARY.items():
            y_train = train_truth[assay].to_numpy(float)
            rad = residual_radius(inner[assay], y_train, q)
            pred = outer_preds[assay]
            t = float(spec["threshold"])
            if spec["bad_if"] == ">":
                bad = (pred - rad) > t
                bound = pred - rad
                bound_side = "lower"
            else:
                bad = (pred + rad) < t
                bound = pred + rad
                bound_side = "upper"
            high_conf_bad |= bool(bad)
            assay_receipts[assay] = {
                "prediction": pred,
                "residual_radius": rad,
                "decision_bound": bound,
                "bound_side": bound_side,
                "threshold": t,
                "high_confidence_violation": bool(bad),
                "ridge_alpha": alphas[assay],
            }

        decisions[outer_i] = high_conf_bad
        trace.append({
            "candidate_id": str(truth.iloc[outer_i]["antibody_id"]),
            "disposition": "VETO" if high_conf_bad else "UNKNOWN",
            "selected_residual_quantile": q,
            "assays": assay_receipts,
        })
    return {"name": name, "veto": decisions, "trace": trace}


def metrics(veto: np.ndarray, truth: pd.DataFrame) -> dict[str, Any]:
    clean = clean_mask(truth)
    bad = ~clean
    clean_n, bad_n = int(clean.sum()), int(bad.sum())
    veto_n = int(veto.sum())
    bad_caught = int((veto & bad).sum())
    clean_wrong = int((veto & clean).sum())
    retention = 1.0 - clean_wrong / clean_n if clean_n else 0.0
    avoided = veto_n / len(veto) if len(veto) else 0.0
    enrichment = None
    if veto_n and bad_n:
        base = bad_n / len(veto)
        enrichment = (bad_caught / veto_n) / base if base else None
    p = float(hypergeom.sf(bad_caught - 1, len(veto), bad_n, veto_n)) if veto_n else 1.0
    return {
        "n": int(len(veto)),
        "clean_n": clean_n,
        "bad_n": bad_n,
        "veto_n": veto_n,
        "experiments_avoided": avoided,
        "clean_retention": retention,
        "bad_candidates_caught": bad_caught,
        "clean_candidates_wrongly_vetoed": clean_wrong,
        "bad_candidate_enrichment": enrichment,
        "matched_random_one_sided_hypergeom_p": p,
    }


def dominated(rgv: dict[str, Any], baseline: dict[str, Any]) -> bool:
    floor = float(FREEZE["pilot_bar"]["clean_retention_min"])
    if baseline["clean_retention"] < floor:
        return False
    weak = (
        baseline["experiments_avoided"] >= rgv["experiments_avoided"]
        and baseline["bad_candidates_caught"] >= rgv["bad_candidates_caught"]
        and baseline["clean_candidates_wrongly_vetoed"] <= rgv["clean_candidates_wrongly_vetoed"]
    )
    strict = (
        baseline["experiments_avoided"] > rgv["experiments_avoided"]
        or baseline["bad_candidates_caught"] > rgv["bad_candidates_caught"]
        or baseline["clean_candidates_wrongly_vetoed"] < rgv["clean_candidates_wrongly_vetoed"]
    )
    return bool(weak and strict)


def run(csv_path: Path, tap_path: Path) -> dict[str, Any]:
    cohort, source_receipt = read_bound_cohort(csv_path)
    expected = int(FREEZE["cohort_binding"]["expected_candidate_count"])
    if len(cohort) != expected:
        return {
            "schema": "openline.rgv_p34.report.v1",
            "experiment": "RGV-P34",
            "verdict": FREEZE["verdicts"]["coverage"],
            "passed": False,
            "policy_authority": "NONE",
            "evidence_grade": FREEZE["evidence_grade"],
            "source_receipt": source_receipt,
        }

    simple_x = descriptor_features(cohort)
    rich_x = kmer_features(cohort)
    tap_x = load_tap_features(tap_path, cohort)

    simple = nested_arm("simple_sequence_descriptor_veto", simple_x, cohort)
    tap = nested_arm("ginkgo_TAP_feature_linear_veto", tap_x, cohort)
    rgv = nested_arm("RGV_sequence_kmer_confidence_veto", rich_x, cohort)

    simple_m = metrics(simple["veto"], cohort)
    tap_m = metrics(tap["veto"], cohort)
    rgv_m = metrics(rgv["veto"], cohort)

    bar = FREEZE["pilot_bar"]
    coverage_ok = (
        len(cohort) >= int(bar["minimum_evaluable_candidates"])
        and rgv_m["clean_n"] >= int(bar["minimum_clean_candidates"])
        and rgv_m["bad_n"] >= int(bar["minimum_bad_candidates"])
    )
    dominated_by = [
        name for name, m in (
            ("simple_sequence_descriptor", simple_m),
            ("ginkgo_TAP_feature_linear", tap_m),
        )
        if dominated(rgv_m, m)
    ]
    signal = (
        coverage_ok
        and rgv_m["clean_retention"] >= float(bar["clean_retention_min"])
        and rgv_m["experiments_avoided"] >= float(bar["experiments_avoided_min"])
        and rgv_m["matched_random_one_sided_hypergeom_p"]
            <= float(bar["matched_random_enrichment_one_sided_p_max"])
        and not dominated_by
    )

    if not coverage_ok:
        verdict = FREEZE["verdicts"]["coverage"]
    elif signal:
        verdict = FREEZE["verdicts"]["signal"]
    else:
        verdict = FREEZE["verdicts"]["null"]

    return {
        "schema": "openline.rgv_p34.report.v1",
        "experiment": "RGV-P34",
        "verdict": verdict,
        "passed": verdict == FREEZE["verdicts"]["signal"],
        "policy_authority": "NONE",
        "evidence_grade": FREEZE["evidence_grade"],
        "claim_boundary": FREEZE["claim_boundary"],
        "source_receipt": source_receipt,
        "cohort": {
            "candidate_count": int(len(cohort)),
            "candidate_ids": cohort["antibody_id"].tolist(),
            "clean_count": rgv_m["clean_n"],
            "bad_count": rgv_m["bad_n"],
        },
        "arms": {
            "simple_sequence_descriptor": {**simple_m, "trace": simple["trace"]},
            "ginkgo_TAP_feature_linear": {**tap_m, "trace": tap["trace"]},
            "RGV": {**rgv_m, "trace": rgv["trace"]},
            "random_matched": {
                "veto_n": rgv_m["veto_n"],
                "expected_bad_caught": (
                    rgv_m["veto_n"] * rgv_m["bad_n"] / len(cohort)
                ),
                "comparison_p": rgv_m["matched_random_one_sided_hypergeom_p"],
            },
        },
        "comparison": {
            "pareto_dominated_by_nonrandom_baselines": dominated_by,
            "pilot_bar": bar,
        },
        "kill_condition": FREEZE["kill_condition"],
    }


def self_test() -> None:
    rng = np.random.default_rng(34)
    fake = pd.DataFrame({
        "antibody_id": [f"x{i:02d}" for i in range(12)],
        "vh_protein_sequence": ["ACDEFGHIKLMNPQRSTVWY"*5 for _ in range(12)],
        "vl_protein_sequence": ["YWVTSRQPNMLKIHGFEDCA"*5 for _ in range(12)],
        "HIC": rng.normal(3.0, .4, 12),
        "PR_CHO": rng.normal(.30, .1, 12),
        "AC-SINS_pH7.4": rng.normal(12, 6, 12),
    })
    x = descriptor_features(fake)
    assert x.shape[0] == 12
    m = metrics(np.zeros(12, dtype=bool), fake)
    assert m["n"] == 12 and m["veto_n"] == 0
    print(json.dumps({"self_test":"PASS","rows":12,"features":int(x.shape[1])}))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--csv")
    p.add_argument("--tap")
    p.add_argument("--output")
    p.add_argument("--self-test", action="store_true")
    a = p.parse_args()
    if a.self_test:
        self_test()
        return 0
    if not all((a.csv, a.tap, a.output)):
        p.error("--csv --tap --output are required")
    report = run(Path(a.csv), Path(a.tap))
    out = Path(a.output)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    # Scientific null is a valid CI result. Coverage is also a valid receipt.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
