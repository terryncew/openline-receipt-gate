from __future__ import annotations

import argparse
import hashlib
import json
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

HERE = Path(__file__).resolve().parent
FREEZE = json.loads((HERE / "FREEZE.json").read_text(encoding="utf-8"))
PRIMARY = FREEZE["primary_viability_region"]
FOLD_COL = "hierarchical_cluster_IgG_isotype_stratified_fold"
ALPHAS = [float(x) for x in FREEZE["evaluation"]["ridge_alphas"]]
QGRID = [float(x) for x in FREEZE["evaluation"]["residual_quantile_grid"]]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def derive_cohort(csv_path: Path) -> tuple[pd.DataFrame, dict[str, Any]]:
    raw = pd.read_csv(csv_path)
    required = [
        "antibody_id",
        "vh_protein_sequence",
        "vl_protein_sequence",
        FOLD_COL,
        *PRIMARY.keys(),
    ]
    missing_cols = [c for c in required if c not in raw.columns]
    if missing_cols:
        return pd.DataFrame(), {
            "source_rows": int(len(raw)),
            "coverage_error": f"missing_columns:{missing_cols}",
        }
    if raw["antibody_id"].astype(str).duplicated().any():
        return pd.DataFrame(), {
            "source_rows": int(len(raw)),
            "coverage_error": "duplicate_antibody_id",
        }

    work = raw.copy()
    source_rows = len(work)
    seq_ok = (
        work["vh_protein_sequence"].fillna("").astype(str).str.replace("*", "", regex=False).str.strip().ne("")
        & work["vl_protein_sequence"].fillna("").astype(str).str.replace("*", "", regex=False).str.strip().ne("")
    )
    assay_ok = np.ones(len(work), dtype=bool)
    for assay in PRIMARY:
        work[assay] = pd.to_numeric(work[assay], errors="coerce")
        assay_ok &= np.isfinite(work[assay].to_numpy(float))
    fold_numeric = pd.to_numeric(work[FOLD_COL], errors="coerce")
    fold_ok = np.isfinite(fold_numeric.to_numpy(float))

    include = seq_ok.to_numpy(bool) & assay_ok & fold_ok
    cohort = work.loc[include].copy().reset_index(drop=True)
    cohort["vh_protein_sequence"] = (
        cohort["vh_protein_sequence"].astype(str).str.replace("*", "", regex=False).str.strip()
    )
    cohort["vl_protein_sequence"] = (
        cohort["vl_protein_sequence"].astype(str).str.replace("*", "", regex=False).str.strip()
    )
    cohort[FOLD_COL] = pd.to_numeric(cohort[FOLD_COL], errors="raise").astype(int)

    ids = cohort["antibody_id"].astype(str).tolist()
    receipt = {
        "source_rows": int(source_rows),
        "excluded_missing_or_invalid_sequence": int((~seq_ok.to_numpy(bool)).sum()),
        "excluded_missing_primary_truth": int((~assay_ok).sum()),
        "excluded_missing_fold": int((~fold_ok).sum()),
        "included_candidates": int(len(cohort)),
        "unique_included_ids": int(cohort["antibody_id"].nunique()),
        "candidate_ids_sha256": hashlib.sha256(
            json.dumps(ids, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest(),
        "outer_folds": sorted(int(x) for x in cohort[FOLD_COL].unique()),
        "cohort_rule": FREEZE["cohort_rule"],
    }
    return cohort, receipt


def load_tap_features(path: Path, cohort: pd.DataFrame) -> np.ndarray:
    tap = pd.read_csv(path)
    id_candidates = [
        c for c in tap.columns
        if str(c).strip().lower() in {"antibody_id", "id", "antibody", "name", "antibody_name"}
    ]
    id_col = id_candidates[0] if id_candidates else tap.columns[0]
    feat = tap.copy()
    feat["_join"] = feat[id_col].astype(str).str.strip()
    ref = cohort[["antibody_id"]].copy()
    ref["_join"] = ref["antibody_id"].astype(str).str.strip()
    merged = ref.merge(feat, on="_join", how="left", validate="one_to_one")

    excluded = {id_col, "_join", "antibody_id", "antibody_id_x", "antibody_id_y"}
    numeric = {}
    for c in merged.columns:
        if c in excluded:
            continue
        vals = pd.to_numeric(merged[c], errors="coerce")
        if vals.notna().any():
            numeric[c] = vals
    if not numeric:
        raise ValueError("no numeric TAP features after identity join")
    frame = pd.DataFrame(numeric)
    if frame.isna().all(axis=1).any():
        raise ValueError("at least one cohort antibody has no TAP feature row")
    # Feature-only imputation is allowed for the baseline; truth is never imputed.
    frame = frame.fillna(frame.median(numeric_only=True)).fillna(0.0)
    return frame.to_numpy(float)


def clean_mask(df: pd.DataFrame) -> np.ndarray:
    out = np.ones(len(df), dtype=bool)
    for assay, spec in PRIMARY.items():
        vals = df[assay].to_numpy(float)
        if spec["bad_if"] == ">":
            out &= vals <= float(spec["threshold"])
        else:
            out &= vals >= float(spec["threshold"])
    return out


def fit_ridge_predict(x_train: np.ndarray, y_train: np.ndarray, x_test: np.ndarray, alpha: float) -> np.ndarray:
    scaler = StandardScaler().fit(x_train)
    model = Ridge(alpha=alpha).fit(scaler.transform(x_train), y_train)
    return model.predict(scaler.transform(x_test))


def inner_oof(
    x: np.ndarray,
    y: np.ndarray,
    folds: np.ndarray,
    outer_train_mask: np.ndarray,
    alpha: float,
) -> np.ndarray:
    train_indices = np.where(outer_train_mask)[0]
    pred = np.full(len(train_indices), np.nan)
    local_folds = folds[train_indices]
    unique = sorted(set(int(v) for v in local_folds))
    if len(unique) < 2:
        raise ValueError("fewer than two inner source folds")
    for f in unique:
        local_valid = local_folds == f
        local_train = ~local_valid
        if not local_train.any() or not local_valid.any():
            continue
        pred[local_valid] = fit_ridge_predict(
            x[train_indices][local_train],
            y[train_indices][local_train],
            x[train_indices][local_valid],
            alpha,
        )
    return pred


def select_alpha(
    x: np.ndarray,
    y: np.ndarray,
    folds: np.ndarray,
    outer_train_mask: np.ndarray,
) -> tuple[float, np.ndarray]:
    train_y = y[outer_train_mask]
    best = None
    for alpha in ALPHAS:
        pred = inner_oof(x, y, folds, outer_train_mask, alpha)
        valid = np.isfinite(pred) & np.isfinite(train_y)
        if valid.sum() < 10:
            continue
        mse = float(np.mean((pred[valid] - train_y[valid]) ** 2))
        cand = (mse, alpha, pred)
        if best is None or (cand[0], cand[1]) < (best[0], best[1]):
            best = cand
    if best is None:
        raise ValueError("could not select ridge alpha")
    return float(best[1]), best[2]


def residual_radius(pred: np.ndarray, truth: np.ndarray, q: float) -> float:
    valid = np.isfinite(pred) & np.isfinite(truth)
    if valid.sum() < 10:
        raise ValueError("too few residuals")
    return float(np.quantile(np.abs(pred[valid] - truth[valid]), q))


def veto_from_inner(
    inner_predictions: dict[str, np.ndarray],
    train_truth: pd.DataFrame,
    q: float,
) -> np.ndarray:
    veto = np.zeros(len(train_truth), dtype=bool)
    for assay, spec in PRIMARY.items():
        pred = inner_predictions[assay]
        truth = train_truth[assay].to_numpy(float)
        rad = residual_radius(pred, truth, q)
        t = float(spec["threshold"])
        if spec["bad_if"] == ">":
            veto |= (pred - rad) > t
        else:
            veto |= (pred + rad) < t
    return veto


def select_q(inner_predictions: dict[str, np.ndarray], train_truth: pd.DataFrame) -> float:
    clean = clean_mask(train_truth)
    floor = float(FREEZE["evaluation"]["inner_clean_retention_floor"])
    choices = []
    for q in QGRID:
        veto = veto_from_inner(inner_predictions, train_truth, q)
        retention = 1.0 - float(veto[clean].mean()) if clean.any() else 0.0
        avoided = float(veto.mean())
        if retention >= floor:
            choices.append((avoided, q))
    if not choices:
        return max(QGRID)
    choices.sort(key=lambda z: (z[0], z[1]), reverse=True)
    return float(choices[0][1])


def nested_arm(name: str, x: np.ndarray, cohort: pd.DataFrame) -> dict[str, Any]:
    folds = cohort[FOLD_COL].to_numpy(int)
    decisions = np.zeros(len(cohort), dtype=bool)
    trace = []

    for outer_fold in sorted(set(int(v) for v in folds)):
        outer_test = folds == outer_fold
        outer_train = ~outer_test
        train_truth = cohort.loc[outer_train, list(PRIMARY)].reset_index(drop=True)

        inner_preds: dict[str, np.ndarray] = {}
        outer_preds: dict[str, np.ndarray] = {}
        selected_alphas: dict[str, float] = {}

        for assay in PRIMARY:
            y = cohort[assay].to_numpy(float)
            alpha, inner_pred = select_alpha(x, y, folds, outer_train)
            inner_preds[assay] = inner_pred
            selected_alphas[assay] = alpha
            outer_preds[assay] = fit_ridge_predict(
                x[outer_train],
                y[outer_train],
                x[outer_test],
                alpha,
            )

        q = select_q(inner_preds, train_truth)
        fold_veto = np.zeros(int(outer_test.sum()), dtype=bool)
        assay_receipts = {}
        for assay, spec in PRIMARY.items():
            y_train = train_truth[assay].to_numpy(float)
            rad = residual_radius(inner_preds[assay], y_train, q)
            pred = outer_preds[assay]
            t = float(spec["threshold"])
            if spec["bad_if"] == ">":
                violations = (pred - rad) > t
            else:
                violations = (pred + rad) < t
            fold_veto |= violations
            assay_receipts[assay] = {
                "ridge_alpha": selected_alphas[assay],
                "residual_radius": rad,
                "threshold": t,
                "predicted_violations": int(violations.sum()),
            }

        decisions[outer_test] = fold_veto
        trace.append({
            "outer_fold": int(outer_fold),
            "train_n": int(outer_train.sum()),
            "test_n": int(outer_test.sum()),
            "selected_residual_quantile": q,
            "veto_n": int(fold_veto.sum()),
            "assays": assay_receipts,
        })

    return {"name": name, "veto": decisions, "trace": trace}


def metrics(veto: np.ndarray, cohort: pd.DataFrame) -> dict[str, Any]:
    clean = clean_mask(cohort)
    bad = ~clean
    n = len(cohort)
    veto_n = int(veto.sum())
    clean_n = int(clean.sum())
    bad_n = int(bad.sum())
    bad_caught = int((veto & bad).sum())
    clean_wrong = int((veto & clean).sum())
    retention = 1.0 - clean_wrong / clean_n if clean_n else 0.0
    avoided = veto_n / n if n else 0.0
    enrichment = None
    if veto_n and bad_n:
        enrichment = (bad_caught / veto_n) / (bad_n / n)
    p = float(hypergeom.sf(bad_caught - 1, n, bad_n, veto_n)) if veto_n else 1.0
    return {
        "n": int(n),
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


def render_markdown(report: dict[str, Any]) -> str:
    sr = report["source_receipt"]
    lines = [
        "# RGV-PILOT — Canonical Experiment Report",
        "",
        f"**Verdict:** `{report['verdict']}`  ",
        f"**Evidence grade:** `{report['evidence_grade']}`  ",
        f"**Policy authority:** `{report['policy_authority']}`",
        "",
        "## Question",
        "",
        "Can sequence-derived prediction identify a high-confidence developability-failure tail inside pinned GDPa1 while preserving most experimentally clean antibodies?",
        "",
        "## Source and cohort derivation",
        "",
        f"- Pinned source: `{FREEZE['source']['repository']}@{FREEZE['source']['commit']}`",
        f"- File: `{FREEZE['source']['path']}`",
        f"- Source SHA-256: `{report['data_receipts']['source_sha256']}`",
        f"- Source rows: **{sr['source_rows']}**",
        f"- Excluded for missing/invalid VH/VL sequence: **{sr['excluded_missing_or_invalid_sequence']}**",
        f"- Excluded for missing primary truth: **{sr['excluded_missing_primary_truth']}**",
        f"- Excluded for missing source fold: **{sr['excluded_missing_fold']}**",
        f"- Final evaluable cohort: **{sr['included_candidates']}**",
        f"- Cohort ID-set receipt: `{sr['candidate_ids_sha256']}`",
        f"- Source-derived outer folds: `{sr['outer_folds']}`",
        "",
        "No candidate count was hard-coded. No Jain-overlap exclusion was applied. Truth values were never imputed.",
        "",
        "## Experimental truth",
        "",
        "| Assay | Clean boundary |",
        "|---|---:|",
        f"| HIC | <= {PRIMARY['HIC']['threshold']} |",
        f"| PR_CHO | <= {PRIMARY['PR_CHO']['threshold']} |",
        f"| AC-SINS pH 7.4 | <= {PRIMARY['AC-SINS_pH7.4']['threshold']} |",
        "",
        f"Observed truth composition: **{report['cohort']['clean_count']} clean / {report['cohort']['bad_count']} bad**.",
        "",
        "## Leakage barrier",
        "",
        "The source-provided cluster/isotype fold is the outer holdout. Model alpha and residual-confidence quantile are selected using only the remaining source folds. The outer fold cannot tune its own veto.",
        "",
        "## Arms and results",
        "",
        "| Arm | Clean retention | Experiments avoided | Bad caught | Clean wrongly vetoed | Random-enrichment p |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for key, label in [
        ("simple_sequence_descriptor", "Simple sequence descriptors"),
        ("ginkgo_TAP_feature_linear", "Ginkgo TAP features + linear model"),
        ("RGV", "RGV sequence-kmer confidence veto"),
    ]:
        m = report["arms"][key]
        lines.append(
            f"| {label} | {m['clean_retention']:.3f} | {m['experiments_avoided']:.3f} | "
            f"{m['bad_candidates_caught']} | {m['clean_candidates_wrongly_vetoed']} | "
            f"{m['matched_random_one_sided_hypergeom_p']:.4f} |"
        )
    rm = report["arms"]["random_matched"]
    lines += [
        f"| Matched random expectation | — | {rm['experiments_avoided']:.3f} | {rm['expected_bad_caught']:.2f} expected | — | — |",
        "",
        "## Frozen pilot bar",
        "",
        f"- Clean retention >= **{FREEZE['pilot_bar']['clean_retention_min']:.0%}**",
        f"- Experiments avoided >= **{FREEZE['pilot_bar']['experiments_avoided_min']:.0%}**",
        f"- One-sided matched-random enrichment p <= **{FREEZE['pilot_bar']['matched_random_enrichment_one_sided_p_max']}**",
        f"- At least **{FREEZE['pilot_bar']['minimum_clean_candidates']} clean** and **{FREEZE['pilot_bar']['minimum_bad_candidates']} bad** candidates",
        "- RGV must not be Pareto-dominated by a nonrandom baseline meeting the same clean-retention floor",
        "",
        f"Pareto-dominating nonrandom baselines: `{report['comparison']['pareto_dominated_by_nonrandom_baselines']}`",
        "",
        "## What this means",
        "",
        report["interpretation"],
        "",
        "## Prior-work ledger",
        "",
        f"- CPG-001: {FREEZE['prior_work']['CPG-001']}",
        f"- CPG-002: {FREEZE['prior_work']['CPG-002']}",
        f"- RGV-001: {FREEZE['prior_work']['RGV-001']}",
        f"- RGV-P34: {FREEZE['prior_work']['RGV-P34']}",
        "",
        "## Claim boundary",
        "",
        FREEZE["claim_boundary_if_signal"] if report["verdict"] == FREEZE["verdicts"]["signal"]
        else "No positive biological claim is earned by this result.",
        "",
        "## Stop rule",
        "",
        FREEZE["kill_condition"],
        "",
        "## Candidate membership receipt",
        "",
        "The full ordered candidate ID list and per-fold model traces are preserved in the companion JSON report. This page carries the cohort hash so the membership can be independently checked without turning the human-readable report into a raw-data dump.",
        "",
    ]
    return "\n".join(lines)


def run(csv_path: Path, tap_path: Path) -> dict[str, Any]:
    cohort, source_receipt = derive_cohort(csv_path)
    bar = FREEZE["pilot_bar"]

    if (
        len(cohort) < int(bar["minimum_evaluable_candidates"])
        or source_receipt.get("coverage_error")
    ):
        return {
            "schema": "openline.rgv_pilot.report.v1",
            "experiment": "RGV-PILOT",
            "verdict": FREEZE["verdicts"]["coverage"],
            "passed": False,
            "policy_authority": "NONE",
            "evidence_grade": FREEZE["evidence_grade"],
            "source_receipt": source_receipt,
            "data_receipts": {"source_sha256": sha256_file(csv_path)},
            "interpretation": "The source-derived cohort did not satisfy the frozen mechanics/coverage boundary. No biological verdict was produced.",
        }

    simple_x = descriptor_features(cohort)
    rich_x = kmer_features(cohort)
    try:
        tap_x = load_tap_features(tap_path, cohort)
    except Exception as exc:
        return {
            "schema": "openline.rgv_pilot.report.v1",
            "experiment": "RGV-PILOT",
            "verdict": FREEZE["verdicts"]["coverage"],
            "passed": False,
            "policy_authority": "NONE",
            "evidence_grade": FREEZE["evidence_grade"],
            "source_receipt": {**source_receipt, "coverage_error": f"TAP_feature_binding:{type(exc).__name__}:{exc}"},
            "data_receipts": {"source_sha256": sha256_file(csv_path), "tap_sha256": sha256_file(tap_path)},
            "interpretation": "The frozen nonrandom baseline could not be identity-bound to the source-derived cohort. No biological verdict was produced.",
        }

    simple = nested_arm("simple_sequence_descriptor_veto", simple_x, cohort)
    tap = nested_arm("ginkgo_TAP_feature_linear_veto", tap_x, cohort)
    rgv = nested_arm("RGV_sequence_kmer_confidence_veto", rich_x, cohort)

    simple_m = metrics(simple["veto"], cohort)
    tap_m = metrics(tap["veto"], cohort)
    rgv_m = metrics(rgv["veto"], cohort)

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
        interpretation = "The source was available, but the derived truth composition did not meet the frozen minimum clean/bad support. No biological signal/null verdict is earned."
    elif signal:
        verdict = FREEZE["verdicts"]["signal"]
        interpretation = "Within this source-derived GDPa1 pilot, the learned confidence veto cleared the frozen retention, experiment-avoidance, matched-random enrichment, and baseline non-domination bars. This is exploratory internal evidence only; RGV-001 remains the independent external falsifier."
    else:
        verdict = FREEZE["verdicts"]["null"]
        interpretation = "The learned confidence veto did not clear the frozen pilot bar on the source-derived GDPa1 cohort. Under the preregistered stop rule, the learned selector/veto line closes rather than being renamed or retuned."

    return {
        "schema": "openline.rgv_pilot.report.v1",
        "experiment": "RGV-PILOT",
        "verdict": verdict,
        "passed": verdict == FREEZE["verdicts"]["signal"],
        "policy_authority": "NONE",
        "evidence_grade": FREEZE["evidence_grade"],
        "data_receipts": {
            "source_sha256": sha256_file(csv_path),
            "tap_sha256": sha256_file(tap_path),
        },
        "source_receipt": source_receipt,
        "cohort": {
            "candidate_count": int(len(cohort)),
            "clean_count": rgv_m["clean_n"],
            "bad_count": rgv_m["bad_n"],
            "candidate_ids": cohort["antibody_id"].astype(str).tolist(),
        },
        "primary_viability_region": PRIMARY,
        "arms": {
            "simple_sequence_descriptor": {**simple_m, "trace": simple["trace"]},
            "ginkgo_TAP_feature_linear": {**tap_m, "trace": tap["trace"]},
            "RGV": {**rgv_m, "trace": rgv["trace"]},
            "random_matched": {
                "veto_n": rgv_m["veto_n"],
                "experiments_avoided": rgv_m["experiments_avoided"],
                "expected_bad_caught": (
                    rgv_m["veto_n"] * rgv_m["bad_n"] / len(cohort)
                ),
            },
        },
        "comparison": {
            "pareto_dominated_by_nonrandom_baselines": dominated_by,
            "pilot_bar": bar,
        },
        "interpretation": interpretation,
        "kill_condition": FREEZE["kill_condition"],
    }


def self_test() -> None:
    rng = np.random.default_rng(25)
    fake = pd.DataFrame({
        "antibody_id": [f"x{i:02d}" for i in range(16)],
        "vh_protein_sequence": ["ACDEFGHIKLMNPQRSTVWY" * 5 for _ in range(16)],
        "vl_protein_sequence": ["YWVTSRQPNMLKIHGFEDCA" * 5 for _ in range(16)],
        FOLD_COL: [i % 4 for i in range(16)],
        "HIC": rng.normal(3.0, .4, 16),
        "PR_CHO": rng.normal(.30, .1, 16),
        "AC-SINS_pH7.4": rng.normal(12, 6, 16),
    })
    x = descriptor_features(fake)
    assert x.shape[0] == 16
    m = metrics(np.zeros(16, dtype=bool), fake)
    assert m["n"] == 16 and m["veto_n"] == 0
    print(json.dumps({"self_test": "PASS", "rows": 16, "features": int(x.shape[1])}))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--csv")
    p.add_argument("--tap")
    p.add_argument("--json-output")
    p.add_argument("--markdown-output")
    p.add_argument("--self-test", action="store_true")
    a = p.parse_args()
    if a.self_test:
        self_test()
        return 0
    if not all((a.csv, a.tap, a.json_output, a.markdown_output)):
        p.error("--csv --tap --json-output --markdown-output are required")
    report = run(Path(a.csv), Path(a.tap))
    Path(a.json_output).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    # Coverage reports may lack the full science sections; render a minimal one-page receipt.
    if report["verdict"] == FREEZE["verdicts"]["coverage"]:
        sr = report.get("source_receipt", {})
        md = "\n".join([
            "# RGV-PILOT — Canonical Experiment Report",
            "",
            f"**Verdict:** `{report['verdict']}`",
            "",
            report["interpretation"],
            "",
            "## Source receipt",
            "",
            "```json",
            json.dumps(sr, indent=2, sort_keys=True),
            "```",
            "",
            "## Stop/claim boundary",
            "",
            "Coverage failure is not a biological null. No positive or negative selector claim is earned.",
        ])
    else:
        md = render_markdown(report)
    Path(a.markdown_output).write_text(md + "\n", encoding="utf-8")
    print(json.dumps({
        "experiment": report["experiment"],
        "verdict": report["verdict"],
        "cohort_n": report.get("cohort", {}).get("candidate_count"),
        "clean_n": report.get("cohort", {}).get("clean_count"),
        "bad_n": report.get("cohort", {}).get("bad_count"),
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
