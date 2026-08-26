from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from pathlib import Path
from typing import Any, Iterable

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from benchmarks.candidate_promotion.experiments.rgv_001.run_suite import descriptor_features

HERE = Path(__file__).resolve().parent
FREEZE = json.loads((HERE / "FREEZE.json").read_text(encoding="utf-8"))
ASSAYS = tuple(FREEZE["truth"].keys())
FOLD_COL = FREEZE["cohort_rule"]["required_outer_fold"]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def is_fail(assay: str, value: float) -> bool:
    spec = FREEZE["truth"][assay]
    t = float(spec["threshold"])
    if spec["bad_if"] == ">":
        return float(value) > t
    return float(value) < t


def derive_cohort(path: Path) -> tuple[pd.DataFrame, dict[str, Any]]:
    raw = pd.read_csv(path)
    required = [
        "antibody_id", "vh_protein_sequence", "vl_protein_sequence", FOLD_COL, *ASSAYS
    ]
    missing = [c for c in required if c not in raw.columns]
    if missing:
        return pd.DataFrame(), {"coverage_error": f"missing_columns:{missing}", "source_rows": len(raw)}
    if raw["antibody_id"].astype(str).duplicated().any():
        return pd.DataFrame(), {"coverage_error": "duplicate_antibody_id", "source_rows": len(raw)}

    work = raw.copy()
    seq_ok = (
        work["vh_protein_sequence"].fillna("").astype(str).str.replace("*","",regex=False).str.strip().ne("")
        & work["vl_protein_sequence"].fillna("").astype(str).str.replace("*","",regex=False).str.strip().ne("")
    )
    truth_ok = np.ones(len(work), dtype=bool)
    for a in ASSAYS:
        work[a] = pd.to_numeric(work[a], errors="coerce")
        truth_ok &= np.isfinite(work[a].to_numpy(float))
    fold = pd.to_numeric(work[FOLD_COL], errors="coerce")
    fold_ok = np.isfinite(fold.to_numpy(float))
    keep = seq_ok.to_numpy(bool) & truth_ok & fold_ok
    cohort = work.loc[keep].copy().reset_index(drop=True)
    cohort["vh_protein_sequence"] = cohort["vh_protein_sequence"].astype(str).str.replace("*","",regex=False).str.strip()
    cohort["vl_protein_sequence"] = cohort["vl_protein_sequence"].astype(str).str.replace("*","",regex=False).str.strip()
    cohort[FOLD_COL] = pd.to_numeric(cohort[FOLD_COL], errors="raise").astype(int)

    ids = cohort["antibody_id"].astype(str).tolist()
    receipt = {
        "source_rows": int(len(raw)),
        "excluded_missing_or_invalid_sequence": int((~seq_ok.to_numpy(bool)).sum()),
        "excluded_missing_primary_truth": int((~truth_ok).sum()),
        "excluded_missing_fold": int((~fold_ok).sum()),
        "included_candidates": int(len(cohort)),
        "candidate_ids_sha256": hashlib.sha256(
            json.dumps(ids, separators=(",",":")).encode()
        ).hexdigest(),
        "outer_folds": sorted(int(x) for x in cohort[FOLD_COL].unique()),
    }
    return cohort, receipt


def final_truth(row: pd.Series) -> str:
    return "VETO" if any(is_fail(a, float(row[a])) for a in ASSAYS) else "RETAIN"


def run_order(row: pd.Series, order: Iterable[str]) -> tuple[str, int, list[str]]:
    revealed = []
    for a in order:
        revealed.append(a)
        if is_fail(a, float(row[a])):
            return "VETO", len(revealed), revealed
    return "RETAIN", len(revealed), revealed


def static_best_order(train: pd.DataFrame) -> tuple[str, ...]:
    candidates = []
    for order in itertools.permutations(ASSAYS):
        total = sum(run_order(row, order)[1] for _, row in train.iterrows())
        candidates.append((int(total), tuple(order)))
    candidates.sort(key=lambda x: (x[0], x[1]))
    return candidates[0][1]


def conditional_pool(train: pd.DataFrame, passed: tuple[str, ...]) -> pd.DataFrame:
    if not passed:
        return train
    mask = np.ones(len(train), dtype=bool)
    for a in passed:
        vals = train[a].to_numpy(float)
        mask &= np.array([not is_fail(a, v) for v in vals], dtype=bool)
    return train.loc[mask]


def smoothed_failure_rate(train: pd.DataFrame, target: str, passed: tuple[str, ...]) -> float:
    pool = conditional_pool(train, passed)
    if len(pool) == 0:
        return 0.5
    y = np.array([is_fail(target, v) for v in pool[target].to_numpy(float)], dtype=int)
    return float((y.sum() + 1.0) / (len(y) + 2.0))


def history_route(row: pd.Series, train: pd.DataFrame) -> tuple[str, int, list[str]]:
    remaining = list(ASSAYS)
    passed: list[str] = []
    revealed: list[str] = []
    while remaining:
        scores = [
            (smoothed_failure_rate(train, a, tuple(sorted(passed))), a)
            for a in remaining
        ]
        scores.sort(key=lambda x: (-x[0], x[1]))
        a = scores[0][1]
        remaining.remove(a)
        revealed.append(a)
        if is_fail(a, float(row[a])):
            return "VETO", len(revealed), revealed
        passed.append(a)
    return "RETAIN", len(revealed), revealed


def seq_state_features(
    seq_x: np.ndarray,
    frame: pd.DataFrame,
    indices: np.ndarray,
    passed: tuple[str, ...],
) -> np.ndarray:
    base = seq_x[indices]
    extras = []
    for a in ASSAYS:
        if a in passed:
            vals = frame.iloc[indices][a].to_numpy(float).reshape(-1,1)
            extras.append(vals)
        else:
            extras.append(np.zeros((len(indices),1), dtype=float))
        extras.append(np.full((len(indices),1), 1.0 if a in passed else 0.0))
    return np.hstack([base, *extras])


def predict_failure_probability(
    train: pd.DataFrame,
    seq_train: np.ndarray,
    row_seq: np.ndarray,
    target: str,
    passed: tuple[str, ...],
    observed_values: dict[str,float],
) -> float:
    pool = conditional_pool(train, passed)
    if len(pool) == 0:
        return 0.5
    pool_idx = pool.index.to_numpy(int)
    y = np.array([is_fail(target, v) for v in pool[target].to_numpy(float)], dtype=int)
    if len(np.unique(y)) < 2 or len(y) < 12:
        return float((y.sum() + 1.0) / (len(y) + 2.0))

    # train.index is reset in each outer fold, so pool_idx aligns to seq_train.
    x = seq_state_features(seq_train, train, pool_idx, passed)
    test_base = row_seq.reshape(1,-1)
    extras = []
    for a in ASSAYS:
        extras.append(np.array([[observed_values.get(a, 0.0)]], dtype=float))
        extras.append(np.array([[1.0 if a in passed else 0.0]], dtype=float))
    xt = np.hstack([test_base, *extras])

    scaler = StandardScaler().fit(x)
    model = LogisticRegression(C=1.0, penalty="l2", max_iter=5000, solver="liblinear")
    model.fit(scaler.transform(x), y)
    return float(model.predict_proba(scaler.transform(xt))[0,1])


def sequence_route(
    row: pd.Series,
    row_seq: np.ndarray,
    train: pd.DataFrame,
    seq_train: np.ndarray,
) -> tuple[str, int, list[str]]:
    remaining = list(ASSAYS)
    passed: list[str] = []
    observed: dict[str,float] = {}
    revealed: list[str] = []
    while remaining:
        state = tuple(sorted(passed))
        scores = []
        for a in remaining:
            p = predict_failure_probability(
                train, seq_train, row_seq, a, state, observed
            )
            scores.append((p, a))
        scores.sort(key=lambda x: (-x[0], x[1]))
        a = scores[0][1]
        remaining.remove(a)
        revealed.append(a)
        value = float(row[a])
        observed[a] = value
        if is_fail(a, value):
            return "VETO", len(revealed), revealed
        passed.append(a)
    return "RETAIN", len(revealed), revealed


def oracle_count(row: pd.Series) -> int:
    return 1 if final_truth(row) == "VETO" else len(ASSAYS)


def paired_bootstrap_relative_savings(
    baseline: np.ndarray, challenger: np.ndarray
) -> dict[str,float]:
    rng = np.random.default_rng(int(FREEZE["bootstrap"]["seed"]))
    draws = int(FREEZE["bootstrap"]["paired_candidate_bootstrap_draws"])
    n = len(baseline)
    vals = np.empty(draws, dtype=float)
    for i in range(draws):
        idx = rng.integers(0, n, size=n)
        b = baseline[idx].sum()
        c = challenger[idx].sum()
        vals[i] = (b-c)/b if b else 0.0
    alpha = (1.0 - float(FREEZE["bootstrap"]["confidence"])) / 2.0
    return {
        "point": float((baseline.sum()-challenger.sum())/baseline.sum()),
        "ci_low": float(np.quantile(vals, alpha)),
        "ci_high": float(np.quantile(vals, 1-alpha)),
    }


def run(csv_path: Path) -> dict[str,Any]:
    cohort, receipt = derive_cohort(csv_path)
    if receipt.get("coverage_error") or len(cohort) < 30:
        return {
            "schema":"openline.rma_001.report.v1",
            "experiment":"RMA-001",
            "verdict":FREEZE["verdicts"]["coverage"],
            "policy_authority":"NONE",
            "evidence_grade":FREEZE["evidence_grade"],
            "source_receipt":receipt,
        }

    seq_all = descriptor_features(cohort)
    folds = cohort[FOLD_COL].to_numpy(int)
    n = len(cohort)
    exhaustive = np.full(n, len(ASSAYS), dtype=int)
    static_counts = np.zeros(n, dtype=int)
    hist_counts = np.zeros(n, dtype=int)
    seq_counts = np.zeros(n, dtype=int)
    oracle_counts = np.zeros(n, dtype=int)
    traces = []
    concordance = {"best_static":0, "history_adaptive":0, "sequence_adaptive":0}

    for outer_fold in sorted(set(int(x) for x in folds)):
        test_idx = np.where(folds == outer_fold)[0]
        train_idx = np.where(folds != outer_fold)[0]
        train = cohort.iloc[train_idx].copy().reset_index(drop=True)
        seq_train = seq_all[train_idx]
        order = static_best_order(train)

        fold_trace = {"outer_fold":outer_fold, "best_static_order":list(order), "candidates":[]}
        for i in test_idx:
            row = cohort.iloc[i]
            truth = final_truth(row)
            sdisp, scount, sorder = run_order(row, order)
            hdisp, hcount, horder = history_route(row, train)
            qdisp, qcount, qorder = sequence_route(row, seq_all[i], train, seq_train)

            static_counts[i] = scount
            hist_counts[i] = hcount
            seq_counts[i] = qcount
            oracle_counts[i] = oracle_count(row)
            concordance["best_static"] += int(sdisp == truth)
            concordance["history_adaptive"] += int(hdisp == truth)
            concordance["sequence_adaptive"] += int(qdisp == truth)
            fold_trace["candidates"].append({
                "candidate_id":str(row["antibody_id"]),
                "truth":truth,
                "best_static":{"disposition":sdisp,"reveals":scount,"order":sorder},
                "history_adaptive":{"disposition":hdisp,"reveals":hcount,"order":horder},
                "sequence_adaptive":{"disposition":qdisp,"reveals":qcount,"order":qorder},
            })
        traces.append(fold_trace)

    for k in concordance:
        concordance[k] = float(concordance[k]/n)

    seq_vs_static = paired_bootstrap_relative_savings(static_counts, seq_counts)
    hist_vs_static = paired_bootstrap_relative_savings(static_counts, hist_counts)
    seq_vs_hist = paired_bootstrap_relative_savings(hist_counts, seq_counts)

    exact = all(v == 1.0 for v in concordance.values())
    b = FREEZE["signal_bars"]
    sequence_signal = (
        exact
        and seq_vs_static["point"] >= float(b["sequence_vs_best_static_relative_savings_min"])
        and seq_vs_static["ci_low"] > 0
        and seq_vs_hist["point"] >= float(b["sequence_vs_history_relative_savings_min"])
        and seq_vs_hist["ci_low"] > 0
    )
    history_signal = (
        exact
        and hist_vs_static["point"] >= float(b["sequence_vs_best_static_relative_savings_min"])
        and hist_vs_static["ci_low"] > 0
    )

    if not exact:
        verdict = FREEZE["verdicts"]["coverage"]
        interpretation = "A routing policy failed exact final-disposition concordance. The benchmark is invalid because prediction was allowed to substitute for measurement somewhere in the path."
    elif sequence_signal:
        verdict = FREEZE["verdicts"]["sequence"]
        interpretation = "Sequence-conditioned adaptive routing reduced held-out assay reveals beyond both the strongest fixed-order baseline and history-only adaptive routing, while every final disposition remained grounded in revealed assay truth."
    elif history_signal:
        verdict = FREEZE["verdicts"]["history"]
        interpretation = "Adaptive routing reduced held-out assay reveals relative to the best fixed order, but sequence information did not earn the frozen incremental advantage. The useful mechanism is conditional measurement history, not sequence prediction."
    else:
        verdict = FREEZE["verdicts"]["null"]
        interpretation = "Adaptive routing did not clear the frozen savings bar over the strongest fixed-order baseline. On this three-assay substrate, there is no measurement-allocation mechanism worth promoting."

    clean_n = sum(final_truth(row)=="RETAIN" for _,row in cohort.iterrows())
    report = {
        "schema":"openline.rma_001.report.v1",
        "experiment":"RMA-001",
        "verdict":verdict,
        "policy_authority":"NONE",
        "evidence_grade":FREEZE["evidence_grade"],
        "source_receipt":receipt,
        "data_receipts":{"source_sha256":sha256_file(csv_path)},
        "cohort":{"n":n,"clean_n":int(clean_n),"bad_n":int(n-clean_n)},
        "authority_boundary":FREEZE["authority_boundary"],
        "concordance":concordance,
        "measurement_counts":{
            "exhaustive":int(exhaustive.sum()),
            "best_static":int(static_counts.sum()),
            "history_adaptive":int(hist_counts.sum()),
            "sequence_adaptive":int(seq_counts.sum()),
            "oracle":int(oracle_counts.sum()),
        },
        "relative_savings":{
            "history_vs_best_static":hist_vs_static,
            "sequence_vs_best_static":seq_vs_static,
            "sequence_vs_history":seq_vs_hist,
            "sequence_vs_exhaustive":float((exhaustive.sum()-seq_counts.sum())/exhaustive.sum()),
            "best_static_vs_exhaustive":float((exhaustive.sum()-static_counts.sum())/exhaustive.sum()),
            "oracle_vs_exhaustive":float((exhaustive.sum()-oracle_counts.sum())/exhaustive.sum()),
        },
        "interpretation":interpretation,
        "claim_boundary":FREEZE["claim_boundary"],
        "stop_rule":FREEZE["stop_rule"],
        "traces":traces,
    }
    return report


def render_markdown(r: dict[str,Any]) -> str:
    if r["verdict"] == FREEZE["verdicts"]["coverage"]:
        return "\n".join([
            "# RMA-001 — Canonical Report","",
            f"**Verdict:** `{r['verdict']}`","",
            "No routing claim is earned.","",
            "```json",json.dumps(r.get("source_receipt",{}),indent=2,sort_keys=True),"```"
        ])
    m = r["measurement_counts"]; s = r["relative_savings"]; c = r["concordance"]
    return "\n".join([
        "# RMA-001 — Reality Measurement Allocation","",
        f"**Verdict:** `{r['verdict']}`  ",
        f"**Evidence grade:** `{r['evidence_grade']}`  ",
        f"**Policy authority:** `{r['policy_authority']}`","",
        "## Question","",
        "Can prediction help decide **where reality should look next** even when it cannot safely replace reality?","",
        "## Evidence boundary","",
        "The model never declares VETO or RETAIN. It only chooses the next assay. VETO requires an observed failure; RETAIN requires all three observed clean.","",
        "## Cohort","",
        f"- Source rows: **{r['source_receipt']['source_rows']}**",
        f"- Evaluable antibodies: **{r['cohort']['n']}**",
        f"- Clean: **{r['cohort']['clean_n']}**",
        f"- Bad: **{r['cohort']['bad_n']}**",
        f"- Cohort receipt: `{r['source_receipt']['candidate_ids_sha256']}`","",
        "## Unit-cost measurement results","",
        "| Policy | Assay reveals | Final concordance |",
        "|---|---:|---:|",
        f"| Exhaustive | {m['exhaustive']} | 1.000 by full measurement |",
        f"| Best fixed order, chosen on training folds | {m['best_static']} | {c['best_static']:.3f} |",
        f"| History-only adaptive | {m['history_adaptive']} | {c['history_adaptive']:.3f} |",
        f"| Sequence + history adaptive | {m['sequence_adaptive']} | {c['sequence_adaptive']:.3f} |",
        f"| Oracle upper bound | {m['oracle']} | 1.000 |","",
        "## Paired savings","",
        f"- Best static vs exhaustive: **{s['best_static_vs_exhaustive']:.1%}**",
        f"- History adaptive vs best static: **{s['history_vs_best_static']['point']:.1%}** "
        f"(95% bootstrap CI {s['history_vs_best_static']['ci_low']:.1%} to {s['history_vs_best_static']['ci_high']:.1%})",
        f"- Sequence adaptive vs best static: **{s['sequence_vs_best_static']['point']:.1%}** "
        f"(95% bootstrap CI {s['sequence_vs_best_static']['ci_low']:.1%} to {s['sequence_vs_best_static']['ci_high']:.1%})",
        f"- Sequence adaptive vs history adaptive: **{s['sequence_vs_history']['point']:.1%}** "
        f"(95% bootstrap CI {s['sequence_vs_history']['ci_low']:.1%} to {s['sequence_vs_history']['ci_high']:.1%})",
        f"- Sequence adaptive vs exhaustive: **{s['sequence_vs_exhaustive']:.1%}**",
        f"- Oracle vs exhaustive: **{s['oracle_vs_exhaustive']:.1%}**","",
        "## Frozen bar","",
        "- Sequence routing signal: >=10% fewer reveals than best static, CI lower bound >0; AND >=5% fewer than history-only adaptive, CI lower bound >0.",
        "- History-only routing signal: >=10% fewer reveals than best static, CI lower bound >0.",
        "- Every executable policy must have 100% final-disposition concordance.","",
        "## Interpretation","",r["interpretation"],"",
        "## Prior result","",FREEZE["prior_result"]["RGV-PILOT"],"",
        "## Claim boundary","",
        "No clinical-ranking claim. No sequence-only veto claim. No dollar-savings claim. This is a held-out GDPa1 simulation of measurement allocation under unit assay cost.","",
        "## Stop rule","",FREEZE["stop_rule"],""
    ])


def verify_report(r: dict[str,Any]) -> list[str]:
    errors = []
    if r.get("experiment") != "RMA-001": errors.append("wrong_experiment")
    if r.get("policy_authority") != "NONE": errors.append("policy_authority_changed")
    if r.get("verdict") not in set(FREEZE["verdicts"].values()): errors.append("unknown_verdict")
    if r.get("verdict") != FREEZE["verdicts"]["coverage"]:
        for k,v in r.get("concordance",{}).items():
            if float(v) != 1.0: errors.append(f"concordance_failed:{k}")
        m = r["measurement_counts"]
        if not (m["oracle"] <= m["best_static"] <= m["exhaustive"]): errors.append("static_bounds_invalid")
        if not (m["oracle"] <= m["history_adaptive"] <= m["exhaustive"]): errors.append("history_bounds_invalid")
        if not (m["oracle"] <= m["sequence_adaptive"] <= m["exhaustive"]): errors.append("sequence_bounds_invalid")
    return errors


def self_test() -> None:
    row = pd.Series({"HIC":4.0,"PR_CHO":0.1,"AC-SINS_pH7.4":10.0})
    d,n,o = run_order(row, ASSAYS)
    assert d == "VETO" and n >= 1
    assert oracle_count(row) == 1
    print(json.dumps({"self_test":"PASS","assays":ASSAYS}))


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("--csv")
    p.add_argument("--json-output")
    p.add_argument("--markdown-output")
    p.add_argument("--self-test",action="store_true")
    p.add_argument("--verify")
    a=p.parse_args()
    if a.self_test:
        self_test(); return 0
    if a.verify:
        r=json.loads(Path(a.verify).read_text())
        errors=verify_report(r)
        print(json.dumps({"valid":not errors,"errors":errors,"verdict":r.get("verdict")},indent=2))
        return 0 if not errors else 1
    if not all((a.csv,a.json_output,a.markdown_output)):
        p.error("--csv --json-output --markdown-output required")
    r=run(Path(a.csv))
    Path(a.json_output).write_text(json.dumps(r,indent=2,sort_keys=True)+"\n")
    Path(a.markdown_output).write_text(render_markdown(r)+"\n")
    print(json.dumps({
        "experiment":r["experiment"],
        "verdict":r["verdict"],
        "cohort_n":r.get("cohort",{}).get("n"),
        "measurement_counts":r.get("measurement_counts"),
        "relative_savings":r.get("relative_savings"),
    },indent=2))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
