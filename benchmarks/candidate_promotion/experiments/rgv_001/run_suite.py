from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import random
import re
from typing import Any

import numpy as np
import pandas as pd
from sklearn.linear_model import Ridge
from sklearn.preprocessing import StandardScaler

HERE = Path(__file__).resolve().parent
FREEZE = json.loads((HERE / "FREEZE.json").read_text(encoding="utf-8"))
PRIMARY = FREEZE["primary_viability_region"]
SECONDARY = FREEZE["secondary_only"]
VERDICTS = FREEZE["verdicts"]
AA = "ACDEFGHIKLMNPQRSTVWY"
AA_INDEX = {a: i for i, a in enumerate(AA)}
HYDRO = set("AVILMFWY")
POS = set("KRH")
NEG = set("DE")
GDP_COL_ALIASES = {
    "antibody_id": ["antibody_id", "Antibody ID", "antibody", "id", "ID"],
    "antibody_name": ["antibody_name", "Antibody Name", "name", "Name"],
    "HIC": ["HIC", "hic", "HIC Retention Time", "HIC retention time"],
    "PR_CHO": ["PR_CHO", "PR-CHO", "PR CHO", "CHO", "Polyreactivity CHO"],
    "AC-SINS_pH7.4": ["AC-SINS_pH7.4", "AC-SINS pH7.4", "AC-SINS pH 7.4", "AC_SINS_pH7.4"],
    "Tm2": ["Tm2", "TM2", "Tm 2"],
    "vh_protein_sequence": ["vh_protein_sequence", "VH", "VH sequence", "heavy_sequence", "Heavy Sequence"],
    "vl_protein_sequence": ["vl_protein_sequence", "VL", "VL sequence", "light_sequence", "Light Sequence"],
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def canonical_col(df: pd.DataFrame, key: str, required: bool = True) -> str | None:
    lowered = {str(c).strip().lower(): str(c) for c in df.columns}
    for alias in GDP_COL_ALIASES[key]:
        if alias.lower() in lowered:
            return lowered[alias.lower()]
    # permissive normalized fallback
    def norm(x: str) -> str:
        return re.sub(r"[^a-z0-9]", "", x.lower())
    target = {norm(a) for a in GDP_COL_ALIASES[key]}
    for c in df.columns:
        if norm(str(c)) in target:
            return str(c)
    if required:
        raise ValueError(f"required column {key!r} not found; columns={list(df.columns)!r}")
    return None


def normalize_frame(df: pd.DataFrame, *, need_sequences: bool) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)
    for key in ("antibody_id", "antibody_name"):
        c = canonical_col(df, key, required=False)
        if c is not None:
            out[key] = df[c].astype(str).str.strip()
    for key in ("HIC", "PR_CHO", "AC-SINS_pH7.4", "Tm2"):
        c = canonical_col(df, key, required=False)
        if c is not None:
            out[key] = pd.to_numeric(df[c], errors="coerce")
    if need_sequences:
        for key in ("vh_protein_sequence", "vl_protein_sequence"):
            c = canonical_col(df, key, required=True)
            out[key] = df[c].astype(str).str.replace("*", "", regex=False).str.strip()
    return out


def read_table(path: Path) -> pd.DataFrame:
    if path.suffix.lower() == ".csv":
        return pd.read_csv(path)
    if path.suffix.lower() in {".xlsx", ".xls"}:
        book = pd.ExcelFile(path)
        candidates = []
        for sheet in book.sheet_names:
            frame = pd.read_excel(path, sheet_name=sheet)
            candidates.append((len(frame), sheet, frame))
        if not candidates:
            raise ValueError(f"no sheets in {path}")
        candidates.sort(reverse=True, key=lambda x: x[0])
        return candidates[0][2]
    raise ValueError(f"unsupported table: {path}")


def discover_gdpa3(path: Path) -> tuple[Path, pd.DataFrame]:
    files = [path] if path.is_file() else sorted(
        p for p in path.rglob("*") if p.suffix.lower() in {".csv", ".xlsx", ".xls"}
    )
    scored = []
    for p in files:
        try:
            df = read_table(p)
            norm = normalize_frame(df, need_sequences=False)
            assay_count = sum(k in norm.columns for k in PRIMARY)
            id_count = sum(k in norm.columns for k in ("antibody_id", "antibody_name"))
            score = assay_count * 100 + id_count * 10 + min(len(df), 100)
            scored.append((score, p, norm))
        except Exception:
            continue
    if not scored:
        raise ValueError(f"no GDPa3-like table found under {path}")
    scored.sort(key=lambda x: x[0], reverse=True)
    _, p, norm = scored[0]
    return p, norm


def clean_mask(df: pd.DataFrame, thresholds: dict[str, dict[str, Any]]) -> np.ndarray:
    mask = np.ones(len(df), dtype=bool)
    for assay, spec in thresholds.items():
        vals = df[assay].to_numpy(float)
        if spec["bad_if"] == ">":
            mask &= vals <= float(spec["threshold"])
        else:
            mask &= vals >= float(spec["threshold"])
    return mask


def _seq(seq: Any) -> str:
    return "".join(ch for ch in str(seq).upper() if ch in AA)


def descriptor_features(df: pd.DataFrame) -> np.ndarray:
    rows = []
    for _, r in df.iterrows():
        vals = []
        for key in ("vh_protein_sequence", "vl_protein_sequence"):
            s = _seq(r[key])
            n = max(len(s), 1)
            vals.extend([
                len(s) / 150.0,
                sum(ch in HYDRO for ch in s) / n,
                (sum(ch in POS for ch in s) - sum(ch in NEG for ch in s)) / n,
                sum(ch == "C" for ch in s) / n,
                sum(ch in "GP" for ch in s) / n,
            ])
            vals.extend([s.count(a) / n for a in AA])
        rows.append(vals)
    return np.asarray(rows, dtype=float)


def kmer_features(df: pd.DataFrame, bins: int = 256) -> np.ndarray:
    base = descriptor_features(df)
    extra = np.zeros((len(df), bins * 2), dtype=float)
    for i, (_, r) in enumerate(df.iterrows()):
        for chain_i, key in enumerate(("vh_protein_sequence", "vl_protein_sequence")):
            s = _seq(r[key])
            denom = max(len(s) - 2, 1)
            offset = chain_i * bins
            for j in range(max(0, len(s) - 2)):
                k = s[j:j+3].encode()
                idx = int.from_bytes(hashlib.blake2b(k, digest_size=4).digest(), "big") % bins
                extra[i, offset + idx] += 1.0 / denom
    return np.hstack([base, extra])


def load_tap(path: Path, ids: pd.DataFrame) -> np.ndarray:
    df = pd.read_csv(path)
    # infer identifier column; Ginkgo processed features use antibody identifiers.
    id_candidates = [c for c in df.columns if str(c).lower() in {"antibody_id", "id", "antibody", "name", "antibody_name"}]
    if not id_candidates:
        id_candidates = [df.columns[0]]
    id_col = id_candidates[0]
    join_key = "antibody_id" if "antibody_id" in ids.columns else "antibody_name"
    ref = ids[[join_key]].copy()
    ref["_join"] = ref[join_key].astype(str)
    feat = df.copy()
    feat["_join"] = feat[id_col].astype(str)
    merged = ref.merge(feat, on="_join", how="left", validate="one_to_one")
    numeric = merged.select_dtypes(include=[np.number]).copy()
    if numeric.shape[1] == 0:
        for c in feat.columns:
            if c in {id_col, "_join"}:
                continue
            merged[c] = pd.to_numeric(merged[c], errors="coerce")
        numeric = merged[[c for c in merged.columns if c not in {join_key, "_join", id_col}]].select_dtypes(include=[np.number])
    if numeric.isna().all(axis=0).any():
        numeric = numeric.loc[:, ~numeric.isna().all(axis=0)]
    numeric = numeric.fillna(numeric.median(numeric_only=True)).fillna(0.0)
    if len(numeric) != len(ids):
        raise ValueError("TAP feature join changed row count")
    return numeric.to_numpy(float)


def ridge_oof(train_x: np.ndarray, train_y: np.ndarray, folds: np.ndarray, test_x: np.ndarray) -> tuple[np.ndarray, np.ndarray, float]:
    alphas = [0.1, 1.0, 10.0, 100.0]
    valid = np.isfinite(train_y)
    unique_folds = sorted(set(int(v) for v in folds[valid]))
    best = None
    for alpha in alphas:
        pred = np.full(len(train_y), np.nan)
        for f in unique_folds:
            tr = valid & (folds != f)
            va = valid & (folds == f)
            scaler = StandardScaler().fit(train_x[tr])
            model = Ridge(alpha=alpha).fit(scaler.transform(train_x[tr]), train_y[tr])
            pred[va] = model.predict(scaler.transform(train_x[va]))
        mse = float(np.nanmean((pred[valid] - train_y[valid]) ** 2))
        if best is None or mse < best[0]:
            best = (mse, alpha, pred)
    assert best is not None
    _, alpha, oof = best
    scaler = StandardScaler().fit(train_x[valid])
    model = Ridge(alpha=alpha).fit(scaler.transform(train_x[valid]), train_y[valid])
    test_pred = model.predict(scaler.transform(test_x))
    return oof, test_pred, float(alpha)


def fit_prediction_bundle(train: pd.DataFrame, test: pd.DataFrame, x_train: np.ndarray, x_test: np.ndarray, folds: np.ndarray) -> dict[str, Any]:
    bundle = {}
    for assay in list(PRIMARY) + list(SECONDARY):
        y = train[assay].to_numpy(float)
        oof, pred, alpha = ridge_oof(x_train, y, folds, x_test)
        bundle[assay] = {"oof": oof, "test": pred, "alpha": alpha}
    return bundle


def choose_quantile(bundle: dict[str, Any], train: pd.DataFrame) -> float:
    grid = FREEZE["operating_point"]["residual_quantile_grid"]
    clean = clean_mask(train, PRIMARY)
    best = None
    for q in grid:
        veto = veto_from_predictions(bundle, train, phase="oof", q=float(q))
        retention = 1.0 - float(veto[clean].mean()) if clean.any() else 0.0
        avoided = float(veto.mean())
        if retention >= FREEZE["operating_point"]["minimum_training_clean_retention"]:
            # maximize avoidance, break ties toward more conservative q
            cand = (avoided, q)
            if best is None or cand[0] > best[0] or (cand[0] == best[0] and q > best[1]):
                best = cand
    return float(best[1] if best else max(grid))


def residual_radius(bundle: dict[str, Any], train: pd.DataFrame, assay: str, q: float) -> float:
    pred = np.asarray(bundle[assay]["oof"], float)
    y = train[assay].to_numpy(float)
    valid = np.isfinite(pred) & np.isfinite(y)
    return float(np.quantile(np.abs(pred[valid] - y[valid]), q))


def veto_from_predictions(bundle: dict[str, Any], train_for_residuals: pd.DataFrame, *, phase: str, q: float, thresholds: dict[str, dict[str, Any]] | None = None) -> np.ndarray:
    thresholds = thresholds or PRIMARY
    n = len(next(iter(bundle.values()))[phase])
    veto = np.zeros(n, dtype=bool)
    for assay, spec in thresholds.items():
        pred = np.asarray(bundle[assay][phase], float)
        rad = residual_radius(bundle, train_for_residuals, assay, q)
        t = float(spec["threshold"])
        if spec["bad_if"] == ">":
            high_conf_bad = (pred - rad) > t
        else:
            high_conf_bad = (pred + rad) < t
        veto |= high_conf_bad
    return veto


def metrics(veto: np.ndarray, truth: pd.DataFrame, thresholds: dict[str, dict[str, Any]]) -> dict[str, Any]:
    clean = clean_mask(truth, thresholds)
    bad = ~clean
    clean_n = int(clean.sum())
    bad_n = int(bad.sum())
    retained_clean = int((~veto & clean).sum())
    veto_bad = int((veto & bad).sum())
    avoided = float(veto.mean()) if len(veto) else 0.0
    retention = retained_clean / clean_n if clean_n else 0.0
    bad_enrichment = (veto_bad / int(veto.sum())) / (bad_n / len(veto)) if int(veto.sum()) and bad_n else 0.0
    false_veto = int((veto & clean).sum())
    return {
        "n": int(len(veto)),
        "clean_n": clean_n,
        "bad_n": bad_n,
        "veto_n": int(veto.sum()),
        "experiments_avoided": avoided,
        "clean_retention": retention,
        "bad_candidates_caught": veto_bad,
        "clean_candidates_wrongly_vetoed": false_veto,
        "bad_candidate_enrichment_among_vetoes": bad_enrichment,
        "experiments_avoided_per_clean_wrongly_vetoed": (int(veto.sum()) / false_veto) if false_veto else None,
    }


def random_baseline(n: int, veto_n: int, truth: pd.DataFrame, thresholds: dict[str, dict[str, Any]], seed: int = 1729, reps: int = 10000) -> dict[str, Any]:
    rng = random.Random(seed)
    vals = []
    for _ in range(reps):
        idx = set(rng.sample(range(n), veto_n)) if veto_n else set()
        v = np.array([i in idx for i in range(n)], dtype=bool)
        vals.append(metrics(v, truth, thresholds))
    return {
        "reps": reps,
        "matched_veto_n": veto_n,
        "mean_experiments_avoided": float(np.mean([x["experiments_avoided"] for x in vals])),
        "mean_clean_retention": float(np.mean([x["clean_retention"] for x in vals])),
        "mean_bad_candidate_enrichment": float(np.mean([x["bad_candidate_enrichment_among_vetoes"] for x in vals])),
    }


def align_external(train_seq_source: pd.DataFrame, labels: pd.DataFrame) -> pd.DataFrame:
    # Prefer stable antibody_id; fall back to antibody_name.
    for key in ("antibody_id", "antibody_name"):
        if key in train_seq_source.columns and key in labels.columns:
            a = train_seq_source.copy()
            b = labels.copy()
            a["_join"] = a[key].astype(str).str.strip().str.lower()
            b["_join"] = b[key].astype(str).str.strip().str.lower()
            out = a.merge(b.drop(columns=[key], errors="ignore"), on="_join", how="inner", suffixes=("", "_label"))
            if len(out) >= 60:
                return out.drop(columns=["_join"])
    # Last-resort row alignment is forbidden because it can silently misbind truth.
    raise ValueError("could not identity-bind GDPa3 labels to heldout sequences with >=60 rows")


def stress_thresholds(sign: int) -> dict[str, dict[str, Any]]:
    frac = float(FREEZE["robustness"]["threshold_stress_fraction"])
    out = json.loads(json.dumps(PRIMARY))
    for spec in out.values():
        spec["threshold"] = float(spec["threshold"]) * (1.0 + sign * frac)
    return out


def evaluate_arm(name: str, bundle: dict[str, Any], train: pd.DataFrame, test: pd.DataFrame) -> tuple[dict[str, Any], float, np.ndarray]:
    q = choose_quantile(bundle, train)
    veto = veto_from_predictions(bundle, train, phase="test", q=q)
    return {"name": name, "selected_residual_quantile": q, **metrics(veto, test, PRIMARY)}, q, veto


def run(args: argparse.Namespace) -> dict[str, Any]:
    train_path = Path(args.gdpa1)
    heldout_seq_path = Path(args.heldout_sequences)
    gdpa3_root = Path(args.gdpa3)
    tap_train_path = Path(args.tap_train)
    tap_test_path = Path(args.tap_test)

    train_raw = pd.read_csv(train_path)
    train = normalize_frame(train_raw, need_sequences=True)
    fold_col = FREEZE["data"]["train"]["fold_column"]
    if fold_col not in train_raw.columns:
        raise ValueError(f"frozen fold column missing: {fold_col}")
    folds = pd.to_numeric(train_raw[fold_col], errors="raise").to_numpy(int)

    heldout_raw = pd.read_csv(heldout_seq_path)
    heldout_seq = normalize_frame(heldout_raw, need_sequences=True)
    gdpa3_file, gdpa3_labels = discover_gdpa3(gdpa3_root)
    test = align_external(heldout_seq, gdpa3_labels)

    required = list(PRIMARY) + list(SECONDARY)
    missing = [c for c in required if c not in train.columns or c not in test.columns]
    if missing:
        verdict = VERDICTS["coverage"]
        return {
            "schema": "openline.rgv_001.report.v1",
            "experiment": "RGV-001",
            "verdict": verdict,
            "passed": False,
            "policy_authority": "NONE",
            "coverage_error": f"missing required columns: {missing}",
            "gdpa3_file": str(gdpa3_file),
        }

    test = test.dropna(subset=list(PRIMARY)).reset_index(drop=True)
    train_primary_valid = train[list(PRIMARY)].notna().all(axis=1).to_numpy()
    folds = folds[train_primary_valid]
    train = train.loc[train_primary_valid].reset_index(drop=True)

    seq_train_simple = descriptor_features(train)
    seq_test_simple = descriptor_features(test)
    seq_train_rich = kmer_features(train)
    seq_test_rich = kmer_features(test)

    simple_bundle = fit_prediction_bundle(train, test, seq_train_simple, seq_test_simple, folds)
    rich_bundle = fit_prediction_bundle(train, test, seq_train_rich, seq_test_rich, folds)

    tap_train = load_tap(tap_train_path, train)
    tap_test = load_tap(tap_test_path, test)
    tap_bundle = fit_prediction_bundle(train, test, tap_train, tap_test, folds)

    simple_metrics, simple_q, simple_veto = evaluate_arm("simple_sequence_descriptor_veto", simple_bundle, train, test)
    tap_metrics, tap_q, tap_veto = evaluate_arm("ginkgo_TAP_feature_linear_veto", tap_bundle, train, test)
    rgv_metrics, rgv_q, rgv_veto = evaluate_arm("RGV_sequence_kmer_confidence_veto", rich_bundle, train, test)
    random_metrics = random_baseline(len(test), int(rgv_veto.sum()), test, PRIMARY)

    baseline_candidates = [m for m in (simple_metrics, tap_metrics) if m["clean_retention"] >= FREEZE["primary_bar"]["external_clean_retention_min"]]
    best_baseline_avoid = max([m["experiments_avoided"] for m in baseline_candidates], default=0.0)
    margin = rgv_metrics["experiments_avoided"] - best_baseline_avoid

    coverage_ok = (
        len(test) >= FREEZE["primary_bar"]["minimum_external_evaluable_rows"]
        and rgv_metrics["clean_n"] >= FREEZE["primary_bar"]["minimum_external_clean_rows"]
    )
    core_ok = (
        rgv_metrics["clean_retention"] >= FREEZE["primary_bar"]["external_clean_retention_min"]
        and rgv_metrics["experiments_avoided"] >= FREEZE["primary_bar"]["external_experiments_avoided_min"]
        and margin >= FREEZE["primary_bar"]["margin_over_best_nonrandom_baseline_experiments_avoided"]
    )

    stress = {}
    stress_ok = True
    for label, sign in (("minus_5pct", -1), ("plus_5pct", 1)):
        th = stress_thresholds(sign)
        m = metrics(rgv_veto, test, th)
        stress[label] = m
        # direction must remain useful: retention floor plus positive bad enrichment.
        stress_ok &= m["clean_retention"] >= FREEZE["primary_bar"]["external_clean_retention_min"]
        stress_ok &= m["bad_candidate_enrichment_among_vetoes"] >= 1.0 if m["veto_n"] else False

    if not coverage_ok:
        verdict = VERDICTS["coverage"]
    elif core_ok and stress_ok:
        verdict = VERDICTS["pass"]
    else:
        verdict = VERDICTS["fail"]

    return {
        "schema": "openline.rgv_001.report.v1",
        "experiment": "RGV-001",
        "verdict": verdict,
        "passed": verdict == VERDICTS["pass"],
        "policy_authority": "NONE",
        "claim_boundary": "Sequence-only held-out viability veto on one 80-antibody external Ginkgo holdout; no claim of clinical-success prediction or generative design.",
        "data_receipts": {
            "gdpa1_sha256": sha256_file(train_path),
            "heldout_sequences_sha256": sha256_file(heldout_seq_path),
            "gdpa3_file": str(gdpa3_file),
            "gdpa3_sha256": sha256_file(gdpa3_file),
            "tap_train_sha256": sha256_file(tap_train_path),
            "tap_test_sha256": sha256_file(tap_test_path),
            "external_evaluable_rows": int(len(test)),
        },
        "primary_viability_region": PRIMARY,
        "secondary_not_in_primary": SECONDARY,
        "arms": {
            "random_matched": random_metrics,
            "simple_sequence_descriptor": simple_metrics,
            "ginkgo_TAP_feature_linear": tap_metrics,
            "RGV": rgv_metrics,
        },
        "comparison": {
            "best_nonrandom_baseline_avoidance_at_external_clean_retention_floor": best_baseline_avoid,
            "RGV_margin_over_best_nonrandom_baseline": margin,
        },
        "robustness": {
            "probe": "predeclared ±5% threshold stress; not published assay uncertainty",
            "passed": bool(stress_ok),
            "results": stress,
        },
        "frozen_bar": FREEZE["primary_bar"],
        "kill_condition": FREEZE["kill_condition"],
    }


def synthetic_self_test() -> None:
    # Mathematical sanity only; not evidence for the biological claim.
    rng = np.random.default_rng(17)
    n = 50
    df = pd.DataFrame({
        "vh_protein_sequence": ["ACDEFGHIKLMNPQRSTVWY" * 6 for _ in range(n)],
        "vl_protein_sequence": ["YWVTSRQPNMLKIHGFEDCA" * 5 for _ in range(n)],
        "HIC": rng.normal(2.8, .3, n),
        "PR_CHO": rng.normal(.25, .08, n),
        "AC-SINS_pH7.4": rng.normal(8, 4, n),
        "Tm2": rng.normal(82, 3, n),
    })
    x = descriptor_features(df)
    assert x.shape[0] == n and np.isfinite(x).all()
    clean = clean_mask(df, PRIMARY)
    assert clean.dtype == bool and len(clean) == n
    print(json.dumps({"self_test": "PASS", "rows": n, "features": int(x.shape[1])}))


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--gdpa1")
    p.add_argument("--heldout-sequences")
    p.add_argument("--gdpa3")
    p.add_argument("--tap-train")
    p.add_argument("--tap-test")
    p.add_argument("--output")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args()
    if args.self_test:
        synthetic_self_test()
        return 0
    required = ["gdpa1", "heldout_sequences", "gdpa3", "tap_train", "tap_test", "output"]
    absent = [x for x in required if getattr(args, x) is None]
    if absent:
        p.error(f"missing required args: {absent}")
    report = run(args)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["verdict"] != VERDICTS["coverage"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
